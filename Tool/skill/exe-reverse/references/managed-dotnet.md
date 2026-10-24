# Managed assemblies, bundles, and mixed-mode images

Goal: decide what kind of managed artifact you actually have, and whether the layer you are
about to edit is the layer that executes.

## When to load this

Load this when the sample is a .NET assembly, or a PE that turns out to carry a CLR runtime
header, or a signed-looking `.exe` whose imports resolve to nothing familiar because the code
inside is not native. Load it before reaching for a hex editor, and again when a byte edit on
disk has no effect at run time. Stop and load the native route files only after the last
section here tells you the managed layer hands over.

## Recognise it before you plan the edit

A managed assembly is still a PE. The marker is the **CLR runtime header** data directory
entry in the optional header, at optional-header offset 208 (PE32) or 224 (PE32+); the entry
is the fourteenth data directory entry in array order (`inferred`: the arithmetic from the
offsets the format specification lists, whose first entry is at 96/112). A non-zero entry
points at a CLI header, which in turn points at metadata and at the method bodies
(`observed`: Microsoft PE/COFF specification, "Optional Header Data Directories" and "CLR
Runtime Header").

Read the directory, not the filename. `.dll` covers native libraries, managed libraries,
and mixed-mode libraries; `.exe` covers all three plus native hosts that merely embed a
managed payload.

| What you find | What it is | What that means for the plan |
|---|---|---|
| CLR directory present, entry point in managed code, method bodies at the RVAs given in metadata | Ordinary managed assembly | No native disassembly is needed. Work from metadata and CIL; a hex edit aimed at machine code has nothing to aim at |
| CLR directory present, code outside the CLI metadata is machine code, native exports present | Mixed-mode (the managed and native parts are in one image) | Two different layers in one file. Locate which layer owns the behaviour before editing either |
| No CLR directory, large embedded blob, entry point in a small native stub | Single-file bundle or a self-contained host | The managed payload is data inside, not code you can read yet. Extract or read the bundle first |
| CLR directory present, CLI header flags include the IL-library flag, a native precompiled section for the same methods | Ready-to-run output | Metadata and IL are both present. The native copy is a second, discardable rendering of the same methods |
| No CLR directory at all, native code, name suggests .NET | Native AOT output, or a managed assembly wrapped in a native loader | Effectively native. Use the native routes; do not look for CIL that is not there |

`observed`: the data-directory table, the CLR runtime header entry, and the `IMAGE_SUBSYSTEM`
values below are from the Microsoft PE/COFF specification. `observed`: for ready-to-run, the
`.NET` runtime repository's ReadyToRun file-format document states that a single-file
ready-to-run image conforms to the CLI file format with the CLI header's IL-library flag
(`0x00000004`) set, that a `READYTORUN_HEADER` is reached through the CLI header's
`ManagedNativeHeader`, that its signature is `0x00525452`, and that the COR header and the
ECMA-335 metadata it points to are a full copy of the input IL and metadata.

## Why a CIL edit is not a byte patch

The instruction set is not the reason. The reason is that CIL carries its own addressing
model, and edits have different failure modes from native patches.

- **The bytes are not the executed bytes.** CIL is compiled by the just-in-time compiler at
  run time. Nothing in the file format promises the on-disk method body is what ran, and a
  change on disk has to survive compilation to have any effect. A patch that "does nothing"
  is therefore an expected outcome of editing the wrong artifact, not a sign the check does
  not exist.
- **The precompiled native copy can be discarded at run time.** `observed`: Microsoft's
  ready-to-run documentation states that ahead-of-time generated code is not as optimised as
  just-in-time output and that tiered compilation replaces commonly used ready-to-run methods
  with just-in-time generated methods. A patch inside the precompiled region can be replaced
  by freshly compiled code while the process runs.
- **Length changes are safe here, and that is the trap.** CIL method bodies are byte arrays
  referenced by an RVA and a size in metadata, so an edit that changes length is not the
  structural emergency it is in native code. It is still a structural edit: the body of a
  method carries its own header, and one that contains exception-handling clauses carries a
  clause table whose offsets are relative to the body. An edit that keeps the body the same
  size and the structure identical is the one that does not need the rest of the file to be
  repaired.
- **Metadata tokens are not text.** A call is an index into a table plus a one-byte table
  selector, so "replace this call with a nop" has a different shape from its native
  equivalent, and a wrong token targets a different method silently rather than crashing.
- **A managed failure is an exception, not a crash.** A bad edit can throw a verification or
  type-load exception at the first use of the method, which is easily mistaken for the
  application's own error handling. Time to failure is not the entry point.

## The readable layer

Metadata is the reason managed work is usually easier than native work, and it is also the
reason obfuscation is a different problem here.

Read in this order: the assembly manifest (identity, version, culture, strong-name public
key), the type and method tables with their names, then the method whose RVA points into the
body you care about. Method bodies live in a section the metadata addresses directly; the
CLI header gives the metadata root, and the metadata root gives the streams and the tables.
The published definition of that layout is the CLI standard, and a checksum of it is the
document you should have open while writing a reader (`observed`: the CLI metadata layout is
specified by ECMA-335; Microsoft's runtime repositories describe the ready-to-run additions
on top of it).

Tooling this repository's host probe looks for, and what each is for:

- `ildasm` and `ilasm`, for text-form CIL round trips. A disassembly plus reassembly is the
  cheapest way to test a hypothesis about a method body, and it fails loudly when the body
  cannot be represented.
- `dotnet`, for `dotnet --list-sdks` / `--list-runtimes` on the analysis host, which tells you
  which runtime the sample was probably built against and which packaging shapes are even
  producible on this machine.
- No decompiler is required to locate behaviour, but a name-preserving disassembly is much
faster than reading token numbers by hand.

Which of these to use for which question, how to read a CIL listing, and how to go from a method
body to a statement about business logic is `dotnet-decompilation.md`. This file stops at
classification and at the structural rules for an edit.

Cheap questions that answer a lot before any editing: is the assembly signed with a strong
name, does it carry a mixed-mode native part, does it reference a licensing or activation
assembly, and are the type and method names meaningful or renamed to unusable characters.

## Four shapes that are not the same artifact

These four are routinely confused, and each confusion costs an hour.

**Ordinary assembly.** Metadata plus CIL. The file can be disassembled, edited and reassembled.
Everything above applies.

**Single-file bundle.** `observed`: Microsoft's single-file documentation states that only
managed DLLs are bundled into the single file; at start-up they are extracted and loaded in
memory "avoiding the extraction to a folder"; the native binaries of the core runtime are
separate files unless the build sets `IncludeNativeLibrariesForSelfExtract`; and the
compatibility mode `IncludeAllContentForSelfExtract` extracts all files, including the
managed assemblies, before running. Where extraction happens is documented: a directory under
the path in `DOTNET_BUNDLE_EXTRACT_BASE_DIR`, otherwise under `%TEMP%\.net` on Windows. Two
documented consequences make this a distinct artifact: with a single-file app
`Assembly.Location` returns an empty string and `Module.FullyQualifiedName` returns
`<Unknown>` or throws, and the embedded assemblies may be compressed at build time
(`EnableCompressionInSingleFile`), so the payload may not be visible as plain metadata runs.
The practical consequence: **there may be no file on disk that contains the code being
executed**, and if extraction is used, the executed copy is under the temporary extraction
directory rather than next to the original.

**Ready-to-run / native-precompiled output.** `observed`: Microsoft's ready-to-run
documentation says the binaries contain both intermediate language, "which is still needed
for some scenarios", and the native version of the same code, and that enabling it grows an
assembly to roughly two to three times its size. `observed`: the runtime repository's format
document says the metadata and COR header are a full copy of the input. There is a documented
symbol file for the precompiled code on Windows (extension `.ni.pdb`), emitted only when
symbol generation is requested at publish time. So a ready-to-run sample is not "a managed
assembly without CIL"; it is a managed assembly **plus** a native rendering, and the two must
not be mixed in one patch plan.

**Native AOT output.** `observed`: Microsoft's Native AOT documentation states that publishing
this way produces a self-contained app ahead-of-time compiled to native code, which does not
use a just-in-time compiler when it runs, and that the published output contains all the code
needed to run, "including a stripped-down version of the coreclr runtime". Its documented
limitations matter for analysis: no dynamic loading, no run-time code generation, no C++/CLI,
trimming required, and on Windows no built-in COM. Debug information is a separate file,
`.pdb` on Windows, and the documentation states that file is necessary for running under a
debugger or for inspecting crash dumps. Treat this output as native: the native sections of
this skill are the right instrument, and a search for CIL in it is a search that returns
nothing for a reason that has nothing to do with a protector. **Verify per build, not per
claim:** whether a given image retains any IL (for reflection metadata and similar) is a
question about that build's trim and metadata settings; open the image and check the
directory and the method-body RVAs rather than assuming either way. `unknown` here means the
search you ran, not a conclusion.

## Strong naming: identity, not tamper protection

The documented position is unambiguous and it should end a whole class of wrong reasoning.

`observed`: Microsoft's strong-named assemblies documentation carries the warning "Do not rely
on strong names for security. They provide a unique identity only." The same page states that
for .NET Core and .NET 5 and later, "the runtime never validates the strong-name signature,
nor does it use the strong-name for assembly binding".

Consequences for the plan:

- A strong name is a **binding and identity** mechanism. It says which assembly this is and
  which key signed it, and it is what makes side-by-side versions and the assembly cache work
  in the older framework model.
- It is not an anti-tamper mechanism and it is not a signature over the code that the runtime
  checks before executing. Editing a strong-named assembly and clearing or replacing the
  strong name is a tooling step, not a defeat of a defence.
- Therefore, the presence of a strong name tells you nothing about whether the sample checks
  its own bytes. Those are separate questions, and the second is answered by looking for an
  integrity routine, not by looking at the signature.
- An Authenticode signature on the PE and a strong name are also different things, and neither
  one is a substitute for the other in either direction.

If a cost estimate depends on "the strong name will stop the edit", the estimate is wrong and
the check you were planning to run is the wrong check.

## Obfuscation and control flow in managed code

Managed obfuscation moves the same problem as native obfuscation, but the techniques are
listed in the artifact.

- **Renaming** removes the free map that metadata gives you. The tables still exist, the tokens
  still resolve, and the call graph is intact; only the names are gone. Control-flow reasoning
  and string-based location still work.
- **String and constant encryption** hides the literals that would otherwise point straight at
  a check. A decryption call site near a comparison is the usual landmark.
- **Control-flow rewriting** replaces the original shape with a dispatcher: a state variable, a
  loop, and a switch over that variable. In managed code this is unmistakable in CIL, because a
  `switch` over a local loaded from a field is not what a compiler emits for ordinary code. The
  route for that shape is dynamic: run it, log the state transitions, and let the observed
  order of blocks stand in for the flow that was removed.
- **Method-body encryption or a runtime loader** breaks the static artifact. The bodies are
  not readable in the file, the loader is, and the loader runs before the code does. This is the
  managed analogue of a packer, and the same rule applies: dump and fix up after the loader has
  run, then read the result.
- **A protector that mixes in a native component** puts the loader or the checks in native
  code inside the same image. Then the first thing to do is the classification above, because
  two of the four columns in the table are now in play at once.
- **Vendor claims are claims.** Products in this category advertise attack resistance in
  absolute terms. Documentation of a technique, in a manual, is evidence that the technique
  exists; it is not a measurement of whether a given sample's protection survives a given
  approach. Treat strength claims as `unverified` until measured on the sample in front of you.

What obfuscation does **not** change: the runtime still has to load, verify/compile and run the
code, the check still has to reach a decision, and that decision is still observable at run
time. Every static block is a dynamic-work estimate, not a wall.

## Where managed hands over to the native routes

Hand over, deliberately, at one of these points:

- **P/Invoke and native dependencies.** A managed check often calls into a native library,
  and the actual comparison happens there. Follow the call out: the `DllImport` target name is
  in metadata, and the native binary is a normal sample for the rest of this skill.
- **Mixed-mode images.** The native part is patched as native code; the managed part is not.
  Count the layers before editing, and record which one you changed.
- **Native AOT output.** No differentiation is needed: it is a native sample with an unusual
  runtime library.
- **A bundle whose payload is native.** Bundles are not only managed. If the payload is a
  native library, the extraction step is still the first move, and every conclusion after that
  comes from the native routes.
- **A protector with a native core.** The managed layer may be a thin shell over a native
  loader; classify before choosing a toolchain.

## Verification question for this shape

The question here is not "did the edit apply", it is **"is the artifact that ran the artifact
I built"**. Three answers are required before any claim:

1. **The identity of what ran**, as a path plus a hash. For a single-file bundle with
   extraction, that is the extracted copy, not the file you edited, and the extraction path
   itself is evidence worth recording.
2. **Which layer executed**, managed or native, for the specific method you changed. If a
   precompiled native copy exists and tiered compilation is in play, a managed-layer change
   and a native-layer change are not interchangeable.
3. **The feature exercised**, observed directly, with the unmodified original run under the
   same conditions. A clean log is not evidence.

## What this file does not cover

`unknown`: no managed sample was measured while writing this file, so every statement above is
from the format documentation and the runtime documentation named inline, not from a
reproduction on this host. Specifically not covered here:

- The exact shape of the CLI header flags beyond the IL-library flag used above, and the
  metadata table layout at field granularity. Both are in the CLI standard (ECMA-335) and must
  be read there before a reader or writer is written against them.
- Whether a specific commercial obfuscator's output survives any specific approach. That is a
  per-sample measurement.
- Ready-to-run and Native AOT debug-info formats beyond what is quoted above.
- Any per-build question about retained IL in native AOT output: check the sample.
