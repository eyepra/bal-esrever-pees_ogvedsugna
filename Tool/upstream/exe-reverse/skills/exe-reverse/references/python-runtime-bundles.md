# Python-packaged Windows software

Goal: recognise a Python program that has been packaged into an executable, find the layer that
holds the logic, and separate three problems that look alike at first contact — a **packed
archive**, a **cryptographic code-object wrapper**, and **native-compiled Python**.

## When to load this

Load this when the target directory holds `python3xx.dll` (or `python27.dll`), a
`_internal/` tree, `base_library.zip`, a `PYZ` archive or a `pyarmor_runtime` module; when the
executable shows a "failed to execute script" dialog; when strings contain `PyInstaller`,
`pyi-`, `pyiboot` or `pyarmor`; or when a decompiled module is high-entropy while the rest of the
program is ordinary Python.

The layer decides the route:

| What is there | What it is | Where to go |
|---|---|---|
| a packaged archive with ordinary bytecode inside | a packager: the program is normal Python with a container around it | this file, "Unpacking the archive" |
| bytecode that is encrypted per code object, with a small runtime module beside it | a code-object wrapper (PyArmor is the one described here) | this file, "The wrapper layer" |
| `python3xx.dll` present but no bytecode to find | native-compiled Python: the logic was translated to C and built | this file, "Native-compiled Python", then the native routes |
| a native extension (`.pyd`) that is itself protected | a protector on top of native code | `references/virtualization-and-flattening.md` or `references/protectors-and-packers.md` |

Grades: the file-layout facts are `inferred` from the tools' documented behaviour; the wrapper
internals below are `unverified` here, taken from a public write-up and not reproduced on a
sample. Each section says what would make its rows `observed`.

## The gate that decides everything: the Python version

A `.pyc` is a version-specific serialisation (`marshal`) of a code object. The header carries a
magic number, and the body's field order changed several times across 1.x-3.13. **A code object
parsed under the wrong version yields a plausible wrong result rather than an error**, which makes
this the most expensive fact to get wrong and the cheapest to establish.

Read it before anything else, from the least ambiguous source available:

| Source | What it gives |
|---|---|
| the runtime DLL's name (`python311.dll`) | the major and minor version, when the packager kept the standard name |
| the DLL's version resource | the full version, including the patch level the packager bundled |
| `sys.version` in the bundled library, if a `.py` or a string constant survives | the exact build string |
| the code object's magic number | the marshalling version, once you can read four bytes |

Record the version next to the artifact's hash. Every later step — unmarshalling, decompiling,
re-importing — is only valid under the version that produced the bytes.

## Layer map

| Layer | What it holds | What it costs to remove |
|---|---|---|
| the packager's bootloader | unpacks the archive to a temporary directory and runs the entry script | nothing: it is a documented container, and the payload lands on disk |
| the archive | compressed entries: the bytecode modules, data files, extension modules | extraction only |
| the code objects | the program's logic, as `marshal` data | a version-matched unmarshaller and a decompiler |
| the wrapper (if present) | encrypted code objects and literals, plus a runtime that decrypts them per module | the key derivation, or a dump after decryption |
| native extensions | C/C++ modules the program imports | the ordinary native route; a protector here is a separate problem |

## Unpacking the archive

**Diagnosis before extraction.** The packager leaves fingerprints that are cheap to read: the
runtime DLL, the archive file or a `base_library.zip`, the `_internal` directory convention, and
the bootloader's own strings. `scripts/pe_triage.py` plus a directory listing answers which
packager it is; the packager's extraction tool is then a known one instead of a guess.

**Extraction.** Two options, and the second is the one that survives a modified archive:

1. Run the packager's own extractor against the executable. It reads the container format
   directly and needs no execution of the target. The result is a directory of modules.
2. Run the target once in an isolated environment with its temporary directory redirected and
   captured. This sees the payload the process actually used, which is the control for option 1:
   if the two differ, the on-disk archive is not the one being executed.

**Then unmarshal and decompile under the recorded version.** Two checks keep this honest:

- the module count and the import graph should look like a program (an entry module that imports
  tens of modules), not like a fragment;
- a decompiled module must contain calls whose names appear in the archive's string data. A
  decompiler run under the wrong version fails this test while still producing output.

## The wrapper layer

In the version analysed, the wrapper does not transform control flow; it encrypts the artifacts the
interpreter needs and decrypts them as they are loaded. That distinction is what makes it tractable,
and it is also why "deobfuscation" is the wrong word for the work: there is no obfuscated logic to
simplify, only a key to find or a plaintext to capture. The same analysis warns that the scheme has
no obfuscation layer to fall back on, which is why wrapping is usually accompanied by native
compilation or by a protector on the runtime module.

The following is what one public analysis reported for one version (`unverified`; none of it was
reproduced here). Treat the field names as the shape to look for rather than as offsets to trust.

| Element | Reported mechanism |
|---|---|
| the marker in the code object | a `co_flags` bit (`0x20000000`) says "this code object carries wrapper data". When it is clear, the object is ordinary bytecode |
| the extra data | after the standard fields, a length-prefixed blob, with counts packed into its first byte for per-function records and code descriptors |
| the descriptor | stored as a constant in the code object, referenced by index; its first 8 bytes are a placeholder rewritten at run time, the rest is `flags`, a start index and a length |
| descriptor flags | bit `0x2` short form, `0x4` "the nonce is XORed with a key", `0x8` "copy the prologue back after decryption" |
| the cipher | AES in CTR mode. The key is 16 bytes derived by MD5; the nonce is 12 bytes cut from the encrypted region itself, with the final byte set to `2` |
| the key derivation | MD5 over: a versioned identifier string (`pyarmor-vax-<6 digits>`; all zeros for one edition), a fixed-length slice of a key blob, a second slice whose length comes from a field in its own header, and a 16-byte value XORed with a constant |
| the nonce for literals | the first 12 bytes of the second key slice; in the analysed build the ASCII text `i.non-profit` |
| an optional second transform | when a "xor key procedure" length is non-zero, a small bytecode interpreter computes a 12-byte key that is XORed into the nonce before decryption |
| the mini interpreter | 8 registers, 11 opcodes: add/subtract/multiply/divide/XOR/assign against the register named by the high nibble, plus store operations at fixed offsets of a 12-byte output |
| the prologue copy | the first `N` bytes of the decrypted region are copied to offset zero and the source is overwritten with NOPs, because the interpreter expects the prologue at the front |

**Two routes, and what each buys.**

- **Static.** Reproduce the key derivation, decrypt each descriptor's range, restore the prologue,
  and the code object becomes ordinary bytecode. The published tooling for this is version-matched
  to the wrapper's version, and the version check is part of the tool's correctness rather than a
  formality: an object decrypted under the wrong scheme produces bytes that unmarshal into
  nonsense, or worse, into a plausible object with corrupted constants.
- **Dynamic.** The interpreter decrypts a module just before executing it, so a dump taken at the
  right moment contains plaintext. The published analysis reported this as **incomplete**: the
  decryption is per node and per literal, so a single snapshot does not reconstruct the whole
  program. It is the cheaper route for "what does this one function do" and the wrong route for
  "reconstruct the package".

**The tempting wrong move**, worth naming because it produces a working-looking result: patching
the wrapper's check or skipping the decrypt call. The module then either runs with a corrupt code
object or falls back to a path that never touches the protected logic, and the session ends with a
program that starts and does nothing.

## Native-compiled Python

When the logic is in a `.pyd` or in a compiled executable with no bytecode to find, the program
was translated to C and built (Nuitka and Cython are the common ones; hand-written bindings are
another). The ordinary native workflow applies from that point: the module is a PE with the
Microsoft C++ runtime, its structure is readable by `scripts/pe_triage.py`, and the Python C-API
calls are visible imports that mark the boundary between compiled Python and the interpreter.

Two consequences:

- **The Python version is still a fact you need**, because the C-API symbols the module imports are
  version-specific, and a module built for 3.11 does not load into 3.12.
- **A protector on a `.pyd` is a native-protector problem**, and the protections that matter there
  are the ones in `references/virtualization-and-flattening.md`. A wrapper has no relevance to
  code that never becomes a code object.

## Verification

| Claim | The check that settles it |
|---|---|
| the payload came from this executable | hash the binary, hash the extracted module, and run the target once with the temporary directory captured; the two payloads must match |
| the decompiled module is the module that ran | import it under the recorded interpreter and observe the same behaviour on the same input as the packed original. A decompiler's output that does not import has proved nothing |
| the Python version is right | recompile a decompiled module with that interpreter and compare the code object's structure (arg counts, names, constants) with the original |
| the wrapper was removed rather than bypassed | the recovered module imports with no wrapper runtime present, and every function in it executes. A module that only works while the wrapper's runtime is loaded is a hook, not a recovery |

Record the interpreter version, the artifact hashes and the command in the result. "It decompiled"
is a statement about the decompiler.

## What this route does not do

- **Ship a general unpacker.** The wrapper's format is version-specific, and the published tools
  state which versions they cover; a version outside that set is a research task, not a command.
- **Recover a key that is bound to a licence.** Where the key material is delivered by an
  activation step, the bound value lives in the same category as
  `references/network-activated-licensing.md` describes, and the client-side file is not where
  the decision is made.
- **Treat recovered source as the original.** Decompiled Python is a reconstruction; names of
  locals and the shape of expressions are not what the author wrote.
- **Cover Python packaged for another platform.** An Android or iOS bundle is a different artifact
  class; `references/handoff-boundaries.md` names the owner.

## What makes this `observed`

- the packager identified from the files, with the paths and the hashes;
- the interpreter version and where it was read from;
- the extraction route used, and the control run that shows the extracted payload is the executed
  one;
- for the wrapper: the descriptor, the derivation reproduced, one decrypted object that unmarshals
  and imports, and the literal sample that decodes to text a program would contain;
- one module that was recovered and executed with the wrapper absent.

## Provenance of the unverified rows

The wrapper analysis summarised above comes from a public write-up built on two open-source
projects, `Pyarmor-Static-Unpack-1shot` and `Pyarmor-Tooling`; the mechanisms are theirs, the
paraphrase is this file's, and neither project was run against a sample here. The packager
behaviour is documented by the packagers' own tooling. When one of these rows is tested, the
result belongs beside the artifact's hash and the wrapper's version, not in this section.
