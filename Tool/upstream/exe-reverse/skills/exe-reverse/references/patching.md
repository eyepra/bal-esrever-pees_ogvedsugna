# Patching a PE image

Goal: change the target's behaviour with the smallest edit that can be proven to be reached, and know
exactly what else the edit invalidated.

## When to load this

- A byte or a branch has to change and the change must survive a restart.
- A patch is present in the file but the behaviour did not change.
- Something now refuses the binary, or a loader reports a bad image.
- You are choosing between editing the file and editing the process.

Equal-length editing is the default for a mechanical reason, not a stylistic one: nothing moves. Every
consequence below follows from that one property.

## What a patch site is, and what each kind costs

A "site" is the smallest byte range whose change produces the behaviour change. Five shapes dominate,
and they are not interchangeable: the same edit amount produces different collateral damage in each.

| Site | Typical edit | What else the edit touches | Failure if done carelessly |
|---|---|---|---|
| Conditional branch | invert the opcode (a two-byte `74 xx` becomes `75 xx`, both `Jcc rel8`) | nothing; the branch distance is unchanged | the check still runs and still has its side effects |
| Constant / comparison immediate | change the compared value in place | the instruction length changes with the encoding width | a longer immediate widens the instruction and shifts every following byte |
| Data table entry (jump table, dispatch entry, index table) | overwrite one entry with another existing entry's value | only that entry; table size is unchanged | the target now dispatches into the middle of an unrelated routine |
| Called routine body | overwrite the first bytes with a `ret`, or with a return of a benign value | the routine's prologue is skipped, so stack cleanup may be skipped with it | the routine is shared by unrelated features; a gate is not a helper |
| Routine pointer / import thunk | repoint a slot at a different existing routine | the slot's width must match | the replacement's calling convention or argument count differs |

Four rules fall out of the table.

1. **Prefer changing a value to changing control flow** where both are available. A comparison that
   returns success instead of failure leaves every caller's stack and register state as the code
   already expects.
2. **Count the callers before editing a routine body** (`observed`: a reference listing or a
   cross-reference pass over the image). A helper with thirty callers is not a feature gate, and a
   patch there produces failures in features you never opened.
3. **Do not neutralise a check by making it never return.** A stub that spins forever freezes the
   caller while it holds whatever lock it took, and the visible symptom (a hang, or a feature that
   silently does nothing) points nowhere near the edit. Return a benign value instead.
4. **Prefer success over failure** when you must choose a returned value: a gate that answers "yes"
   usually leaves the program in its designed path, while one that answers "no" falls into error
   handling that was never exercised.

## Why an equal-length edit is safe

The PE format pins several structures to positions and orderings (`observed`; PE Format
specification, section data and attribute-certificate rules):

- Section raw data is located by `PointerToRawData` and must be aligned to `FileAlignment`, and the
  section bodies must appear in the file in the order of their RVAs.
- The attribute certificate table and the debug information must sit at the very end of the image,
  with the attribute certificate immediately preceding the debug section, because the loader does not
  map them.
- Section sizes are declared in the section table; `SizeOfRawData` may be smaller than `VirtualSize`,
  in which case the remainder is zero-padded at load.

An equal-length overwrite changes bytes and nothing else. No offset moves. Therefore:

- the section table still describes what is on disk (`inferred` from the alignment and ordering rules
  above);
- the base relocation entries, which are recorded as RVAs plus type, still point at the same relative
  displacements (`observed`; the `.reloc` section holds RVA-keyed entries such as
  `IMAGE_REL_AMD64_REL32`, described in the PE Format specification);
- the security directory still points at the same file offset, and the certificate table is still the
  last mapped-excluded structure in the file;
- the only header field whose value becomes wrong is the checksum, and that field is recomputable.

## What a length change breaks

A length change inside a section is a structural edit, and it invalidates things in a chain rather
than one at a time (`inferred` from the format rules above):

- Every later byte in the file shifts, so every file offset recorded anywhere, including in your own
  notes and in any other patch spec, becomes wrong.
- Section data alignment and RVA ordering have to be re-established; the section table has to be
  rewritten.
- Relative displacements recorded as file offsets are unaffected, but any structure the loader
  resolves through an absolute offset from the section start now describes shifted content.
- The certificate table must remain last; if the growth pushes it, or if the growth happens after it,
  the file no longer satisfies the ordering rule.
- The checksum changes even if you recompute it, because the file has a different length.

A length change is sometimes the correct answer, for example when a slot is genuinely too small and a
five-byte redirect is needed where four bytes exist. It must be an explicit decision, reported as a
structural change, not a side effect of a sloppy byte count. The patcher refuses one unless it is
asked for it explicitly (`observed`; `scripts/pepatch.py`, `--allow-resize`, which then labels the
result a structural edit).

## Locating an exact file offset rather than guessing from a listing

A disassembly listing shows addresses, not file offsets, and the two differ by the section mapping.
Resolve deliberately:

1. Read the section table and find the section containing the RVA. Within it,
   `file_offset = PointerToRawData + (rva - VirtualAddress)` (`observed`; this is what the patcher's
   RVA resolution does).
2. Check that the offset lands inside `SizeOfRawData`. If it lands between `SizeOfRawData` and
   `VirtualSize`, the bytes there are zero padding in the file, not code; writing them changes nothing
   the loader will execute as code and may look like a successful patch.
3. Pin the site with the bytes you expect to find. An offset plus an expected-bytes check fails loudly
   when you are looking at a different build; an offset alone silently edits whatever is there
   (`observed`; `--expect` aborts on mismatch).
4. Prefer a pattern plus an expected span over a bare offset when the build identity is not certain.
   A pattern that matches more than once must be refused rather than resolved to the first hit
   (`observed`; the patcher raises an ambiguity error unless an index is given explicitly).

```
python scripts/peutil.py APP.dll --sections
python scripts/pepatch.py APP.dll --at-rva 0x2A10 --expect "74 0A" --bytes "EB 0A" --out APP.patched.dll --dry-run
python scripts/pepatch.py APP.dll --pattern "E8 ?? ?? ?? ?? 85 C0 74" --pattern-offset 5 --bytes "75" --expect "74" --at-hit 0 --out APP.patched.dll
```

The `--dry-run` form resolves and reports without writing, which is the cheap way to find out that the
site moved.

## The instruction-width trap

x86 instructions are variable length and the encoding is not self-synchronising: a decoder that starts
one byte off an instruction boundary produces a plausible instruction stream made of the wrong
instructions (`inferred`; this follows from variable-length encoding without alignment markers, and is
the standard reason disassembly is done from a known boundary rather than from an arbitrary offset).

Symptoms that you are reading fiction rather than code:

- Implausible but valid-looking mnemonics, especially long runs of unusual combinations.
- A call target that lands in the middle of what the listing calls another instruction.
- A prologue that is almost right: one push or one `sub rsp` off from every other function in the
  image.
- A branch whose destination does not align with any block boundary the listing itself shows.
- Two "instructions" whose bytes are individually valid and whose addresses overlap.

Recovery: re-decode from the nearest boundary you can justify independently, which in practice is a
function start reached from a call site, an export, or the entry point. Then travel forward. A short
window read in isolation cannot tell you whether its first byte was an instruction boundary, and the
common form of this failure is a patch that lands where the listing said an instruction began.

## Neutralising a branch versus redirecting it

Three edits, three different consequences:

- **Invert the condition** (`74 xx` to `75 xx`, or the wider `0F 84` form to `0F 85`): the taken path
  swaps. The check's side effects still execute, and both paths are still present. This is the right
  edit when the decision itself is the gate and the fall-through leads to working code.
- **Force the branch** (replace the conditional with an unconditional jump of the same displacement,
  or with a filler): the conditional no longer evaluates, so any state the check populated is absent,
  and the path that was skipped is now dead. Callers that read state instead of a return value break
  here, and they break in a place unrelated to the branch.
- **Redirect the call** to another routine or to a stub: the caller's expectations about the callee's
  signature, return value, and side effects become the new failure surface. A redirect is only cheap
  when a suitable existing routine exists in the image.

NOP-filling a conditional and expecting the following code to work is a specific trap: the block after
the branch was often written on the assumption that the check consumed something (a handle, a
reference count, a heap pointer). Removing the branch without removing the consumption is how a patch
produces an access violation that looks like a new bug in the target.

## File patch or memory patch

| | File patch | Memory patch |
|---|---|---|
| Survives process restart | yes (`observed`; the bytes are on disk) | no, it is reapplied each run |
| Portable to another machine | yes, if the build matches | no, it is bound to the launcher |
| Visible to the target's own file reads | yes | no |
| Visible to a code-page hash | no, if it hashes the file on disk | yes, if it hashes mapped pages |
| Invalidates an on-disk signature | yes, as a consequence of the covered bytes changing | no |
| Needs a writable artifact and a loader | no | yes |

Choose the file patch when the deliverable is a file that must work elsewhere. Choose the memory patch
when the file must stay byte-identical (a signature must keep verifying, or a supervisor compares the
file against a copy), or when the target re-reads and re-verifies its own file but does not inspect its
mapped pages. Choose neither when a self-check hashes its own mapped code: a memory patch is written
into exactly the pages that check reads.

A mapped code page that has been written stays reported as part of the image rather than as private
memory, so the file/memory distinction is not visible in a simple page-state query (`observed`;
`VirtualQueryEx` remarks: a modified copy-on-write image view is still reported as `MEM_IMAGE`, and
detecting the modification requires the working-set `Shared` bit via `QueryWorkingSet` or
`QueryWorkingSetEx`).

## The checksum field

The optional header carries the image checksum in the `CheckSum` field, at offset 64 in both PE32 and
PE32+ (`observed`; PE Format specification, optional header Windows-specific fields). The same page
states that drivers, DLLs loaded at boot time, and DLLs loaded into a critical process have their
checksum checked at load time, and that the algorithm is implemented in the ImageHlp library
(`observed`).

Consequences:

- Recomputing the checksum after an edit is expected, not optional. A patch that leaves a stale
  checksum has changed a field that some loaders validate.
- The check is real but narrow: it is not a general anti-tamper mechanism, and a wrong checksum is
  not evidence that your patch was rejected unless the target is in one of those categories.
- The API surface for reproducing the algorithm is the ImageHlp pair `MapFileAndCheckSum` (file name
  in, declared and computed checksums out) and `CheckSumMappedFile` (mapped image in, same outputs)
  (`observed`; both documented, `imagehlp.h`).
- The patcher recomputes it by default and reports the result; suppressing that is a deliberate flag
  (`observed`; `scripts/pepatch.py`). To read the declared value without editing anything, use
  `python scripts/peutil.py APP.dll --check-sum`.

## What a patch does to an Authenticode signature

State this as a consequence, not as advice. The attribute certificate is, in the format
specification's own words, a statement by the software manufacturer that indicates what the message
digest of the image is expected to be, and it is "very difficult to modify a file to have the same
message digest as the original file" (`observed`; PE Format specification, general concepts). An edit
that changes any byte the digest was computed over therefore leaves a signature that no longer
verifies against the file. The patcher reports the signature state of the output for exactly that
reason (`observed`).

Two things follow, and neither is a recommendation. Policy that requires a valid signature will now
refuse the image even though it loads without one on an ordinary desktop. And a target that verifies
its *own* signature, or that hands the check to the platform, will observe the same failure as a
checksum mismatch and may treat it as tampering. Which bytes a particular digest implementation
excludes is a detail of that implementation; do not assert an exclusion list from memory.

## Proving that a patch landed, and that it is reached

"Present in the file" and "executed at run time" are different claims, and the second is the one that
matters.

Present in the file, in increasing order of strength:

1. The edit tool reported success.
2. The output file re-parses as a PE and the site resolves in it (`observed`; the patcher re-opens the
   written file and re-reads every patched byte, reporting any mismatch).
3. The raw bytes at the recorded offset, read back from the written file, equal the replacement
   (`observed`).
4. The file hash is recorded, so a later reader is testing the artifact you built rather than a
   filename.

Reached at run time is a separate experiment, and the control is the unmodified original:

1. Confirm the target that runs is the artifact you patched. Two copies on the search path, a
   side-by-side or versioned DLL, an installer that restores the file, and a launcher that extracts a
   copy to a temporary directory all defeat this step while every file-level check stays green.
2. Exercise the exact feature, not the application. Startup succeeding proves the image loads.
3. Observe the outcome, not the log. A clean log with the feature still absent is a failed patch, and
   the absence of an error is not evidence of the change.
4. If the outcome does not change, the diagnosis is wrong rather than the patch being unlucky. The
   likely reasons, in order: the patched code is not the gate, the gate is reached but a second check
   re-derives the answer, the changed bytes are overwritten before use, or the site was decoded from a
   desynchronised instruction stream.

Record with the patch, so the work is reproducible: input file hash, output file hash, per-site offset,
RVA, expected bytes, replacement bytes, whether the span was proven equal-length, and the observed
before/after behaviour of the feature you exercised.
