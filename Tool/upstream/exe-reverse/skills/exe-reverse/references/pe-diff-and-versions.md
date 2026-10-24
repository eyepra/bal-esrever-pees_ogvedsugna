# Comparing two builds of the same program

Goal: turn two binaries into a short list of what is genuinely different — with volatile fields removed
first — and state clearly that a difference is not evidence of intent.

## When to load this

Load this when two supposedly identical builds behave differently; when a patch worked on one version
and not the next; when you must find which routine changed between releases; when you suspect a binary
has been modified by someone else before it reached you; when you need to know whether a replacement
file is really the same file; and before you conclude that a signature-based patch "should still work".

## The two questions a diff answers, and the one it does not

It answers **what changed** (a list of file ranges, sections, fields and routines) and **how much
changed** (which is your only cheap estimate of how expensive a re-location will be). It does not answer
**why**, and it cannot tell you which build is newer. A diff shows change, never intent — and a change
list is exactly the artifact most likely to be misread as a cause list.

## Step 0: identity, before anything else

A size comparison is not an identity check, and neither is a version resource. A same-size replacement
is the specific case that catches people: two files of identical length can differ in every byte, and a
build that only touched a constant produces a same-size, different-content file. The check is a
**content hash over the whole file**, plus the same hash over the parts, so that you can state what
matched:

```
whole-file:   sha256(A) vs sha256(B)        -> equal or not; nothing in between
per-section:  sha256 of each section's raw range
overlay:      sha256 of bytes after the last section, if any
```

If the whole-file hashes are equal, stop: there is nothing to diff. If they differ, the per-section
hashes localise the difference to one section before you compare a single byte, which is far cheaper
than a byte diff over the entire image.

## Volatile fields: normalise or drown in noise

Two builds of the same source can differ in fields that carry no behaviour. Normalise these **before**
you compare, and say which ones you normalised — otherwise your change list is mostly build metadata and
your real change is somewhere in the middle of it.

| Field | Why it differs without any code change |
|---|---|
| `TimeDateStamp` at COFF header +8 | A build clock, or a hash-derived value. On this host both `notepad.exe` and `kernel32.dll` carry a type-16 reproducibility debug entry, and the specification states of such builds that stamp fields "no longer represent the actual date and time" |
| `CheckSum` (optional header offset 64) | Recomputed over the whole file, so it changes when anything else does |
| Rich Header region | Per-file obfuscation with a key stored in the file. `observed`: `notepad.exe` key `0xD452EC34`, `kernel32.dll` key `0x751E534F`. The whole region is volatile, not just the key |
| Debug directory and CodeView record | The PDB path usually contains a build machine's directory layout, and the GUID/age identify a build rather than a source state |
| Resource directory table | The specification gives this table a `Time/Date Stamp` field at offset 4, described as "the time that the resource data was created by the resource compiler" |
| Certificate table | Any re-signing changes an appended blob at the end of the file, and it is a file offset, not an RVA (`pe-structure.md`) |
| Data-directory raw sizes when a section grew | `SizeOfRawData` is `FileAlignment`-rounded, so one added byte can move every later section's `PointerToRawData` |

A useful habit: run the comparison twice, once with these fields masked and once without. The unmasked
diff should contain exactly the fields in the table plus your real change. If it contains anything else,
you have a change you did not account for.

## Step 1: section-level diff

Compare the section tables as records, not as text: name, `VirtualSize`, `VirtualAddress`,
`SizeOfRawData`, `PointerToRawData`, characteristics. Four readings matter.

- A section present in one build and absent in the other. Name the consequences for every later offset.
- A section whose raw size changed. Every later `PointerToRawData` in that build moved, so all
  RVA-to-offset arithmetic from the other build is now wrong.
- A section whose characteristics changed. Execute or write appearing where neither was is the loudest
  signal in this table.
- Identical section tables with different per-section hashes. The interesting case: the layout is stable
  and the change is inside a section, so a byte diff over that section's raw range is safe.

`observed` example of how much the end of the file can move for structural reasons: in the .NET assembly
`System.Runtime.dll` 6.0.12, `.reloc` has raw pointer `0x7C00` and raw size `0x200`, so it ends exactly
where the certificate table begins at file offset `0x7E00`. Add anything to `.reloc` and the certificate
table moves, which changes the certificate directory value and the file checksum — three fields for one
edit.

## Step 2: byte-level diff, folded into runs

Diff the two files as byte ranges and report **runs**, not bytes: `offset`, `length`, which section the
offset falls in, and an entropy or printable-ratio reading for each run. A run inside a code section is
a candidate routine change; a long run of printable bytes inside a data section is usually a string or
resource change; a run confined to the header region is a build-metadata change.

Fold the result before reading it. A raw byte diff of two builds of a real program is thousands of runs,
and a report nobody can read produces no conclusion. Group runs by section, sort by length, and keep the
complete list in a file whose path you report — the same summary-first discipline the rest of this
project uses for large tool output.

Two traps in this step:

- A one-byte change can be a jump displacement that moved because an unrelated byte earlier in the same
  function changed length. The displacement change is real but is not the change; read the run in
  context before writing it into a report.
- A region can differ purely because a resource was recompressed or a string table was reordered. Check
  whether the changed bytes are referenced by code at all before treating them as behaviour.

## Step 3: locating the routine that changed

Order these by cost, and stop as soon as one answers.

1. **Names, if you have them.** A PDB path in the debug directory points at a symbol file; a matching
   GUID and age means that symbol file describes this build. With symbols, the diff is a list of function
   names, which is the whole problem solved.
2. **Function extents from the exception directory.** On 64-bit images, data directory 3 is populated
   and its data lives in the section named `.pdata` (`observed`: the Go sample built here reports
   `dir[3] exception rva=0x1C8000 size=0x4020` and a `.pdata` section with virtual size `0x4020`). If
   the directory describes per-function ranges — a property to verify on your target, since the
   specification copy available here does not detail the entry layout — then a changed run can be
   attributed to the function that contains it without any disassembly.
3. **Signature scanning across the two builds.** Take a byte pattern that identifies the routine in
   build A, scan for it in build B, and compare the two matches. This is the same technique the
   signature routes use, run for localisation rather than for patching: `aob-and-signatures.md`.
4. **Call-graph comparison.** Where nothing else localises the change, compare the set of call targets
   reachable from the code you care about. A function that gained or lost a caller is a smaller search
   space than the whole section.

## Step 4: signatures plus diff, when the build is stripped

A stripped build and a modified build fail differently, and the difference is the diagnosis.

- The pattern is **absent** from build B, and the surrounding code is unrecognisable: the routine was
  rewritten or removed. Widen the pattern to the stable prefix and suffix, then re-scan.
- The pattern is **absent**, but a near variant exists: the bytes around a constant changed. Reduce the
  pattern to the invariant instructions and re-derive the site.
- The pattern matches **more than once**: the pattern is not unique enough to be a patch site, and
  patching the first match is how a very bad artifact gets built. `scripts/aob_scan.py` and the patching
  route both refuse an ambiguous match, and so should you.

The diff's contribution here is scope: it tells you which section to scan and which of two candidate
matches the change actually touched.

## Step 5: overlays, appended data and modified inputs

Bytes after the last section are not part of any section and, per the specification's Authenticode
appendix, are outside the signed hash — they are also outside what a section-level diff will show you.
Compare the overlay as its own region. It is where installer payloads, embedded archives and
per-build configuration live, and a difference there explains behaviour changes that no code diff
accounts for.

One more question belongs in this step: **is either build a build someone else modified?** A circulating
"cracked" or repacked copy is frequently re-protected, and comparing against it measures the packer as
much as the program. Identify both inputs before treating either as a baseline.

## What a diff cannot tell you

| It cannot | Because |
|---|---|
| Which build is newer | Nothing in the file orders the two builds once timestamps are hash-derived |
| Why something changed | A byte range is an observation; authorship and motivation are not in the file |
| That the change is reachable | A modified routine may be dead code, or behind a branch that is never taken on your host |
| That the change matters | Compiler version, inlining decisions, optimisation level, code layout and PGO all produce diffs with identical behaviour |
| That two different builds are the same program | A diff measures difference; establishing "same program" needs identity evidence, not similarity |
| Whether a feature is server-side | The diff is entirely local, and the layer question is answered by recon and by network observation |

When you report a diff, report it as a change list with its scope, plus the explicit statement that the
change list is not a cause list. Then hand the layer and verification questions to the routes that own
them: `recon.md` for what the binary is, `verification.md` for whether a change you made did anything.
