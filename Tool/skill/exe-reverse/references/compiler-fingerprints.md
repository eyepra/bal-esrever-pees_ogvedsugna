# Compiler fingerprints: identifying the toolchain, and what the identity changes

Goal: say which toolchain produced a binary, with the observation behind the claim separated from the
inference drawn from it, and name what that identity changes about the analysis route.

## When to load this

Load this when the compiler is unknown and the tool choice depends on it; when the call structure looks
wrong for the language the strings suggest; when a binary is unexpectedly large for what it does; when
symbols exist in a stripped-looking file; when the timestamp cannot be a date; when imports resolve to a
single runtime module; and before proposing a patch whose viability depends on how the code was built.

The recurring trap in this topic is repeating a fingerprint as though it were measured. Every row below
is therefore split into **what is observed from the file**, **what may be inferred**, and **what it
changes**. Claims marked `unverified` were not reproduced on any sample available on this host, and are
flagged as needing verification rather than being quietly asserted.

## The rule that governs the whole file

A fingerprint is a **default of a build system**, not a property of a language. A binary written in one
language is routinely produced by another language's linker, and a project can set flags that erase the
usual markers (`inferred` from the fact that every layer below is configurable: linker, runtime
library, symbol emission, and packing). Calibrate on samples whose toolchain you know before you apply
any table row to an unknown target.

Three fingerprints survive most builds and are worth checking first.

- The **linker version** pair in the optional header (`MajorLinkerVersion` at offset 2,
  `MinorLinkerVersion` at 3) is written by the linker, not the language.
- The **runtime import set** names the language or framework runtime the program actually needs.
- The **debug directory** and its CodeView record carry a symbol-file name and a build-time GUID
  (`pe-structure.md`, "The debug directory and the PDB path").

Two further fingerprints are read from instructions rather than from headers: whether the frame,
the register use and the epilogue match a compiler at all, and whether floating-point work went
through the x87 stack or through SSE. `references/assembly-idioms.md` carries the shapes and what each
one changes about reading the routine; both are `inferred` until a second signal confirms the toolchain.

## MSVC

**Observed.** This host's system images were built by Microsoft's toolchain: `notepad.exe` and
`kernel32.dll` both report linker `14.38`, machine `0x8664`, `SizeOfOptionalHeader` 240, and four debug
directory entries of types 2, 13, 16 and 20; both carry a Rich Header with a per-file XOR key
(`0xD452EC34` on `notepad.exe`), and both carry a type-16 reproducibility entry
(`pe-structure.md`, "The Rich Header" and "The debug directory and the PDB path").

**Inferred.** A linker-major version in the 14.x range indicates a modern Visual C++ build line;
the Rich Header's presence indicates a Microsoft-produced image, since the region is emitted by that
toolchain and is absent from the others listed below. Neither inference names a language: a C++ and a C
project linked the same way look alike here.

**What it changes.** The runtime import set is the useful part: a dependency on the versioned C runtime
and the versioned C++ runtime (both present on this host as `vcruntime140.dll` and `msvcp140.dll`,
`observed` by path existence) indicates a C/C++ build whose exceptions and STL use the matching
runtime. Symbol names in `.pdb`-style C++ mangling, RTTI records, and a `.pdata` array covering every
non-leaf function give you function extents for free — read the exception directory before
disassembling (`references/static-analysis.md` reads it as a function table), because it bounds
functions the disassembler will otherwise join.

**The timestamp caution.** A `/Brepro`-style deterministic build writes a hash into date/time fields, and
the file declares that with a debug entry of type 16. The specification's wording is explicit that such
stamps "no longer represent the actual date and time" (`pe-structure.md`, quoting the specification).
Using such a stamp to order two builds is an error that produces plausible, wrong version ordering.

## MinGW and other GCC-family Windows builds

**Observed on this host, negatively.** A GCC installation is present (`C:\MinGW\bin\gcc.exe` reports
`gcc.exe (MinGW.org GCC-6.3.0-1) 6.3.0`) but it cannot produce a sample: compiling anything that
includes a standard header fails with `stddef.h: No such file or directory`, and linking fails with
`cannot find crtbegin.o: No such file or directory` and `cannot find -lgcc`. The coverage limit is that
installation, not the toolchain family.

**Unverified** (must be checked against a real sample before being relied on): the GCC-family markers
usually described are a separate language-runtime DLL dependency where the C++ library is used, name
mangling that differs from the Microsoft scheme, and the absence of the Rich Header region. Treat each
as a hypothesis to test, not a fact to cite.

**What it changes if confirmed.** Symbol handling is the practical difference: a GCC-family build often
keeps a symbol table and DWARF debug sections where an MSVC release build does not, which changes
whether you start from names or from a signature search. `pe-structure.md` documents a real case of
DWARF debug sections appearing in an executable image under names that only resolve through the COFF
string table — the same class of build habit.

## Go

**Observed**, on a hello-world built on this host with the toolchain present at
`C:\Program Files\Go\bin\go.exe`, `go version go1.22.5 windows/amd64`, module-mode build:

- 1989632 bytes for a program that prints one line. The size is the fingerprint.
- 15 sections, of which seven are named `/4`, `/19`, `/32`, `/46`, `/65`, `/78`, `/90`, resolving
  through the COFF string table to `.zdebug_abbrev`, `.zdebug_line`, `.zdebug_frame`,
  `.debug_gdb_scripts`, `.zdebug_info`, `.zdebug_loc`, `.zdebug_ranges`.
- `.symtab` present with raw size `0x15000`; `PointerToSymbolTable=0x1D0C00` and
  `NumberOfSymbols=0x80F`, both non-zero in an image, which the specification says should not happen.
- Section characteristics `0x42100040` on the data sections, i.e. a non-zero value in the
  object-files-only bits-20–23 alignment field.
- Data directories limited to import, exception, base relocation and IAT — no export, no TLS, no load
  configuration, no CLR.
- The string `go:buildid` occurs 2 times and `runtime.` 3321 times in the file.
- The toolchain inventory is readable from the binary itself without symbols: `go version -m` on the
  sample reported `go1.22.5`, `path obs`, `build -buildmode=exe`, `-compiler=gc`, `CGO_ENABLED=0`,
  `GOARCH=amd64`, `GOOS=windows`, `GOAMD64=v1`.

**Inferred.** The presence of runtime symbol names plus a symbol table means a Go build gives you a
richer static surface than an MSVC release build — names for its own functions, and a runtime whose
entry path is not the C runtime start-up a native debugger expects. The scheduler and goroutine
machinery mean the call graph you reconstruct is dominated by runtime plumbing rather than by the
program's own functions.

**What it changes.** Do not start by reading the entry point. Start from the strings and the symbol
table, then from the runtime's own function names, and expect concurrency machinery between your
breakpoint and the code you want. A hex patch is still possible, but any patch that assumes a C-style
stack frame and a single-threaded call path is a guess.

**Not established here:** the exact meaning of the individual compressed debug section names in this
toolchain's output, and whether every Go version emits the same section set. That is `unknown`; the
search run was a single 15-section dump of one binary from one version.

## Rust

**Not observed.** `rustc` is not on `PATH` on this host, no Rust installation directory exists under the
common locations checked, and no candidate sample was found in the application directories searched.
The coverage limit is this host's inventory; "no Rust sample was available" is not "Rust binaries look
like this".

**Unverified**, and to be tested against a real sample: static linking with the runtime included,
panic and formatting strings in the data sections, mangled symbol names distinct from both the
Microsoft and GCC-family schemes, and a large read-only data section. No claim about Rust is made in
this file beyond that list.

## Delphi and Object Pascal

**Not observed.** No Delphi compiler is on `PATH` on this host and no sample was identified, so
everything here is `unverified` and needs verification against a real binary: a small runtime import
surface, a distinctive string-literal encoding, a linker version value unrelated to the Microsoft
sequence, and vendor-specific section naming. Do not apply any of it as a conclusion.

**What it changes if confirmed:** the string encoding and the calling convention are the two things that
make hand-reading unfamiliar, so establish the convention from a function you can confirm before
trusting a decompiler's parameter list.

## Visual Basic 6

**Not observed.** The runtime module a VB6 program typically requires is not present on this host (the
expected system-directory filenames were checked and are absent), so no sample exists here to measure.
**Unverified**, needing verification against a real sample: an import list dominated by a single
language-runtime DLL alongside a few Win32 calls, a small entry stub, and vendor-specific structures in
the executable. Verify the exact runtime module name from the sample's own import table rather than
from memory.

## .NET assemblies

**Observed** on
`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\6.0.12\System.Runtime.dll`: optional-header magic
`0x10B` (PE32), 42632 bytes, data directories present for import, resource, certificate, base
relocation, debug, IAT and **CLR (index 14, `rva=0x2008 size=0x48`)**, a certificate table at file
offset `0x7E00` with size `0x2888` ending exactly at the file length, and a `.text`/`.rsrc`/`.reloc`
section set with no export directory, no TLS and no load configuration.

**Inferred.** A non-empty CLR data directory is the definitive structural marker of a managed assembly
in this reconnaissance (`inferred` from the specification's data-directory table plus the observation
above); the file is still a normal PE, which is why a PE-only triage reports plausible but useless
sections. Hex-patching IL and metadata does not behave like patching native code: the metadata tables
record sizes, offsets and token counts that a byte edit does not update.

**What it changes.** Take the managed route (`managed-dotnet.md`) rather than a hex editor. The CLR
header points at metadata and the IL stream, and the useful reconnaissance is metadata-level: type and
method names, member references, and the resource that usually holds the licence text.

## Packing and compression layers that hide all of the above

**Observed behaviour worth naming:** any of the fingerprints above can be destroyed without changing the
language. Packing replaces the sections and the import table; compression inside a data section hides
strings. What remains is a header whose linker version and rich region describe the *packer's* build,
not the program's.

**What it changes.** A toolchain verdict taken from a packed file is a verdict about the stub. Record the
verdict as `unknown` for the real code and mark the packed-file observation, then follow
`protectors-and-packers.md` and re-run the identification after unpacking — the unpacked image is a new
target with its own fingerprints, and the fingerprints in the packed original tell you about whoever
packed it.

## Reporting a fingerprint

State the observation, the inference and the confidence separately, and never merge them:

```
toolchain: <name or unknown>
observed:  linker=14.38  debug_types=[2,13,16,20]  rich_key=0x...  dirs=[import,resource,...]
inferred:  Microsoft toolchain; C/C++ runtime in use  (confidence: medium)
unverified: <anything repeated from habit rather than measured on this sample>
counter:   the one observation that would overturn the inference
```

The counter line is the point. A fingerprint without it is an impression, and an impression about a
toolchain leads directly to the wrong tool (`static-analysis.md`).
