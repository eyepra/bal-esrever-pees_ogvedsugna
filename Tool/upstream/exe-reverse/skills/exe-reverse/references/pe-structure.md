# PE structure: the layout a patcher actually depends on

Goal: know which bytes at which offsets define the loader's view of an image, and which of those fields
a naive reader gets wrong, before any edit is written.

## When to load this

Load this when you compute an offset by hand; when two tools disagree about the same file; when a
breakpoint at the entry point is never hit; when a patch is in the file but not in effect; when a length
change is considered; when a signature, checksum or update check now rejects the binary; when you must
decide whether a data-directory value is an RVA or a file offset; and whenever a memory dump has to be
mapped back to file bytes.

The authority for every field value, flag and offset below is the Microsoft PE format specification,
published as part of the platform's own documentation and cited here as "the specification". Values
marked `observed` were measured on this host and name the file.

## Two distinctions that decide everything

**PE32 against PE32+.** The optional-header magic is `0x10B` for a normal PE32 image and `0x20B` for
PE32+ (`0x107` is a ROM image; specification, Optional Header Standard Fields). PE32 has a `BaseOfData`
field at offset 24 that PE32+ lacks, so every later field sits 4 bytes earlier in PE32+ and the data
directories begin at **96** in PE32 and **112** in PE32+ (`observed`: a parser using those two bases
reads `C:\Windows\System32\notepad.exe` and `kernel32.dll` — both PE32+, with `SizeOfOptionalHeader`
240 = 112 + 16·8 — and a PE32 .NET assembly below, without misframing a field).

**RVA against file offset.** An RVA is relative to the image base after loading; a file offset is a
position on disk. The specification states that an RVA "almost always differs from its position within
the file on disk". Each field must be read as the right kind, and exactly one data directory is not an
RVA.

## DOS header and the offset to the PE header

The image begins with an MS-DOS stub. At file offset **0x3C** a 4-byte field holds the file offset of
the PE signature (specification, MS-DOS Stub; named `Offset to PE Header` there, `e_lfanew` in the
structures tooling uses). At that offset sit the bytes `PE\0\0`, and the PE header is 8-byte aligned.
The field is a file offset to the **signature**, so the COFF file header starts at that value + 4. The
stub is replaceable — the specification notes the default stub prints "This program cannot be run in DOS
mode" and that a different one can be supplied at link time — so an altered stub string is not evidence
of tampering.

## COFF file header

Field order and sizes from the specification's COFF File Header table; these offsets parse real system images correctly (`observed`).

| Offset from signature | Size | Field | What it decides |
|---|---|---|---|
| +4 | 2 | Machine | Architecture: `0x14c` i386, `0x8664` AMD64, `0xaa64` ARM64 (specification machine-type table) |
| +6 | 2 | NumberOfSections | Size of the section table. The loader limits this to 96 per the specification; a tool that reads more than declared mis-frames everything after the headers |
| +8 | 4 | TimeDateStamp | Not a date when a reproducibility marker is present (see "The debug directory and the PDB path") |
| +12, +16 | 4 each | PointerToSymbolTable, NumberOfSymbols | Should be zero for an image; non-zero is a real shipped case (see "Long section names and the string table") and together they locate the COFF string table |
| +20 | 2 | SizeOfOptionalHeader | Must bound any probe into the optional header; the specification says so because the optional header is not fixed in size |
| +22 | 2 | Characteristics | `0x0002` executable image, `0x2000` DLL, `0x0020` large-address-aware, `0x0001` relocations stripped (specification characteristics table) |

`IMAGE_FILE_RELOCS_STRIPPED` (`0x0001`) matters before you plan a dump or rebase: the specification says
such an image "does not contain base relocations and must therefore be loaded at its preferred base
address", and that stripping is the linker's default for executables.

## Optional header: PE32 against PE32+

Offsets are relative to the start of the optional header, read from the specification's two field tables.

| PE32 / PE32+ | Size | Field |
|---|---|---|
| 0 | 2 | Magic (`0x10B` / `0x20B`) |
| 2 | 1 | MajorLinkerVersion |
| 3 | 1 | MinorLinkerVersion |
| 4–15 | 4 each | SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData (derived totals) |
| 16 | 4 | AddressOfEntryPoint |
| 20 | 4 | BaseOfCode |
| 24 / — | 4 | BaseOfData (PE32 only) |
| 28 / 24 | 4 / 8 | ImageBase |
| 32 | 4 | SectionAlignment |
| 36 | 4 | FileAlignment |
| 40–51 | 2 each | OS, image and subsystem version fields: major/minor pairs at 40/42, 44/46 and 48/50 |
| 52 | 4 | Win32VersionValue (reserved, must be zero) |
| 56, 60 | 4 each | SizeOfImage, SizeOfHeaders |
| 64 | 4 | CheckSum |
| 68 | 2 | Subsystem |
| 70 | 2 | DllCharacteristics |
| 72 / 72, 76 / 80 | 4 / 8 | SizeOfStackReserve, SizeOfStackCommit |
| 80 / 88, 84 / 96 | 4 / 8 | SizeOfHeapReserve, SizeOfHeapCommit |
| 88 / 104, 92 / 108 | 4 each | LoaderFlags (must be zero); NumberOfRvaAndSizes |
| 96 / 112 | — | first data directory |

`DllCharacteristics` values worth reading before planning work: `0x0020` high-entropy VA, `0x0040`
dynamic base (relocatable at load time), `0x0080` force integrity, `0x0100` NX compatible, `0x4000`
Control Flow Guard (specification DLL characteristics table). Guard changes what a hijacked indirect
call does at run time, so its state belongs in the recon record.

## Data directories

Each entry is 8 bytes: a 4-byte `VirtualAddress` (normally an RVA) and a 4-byte size. The count is
`NumberOfRvaAndSizes`, which the specification says to use when bounding a probe. Order: 0 export,
1 import, 2 resource, 3 exception, 4 certificate, 5 base relocation, 6 debug, 7 architecture,
8 global pointer, 9 TLS, 10 load configuration, 11 bound import, 12 IAT, 13 delay import, 14 CLR,
15 reserved.

### The one directory that holds a file offset

Directory 4, the certificate table. The specification states it outright: the certificates "are not
loaded into memory as part of the image. As such, the first field of this entry, which is normally an
RVA, is a file pointer instead."

`observed`: the .NET assembly
`C:\Program Files\dotnet\shared\Microsoft.NETCore.App\6.0.12\System.Runtime.dll` is 42632 bytes
(`0xA688`) with a certificate entry of `file_offset=0x7E00 size=0x2888`, and `0x7E00 + 0x2888 = 0xA688`,
exactly the file length. A reader that treats `0x7E00` as an RVA maps it through the section table and
lands in an unrelated part of `.text`.

### The one table whose entries contain file offsets

The debug directory (index 6) is a normal RVA-addressed array, but each 28-byte entry carries
`PointerToRawData`, a **file offset**, to its debug data. `observed` on that same assembly: the directory
is at RVA `0x9164` (file offset `0x7364`, inside `.text`) and its CodeView entry points to raw data at
`0x739C`, also inside `.text` — not after the certificate.

## The section table

Placed at the signature + 24 + `SizeOfOptionalHeader`; 40 bytes per entry, in the specification's order.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Name |
| 8 | 4 | VirtualSize |
| 12 | 4 | VirtualAddress |
| 16 | 4 | SizeOfRawData |
| 20 | 4 | PointerToRawData |
| 24–35 | — | PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers (all zero in images) |
| 36 | 4 | Characteristics |

RVA to file offset, for RVA `r` in section `s`:

```
if (r >= s.VirtualAddress && r < s.VirtualAddress + max(s.VirtualSize, s.SizeOfRawData))
    file_offset = s.PointerToRawData + (r - s.VirtualAddress)
```

The conversion is only valid while the delta is below `SizeOfRawData`. Two ways to get it wrong: using
`VirtualSize` alone as the section extent makes you refuse an RVA that does have bytes on disk, because
`SizeOfRawData` is the rounded field and can be **greater** than `VirtualSize` (the specification says
exactly that); and not checking the raw range at all lets you compute an offset into the virtual tail.

Characteristics you will decode: `0x00000020` code, `0x00000040` initialised data, `0x00000080`
uninitialised data, `0x02000000` discardable, `0x20000000` executable, `0x40000000` read, `0x80000000`
write (specification section characteristics table).

### Bits 20–23 of Characteristics are one field, not four flags

`IMAGE_SCN_ALIGN_1BYTES` (`0x00100000`) through `IMAGE_SCN_ALIGN_8192BYTES` (`0x00E00000`) occupy bits
20–23 as a single 4-bit index, and the specification marks each "Valid only for object files". They are
not independent bits. The same four-bit field is defined again in the TLS directory, where the
specification describes it as "The four bits [23:20]" (The TLS Directory). It is also not reliably zero
in a shipped image: `observed`, the Go 1.22.5 hello-world built during this recon pass carries
`characteristics = 0x42100040` — `IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE |
IMAGE_SCN_CNT_INITIALIZED_DATA` plus a bits-20–23 value of 1 — on seven sections. Report the whole field
value; do not fan it out into flags.

### The virtual-only tail

`SizeOfRawData` is initialised bytes on disk, `VirtualSize` the size when loaded; when the former is
smaller the specification says the remainder is zero-padded. An RVA beyond the raw range but inside
`VirtualSize` has **no bytes in the file**: a write to that RVA lands past the section's data, and a
section reported as "N bytes" from `VirtualSize` is not N indexable bytes. Zero-initialised globals
normally live here, the ordinary explanation for a large `VirtualSize` beside a small `SizeOfRawData`.

## The checksum

`CheckSum` is at optional-header offset 64 in both layouts. The specification says the algorithm "is
incorporated into IMAGHELP.DLL" and that it is validated at load time for all drivers, any DLL loaded at
boot time, and any DLL loaded into a critical Windows process. That is the whole documented scope: an
ordinary user-mode executable is not checksum-validated by the loader, so a stale checksum there is
usually cosmetic, while a stale checksum on a driver is not.

Two facts that are easy to get backwards. The specification's Authenticode appendix states that the
`CheckSum` field is **excluded** from the Authenticode image hash, so recomputing it does not break a
signature; and the checksum itself "includes the entire file (including any attribute certificates in
the file)". The two cover different ranges, and repairing one does not repair the other. This
repository's patching script recomputes the checksum after an edit and reproduces the declared checksum
on unmodified `notepad.exe`, `kernel32.dll` and `ntdll.dll` (recorded in `PROJECT-CONTEXT.md`).

## The certificate table and Authenticode

The attribute certificate table is a set of quadword-aligned entries at the end of the file; each entry's
`dwLength` advances to the next after rounding up to an 8-byte multiple, and the rounded lengths must sum
to the directory size (specification, The Attribute Certificate Table). The specification also requires
the certificate table and debug information to be at the very end of the file "with the attribute
certificate table immediately preceding the debug section", because the loader does not map them.

Authenticode hash coverage decides which edits break a signature. Per the specification's appendix: all
data in the sections listed in the section table is hashed in its entirety except the `CheckSum` field,
the Certificate Table data-directory entry, the certificate table and its certificates, and
**information past the end of the last section**, which the appendix notes commonly contains debug
information. An edit inside a section therefore invalidates the signature — including removal of debug
information that lives inside one — while bytes appended after the last section and the checksum field
are outside the hash. That does not make appending harmless: it changes the file checksum and violates
the end-of-file layout rule if it lands after the certificate table. Strip or replace a signature
deliberately and record that you did; whether the target checks its own signature at run time is a
separate question with its own route (`integrity-checks.md`).

## TLS callbacks

Directory 9 points at the TLS directory; layout from the specification's TLS Directory table:
`Raw Data Start VA` at 0 (4/8 bytes), `Raw Data End VA` at 4/8, `Address of Index` at 8/16,
`Address of Callbacks` at 12/24, `Size of Zero Fill` at 16/32, `Characteristics` at 20/36. The first two
are **VAs, not RVAs** — the specification says so for both and adds that the start address should have a
base relocation in `.reloc`. `Address of Callbacks` points to a null-terminated array of function
pointers, and each callback takes the same parameters as a DLL entry point (`DllHandle`, `Reason`,
`Reserved`). This is the mechanism behind the symptom "a breakpoint at the entry point is never hit, yet
the process runs": code reached from here is not reached through the entry point.

The ordering claim that these callbacks run before the entry point is widely repeated and is **not** in
the specification copy available here. Treat it as `unverified` for your target and settle it there:
break at the callback and at `AddressOfEntryPoint`, and read the order you observe.

## The Rich Header

Present in many images from the Microsoft toolchain and **not described in the specification** — there is
no match for it in the copy here, so this is `observed` on one file and must be reproduced before it is
relied on. `observed` on `C:\Windows\System32\notepad.exe`: the bytes `Rich` at file offset `0xE8`,
followed by a 4-byte key (`0xD452EC34`); XOR-ing the earlier 4-byte words with that key makes `DanS`
appear at offset `0x80`, and the words between `DanS` and `Rich` decode to 32-bit pairs. Decoding those
pairs into vendor, product and usage counts is a third-party convention: `unverified` here, needing
calibration against a second file with a known toolchain before it is quoted. Safe to say: the region
exists, it is XOR-obfuscated with the key stored beside `Rich`, and it survives stripping better than the
linker version field does.

## The debug directory and the PDB path

Directory 6 addresses an array of 28-byte entries: `Type` at offset 12, `SizeOfData` at 16,
`PointerToRawData` at 24. The specification's type table includes `2` CodeView, `16` PE
determinism/reproducibility and `20` extended DLL characteristics.

`observed` on `notepad.exe` and `kernel32.dll`: four entries, types 2, 13, 16 and 20. The CodeView raw
data was 36 bytes and decoded as the 4 bytes `RSDS`, 16 bytes of GUID, a 4-byte age of 1, then a
NUL-terminated path:

```
origin: debug directory, CodeView entry, C:\Windows\System32\notepad.exe
raw:    52534453 | 16 bytes GUID | 01 00 00 00 | "notepad.pdb" 00
```

The signature, field order and path are `observed` on these files; the CodeView container is not
documented in the specification copy here, so treat `RSDS` as observed rather than documented. Type 13
appears in both files and its meaning is **not** in the type table — do not guess it.

Type 16 changes how you read everything else. The specification says an entry of type
`IMAGE_DEBUG_TYPE_REPRO` "indicates the PE file is built in a way to achieve determinism or
reproducibility", that identical input yields a bit-for-bit identical file, and that "various date/time
stamp fields in the PE file are filled with part or all the bits from a calculated hash value ... and
therefore no longer represent the actual date and time". `observed`: `notepad.exe` carries
`TimeDateStamp=0xDBDAC69B` and `kernel32.dll` `0xF304CEE4`, both with a type-16 entry present. Neither is
a build date, and any version or build-order argument resting on those numbers is invalid.

## Long section names and the string table

The specification says a section `Name` holding a slash followed by a decimal number is an offset into
the string table, then states the consequence for images: "Executable images do not use a string table
and do not support section names longer than 8 characters." Real builds do not all obey that. `observed`
on the Go 1.22.5 hello-world built on this host: 15 sections, seven named `/4`, `/19`, `/32`, `/46`,
`/65`, `/78`, `/90`; `PointerToSymbolTable=0x1D0C00` and `NumberOfSymbols=0x80F`, so the string table
begins at `0x1D0C00 + 18·0x80F = 0x1D9D0E` (a symbol table record is 18 bytes per the specification).
Resolving those names yields `.zdebug_abbrev`, `.zdebug_line`, `.zdebug_frame`, `.debug_gdb_scripts`,
`.zdebug_info`, `.zdebug_loc` and `.zdebug_ranges` — compressed DWARF sections. The spec-literal reader
prints `/4` and concludes nothing; the correct answer needs the object-file rule the specification says
images do not use.

So: if a name starts with `/` and a string table exists at the computed offset, resolve it and say so;
otherwise report the raw 8 bytes and mark the reading ambiguous. Never invent a decoded name.

## Base relocations

Directory 5 holds blocks. Each block starts with a 4-byte `Page RVA` and a 4-byte `Block Size` covering
the two header fields and everything after them, then a run of 2-byte entries whose high 4 bits are the
`Type` and whose low **12** bits are an offset from the block's page RVA (specification, Base Relocation
Block). Types you will meet: `0` `ABSOLUTE` (padding), `3` `HIGHLOW`, `10` `DIR64` (specification base
relocation type table). Blocks are page-granular.

Stripped relocations imply that the loader must honour the preferred base, that a dump cannot be made
loadable by adjusting a field, and that any technique depending on the image being mapped elsewhere has
no support in the file. No `.reloc` on a `DLL` is a strong signal of a stripped link.

## Where a naive reader gives a wrong answer

| Situation | The wrong answer | The right reading |
|---|---|---|
| Certificate value `0x7E00` | "an RVA; map it through the sections" | A file offset; here it points at the file's last 10376 bytes |
| Debug entry `PointerToRawData` | "an RVA" | A file offset inside a table whose own address is an RVA |
| Section extent from `VirtualSize` only | "no bytes on disk for that RVA" | Use `max(VirtualSize, SizeOfRawData)` for extent, `SizeOfRawData` for the writable range |
| Characteristics bits 20–23 tested one by one | "four flags" | One 4-bit index, object-files-only per the specification, and non-zero in real images |
| `TimeDateStamp` read as a date | "built on <date>" | Not a date when a type-16 debug entry is present |
| TLS `Raw Data Start VA` taken as an RVA | "an address inside the image" | A VA, which the specification says should carry a base relocation |
| Checksum repaired after signing | "the signature is valid again" | The checksum is outside the Authenticode hash; the edited bytes broke the signature |
| Appending bytes after the last section | "the signature is now invalid" | Past-the-end data is outside the Authenticode hash, inside the file checksum, and possibly in violation of the end-of-file layout rule |

## What this file cannot tell you

Structure is not behaviour: which routine owns a decision, whether a path is ever taken, and whether a
check is enforced at run time all need `static-analysis.md` and then a debugger or a trace. A correctly
located byte is only located — prove the artifact under test is the one you built (`verification.md`).
