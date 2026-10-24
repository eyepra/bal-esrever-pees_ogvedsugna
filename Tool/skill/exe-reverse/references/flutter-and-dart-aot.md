# Flutter and Dart AOT snapshots

Goal: recognise a Flutter application from its file layout, find the layer that actually holds the
behaviour, and know exactly how far a static pass can get before it needs version-matched tooling.

## When to load this

Load this when a target ships `flutter_windows.dll`, when a directory contains a large
`data/app.so` beside a small launcher executable, when `strings` on a Windows binary starts
returning Dart class names, or when an installer has been extracted and the payload contains a
`flutter_assets` tree. The symptom index routes "the target is a .NET assembly and hex-patching it
does nothing" and "strings you expect are absent" here when the artifact turns out to be neither
native C++ nor managed.

A Flutter desktop application is the one common shape where the ordinary Windows workflow inverts:
there is no meaningful native code to patch, no import table worth reading, and no symbol table,
and the behaviour you were asked to change is in a compiled Dart snapshot.

## The shape, measured

Everything in this section was measured on one shipping application: a 31,059,248-byte Inno Setup
installer, extracted with `innoextract`, whose payload contained a 26,821,600-byte
`app/data/app.so`. `observed`.

| Property | Value | What it means |
|---|---|---|
| Container of the download | Inno Setup 6.1.0, unicode | The download is an installer, not the program. Extract before analysing (`installers-and-packaging.md`) |
| The launcher beside the engine | 73.6 KiB | A launcher. It starts the engine and does nothing interesting |
| `data/app.so` | 26.8 MB, **ELF64, x86-64, ET_DYN** | The compiled Dart. An **ELF** shared object inside a Windows application |
| `.text` | 16.7 MB, flags `0x6` (alloc + execute) | The AOT-compiled Dart code |
| `.rodata` | 10.1 MB | Read-only data: string literals, constants, metadata |
| `.dynsym` | 144 bytes | Six symbols. The image is stripped of everything useful |
| `.eh_frame` | 66 bytes | No unwinding data, so a stack walk gives you nothing |
| relocation sections | **none** | No `.rela.dyn` or `.rela.plt` at all |
| `.rodata` strings | reconstructed by offset | Literals survive AOT compilation and are readable |

Two consequences follow immediately, and both are the opposite of a native target:

**You cannot patch the code without understanding the snapshot format.** The Dart compiler emits
its own object layout, and an edit that changes a byte in `.text` is an edit to compiled Dart with
no symbols, no types and no function boundaries you can trust.

**The launcher is not the program.** Patching the small launcher executable achieves nothing; it is
an engine bootstrap. This is the desktop analogue of the mistake of patching a dex loader instead
of the loaded code.

## How references work, and why the obvious method fails

The natural first move for a stripped binary is: find a string, then find the instruction that
loads its address. On this image that method returns a confidently wrong answer, and the
measurement is worth recording because a plausible-looking negative is worse than no answer.
**A byte scan over `.text` reports instruction shapes that are not there, and the way it fails is
worth recording in full**, because every step of it looked like evidence.

Three models were tried against this image, and two were disposed of by measurement before the third
was believed:

| Model | What was measured | Verdict |
|---|---|---|
| a self-relative load, `mov r64, [rip+disp32]`, whose displacement names the literal | a few hundred byte-pattern hits, **none** landing in the read-only data | refuted, wrongly read as "this image does not reference its data that way" |
| a table of absolute addresses in the data section | **no** run of 8-byte words pointing into the image, across all 10 MB | refuted |
| a compressed-pointer pool: 4-byte tagged values inside the data section | a contiguous run of 97,751 such values, 100% in range against a 0.23% random baseline, slots that appeared to name literals once a tag bit was cleared | **believed, and wrong** |

The third model produced the kind of result that is easiest to accept, and a real disassembler
disposes of it in two lines (`observed`; capstone, installed on this host):

| Measurement | Result |
|---|---|
| `mov r15, imm64` found by byte pattern, immediates examined | nine, whose "immediates" are plainly other instructions (`0xF8458B48C1894800` decodes as `mov rcx, rax; mov rax, [rbp-8]`) -- the pattern matched *inside* operands |
| genuine writes to `r15`, decoded at real instruction boundaries | **zero** |
| `[r15 + disp]` operands, decoded at real instruction boundaries | **zero** |

The cause is structural rather than a coding slip. A byte pattern over variable-length code has no
notion of where instructions begin, so it matches inside operands and inside data. `.text` here also
opens with zero padding and the ELF entry point is **0**, because this artifact is a shared object
rather than a program, so there is no address from which a reliable sweep can start. The earlier
counts were measuring the scanner, not the image.

**What survives, and what is withdrawn.** Literal recovery is unaffected: it scans printable runs,
which needs no instruction boundaries and can be checked by eye. Every claim about *which code*
references a literal is withdrawn, and the tool no longer reports one.

**What it would be needed, and what was actually done.** Reference sites require the snapshot's own
layout parsed by tooling built for the release that produced it. `observed`: **this was reached**, and
the route is reproducible:

| Step | Command or artifact | Result |
|---|---|---|
| identify the release | the companion executable's runtime string | `3.3.4` |
| obtain a front end | a pure-Go static analyzer published with checksummed release archives; `sha256` verified against the published sums before running | 7.3 MB, no toolchain needed |
| confirm it fits | its own diagnostic subcommand | `Snapshot: OK`, `Pointers: uncompressed (8 bytes)`, features include `x64 windows` |
| run the pipeline | full analysis, 26.8 MB input | **76,477 functions, 10,102 classes**, 300 s |
| locate sites | `string_refs.jsonl` (99,504 entries, each naming function, `pc`, pool index and value) | every gate message and endpoint resolved to a function |

**Two corrections that this step forces on the earlier text.** The diagnostic reports
**`uncompressed (8 bytes)`** pointers and lists `no-compressed-pointers` among the build features, so
the "4-byte compressed pointer" model was not merely unverified but wrong in its premise. And the same
diagnostic prints a Dart version that is a **structural profile label rather than the SDK version** --
its number and the executable's runtime string disagree, which is a documented property of that tool,
so the version used for any VM-compiling step must come from the banner, never from the profile label.

**What the located sites look like.** Four gate functions that carry the feature-gate messages share
one shape, with only the message's pool offset differing (`observed`, from the emitted disassembly):

```
CALL  stub_2645ec              ; the judge: returns a bool object
TEST  AL, 0x10                 ; that object's tag bit
JE    0x…                    ; tag clear  -> the ordinary path, the feature runs
MOV   R11, [R15+0x7c0ff]       ; tag set    -> load the message
CALL  stub_b66578              ; a single shared "show it and return" routine
RET
```

**The population, not the anecdote.** One gate read by hand is a single site. The whole snapshot was
counted from the emitted disassembly, and the count is what makes the shape a mechanism rather than a
coincidence (`observed`):

| Measurement | Result |
|---|---|
| disassembly files scanned | 74,547 |
| functions containing a tag test at all | **6,530** |
| of those, `TEST AL,0x10` + `JE` | 3,247 |
| functions containing the full `judge → test → display` chain | **66** |
| functions mentioning the judge but not the display (or the reverse) | 0 |

**The first row is the trap, and it is why the count had to be run before anything was proposed.**
`TEST AL, 0x10` appears 13,625 times across 6,530 functions, because it is simply how this compiler
tests a boolean -- not a licence shape at all. A change to that instruction would have broken every
boolean comparison in the program rather than unlocking anything, and a hand-read single site would
have suggested exactly that change. What is specific to the gates is the **chain**: the judge, then
the test, then the one shared display routine, present in 66 functions and absent everywhere else.

**The judge is the leverage, and it is 120 bytes.** All 66 gates reach the decision through one
function, which delegates once more and finally applies a single `XOR RCX, 0x10` -- in this ABI the
two boolean objects sit `0x10` apart, so that instruction *is* a logical negation, and it is the same
bit the callers test. One function therefore decides for every gate, which is why the finding worth
reporting is the judge rather than the 66 call sites.

**What is settled here and what is not.** Settled: the gates are client-side, there are 66 of them,
they share one decision function, and the mechanism is a boolean whose tag bit selects between the
ordinary path and a message. Not settled by static reading: that a patched build behaves, which needs
a run.

**A statistic was used to settle the slot, and the authoritative table overturned it.** The inference
looked reasonable: the shape "compare against a slot, then load another slot" is how a null-coalescing
default compiles, one slot appeared in that shape 1,087 times against 146 for the other, and a boolean
field defaulting to false is the ordinary reading -- so `0x78` was reported as the false constant.
The snapshot front end's own thread-field table, which it validates against the language runtime's
source, says otherwise: the slots at 0x70, 0x78 and 0x80 are `object_null`, `bool_true` and
`bool_false`, and the slot the code compares against is `field_table_values`, not null at all.

**The reading survives; the reasoning for it does not.** The judge is loaded from `0x78`, which the
table names `bool_true`, so the change makes it return true rather than false -- the same conclusion
arrived at by the wrong route. Two lessons, and the second is the one worth keeping:

- a frequency argument over disassembly can point the right way and still be the wrong argument, so
  it may support a decision but cannot be the record of one;
- a runtime field table shipped by a front end that validates it against the runtime's own source is
  cheaper to consult than a statistical argument is to construct, and it should have been the first
  step rather than the correction.

**Reading a disassembly is not reading bytes, and the difference cost a wrong edit here.** The
listing rendered the decisive instruction as `JNE .+9`, which reads like a two-byte short jump. The
bytes at that offset are `0F 85 09 00 00 00` -- a **six-byte** `JNE rel32`. The listing does not
print instruction lengths, so the two are indistinguishable on the page, and an edit prepared from
the listing alone would have overwritten four bytes of the following instruction. The habit that
catches this is cheap and is worth stating as a step rather than a caution:

1. map the virtual address to a file offset from the section table, rather than assuming the two are
   equal (they are here, which is a property to read, not to assume);
2. read the bytes at that offset and compare them against what the disassembly claimed;
3. prepare an **equal-length** replacement, so nothing after the site shifts;
4. write to a **copy**, re-read the bytes from the written file, and compare the two hashes.

**The candidate edit, and its exact scope.** Six bytes at `0xC0AC37` become six no-ops, so the judge
falls through to the true constant and all 66 callers take the ordinary path. It is one instruction
in one function, equal-length, and it changes nothing about the gates themselves -- if the reading of
the mechanism is wrong, the result is a build that still gates, not a build that broke elsewhere.
**What the patch is not is verified**: it is a file that differs in six bytes, and the difference
between that and a working unlock is exactly what `verification.md` exists to measure.

**Report the finding in the right shape.** "The client decides, the gate is local, and the decision
is one small function" is the deliverable here, and it is what makes the earlier classification
question answerable with evidence instead of argument. What must not be claimed from a static read
alone is that a patched build behaves: the artifact's own integrity expectations, and any second
check, are separate questions. See `verification.md` before treating a located branch as a result.

## Locating behaviour: what works, and in what order

1. **Extract the installer first.** Everything below operates on the payload, and the payload is
   what the snapshot sits inside.
2. **Confirm the shape.** `scripts/dart_snapshot_strings.py <snapshot>` prints the section layout,
   and the layout is the identification: a very large code section, a large data section, a symbol
   table measured in bytes, and an unwinding table that is a stub. Nothing needs disassembling to
   see it, which matters because the disassembly is the part that cannot be trusted here.
3. **Recover literals and search them.** This is the step that produces real leads, because a string
   literal survives both AOT compilation and minification while names do not. It finds *printable
   runs* rather than parsed strings, so treat each hit as a lead with an offset.
4. **Read the literals as a map, not as a verdict.** On the measured target one search returned the
   three feature-gate messages, an account endpoint, a purchase flag, an upgrade-page route and a
   parse routine's name. That is enough to write a plan, and not enough to make a claim: the
   literals say the feature exists and what the product calls it.
5. **Do not expect another platform's tooling to finish the job.** Measured above: the Android
   reader for the same snapshot family returns nothing usable on this artifact. Borrow tools as
   hypotheses and count their output on one file before planning around them.
6. **What locating the referencing code needs.** The snapshot's own layout parsed by tooling built
   for the exact release that produced it. `observed`: the release here is **3.3.4**, read from a
   companion executable's runtime string because the stripped payload carries no version at all.
   Until that exists, the honest position is the one in the next section.



A reasonable next move is to borrow the Dart tooling written for Android's `libapp.so`: same
compiler, same snapshot family, so the readers should apply. **Measured, they do not**, and the
comparison is worth recording because it is cheap to re-run and expensive to assume.

The tool in question parses the snapshot's string framing directly -- entries shaped
`[tag][payload]` with the length in the tag -- and it is pure Python with no external dependency, so
it ran against this artifact unchanged (`observed`):

| Measurement | Result on a Windows payload | Its own record on an Android payload |
|---|---|---|
| candidates found | **146** | thousands; its reference case cites 4,241 strings shared with a decompiler listing |
| of those, forming a run of three or more | **0** | the normal case |
| after reading the 146 isolated candidates | all noise: ` !ӁrBO`, `yQÜxQÜwQÜuQ`, `DDDDDDDDDD` | genuine literals |

So the framing this tool relies on is not the framing this artifact uses. The layouts differ, and
"same language, same snapshot family" is not the same statement as "same container".

**What did work on this artifact** was the crude method: scanning the data sections for printable
runs, which recovered eight complete literals the framed parser never surfaced -- including the
three feature-gate messages and an account endpoint. The honest description of that method is that
it finds *printable runs*, not *Dart strings*: it has no notion of framing, so its output must be
read rather than trusted, and a hit is a lead with an offset rather than a parsed value.

**The transferable rule.** A tool written for one platform's copy of a shared format is a hypothesis
about the other platform, not a capability. Test it on one file and count the results before
building a plan on it -- the cost is one command, and the failure mode otherwise is a tool that
runs, exits zero, and returns nothing, which reads as "there is nothing there" rather than "this
reader does not fit this file".

1. **Extract the installer first.** Everything below operates on the payload, and the payload is
   what `app.so` is inside.
2. **Confirm the shape.** `scripts/dart_snapshot_strings.py app.so` prints the section layout, and
   the layout is the identification: a very large code section, a large data section, a symbol table
   measured in bytes, and an unwinding table that is a stub. Nothing needs disassembling to see it,
   which matters because the disassembly is the part that cannot be trusted here.
3. **Recover literals and search them.** `scripts/dart_snapshot_strings.py app.so --find premium,licen,vip`
   is the cheapest step that produces real leads, because a string literal survives AOT compilation
   and minification while names do not. Both one-byte (UTF-8) and two-byte (UTF-16) literals are
   recovered, because a localised application carries both.
4. **Read the literals as a map, not as a verdict.** On the measured target a single `--find`
   returned feature-gate messages that name the product's own tier system, an enum type
   (`AccountPremiumRequirementType`), a result type (`PremiumLicenseUpgradeResult`), a route name
   (`page_premium_upgrade`), a storage flag (`license_migration_notification_shown`) and a
   method name (`parseLicenses`). That is enough to write a plan and not enough to make a claim:
   the literals tell you the feature exists and what the product calls it.
5. **Then parse the pool** if you need the sites that use a literal. This needs the snapshot
   structure decoded, which means tooling built for the exact Dart release. Two public options
   exist and both are external: one is a standalone binary that reads a snapshot directly, the
   other is built from source and needs the Dart version to match. Neither is shipped here.
6. **Watch the version boundary.** A snapshot is produced by one Dart release and the tooling must
   match it. `flutter --version` from the payload, or the engine's own version string, is the
   input; a mismatched parser fails in ways that look like a corrupted file.

## The Android tooling does not transfer, measured

A reasonable next move is to borrow the Dart tooling written for Android's payload image: same
compiler, same snapshot family, so the readers should apply. **Measured, they do not**, and the
comparison is cheap to re-run and expensive to assume.

The tool in question parses the snapshot's string framing directly -- entries shaped `[tag][payload]`
with the length carried in the tag -- and it is pure Python with no external dependency, so it ran
against this artifact unchanged (`observed`):

| Measurement | Windows payload | Its own record, Android payload |
|---|---|---|
| candidates found | **146** | thousands; its reference case cites 4,241 strings shared with a decompiler listing |
| candidates forming a run of three or more | **0** | the normal case |
| reading the 146 isolated candidates | all noise: ` !ӁrBO`, `yQÜxQÜwQÜuQ`, `DDDDDDDDDD` | genuine literals |

So the framing that tool relies on is not the framing this artifact uses. The layouts differ, and
"same language, same snapshot family" is not the same statement as "same container".

**What did work here** was the crude method: scanning the data sections for printable runs, which
recovered eight complete literals the framed parser never surfaced -- the three feature-gate
messages and an account endpoint among them. Its honest description is that it finds *printable
runs*, not *parsed strings*: it has no notion of framing, so a hit is a lead with an offset and must
be read rather than trusted.

**The transferable rule.** A tool written for one platform's copy of a shared format is a hypothesis
about the other platform, not a capability. Test it on one file and count its output before building
a plan on it. The cost is one command; the failure mode otherwise is a tool that runs, exits zero and
returns nothing, which reads as "there is nothing there" rather than "this reader does not fit this
file".

**The other side of the same product.** When the same application ships an Android build, that build
belongs to the companion skill for its platform, not to this one: `apk-reverse`, when it is installed
in the same environment, reads the APK side -- its smali, its DEX, its own runtime -- and this skill
reads the Windows side. The same goes for the agent-native fast tools written for that container: a
SQL interface over the DEX and a whole-app Java decompiler with verified output both exist, both are
fast, and both read formats this skill never meets. The measurement above is exactly why that
boundary is drawn at the container and not at the language: the tooling does not cross, so neither
skill should reach into the other's file format. **What does cross is the finding, not the tool**: a
gate function located here names what to look for in the Android build of the same feature -- same
product, same tier, a different container -- and a mechanism located there narrows what to expect
here. Hand over the located addresses, the mechanism's shape and the verdict, and let the skill that
owns the container choose its own tools.

## Reaching the code at run time, which needs a different address convention

A static address is not a runtime address, and on this platform the difference is larger than an
image base. Three lookup strategies failed before the mapping was understood (`observed`):

| Attempt | Result | Why |
|---|---|---|
| module lookup by name | not found | the snapshot is not loaded as a named module |
| ELF-header scan over executable ranges | no hit | the code section is mapped **without** its file header |
| byte-signature scan at the wrong base convention | no hit | the address arithmetic assumed the base meant the file's first byte |

What the runtime actually does is map the **code section alone** into executable memory. Measured:
a region of size `0xFF3000` whose first bytes are `00 66 00 00`, matching the section's own opening
bytes and its size rounded to a page. Two consequences follow, and both are needed to place anything:

- **recognise the region by its content**, not by a header it does not have: the size is close to the
  section size and the opening bytes match the file's;
- **translate with the section's own virtual address**, not zero: a function at file vaddr `V` lives
  at `mappedBase + (V − sectionVaddr)`. Using `mappedBase + V` puts the address inside the mapping
  but not at the function, which is the failure that produced a legal-looking but unhookable address.

**And the check that makes any of it worth doing:** read the bytes at the site the edit touched, in
memory, and compare them with what was written to disk. That answers "did the edited file actually
get loaded" before anything about behaviour is observed, and it is cheap. `observed`: the region was
found, the site read back as six no-ops, and the loaded build was identified as the edited one -- so
the runtime observation that follows is about the change rather than about a stale copy.

**A negative from the same run, stated as a negative.** With the probe attached, the judge was not
reached during startup or forty seconds of idle, which is the expected result rather than a failed
one: a gate is evaluated when the gated action is attempted, not when the program opens. The probe
distinguishes that state explicitly, because "nothing was attempted" and "the gate cleared" are both
silent and only one of them means anything.

## What cannot be done from the file alone

- **No symbol recovery.** There is nothing to recover: the image is stripped by design, not by an
  accident of the build.
- **No honest function boundaries without the pool.** The Dart compiler lays out code by its own
  rules; a disassembler's guess at a function start is a guess.
- **No patch-and-run without repairing the snapshot's own integrity expectations.** A modified
  `app.so` that the engine refuses produces a startup failure, not a diagnostic. Establish the
  build's own checks before assuming a byte edit is enough.
- **No conclusion about a server-side tier.** A Flutter client renders what it is told; the
  literals above describe client-side gates, and which of them are decided locally is exactly the
  classification question in `license-mechanisms.md`.
- **Patching the launcher, the plugin DLLs or the assets.** None of them holds the behaviour. If a
  plan names one of those, the layer diagnosis is wrong.

## The handoff to the rest of this skill

Once the snapshot is understood, the ordinary questions apply again, and they are answered
elsewhere: which decision is client-side (`license-mechanisms.md`), how to observe it without a
symbol (`hardware-tracing.md`), whether the change can be proven (`verification.md`), and what a
deliverable may even be when the code is compiled Dart (`handoff-boundaries.md`).

**State the boundary out loud when reporting.** "The literals show the client names this tier, and
the decision site is inside a compiled snapshot that this repository cannot parse" is a true and
useful sentence. "The premium check is at that string" is not supported by anything in this file.
