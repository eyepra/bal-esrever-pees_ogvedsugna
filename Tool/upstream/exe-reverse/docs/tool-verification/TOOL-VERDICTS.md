# Tool Verdicts

What was verified about each tool this skill depends on or recommends, **and what is only
documentation**. Two different questions live here and they are kept apart: "is the tool present on
the machine that did this work" and "is what the skill says about the tool true".

A tool being absent from the development host is not a defect in the skill. It is the reason a
route's grade is `inferred` rather than `observed`, and it is recorded so a reader knows which rows
are plan-shaped and which are run-shaped.

## Local inventory

Measured on the development host with a path lookup and a version call. Windows 11 build 26100,
Python 3.14.

| Tool | On the host | Used for |
|---|---|---|
| Python 3.14 | present | every script |
| `git` | present | repository work |
| `gcc`, `objdump`, `strings`, `gdb` (MinGW) | present | building small C helpers, section and symbol dumps |
| `go` | present | reading a Go binary's symbols and code |
| `dotnet` | present | managed assemblies |
| `java`, `javac` | present | tools distributed as archives |
| `node`, `npm` | present | the `skills` CLI, and scriptable tooling |
| `frida` | present | runtime instrumentation |
| `wpr`, `logman`, `tracerpt`, `bcdedit` | present | OS-level event tracing and boot configuration |
| `nasm` | present | assembling small stubs |
| `curl`, `tar` | present | fetching and unpacking archives |
| A disassembler (IDA, Ghidra, Binary Ninja, Cutter) | **absent** | reading code; several are GUI-only |
| `x64dbg`, `WinDbg`, `cdb` | **absent** | interactive and command-line debugging |
| `dumpbin`, `link`/`editbin`, `signtool` (MSVC) | **absent** | header inspection and signing |
| `ildasm`, `ilasm`, `corflags` | **absent** | CIL disassembly and assembly |
| A packer/protector identifier | **absent** | shell and protector recognition |
| `procdump` | **absent** | process dumping |
| `tshark` | **absent** | capture reading |
| `cargo`, `rustc` | **absent** | building Rust tooling |
| `cl`, `msbuild` | **absent** | building from the MSVC toolchain |

The scripts treat absence as a report, not a failure: `scripts/hwprobe.py --tools` prints what is
present and names what is not, and `EXEREV_TOOLS` lets a toolchain that lives outside `PATH` be found.

## What is verified about each mechanism

Three columns: what the skill says, how strongly it is supported, and what would raise it.

| Mechanism | Support | What would raise it |
|---|---|---|
| PE structure, flag values, directory semantics, checksum | `observed` against the published format specification, and confirmed by the reader reproducing the declared checksum on real images | nothing further needed for the fields in use |
| Import, export, resource, TLS, debug and relocation parsing | `observed` against fixtures that declare their own expected values, plus plausible results on platform images | a second, independent parser agreeing on a larger corpus |
| Byte patching, checksum recomputation, patch verification | `observed` by running the pipeline end to end on a copy and re-reading the written bytes | nothing further for the described behaviour |
| Pattern location and cross-build comparison | `observed` on generated fixtures, including the ambiguous and zero-match cases | a real multi-version pair to exercise migration |
| Managed-assembly structure and tooling | `inferred` from the platform's own published format documentation and the tools' own documentation | a managed sample and a run |
| Installer and package formats | `inferred` from each project's own documentation | extraction performed on a sample of each container type |
| Debugger breakpoint families and their costs | `inferred` from the debugger's own documentation | a debugger installed, and a session recorded |
| Injection and hooking mechanics | `inferred` from the platform API documentation | a run, on a sample, with a control |
| Runtime gate verdict by paired observation | `observed` end to end on a real gated feature of a patched snapshot target: the code section was located by content match, the six patched bytes were read back live from the mapped code before any verdict was trusted, the shared decision function was entered exactly once, returned the true-object pointer, and the refusal display routine was never entered | a second target whose gate shape differs, to exercise the other two verdict states against reality |
| Dump semantics and repair | `inferred` from the platform's dump documentation | a dump repaired and loaded |
| Hardware breakpoints | `inferred` from the architecture as documented; the **count** of debug registers is the only architectural fact stated | a debugger, and a session on a host whose probe reports the route available |
| Instruction tracing capability and decoding | `unverified` here: the CPU reports the feature and no capture was taken | a capture path, then a decoder, then an address-to-symbol pass |
| OS event tracing | `inferred`; the tools are present and no session was recorded | a recorded trace of a known operation |
| Kernel debugging and driver loading | `inferred` from platform documentation | a second machine, or a boot configuration change, plus a driver to load |
| Hypervisor-assisted observation | `unverified`; documented as a route with its requirement chain | a driver, signing, and a host that is not already nested |

## Facts worth stating because common belief differs

Each of these was checked against a primary source, and each contradicts a thing that is widely
repeated. They are recorded here because a reader acting on the common version will build the wrong
plan.

- **A strong name is not anti-tamper.** It provides identity, and on current runtimes the signature is
  not validated at load time. Work planned around defeating it is planned against a mechanism that is
  not doing the work.
- **A managed assembly can be compiled to something with no readable intermediate code.** A
  ready-to-run image can still have its methods replaced by the runtime's compiler, so "precompiled"
  does not mean locked; a native-compiled deployment is the one that genuinely removes the readable
  layer.
- **`-A` on a disassembler's command line is not "run this script".** It suppresses dialogs; the script
  is a separate switch, and the two are documented as being used together.
- **The Rich Header is not in the format specification.** The published document does not describe it
  at all, so a parser for it is reading an undocumented structure and must say so rather than implying
  a normative source.
- **A full dump is not always the most complete dump.** The largest minidump configuration can carry
  more than a nominal "full" one, and one of the flags commonly believed to mean "everything" is
  documented as not supported for user-mode dumps.
- **A protected process cannot be recorded by the record-and-replay debugger**, and its replay is
  read-only. A recording is evidence about the run that was recorded, not about the binary.
- **A page-guard breakpoint fires once.** It is an alarm that the page was touched, not a watchpoint,
  and treating it as one loses every access after the first.
- **A copy-on-write image page is still reported as an image**, not as private memory. Distinguishing
  it needs the working-set information rather than the region query.
- **An administrative installation of a package removes its digital signature.** The extraction route
  and the signing state are not independent.
- **A certificate in the image is a statement about the image digest**, which is why editing the file
  while preserving the digest is not a thing that happens.

## What is deliberately not asserted

These came up during the research and were left out of the documentation rather than stated from
partial evidence:

- The exact byte ranges excluded from an Authenticode digest. The page that would have said so was not
  reachable; the consequence of editing is documented, the exclusion list is not.
- The deterministic-build behaviour of the linker's timestamp field. Candidate specification pages
  were not reachable, so build identity is described through the file hash and product version, with
  the format's own caveat about the timestamp.
- Byte values of any standard cryptographic substitution table. The standard is named and the reader
  is told to compare against it rather than against a recollection.
- Information classes for the undocumented memory-query call. The family is named and the reader is
  pointed at the target's own call sites.
- The detailed control layout of the debug registers. Only the architectural count is stated.
