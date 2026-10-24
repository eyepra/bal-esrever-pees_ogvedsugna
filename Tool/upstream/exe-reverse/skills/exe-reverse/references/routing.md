# Routing

**What this answers:** where to go next. The entry point keeps only what must be one hop away (a
symptom, and the gates); every lookup table lives here, so a session pays for the inventory once,
when a route has been chosen.

**When to load this:** immediately after classifying the target and choosing a route, then again
whenever a script or a reference needs to be found. Open only the row's target.

**Registering a new file:** adding anything under `references/` or `scripts/` means adding a row
here. The routing gate fails an unregistered file, because an inventory that has drifted from the
directory reads as complete and is worse than none.

## Symptom index (mirror of the entry point)

This table is a mirror. The live copy is in `SKILL.md`, and the routing gate fails if the two
disagree — a symptom-to-file lookup must stay one hop, so it cannot be maintained in two places
without a check.

| What you observe | Load first |
|---|---|
| The patched binary will not start, or dies before your code is reached | `references/integrity-checks.md` |
| It starts, renders, logs nothing wrong — and one feature silently never works | `references/license-mechanisms.md` |
| Your edit is present in the file but clearly not in effect at run time | `references/dynamic-debugging.md` |
| A breakpoint at the entry point is never hit, yet the process runs | `references/pe-structure.md` |
| The process dies when a debugger attaches, and only then | `references/anti-analysis.md` |
| It dies on its own after a delay, with a crash that looks like an ordinary bug | `references/anti-analysis.md` |
| Every licence check you patch is followed by another one | `references/license-mechanisms.md` |
| There is no readable check anywhere, and the decision seems to come from outside | `references/network-activated-licensing.md` |
| The whole `.text` section looks like noise, or imports are missing or fake | `references/protectors-and-packers.md` |
| Strings you expect are absent; the import table resolves almost nothing | `references/protectors-and-packers.md` |
| One function is a many-thousand-line switch over a value that is loaded from memory | `references/virtualization-and-flattening.md` |
| A dump runs but every call lands in a jump table, or the code differs after a restart | `references/protectors-and-packers.md` |
| The image you dumped will not load — sections are misaligned or headers are gone | `references/memory-and-dumps.md` |
| The file checksum no longer matches and something now refuses the binary | `references/patching.md` |
| Your signature-based patch worked on one version and misses on the next | `references/aob-and-signatures.md` |
| Two supposedly identical builds behave differently | `references/pe-diff-and-versions.md` |
| A check passes here and fails on the machine the deliverable is for, with the same OS build | `references/cpu-vendor-divergence.md` |
| The target is a .NET assembly and hex-patching it does nothing | `references/managed-dotnet.md` |
| A .NET assembly decompiles, but the names are gone or the C# does not add up | `references/dotnet-decompilation.md` |
| A Unity game's `global-metadata.dat` is missing, empty or unreadable beside its `GameAssembly.dll` | `references/unity-il2cpp.md` |
| il2cppdumper reports `CodeRegistration : 0`, or the metadata version disagrees with the struct it parses | `references/unity-il2cpp.md` |
| A hot-update assembly decompiles to high-entropy IL, or an AssetBundle refuses to open | `references/unity-il2cpp.md` |
| The target directory holds `python3xx.dll`, `_internal` or `pyarmor_runtime` | `references/python-runtime-bundles.md` |
| A Python module is high-entropy while the rest of the packaged program is ordinary | `references/python-runtime-bundles.md` |
| The payload holds a large `data/app.so` and hardly any native code | `references/flutter-and-dart-aot.md` |
| The sample is an installer, and the interesting binary is nowhere on disk after install | `references/installers-and-packaging.md` |
| The file is a driver, or it refuses to load without a driver present | `references/kernel-and-drivers.md` |
| You need to observe a check without modifying anything, and every hook is detected | `references/hardware-tracing.md` |
| A debugger session is impossible: a hypervisor, VBS, or anti-debug owns the debug registers | `references/hypervisor-observation.md` |
| The algorithm is clear in shape but the constants come from somewhere you cannot see | `references/algorithm-recovery.md` |
| You have a trace or a hot address list and no idea which routine it belongs to | `references/hardware-tracing.md` |
| A tool returns more output than you can read, or the same run returns different amounts | `references/toolchain.md` |
| The binary was produced by a compiler you have not identified | `references/compiler-fingerprints.md` |
| The target is written in Go, Rust or Delphi and the call structure looks wrong | `references/compiler-fingerprints.md` |
| A detour or code cave crashes its callee, or the arguments arrive at wrong offsets | `references/assembly-idioms.md` |
| A 32-bit target's licence file or registry key is absent from the path the documentation gives | `references/assembly-idioms.md` |
| A prologue does not look like the compiler the headers named | `references/assembly-idioms.md` |
| A routine compares the CPUID vendor string, or branches on a flag the manual calls undefined | `references/cpu-vendor-divergence.md` |
| You are about to conclude "it must be server-side" | `references/network-activated-licensing.md` |
| You cannot tell whether a failure is your patch or the target's own behaviour | `references/verification.md` |
| You are about to write off a route as impossible | `references/protectors-and-packers.md` |
| You are about to publish notes, a script or a screenshot of the work | `references/desensitization.md` |
| The task has run long and you are unsure what is already proven | `references/long-task-discipline.md` |
| A documented command does not run, or a tool "is missing" | `scripts/hwprobe.py` |
| A fix removed the error, and the requester still sees the symptom | `references/pitfalls.md` |
| A verification passed, but you cannot say what would have failed without the change | `references/pitfalls.md` |
| You need to know what this skill does not cover before promising anything | `references/coverage-and-limits.md` |

## Reference index

Load one file, not the shelf. The "load it when" column is the whole point of this table: a
reference that is loaded at the wrong moment costs context and answers nothing.

| File | Load it when |
|---|---|
| `references/recon.md` | first contact with an unknown binary: what to establish, in what order, and how to recognise a protector without claiming certainty |
| `references/pe-structure.md` | a header, section, import, relocation, TLS or checksum question — or when an offset and an RVA disagree |
| `references/static-analysis.md` | reading code: disassembly, decompilation, structure recovery, and where a listing lies |
| `references/compiler-fingerprints.md` | the toolchain is unidentified, or the call structure does not look like C or C++ |
| `references/assembly-idioms.md` | a listing must be read at the instruction level: the convention moves the arguments, the prologue says who produced the code, a string instruction stands in for a library routine, or a detour must preserve the frame |
| `references/cpu-vendor-divergence.md` | a result may belong to one processor's implementation rather than to x86-64: undefined flags, vendor-string dispatch, feature-gated decoding, system-instruction fault timing, or a specification about to be handed to another team |
| `references/pe-diff-and-versions.md` | two builds must be compared, or a finding has to survive a version change |
| `references/patching.md` | any byte edit: site choice, equal-length discipline, checksum, and proving the patch is reached |
| `references/aob-and-signatures.md` | a patch must be located across versions rather than at one address |
| `references/integrity-checks.md` | the target verifies its own bytes, and a correct-looking patch is refused |
| `references/license-mechanisms.md` | deciding what kind of licence decision this is, before touching anything |
| `references/algorithm-recovery.md` | recovering a key, hash or licence algorithm rather than a branch |
| `references/network-activated-licensing.md` | the decision may belong to a server, or a capture must be classified |
| `references/dynamic-debugging.md` | locating behaviour at run time, and choosing a breakpoint family |
| `references/injection-and-hooking.md` | instrumentation by modification: what to hook, and what a hook changes |
| `references/memory-and-dumps.md` | process memory as evidence, and turning a dump into something loadable |
| `references/anti-analysis.md` | the target fights back: which mechanism fired, and how to tell it from a broken host |
| `references/protectors-and-packers.md` | the code cannot be read: recognising the layer and working through it |
| `references/virtualization-and-flattening.md` | the code is readable but its shape is wrong: dispatchers, opaque predicates, virtual machines |
| `references/symbolic-execution.md` | reading has stopped paying: when a solver or an emulator is the cheaper route |
| `references/managed-dotnet.md` | a managed assembly, or a mixed-mode one, is the target |
| `references/dotnet-decompilation.md` | a managed assembly must be read rather than classified: deobfuscation, decompiler choice, CIL reading, and the path from a method body to a business rule |
| `references/unity-il2cpp.md` | a Unity IL2CPP build: the metadata file is missing or protected, the dumper will not find its registrations, or the hot-update and bundle layers must be read |
| `references/python-runtime-bundles.md` | a packaged Python program: which packager produced it, the interpreter version it needs, the wrapper around its code objects, or Python compiled to native code |
| `references/installers-and-packaging.md` | the sample arrives as an installer or a package |
| `references/flutter-and-dart-aot.md` | the payload is a Flutter application: an ELF `app.so` inside a Windows package, with the behaviour in compiled Dart |
| `references/kernel-and-drivers.md` | the boundary where user-mode tooling stops |
| `references/hardware-tracing.md` | observing without modifying: hardware breakpoints, instruction tracing, and what each requires |
| `references/hypervisor-observation.md` | the layer above the operating system, and what its presence changes |
| `references/toolchain.md` | installing, invoking and reason about tools, and the budget rules for a tool's output |
| `references/environment.md` | isolating the analysis host before the first execution |
| `references/verification.md` | the claim ladder, and what "verified" means for each deliverable form |
| `references/long-task-discipline.md` | a task that will run long: the live record and the drift controls |
| `references/desensitization.md` | before publishing anything derived from the work |
| `references/coverage-and-limits.md` | before promising a result: what this skill covers, how strongly, and what it does not |
| `references/handoff-boundaries.md` | the question belongs to another layer or another discipline |
| `references/evidence-summary.md` | the condensation: capability → conclusion → strength → the evidence behind it |
| `references/pitfalls.md` | before building, and whenever a result is puzzling |
| `references/routing.md` | this file: the symptom, reference and script inventory |

## Script index

Every script here is plain Python 3.9+, imports nothing outside the standard library, and accepts
explicit paths for anything it shells out to. `--help` on each one is the authoritative interface.

| Script | What it does |
|---|---|
| `scripts/peutil.py` | dependency-free PE reader: headers, sections, RVA↔file-offset both ways, imports, exports, resources, TLS, debug/PDB, relocations, load config, the checksum Microsoft's algorithm computes, and per-section entropy. Also a library for the other scripts |
| `scripts/pe_triage.py` | one-pass triage of an unknown binary: identity, build evidence, protective signals with their measurements, surface, and what to do next |
| `scripts/pepatch.py` | equal-length byte patches from a spec or from the command line: read-only input, a new output file, an ambiguity guard, a length-provenance rule, checksum recomputation, and every patched byte re-read from the written file |
| `scripts/aob_scan.py` | locate a byte pattern and report its hit count, each site's offset/RVA/section, a verdict (`unique` / `ambiguous` / `pervasive` / `no-match`), and hit-count comparison across two builds |
| `scripts/pe_diff.py` | compare two builds by content hash with the volatile header fields normalised, and report the differing ranges with the RVA each maps to |
| `scripts/hwprobe.py` | report which routes **this host** supports: CPUID features read through a local stub, CPUID bits printed raw unless their meaning is verified, OS build and boot flags, privilege, and the tool inventory — with an `available` / `needs-<x>` / `unavailable` verdict per route |
| `scripts/capabilities.py` | the capability registry: what each capability needs, how to detect it, which script implements it and which reference documents it |
| `scripts/make_fixture_pe.py` | build a synthetic PE image offline for testing (PE32 or PE32+, five sections, imports/exports/resources/TLS/debug/relocations, a correct checksum, and a byte sequence planted twice on purpose) |
| `scripts/scan_leaks.py` | scan a repository for target identity before publishing: rules with their exemptions, findings with their context, `--show-exempt` for the suppressions, and an exit code that can gate a commit |
| `scripts/doctor.py` | run this first: capability verdicts from the registry, per-script runnability from a static dependency pass, and the host facts that would silently poison an experiment |
| `scripts/trace_reduce.py` | reduce an obfuscated bit-vector expression to a simpler equivalent: recognises the identities a protector substitutes in reverse, folds constants at the working width, and checks the result by sampling the boundaries -- reporting that as "equivalent on N inputs" rather than as a proof. With `--prove <solver>` the statement changes: the equivalence question goes to an external solver as SMT-LIB2 (asserting the two forms differ) and an `unsat` answer upgrades the verdict to proven for every input at that width, in exactly the semantics the tool evaluates -- the shift-count mask is encoded on both sides, so the proof covers the same functions the samples ran on. A solver's witness is re-checked by substitution before being believed |
| `scripts/gate_probe.js` | a Frida probe that watches a located decision function and the routine that reports its refusal, so one exercise of a feature distinguishes "the gate fired", "the gate cleared" and "nothing was attempted". Ships with placeholder addresses and refuses to attach until they are filled, because a probe at address zero reports nothing and reads as a clean result |
| `scripts/plan.py` | the entry point for a wish: turn a stated intent into the capabilities it needs, resolve them against this host, and print the questions that decide whether the wish is well-posed, the first steps, the references, and the limits that do not go away |
| `scripts/preflight.py` | run this before one session starts: the sample hashed and a working copy in place, the destination writable and large enough for the route (and, when it is not, which volume is), the route's prerequisites held, and no leftover tracing session or proxy to make the run incomparable. `--space` lists the volumes; `--cleanup` reclaims session directories this script created, and refuses any directory that does not carry its own manifest |
| `scripts/capabilities.py` | the capability registry: atoms and their closures, what each needs, an executable next step for anything missing, and a cost estimate labelled with the strength of the measurement behind it |
| `scripts/dart_snapshot_strings.py` | recover string literals from a Dart AOT snapshot (the `app.so` of a Flutter application) and report the reference mechanism, which decides whether instruction scanning can find a literal's users at all |
| `scripts/fold.py` | the bounded-summary rule made executable: one pass over a large record, a shape decided by a depth scan of its own bytes (a pretty-printed document and a line-delimited one both begin with `{`, and a size cutoff once streamed one as the other), every list capped at `--limit` and every cap admitted, `--grep` for the lines that matter, `--key` for one field's distribution, and the record itself left untouched -- because re-running a producer to shrink its answer costs the same and returns less |

## Sub-indexes

| File | What it holds |
|---|---|
| `references/coverage/route-inventory.md` | the per-route inventory: what each route is for, what it needs, and how far it was taken |
| `references/precedents/README.md` | the case-library index and the template a new case must follow |
