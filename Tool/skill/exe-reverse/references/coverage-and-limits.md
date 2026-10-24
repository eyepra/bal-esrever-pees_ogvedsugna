# Coverage and limits - the honest inventory, written before the fact

This file states, before any task is run, what this skill covers, how strongly, and what each
claim depends on, so that a later reader can check every claim against the same standard it was
written under.

## When to load this

Load it when the strength of a claim decides whether to trust it, when about to quote this
skill's coverage, and before describing any route as "covered" or as "not possible". It names the
dependencies this repository does not ship, the routes nobody here has run, and the rules by which
a gap must be reported.

## Strength labels

- `observed` - something in this repository was read or run, and the result is stated with the
  command or the file that produced it.
- `inferred` - follows from documented mechanism (PE structure, Windows loading, a toolchain's
  documented behaviour) or from a neighbouring observation. The step itself was not executed.
- `unverified` - assumed, or taken from someone else's write-up, and not reproduced here.

Two kinds of `observed` must not be conflated, because they support different claims. The
existence and behaviour of a shipped tool is `observed` when its source was read or when it was
run, and that observation is about *the tool*. The behaviour of a *target* is `observed` only if
a target was actually run and a result was recorded. A tool that exits zero has reported on
itself.

**The chain rule.** A claim is only as strong as the weakest link in its chain. A strong
observation at the start does not upgrade a weak step later: if the route ends with a step nobody
executed, the conclusion is `inferred` at best, and a passing self-check of a tool is never
evidence about the target the tool was pointed at. This is why the grades below are stated per
direction rather than per document.

## Coverage by direction

The grades describe what this repository can support today, and they are deliberately pessimistic
where no measurement exists. `Dependency not shipped here` names what a reader must supply before
the row's route can run at all; a row with an unshipped dependency is not a covered route, it is a
named gap.

| Direction | Strongest defensible grade | What it rests on | Dependency not shipped here |
|---|---|---|---|
| Static PE structure analysis | `observed` for the reader; `unverified` per target | the shipped reader (`scripts/peutil.py`) parses the DOS header and stub, compiler fingerprint, NT and optional headers, data directories, sections, both offset directions, imports, delay imports, exports, resources, base relocations, TLS callbacks, debug directory and CodeView/PDB, load configuration, the certificate table location, a recomputed file checksum and per-section entropy (`observed`: a summary run over a local sample returned architecture, signature state, declared-versus-computed checksum agreement and the populated directory set) | a disassembler or decompiler for anything past the headers; a second reader when two tools disagree about one field |
| Instruction-level reading | `inferred` | the calling conventions, frame shapes and idiom meanings are documented architecture and toolchain behaviour, stated in `references/assembly-idioms.md` so a listing can be checked against them; no target was disassembled here | a disassembler or decompiler, and a build whose toolchain is known — the producer claim stays `inferred` until a second fingerprint agrees |
| CPU-vendor divergence | `inferred` | the differences in undefined results, system-instruction fault timing, feature-gated decoding and model-specific cost are stated from both vendors' specifications in `references/cpu-vendor-divergence.md`; no divergent behaviour was measured, because every run here came from one Intel host | a host of the other vendor (or a model pinned to one), and a target whose two paths can both be exercised |
| Byte patching | `observed` for the patcher's guards; `unverified` on any target | the shipped patcher (`scripts/pepatch.py`) opens the input read-only, writes a new file, refuses a length change without an explicit flag, refuses an ambiguous pattern, pins the expected bytes, re-parses its own output and re-reads every patched byte, and recomputes the checksum (`observed`: a dry run printed the site, the byte pair, the unproven-length note, and wrote no output file) | a debugger, to establish that the patched site is the site that executes |
| AOB pattern work | `observed` as a matching rule; `inferred` as a method | a three-byte pattern matched 64 sites and the tool refused the patch, naming three ways out (select an index, accept all, or extend the pattern with context); exact-once is the default (`observed`) | a disassembler, to argue that a pattern's identity is stable across the builds that matter |
| Dynamic debugging workflow | `unverified` | the route is described and a debugger exists on at least one host; no breakpoint log, stepping session or debugger transcript is recorded in this repository | an interactive debugger, and a target you are permitted to run |
| Runtime instrumentation | `unverified` | an instrumentation runtime is reported present by the host probe (`observed` for that inventory); no run against a target is recorded | the instrumentation runtime, and the target's own build identity |
| Injection and hooking | `unverified` | the technique is described, not performed here; the observer-versus-interceptor split in `references/handoff-boundaries.md` decides when it is allowed at all | an injection mechanism and a hook library |
| Dump and repair | `unverified` | nothing here dumps a process image, rebuilds a dumped image, or repairs imports | a dumper, an image rebuilder, and a way to show the repaired image is the image that ran |
| Licensing-mechanism classification | `inferred` | the classification is a decision procedure over observed structure: which layer holds the decision, local versus remote, one check versus a check repeated at every use | nothing to classify with, but a capture path and a second account for the remote rows |
| Algorithm recovery | `inferred` | the route is described; no implementation here has been checked against the target's own acceptance of a produced value | a decompiler or symbolic engine, and the target's acceptance as the only real oracle |
| Network-activated licensing | `unverified` | no capture, no replay and no account pair is recorded here | a capture path and a test account |
| Installers and packaging | `inferred` | the reader parses a PE and its resources, so an installer's outer image is readable; the inner container and install-time behaviour rest on nothing measured here | an unpacker for the installer's own container, and a disposable machine to install on |
| Managed (.NET) code | `observed` as classification; `unverified` for recovery | the runtime header is data directory index 14, the shipped reader carries that index and reports the populated directory set, so "this artifact is managed" is measurable | a metadata and intermediate-language toolchain, plus a runtime to test against |
| Anti-analysis | `inferred` | the decision procedure is described: identify, measure the cost, prefer static, keep observers separate from interceptors; nothing here was measured on a target that detects observers | a second machine, and a target you can afford to lose |
| Protectors and packers | `inferred` | the reader measures per-section entropy and documents it as a heuristic rather than a verdict, and documents following a packer as a non-goal; no protected image was analysed here | protector-specific tooling, and a decision about whether buying it is justified |
| Code virtualization and flattening | `unverified` | the shapes and the interpreter's anatomy are described, the latter from public write-ups of one protector family; no virtualized target was analysed here | a devirtualizer, which in practice is the reader's own budget |
| Unity IL2CPP runtime layer | `unverified` | the layer map, the metadata placements and the registration failure modes are described from public write-ups; no IL2CPP build was opened here, and the shipped reader proves only that the outer file is a PE | an il2cpp dumper or equivalent, the build itself, and a host that can run it when the metadata must be dumped rather than read |
| Python-packaged software | `unverified` | the packager shapes and the code-object wrapper's mechanisms are described from a public write-up; no packaged Python program was unpacked here | the packager's extractor, an interpreter at the exact version, a decompiler, and the wrapper's own version where one is present |
| Symbolic execution and deobfuscation | `unverified` | an engine may exist on a host and is reported by the probe (`observed` for that inventory); no result from one is recorded | a symbolic execution engine, and a way to bound the search |
| Kernel and driver analysis | `unverified` | the host probe (`scripts/hwprobe.py`) reports driver load as gated on reboot-and-test-signing and warns that enforced code integrity may refuse an unsigned driver regardless of boot flags (`observed` as the repository's own statement); no driver was built or loaded here | a signing path or a test-signing machine, a second host for debugging, and a driver toolchain |
| Hardware tracing | `unverified` | the probe reports trace support as gated on a capture path even where the CPU advertises support, names decoding as the lesser constraint, and reports branch-record reads as needing kernel or hypervisor privilege (`observed` as the repository's own statement); no trace was captured here | a supported CPU, a capture path, and a decoder |
| Hypervisor-assisted observation | `unverified` | the probe reports whether a hypervisor is present, and reports the security-feature keys it checks as unreadable on editions that do not populate them, which is a gap rather than a "no"; nothing here was observed from inside a hypervisor | a hypervisor, a configuration that permits it, and a second host |

Two rows deserve their pessimism explained, because both look closer to covered than they are.
Byte patching is `observed` for the guards that make a patch auditable and still `unverified` for
the only question that matters in the end, which is whether the edited byte is the byte the
program consults. Algorithm recovery is `inferred` because the only oracle that settles it is the
target's own acceptance, and no such acceptance was recorded here.

## Not covered - say so instead of improvising

Each line below is a route that must be declined rather than attempted with the nearest available
procedure. The failure worth preventing is not ignorance; it is a confident wrong answer produced
by applying a procedure to a target it was never written for.

- **Defeating a server-side authority.** Classifying which layer owns a decision is in scope, and
  `references/handoff-boundaries.md` draws that line; breaking an authorization the server
  performs is not, and no amount of client-side work substitutes for it.
- **A fully automated general-purpose devirtualizer.** There is no such capability here, neither
  for a commercial protector nor for a custom bytecode interpreter.
- **Decrypting a container whose cipher is itself virtualised.** Where a metadata file or a code
  object is held by a bytecode interpreter that runs before the plaintext exists, the route is to
  dump after that interpreter has run, or to implement it; nothing here decrypts it by reading.
- **A general unpacker for a versioned code-object wrapper.** The mechanism is described; a tool
  that covers a version this repository has not seen is a research task, not a command.
- **Defeating a specific commercial protector as a product claim.** No row above asserts that any
  named protector falls to any route. Naming a protector is a classification result; whether it
  yields is a per-target measurement that must be made, with its result recorded.
- **Driver-signature bypass as a shipped capability.** The gate is reported; no way around it is
  implemented, and test signing is not presented as a general answer.
- **Any guarantee of behaviour on Windows versions this repository has not measured.**
  Version-gated behaviour, including signing requirements, security-feature interactions and
  debugger permissions, is reported as a per-host measurement or as unknown.
- **Anything outside this artifact class.** Mobile packages, ELF images, firmware and other
  platforms are routed in `references/handoff-boundaries.md`, which names the owner; the tooling
  here does not transfer and its offsets do not mean the same thing there.
- **A result that is invisible to the target's own anti-analysis.** Detection handling here is a
  cost decision plus an observer/interceptor discipline, not an evasion catalogue, and the cost of
  each added module is what decides when to leave for static analysis.
- **Guarantees about another tool's output.** Where a route depends on a third-party tool, that
  tool was not audited here; its output inherits its own trust level and must be labelled as such.
- **Reconstructing a source tree.** Recovered structure, names and types are an interpretation of
  an artifact, never the original program text, and must never be presented as the latter.
- **Any claim about a target that was never obtained.** With no artifact and no digest, every
  statement about it is `unverified`, including statements about difficulty.

## Missing coverage is unknown, never absence

This is the rule the rest of the file exists to make checkable.

- A route that was not executed is not a route that was excluded. Three states must stay distinct
  in every report: `unknown (not attempted)`, `unknown (attempted, blocked by <named condition>)`
  and `unknown (attempted, inconclusive)`.
- A search that returned nothing is evidence about the search, not about the target. "The pattern
  was not found" means the search ran over the stated range with the stated pattern; it does not
  mean the sequence is absent from the artifact.
- An unreadable value is not a zero and an absent key is not a "no". The host probe is the model
  for this behaviour (`observed`): where the registry keys it checks for a security feature are
  missing, it reports that the feature's state cannot be concluded rather than reporting it off,
  and names the interface to cross-check with.
- An empty cell or a missing row in this file is a gap in this file's coverage, not a claim about
  the world.
- A downstream success never repairs an upstream malformed input. If the artifact could not be
  read correctly, no later step's result validates that read.
- A partial read is reported as partial. Paging, truncation and an interrupted run each leave a
  stated remainder; the remainder is unknown, not empty.

## What would move a row upward

- A row moves only when the missing evidence is produced *and recorded*: the exact command, the
  artifact digest, the tool and its version, and the observed output. Measurements are comparable
  only when those pins match, so a number without its pins cannot raise a grade.
- A negative measurement raises a row too, and must be recorded rather than dropped. A route that
  was measured and failed on a named host is more useful than a route nobody ran, because it stops
  the next reader from paying for the same attempt. Absence from this file is not a verdict on a
  route that was never tried.
- A claim never rises because it was repeated, cited, or found coherent. It rises when the weakest
  link in its chain is replaced by an observation, and the grade is then restated for the whole
  chain rather than for the new step alone.
