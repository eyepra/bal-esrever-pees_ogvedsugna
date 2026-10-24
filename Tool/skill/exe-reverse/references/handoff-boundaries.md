# Hand-off boundaries - where this skill ends and another view begins

Seven boundaries that are easy to cross without noticing, written as ownership rather than as
repeated advice: each one names what the *other* side owns, because two copies of the same
procedure drift apart and the copy read first is then treated as the authority.

## When to load this

Load it when a task is about to leave the artifact this skill was written for: the gate may be
enforced where the binary cannot reach, the file may not be a native image at all, the check may
be invisible to a debugger, the evidence may be a trace nobody here recorded, or the deliverable
may have stopped being an edited executable. This file routes; the procedure lives in the file
that owns the route.

Strength labels used below: `observed` means something in this repository was read or run and
its result is stated here; `inferred` means it follows from the documented mechanism of the PE
format, of Windows loading, or of a neighbouring observation; `unverified` means assumed and not
reproduced here.

## 1. Client-enforced versus server-authoritative

A gate that lives in the client is a function of local state. An authorization the server
performs is a function of account state on a machine you do not have. The two look identical in
a debugger, because both present as a branch that decides "unlocked", and they cost completely
different amounts.

| What you see | Who owns the decision | What this skill can conclude |
|---|---|---|
| A branch over a local comparison, with no traffic at the moment of the decision | the client | the decision is local, so patching, hooking and a keygen are all in scope |
| A branch taken after a response arrives, and the same binary behaves differently for two accounts | the server | the client is displaying a verdict someone else computed; a patch changes what is shown, not what is entitled |
| Feature data that is never delivered to the client for the unentitled account | the server | there is nothing local to unlock, and the owner is whichever discipline handles accounts and entitlements |

The discriminating experiment needs no patching at all: run the same build twice with two
accounts while the traffic is captured, and change only the account. Same binary plus different
outcome means the decision is remote. That method is `inferred` here, and `unverified`: this
repository holds no capture transcript and no account pair.

The asymmetry this skill cares about is that "the check is in the client" and "the server without
the right account" are not an easy and a hard version of one problem. The first is a
local-control-flow question. The second is an entitlement question, and a patched binary that
shows an unlocked interface while the server keeps withholding the data has not solved it. It has
moved the failure somewhere less visible, which is worse than leaving it alone.

The part this skill does own on the border is the classification: which layer holds the decision,
what evidence says so, and the plain statement that the other layer owns the rest.

## 2. A local PE versus managed code

An assembly is a PE file whose logic is not machine code. The runtime header is data directory
index 14 in the format, and the shipped reader carries that index among the directories it
reports (`observed`: `scripts/peutil.py` defines the CLR directory index and prints the populated
directory set; a summary run over a local sample returned that set as one of its header facts).
So "this artifact is managed" is a measurable statement rather than an impression.

What follows from it:

- The sections and the entry point still exist, so the outer file remains readable by this
  skill's tools, but the bytes a native disassembler shows at the entry point are a stub rather
  than the program.
- The logic is addressed by metadata token rather than by offset into a code section, so every
  habit built on RVA-to-offset translation stops applying once you are inside.
- Naming, control flow and string protection for that runtime are a separate family of
  protections with their own tooling.

Ownership: this skill owns the outer facts of an assembly (version resource, signature state,
whether a native launcher or a protector wraps it, and the classification itself). Recovery at
the managed level belongs to the toolchain that owns metadata and intermediate-language
disassembly. Mixed artifacts are drawn per region, not per file: a native launcher that loads an
assembly, or an assembly with a native component, needs the conclusion labelled with the region
it came from.

Strength: classification `observed`; managed-level recovery `unverified` here, since this
repository ships no tooling for it.

## 3. User mode versus kernel mode

The boundary is where a check stops being visible. A user-mode debugger sees the transition into
a system call and then the return from it, not what happened on the other side. When the decision
is taken by a kernel component, every user-mode hook you install can succeed and change nothing.

Three observables together are the signature of a check you cannot see (`inferred`, and the point
of the section): the hook is confirmed to fire, its arguments are the ones you expected, and the
outcome does not change. Each of the three alone has a benign explanation, including a hook that
fires on a call the deciding layer never consults.

What crossing costs, in the vocabulary of the shipped probe (`observed` as this repository's own
statement of the gates):

- Kernel driver load is gated on reboot-and-test-signing, and the probe warns that virtualization
  based security with enforced code integrity may refuse an unsigned driver regardless of the boot
  flags.
- The same probe reports that where the registry keys it checks for those security features are
  absent, it cannot conclude the feature is off, and names the interface to cross-check with
  instead. A missing key produced "unknown", not "disabled".
- Reading model-specific registers for branch records needs kernel or hypervisor-level access.

Those are per-machine facts. For any given host they are `unverified` until the probe is run
there, which is exactly why the probe exists as a first step rather than as a footnote.

Ownership: building, signing and loading a driver, and analysing the kernel side of a check,
belongs to a different activity with a different toolchain and a different lab. This skill owns
deciding whether the boundary was crossed, naming the evidence, and stopping. Do not present a
user-mode result as a kernel-side answer.

## 4. Software observation versus hardware observation

| Observer | Can see | Cannot see | Changes |
|---|---|---|---|
| Debugger, breakpoints, stepping | control-flow arrival, registers, memory and stack at that point | anything between two stops, and what the process does to itself when it detects a stop | executes with modified bytes at the break site; perturbs timing and the exception path |
| User-mode hook or trampoline | the values crossing one chosen function boundary, arguments and results | a decision taken inside another layer, and any path that does not call the hooked function | rewrites the first bytes of the target function, which a self-integrity check can see |
| Instruction-trace hardware | the control-flow trajectory of what actually executed, in order, with no code modification | symbols, register values, memory contents, and the operands that made a branch differ | nothing in the target's code path, because it records rather than intervenes |
| Branch records or sampling | recent branch outcomes, or a statistical picture of where time goes | block-by-block sequence at full fidelity, and anything between two samples | nothing, subject to counter and privilege gates |

The practical asymmetry is the whole point: a hook gives values but has already perturbed the
target, and a trace leaves the target alone but has no values. When the question is "what value
did this comparison see", reach for the observation that can show a value. When the question is
"which code ran at all", reach for the one that cannot lie by intervention. And a trace is
evidence about a run, not about a build: it must be pinned to the artifact digest and to the
machine it came from, or it transfers to nothing.

The probe's route report separates these mechanisms by availability rather than by preference
(`observed` on one host): static PE analysis needs only Python and a file on disk; hardware
breakpoints are reported as needing a user-mode debugger, with the note that a hypervisor may
intercept the debug exception before it reaches a handler; instruction-trace capture is reported
as gated on a capture path even where the CPU advertises support, with decoding named as the
lesser constraint; branch records and performance counters are reported as needing
kernel-or-hypervisor privilege. Those rows are per host.

## 5. Analysis versus delivery form

Every word of a verification checklist assumes a delivery form. Four are common here, and they
are not ranked: they answer different questions, and the quiet failure is a privileged result
reported in the language of a finished build.

| Form | What "verified" means for it | What is not evidence | Pins the claim needs |
|---|---|---|---|
| Patched binary | the change is reproducible from a named original as a byte-level difference; the behavioural difference is observed on a named build; and the causal step is controlled, meaning the unmodified original was run first and did not show the difference | that the file loads, that the process starts, or that the patch tool reported success; the tool's success is a statement about the tool | digest of the original, digest of the output, the exact patch specification, and the run that showed the difference |
| In-memory patch | the modification took effect in a named process on a named build at a named point in its life, and the effect is visible in the target's own behaviour or log afterwards, with the process surviving long enough to show it | "the injection returned success", "the hook was installed", or a module listing that contains your module | process build identity, injection timing, and the observable that changed |
| Standalone keygen | the produced value is accepted by the target itself, on a clean unmodified build, for a defined and reproducible set of inputs, reproducibly across runs | agreement between your implementation and your own reading of the algorithm, or a value that only works because a hook is still installed | the target build, the input set, the acceptance observation, and the output digest |
| Written report | the evidence chain (the commands and their outputs, plus which layer each conclusion belongs to) and an explicit boundary: what was not determined and why | any implication that a route was exhausted when it was only abandoned, and a conclusion whose only support is another conclusion | the artifact digests and tool versions the observations were made with |

Two of these cross-checks are easy to get wrong in a way that looks like success. A signature that
required a hook is not a patched binary, and a keygen whose acceptance was only ever observed
under an active hook has not been separated from that hook. Changing the form is a decision that
must be said out loud, not a silent downgrade of what counts as done.

The shipped patcher already speaks this way, and its vocabulary is worth copying (`observed`): a
dry run over a local sample printed the site, the byte pair, and the note that the replacement
length was unproven, with the instruction to supply the expected bytes. The verification question
for a patch begins at that note, not at the file that gets written.

## 6. Packers and protectors versus ordinary compilation

"It is compressed" is not a diagnosis. Two very different things produce a file whose sections
look odd:

- A build setting. The toolchain compressed or reordered its own output, or a self-extracting stub
  was linked in. The code inside is the program, and an entropy reading says nothing about how
  hard the analysis is.
- A protection layer. A runtime unpacks in memory, owns the entry point, hides imports, and often
  runs its own checks against observers. Here the file on disk is a loader, and the analysis
  target is the image the loader produces at run time.

The shipped reader explicitly refuses to convert entropy into a verdict (`observed`: it computes
per-section Shannon entropy, documents it as a shell heuristic rather than a verdict, and lists
"follow a packer" and "repair a damaged image" among the things it will not do). That restraint is
the correct default. Entropy is a reason to look, never a finding.

What actually discriminates, all `inferred` here and each needing per-target confirmation: a tiny
high-entropy section holding the entry point; an import table that names only the loader; section
names and characteristics that do not match the toolchain the compiler fingerprint claims; a
memory image whose bytes differ from the file at the same relative offset; and strings that appear
only after the process has run.

Ownership: once the shape is a protection layer, the work has its own owner, its own cost and, for
commercial products, no general solution. This skill's job is to name the mechanism and the
boundary it imposes, then stop rather than spend a budget on a route that only a product-level
claim says works.

Avoid both directions of the wrong claim: "it is packed, so nothing can be concluded" is as
incorrect as "the entropy is high, so it is protected".

## 7. This skill versus a different sample type

This skill's measurements, file format and loader semantics are Windows PE. When the artifact is
not one, the tools and the offsets are not merely different, they are incompatible, and the
failure is not only "wrong tool" but wrong semantics carried over.

| Artifact | The habit that breaks | Owner |
|---|---|---|
| ELF | offset and relocation semantics, entry-point conventions, and the habit of reading a signature as a signed PE attribute | the discipline that owns the ELF toolchain |
| Mach-O | segmentation, embedded code-signature data, and the quarantine and notarization model | the discipline that owns that platform |
| Mobile application packages | bytecode formats, repacking and re-signing, and a runtime that is not the Windows loader | the discipline that owns that packaging format |
| Firmware and embedded images | container extraction, target architecture identification, and a bootloader rather than a loader | the discipline that owns the device |
| A bytecode runtime embedded in a native binary | reading the dispatcher as the program instead of the interpreter loop, and expecting x86 semantics from a virtual instruction set | the discipline that owns that runtime |

State the artifact class before the first conclusion, because every later claim inherits it. For a
framework or runtime hosted inside a PE, the wrapper is this skill's business and the logic inside
it is not; say which of the two you are reporting on.

## 8. The rule that makes these boundaries usable

Crossing a boundary is a decision that must be stated in the output, in one sentence: which side
owns the question now, and why. A boundary that is crossed silently reads to the next reader as a
solved problem.

The claim-strength rule applies across a boundary with more force than within a file, because the
chain is longer: a conclusion that depends on the other side is only as strong as the evidence
there. If this repository holds no observation on that side, the honest grade for the whole chain
is the weaker grade, not the grade of the half you measured yourself. `references/coverage-and-limits.md`
carries the grades and the chain rule.

When the answer turns out to live on the other side, the deliverable is the boundary itself: what
was determined, what was not, and which discipline owns the remainder. That is a result, not a
failure to produce one.
