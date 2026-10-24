# Repository Decisions

Why the repository is shaped the way it is. Each entry records the alternative that was considered
and the reason it lost, because a decision with no recorded alternative gets re-litigated by every
future contributor.

**When to read it:** before proposing a structural change, and when an existing rule looks arbitrary.

## Layout

**Decision: a skills repository with the skill under `skills/<name>/`, and everything else as
maintenance tooling.**

The alternative was a flat repository where the skill is the root. It loses on one specific point: the
gates, the tests and the evidence record are *about* the skill rather than part of it, and installing
the skill should not install them. The `skills/<name>/SKILL.md` layout is also what the installer
resolves, so the structure and the install mechanism are the same fact stated once.

**Decision: an agent preset is not involved, and no runtime is required.**

The skill is documents plus scripts. A background process, a server, or a plugin would each add a
failure mode that cannot be checked by reading a file, and none of them is needed to answer the
questions this skill answers.

## The strength vocabulary

**Decision: three grades — `observed`, `inferred`, `unverified` — applied to every factual claim.**

The alternative was ordinary prose, which reads as uniformly confident. The observed failure is not
that a reader disbelieves a claim; it is that a reader cannot tell a measured result from a plausible
one, and therefore builds a plan on top of an assumption.

Three grades rather than two, because the interesting middle case is real: a mechanism verified from
its documentation, exercised by nobody here. Calling that "unverified" hides that the mechanism is
known; calling it "verified" is a lie.

**Decision: missing coverage is recorded as `unknown`, never as absence.**

A search that returned nothing is evidence about the search. "The tool is not installed" and "the tool
does not exist" lead to different actions, and collapsing them is the most repeated data error in this
kind of record.

**Decision: a claim is only as strong as the weakest link in its chain.**

Stated separately because it is violated by composition rather than by any single sentence: a row that
joins a verified mechanism to an unexercised route reads as one verified claim unless the joining is
called out.

## The entry point

**Decision: `SKILL.md` stays near 300 lines, and the inventory lives in `references/routing.md`.**

The alternative was one large entry point. It loses because the entry point loads in full on every
activation: a lookup table that is read once per task is a poor use of that budget, while a
symptom-to-file mapping must stay one hop and therefore belongs there.

**Decision: the symptom index is mirrored into `routing.md`, with a gate comparing the two.**

Splitting a table is how two tables start disagreeing. A mirror plus a check gives a reader all three
tables in one load and makes drift a build failure rather than a slow decay.

**Decision: the entry point is a procedure with gates, not background reading.**

Because the observed failure mode is a reader agreeing with the material and then reasoning from
first principles anyway. Gates are actions with pass criteria precisely so that "I understand the
idea" cannot be mistaken for having done it.

## The scripts

**Decision: standard library only, Python 3.9+, no third-party imports.**

A parser used to build a toolchain must be readable and must run on a bare install, including in a
locked-down analysis VM. A dependency is a thing that can fail to install at the moment the analysis
is happening. Where a third-party tool is the right instrument, the script reports its absence
instead of substituting a weaker method.

**Decision: every structure offset is computed, never estimated.**

Two structures in the fixture generator overlapped because each had a hand-picked offset. A single
allocating cursor makes the overlap impossible rather than merely absent.

**Decision: a numeric table carries its source.**

A constant table written from recall was wrong in every entry and produced plausible output. Tables
taken from a specification name the specification; tables that read an undocumented structure say so.

**Decision: an unproven property is reported as unproven, not as satisfied.**

The length guard is the case that produced this rule: it compared a value with itself and could never
fail. A property the tool cannot establish — the length of a site without disassembling it — is now a
third state rather than a silent pass.

**Decision: fixtures are generated, not committed.**

A committed sample is a licensing and provenance problem, and a downloaded one makes the suite depend
on the network and on a target that changes. A generated fixture is deterministic, carries the awkward
cases deliberately, and is code rather than an artifact.

## The gates

**Decision: six structural gates at the repository root, and CI runs all of them.**

Consistency has a natural counter-pressure — a broken path fails loudly. Bloat and drift do not, which
is why there is a budget gate and a routing gate rather than only link checking. Every gate exists
because a specific class of change went unnoticed without it.

**Decision: the leak scanner owns its rules, and the repository gate delegates to it.**

One place to argue with an exemption list. A second implementation would diverge, and the diverging
one would be the one that ran.

**Decision: the claim that a document makes about a command is machine-checked against that script's
own argument table.**

A flag that no longer exists is drift no path check can see: the file resolves, the line number is
right, and the command fails at the moment someone follows the page instead of the tool.

## The hardware layer

**Decision: the hardware routes are probed per host and degraded honestly, rather than declared
supported.**

This is the skill's differentiator and its least portable part. A CPU reporting the feature says
nothing about whether a capture path is reachable, and a hypervisor present on the analysis host
changes what a debugger and a hardware breakpoint can do. A plan that assumes otherwise fails at the
first step and gets attributed to the tooling. The probe exists so the answer is a measurement.

**Decision: bits whose meanings are not verified are printed raw.**

Reading a capability out of a recollection is how a wrong plan becomes an authoritative-looking one.
There is no loss in printing the register values and letting the reader consult the processor
specification for the family in front of them.

## Publishing

**Decision: the desensitization rules state what must be removed *and* what must stay.**

A one-sided rule trains people to redact tool names and format names, which destroys the reusable part
of the material while removing none of the target's identity. A scanner that flags those gets switched
off, and then the real findings go with it.

**Decision: an entry-point document is treated as a prompt surface.**

A README, a case note, a screenshot filename — these carry target identity as easily as body text, and
they are the part most often forgotten because they were written before the material was.
