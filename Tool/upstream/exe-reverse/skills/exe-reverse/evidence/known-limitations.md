# Known limitations

Goal: state, for someone who has the installed skill and not this repository, what must not be
trusted without a measurement of their own.

## When to load this

Load it before promising anything on the strength of this skill's coverage, before quoting a grade
from `evidence/capability-matrix.json`, and whenever a route is about to be planned on a machine
other than the one the grades were measured on. It is the installer-facing counterpart to
`references/coverage-and-limits.md`, which is the same inventory written for a reader working inside
the repository.

## Labels used here

`observed` means a command was run and its output exists, or a file was read at a stated revision.
`inferred` means the conclusion follows from an observation or from documented mechanism by a step
that is stated. `unverified` means assumed or reported elsewhere and never reproduced here. A claim
is only as strong as the weakest link in its chain, and a passing self-check of one of this skill's
own scripts is never evidence about any target.

## Documentation-derived rather than measured

Fourteen of the twenty-eight capability rows are `unverified`, and five more are `inferred`. The
split is not arbitrary: the rows on the `observed` side are the ones backed by a script that was run
during the measurement pass, and everything else is a procedure that is written down and has not
been executed here.

The `unverified` routes, each with the reason: dynamic debugging (no debugger session recorded, and
no interactive debugger installed on the measuring host); runtime instrumentation (the runtime is
installed, nothing was instrumented); injection and hooking (described, not performed); dump and
repair (no dumper present, nothing dumped or rebuilt); network-activated licensing (no capture, no
account pair, no capture reader installed); installers and packaging (the inner container is
untouched); managed recovery (no metadata toolchain installed, no assembly modified);
virtualisation and flattening (no virtualised target analysed, no devirtualiser); symbolic execution
(an emulation engine is installed, no symbolic engine is, and no result was recorded); kernel and
driver analysis (no driver built, signed or loaded, and test signing is not enabled on the measuring
host); hardware tracing (nothing traced); hypervisor-assisted observation (nothing observed from
inside a hypervisor); the two-build diff route (the script and the reference exist, neither was
exercised); and disassembly (a library and a binutils disassembler are installed, no disassembly was
performed).

Every reference file that the entry point and the routing table name exists in the tree at the
recorded revision. That was not true throughout the pass: two route files and the capability
registry script were absent at the first measurement and present at the last, and the repository gate
went from reporting eleven missing paths to reporting none. The rows affected are graded against the
later state, and the earlier state is kept in the evidence file, because a claim about what this
skill covers is a claim about a revision.

The `inferred` rows are licence-mechanism classification, algorithm and key recovery, anti-analysis
handling, protector and packer recognition, and compiler fingerprinting. Each rests on a written
decision procedure plus, at most, a neighbouring observation. For example, the reader's compiler
fingerprint path was exercised only on its negative branch: a triage run on a synthetic fixture
reported the header region absent, which is not the same as having decoded one. The reference itself
records that turning the region's integer pairs into a vendor identity is a third-party convention
that must be calibrated against a second file before it is quoted, and nothing here has done that.

## What the scripts are tested against

The test corpus is synthetic fixtures plus platform binaries. It is not a corpus of real-world
commercial targets, and no target sample is committed to this tree.

The fixtures are built by the shipped generator, and they are byte-reproducible: two independent
generations of the default recipe produced the same 4096-byte file with the same SHA-256. That makes
them a usable pinned test input and it is the property that lets a reader reproduce a parser or
patcher result exactly. They also carry deliberately awkward features so that the tools are tested
against the cases that break naive implementations, including a code section that is executable and
writable, a data section whose virtual size exceeds its raw size so that a virtual-only tail with no
bytes on disk is representable, a doubled byte sequence that makes an ambiguous pattern a first-class
test case, and a TLS callback pointer.

Two things follow that a user should hold onto. First, a fixture is a structurally valid PE image and
is not a runnable program: there is no real code and the entry point is a stub, so no fixture can
establish anything about run-time behaviour. Second, the platform binaries used in the measurement
pass (three system images and one shared runtime assembly) are not targets either: they were read,
never modified, and they establish only that the reader agrees with them about header fields and
checksums.

The consequence for grading is blunt. Every `observed` row that concerns a shipped script is a
statement about the script. The rows that would matter to a user, whether a patched byte is the byte
the program consults, whether a pattern still points at the same routine on a new build, and whether
a licence decision is computed locally, are each still `unverified` or `inferred`.

## Routes that need something many hosts do not have

Each line names the gate, and the gate is per-machine. Run the host probe on the machine in question
rather than reusing the numbers below; the numbers below are one host.

Hardware breakpoints need a debugger plus usable debug registers. The architecture provides four,
they are consumed per thread, and a hypervisor may intercept the debug exception before it reaches
your handler. The measuring host had a hypervisor present and reported this route as needing a
debugger with that caveat attached.

Instruction tracing needs a processor that reports the feature and a way to reach the trace unit.
Reports disagree in the useful direction: the measuring host's processor advertises support, and the
probe nevertheless reported no documented user-mode path to the trace unit on that platform, naming
capture rather than decoding as the constraint. A capability you never probed for is not a capability
you lack, but a capability whose capture path does not exist is not one you can plan on either.

Branch records and performance counters need kernel or hypervisor-level access, and the record depth
is a capability rather than a constant.

Kernel drivers need test signing or a second machine, and the gate is not the only obstacle:
virtualization-based security with enforced code integrity may refuse an unsigned driver regardless
of the boot flags. On the measuring host no test-signing or debug boot flag was set.

Record-and-replay debugging is a feature of one debugger, and recording is user-mode only.

Signing and re-signing need a signing tool that was not installed on the measuring host, and an edit
that changes any covered byte invalidates an existing signature as arithmetic rather than as policy.

Managed assembly recovery needs a metadata and intermediate-language toolchain. Classification does
not: the managed case was observed directly, because the reader reports the directory that marks it.

Network-activated licensing needs a capture path and a second account. Dumps need a dumper. Kernel
analysis needs a driver toolchain and a second host for debugging. None of those was present.

## Routes this repository deliberately does not ship

These are refusals by design, not gaps waiting to be filled. A request that needs one of them must be
routed to the discipline that owns it.

Defeating a server-side authority. Classifying which layer owns a decision is in scope and is a
first-class result. Breaking an authorization the server performs is not, and no amount of
client-side work substitutes for it. A patched client that displays an unlocked interface while the
server keeps withholding the data has not solved the problem; it has moved the failure somewhere
less visible.

A general-purpose automated devirtualiser. There is no such capability here, neither for a commercial
protector nor for a custom bytecode interpreter. The route describes the shapes to recognise and
says plainly that in practice the budget is the reader's own.

Defeating a named commercial protector as a product claim. No row here asserts that any named
protector falls to any route. Naming a protector is a classification result; whether it yields is a
per-target measurement that has to be made and recorded.

Building, signing or bridging a kernel driver as a shipped capability. The gate is reported and the
boundary is named. Test signing is not presented as a general answer, and no way around the gate is
implemented. User-mode tooling stops at the boundary, and a user-mode result must not be presented as
a kernel-side answer.

Reconstructing a source tree. Recovered structure, names and types are an interpretation of an
artifact and are never the original program text.

Guarantees about another tool's output. Where a route depends on a third-party tool, that tool was
not audited here; its output inherits its own trust level and must be labelled as such.

Behaviour on Windows versions this repository has not measured. Version-gated behaviour, including
signing requirements, security-feature interactions and debugger permissions, is a per-host
measurement or `unknown`.

## A null result is evidence about the search, not about the world

This is the single rule most likely to be broken by a reader in a hurry, so it is stated as a
distinction rather than as advice.

"I did not find it" and "it is not there" are different statements. The first requires the search to
be named: over what range, with what pattern, under what restriction, and what it could not read. A
pattern that matched nothing is evidence about the pattern and the range it ran over. A string that
is absent from the file is not evidence that the feature does not exist, because a protected target
decrypts strings at the point of use and may build a reference by arithmetic rather than by address.

Three states must stay distinct in every report, and no two of them may be collapsed into "no":
`unknown (not attempted)`, `unknown (attempted, blocked by a named condition)`, and
`unknown (attempted, inconclusive)`. A region that could not be read is not the same finding as a
region that was absent. An unreadable value is not a zero, and an absent registry value is not a
`no`.

The host probe is the worked example and it is worth copying. On the measuring host, four
security-feature registry values were absent, and the probe reported their state as unavailable with
the explicit statement that absence is not the feature being off, naming the interface to cross-check
with instead. The security-service state on that host is therefore genuinely unknown. A tool that
had reported `False` there would have been lying in a format nobody questions.

The same rule applies to the grades in this skill. A row that was not attempted is not a row that was
excluded, and a negative measurement raises a row as much as a positive one does, provided it is
recorded with the host, the tool and the command that produced it.

## The scanner reports findings on this repository

The identity scanner, run against the shipped skill surface, does not report `clean`. At the
remeasurement it reported fifteen strong findings and exit code 1, spread across the entry point, the
signature reference, the routing file, one route reference, the reader, and nine in the capability
registry script. Every one of them is the scanner matching this repository's own text, and none is a
real target identity. There are only two shapes:

The first is a language name bound to a version number, caught by the rule for a capitalised product
name with a version. The second is a four-field version number used as an example build identity,
caught both by that same rule and by the rule for a routable address, because a four-field version
number parses as a dotted quad.

The literal matched strings are not reproduced here, and that is deliberate rather than fastidious.
When this section was first written with those strings quoted, the repository's own finding count rose
from five to twenty-two: describing a leak finding in the file that is scanned reproduces the trigger
in the very document that reports it. A report of a finding has to name the shape of the match, not
the bytes, or the report becomes a new instance of the problem it documents.

Two things follow, and neither is an instruction to weaken the scanner. The rule that fires on the
version quad is the same rule that catches a captured target address, so widening its exemptions is
how a real address is let through. And the rule that fires on the language name plus version is doing
its job on a genuinely ambiguous string; the wording of the file is what should change.

A second run, pointed at the repository root rather than the shipped surface, did not complete inside
a 120-second bound because that root also holds a large untracked recon tree. Whether the wider root
carries findings is `unknown`; the run was cancelled, not reported as clean. A whole-repository pass
should be given an explicit tracked-file list.

One further operational limit belongs here, because it is the failure the gate itself produced on this
host. With the console code page set to the local multi-byte encoding, the repository gate crashes
while printing a leak finding, with a character-encoding error on the name of the encoding in use,
and its verdict becomes unreachable. Running the same gate with the interpreter's output encoding
forced to UTF-8 completes and reports the single remaining problem. The gate's own source documents a
related decoding defect it already fixed elsewhere, so this is the same class of bug surviving on a
different line: an encoding that is safe while reading a subprocess's output but not while printing
it. Until it is fixed, a clean-looking gate run on such a console means the gate did not finish, not
that it passed.

## The tree was being written during the measurement

The repository was under concurrent authorship throughout the measurement pass. Scripts were
rewritten between reads, and a script that did not exist at the start of the pass existed at the end
of it. Every citation in `evidence/capability-matrix.json` was produced inside one window in which a
hash of every shipped script was taken before and after the runs and did not change; that hash set is
recorded in the file. Structural facts about which files exist were re-measured at the end of the
window and carry their own timestamp.

A reader of the installed skill does not see any of that, which is why it is written down. A claim
about what this skill covers is a claim about a revision, and a revision moves.

## Host facts that do not transfer

The registry product-name field reads `Windows 10` on the measuring host while the build number is a
Windows 11 build. That is a trap in the field itself, not a quirk of this host, and it is the reason
the probe prints the build number and a warning next to it.

The host probe's report contains a token SID and a path naming the account. That report is an
identity surface: it must be redacted before it is published, and no such value is reproduced in
this repository.

Elevation, hypervisor presence, and which of the security features are enforced are per-host and
per-session facts. Two runs of the same experiment on the same machine at different elevations are
different experiments and must carry the elevation with them.

## What a reader should do with this file

Take the `observed` rows as statements about tools and treat them as true for the pinned revisions;
take the `inferred` rows as procedures that need a verification step of your own; take the
`unverified` rows as plans. Then run the host probe on the machine you actually intend to work on,
and replace this file's host facts with yours. Anything you cannot measure stays `unknown`, with the
search you ran named next to it.
