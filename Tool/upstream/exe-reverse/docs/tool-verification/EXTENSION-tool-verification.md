# Extension: tool verification

How the toolchain claims in this skill were established, and which of them remain documentation only.

## Method

For each tool or mechanism the skill depends on, three questions were asked in this order:

1. **Is it present on the host that did the work?** A path lookup and a version call, recorded in
   `TOOL-VERDICTS.md`. Absence is a finding, not a failure.
2. **Is what the skill says about it true?** Wherever possible from the tool's own documentation or
   the platform's own specification — not from a recollection, and not from a secondary summary.
3. **Has the route been run?** If not, the claim is `inferred` or `unverified` and the missing step is
   named. `references/evidence-summary.md` carries the grade.

The order matters. A tool that is present but whose behaviour is described from memory is worse than
an absent tool, because the description reads as verified.

## What is `observed` and can be re-run

These rest on commands whose output exists, and every one of them needs only Python plus a file on
disk — no third-party sample, no debugger, no network:

- the reader parsing real platform images and generated fixtures, and reproducing the declared checksum
  on unmodified images;
- RVA-to-file-offset translation in both directions, including the virtual-only tail that has no bytes
  on disk;
- import, export, resource, TLS, debug and relocation parsing against fixtures that declare their own
  expected values;
- the patch pipeline end to end: a read-only input, a new output, a recomputed checksum, every patched
  byte re-read from the written file, and the input's hash unchanged;
- the patcher's refusals, each exercised deliberately: an ambiguous pattern, a mismatch against
  expected bytes, and a length that cannot be established;
- pattern location with its hit counts and verdicts, including the zero-match and multi-match cases;
- fixture generation, deterministic in bytes and parsing back through the reader;
- the host probe's three-state route table and its raw CPUID reporting;
- the identity scanner on this repository.

## What is `inferred` and why

A mechanism described from its documentation, with the tool absent from the development host.
Debugging workflows, injection and hooking, dump repair, managed tooling, installer extraction,
kernel debugging and driver loading are all in this category. For each, the reference states the
mechanism and its requirements, and the evidence summary names what would raise the grade: a run.

This is the honest position, and it is deliberate rather than accidental: the alternative is to write
procedures that have never been executed in the register of ones that have.

## What is `unverified` and why

Two kinds of thing sit here, and they are different problems.

**Hardware-bound routes.** The trace unit and the branch-record registers are reachable only from
privileged code, and the host used for this work runs under a hypervisor. The probe reports what the
processor advertises and what the platform permits; the route itself was not exercised. A reader with
a bare-metal host and a driver can move this row, and the documentation says so rather than implying
the route is unavailable in principle.

**Details whose normative source was unreachable.** Where a vendor or platform specification could not
be opened from this environment, the detail is either omitted or labelled. The list is in
`TOOL-VERDICTS.md` under "what is deliberately not asserted", and it exists so that a later pass
knows exactly which gaps to close rather than re-discovering them.

## Corrections this pass made

Facts that were checked and turned out to contradict the widely repeated version. Each one is now
stated in its corrected form where the skill needs it, because a reader acting on the common version
builds the wrong plan:

- a strong name is identity, not an anti-tamper mechanism, and is not validated at load on current
  runtimes;
- a precompiled managed image is not thereby locked — methods can still be replaced at run time,
  while a natively compiled deployment is the one that removes the readable layer;
- a dialogs-suppressing switch on a disassembler's command line is not the switch that runs a script;
- an undocumented build-fingerprint block in a PE header has no normative source, and a parser for it
  must say so;
- the largest minidump configuration can carry more than a nominal "full" one, and a flag commonly
  read as "everything" is documented as unsupported for user-mode dumps;
- a page-guard breakpoint fires once, and treating it as a watchpoint loses every access after the
  first;
- a copy-on-write image page is still reported as an image, so distinguishing it needs the working-set
  information;
- an administrative installation of a package removes its digital signature;
- a certificate in the image is a statement about the digest, which is why editing the file while
  preserving the digest does not happen;
- there is no single timing packet in the trace format, and the branch-record depth is a per-generation
  capability rather than a constant.

## The rule this pass produced

**A tool's absence is a finding, and a tool's behaviour described from memory is a defect.** The first
is cheap to record; the second propagates as a fact. Everything in this directory exists so a reader
can tell which of the two they are looking at.
