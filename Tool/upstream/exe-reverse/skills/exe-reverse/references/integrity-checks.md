# Integrity checks: recognising self-verification

Goal: identify which check fired before choosing an instrument, because the two routes out (neutralise
the comparison, or never modify the checked bytes) depend on what the check reads.

## When to load this

- The patched binary will not start, or dies before your changed code is reached.
- The patched binary starts and one feature silently never works.
- The file checksum no longer matches and something now refuses the binary.
- The process behaves differently on a signed build than on an unsigned one.
- The target dies at a roughly constant time after launch, with a crash that looks like an ordinary bug.

## The two routes out, and when each applies

**Route A, neutralise the comparison at equal length.** Make the comparing instruction answer
"unchanged" (or answer "benign") without moving any byte. This keeps a file patch viable, but it only
defeats the specific comparison you found: a duplicate, a second range, or a supervisor keeps working.

**Route B, move the change to memory.** Leave the checked bytes untouched and change behaviour after
the check has read them. This defeats every check that reads file bytes or embedded digests, and it
fails against every check that reads mapped pages or re-reads the file from disk.

| Check reads | Route A viable | Route B viable |
|---|---|---|
| The file on disk (opens it, or hashes bytes read from the file) | yes | yes, the file never changes |
| The image mapped in memory, by page range | yes | no, your bytes are inside those pages |
| Its own headers in memory | yes | no |
| A digest stored in the image and compared there | yes | no |
| A digest sent to a service that answers | yes locally, not remotely | no |
| Nothing local: a supervisor process | partially | partially, the supervisor must still be satisfied |

## What each check reads, and how to tell it fired

**PE checksum.** Reads the image checksum field (`CheckSum` at offset 64 of the optional header in both
PE32 and PE32+; `observed`, PE Format specification) and recomputes the file's checksum to compare.
The recomputation is available to the target through the documented ImageHlp pair `MapFileAndCheckSum`
(file name in, declared and computed checksums out) and `CheckSumMappedFile` (mapped image in,
`observed`). How to tell: the import list names ImageHlp, or the routine dynamically resolves it; the
declared checksum in the file differs from the recomputed one; the target refuses before rendering
anything. Which images the *loader* validates is narrower than people assume, and the format
specification states it precisely: drivers, DLLs loaded at boot time, and DLLs loaded into a critical
process (`observed`). A failure on an ordinary executable is therefore the target's own check rather
than the loader's.

**Section-level hash.** Reads one section's bytes and compares against a stored digest. How to tell: a
digest-shaped constant (16 bytes for a 128-bit digest, 32 for a 256-bit one) in a read-only data
section, referenced from a routine that runs before the code you changed; the section name or size is
usually visible as an immediate or as a data reference immediately before the digest compare. The
range chosen is the tell: a check over `.text` fails when you patch code and passes when you patch
data, and a check over `.rdata` does the opposite.

**Hash over a code range.** The same mechanism with an explicit start and length. How to tell: a
hash-init, hash-update, hash-final sequence whose update argument is a code address and a size, often
fed the image base from a module-handle call. Ranges that exclude the headers, or that start a fixed
distance into the section, indicate a check that tolerates header edits and refuses code edits.

**Page-guard traps.** A page guard is a one-shot access alarm: the platform sets guard status on a
page and an access raises a guard-page violation, after which the guard status is cleared and the
underlying protection applies (`observed`; memory protection constants, `PAGE_GUARD`, which raises a
guard-page violation and "turn[s] off the guard page status", described as "a one-time access alarm").
How to tell: a violation appears where the target itself does not fault; a routine installs protection
changes on its own pages before the code you changed runs; the first access behaves differently from
the second. A guard page is also how a target can notice that something *read* its code, so a
disassembler that walks the mapped image rather than the file can trigger it.

**Queries about its own image.** The target can ask the kernel what its own address space looks like,
through the documented wrapper `VirtualQueryEx` and the native query family behind it, and compare the
answer with what it expects. The useful detail for a patcher is what such a query *can* and *cannot*
show: a code page that has been written through copy-on-write is still reported as part of the image
rather than as private memory, and detecting the modification requires the working-set `Shared` bit
through `QueryWorkingSet` or `QueryWorkingSetEx` (`observed`; `VirtualQueryEx` remarks). So a target
that checks page state only sees the obvious cases, and a target that checks the working-set bit is
specifically looking for modified code pages. The specific native information classes are not part of
the published API surface; read them from the target's own call sites or from the headers the toolchain
ships rather than from memory.

**A self-diff against the on-disk copy.** The target re-opens its own file and compares bytes against
its mapped image. This catches a memory patch and is indifferent to a file patch in the opposite
direction: a file edit changes both sides and compares equal, which is why "the file patch worked and
the memory patch did not" is not an unusual outcome. How to tell: an open of the module's own path
early in startup, followed by a read of comparable length and a byte comparison.

**Debugger-visible self-checks.** Timing deltas around a routine, exception-based probes, reads of
processor debug registers, and reporting of anomalies to a window or a debug output channel. These
share one property: they detect an observer rather than a modification. How to tell: the behaviour
changes only when an observer is attached, and the unmodified original behaves the same way under the
same observer, which is the control that separates "the target dislikes observers" from "the target
dislikes my patch".

**A second process supervising the first.** Two shapes. A supervisor starts the target and inspects it
(injection, memory reads, restart on exit), or the two mutually supervise and each restarts the other.
How to tell: a second process with no user-facing purpose appears in the same tree; a named event,
mutex or pipe ties them together; killing one causes the other to react, either by exiting or by
restarting it; the target's own log mentions a companion. In-process periodic verification by a worker
thread looks similar from the outside and is distinguished in the same way: the check runs on a timer,
so the failure arrives after the feature worked once.

**Authenticode verification.** The target verifies its own signature, or asks the platform to. The
documented entry point is `WinVerifyTrust`, whose generic action verifies a file or object using the
Authenticode policy provider, whose return value is a status code where only zero means trusted, and
whose failure for a tampered subject surfaces as a "subject not trusted" status (`observed`; the
`WinVerifyTrust` documentation describes the action identifier, the zero-means-success rule, and
`TRUST_E_SUBJECT_NOT_TRUSTED`). How to tell: the import list shows the trust library; the failure
appears on a signed build that you edited and not on an unsigned build you edited the same way; a
catalog-based check looks similar but resolves the digest through a catalog rather than the file's own
certificate table, so an unsigned build fails a catalog check and an unsigned build usually skips a
self-signature check. The consequence of an edit is structural: the attribute certificate states the
digest the image is expected to have, and modifying a file while keeping that digest is, in the
format's own words, "very difficult" (`observed`; PE Format specification). A target doing this will
report the same failure whether or not the platform itself cares.

## Never neutralise a check by making it loop forever

A stub that never returns is not a neutralised check; it is a permanent stall inside the caller. The
caller frequently holds a lock, an allocation, or a per-process initialisation flag while it waits, so
the damage is not confined to the check: other threads block on the same lock, the feature that needed
the result waits forever, and the failure surfaces as a freeze or as a feature that silently does
nothing. There is no crash record, no exception, and no error text, so nothing in the target's own
reporting points at the edit. The symptom then gets attributed to the feature rather than to the patch,
and the next hour is spent reading the wrong routine.

Answer a check with a value instead. Return the benign result at equal length: the "unchanged" outcome
for an integrity comparison, the "present" outcome for a presence test, success rather than failure
where the caller only branches on a boolean. If the comparison's result is consumed arithmetically,
find the value that makes the arithmetic produce the benign answer rather than editing the branch,
because skipping a branch does not skip the arithmetic that fed it.

## Sequencing, duplicates, and the control

Checks are ordered, and a check that runs before the code you changed explains a crash rather than a
missing feature. Two habits prevent the most common wasted cycle:

- **Enumerate every site that asks the same question.** Integrity checks are duplicated by design.
  Search for the digest constant, the checksum API, and the comparison opcode across the whole image,
  not in the routine you happened to find first. Symptoms from a surviving duplicate: the target runs
  for a while, or long enough to open a window, and then exits.
- **Keep the unmodified original as the control for every experiment.** If the original, run under the
  same conditions, also fails or also exits, the cause is the environment (an expired trial, a missing
  service, a clock that is wrong, a host state that was already modified) rather than your patch. That
  distinction is not available after the fact, which is why the control is captured first.

## Proving an integrity check was the cause

The claim "an integrity check was blocking me" needs evidence, and the evidence is a difference:

1. The original and the patched build differ only in the patched bytes, and both are run under the same
   conditions, on the same host, in the same session.
2. The patched build fails while the original succeeds, or fails at a different point in the sequence
   with a different symptom.
3. Neutralising the comparison you identified changes the outcome; neutralising an unrelated comparison
   does not.
4. With the comparison neutralised, the feature you are actually after now behaves differently, so the
   check and the gate were both upstream of it.

If step 4 fails, the integrity check was a second problem rather than the problem, and the classification
of the gate is still open. Which mechanism owns the gate is a different question from whether the binary
verifies itself, and the answer to the first is in `references/license-mechanisms.md`.
