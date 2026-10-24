# Verification: what "done" means for a Windows target

Verification is the difference between a patch that exists and a patch that works: this file fixes the claim ladder, the evidence each rung requires, and the six conditions a Windows deliverable must satisfy before it is called done.

## When to load this

Load this when you are about to claim the work is finished, when you need to define "finished" for a
reviewer or a handover, and whenever a result feels obviously correct. It applies to all four
deliverable forms this skill produces: a patched EXE or DLL, a live memory patch, a keygen or
activation tool, and a static analysis report. The last of those is not exempt: a report's claims
have rungs and conditions in exactly the same way a patch does.

## Strength labels used here

- **observed**: reproduced here, with the artefact named (a command and its output, a file and its
  hash, a header field, a process exit code, a screenshot that was inspected).
- **inferred**: follows from observations by a stated step, and the step can be attacked on its own.
- **unverified**: asserted from documentation or expectation, not reproduced here. It may shape a plan
  and must not be a premise for a stronger claim.

A claim is bounded by the weakest evidence in its chain. An observation at rung 3 does not repair an
unverified step at rung 1 that rung 3 depended on, and no passing check below can promote an
unverified step above it. Missing coverage is written as `unknown`, never as absence: "the check
reported nothing" and "the property is not present" are different statements, and only the first one
was measured.

## The claim ladder

Each rung is a stronger claim, and it needs the evidence in this column. Climb as high as the
deliverable requires, and state which rung was reached.

| Rung | Claim | Evidence required |
|---|---|---|
| 0 | "The bytes are edited" | A byte-level diff against the pinned baseline copy, listing every changed offset and both values |
| 1 | "The image is structurally intact" | Re-parse with `peutil.py`: section table still coherent, directory sizes consistent, entry point inside an executable section, checksum recomputed for the new bytes |
| 2 | "The loader accepts it" | The process starts and is still alive at two samples spaced apart; for a DLL, the module is listed in the loading process |
| 3 | "The change is reached at run time" | Execution arrives at the patched address in the same run that was observed (a breakpoint hit, a hit counter, a trace record), or the patched instruction's effect is read out (a register, a return value, a branch direction) |
| 4 | "The declared behaviour changed" | The specific user-visible outcome differs from the control run, captured before and after in the same session |
| 5 | "Nothing adjacent regressed" | The neighbouring features were exercised: open and save, print or export, the update path, the licence or settings dialogs, any network path the program uses |
| 6 | "The mechanism is proven" | Independent evidence of why: the check never runs, the comparison is fed equal values, the branch is never taken, the flag is read from a location that is now constant |
| 7 | "The delivered artefact is the verified one" | Re-read the copy that is leaving your machine and compare its SHA-256 with the file you tested |

Rung 2 is the minimum for any file deliverable. Rung 3 is required before any claim that a patch
does anything, because rung 0 to rung 2 are all statements about a file that the loader may never
execute in the state you think. Rung 4 is required for the claim that the problem is solved. Rung 5
before handing anything to a user. Rung 6 when the claim is a mechanism rather than an outcome. Rung
7 whenever the artefact leaves your machine.

## Is the patch actually reached, or only present?

This distinction is where most false success lives, and it is measured, not argued.

The file-level observation is cheap: a two-byte difference was observed here between a working copy
of a system binary (360448 bytes) and a patched copy of that same file. Offset `0x000160`
changed `73 -> F7`, and offset `0x0019B0` changed `48 -> CC`. The first is the image checksum field,
consistent with a recomputed checksum; the observed header line confirms it, since `peutil.py`
reported declared checksum `0x5e673` on the original and `0x5e6f7` on the patched copy, each matching
its own computed value (observed). The second offset equals the entry point RVA reported for that
image, and the section table maps that RVA to the same file offset (both observed; the identification
of `0x0019B0` as the entry-point byte is therefore inferred from those two observations).

What that byte change does at run time is a separate question with a separate answer:

- Observed: the patched copy terminated 4006 ms after launch with exit code `0x80000003`.
- Unverified: that `0x80000003` is the documented breakpoint status, and that the byte written at the
  entry point is what produced that code. The mapping is asserted from documentation here; the fault
  was not inspected. Another `int3` anywhere in the executed chain would look identical.
- Observed and unexplained: the byte-identical unmodified copy of the same system binary, launched
  from the same directory, left no process that survived one 400 ms sample. The mechanism is
  unverified. That is a property of the environment until a control says otherwise, which is exactly
  why the control exists.

Practical rules that follow:

- Presence in the file is rung 0 and nothing more. Reading the patched bytes back out of the file
  proves the write, not the execution.
- Establish reach with an instrument that observes execution of that address in that run: a breakpoint
  or one-shot run in a debugger, a page-guard style trap, or a trace record. Name the instrument and
  keep its output; the claim is "the address was executed in run R", not "the patch works".
- Reach evidence must be tied to one process instance and one session. A record from an earlier run,
  or from a different build, does not establish reach for this run.
- If the image is packed or otherwise self-modifying, the file bytes may not be the bytes that
  execute. Establish that the code at the patched RVA is the code the loader executes before
  interpreting any breakpoint as a hit (unverified for the general case; the observed patched copy
  above shows the file byte taking effect, which is consistent with an unpacked image).
- A debugger that makes the process die at the patch site has proven reach, not success. Rung 3 is not
  rung 4.

## "The process started" is not "the feature changed"

The observable for "it started" is weaker than it looks, and it is easy to write down as if it were
the goal.

| Observable | Establishes | Does not establish |
|---|---|---|
| process id exists | the loader accepted the image | that the program is doing anything useful |
| process id alive at two spaced samples | not a crash loop, not an immediate self-exit | which code path ran |
| a window exists | UI initialised | that the window is the one under study, or that any control works |
| the window content was inspected | the rendered state | the state's cause |
| the declared feature behaves differently from the control | rung 4 | that the mechanism is what you think it is |
| exit code | that the process ended with that code | what produced the code |

Sampling rules that cost nothing and catch most confusions: sample process liveness twice with a gap,
because a single reading cannot distinguish a stable process from one that is about to die or is
already restarting; capture the exit code whenever a process ends, because it is the cheapest piece
of information the OS gives away; and check for children, since a launcher that hands off and exits
will otherwise look like a failed launch (observed as an open question here: the unmodified desktop
copy left no process, and no child process check was made, so the cause stays unknown).

The user-visible outcome is the deliverable, not the process. An internal improvement (a cleaner
parse, a quieter log, a shorter diff) is not progress; write down what a user would see differently.

## Visible-outcome evidence, and why absence of an error is not evidence

Absence of an error message is compatible with at least four different states: the feature ran and
succeeded, the feature never ran, the error is reported somewhere you are not reading, or the process
never reached that code. It is therefore the weakest available signal and it is the one most often
quoted.

Evidence that does work:

- A positive observation of the changed state, read out rather than inferred: a value in a dialog,
  the contents of a settings key, a file the program wrote, a window whose content you inspected.
- A before/after pair from the same session, with the control run supplying the "before".
- For a gate or a trial limit: walk the gated flow end to end and trigger the condition that used to
  block it, then confirm the flow completed rather than that no dialog appeared.
- For a check that is supposed to be skipped: show that the check's code never executed (a breakpoint
  that was never hit, a counter that stayed at zero), which is a positive observation of zero, not an
  absence.
- For a UI outcome: capture continuously across the moment the element would have appeared. A single
  screenshot of a clean screen does not prove the absence of a dialog, because the dialog can appear
  and be dismissed between two samples. Two byte-identical consecutive captures are a finding (the
  screen is static), not a capture artefact.
- If an error path is possible, read it rather than assume it: a message box, a log file the program
  writes, or the exit code. An application that reports the failure through its own channel looks
  exactly like an application that succeeded, if you only look at the channel you chose.

## Prove the artefact under test is the artefact you built

Every conclusion rests on "the binary I am observing is the binary I produced". That assumption is
false more often than any other, and a wrong artefact does not look wrong; it looks like a result.

Pin four things and keep them apart:

- The received sample, copied once, read-only, never run: this is the baseline, and its hash belongs
  in the record before the first experiment.
- The build you wrote: hash it immediately after writing it.
- The file the OS actually loaded: read the path the process reports for the loaded module and hash
  that file, at observation time rather than an hour earlier (that the OS exposes this for a given
  process is a route to confirm per tool, not something to assume).
- The copy you publish: hash it after publishing, because a copy can truncate.

A matching file name proves nothing. A matching size proves nothing beyond a length coincidence. The
hash is the identity, and a hash is only comparable within the same tool and the same file; record
the algorithm with the value. Where a PE debug directory is present, its CodeView record carries a
PDB path and a GUID that identifies a build more precisely than a timestamp does (that `peutil.py`
parses the debug directory is observed from the script source; that the GUID is a reliable build
identity is a documented property and unverified here).

Two traps specific to this file format. The PE checksum is not a hash: it is a weak integrity field,
recomputed over the image, and some installers and loaders treat a mismatch as a damaged file while
others ignore it entirely (the recomputation is observed in `pepatch.py`'s source as a step it
performs; the refusal behaviour is unverified). And the linker timestamp is not proof of provenance;
it is a field, and it can be zeroed, preserved or forged, so use it as a hint and hash for identity.

If you tested a memory patch, the file on disk is a different artefact and the honest claim is about
the process, not the file. If you tested a file, do not present a run that used the old copy.

## The six conditions for "done"

A Windows deliverable is done when all six hold. Each one is a statement with evidence, not an
impression.

1. **Identity is pinned.** The artefact under test is the one produced for this task, by hash; the
   baseline is a separate copy with its own recorded hash; the byte diff against the baseline is
   exactly the intended change and contains nothing else. The diff is the evidence for this
   condition, and "nothing else" has to be shown by reading it, not assumed.
2. **The loader accepts it, in the declared environment.** The process starts and stays alive, or the
   library loads into a process that stays alive, on the host build and snapshot recorded in the
   report. Anything that only loaded on a different OS build, a different elevation level or a
   snapshot with different security settings is a different result and must be labelled as such.
3. **The change is reached, in the observed run.** Rung 3 evidence, tied to one process instance, one
   session, one artefact hash.
4. **The declared outcome changed, positively observed.** Rung 4: a before/after from the same session
   with the control supplying the before, described in terms of what a user sees or reads.
5. **The neighbours were exercised.** Rung 5, with the list of what was checked. An unexercised
   neighbour is `unknown`, not "fine".
6. **The scope is stated.** Rung 6 or 7 as applicable, the host build and tool revisions the run used,
   an explicit list of what was NOT verified, and the residuals named with their reason. A deliverable
   without this condition is not less correct, it is just unusable, because the next reader cannot
   tell which parts are load-bearing.

What those six conditions mean per deliverable form:

| Deliverable | Conditions 1 to 3 in practice | Conditions 4 to 6 in practice |
|---|---|---|
| Patched EXE or DLL | The output file is a new file whose hash is recorded; the baseline stays untouched and read-only; a re-parse shows a structurally coherent image; the process runs and stays alive from that exact file | Rung 4 on the feature the patch targets, plus the neighbour list; the mechanism by which the patch produces the outcome; the delivered copy re-hashed |
| Live memory patch | The target's on-disk hash and the process id are recorded; the patch is applied to a named address range, and the write is read back from the process rather than from the patch script's intent | The outcome observed while the patch is live, plus what happens after the process restarts (state whether the change is persistent or session-scoped), plus the exact script and address so the run is reproducible |
| Keygen or activation tool | The tool's own hash, the input format it accepts, and the fact that the generated values are accepted by the unmodified target | The acceptance observed on the target's own surface, not on the tool's own self-check; the mechanism (which validation accepts the value) at rung 6; a statement about what was never tested, such as another build or another edition |
| Analysis report | Every cited artefact exists on disk with a hash and was produced by the run described | Each claim carries its rung and its label; the report states the host build and tool revisions; the unverified coverage is named in the same section as the claim it limits, not in a closing paragraph |

## Reporting

```
Artefact:      <path> <sha256> (<size> bytes)
Baseline:      <path> <sha256> the received sample, copied once, never modified
Changes:       <file offset or RVA> <before> -> <after>, one line each, with the reason per site
Structure:     re-parse result after writing (sections, directories, checksum recomputed?)
Host:          OS build <build>, elevated <yes/no>, hypervisor present <yes/no>, VBS state <state or unknown>, snapshot <id>
Tooling:       <tool>: <version or "not available">, per tool actually used
Runtime:       process id observed <n> times over <window>; exit code <code or "still running">
Reach:         <instrument> showed execution at <address> in run <id>
Outcome:       <feature> before <state> / after <state>, control run <ref>
Neighbours:    <list exercised>
Rung reached:  0..7, per claim
Not verified:  <what was not checked, named explicitly, with the check that would settle it>
Residual:      <what is still broken or unmet, and why>
```

Two rules for this block. Every number in it cites the pin that makes it comparable (host build,
snapshot, tool revision), because a measurement without its pins is not reusable. And the "not
verified" line is not optional: an unverified area named next to the claim is a limit a reader can
work with; the same area left out reads as coverage.

## Anti-patterns

- Calling a byte change a fix, without rung 3.
- Reporting a process that started as a feature that changed.
- Treating a quiet log, an absent dialog or a missing error message as a pass.
- Quoting an exit code without establishing what produced it.
- Sample a process once and calling it stable.
- Claiming an outcome for a file you patched while the run used a stale copy, or vice versa.
- Reusing a hash and a result from an hour ago as if it described the current file.
- Testing on a host state different from the one named in the report, and not naming the difference.
- Checking the neighbours you remember and staying silent about the ones you did not check.
- Reporting the unverified parts by omission instead of by name.
- Citing an analysis as support for a stronger claim than the analysis itself established.
