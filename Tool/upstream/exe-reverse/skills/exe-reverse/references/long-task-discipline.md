# Long-Task Discipline

A long investigation into one Windows image fails from judgement drift rather than from missing tools: this file keeps what is proven, what is assumed and what is still open in a form that survives a lost context, a long wait and a handover.

## When to load this

Load this before any investigation that will outlive one working session: several rounds on the same
sample, a long-running dynamic run, a task resumed by someone else, or a task where the analysis
machine will be snapshotted, reverted and re-entered. Load it again at the start of every resumed
session, before the first command, not after the first surprise. If the whole task fits in one
sitting and one screen of notes, this file is overhead and the four rules in "Keep a live record"
are the only part worth reading.

## Strength labels used here

- **observed**: reproduced here, and the artefact that shows it is named (a command and its output, a
  header field read from a file, a registry value, a script's source at a stated revision, a
  screenshot that was actually inspected).
- **inferred**: follows from one or more observations by a step that is stated. The step is the
  weakest link and can be attacked on its own.
- **unverified**: asserted from documentation, from expectation, or from another person's report, and
  not reproduced here. It stays usable as a hypothesis and as a plan input; it never serves as a
  premise for a stronger claim.

Two consequences that matter more than the labels themselves. Reading a header field is an
observation of that header, not of run-time behaviour, so a source-level observation never closes a
run-time claim. And a claim is only as strong as the weakest piece of evidence in its chain: an
observation of step 3 does not upgrade an unverified step 2 that step 3 depended on.

Imperative guidance in this file ("hash the copy", "revert the snapshot") is a procedure, not a
claim about the world, and carries no label.

## Keep a live record, not a log

The failure this prevents is cheap to avoid and expensive to discover late: an investigation that
re-derives what it already proved, re-walks a route it already excluded, and keeps acting on a
conclusion that was never verified. All three happen because conclusions live in a conversation
instead of in a file.

Keep one file as the authoritative state of the task, and write to it while working. A single file
beats a folder of outputs: the point is that the decision-relevant content is in one place a
decayed context can still read.

The sections, and what each is for:

| Section | Contents | Why it exists |
|---|---|---|
| Target identity | file name as received, size, SHA-256 of the received copy, SHA-256 of the working copy, architecture, subsystem, whether it is signed | the identity triple (hash, size, arch) is what every later claim is pinned to |
| Deliverable sentence | one sentence naming the artefact and the constraint it must satisfy | a constraint discovered in round nine invalidates rounds one to eight |
| Proven facts | one line each, with the check that showed it | the basis for everything else |
| Refuted hypotheses | what was believed, the check that killed it, what replaced it | the most valuable entries in the file; deleting them re-arms the mistake |
| Open questions | what is still unknown, phrased as a question a check can answer | keeps the next action honest |
| Next action | exactly one step, and the observable that will judge it | removes the "where was I" tax from every resumed session |
| Environment pins | OS build, elevation, snapshot id, tool versions, the routes that are available here | the pins without which two measurements are not comparable |
| Measured timings | how long each operation class actually took on this machine | the numbers that turn a timeout into a signal |
| Dead routes | route, the evidence, and the single-variable state it was tested in | the largest single time saver on a long task |

A layout that works as a file, and that stays skimmable at the top:

```markdown
Task: <id>
Target: <name as received> | <size> bytes | sha256 <hash> | <amd64|i386> | signed <yes/no>
Deliverable: <one sentence: artefact + constraint>
Snapshot: <vm snapshot id> | OS build <build> | elevated <yes/no> | pins: <tool revisions>

## Proven (do not re-derive)
- <fact> [shown by: <command or artefact>]

## Refuted (do not retry)
- <hypothesis> [killed by: <check>] -> replaced by <what>

## Open
- <question> [would be answered by: <check>]

## Next action
- <one step> | judged by: <observable>

## Environment and timings
- <operation class>: <measured duration> on <host build> at <snapshot id>

## Dead routes
- <route> [evidence] [single-variable state]
```

Two rules make the file worth its cost. Every proven fact cites the check that showed it, because an
unattributed line is how an assumption is promoted to a fact by repetition. And a refutation is a
first-class entry, not an edit: record both the wrong conclusion and the check that killed it, since
the mechanism is what stops the same idea from returning in a new shape.

Keep the file itself out of anything you publish. It is written while the target is in front of you,
so it is where the target's identity lands first.

## Grade the conclusions, and never let a label drift upward

Most long-task damage is not a wrong measurement. It is a hypothesis that became a fact because it
was repeated, and it is invisible because labels are not visible in prose.

| Grade | Requires | May it steer a decision? |
|---|---|---|
| observed | the artefact, and the check that read it | yes, within the artefact's scope |
| inferred | the observations, the step between them, and what would falsify the step | provisionally, and the step must be stated when the claim is used |
| unverified | nothing beyond an honest label | only as a test to run, never as a premise |
| refuted | the check that killed it | never; keep it as a warning |

Two habits keep this honest. Before using a conclusion in a plan, look up its grade in the record; if
it is not observed, either observe it or restate it with its real label. And when a claim is carried
into a report or into a later round, carry the label with it, because the reader of the summary does
not have the record.

Missing coverage is `unknown` and must never be written as absence. "The probe reported nothing"
and "the property is not there" are different statements, and the second one is what a summary
usually ends up saying. Write `unknown` and name the check that would have resolved it.

## Drift control at checkpoints

Cheap checks, run only where they can change a decision:

- **Before a new experiment**: read the refuted and dead-route sections. If the plan is in either,
  read why before running anything.
- **Before declaring progress**: say out loud what the user-visible outcome is right now. An
  internal signal improving (a cleaner parse, a shorter diff, a quieter log) is not progress towards
  a changed behaviour.
- **After any surprise**: write it down with the raw observation before forming a theory. A theory
  composed after the fact is hard to tell apart from an observation, especially by your own later
  reading.
- **Before an irreversible step**: state the constraint sentence from the record and check the step
  against it. An in-memory patch is not a patched file. A patch that dies with the process is not a
  persisted change. A bypass that only works while a debugger is attached is not a deliverable. This
  is where a long task most often succeeds at the wrong goal.
- **When context feels long**: write to the record instead of re-reading the conversation. The
  conversation will be truncated; the file will not.
- **When resuming, including resuming your own earlier work**: read the record first, and treat
  anything not in it as unknown, however familiar it feels.

## Bound every wait from a measured baseline

Unbounded waits are the most expensive failure mode that produces no information at all. A helper
that launches a process, attaches a debugger or waits for a window without a bound will hang, and the
failure presents as "the task stopped progressing" rather than "this call blocked".

A timeout is only meaningful relative to how long the operation should take, because that difference
is what makes "slow" and "hung" distinguishable. Measure once on this machine, write the number into
the record, then derive the bound from it. Numbers measured on one host at one snapshot are
comparable only to runs with the same pins; state the pins next to the number.

Operation classes, with the measured anchors that exist for this skill:

| Operation class | How to bound it |
|---|---|
| static parse by the skill's own reader | measured here: `peutil.py --summary` on a 360448-byte image took 158, 166 and 167 ms over three runs. Bound similar parses at a small multiple of that, scaled by image size |
| capability probe of the machine | measured here: `hwprobe.py --json` took 1858 ms. It reads CPUID through an allocator, so it is host work, not target work |
| GUI process cold start to a visible window | measure once on the same host and snapshot; a first launch after a revert is slower than the second |
| a launch whose outcome is "the process ended" | observed here: an image patched at its entry point settled 4006 ms after launch. The settle time includes whatever the OS does around a fault, so it is not the failure time |
| launching a copy of a system binary from a non-system directory | observed here: the process did not survive a 400 ms sample, and no further process appeared over four seconds. Bound it, and treat the outcome as a property of the environment until a control says otherwise |
| a debugger one-shot run under a snapshot | measure per debugger and per target; expect tens of seconds, and set the bound from the measurement rather than from the example |
| a repack, installer or update step | unbounded in principle; do not wait on it inside a blocking call |
| waiting for a visible UI state | bound it and sample it; a fixed sleep measures the wrong instant |

Every wait in a script ends with a deadline, an observable and a verdict on expiry:

```
waiting for : <observable>              e.g. process id alive, window title present, byte at RVA changed
sample      : <how and how often>       e.g. every 400 ms: process list, module list
give up at  : <deadline>                e.g. 20 s
on expiry   : <what is concluded>       e.g. "did not complete inside the window", never "cannot work"
```

A deadline that passes is a measurement of latency or state, not a verdict about the approach.
Writing "still not finished after N seconds" into the record as "does not work" is how a viable route
is discarded, and the record will defend the mistake later.

Prefer one bounded observable over a fixed sleep, and never busy-poll a long job while independent
work is available. Start it in the background, do the other thing, and collect it when it settles.

## Single-variable discipline, and the zero-change control

The most durable wrong conclusions come from compound experiments: two changes, one failure, one
invented explanation. The failure is real, so the explanation feels earned.

The control in this skill is the unmodified sample, kept as a separate file with its own recorded
hash, run through the same launch path, on the same snapshot, with the same tooling and the same
observation window. If the control fails, nothing measured in the patched run means anything yet:
the environment, the launch path or the host state is implicated, and the patch is not. If the
control passes and the patched run fails, the patch is implicated, and the next step is to bisect one
patch site at a time rather than to reason about the whole diff.

Rules that follow:

- A route abandoned after a compound experiment is not yet excluded. Re-read the evidence; if two
  variables moved, re-run single-variable before writing it into the dead-route section.
- Change one byte, one flag or one host setting per run. `pepatch.py` refuses a length-changing patch
  unless `--allow-resize` is given, and reports it as a structural change (observed from the script
  source, not from a run); that refusal exists because a length change moves every later offset and
  then the failure has two candidate causes.
- A revert is not a variable. After `revert to snapshot`, re-measure the control, because a reverted
  host is a new state until it is shown to behave identically.
- Record the control's result in the same section as the experimental result. A result stored without
  its control cannot be interpreted later.

## Long-context decay

Past a certain conversation length, settled conclusions lose their force: something verified two
hours ago becomes one plausible belief among several, and the cheapest route from a stuck point to a
feeling of progress is to retry what already failed.

Symptoms worth recognising in yourself:

- About to run a command whose result is already in the record.
- About to re-derive a value (the entry point RVA, the patched offset, the image hash, which
  snapshot is current) that the record already holds.
- About to re-attempt an approach that failed, without an obvious link in mind to that failure.
- Treating a conclusion as solid that was assumed early and repeated since.
- Rewriting a summary of the task from memory instead of reading the record, which is how a
  one-line error becomes a paragraph of confident nonsense.

The antidote is a record written for the second half of the task rather than for a reader at the end.
The four-line shape that survives a weakened context:

```markdown
## Settled (verified; do not re-derive)
- <fact> [shown by: <check>]
## Refuted (do not retry)
- <approach> [fails because: <mechanism>]
## Unverified assumptions currently in play
- <assumption> [becomes a problem if: <condition>]
## Next action
- <one step> | judged by: <observable>
```

Record the mechanism, not just the outcome. "The patch is in the file but the entry point never runs,
because the loader rewrote the section before the first byte is executed" survives a context loss and
prevents a second attempt. "The patch did not work" invites one.

Two failures of the same shape mean the model is wrong, not the parameters. Do not run a third
variation of the same idea; change the question instead.

Re-verifying is cheap; re-deciding is not. Reading a byte back out of the image costs a second and is
always allowed. Re-running a whole experiment because its conclusion was forgotten is what costs the
round.

## Summary first, complete record retained

Long work produces more material than any reader will consume: full captures, complete process
listings, an entire byte diff, a full trace. Two rules keep that material usable.

The report you hand over is a **summary**, and the complete record stays addressable behind it. Write
the summary so it answers the decision the reader actually has, and keep every full artefact in place
with an identity (path plus hash) that the summary names. A summary that requires the reader to
re-run a producer to answer a follow-up is not a summary, it is a rerun, and on this kind of task the
rerun may not be reproducible at all once the snapshot has moved.

The reverse rule: do not compress by deleting. A summary that omits the evidence for one of its own
claims is unreviewable, and a claim whose full artefact was overwritten can never be re-checked.
Where a result is too large to present, present the summary, name the file, and state the number of
items omitted rather than dropping them silently.

Any numeric limit that appears in a report (a timeout, a sample count, a size cap) carries the
measurement that set it, and the pins that measurement was taken under. A limit without its
measurement is indistinguishable from a guess the next reader will either ignore or, worse, trust.

## Handover

A handover is the record plus three things, written for a reader with no memory of the task:

1. Operating rules first: the mechanical facts that silently waste time when unknown (which snapshot
   is clean, how the sample is launched, where the tooling lives, which routes this machine cannot
   provide).
2. Honest current state, including what is not achieved. An optimistic summary costs the next person
   more than an accurate one, because they will build on it.
3. The next best step and why, plus the dead routes so they do not start there.

Two items belong in every handover because they are the hardest to recover: what you got wrong, with
the check that corrected it, and what you never verified, stated plainly. "Not confirmed" is more
useful than silence, and it is the second item that keeps an unverified assumption from arriving in
the next session wearing the label of an observation.

## Avoiding the opposite failure

- Do not log everything. Record what would change a future decision or prevent a repeated mistake. A
  record nobody reads is worse than no record, because it looks like coverage.
- Do not treat the record as authority. The host, the file on disk and the live process are ground
  truth. If the record disagrees with a fresh observation, re-test and correct the record.
- Do not let grades calcify. A hypothesis that has become testable is a task, not an archive entry.
- Do not let this file's structure dictate the work. An empty section is fine; an invented entry to
  fill it is not.
