# Environment: host, isolation, snapshots and capture

A Windows reverse-engineering result is only as good as the machine it was produced on: this file covers the isolated analysis environment, the facts about the host that decide which routes exist, and how to keep the observation window clean enough that a conclusion can be attributed to the target.

## When to load this

Load this before the first execution of an unknown sample, before snapshotted work begins, and again
whenever a result surprises you, whenever a route fails at its first step, or whenever the target
behaves differently from the control. It is also the file to re-read before writing the environment
and pins section of a report, because the pins are cheap to record now and impossible to reconstruct
later.

## Strength labels used here

- **observed**: reproduced here, with the artefact named (command output, registry value, header
  field, process exit code, script source at a stated revision).
- **inferred**: follows from observations by a stated step.
- **unverified**: asserted from documentation or expectation, not reproduced here. It is a plan input
  and never a premise for a stronger claim.

Reading a registry value or a capability report is an observation of that source, not of target
behaviour. Missing coverage is `unknown`, never absence.

## Build the environment before the first touch

Work in a virtual machine you can revert, and take a snapshot before the sample runs for the first
time. The reason is not hygiene, it is measurement: a revert is the cheapest control this domain
offers, and a target that writes machine state (settings, licences, trial counters, drivers,
scheduled tasks, its own cache) is not comparable to itself after a run unless the state is restored.

Operationally:

- Keep at least two snapshots: one clean baseline (no sample has ever run) and one work state (tooling
  installed, sample copied in, nothing executed). Record the snapshot identifier next to every result,
  because a result produced at a different snapshot is a different experiment.
- Revert before a run whose outcome a conclusion will rest on, rather than after. Reverting afterwards
  loses the state that explained the result.
- Do not run an unknown sample on the machine you rely on. The sample's behaviour is unknown by
  definition at this stage; a licence check, an updater or a self-installer can write state that
  outlives the investigation.
- Expect a first launch after a revert to be slower than the second. Take timing baselines after the
  host has settled, and record which launch the number came from.

## The copy, the hash and the baseline

The received sample is a permanent reference and is never modified, never run and never patched in
place. Copy it once into the working directory, hash both the received file and the copy, and record
both hashes with sizes. If they differ, the copy is not a copy and nothing measured against it means
anything.

The patcher in this skill embodies that rule rather than describing it: `pepatch.py` opens its input
read-only, writes a new output file, re-parses the output after writing, re-reads every patched byte
and compares, and refuses a length-changing replacement unless explicitly allowed (observed from the
script source, not from a run). The output file is a new artefact and needs its own hash.

Keep three files distinguishable at all times, ideally by name and directory rather than by memory:
the received baseline, the built output, and the control (an unmodified copy used to establish that
the launch path and the environment behave normally). Label them in the record by hash, not by name,
because names drift and hashes do not.

Two file properties are worth checking once, because both change what a launch means:

- **Alternate data streams.** A file that arrived through a browser or an archive extraction tool may
  carry a `Zone.Identifier` stream, and the OS may then gate its execution. The streams on a file are
  readable without admin rights (`Get-Item -Stream *` was used here; observed). In the samples
  inspected here only the default `:$DATA` stream was present, so no such gate applied.
- **Whether the copy is a copy.** A workspace sample that is byte-identical to a system binary (same
  size, same SHA-256; observed here against the desktop text editor in the system directory) is a
  convenient fixture, but its launch behaviour may depend on its location or on a component the
  original has and the copy does not. Treat an unexpected exit as an environment question first.

## Record the host, because it decides which routes exist

Four host facts change which techniques are available. Record them with the result, every time,
because they are the pins that make two runs comparable.

| Host fact | How to read it | What it changes |
|---|---|---|
| OS build | The build number, from the OS itself, not the marketing name | Loader behaviour, security posture, which APIs exist. Observed here: the product-name field reported "Windows 10" while the build number was 26100, which is a Windows 11 build; the capability probe's own note states that the product name keeps saying "Windows 10" on Windows 11 and that the build number is the reliable field. Record the build number |
| Elevation | Whether the current session is elevated | Kernel providers, driver operations, reading some processes, and several debugger attach paths. Observed here: the authoring session was elevated (token elevation reported true) |
| Hypervisor present | A CPUID bit and an OS-reported flag | Debug exceptions and hardware breakpoints may be intercepted rather than reaching your handler; MSR-level routes need kernel privilege; some timing-based checks change. Observed here: the hypervisor bit (`CPUID.01H:ECX[31]`) was set and the OS also reported a hypervisor present |
| VBS / HVCI state, and driver-loading policy | Registry values and, where available, the WMI class that reports the security services running | Whether unsigned or test-signed drivers can load, and what a debugger is allowed to do. Also boot configuration flags; observed here as `none`, meaning no debug or test-signing boot flags were set |

The VBS row is the clearest worked example of the reporting rule in this skill. Observed here: the
`DeviceGuard` key under the control set existed and was readable, but the specific values inside it
(enable flag, required platform security features) were absent, and the documented cross-check class
(`Win32_DeviceGuard`) was not available on this SKU, returning an invalid-class error. Consequence:
the VBS state on that host is `unknown`. It is not "off". An absent registry value is missing
coverage, and a probe that cannot run reports `unavailable`, not `false`.

A second discipline: when a capability report contradicts itself, resolve the row's meaning before
using the value. The probe's route table listed interactive user-mode debugging as available while
its tool inventory listed the graphical debugger as not found; the two rows answer different
questions (is the machine's posture blocking the technique, versus is the tool present here). A route
whose tool is missing is `needs-tool`, not `available`, and the difference matters the first time a
plan depends on it (observed tension in the same report; the reading of the two rows as answers to
different questions is inferred).

## The three-state vocabulary for anything environment-related

Report every environment capability in one of three states, and never collapse them:

- `available`: measured to work on this machine, with the measurement named.
- `needs-<something>`: the mechanism exists, and it is gated on something the row names (a driver, a
  reboot, a tool install, a privilege level, a second machine).
- `unavailable`: measured absent, or the probe could not run. When the probe could not run, say so,
  because "not supported" and "not measured" are different facts with different next steps.

Missing capability is a finding about the machine, not a failure of the task. The capability probe
shipped with this skill follows exactly that rule: it never exits non-zero because a machine is
limited (observed from its source and from a run here that exited 0 while reporting several
unavailable routes).

Tool inventory, run once and recorded with revisions. Observed on the authoring host, as an example
of the shape rather than a recommendation: available were `python` plus the `pefile`, `capstone`,
`lief`, `unicorn` and `frida` modules, a MinGW toolchain (`gcc`, `objdump`, `strings`, `gdb`), `wpr`
and `logman` for trace sessions, `dotnet`, `go` and `git`; unavailable were a graphical debugger, the
kernel and command-line debuggers, time-travel debugging, the MSVC header tools (`dumpbin`,
`editbin`, `link`), signing tools, a packer identifier, a process dumper, a capture reader, and the
`keystone` and `yara` modules. Three rules come out of that list. An absent tool narrows the route
and says nothing at all about the target. A script that depends on a missing tool must fail with a
named reason and the same exit-code discipline the other scripts use (`2` for usage, a distinct code
for input the tool cannot read, and never a code that means "a finding about the target"). And the
inventory report itself is an identity surface: the JSON emitted here contained a token SID and
absolute paths including the account name (observed), which is exactly what must be replaced before
that report is published.

## Anti-VM and anti-sandbox behaviour: whose property is it

A target may inspect its environment: the hypervisor CPUID bit, timing behaviours such as the
instruction counter and the timestamp counter, device and driver enumeration, firmware and vendor
strings, and the presence of analysis tooling (mechanisms asserted from documentation; unverified
here). Your analysis VM is also a VM, so a hostile-looking result has two candidate readings, and
they are not equally likely:

- The target refuses to run under a hypervisor.
- Our environment is missing something the target needs, or the launch is gated by the host for an
  unrelated reason.

The observation that separates them is the control, not reasoning: run the unmodified baseline copy
through the identical launch path in the same snapshot with the same tools. If the baseline behaves
the same way, the environment is implicated. Observed example from this workspace: a byte-identical
copy of a system binary, launched from a non-system directory, left no process surviving one 400 ms
sample, with the mechanism unexplained. Nothing about that observation says the sample refuses VMs,
and nothing about it says the sample is broken; it says the launch path needs a control before any
conclusion is written.

Practical rules:

- Record the hypervisor bit as a fact about your host, and remember that the target can read it too.
  Reported as `observed` here: it was set on the authoring host.
- Do not weaken host security settings on a machine you depend on. If a route genuinely needs a boot
  configuration change (test signing, debug boot flags), do it inside a snapshot you can revert and
  write down what changed, because that change becomes a pin for every measurement taken afterwards.
- If the target's environment check is itself the analysis object, find the check statically first and
  name it. Then decide deliberately whether the bypass is part of the deliverable or part of the lab.
  A lab-side bypass is legitimate; presenting it as the deliverable is not.
- Never conclude from a single run. A detection result and a flaky launch look identical once.

## Network isolation and which captures to take

Decide isolation before the first run, because reachability changes target behaviour: a licence or
update endpoint that answers produces a different flow from one that times out, and a target that
cannot reach its server may show a state that looks like a licence failure (asserted from documented
behaviour of licence and update flows; unverified here).

Choose deliberately among: no network at all, host-only so the VM can talk to the analysis host, and
address-translated with the internet reachable. Record which one was in force for each run, next to
the snapshot id, because a behaviour change between two runs is otherwise unattributable.

Take the captures as a set, not as one artefact:

- Name lookups, including the names that do not resolve, since a failed lookup is evidence that the
  endpoint was attempted and is often the reusable part of the finding.
- Connection attempts with their endpoints and ports, and the timing relative to the launch.
- TLS handshake metadata (server name and, where present, the negotiated protocol and certificate
  subject). Certificate subjects frequently carry the vendor and organisation identity that must be
  redacted later.
- Request and response content, if the transport can be read; state the transport and why it was
  readable, and do not generalise from one decrypted channel to another.
- The host-side writes a run performs, since files and registry changes are part of the behaviour and
  part of what a revert restores.

Start the capture before the launch and keep it running past the point where you believe the target
has finished, because late update checks are common. Keep the raw capture file: a summary made while
capturing cannot be re-examined later, and the question you will want to ask is usually not the one
you anticipated.

Captures nobody looked at are not evidence. Read the capture you intend to cite, and state what you
read. A capture taken while the wrong process was in the foreground, or before the launch actually
started, describes something other than the target and does so in a convincing format.

## Keep the observation window clean

Every conclusion rests on "the process I observed was the one I launched from the file I built". Keep
that assumption enforced rather than assumed:

- State the window explicitly when a capture or a measurement will carry a conclusion: from this
  moment to this moment, this is the only thing running. Do not patch, install, revert or restart
  inside the window.
- Timestamp the window. It costs one line and it is the only way to notice later that a background
  job, an update service or your own earlier script landed inside it.
- Change one variable per run: one byte, one flag, one host setting, one launch method. A compound run
  that fails produces a compound explanation, and compound explanations survive far too long.
- Prefer one continuous run over several short ones. A restarted capture invites a restarted state.
- Sample the observable you actually care about, with a cap, and look at the samples. For a
  process, that is liveness at two spaced readings plus the exit code; for a UI state, that is a
  frame sequence you inspected rather than a duration you hoped was right.
- When a window turns out to be contaminated, discard it and re-capture. A re-run costs minutes; a
  conclusion drawn from a mixed window costs the rest of the task, and the record will defend it as
  observed.

## When the analysis machine itself is detected

Symptoms that the host, not the target, is the problem: the launch succeeds but the process ends
almost immediately; a window never appears; the target exits after a check that the control run did
not reach; a debugger attach terminates the process; name lookups stop resolving mid-session; a nag or
warning text appears that the control never showed.

Procedure, in order:

1. Establish whether the control shows the same behaviour, in the same snapshot, with the same launch
   path and the same window. If the baseline does the same, stop debugging the patch.
2. Check the obvious environment regressions before theorising: is the analysis tooling still
   running, is the trace session still recording, is the sample the file you think it is (hash it
   again), is the host still at the snapshot you started from.
3. Separate "the target detected us" from "the host refused the launch". Both look like an immediate
   exit; they are distinguished by whether the same file launched from a different location (or as
   the original system component rather than a copy) behaves differently, and by whether an OS-level
   diagnostic exists for the attempt. Observed above: a copy of a system binary that exits
   immediately with no surviving process, whose mechanism stayed unknown.
4. If the target's detection is the object of the study, name the check and keep the run
   single-variable: one lab change per run, recorded with its snapshot id.
5. If the detection is an obstacle rather than the object, prefer moving the observation to a route
   the target does not gate (a static route, a debugger route, a snapshot-restored run) over weakening
   the host. Note in the record which route was abandoned and why, so it is not re-attempted.

## Preflight, then work

The rule that makes all of the above worth doing: do not attribute a failure to your patch while the
environment is unverified. Run the capability probe, confirm the pinned hashes, confirm the snapshot
id, confirm the tool inventory you depend on, and only then run. The probe takes about two seconds
(observed: 1858 ms for the JSON report on the authoring host), and the same order of magnitude for a
static parse is measured too (158 to 167 ms for a 360448-byte image). Spending that time is cheaper
than spending several rounds on a conclusion that the environment caused and the record will keep.

## Anti-patterns

- Running the first sample on a machine you cannot revert.
- Patching or executing the received copy in place.
- Recording a tool version, a hash or a result without the host build and snapshot it belongs to.
- Writing an absent registry value or a failed probe as "off" or "no".
- Treating a missing tool as a property of the target.
- Concluding anti-VM behaviour without an unmodified control in the same environment.
- Changing isolation, elevation or boot configuration inside a measurement.
- Taking a capture and never reading it, or reading a capture of a different process.
- Changing two variables in a run and calling the result an explanation.
- Publishing the capability report as-is, including the account path and the SID it prints.
