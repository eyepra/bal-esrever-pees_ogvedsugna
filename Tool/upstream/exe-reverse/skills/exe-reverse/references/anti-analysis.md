# Anti-Analysis

Goal: identify **which** mechanism is actually firing, from evidence the process itself produced, so the
next action follows from a diagnosis instead of from a list of techniques.

## When to load this

Load it when the target reacts to being observed:

- the process dies when a debugger attaches, and only then
- it dies on its own after a delay, with a crash that looks like an ordinary bug
- a breakpoint is never reached, yet the process keeps running perfectly
- it starts on one machine and not another, with no visible error
- a patch produced no effect, and the code around the patch will not read cleanly
- the same input produces different behaviour on the same host

An anti-analysis mechanism is a **branch in the target's own code**: it has an observable input, an
observable consequence, and therefore a way to be told apart from a broken environment.

## Two rules that outrank everything below

**An unexplained death or a hang is a stop signal, not a puzzle.** Stop editing, stop attaching, stop
retrying with a different tool, and record the **time-to-death** with the exact conditions of the run
(attached or not, network up or down, which user). That record is the baseline every later attempt is
measured against, and the delay is itself evidence: a mechanism that kills after a measured interval is one
you can find by looking at what runs during that interval.

**Never neutralise a check by making it never return.** A jump-to-self where a call should return, or a
comparison patched so the branch spins, turns a detectable failure into a silent one: the caller is usually
holding a lock or an object the surrounding code needs, the process freezes somewhere unrelated, there is no
crash record, and the symptom no longer points at the cause. Return a benign value instead, chosen so the
caller's later code takes the working path. If the check's result is discarded anyway, leave it alone and
stop being observed at all (`observe` below).

## The three workaround classes

Every mechanism below resolves into exactly one of these. Name the class before typing anything: it decides
whether the deliverable is a patch, a driver, or a report.

| Class | What it means | Typical form |
|---|---|---|
| `value` | The check runs, reads something, and its **result** is consumed at a point you can reach | Return a benign value at the consumption point, or make the read produce it |
| `avoid` | No value satisfies it, because observing the process is what triggers it | Stop being inside the process: static analysis, a dump, a kernel-side view, an unrelated process |
| `observe` | The mechanism detects the *instrument*, not the analysis | Move the instrument out of the process: hardware breakpoints, tracing, hypervisor-level observation |

`avoid` is the class that gets forgotten and is frequently the correct answer. A target that reads its own
debug registers is not defeated by a clever patch; it is defeated by nobody setting those registers.

## Symptom to mechanism

| Symptom | Likely mechanism | First separation test |
|---|---|---|
| Dies only when a debugger is attached | debugger-presence read, debug-object or debug-port query, hardware-breakpoint or trap-flag read | Run unattached under the same conditions and compare time-to-death (`observed`) |
| Dies a few seconds after start, unattached, crash looks ordinary | timing check, watchdog thread, or a supervisor process | Record time-to-death across three runs; a constant delay is a timer, a variable one a supervisor |
| A breakpoint never fires although the code executes | the site is not the code that runs (unpacking, or a per-run generated copy) | Confirm with a trace or a logging hook rather than a second breakpoint |
| No effect from a patch that is present in the file | a second copy of the routine, self-integrity, or per-run decryption | Compare on-disk bytes against live bytes at the same RVA |
| Refuses to start on one host, runs on another | environment check: firmware strings, hypervisor present, adapter identifiers, installed tools | Read the same environment value on both hosts and compare |
| A read of target memory faults | guard page, or a page whose protection changes | Query the page protection before and after the read |
| Two runs differ with identical input | uninitialised state, timing-dependent branch, or a remote value | Fix the clock and the network posture and re-run |

## Debugger presence

**What it reads.** `IsDebuggerPresent`, which detects a user-mode debugger attached to the calling process,
and `CheckRemoteDebuggerPresent`, which Microsoft's own PEB page names as the supported replacement for
reading the process environment block directly (`observed`). That block's field is `BeingDebugged`: the `PEB`
structure documented in the `winternl.h` surface carries a `BYTE BeingDebugged` immediately after two
reserved bytes, the page states the layout may change, and it points at `CheckRemoteDebuggerPresent` instead
(`observed`). The native route is `NtQueryInformationProcess`: the `ProcessBasicInformation` class (`0`) is
documented as returning a PEB pointer usable to determine whether the process is being debugged, and the
`ProcessDebugPort` class (`7`) is documented as returning the port number of the debugger, where "a nonzero
value indicates that the process is being run under the control of a ring 3 debugger" (`observed`).

Debug-object and debug-flags classes are used by real targets and are **not** on that page, whose documented
set is `0`, `7`, `26`, `27`, `29`, `64` and `75` (`observed`). Treat any number quoted for them as needing
verification on your own build (`unverified`): a wrong class number in a diagnostic tool produces a clean,
confident, wrong answer.

Every read above is routed through a stub in the system library, and a stub is what an injected hook
rewrites. Issuing the system call instruction directly from the target's own code skips the hook, so a hook
reporting "not being debugged" is not evidence that the debugger is unseen (`inferred`). The syscall number
is build-specific and has to be resolved from the target's own stub (`inferred`).

**Symptom, and separating it from a broken environment.** Death or a hostile branch within milliseconds of
attach, often before any window appears; these reads are per-process, so a debugger attached elsewhere is
invisible to them. Run the control, unattached, from an identical command line: if attached dies and
unattached does not, the mechanism is debugger presence and nothing else; if both die, it is elsewhere in
this file. One variable, one run, and skipping it is the most common way this diagnosis is guessed wrong.

**Workaround class.** `value` when the read's result reaches a comparison you can locate, with the benign
value being the "not debugged" one. `observe` when the routine is unreadable or virtualised. `avoid` when
the check is the only obstacle and static analysis answers the question anyway.

## Hiding a thread from the debugger

**What it reads.** A thread can be marked so that its debug events are not delivered, which makes everything
that thread does invisible while the rest of the process stays debuggable. `NtSetInformationThread` is
documented in the WDK, but the classes named on that page are the priority and throttling classes; the class
used for this purpose is **not** named there (`observed`), so the value needs verification on your build
(`unverified`).

**Symptom, and separating it from a broken environment.** The debugger attaches, the process runs, and one
activity never appears: no breakpoint hits, no exception notifications, no thread events, while unrelated
activity behaves normally. Compare what the process *did* (an output file, a log line, a network request)
against what the debugger *saw*: if the declared effect happened and the debugger saw nothing, a thread is
hidden. A genuinely broken session fails uniformly, including on ordinary activity.

**Workaround class.** `observe`. The mechanism aims at the debugger's event stream, so the answer is a view
that does not depend on that stream: tracing, hardware observation, or a second process reading memory.

## Hardware breakpoints and single-step

**What it reads.** The thread's own context. `GetThreadContext` retrieves registers selectively according to
`ContextFlags`, and the x64 `CONTEXT` structure contains `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr6` and `Dr7`
alongside `EFlags`; the x86 view of the same structure carries the same six fields as 32-bit values
(`observed`). The address-register count is therefore **four** in the API surface, matching the four the
architecture provides. The bit-level encoding of `Dr6` and `Dr7` is **not** on the structure pages read and
must come from the processor specification before any bit number is written down (`unverified`). Read the
state, not the numbering: any nonzero value in `Dr0` through `Dr3` means a hardware breakpoint address is
set, and that is already a decision.

**The awkward fact.** These registers are set by *the debugger*, so a target reading them detects the
instrument, not the analysis. Microsoft's text on processor breakpoints states that a user-mode processor
breakpoint "does not affect any kernel-mode processes", while a kernel-mode one may or may not affect a
user-mode process depending on whether that code is using the debug register state and whether a user-mode
debugger is attached (`observed`). That page also states each processor supports only a limited number of
processor breakpoints (`observed`), which is why those four registers are scarce and why watching them means
watching something a debugger cannot hide.

**Single-step uses the same channel.** The trap flag is documented in the debugger's x86 architecture
reference: "If `tf` equals 1, the processor will raise a `STATUS_SINGLE_STEP` exception after the execution
of one instruction. This flag is used by a debugger to implement single-step tracing" (`observed`). The
matching `EXCEPTION_SINGLE_STEP` is documented as "a trace trap or other single-instruction mechanism
signaled that one instruction has been executed" (`observed`). Reading `EFlags` sees stepping as directly as
it sees a hardware breakpoint.

**Symptom, and separating it from a broken environment.** Death on the first step, or the first time a
hardware breakpoint fires, while software breakpoints are ignored. Run with no hardware breakpoints and no
stepping: if the death disappears, the mechanism is the register read; if it persists, it is elsewhere. Do
not attribute an unexplained death to register detection without this run.

**Workaround class.** `observe`. Software breakpoints and stepping both live in state the target can read,
so a software-only session is not a neutral position.

## Timing

**What it reads.** A delta between two reads of a clock: the `__rdtsc` intrinsic, documented as generating
the `rdtsc` instruction, whose result records "the number of clock cycles since the last reset"
(`observed`); `QueryPerformanceCounter`, documented as "a high resolution (<1 microsecond) time stamp that
can be used for time-interval measurements" (`observed`); and `GetTickCount64`, whose "resolution is limited
to the resolution of the system timer, which is typically in the range of 10 milliseconds to 16
milliseconds" (`observed`).

**Why a breakpoint inflates a measured interval.** Halting the process does not halt the clock, so any
interval containing a breakpoint stop, a debugger step, or a suspended thread is larger than the interval the
target intended to measure. That is the whole primitive: it needs no knowledge of the debugger, only a
threshold, and the target calibrates the threshold on its own host.

**Why timing checks also fail for host reasons.** This is the mechanism most often misdiagnosed. Under a
hypervisor the reported performance-counter frequency need not be the hardware value: Microsoft's
high-resolution timestamp guidance states that on some hypervisors, and in some Windows versions generally,
that frequency is fixed at **10 MHz**, so `QueryPerformanceFrequency` must not be assumed to return a
hardware-derived value (`observed`). The same guidance states that Windows checks at system initialization
whether the time stamp counter is usable and selects an alternative time source when it is not, because
processors with a non-invariant counter vary or stop that counter (`observed`), and states plainly that
direct use of the counter instruction is discouraged because results are unreliable on some Windows
versions, across virtual-machine live migrations, and on hardware without invariant or tightly synchronized
counters (`observed`).

**Host fact for this project.** The development host reports `CPUID.01H:ECX[31]` set and runs under a
hypervisor, on a 12th Gen Intel Core i7-12700H (`observed`), so every timing measurement taken there carries
a hypervisor in the path. Treat that as a property of the lab rather than of the target, and confirm the
architectural meaning of the bit in the processor specification before relying on it as a general rule
(`unverified`).

**Symptom, and separating it from a broken environment.** Death or a hostile branch after a delay of
seconds, unattached, with no debugger present; a roughly constant time-to-death belongs to a timer rather
than to a supervisor thread. Measure the same interval the target measures, on the same host, in a process
you control: if your own control loop reports a wildly inflated interval, the host is the variable and the
target's threshold is being crossed without an observer. Then vary one thing at a time (affinity, competing
processes, power policy). If the death tracks your debugger rather than the interval, the mechanism is
debugger presence read through the clock.

**Workaround class.** `value` when the comparison is reachable. `observe` when the comparison is threaded
through code that also does real work, because there the honest move is to stop perturbing the interval.

## Exception-based detection

**What it reads.** How an exception was dispatched, or whether it was delivered at all. `DebugBreak` is
documented as causing "a breakpoint exception to occur in the current process", and the same page states
that if the process is not being debugged it "uses the search logic of a standard exception handler", which
in most cases terminates the process as an unhandled breakpoint (`observed`): one instruction, two
behaviours, depending on whether a debugger consumes it, with `EXCEPTION_BREAKPOINT` documented as "a
breakpoint was encountered" (`observed`). `RaiseException` is documented as raising "an exception in the
calling thread" (`observed`), which lets a target route an arbitrary exception through its own handlers and
branch on which handler ran. `SetUnhandledExceptionFilter` installs a filter "that will be called whenever
the `UnhandledExceptionFilter` function gets control, **and the process is not being debugged**"
(`observed`); that conditional is the mechanism, since installing a filter that sets a flag, then triggering
an exception the target's own handler absorbs, distinguishes an attached run from a clean one without calling
any debugger-detection API.

An interrupt whose Windows behaviour is reported by anti-analysis corpora but is **not** documented by
Microsoft was not verified here: any claim that a particular software interrupt is consumed differently
under a debugger needs a local experiment with a control run (`unverified`).

**Symptom, and separating it from a broken environment.** Correct behaviour inside the debugger and
incorrect behaviour outside it, or the reverse, with no detection call anywhere in the trace. Before blaming
the target, check the reserved-handler list: for images marked as containing reserved structured exception
handling, the PE specification states that a handler must appear in the load configuration's sorted handler
table for the image, "otherwise the operating system terminates the application" (`observed`). An injected
handler, or a dump whose load configuration was not rebuilt, produces the same death as a deliberate trap.

**Workaround class.** `value` at the filter or the handler, with the benign value chosen so the working path
continues. `observe` when the dispatch difference *is* the mechanism, since a debugger that does not create
the difference is the only neutral position.

## Memory and page checks

**What it reads.** Page state and page contents. `PAGE_GUARD` is documented as making pages "become guard
pages", where any attempt to access one "causes the system to raise a `STATUS_GUARD_PAGE_VIOLATION`
exception and turn off the guard page status", and the documentation supplies the reading itself: "guard
pages thus act as a one-time access alarm" (`observed`). A target that makes its own code a guard page learns
somebody read it, and the alarm is consumed by the first read, which is why the same probe succeeds the
second time. A code checksum digests a range of the image and compares it against a stored value, where the
scope (a page, a section, the whole module) decides the patch strategy. A page whose write permission
changes turns a later write into a fault that looks like a crash rather than a check. The PE specification's
load-configuration guard flags include one documented as "module supports read only delay load IAT"
(`observed`), a supported way for an image to ask the loader to protect a table a repair tool wants to write.

**Symptom, and separating it from a broken environment.** A fault on a read that a normal process permits; a
probe that works once and then fails; a crash whose address lies in a data page. Query the page's protection
before and after the read and compare against a known-good process mapping the same kind of page: if the
protection changed, the target changed it; if it did not, the fault belongs to your access method.

**Workaround class.** `value` when the digest is compared at a single site: patch the comparison, not the
digest, and remember the digest may be recomputed at intervals rather than once. `observe` when the digest is
stored remotely, which puts the decision outside the binary and out of reach of a local edit.

## Self-debugging and a supervisor

**What it reads.** Whether an event reaches the process's own debugging loop. `DebugActiveProcess` is
documented as enabling "a debugger to attach to an active process and debug it"; the system suspends all
threads, sends process, thread and load events, and then arranges for the first thread to execute a
breakpoint instruction, producing an exception event for the debugger (`observed`). A process that attaches
to itself is its own debugger, so exceptions stop reaching the handlers the code installed. Attaching to
another process needs sufficient access, and a debugging process needs the debug privilege to debug any
process (`observed`). The supervisor variant is not an API at all: a second process watches the first and
kills it, or withholds data, when the first stops reporting. Nothing in the target detects the instrument;
the instrument's *absence* is the signal.

**Symptom, and separating it from a broken environment.** A second process appears before or with the target,
or the target's own thread list contains a thread whose stack is a debug event loop; handlers that
demonstrably work elsewhere never run. Enumerate the target's threads, identify those whose start address is
outside the image, and suspend and resume them one at a time: if suspending a non-main thread kills the
process, it was being watched by its own code or by a sibling. A broken environment does not produce a death
tied to one specific non-main thread.

**Workaround class.** `value` where the target consumes its own debug loop's verdict. A supervisor needs
`avoid` for the target plus a decision about the supervisor itself, and that decision is a scope question:
the deliverable sentence must say which processes are in scope.

## Environment checks

**What it reads.** Properties of the machine rather than of the session. `GetSystemFirmwareTable` is
documented with a provider signature for the raw SMBIOS table and separately for ACPI tables, and only the
raw SMBIOS table can be read from a restricted application container (`observed`). The same strings appear
through the computer-system class of the management interface, whose `Manufacturer` and `Model` properties
are documented as mapping to SMBIOS Type 1 system information and which carries a boolean property reporting
a present hypervisor (`observed`). Hypervisor present is also readable from the processor's own reporting; on
this project's development host that bit reads set and the host is virtualised (`observed`), while the
architectural meaning of the bit is to be taken from the processor specification (`unverified`). Adapter
identifiers, installed services and installed analysis tools are string comparisons against a list.

**Symptom, and separating it from a broken environment.** Refusal to start, an immediate exit with no
message, or a feature that silently stays off; because the check runs once at startup it produces a clean "it
does not work on this machine" with no runtime evidence at all. Read the same value the target would read on
both hosts and compare: a host that trips such checks is a host whose measurements are suspect everywhere
else in this file, which is the argument for a lab machine that is deliberately uninteresting.

**Workaround class.** `value` when the comparison is reachable. `avoid` when the check is a startup gate
whose only purpose is to refuse: analyse the binary statically instead of running it, and say so in the
report.

## What this file does not contain

No names of targets or anti-analysis products, because the subject is the mechanism class. No bit numbers for
`Dr6` and `Dr7`, no exception class numbers for the native query classes and no thread-information class
value: each was searched for and not found on the pages read. And no coverage of instruction tracing or host
capability, which decide which `observe` routes exist on your machine.
