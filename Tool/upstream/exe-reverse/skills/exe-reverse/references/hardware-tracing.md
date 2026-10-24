# Hardware observation: breakpoints, tracing, and the OS-level substitutes

Goal: know which observation mechanisms the hardware on this machine actually offers, what each
one records, and which of them needs a driver, a privileged session, a second machine or bare
metal before a plan can depend on it.

## When to load this

Load this when every software route is detected or forbidden: a target that checks its own
bytes, a check you must observe without modifying anything, a question of the form "which path
did this take" rather than "what value was compared", or a hot-address list you cannot map to a
routine. Load it also when a plan depends on a hardware capability, because that is the plan
this file exists to stop before it is written: **the hardware layer is conditional, and the
condition is measured on the host, not assumed from the CPU's marketing name.**

## The layer is conditional: read this before planning

Every row is a prerequisite. A missing one is a finding, and a plan that skips the check is the
failure this file is for.

| Mechanism | Requires | Not available when |
|---|---|---|
| Hardware breakpoints through a user-mode debugger | An x86/x64 CPU (the architectural facility), a debugger that can set them, and a process whose threads you may modify | A virtualisation layer intercepts the debug exception, the four slots are already taken, or the target reads the debug registers rather than the bytes |
| Hardware breakpoints through a kernel debugger | A kernel debugging session, so the kernel-cost rows in this table: a second machine or a disposable virtual machine, plus the boot configuration that enables debugging | Local-only debugging, where the target cannot be stopped |
| Instruction and branch tracing (Intel Processor Trace) | CPU support, **plus a privileged capture path**, plus the exact image that ran | No CPU support; a guest the hypervisor controls; no way to reach the trace output |
| Last branch records / performance counters | Privileged access to the model-specific registers | No privilege, or the facility is already owned by another consumer |
| A system-wide event tracing facility (ETW) | An elevated session for kernel providers | Not elevated: user-mode providers remain, kernel events do not |
| A record-and-replay debugger (TTD) | A debugger installation, an elevated session, and a user-mode target | Kernel-mode targets, protected processes, or a process the recorder cannot attach to |
| Kernel debugging of any kind | Two machines, or one machine plus a virtual target, a supported debug transport, and boot configuration changes | BitLocker or Secure Boot policy that refuses the change, or a policy that forbids the debug configuration |
| Your own instrumentation at the hypervisor layer | A kernel driver, signing or test mode, and a host not already nested inside another hypervisor | Code integrity enforcing policy, a driver blocklist that names your driver, or an outer hypervisor |

The host probe in this skill prints which of these this machine has, as named routes: hardware
breakpoints, Intel Processor Trace capture, last branch records and performance counters, kernel
driver load and test signing, the record-and-replay debugger, and ETW capture. It reads CPU
capability directly from the processor rather than from a product string, prints raw register
values for any leaf whose bit meanings were not verified against a primary source, and refuses
to decode those it cannot cite. Read its output before choosing a row.

## Hardware breakpoints

### The architectural facts

From Intel's published processor specification (Intel 64 and IA-32 Architectures Software
Developer's Manual, the combined volumes PDF on Intel's documentation host, debugging chapter,
sections 18.2.1 to 18.2.4 in the revision read; re-check the numbering in the revision you
open). `observed`:

- Debug registers are **privileged resources**: a move instruction that accesses them can be
  executed only in real-address mode, in system management mode, or in protected mode at a
  privilege level of 0, and an attempt from any other level raises a general-protection
  exception.
- Their primary function is to set up and monitor **from 1 to 4 breakpoints, numbered 0 through
  3**, with address registers `DR0` through `DR3`. The architectural count of four is therefore
  confirmed against the specification, with the qualification that the number in use at any
  moment can be fewer.
- Per breakpoint the architecture defines: the linear address, the length of the location (1, 2,
  4 or 8 bytes), the operation that must be performed there for an exception to be generated,
  whether the breakpoint is enabled, and whether the condition was present when the exception
  fired.
- The **read/write field** per breakpoint occupies bits 16, 17, 20, 21, 24, 25, 28 and 29 of the
  control register; the **length field** occupies bits 18, 19, 22, 23, 26, 27, 30 and 31; the
  status register records which breakpoint condition fired.
- The read/write encoding depends on a control-register flag. With it set: execute only, data
  writes only, I/O reads or writes, or data reads or writes but not instruction fetches. With it
  clear, the I/O case is **undefined** and the other three keep their meanings, which is why I/O
  breakpoints are an x86 kernel-mode facility rather than a general one.
- The **length encoding** is 1 byte, 2 bytes, undefined (or 8 bytes on processors that document
  support), and 4 bytes, in that order. If the read/write field says instruction execution, the
  length field must say 1 byte; other lengths are documented as undefined. So "how many bytes can
  a data breakpoint watch" has two answers, 4 and, on supporting processors, 8, and the 8-byte
  case is per-model rather than general.
- Address plus length defines a **range of sequential bytes**. An access that overlaps the range
  without being identical to it is processor-dependent, and the platform's breakpoint
  documentation says so and defers to the processor manual rather than resolving it.

Windows-side behaviour, `observed` from Microsoft's processor-breakpoint documentation: access
types are execute, read/write, write, and I/O (I/O being kernel-mode and x86 only); the size may
be 1, 2 or 4 bytes on an x86 target and 1, 2, 4 or 8 on an x64 target; when the access type is
execute the size must be 1; processor breakpoints "are stored in the processor's debug
registers"; a breakpoint set on one processor applies to all processors; and the processor
distinguishes breakpoints set by a user-mode debugger from those set by a kernel-mode debugger.

### Execute versus data access

These are two mechanisms sharing one register file, not one mechanism with a size setting.

- **Execute** compares the instruction pointer against a linear address. It fires on the fetch,
  so it fires regardless of what the instruction does.
- **Data access** compares the addresses touched by loads and stores. It has no notion of value:
  it cannot break when a variable equals something, only when a byte range is read or written.
  Every "break on the licence key" idea is really "break when this range is touched, then look at
  what was there".
- They compete for the same four slots, they need different sizes (execute must use length 1),
  and they produce different kinds of stop to reason about.

### The property that makes this layer worth having

**A hardware breakpoint does not modify the bytes it watches.** The breakpoint lives in the
processor's register file and in a comparison the processor performs; the code and data under
observation stay exactly as they were. The contrast is documented directly: a software breakpoint
"temporarily replaces the contents of that memory location with a break instruction", such
breakpoints "cannot be used in read-only code or any other code that cannot be overwritten", and
to break in that code "you must use" the processor breakpoint with the execute option
(`observed`, Microsoft's processor-breakpoint documentation).

Consequences, and they are why this mechanism occupies a whole layer in this skill:

- A target that hashes its own code before running it sees unchanged bytes. The hash matches,
  the anti-patch check is satisfied, and the breakpoint still fires.
- A target that checks the first byte of a function for a breakpoint instruction finds nothing.
- Code in read-only memory, or in a section the target never writes, can still be observed.
- Nothing in the file, the sections or the image changes, so the observation leaves no artifact
  for a checksum to find and no state that survives a restart.

### It is not invisible: what can still see it

The bound is mechanical, not clever: **the breakpoint is visible to anything that reads the
debug registers.**

- The registers are architecturally readable at privilege level 0, and Windows exposes them to
  user mode through a thread context: the x64 `CONTEXT` structure documented by Microsoft
  contains `Dr0`, `Dr1`, `Dr2`, `Dr3`, `Dr6` and `Dr7` fields (`observed`). A process can inspect
  the debug-register state of its own thread with no kernel component at all.
- The debug status register records which breakpoint fired, so the exception path is itself
  evidence that a breakpoint existed.
- A hypervisor can be configured to intercept the debug exception before the guest's handler sees
  it, which turns a hardware breakpoint from an instrument into a detection event.

So state it narrowly every time this route is proposed: **invisible to a check that compares
bytes, visible to a check that reads the debug registers or observes the exception.** A plan
built on the first half alone has removed one detection channel, not detection.

### Cost and failure modes

- **Four slots, machine-wide semantics, shared with everyone**: the debugger's own breakpoints,
  other tools, and an execute and a data breakpoint all compete for the same file.
- **Data breakpoints are address-based only.** Find the address first with another instrument,
  and expect it to move between builds.
- **Overlapping accesses are processor-dependent**, so verify on the actual processor.
- **A debug-register check converts this into a detection.** If the target reads its own context
  and reacts, the honest answer may be a written conclusion about the check rather than a bypass.
- **Stepping is a separate mechanism with its own visibility**: surviving a hardware breakpoint is not evidence about single-stepping.

## Instruction and branch tracing

Intel Processor Trace answers "which path did this take" for code you cannot or must not modify.

### What it records

`observed`: the processor specification's own summary of the packet categories, plus the kernel's
documentation for this facility, give the following.

- **Control flow**: taken/not-taken packets track the direction of direct conditional branches;
  target-IP packets record the target of indirect branches, exceptions, interrupts and other
  branches or events, possibly compressed; flow-update packets give the source address for
  asynchronous events and, in the manual's words, for other cases where "the source address
  cannot be determined from the binary"; mode packets report the execution mode.
- **Timing**: coarse timestamp packets, finer mid-granularity packets, and cycle-count packets
  emitted only alongside another packet. Timing is packet-driven, not per instruction.
- **Synchronisation**: a packet-stream-boundary packet periodically gives the decoder a place to
  start, or to resynchronise after an error.
- **Asynchronous events**, including interrupts, faults, VM entry and exit, and interrupt-flag
  state, in a dedicated event-trace packet family.
- **Software-injected data**: a dedicated instruction writes a value into a packet. This is the
  exception that proves the rule below: data appears in a trace only when the program puts it
  there.

### What it does not record, and why that decides the question

**It does not record data values, register contents, or memory contents.** A trace is control
flow and timing and nothing else; the packet list is the proof, since a conditional branch yields
only a direction and an indirect branch only a target address, and the single packet carrying a
data value is produced by an instruction whose entire purpose is to inject it.

| The question | Can a trace answer it | Why |
|---|---|---|
| Which function ran, in what order, and how it got here | Yes | That is what the trace is |
| Which side of this branch was taken | Yes | A direction packet, once the decoder finds the branch |
| Did this run reach this block or this comparison | Yes | Addresses are enough |
| What string, key or identifier was compared | No, not from the trace | Nothing records the value; you learn the address of the comparison, not its operands |
| How long something took | Approximately | Timing is coarse and packet-driven, not per instruction |

The consequence is a reformulation rather than a rejection: a trace tells you **where to stand**.
It turns "I cannot find the check" into "the check is at this address, reached after this
sequence", and the value question is then answered by a breakpoint, a dump, or the algorithm.

### Reaching the output is the constraint, not decoding it

The trace unit writes into a buffer the operating system has programmed, and programming that
buffer is a privileged operation. `observed`: the specification's enumeration leaf for this
facility reports the output scheme (a table-of-physical-addresses scheme, spelled `ToPA` in the
revision read) together with an output base and an output mask register, and reports whether
packet generation can be disabled by software, whether tables can hold an arbitrary number of
entries, whether a single-range output scheme is supported, and how many configurable address
ranges are available for filtering. Getting bytes out of that buffer therefore requires
privileged code, or an existing tracing facility that already owns the unit.

`unknown`, and it is the important unknown here: **this pass found no first-party documentation
of a supported capture interface on Windows.** Intel publishes the format and a decoder;
Microsoft documents its own tracing framework; neither page read here documents a turnkey way to
collect this trace on Windows. Treat the capture path as the open question on this platform,
answer it by probing and testing on the actual build, and do not confuse CPU support with capture
support.

Two complications to carry into any capture plan: a virtualisation layer's controls "may suppress
packets needed for decoding" and "may block" the notification the host uses to drain the buffer,
both of which produce decoding errors or lost data rather than a clean failure.

### From packets to an address stream

Decoding is solved, by a vendor-maintained reference library whose documentation describes the
decoder layers (raw packets, events, queries, instruction flow, blocks) and PSB-based
synchronisation. Its sample tools dump packets and reconstruct the instruction flow, which is the
step you need: packets are not an address stream. Two properties matter before depending on it:
it needs the configuration used at capture time (the documentation notes decoding needs the
recorded settings, and that some processor-specific errata must be applied), and its objects have
documented threading rules (separate decoders may run concurrently, one decoder may not be shared
across threads, and decoders must not share one image object).

### The image requirement

A trace cannot be decoded without the code that ran, byte for byte.

- The decoder walks the executed instructions to interpret direction packets. The documentation
  states it directly: a direction packet only says whether a conditional branch was taken, so "to
  make use of that packet the decoder must know precisely which instruction was being executed".
- The decoder needs a memory image of what was traced and reports a specific error when it meets
  an instruction pointer outside that image; the image can come from file sections or a callback,
  and without it decoding stops rather than guessing.
- `observed`: the kernel's tracing documentation states the executed images are needed, which
  makes just-in-time-compiled environments and self-modifying code a challenge, and that symbols
  are needed to make sense of addresses.

Belongs in the plan: **you must have the exact build**, not the version string; hash every module
involved; expect decoding to break at generated code; and report addresses as module plus offset,
because a bare address is meaningless the moment the image changes.

### Cost: volume, loss, and decoding errors

`observed`: the same kernel documentation states the facility "produces huge amounts of trace
data (hundreds of megabytes per second per core)", that decoding "takes a long time", "two or
three orders of magnitude longer than it took to collect", and that tracing has its own
performance impact on the target. Data is lost when the buffer is not drained in time, and the
loss is reported as a truncated flag rather than as a silent gap. Decoder errors are expected
with generated or self-modified code and with missing side-band information. The method follows
from that measurement: bound the capture with the filtering facilities the specification reports,
and never start with the whole system.

## The OS-level substitutes

Cheaper, supported, and answering a different class of question. Use them first when they can.

**A system-wide event tracing facility (ETW).** `observed`: Microsoft documents it as an
efficient kernel-level tracing facility that logs kernel or application-defined events to a log
file, with a controller/provider/consumer model and dynamic enabling without a restart, plus a
documented set of reasons events go missing. Good for: which documented operation happened, in
which process, at what time, at the granularity of the providers that emitted it. Not control
flow: it will not tell you which branch was taken, and it emits a value only if a provider was
written to emit one. Requires an elevated session for kernel providers, and a plan for the events
it drops.

**A record-and-replay debugger (TTD).** `observed`: Microsoft describes a tool that captures a
trace of a process and replays it forwards and backwards, integrated with the debugger and
requiring an elevated session to record, with two limits that decide its use: it "currently
supports only user mode operation, so you can't trace a kernel mode process", and it cannot
record a protected process. Documented costs and behaviours: "about a 10x-20x performance hit in
typical recording scenarios"; a `.run` trace with an `.idx` index typically about twice its size,
required for accurate memory values; conflicts with other invasive software, including antivirus;
and replay by an emulator inside the debugger, which is why a replayed trace can report a
derailment, meaning a gap from that point onward. Good for examining a check that already
happened, repeatedly, and it is the only instrument here that runs backwards. It is not an
instruction-level trace of a kernel mechanism.

## Choosing a mechanism

| The question | Reach for | Because |
|---|---|---|
| Where is the check, and is it reached at all | A record-and-replay recording, or a facility's events | Cheapest, supported, no modification, and the recording is reusable |
| The target hashes its own bytes | Hardware breakpoints | They do not change the bytes, so the hash check still passes |
| The target reads the debug registers, or every hook is found | Instruction and branch tracing | Nothing is installed in the process and no debug registers are used |
| Which branch, in what order, across a whole run | Instruction and branch tracing | The only mechanism that records control flow rather than events |
| What value was compared | A data breakpoint on the address, or the algorithm | No trace records values; the trace gives the address, then you read the value |
| The code is generated or self-modified while it runs | Expect decoding to fail; fall back to a dump plus static reading | The decoder needs the exact bytes that ran |

## What was measured about hardware breakpoints on the development host

The architectural facts above say the facility exists. Whether an exception raised by a debug register
reaches a debugger **on a given machine** is a separate question, and this repository measured it
rather than inferring it.

`observed`, on the host described in `evidence/` (a 12th-generation part, with a virtualisation layer
reporting itself present), with a subject built for the purpose and started under the debugger:

| Step | Result |
|---|---|
| activate the debugging privilege on the token | succeeded -- and it was needed: an elevated session alone got `ERROR_ACCESS_DENIED` |
| start the subject under the debugger | succeeded |
| the subject's own breakpoint instruction, placed in its source | **the debugger received it** |
| write `Dr0` with the address of a function called in a hot loop, and `Dr7` to enable slot 0 | **accepted** -- the context write returned success and the register read back |
| wait for the exception from the debug register | **never arrived** |

**The third row is what makes the fifth a finding rather than a suspicion.** Three facts hold at once:
this session can receive a debug exception, the register was accepted, and the exception from the
register did not arrive. The first rules out a broken harness; the second rules out rejection; what
remains is that the mechanism's exception is consumed before it reaches the debugger. On a host with a
virtualisation layer present, that is the expected shape, and it is now a measurement rather than an
inference from the layer's presence.

**The control had to be moved into the subject's own source to make this measurable.** The first
attempt patched a breakpoint byte in from the debugger, which fails for a reason unrelated to
debugging -- the code section is read-only, so the write is refused and the control never runs. A
control that cannot run is worse than no control: it leaves a session looking instrumented.

**Three implementation errors came first, and each produced a plausible negative:**

1. a debug-event structure read at the wrong offset -- the union inside it is 8-byte aligned, so the
   exception code sits at 16 rather than 12, and the wrong read yielded zero, which matched no code
   and was silently treated as an event of no interest;
2. a breakpoint on the start of the code section rather than on a function, which is an address the
   running program may never execute;
3. a breakpoint on a function that runs once, at process start, which the process had already passed
   by the time the register was written.

**All three looked like an environment property and all three were arithmetic.** A measurement of
"does this mechanism work here" has to demonstrate that the mechanism was actually attempted before
its silence can be read as a fact about the machine; otherwise the cheapest bug in the harness gets
recorded as a finding about the host.

**What this means for a plan.** On this kind of host, a route that depends on a debug register —
including a hardware breakpoint used specifically because it leaves no byte changed — cannot be
assumed to work because the architecture provides it and the API accepts it. The probe's existing
advice stands and now has evidence behind it: the routes that survive are the ones whose exception is
not mediated by the layer, and the honest fallback is a software breakpoint, which pays exactly the
cost the hardware one was chosen to avoid.

## What was measured about reaching the trace unit on the development host

The probe reports that the processor supports tracing. Whether a trace can be **collected** is a
separate question, and on this platform the answer has a shape that is worth stating precisely: it is
not that no interface exists, it is that the interface is undocumented. Measured on the host
described in `evidence/` (`observed`):

| Check | Result |
|---|---|
| does the system's own recorder offer a trace profile | **no** -- thirty profiles listed, none for the trace unit; they are CPU, DiskIO, Heap, Pool, GPU and similar |
| is there an in-box driver for the facility | **yes** -- a Microsoft-signed kernel driver, current build, `DEMAND_START` |
| does it create a device | **yes** -- its own strings name `\Device\IPT` and the user-mode path `\DosDevices\IPT` |
| does it look driven by a control request | **plausible** -- the same strings carry option-shaped names (`IptOption`, `IptTraceUntil`, `IptNumTries`, `IptIgnoreCheck`) and a ToPA mapping failure path with a parameter-count constraint |
| is the device reachable here | **no** -- the driver is stopped, so the path does not resolve |
| does anything else already use it | **yes, in-box** -- a WMI autologger is registered against it, which is the platform collecting traces for its own crash analysis |

**What follows, and what does not.** What follows is that the constraint is not the CPU and not the
absence of a path: a device object with a user-mode name implies a handle-based control path, and
option-shaped strings imply a request structure the driver reads. What does **not** follow is that
this path is usable for analysis. It is undocumented, its request layout is unknown, the driver is
stopped, and `hardware breakpoints` measured on this same host showed the broader caution: a
facility the architecture provides and an API accepts can still fail to deliver, because a
virtualisation layer sits between. The two closed doors are therefore different kinds of closed --
one is "no interface", the other is "an interface nobody documented".

**The honest next step is small and testable, on a machine nobody is using**: start the driver and
enumerate the device's control codes, or find the in-box caller and read how it drives them. Neither
is done here. **Loading an undocumented kernel driver to test a hypothesis about trace collection is
not a step to take on a host somebody else is working on**, and the pre-flight now checks for exactly
that situation before a dynamic route is planned.

**The alternatives that are documented stay the recommendation**: a recorded replay, which is
documented and user-mode; a coarser sampling facility, which answers a different question but answers
it; or a different platform, where the collection interface is documented in the first place.

## What this file does not cover

`unknown`: nothing in this file was measured on this host. It is documentation-derived, and these
are the places where the documentation stops and a measurement must start.

- **No capture was performed**: no trace, no packet dump, no decoded address stream, and no
  hardware breakpoint was set. Every claim about behaviour under a hypervisor is a documented
  possibility, not an observation.
- **No Windows capture interface for instruction tracing was identified.** The probe reports the
  CPU's capability; it does not report a capture path. Verify this on the build you are on.
- **The processor-specification details come from one revision of one vendor's manual.** The
  breakpoint count, the field encodings and the length rules must be re-checked against the
  revision you open and the processor in the machine, especially the length encoding that some
  processors define and others leave undefined.
- **Third-party tooling is not covered**, and timing accuracy is described rather than measured.
  Both are empirical questions about a specific instrument and a specific capture.
