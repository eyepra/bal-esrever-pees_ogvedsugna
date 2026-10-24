# Breakpoints and the Live Debugging Session

Goal: turn a runtime observation into a named routine, an address that survives a restart, and a
record someone else can replay, without mistaking the debugger's own effect for the target's
behaviour.

## When to load this

Load this when static reading cannot answer the question because a value is computed at run time, or
when the skill's symptom index sent you here from "your edit is on disk but clearly not in effect",
or from "a breakpoint at the entry point is never hit, yet the process runs". Load it before the
first breakpoint is set, not after three sessions that each found nothing.

## The instrument problem, stated once

Every breakpoint is either a modification of the target or a change in how the target is scheduled,
and both change the measurement. A software breakpoint writes a byte into the image in memory. An
attaching debugger suspends and resumes threads, which is a change to timing even when no byte is
touched. Treat "I observed X in the debugger" as a claim about the target **under a debugger**
(`inferred`): the control that establishes whether X holds without the debugger is the same input on
an unattached run, and if that control disagrees, the debugger's presence is the first suspect, not
the target.

A non-invasive attach exists and is the honest instrument when nothing may change: a debugger can
attach without generating a break-in thread, and a process can be opened for query only, which
allows reading memory and module state but not setting breakpoints at all (`observed`, the debugger
engine's own options list includes a non-invasive attach mode and a variant that also leaves the
target unsuspended).

## Breakpoint families and what each costs

| Family | Mechanism | What it costs | What it survives |
|---|---|---|---|
| Software breakpoint | One byte at the target address is rewritten with the platform's single-byte break instruction | The byte in memory differs from the file; anything that reads, hashes, checksums or copies that code region sees it | Nothing that hashes or self-checks its own code |
| Hardware breakpoint | An address is programmed into the processor's debug registers; the processor raises the exception, no byte changes | The architecture provides **four** such registers, so at most four addresses at once (`observed`, measured on this project's development host); they belong to a thread, not to an address space, so a second thread needs its own copy | Code hashing and self-checksum, because no byte changes. Not an observer that reads the debug registers, and not a hypervisor that intercepts access to them |
| Memory breakpoint / page guard | The page's protection is changed so that any access raises an exception | The granularity is a **whole page**, so unrelated code and data on that page also trap; a guard is a one-shot alarm that the environment clears after firing, so it must be re-armed after every hit (`observed`, memory protection documentation) | Nothing that inspects page protections; it also makes the region trap for every accessor, not only the interesting one |
| Conditional / logging breakpoint | The breakpoint fires every time, then the debugger or an injected handler evaluates a condition | Cost is proportional to hit count, not to the number of interesting hits: a condition on a routine called in a loop converts one slow step into thousands | Nothing — the mechanism underneath is usually a software breakpoint |
| Trace / step | Single-step after each instruction, or processor-level branch/instruction tracing | Slowest, and by far the most timing-perturbing; a stepped target can behave differently because it is no longer running concurrently | Depends on the layer; hardware instruction tracing does not write to the target at all, which is why it is the route of last resort for a target that detects every other one |

The debug-register count is the one number to trust at the level of "four slots"; anything beyond the
count (which bit controls which slot, how execution breakpoints differ from data breakpoints) is
processor-specific and must be read from the processor specification for the exact family
(`unverified` here — the numbers quoted above are the count only).

**The decision, therefore:** if the region you need to break in is hashed, verified, or used as a
self-check input, a software breakpoint is the wrong instrument and the finding it produces will be
"the target died with no explanation". Move to hardware breakpoints, memory breakpoints, or
observation outside the target. If the target runs under a hypervisor, assume the debug registers may
be intercepted and observed, and treat the timing of an exception-based observation as part of the
experiment (`inferred`).

## Where to put the breakpoint

Prefer a location the target cannot avoid reaching over a location you happen to know the address of.
In descending order of durability:

1. **On the API the program must call.** The program has to go through the platform to open the file,
   read the registry value, allocate the buffer, or compare the string. Break on the imported function
   rather than on the code that calls it: the import is a named, per-build-stable target, and its
   caller can move between builds. The cost is that a widely used API is hit by everything, which is
   where a conditional breakpoint on the argument that matters belongs.
2. **On a window or dialog being created.** A licensing dialog is a system object with a lifetime
   (created, shown, destroyed), and the system will call a hook procedure you install when one is
   created (`observed`, the window-hook mechanism provides a hook type for creation/activation
   notifications). This locates the *feature* without knowing any address, which is exactly the case
   where the code has not been found yet.
3. **On a string being formatted.** If the surface extraction produced a user-visible string, the
   interesting moment is when that string reaches an output routine. Break just after the formatting
   call and read the arguments, not the formatted result.
4. **On memory being read or written, instead of on code being executed.** A licence flag is written
   once and read many times; the write tells you who decided, the read tells you who depends on the
   decision. Data breakpoints are the only way to answer "who changed this" and they are the reason
   hardware breakpoints exist.
5. **On data rather than on code, generally.** A breakpoint on a routine answers "this routine ran". A
   breakpoint on the field it reads answers "this value was consulted here, by this caller, at this
   point in the flow" — which is the question the analysis actually needs.

## From a runtime observation to a call site

You have hit something and you do not know who called it. In order:

1. **Read the stack, once, and decide whether to believe it.** A stack walk is trustworthy when the
   frames carry unwind information the reader used (the common case for compiler-generated x64 code)
   and when the routine is near the top. It is not trustworthy when the code is hand-written
   assembly without unwind data, when the call was a tail call that reused the frame, when the routine
   runs on a stack that was switched (fibers, coroutines, an exception handler), or when the walk
   crosses a module boundary into a region with no metadata. A long stack that looks plausible and
   ends in system modules is not confirmation.
2. **Scan upward for return addresses.** A return address on the stack is a value that points a few
   bytes past a call instruction. Find the nearest such value above the current frame and disassemble
   a few instructions before it: the call's target should be the routine you are in. If it is not, the
   frame you scanned was stale data, not a frame.
3. **Follow the value backwards when the stack is untrustworthy.** Set a data breakpoint on the value
   and let the target run to the previous writer; repeat until the writer is a comparison, a table
   lookup, or the point where the value entered the process. This is slower than reading a stack and
   it does not depend on frames being correct, which is why it works on the targets that defeat stack
   walking.
4. **Confirm the call site statically.** Now that you have an address, read the code around it in a
   disassembler and check the arguments being pushed against what the routine reads. A call site you
   only found at run time is a hypothesis until the static read agrees with it.

## What a session must record

A debugging session that is not written down is worth nothing at the next restart, because addresses
are not stable facts. Record, at minimum:

| Field | Why it is required |
|---|---|
| Module file identity — a hash, plus the build stamp and image size the PE carries | This is the only thing that makes an offset meaningful later. Two builds of the same product have the same module name and different code |
| Module base address at the time of the observation | Every live address is relative to it; asynchrony, ASLR and re-layout all change it between runs (`observed`, the PE format defines relocation specifically because the loader may not load an image at its preferred base) |
| Both the live address and the module plus offset | The live address is what you type back into the debugger; the module+offset is what survives a restart |
| What kind of breakpoint produced the hit, and where exactly it was placed | A hit on a page guard and a hit on a software breakpoint at the same address are different observations |
| Whether the session launched the target or attached, and with what debugger options | Non-invasive attach and full attach produce different visible state |
| The platform build, and whether the process is 32-bit under a 64-bit system | The debugger, the register set and the address widths all change; a 32-bit process on a 64-bit host is a different session |
| What the target did differently under observation | This is the control, and without it the next reader cannot tell an observation from an artefact |

The rule underneath the table: **an address without a module base and a build identity is a
coordinate in an unnamed coordinate system.** `0x00007FF6A1B2C3D4` is not a finding. `MOD.dll+0x412C`
in the build whose hash is recorded, which was live at base `0x...` in this session, is a finding.

## Failure modes this topic actually produces

**The breakpoint is never hit.** The usual cause is not a broken debugger. It is that the code path
is different from the one assumed: the function was inlined and the standalone copy is dead, the
import was resolved to a different module than expected, there are several implementations and the
runtime selected another one, or the feature only runs on a path this input does not take. Diagnosis:
put the breakpoint on the API the routine must call instead of on the routine, and see whether the
API is reached. If the API is reached and the routine is not, the routine is not the implementation
in use.

**A breakpoint at the entry point never fires, yet the process runs.** Two mechanisms produce this.
First, the loader runs image initialisation that is *not* the entry point: a TLS callback array is
part of the image, each callback in it is called in the order its address appears in the array, and
the prototype is the same as a DLL entry-point function (`observed`, PE format specification, `.tls`
section). Setting only the entry-point breakpoint therefore misses whatever ran first. Second, the
entry point may already have been passed — an attach to a running process starts after startup, and
some debuggers deliberately skip the initial break-in. Diagnosis: set a breakpoint that is not
address-dependent (loader notifications, or the first API the startup path must call) and read the
module list at the moment it fires.

**The step lands in something that is not code.** Stepping past the end of a function, past a jump
table, or into a data region makes the debugger decode bytes as instructions and produce a
convincing-looking nonsense listing. The tell is that the "code" contains instructions the compiler
does not emit in that pattern, or that stepping suddenly produces an access violation from an address
in a non-executable region. Diagnosis: check the region's protection and state before believing the
listing; a region that is not executable is not code.

**The session changes the behaviour.** A debugger changes timing enough to matter when the target
races, times out, or measures elapsed time as part of its own logic. Symptoms: the target works
unattached and fails attached, or the reverse. Diagnosis: reproduce the observation with the least
invasive instrument that can produce it (non-invasive attach, hardware breakpoint, or tracing that
runs out of process), and confirm whatever survives that downgrade is the real behaviour.

**Two sessions disagree.** Same build, same input, different observation. Before reasoning about the
target, check the two records for the fields in the table above: a different module base is normal, a
different module hash or a different process bitness means the two sessions were not the same
experiment.

## What this route cannot do

It cannot see a value that never reaches a breakpointable location, which is the case for a decision
made entirely inside a virtualised or protected routine, and for a check whose result comes from a
server. It cannot observe a target that refuses to be attached, and it cannot distinguish "this
routine decided" from "this routine merely forwarded a value it was given" — that requires reading
the routine. When the target detects or defeats every breakpoint family above, the observation
techniques that run outside the process are the replacement, not a better-configured debugger, and
this file's material stops there (`observed` as a boundary: the material in this file describes
in-process instruments only).

## Related material in this skill

For getting a breakpoint to be your own code rather than the debugger's, and for the counterpart
question of remembering that any hook is a modification, load `references/injection-and-hooking.md`.
For what a dump offers when a live session is impossible, load `references/memory-and-dumps.md`. For
which debugger and which option is available on the machine you actually have, run
`python scripts/hwprobe.py` and read its tool inventory before planning a session.
