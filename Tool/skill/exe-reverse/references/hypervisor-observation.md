# Hypervisor-level observation

Goal: understand what a virtualisation layer above the operating system can do that a debugger
cannot, and what the hypervisor already present on the analysis machine takes away.

## When to load this

Load this when a mechanism that should work does not: a debug exception that never reaches your
handler, a single-step that behaves oddly, timing that makes no sense, or a hardware facility
that the CPU reports and the tooling cannot use. Load it before promising a route that depends
on kernel or hardware behaviour on a machine running virtualisation-based security, and load it
before writing off a mechanism as impossible, because the three explanations, unsupported,
blocked by policy, and intercepted, have three different answers.

## What a hypervisor changes

A hypervisor owns the processor's virtualisation controls and the second-level translation of
the guest's memory. Everything below follows from those two facts.

| Capability | What it means for observation |
|---|---|
| Diverting exceptions by vector to itself | Any exception, including the debug exception, can be turned into a transition to the hypervisor instead of being delivered to the code that caused it |
| Owning second-level address translation | Access rules can be enforced at page granularity, including permission to execute, independent of the guest's own page tables |
| Logging memory activity at page granularity | The processor specification documents a page-modification logging feature, backed by a VM-control field that points at the log, itself a fixed number of fixed-size entries |
| Observing with no in-guest artifact | Nothing is written into the guest, no debug register is set, and the guest's own page tables are unchanged, so the ordinary in-guest evidence channels, checksums of its own code, debug-register reads and page-table inspection, show nothing |

`observed`: the exception-interception and page-modification-logging descriptions are from
Intel's published processor specification, the virtual-machine control structure chapter,
sections 25.6.3 and 25.6.19 in the revision read; the second-level translation mechanism
(extended page tables) is documented throughout the same chapter, including the instruction
that invalidates its cached mappings, and the pointer to its paging structures is a VM-control
field. Re-check the section numbers against the revision you open.

The honest version of "the guest cannot see it" is narrower than it sounds, and the narrowing
matters:

- **Nothing in the guest changes.** That is a real and useful property: a check that compares
  its own bytes, reads its own page tables, or inspects its own debug-register state sees an
  untouched system.
- **The guest can still notice the hypervisor.** The processor reports that a hypervisor is
  running, the platform has a documented way to report its state, and timing differences exist
  wherever a control structure mediates an operation. A target that is written to care about
  being virtualised is a different problem from a target that checks its own bytes.
- **A hypervisor-aware or hypervisor-hosted target can be outside this layer's reach.** If the
  thing you are analysing is itself protected by the virtualisation layer, the "below the
  guest" position is not available to you at all.

## Exception interception: the mechanism most likely to break your plan

`observed`: the processor specification's exception bitmap is a 32-bit field with one bit per
exception vector. When an exception occurs, its vector selects a bit in that field; if the bit
is 1 the exception causes a transition to the hypervisor, and if the bit is 0 the exception is
delivered normally through the interrupt descriptor table. The debug exception is vector 1
(`observed`: the same specification's debugging chapter titles it as the debug exception,
interrupt vector 1).

So the chain that a hardware breakpoint depends on has a component in it that you do not own:

1. Your code sets a breakpoint in the debug registers.
2. The processor raises the debug exception when the condition is met.
3. The exception is delivered, and a handler decides what happens next.

Step 3 is where a hypervisor can be configured to take control instead. On a host with
virtualisation-based security enabled, the Windows hypervisor is running by design, so the
question is not whether a hypervisor exists but whether the specific mechanism reaches you.
That is a probe-and-test question, and the test is a control: set the mechanism up on a target
whose behaviour you already know, and observe whether the stop occurs. A breakpoint that never
fires is not evidence about the target until the mechanism has been proven to work on that host
at all.

Single-stepping travels down the same path: it is one of the documented debug-exception
conditions in the same chapter, so it is subject to the same interception, and "it survived a
hardware breakpoint but not stepping" is a statement about two different exception conditions
rather than a contradiction.

`unverified`: the exact virtual-machine control fields that govern guest debug-register access
are not asserted here. The specification has such controls in its virtual-machine control
structure chapter; read them there before claiming that a specific guest debug-register access
will or will not cause a transition. What is established is that the hypervisor layer decides,
not the guest.

## Page-granularity observation and rules the guest cannot see

A debugger can enforce very little. It can stop execution, it can watch a handful of addresses,
and it can write to memory. The virtualisation layer is the first layer where the following
become possible, because they are decisions about translation and permissions rather than about
breakpoints:

- **Deny execution on a page**, for instance to observe a first execution of a routine, with no
  byte of the image changed and no breakpoint instruction in memory.
- **Make a page read-only or write-protected** and observe the fault, including the address and
  the writer, without the guest's own page tables recording anything different.
- **Log writes at page granularity** through the documented page-modification log, so a write
  that is never intercepted is still recorded.
- **Observe the guest's own privileged operations**, which is where this layer is the only
  option: nothing inside the guest, at any privilege level available to you, can be both the
  observer and the observed at the same time.

The costs are equally structural. Every interception is a transition out of the guest, which
means performance and timing change; every rule you add is state that must be validated for the
whole address space, not just the interesting page; and the layer you are adding sits under the
code that the operating system itself is already using, so a mistake is not a crashed process
but a failed machine.

## The reverse: the hypervisor under you

The mechanism is symmetric, and the asymmetry is the reason this file exists. The project
context records that this development host reports a hypervisor present
(`CPUID.01H:ECX[31]`, measured). That is the normal state of a modern Windows installation with
virtualisation-based security active, and it changes the value of several things you would
otherwise assume:

- **Hardware breakpoints, single-stepping, and timing all become conditional.** The probe in
  this skill reports the hardware breakpoint route as requiring a verification step rather than
  as available, precisely because the debug exception may be intercepted. Plans should inherit
  that conditionality.
- **Instruction and branch tracing can be degraded by the layer above.** The kernel's tracing
  documentation for this facility states that virtualisation controls "may suppress packets
  needed for decoding" and "may block" the notification used to drain the trace buffer, and
  that both produce decoding errors or lost data. Inside a virtual machine there is additional
  documented work: guest decoding support is limited, timestamps need correction against the
  hypervisor's time offset, and guest thread information is not available.
- **Timing measurements are the least portable thing you can take from a virtualised host.** A
  measurement of "this check takes 40 milliseconds" on a machine where every privileged
  operation may transition into a hypervisor is a statement about that configuration, not about
  the code.
- **The direction of causality is easy to get backwards.** A tool failing to work on a
  virtualised host does not establish that the tool or the mechanism is broken; it establishes
  that the host's configuration is now part of the experiment. Record it as a host fact and
  change one variable, exactly as with any other measurement.

The practical rule: **probe the hardware capability, then test the mechanism with a control on
this host, and only then plan the route.** Probed capability without a control test is an
assumption wearing a measurement's clothes.

## Virtualisation-based security, and what it forbids

This is the concrete, documented form the layer takes on Windows, and it is where most plans
run into a wall. `observed`, from Microsoft's virtualisation-based security and memory
integrity documentation:

- VBS uses hardware virtualisation and the Windows hypervisor to create an isolated
  environment that becomes the root of trust of the operating system, on the stated assumption
  that the kernel can be compromised.
- **Memory integrity**, also called hypervisor-protected or hypervisor-enforced code integrity,
  runs kernel-mode code integrity inside that environment. It checks all kernel-mode drivers
  and binaries before they are started and prevents unsigned or untrusted drivers or system
  files from being loaded into system memory. Kernel memory pages are made executable only after
  passing code integrity checks inside that environment, and executable pages are never
  writable.
- Its documented hardware requirements are a 64-bit CPU with virtualisation extensions,
  second-level address translation, IOMMU support for DMA-capable devices, TPM 2.0, Secure
  Boot, and firmware memory reporting. It works inside a virtual machine only where nested
  virtualisation or guest virtual machine support is enabled.
- On processors without the mode-based execution control or guest mode execute trap features,
  the same protections are provided by an emulation the documentation calls restricted user
  mode, at a larger performance cost.
- Test signing is not a way around it. The documented statement is that starting with Windows 10
  version 1507, with memory integrity enabled, an unsigned binary is not supported and the
  binary must be test-signed with a self-created test certificate.
- A separate, documented control is the recommended driver blocklist for drives with known
  exploitable vulnerabilities, malicious drivers, and drivers that circumvent the Windows
  security model; it is enforced when memory integrity, Smart App Control, or S mode is active,
  and enforcement is observable in the code-integrity operational log as event 3099.

Three consequences for this skill's routes, stated flatly:

- **You cannot load your own unsigned instrumentation on a host with memory integrity on.**
  There is no analysis trick that makes an unsigned kernel component acceptable to a code
  integrity check that is running in another security domain; the documented configuration is
  a self-created test certificate and the documented policy state.
- **The read-only-execute rule removes a whole class of patch.** A kernel page that is never
  writable and only executable after a code-integrity decision cannot be patched in memory in
  the way a user-mode page can. Any plan whose last step is "write these bytes into the kernel's
  code" must first explain how that is permitted on the target, and on a memory-integrity host
  the honest answer is that it is not.
- **Refusal by policy is a finding, not a puzzle.** When a load is refused, look for the
  documented evidence (the code-integrity log, the boot configuration, the device-guard state)
  and report the policy and the evidence, rather than engineering around a control whose
  purpose is exactly to prevent this.

How to measure the state, rather than guess it: `observed`, Microsoft documents querying the
device-guard WMI class from an elevated PowerShell session with
`Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`,
whose fields include the available security properties (among them hypervisor support, secure
boot, DMA protection, the mode-based execution control or guest mode execute trap capability,
and APIC virtualisation), whether services such as memory integrity are configured, and whether
they are running. The same documentation gives the registry keys that configure the features and
names the alternative of the Windows Security interface. The host probe in this skill reads the
registry and boot-option state and prints it with a warning that a Home edition may not
populate those keys even when the feature is active, which is why the WMI query is named here.

## Requirement chain for your own hypervisor-level instrumentation

If the question genuinely needs the layer below the guest, this is the whole cost, in order.
Any missing link ends the route.

1. **A kernel component.** The virtualisation controls are per-processor state that the
   operating system owns; a user-mode process has no path to them. The instrumentation is
   therefore a kernel component, with everything the previous file says about kernel work: the
   signing chain, the reboot, and the fact that a mistake stops the machine.
2. **Signing, or test mode plus the documented exception for memory integrity.** An unsigned
   driver is refused on a current installation, and on a memory-integrity host even test signing
   requires a signed-by-your-test-certificate image.
3. **A host that is not already inside a hypervisor it must share with.** The project context
   measures a hypervisor present on this development host. Running your own layer under that one
   is nesting, and nesting is the documented condition under which VBS itself will run inside a
   virtual machine: nested virtualisation support, or guest virtual machine support, must be
   enabled. `unverified` here: this pass did not establish whether this host exposes nested
   virtualisation to a guest or to a second layer in the same security domain, so treat that as
   the open question and test it on the host.
4. **Processor support for the virtualisation instructions themselves.** The probe decodes the
   capability bit for these instructions from the processor and reports it, which is a necessary
   condition and not a sufficient one: a processor can support them and the platform can still
   refuse to hand them to your component.
5. **The right API for what you are actually trying to do.** Microsoft documents a
   user-mode API, available since the Windows April 2018 update, that lets a third-party
   virtualisation stack "create and manage partitions at the hypervisor level, configure memory
   mappings for the partition, and create and control execution of virtual processors". That is
   a way to build and run your own partitions, and it is **not** a way to instrument the
   operating system you are currently running inside: the running system is not one of your
   partitions. Choosing this API for guest introspection is a design error that costs days,
   which is why it is named here with its actual scope.
6. **A different debugging route if the target is the hypervisor itself.** Microsoft documents a
   hypervisor debug type alongside kernel, boot and loader debugging, enabled through the boot
   configuration (the network debugging documentation lists `bcdedit /set hypervisordebug on`,
   and states that when hypervisor and kernel debugging are both enabled the hypervisor port is
   one above the kernel debug port). That is a documented way to debug the hypervisor, not a
   general instrumentation interface.

## The practical decision

| Situation | Answer |
|---|---|
| The target must not be modified, it checks its own bytes, and a control test shows the debug exception reaches you | Stay at the hardware-trace layer. It is cheaper, it is in this repository, and it is sufficient |
| The target must not be modified, and a control test shows the mechanism is intercepted, but its control flow is the question | Instruction and branch tracing, if the capture path exists on this host. Otherwise the answer is a different question, not a harder mechanism |
| You need an observation with no in-guest evidence channel at all, or page-granularity enforcement the guest cannot see, or the target is a protected process | The hypervisor layer is the only remaining instrument. Then pay the full chain above, including the nested-host question |
| The host's policy refuses your instrumentation and no documented path provides a signed alternative | Write the conclusion instead: state the mechanism, the policy that blocks it, the observable evidence of that policy, and what would have to change for the route to exist. That is a real deliverable, and it is the one most often mistaken for a failure |
| You have not measured whether the mechanism works on this host at all | Do not plan the route yet. The probe and a control test come first; a plan built on an unsupported host is the failure this layer is prone to |
| The question is about a value the target compared | Neither layer answers it. A trace gives the address, a breakpoint gives the moment, and the value comes from the process at that moment or from the algorithm |

## What this repository ships, and what it does not

Stated without hedging, because a reader who assumes otherwise will plan work that cannot be
done here:

- **No hypervisor, no driver, no virtualisation instrumentation.** Nothing in this repository
  loads below the operating system, manipulates virtual-machine control structures, configures
  second-level translation, or intercepts exceptions. This file scaffolds the route, enumerates
  its prerequisites, and states where it is the right answer; the code for it is not here.
- **No bypass of code integrity, test signing, or the driver blocklist**, and no workaround for
  memory integrity. Those are documented controls with documented observable evidence, and the
  repository's position is that a refusal by them is reported, not defeated.
- **What exists here** is a host probe that reports the virtualisation-related state it can read
  (processor capability bits it has verified against a primary source, boot options, device-guard
  registry keys, privilege and tool inventory), and refuses to decode anything it cannot cite.
  It reports conditions; it does not decide for you whether they are fatal.
- **The deliverable for most requests that land in this file is a written conclusion**: which
  layer can answer the question on this host, what it costs, and what is unavailable. That is
  the honest output, and it is more useful than an instrument that was never going to load.
- **The mechanisms here are one vendor's.** The control structure, the entry instructions and the
  second-level translation named above are Intel's; the other vendor's equivalents, and why a tool
  built for one set does not drive the other, are in `references/cpu-vendor-divergence.md`.

## Verification for this shape

1. **Separate the three explanations** before reporting: unsupported by the processor, refused
   by platform policy, or intercepted by a layer above. Each has different evidence: a decoded
   capability bit, the boot and device-guard state plus a code-integrity log entry, or a control
   test showing the mechanism works on a known target and not on this one.
2. **Record the policy state with the result.** A measurement taken with memory integrity off is
   not a measurement of the same machine with it on.
3. **Never generalise "invisible" to "undetectable".** The correct claim is the mechanical one:
   what is unchanged in the guest, and which in-guest evidence channels therefore show nothing.
   Whether a given target notices a virtualised environment is a question about that target.
4. **Timestamp and version everything.** Processor model, build number, device-guard state, and
   the exact image under test. This layer is the one where an unrecorded environment change
   invalidates the whole result.
5. **If the conclusion is "not available on this host", record what would change it** so the next
   attempt starts from a fact instead of from the same assumption.
