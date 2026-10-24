# Kernel drivers and the user-mode boundary

Goal: recognise a kernel image, know what the user-mode toolchain can and cannot reach, and
state the cost of the kernel route before promising anything from it.

## When to load this

Load this when the sample is a `.sys` file, a PE whose subsystem says it is native, a PE with
no user-mode import surface, an installer that drops a driver, or any target that refuses to
work unless a driver or service is present. Also load it when a question is about the *kernel
side* of a mechanism (a hook, a filter, a call-back) rather than about the user-mode code that
drives it.

## Recognise a kernel image from the file

The subsystem field, not the name, is the first proof. Subsystem 1 is
`IMAGE_SUBSYSTEM_NATIVE`, documented as "Device drivers and native Windows processes"; the
only other native-subsystem value in the specification, 8, is the historical Windows 9x driver
case, so a modern driver is subsystem 1 (`observed`: Microsoft PE/COFF specification,
"Subsystem" values). A further documented marker is the DLL-characteristics flag
`IMAGE_DLLCHARACTERISTICS_WDM_DRIVER` (`0x2000`), whose specified meaning is "A WDM driver"
(`observed`, same document).

Cheap confirmations to add, in this order:

- **Entry section and entry point.** A driver's entry point is not a user-mode `main` stub; it
  is the routine the I/O manager calls when the driver is loaded.
- **Imports.** They name kernel modules and kernel routines. There is no user-mode API surface
  to read, and its absence is itself informative.
- **Strings and resources.** Driver object names, device names, symbolic links, IOCTL constant
  names left in from a header, service names, and often the name of the setup component that
  installs it.
- **The installation side.** A driver is normally installed by an `.inf` file and a setup
  component. The driver file is one artifact in a package; the package tells you how it is
  loaded and under what conditions.

One caveat that is easy to over-read: subsystem 1 tells you the image is a native kernel-mode
component. It does not mean every component in the package runs in kernel mode. Microsoft's
own driver documentation states that some device drivers run in user mode, and separates
function, filter and bus drivers within a driver stack (`observed`: "What is a driver?"). The
user-mode half of a driver package is a user-mode problem and belongs to the user-mode routes.

## What is different about a kernel image

**Address space and privilege.** The component executes with kernel privilege, in the system's
own address space sharing page tables with every other kernel component, not in an isolated
process address space with its own boundaries to exploit or to trust. There is no
per-component isolation of the kind a user-mode process gives you, which is why a defect in a
driver is a system failure rather than a process failure.

**No user-mode API.** Kernel-mode code does not call the user-mode API surface: no window
management, no user-mode file API wrapper, no user-mode runtime assumptions. The routines it
calls are kernel routines, and the WDK's reference for each routine documents the mode and the
interrupt request level at which it is legal. `inferred`, from the file: a kernel image's
import table is a list of kernel modules and their exports, and that list is where you start
when you want to know what a routine in the driver actually does. If you need the module that
exports a specific routine, read the WDK reference for that routine rather than guessing from
the name.

**Its own entry point and dispatch table.** `observed`: Microsoft's driver-entry documentation
states that every driver must have a `DriverEntry` routine, that the I/O manager calls it when
it loads the driver, that it runs in the context of a system thread at `PASSIVE_LEVEL`, that it
is responsible for exporting the driver's other entry points, and that in a Plug and Play
driver device initialisation belongs to `AddDevice` instead. So `DriverEntry` is a
configuration step: it fills in the dispatch table. The behaviour you care about is usually
behind a dispatch routine, not in `DriverEntry`.

**IRP dispatch.** `observed`: the I/O stack location of every IRP carries a major function
code that tells the driver what operation to perform, and each kernel-mode driver must provide
dispatch routines for the major function codes it must support. The documented set includes
create, read, write, device control, internal device control, Plug and Play, power, cleanup,
close, flush, query and set information, shutdown, system control, and file system control.
Read the dispatch table first: it is the map of everything the driver is willing to do.

**IOCTL handling.** `observed`: user-mode callers send IOCTLs with `DeviceIoControl`, which
makes the I/O manager create an `IRP_MJ_DEVICE_CONTROL` request; drivers handle those requests
in their device-control dispatch routine. The code itself is a documented 32-bit layout: a
common bit, device type, access, custom bit, function, and method, assembled by the `CTL_CODE`
macro as

    #define CTL_CODE( DeviceType, Function, Method, Access )
        ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)

with device types from `0x8000` to `0xffff` for vendors (Microsoft reserves the lower half),
function numbers from `0x800` to `0xfff` for vendors (Microsoft reserves the lower half), access
in `FILE_ANY_ACCESS` / `FILE_READ_DATA` / `FILE_WRITE_DATA`, and method in `METHOD_BUFFERED` or
the direct and neither variants (all `observed`, Microsoft's "Defining I/O control codes";
the same page gives `DEVICE_TYPE_FROM_CTL_CODE` and `METHOD_FROM_CTL_CODE` for pulling the
fields back out). The same page states plainly that private IOCTLs are "usually defined in a
vendor's header file and aren't documented by Microsoft", and that there is no difference in
how a public and a private code is encoded. That is the whole game: an undocumented code is
still a well-formed 32-bit value, and its structure is documented even when its meaning is not.

**Device objects.** `observed`: a driver that does not create a device object for a device
receives no IRPs for it; drivers call `IoCreateDevice` or `IoCreateDeviceSecure`; the
system-allocated device extension is the driver's per-device storage; and WDM drivers other
than bus drivers deliberately do not name their devices, because supplying a name "bypasses
the PnP manager's security features". A non-WDM driver's unnamed device objects are not
reachable from user mode, so such a driver usually creates at least one named object. The
named object plus its symbolic link is the user-mode-visible door: user mode opens a path and
sends IOCTLs to it.

**Memory rules are not yours to set.** Whether a kernel page can be written, executed or both
is decided by the system and by platform policy, not by the driver. That has a direct
consequence for patching: a byte patch to a driver file is validated by code integrity before
the image is mapped, and a memory patch to a kernel code page runs into the policy described
in the next section. Both are detailed below, and both are reasons to prefer analysis over
modification on this shape.

## Debug and analysis prerequisites, and what they really cost

Two different activities are routinely conflated: analysing a driver image, and debugging the
kernel of a running machine. Only the second one is expensive.

| Requirement | What it actually costs |
|---|---|
| Reading the driver file statically | Nothing beyond a copy and a PE reader. No signature, no privilege, no reboot, no risk |
| Kernel debugging on current Windows | A second machine, or a virtual machine that is itself treated as a target. `observed`: Microsoft's KDNET documentation describes a host computer that runs the debugger and a target computer that is debugged, requires the target to run Windows 8 or later with a supported network adapter, generates a connection key with `kdnet.exe <Host-IP>`, and connects with `windbg.exe -k -d net:port=<port>,key=<key>` with the recommended port range 50000 to 50039. The same page warns that BitLocker and Secure Boot may need to be suspended before changing boot information |
| Local kernel debugging as a shortcut | `observed`: local kernel debugging starts with `windbg -kl` or `kd -kl` from an elevated prompt, and the documented limitation list is decisive: any command that stops the target is unavailable, including `g`, `p`, `t`, `wt`, `tb`, `gh`, `gn`; the crash, dump and reboot commands; all breakpoint commands; register display; and stack traces. Memory read and write remain available. It is a live inspection channel, not a debugger |
| Loading your own test driver | Test signing, administrator rights, a restart, and a watermark on the desktop. `observed`: `bcdedit -set TESTSIGNING ON` must be run from an elevated prompt, takes effect after a restart, and while it is on, any certificate can sign a driver but every driver image must still carry a digital signature |
| Test signing while memory integrity is on | Not sufficient on its own. `observed`: Microsoft's test-signing page states that with memory integrity (hypervisor-enforced code integrity) enabled, an unsigned binary is not supported and the binary must be test-signed with a self-created test certificate |
| Loading any new kernel driver at all | `observed`: Microsoft's driver signing policy states that since Windows 10 version 1607 Windows will not load new kernel-mode drivers that are not signed by the Dev Portal, with narrow documented exceptions (a PC upgraded from an earlier release, Secure Boot off, a pre-July-2015 end-entity certificate, and boot drivers which are not blocked but are removed by the Program Compatibility Assistant) |
| VBS, and memory integrity in particular | `observed`: VBS uses hardware virtualisation and the Windows hypervisor to create an isolated environment that becomes the OS's root of trust; memory integrity runs kernel-mode code integrity inside that environment and "prevents unsigned or untrusted drivers or system files from being loaded into system memory", ensures kernel pages are made executable only after passing code integrity checks there, and ensures "executable pages themselves are never writable". Its documented hardware requirements include a 64-bit CPU with virtualisation extensions, second-level address translation (extended page tables or the equivalent), IOMMU support, TPM 2.0, Secure Boot, and firmware memory reporting. Virtualisation-based security also works inside a virtual machine, but only where nested virtualisation or guest virtual machine support is enabled |
| The vulnerable-driver blocklist | `observed`: Microsoft maintains a recommended driver blocklist for drivers with known exploitable vulnerabilities, malicious drivers, and drivers that circumvent the Windows security model; the policy page states it has been enabled by default since the Windows 11 2022 update and is enforced when memory integrity, Smart App Control, or S mode is active. Enforcement is observable in the code-integrity operational log as event 3099 |

Read that table as a budget. The cheap route is static analysis plus, at most, observing the
target's interaction with an already-installed driver. Everything past that requires a second
machine or a disposable virtual machine, a reboot, and a policy negotiation with the host's
security configuration.

The probe in this skill reports which of these prerequisites this host has, as
`needs-reboot-and-testsigning` on the kernel driver load route, together with the boot options
it read and the virtualisation-based security registry state. It also states explicitly that
VBS and memory integrity may refuse an unsigned driver regardless of test signing. Treat that
row as the starting point rather than assuming any of the above is available.

## What a user-mode debugger can and cannot see

- **Can:** attach to a user-mode process, set software and processor breakpoints in that
  process's code, inspect its memory and handles, and watch its calls into a driver through the
  user-mode boundary. If the interesting behaviour is the user-mode side of an IOCTL, this is
  the right tool and the kernel route is unnecessary.
- **Cannot:** set a breakpoint inside kernel code, step the kernel, read kernel memory, or
  inspect the driver's data structures. A user-mode debugger has no path to kernel execution:
  the mechanisms it uses are process-scoped.
- **Cannot rely on thread context for kernel work.** The debug registers are per-thread state
  reachable through a thread context, so a hardware breakpoint placed through that route is a
  property of that thread in that process, not a property of the machine.
- **Will not see the driver's own logging by default.** `observed`: kernel `DbgPrint` output is
  not displayed automatically in a local kernel debugging session and is retrieved with the
  debugger's `!dbgprint` extension.
- **Cannot be trusted to explain a driver failure.** A fault in kernel code is a bugcheck, and
  the bugcheck plus the dump analysis is a different workflow from user-mode crash handling.

## Enumerating what a driver exposes to user mode

Work from the file, then confirm at run time.

1. **The device names and symbolic links.** Strings in the image, plus the naming rules above.
   A named device or a symbolic link is the user-mode entry point.
2. **The IOCTL codes and their handlers.** Look for code-shaped 32-bit constants near the
   device-control dispatch routine, and decode each candidate into device type, function,
   method and access. Header-derived constant names often survive in the build and give the
   meaning directly; where they do not, the structure still narrows what each code can do
   (a buffered method cannot receive a raw user pointer, a direct method involves an MDL, and
   the neither method hands the driver a user-mode address that it must treat with care).
3. **What each code does with its buffers.** Buffer handling is where the interesting checks
   are: a licence blob validated in the driver, a hardware identifier read from the machine, or
   a decision that user mode cannot be trusted to make.
4. **Shared state.** Some drivers map memory into the calling process or hand back handles to
   kernel objects; both turn the user-mode side into a view over driver state. `unknown`: the
   specific mapping mechanism is case-by-case and is documented in the WDK memory-management
   reference; this file does not claim a particular routine.
5. **Confirm at run time.** Enumerate open handles to the device and observe which IOCTLs are
   issued, from which process, in which order. That trace, plus the decoded codes, is a much
   better map than any amount of reading alone.

## Analysing a driver is not loading one

Keep these apart in the plan and in the report.

- **Analysis** reads the artifact: headers, sections, imports, strings, the dispatch table, the
  IOCTL constants, and any embedded configuration. It requires no signature, no reboot, no
  policy change, and cannot bugcheck the machine. This is where a driver sample should be
  finished if the question is "what does it do".
- **Loading** changes the machine: it needs the signing chain to accept your image, it needs a
  restart if test signing was off, and a mistake in kernel code is a system stop rather than a
  process exit. It is a separate task with its own isolation requirements, and it should be
  attempted on a disposable machine or a virtual machine that you also treat as a target.
- **A driver that resists analysis by refusing to load** is usually a driver whose decision
  depends on the environment: `DriverEntry` and the dispatch routines can read the machine, the
  registry, the firmware tables or a licence file before doing anything else. Reproduce that
  input rather than fighting the load.

## What this repository does not ship

Stated plainly, because a plan that assumes otherwise fails at the first step:

- No kernel-mode component of any kind. Nothing in this repository is loaded into the kernel,
  and nothing here can read kernel memory or kernel data structures.
- No driver template, no driver build pipeline, and no test-signing automation.
- No kernel-debugger automation: no `kd` or `windbg` driver, no symbol handling, no dump
  analysis. Kernel debugging is performed with the documented tooling described above, driven
  by hand.
- No bypass of code integrity, no loading of unsigned drivers, and no work around the
  vulnerable-driver blocklist. Where a prerequisite is blocked by policy, that is a finding to
  report, not a step to engineer past.
- What exists here is static and user-mode: a PE reader, an equal-length patcher with a
  checksum recomputation, and the host probe that reports which kernel-side prerequisites this
  machine actually has.

## Verification for this shape

1. **State which artifact is the deliverable**, a conclusion about the driver or a modified
   driver, and record its identity (path plus hash).
2. **If nothing was loaded, say so explicitly**, and say what the conclusion rests on: file
   contents, strings, dispatch table, IOCTL structure, and any observed user-mode interaction.
   Do not let a static reading imply a runtime observation.
3. **If something was loaded, name the machine, the signing configuration and the exact binary
   that loaded.** A successful load on a test-signed machine says nothing about a machine with
   memory integrity enforcing code integrity.
4. **Record the policy state that could have blocked it** (test signing, secure boot, memory
   integrity, the driver blocklist) and, where enforcement is claimed, the observable evidence
   from the code-integrity log rather than a guess about why a load failed.
5. **Keep a rollback**: the original file, the previous boot configuration, and a machine
   snapshot taken before the first load attempt.
