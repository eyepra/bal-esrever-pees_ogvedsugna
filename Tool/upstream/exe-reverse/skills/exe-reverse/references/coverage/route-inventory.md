# Route Inventory

**What this answers:** for each route this skill describes, one row stating what it is for, what it
requires, and how far it was actually taken — so a reader can tell a route that was exercised from a
route that is argued.

**When to load this:** when deciding whether a route is worth starting here, or when a claim needs to
be traced back to what supports it.

## How to read the "how far it was taken" column

| Value | Means |
|---|---|
| `run` | exercised on this host with the command recorded in `references/evidence-summary.md` |
| `argued` | the mechanism and the tool documentation were read, and no run was performed here |
| `mapped` | the route's shape and requirements are stated so it can be planned, with the dependency named |

A route at `argued` or `mapped` is not a capability. It is a plan with its cost written down, and it
becomes `run` only when someone runs it and records the output.

## Static routes

| Route | For | Requires | Taken |
|---|---|---|---|
| PE structure reading | answering any header, section, directory, import, export, resource, TLS, relocation or checksum question | Python only — offline and dependency-free | `run` |
| Triage | first contact with an unknown binary: identity, build evidence, protective signals, surface | Python only | `run` |
| Toolchain fingerprinting | deciding which toolchain produced a binary, and what that implies for reading it | the binary; a disassembler only if the fingerprint is inconclusive | `run` for the header-level signals, `argued` for the toolchain-specific structure |
| Instruction-level reading | reading a routine's convention, frame and idiom so that a patch or a detour preserves what the callee expects | a disassembler or decompiler — the repository ships none | `argued` |
| CPU-vendor divergence reading | deciding whether an observed result is architectural or one implementation's choice, and reading a vendor-string dispatch | the binary; a disassembler with its target CPU pinned; a second-vendor host to confirm | `argued` |
| Byte patching | making a change that fits an existing instruction or constant slot | Python only, plus a copy to write to | `run` |
| Signature location | finding a site across builds rather than at one address | Python only; a second build for the comparison | `run` |
| Build comparison | locating what changed between two builds | two builds | `run` |
| Identity scanning | publishing derived material without publishing the target | Python only | `run` |
| Managed assembly analysis | reading and changing a .NET assembly | a decompiler or disassembler (`ilspycmd`, `ildasm`) to read it, `de4dot` for a renamed one, an assembler or dnSpyEx to change it — the repository ships none | `mapped` |
| Installer and package extraction | getting at the payload of an installer without running it | extraction tooling; the container type decides which | `mapped` |

## Application-runtime routes

A packaged application adds a layer between the PE and the logic: an interpreter and its artifacts,
a container, or a wrapper around the code. These routes are described from public write-ups and the
tools' own documentation; none was run on an artifact in this repository.

| Route | For | Requires | Taken |
|---|---|---|---|
| Unity IL2CPP metadata recovery | a readable metadata file when the shipped one is missing, empty, or decrypted only in memory | the build; a debugger or an instrumentation runtime for the memory route; a dumper for the code half | `argued` |
| IL2CPP registration and version repair | a dumper that reports no registration, or parses a struct that disagrees with the metadata version | a dumper whose version handling can be overridden, and the exports or call sites that lead to the registration | `argued` |
| Packaged Python extraction | the code objects inside a packaged executable | the packager's extractor, and an interpreter at the exact version the package bundles | `argued` |
| Code-object wrapper removal | bytecode that is encrypted per object, with a runtime that decrypts it | the wrapper's key derivation for its version, or a run in which the plaintext can be dumped | `argued` |
| VM-protector boundary tracing | redirecting one decision inside a virtualised region without devirtualising it | a debugger with tracing, and the point where the virtual flag word is materialised | `argued` |

## Dynamic routes

| Route | For | Requires | Taken |
|---|---|---|---|
| Interactive debugging | locating behaviour at run time, watching values, choosing a breakpoint family | a debugger installed on the host; several are GUI-only | `argued` |
| Command-line debugging | a scriptable debugger engine for a dump or a process | a debugger engine on the host | `argued` |
| Runtime instrumentation | calling into or observing a live process through a hook | an instrumentation framework, and a target that does not object | `argued` |
| Injection and hooking | getting code into a target, or intercepting a call | the rights to write into the process, plus a hooking mechanism | `argued` |
| System event tracing | file, registry, process and image evidence from the OS | an elevated session for kernel providers | `argued` |
| Dumping and repair | capturing process memory, and turning a dump into something loadable | the rights to read the process; repair needs the section mapping restored | `argued` |
| Kernel debugging | watching a driver | a second machine on a current host, or a boot-configuration change | `mapped` |

## Observation routes that do not modify the target

These are the routes this skill exists to describe, and they are also the most conditional ones.
Everything here is probed by `scripts/hwprobe.py` before a plan depends on it.

| Route | For | Requires | Taken |
|---|---|---|---|
| Hardware execute breakpoints | stopping at a location without changing the byte there | a debugger, and a host whose hypervisor does not consume the debug exception | `argued` |
| Hardware data breakpoints | watching a value without a hook and without a code check seeing a change | the same, plus an aligned access width | `argued` |
| Last branch records and performance counters | recent control flow and sampled events | privilege to read the model-specific registers or the counters | `mapped` |
| Instruction tracing | the full control-flow trajectory of a run, with no hooks and no modification | a CPU that reports the feature, **a capture path**, and a decoder | `mapped` — the CPU capability is `run`; capture and decoding were not exercised here |
| Record-and-replay debugging | replaying a recorded user-mode session | the debugger that provides it; recording is user-mode only and replay is read-only | `mapped` |
| Hypervisor-assisted observation | seeing a target that can see every ordinary observer | a driver, signing or test mode, and a host that is not already nested | `mapped` |

**The honest summary of this table:** the offline, static routes are exercised and recorded; the
dynamic and hardware routes are documented with their requirements and their costs, and none of them
is claimed as working here. That distinction is the point of the table — a reader planning a hardware
route needs to know it must be probed, not that it was tried.

## What no route here covers

- Defeating a decision the server owns. The client has nothing to change, and a local edit that
  appears to succeed has moved the failure rather than removed it.
- A general-purpose automated devirtualiser. The mechanisms are documented; the automation is a
  research project, not a script in this repository.
- A named commercial protector as a product claim. The classification and the mechanism are in scope;
  a statement that a specific build of a specific product was defeated is not.
- Building and signing a kernel driver as a shipped capability. The route is mapped with its
  requirements; the driver is not shipped.
- Any guarantee about a Windows build this repository has not measured.
- Any artifact class outside Windows PE: a different sample type belongs to a different skill.
