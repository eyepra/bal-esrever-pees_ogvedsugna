# Evidence Summary

**What this answers:** for each thing this skill claims, one line of conclusion, the strength of
that conclusion, and the evidence a reader can actually open in an installed copy.

**When to load this:** when a claim's strength decides whether you trust it, and the record of the
run is not in front of you.

## How to read the grades

| Grade | Requires | May it justify a decision? |
|---|---|---|
| `observed` | a command was run **and its output exists** | yes |
| `inferred` | follows from an observation, but the step is reasoned | provisionally |
| `unverified` | assumed, or reported elsewhere and never reproduced here | only as something to test |

**A claim is only as strong as the weakest link in its chain.** A chain that ends in "the tool
mechanism is verified" says nothing about "the route works on your target", and the two must not be
written as one sentence. **Missing coverage is `unknown`, never absence:** a search that found
nothing is evidence about the search, and the search has to be named.

Two kinds of `observed` appear below and the difference matters. **Tool behaviour** observed (this
script does this, on this host, with this output) is strong and transfers to any host running the
same tool. **Target behaviour** observed (this binary did this, once) is strong for that build on
that host and does not transfer.

## Scripts — measured

These were run on the development host: Windows 11, build 26100, Python 3.14, elevated session.
The images used were platform binaries readable on any Windows installation plus fixtures this
repository generates itself; no third-party sample is required to reproduce any row.

| Capability | Conclusion | Strength | Evidence you can reproduce |
|---|---|---|---|
| PE header, section and directory parsing | parses real images and the synthetic fixtures, and reports the fields it claims to | `observed` | `python skills/exe-reverse/scripts/peutil.py <pe> --summary` |
| PE checksum recomputation | the computed value equals the declared value on bytes-unchanged platform images, and on every generated fixture | `observed` | `python skills/exe-reverse/scripts/peutil.py <pe> --check-sum` |
| RVA ↔ file-offset conversion | both directions work, including a section whose virtual size exceeds its raw size, where the virtual-only tail correctly has **no** file offset | `observed` | `peutil.py <fixture> --json` against the fixture's declared `rdata` virtual tail |
| Import parsing | named imports and imports by ordinal both resolve; the fixture declares one of each and both are reported | `observed` | `python skills/exe-reverse/scripts/peutil.py <fixture> --imports` |
| Resource tree walk | returns exactly the entries the fixture declares, and plausible counts on platform images | `observed` | `python skills/exe-reverse/scripts/peutil.py <pe> --resources --json` |
| TLS, debug/PDB, relocation parsing | the fixture's TLS callback RVA, RSDS record and relocation block are all reported as constructed | `observed` | `python skills/exe-reverse/scripts/peutil.py <fixture> --tls --debug --relocs` |
| Equal-length patching | a one-byte patch is applied to a copy, the checksum is recomputed, every patched byte is re-read from the written file, and the input file's hash is unchanged | `observed` | `python skills/exe-reverse/scripts/pepatch.py <pe> --at-rva <rva> --bytes CC --expect 48 --out out.exe` |
| Patch refusal on ambiguity | a pattern matching many sites is refused with the sites listed, rather than silently taking the first | `observed` | `python skills/exe-reverse/scripts/pepatch.py <pe> --pattern "FF 15" --bytes 9090 --out o.exe --dry-run` |
| Patch refusal on an unproven length | a patch with no length reference reports `[length unproven: pass expect or original-length]` instead of asserting equal length | `observed` | same command with `--bytes CC` and no `--expect` |
| Byte-pattern location | reports the hit count, each site's offset/RVA/section, and a verdict; a pattern that matches twice is reported as `ambiguous` | `observed` | `python skills/exe-reverse/scripts/aob_scan.py <fixture> --patterns "<the planted sequence>"` |
| Cross-build pattern comparison | `--across` reports each build's hit count and states when the count changed | `observed` | `python skills/exe-reverse/scripts/aob_scan.py <fixture-a> --patterns P --across <fixture-b>` |
| Offline fixture generation | builds a structurally valid PE32 or PE32+ image, deterministic in bytes, with a correct checksum, that the reader parses back | `observed` | `python skills/exe-reverse/scripts/make_fixture_pe.py --out f.exe --json` |
| Identity scanning | scans the tree, reports findings with context, prints `RESULT=` and sets an exit code suitable for gating | `observed` | `python skills/exe-reverse/scripts/scan_leaks.py` |
| Host capability probing | prints a per-route verdict and reads CPUID through a local stub; bits whose meanings are not verified are printed **raw** rather than decoded | `observed` | `python skills/exe-reverse/scripts/hwprobe.py` |
| Whole-report timing (a calibrated baseline, not a benchmark) | `peutil.py --summary` on a 360 KB image: 158 / 166 / 167 ms over three runs. `hwprobe.py --json`: 1858 ms | `observed` | run both and time them |

## Host facts measured on the development machine

These are about *that* machine. They are here because they are exactly the facts a plan must not
assume, and because a reader can compare their own `hwprobe.py` output against them.

| Fact | Value observed | What it implies |
|---|---|---|
| OS | Windows 11, build 26100; the registry `ProductName` still reads "Windows 10" | read the build number, not the product name |
| CPU | family 6, model 154; `CPUID.07H.0:EBX[25]` set | the trace feature is reported by the CPU |
| CPU vendor | the vendor string `cpuid` returned was `GenuineIntel` | every measurement here is from one implementation; a result on this host is not a statement about the other vendor |
| Hypervisor | `CPUID.01H:ECX[31]` set and the platform reports a hypervisor present | a debug exception may be intercepted; hardware routes must be probed, not assumed |
| Debug registers | four (`DR0`–`DR3`) is the architectural count | an upper bound on simultaneous hardware breakpoints, independent of tooling |
| Intel PT capability leaf | `CPUID.14H.0` returns max sub-leaf 1 and capability `EBX = 0x0000005F` | the leaf answers; the bits are printed raw because their meanings belong to the processor specification for this family, not to this repository |
| LBR capability leaf | `CPUID.1CH.0` returns `EAX = 0x4000000B` | reported raw, same reason |
| PMU | `CPUID.0AH.0`: version 6, five counters | performance monitoring exists; reading it needs privilege |
| Security-service registry values | the values under the Device Guard keys were **absent**, and the documented cross-check class was itself unavailable on that edition | the state is `unknown`, and `unknown` is not `off` |
| Privilege | elevated session (`TokenElevation`) | the routes that need elevation were testable there; a reader without it gets a different table |

## Hardware and kernel routes

| Capability | Conclusion | Strength | What is missing |
|---|---|---|---|
| Hardware breakpoints (execute and data) | a small fixed number of debug registers exists in the architecture, and setting one does not modify the bytes it watches — that property is why this route is reached for when software breakpoints are detected | `inferred` from the architecture as documented; not exercised by a debugger in this repository | a debugger on the host; the repository ships no debugger driver |
| Instruction tracing (Intel PT) | the CPU here reports support, and a decoder turns a trace into an address stream | `unverified` for this repository: no capture was taken and no decoder was run | a capture path. On the systems this was researched, user-mode capture on Windows had no first-party documentation found; the Linux `perf` path is documented by its own project. The constraint is **capture**, not decoding |
| OS-level event tracing (ETW) | tooling exists on the host and kernel providers need an elevated session | `inferred` — the tools were found, no trace was recorded | a decided provider set; recording is a separate exercise |
| Record-and-replay debugging | it is a feature of a debugger that is not installed here, recording is user-mode only, and replay is read-only | `inferred` from vendor documentation | the debugger itself |
| Kernel debugging | needs a second machine on a current host, or a boot configuration change | `inferred` from vendor documentation | the second machine; this host was not reconfigured |
| Kernel driver load | needs test signing and may still be refused where virtualisation-based security is enforcing code integrity | `inferred` | a signed or test-signed build, and a host whose policy permits it |
| Hypervisor-assisted observation | the layer above the OS can do what a debugger cannot, and its presence also changes what a debugger can do | `unverified` for this repository | a driver, signing, and a host that is not already nested |

**Read this section as a map of what is reachable and what it costs**, not as a set of capabilities
this repository implements. The repository ships the probe, the decision table and the route
documentation; it does not ship a debugger, a driver, or a VMX implementation.

## Routes documented but not run here

These are argued in the reference library from mechanism and from published tool documentation. They
are `inferred` at best, and a reader should treat them as a plan to test rather than as a procedure
that has been exercised.

| Route | Why it is not `observed` here |
|---|---|
| Unpacking a protected binary and repairing the dump | no protected sample was obtained or analysed in this repository |
| Reconstructing an import table | the mechanism is documented; no dump was repaired end to end |
| Devirtualising a flattened or VM-protected routine | no such sample was obtained; the tools named are third-party and were not run |
| Recovering a licence algorithm and building a key generator | no target with a licence mechanism was analysed here |
| Managed-assembly patching | no managed sample was obtained; the toolchain is documented and its limitations are quoted from their own documentation |
| Kernel driver analysis | no driver was analysed; the tooling is not installed on the development host |
| Any claim about a specific commercial protector | the mechanism and the vendor's own documented descriptions are cited; nothing was measured against a protected sample |
| Unity IL2CPP metadata recovery and registration repair | no Unity build was analysed here; the placements, the dumper's failure modes and the string-literal layer are taken from public write-ups |
| Unpacking a packaged Python program | no packaged sample was analysed here; the container behaviour is documented by the packagers' own tooling |
| Recovering code objects from a versioned wrapper | no wrapped sample was obtained; the mechanism is quoted from one public analysis and is version-specific |
| Instruction-level reading of a listing | no target was disassembled here; the conventions are documented architecture, and a producer claim (compiled here, assembled there) is `inferred` until a build whose toolchain is known confirms it |
| CPU-vendor divergence | no AMD host was available; the divergences are stated from both vendors' specifications and one public CVE analysis, and nothing was measured across vendors |

## Where the corpus comes from

The tests and the fixture generator need binaries, and the two safe sources are: **images this
repository builds itself** (deterministic, byte-reproducible, committed as code rather than as
artifacts) and **software whose licence permits analysis**, each with its permission basis recorded
before it is used. Public practice targets published for the purpose — crackme archives and
challenge sets — are the other legitimate source, on their own stated terms.

Platform binaries are used in the recorded measurements above because they are present on any
Windows installation and need no download; that is a statement about their availability to the
measurement, not a claim about permission for any other use.

## Claim-strength rules that apply to this file itself

- A row may not be promoted because a downstream result succeeded. A passing verifier downstream does
  not repair a malformed read upstream.
- A limit must cite the measurement or constraint that set it. A limit with no constraint behind it
  is a preference.
- When a measurement disagrees with a conclusion recorded here, the conclusion is re-opened. It is
  not explained away, and it is not quietly edited: the change is described.
- **A route that was not run is not a route that works.** It lands in the table above as `inferred` or
  `unverified` with what is missing, and it stays there until someone runs it.
