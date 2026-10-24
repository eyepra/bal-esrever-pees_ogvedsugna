# CPU vendor divergence: what x86-64 promises, and what one implementation decides

Goal: keep a result measured on one processor from being written down as a property of x86-64, and
recognise the code that selects its path by CPU vendor — because that code behaves differently on the
two vendors that run Windows.

## When to load this

Load this when a check passes on the analysis machine and fails on the machine the deliverable is for;
when a routine reads `cpuid`, compares a twelve-byte vendor string, or branches on a flag the manual
calls undefined; when a listing shows `syscall`/`sysret`, `rdrand`, `pause`, `lzcnt` or an AVX-512
form and the decoder and the CPU may not agree; when a target that died on one vendor stopped dying
after a firmware update; and before a behaviour observed on one host is written into a specification
another team will implement.

## The rule: x86-64 fixes the ABI, not the implementation

The Windows x64 ABI — registers, shadow space, alignment, unwind metadata — is one contract, and both
vendors implement it. What is not shared is each instruction's result where the manual says
*undefined*, the behaviour of system and privileged instructions outside their documented cases, and
the cost of an instruction.

`inferred`: the vendors' specifications agree on the encoding and disagree on what a program may rely
on. That disagreement is the subject of this file, not a defect in either implementation.

Every measurement in this repository comes from one Intel host (`references/evidence-summary.md`, host
facts), which is `observed` for that machine and `unverified` for the other vendor. "It did not
happen here" is therefore a statement about one implementation, not about the instruction.

## Undefined is a result you may not read

| Instruction | Documented contract | What it changes for analysis |
|---|---|---|
| `bsf`, `bsr` with a zero source | ZF=1 on both; Intel leaves the destination **undefined**, AMD documents it **unchanged** | Code that relies on the destination keeping its old value is guaranteed on AMD and merely usual on Intel. A specification that states the old value as the result is wrong on one vendor |
| `shl`/`shr`/`sar` with a count other than 1 | OF undefined on both | A branch on OF after a variable shift tests the implementation, not the program. The value observed is not a bug to reproduce |
| `imul`/`mul` | CF and OF defined; SF, ZF, AF and PF undefined | A check that reads ZF after a multiply is reading residue |
| `popfq` at CPL > 0 | privileged flag bits are not changed | An IOPL or IF write silently does nothing; a write that "took" is a different privilege level |

`inferred` from the instruction descriptions in both vendors' manuals. `unverified`: no divergent
value was measured here, and a particular part's residue is not a fact until it is measured on that
part.

Two consequences:

- **An analysis that explains a branch by an undefined flag has explained nothing.** The branch is
  data-dependent on what the part left there. Reproduce it only on the part that produced it, and
  record which part that was.
- **A protector can test the part this way.** A sequence that sets a flag, runs an instruction that
  leaves that flag undefined, and branches on it is a family or vendor probe. The wrong move is to
  "fix" the branch; the right move is to identify what it is testing.

## Vendor dispatch: the branch that never runs on your machine

`inferred`: `cpuid` with EAX=0 returns the highest basic leaf in EAX and the twelve-byte vendor string
in EBX, EDX, ECX — `GenuineIntel` or `AuthenticAMD`. Feature leaves live elsewhere: leaf 1, leaf 7 with
sub-leaves, and the extended leaves at `80000000H` and above.

The dispatch shape:

```
xor eax, eax
cpuid
cmp ebx, 'uneG'          ; 'Genu', little-endian
jne other_vendor
```

What this changes:

- **A vendor string is not a feature.** A library or protector that dispatches on the vendor string
  takes the other path on the analysis host, so the path you are reading may be the one that never
  executes. Cross-reference the vendor compare with the feature leaves before concluding what the
  code does.
- **A feature leaf is the portable test.** The same feature can be present or absent on either
  vendor, so a correct implementation reads the leaf that defines the feature, not leaf 0.
- **A branch that never runs is the same mistake as an entry point that is never hit.** The breakpoint
  is valid; the path it sits on is not the one this machine executes (`references/pitfalls.md`, P4).

Feature leaves used by the patterns below, `inferred` from the specifications — re-check each against
the revision you open, because a bit's meaning belongs to the family in front of you:

| Leaf | Bit | Feature |
|---|---|---|
| `CPUID.01H:ECX[31]` | hypervisor present | already reported by `scripts/hwprobe.py` |
| `CPUID.01H:ECX[5]` | VMX | Intel virtualisation |
| `CPUID.80000001H:ECX[2]` | SVM | AMD virtualisation |
| `CPUID.80000001H:ECX[0]` | LAHF/SAHF in 64-bit mode | absent on early Intel 64 parts |
| `CPUID.80000001H:ECX[5]` | LZCNT | AMD's ABM bit; also on later Intel parts |
| `CPUID.01H:ECX[30]` | RDRAND | hardware random |
| `CPUID.07H.0:EBX[18]` | RDSEED | seeded random |
| `CPUID.07H.0:EBX[16]` | AVX-512F | 512-bit vector baseline |

`python skills/exe-reverse/scripts/hwprobe.py` prints the vendor string, family/model/stepping, the
brand string and the raw leaves. It prints bits raw on purpose: the probe refuses to decode a meaning
it has not verified, and the reader is expected to open the specification for the part.

## The same bytes, two instructions

`inferred`: an instruction that reuses a legacy prefix is decoded by feature, not by encoding alone.
`F3 0F BD` is `lzcnt` where the feature is present and `rep bsr` (prefix ignored, different result)
where it is not. `F3 0F B8` is `popcnt`. `0F 0F` is 3DNow!, an AMD extension removed from current
parts. The XOP prefix `8F` carries AMD-only integer forms that a decoder for the other vendor reads as
a different instruction entirely.

Consequences:

- **A disassembler has a target-CPU setting, and it changes the listing.** A generic x86 target shows
  `rep bsr` where the machine executes `lzcnt`. Record the decoder's processor setting with the
  listing, the same way you record the tool's version.
- **An emulator is a third implementation.** It implements one CPU model and one decode map, and a
  `cpuid` answer under emulation is that model's answer. A behaviour derived under an emulator
  inherits the emulator's choices and is `unverified` for both vendors.
- **Feature-gated code has two bodies.** When one function is compiled for two feature levels, the
  logic you want may exist in only one of them. Locate both before patching one.

## System instructions: privilege and fault timing

`inferred` from the vendor specifications and the public analysis of CVE-2012-0217:

| Case | Intel | AMD | What it changes |
|---|---|---|---|
| `sysenter`/`sysexit` in 64-bit mode | supported in IA-32e | invalid in 64-bit mode (`#UD`) | a reachable `0F 34`/`0F 35` in a 64-bit image carries an Intel-only assumption; the other vendor faults where the author's machine did not |
| `sysret` with a non-canonical RCX | `#GP` taken at CPL0 | privilege restored to CPL3 first, then `#GP` | the same return path faults at a different privilege level, so the handler that runs — and the stack it runs on — differs |

The CVE is the canonical case: a kernel that trusted the fault to arrive before the privilege change
was exploitable on the vendor where it arrives after. The lesson for an analysis is narrower than the
vulnerability: **a check whose failure mode is an exception has a vendor in its semantics.** Reading
the handler shows which case the code expects; "it faults" is not enough.

`unverified`: the cycle-level timing of `popfq`'s effect on TF and RF, and of a pipeline observing a
flag change. Do not build a detection or a patch on a timing claim that was not measured.

## Cost is implementation, and spin loops inherit it

`inferred`: `pause` is a hint whose latency is model-specific, not architectural. Intel's optimisation
guidance documents a change from roughly ten cycles on older parts to roughly 140 on Skylake and later;
AMD's parts use their own value. A spin loop tuned to one vendor's latency wastes time on the other, or
times out.

The same pattern applies to:

- **A `lock`-prefixed access that straddles a cache line.** It is architecturally legal and slow.
  Recent Intel parts can report it as a split lock (`#AC`) when the platform enables the feature, and
  whether a guest's policy enables it is a host property. A fault here is a policy finding, not a
  target bug.
- **AVX-512 width and frequency.** Intel implements 512-bit execution with a frequency consequence on
  some parts; AMD's Zen 4 executes it as two 256-bit halves without the same consequence. A throughput
  number is a number about the part, and a timing check calibrated on one part behaves differently on
  the other.
- **Topology.** Logical-processor counts, SMT numbering and cache sizes come from leaves that describe
  the part in front of the program. A worker pool that hard-codes a topology runs correctly and slowly
  on the other vendor — a performance bug that is really a portability one.

## Virtualisation and control-flow integrity: two instruction sets

`inferred` from the vendors' specifications:

| Mechanism | Intel | AMD |
|---|---|---|
| Enter and leave a guest | `vmxon`/`vmxoff`, `vmlaunch`/`vmresume`, `vmexit` | `vmrun`, `vmexit` |
| Control structure | VMCS, reached through `vmread`/`vmwrite` | VMCB, an ordinary memory structure read and written directly |
| Second-level translation | EPT | NPT |
| Shadow stack | CET (`endbr64`, `incssp`, `rdssp`, `saveprevssp`) | shadow stack with compatible instructions, different control MSRs |

What this changes:

- **Tooling is vendor-bound.** A debugger or hypervisor built on VT-x does not run on an AMD host.
  That is a capability answer, not a target answer: `references/hypervisor-observation.md` describes the
  layer, and which vendor's layer can be driven is a host fact.
- **A vendor-specific instruction in a driver is a portability statement.** Seeing `vmread` says which
  vendor the driver was written for; it says nothing about whether its protection can be bypassed.
- **`endbr64` is a build-era marker.** Its presence says the image was built for a CET-enabled target,
  not that the process is protected at run time; enabling is a policy decision above the image.

## What these divergences look like when they bite

`unverified` as field reports; the mechanisms above are what make each one possible.

| Shape | Check first |
|---|---|
| A launcher aborts on a subset of CPUs, and a firmware update makes it disappear | a hardware-random retry loop whose success flag never sets — measure CF in a control loop on that host before calling it anti-debug |
| A compute library runs several times slower on the other vendor at the same clock | a vendor-string dispatch that selects an older instruction path than the feature leaves justify |
| A game's worker threads collapse to half the cores on the other vendor | a hard-coded topology assumption in a third-party scheduler; the branch is the evidence and the patch site |
| A kernel driver bug-checks only on one vendor during a return to user mode | non-canonical `sysret` handling, and the privilege level at which the fault is taken |
| An analysis tool refuses to start on the other vendor | a VT-x-only implementation; read the vendor leaf before debugging the tool |

The method is the same in all five: **measure the part, not the platform.** Record the vendor string,
family, model, stepping, the microcode revision if the OS exposes it, the OS build and the hypervisor
state beside every timing, fault and feature result. A result without the part is not reproducible,
and a result reproduced on a different part is a different result.

## Before a behaviour goes into a specification

1. **Does the sentence assert a value for something the manual calls undefined?** Rewrite it as
   undefined, and state what the implementation must not rely on.
2. **Is the behaviour conditional on a vendor or a feature?** Name the leaf and bit that select it, and
   test the feature rather than the vendor.
3. **Was the observation made on the part the implementation will run on?** If not, the sentence is a
   hypothesis, and it belongs in the specification as one.
4. **Which instruction set did the decoder assume?** Record it, because `F3 0F BD` is two instructions
   and the listing shows one.
5. **Does the deliverable contain a timing constant?** Replace it with a measurement on the target
   part, or with a bound that does not depend on one.

## What this file does not do

- **It does not rank the vendors.** Neither implementation is the reference; the specification is, and
  where the specification says undefined, both are compliant.
- **It does not replace the manual for the part in front of you.** Leaf numbers and bit positions are
  stable; what a model-specific bit means is not, and no table here substitutes for the revision you
  open.
- **It does not measure the other vendor.** No AMD host was available, so every divergent behaviour is
  `inferred` from documentation and `unverified` here. The first measurement on a second vendor
  replaces the row; the row does not get to overrule the measurement.
- **It is not a portability guide for writing code.** The subject is reading a binary and writing down
  what it is allowed to assume.
