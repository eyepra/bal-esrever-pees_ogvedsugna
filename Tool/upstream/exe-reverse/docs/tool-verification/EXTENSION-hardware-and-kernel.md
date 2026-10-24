# Extension: hardware and kernel routes

What this pass covered, what it verified externally, and what it deliberately did not assert. The
routes here are the skill's reason to exist and its least portable part, so the record is organised
around one question: **what does each mechanism actually require, and what does it still not see?**

## What was verified externally

| Fact | How it was established | Grade |
|---|---|---|
| The trace feature has its own capability leaf, and its bits describe filters and output modes rather than "works / does not work" | read from an operating system kernel's implementation of the same CPUID contract | `inferred` for the bit names, `observed` that the leaf answers on this host |
| The trace unit is reachable only from privileged code | the control registers and the output region are set from ring 0 in that same implementation | `inferred` |
| A last-branch-record capability leaf exists, and its depth field is a **mask rather than a count** | the same implementation computes depth from the mask, and published values differ by generation (4, 8, 16, 32) | `inferred` |
| The architectural performance-monitoring leaf reports version, counter count, bit width and mask length | the same implementation reads those subfields, and treats the leaf as unusable below a minimum mask length | `inferred` |
| A hypervisor is detectable from a single CPUID bit, and its vendor from a separate leaf | the same implementation | `inferred` |
| Hardware breakpoints: a small fixed number of debug registers; a watch is 1, 2, 4 or 8 bytes wide (8 only on 64-bit); the address must be aligned to the width; there is **no read-only data breakpoint**; the access field encodes execute, write, or read-write | processor documentation for the register layout; the encoding rules are what the control field admits | `observed` for the count and the field set |
| A data breakpoint set on a code address never fires | instruction fetch is not a data access, so no access-width and access-type combination can match it | `inferred`, and it is the single most common misunderstanding in this area |
| Single-machine instruction-level recording exists as a debugger feature, is user-mode only, has a high recording overhead, produces multi-gigabyte files, and cannot record a protected process | the feature's own documentation | `observed` |
| Local kernel debugging is documented but cannot stop the target | the documented command set excludes the halting commands while permitting memory access | `observed` |
| Full kernel debugging over a network needs a boot-configuration change on the target and a second machine (or a virtual machine) | the documented setup procedure | `observed` |
| Every register-level monitoring mechanism needs ring 0, and therefore an administrator and a driver — which may in turn need test signing, and may still be refused where code-integrity enforcement is active | the documented requirements for each | `inferred` |

## What this changed in the skill

Three claims that were circulating as common knowledge turned out to be wrong, and the corrections
are now in the route text and in the probe's output:

- **There is no single timing packet.** Timing is carried by three different packet kinds, each
  gated by its own capability bit. A plan that assumes one timing packet will mis-parse a trace.
- **The branch-record depth is not a constant.** Values of 4, 8, 16 and 32 all exist across
  generations, and the field is a mask. Anything that hardcodes "16 entries" is wrong for some of the
  processors it will meet.
- **"Four breakpoints" does not mean four watchpoints of any size.** The width is restricted, the
  address must be aligned, no read-only data watch exists, and setting one on a code address does
  nothing at all.

And one boundary was sharpened enough to change a recommendation: **on this platform there is no
documented user-mode path to the trace unit.** The in-box support that exists is aimed at crash
analytics rather than at analysis, and is not documented for this purpose. That is why the probe
reports the trace route as needing a driver or a record-and-replay debugger rather than as merely
needing a decoder, and why `references/evidence-summary.md` grades the route `unverified` here rather
than `inferred`.

## What was deliberately not asserted

Written down rather than guessed, because each of these is exactly the kind of detail that becomes
authoritative-looking when it is wrong:

- The normative bit layout of every capability field. Where a vendor specification was not reachable,
  the encodings were taken from an implementation of the same contract and are labelled as such. A
  reader who needs the normative definition is told to consult the specification for the processor in
  front of them.
- Byte-level encodings of the trace packet format. The packet *set* is established; the wire encoding
  of individual packets is not.
- Sampling-precision claims, the deprecation status of the older branch-trace mechanism, which
  virtualisation exits intercept which registers, and the interaction between kernel patch protection
  and debuggers. For each of these a first-party source was not reachable from this environment, so
  the documentation names the mechanism without asserting the behaviour.
- A numeric overhead figure for OS-level event tracing. The documented problem is loss accounting and
  a single-session constraint, which is what the text states; an overhead percentage would have had
  to be invented.

## Why this route is probed rather than declared

Every mechanism here is conditional on the host: on a supported processor, on privileges, on signing,
on whether the analysis machine is itself virtualised. A plan that assumes otherwise fails at the first
step and gets attributed to the tooling. `scripts/hwprobe.py` exists so that the answer is a
measurement with three states — available, needs-`<something>`, unavailable — and so that a host
inside a hypervisor reports that fact rather than silently degrading every route that depends on a
debug exception.
