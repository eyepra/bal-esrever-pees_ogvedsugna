# Tool acquisition, and what it costs

**What this answers:** how a tool gets onto an analysis host, what its licence permits, and how
you know it actually runs. This is the part `capabilities.py` reports as a gap but does not
close -- the probe says "missing", and this says what to do about it.

**When to load this:** when a route is blocked by an absent tool, or when its real cost is a
licence rather than an install.

## Licence class before download

| Class | Examples | What it costs you |
|---|---|---|
| Open | Ghidra, radare2/rizin, x64dbg, Frida, gdb, lldb, upx, 7-Zip | nothing; support and maintenance are the real cost |
| Free, restricted | IDA Free (non-commercial), Cheat Engine, most vendor trials | a licence *condition*, not a price; a commercial engagement may exclude it |
| Commercial | IDA Pro + Hex-Rays, Binary Ninja, Hopper | a per-seat licence; procurement lead time is part of the plan |
| Trial | vendor time-limited builds | an expiry date in the middle of a session; write it down |

**No cracked builds, no key generators, no patched installers.** Two reasons, and the second is
the engineering one: a patched binary is an untrusted binary, and you would run it on the machine
whose integrity every later measurement depends on. An unlicensed tool is a capability you do not
have -- record it that way.

## An id copied from a document is `unverified` until a search returns it

`winget search`, `brew search`, `apt-cache search`. Identifiers get renamed, forks get
republished, and a mirror is not the vendor's build. The resolution is one command, and it is the
difference between a record of what happened and a guess that worked once.

Two more things worth knowing before the install: WinDbg exists as a Store build and as the SDK's
Debugging Tools (`cdb`/`kd`), and those are different command lines; on macOS a downloaded bundle
carries a quarantine attribute, so verify the hash before removing it.

## "Installed" is not "available"

| Kind | What proves it works | What it does not prove |
|---|---|---|
| CLI | the version string **and** one real command on a fixture you control | that it parses *your* target without error |
| GUI | it opened the sample and rendered a function list, witnessed by a human | that the analysis finished, or that the decompiler is licensed |
| Kernel / driver | the second machine answered on the debug link | that the driver loads on this build |

A GUI-only tool is a request for a human, not an unavailable capability. A weaker CLI substitute
is not the same capability, and a headless host cannot render the real one.

## When the tool is paid and you cannot pay

1. **Use the free implementation and record what it cannot do.** Ghidra's decompiler differs from
   Hex-Rays in readability, not in existence; "recovered with Ghidra, control flow verified by
   hand" is a real result.
2. **Ask the requester to license it.** A procurement question with a lead time, not a technical
   blocker -- name the blocked route and its cost.
3. **Narrow the deliverable** so the missing capability is not on the critical path.

## What to record

Per tool: class, version, absolute path, **the smoke test you ran**, and a label -- `observed`
(you ran it), `inferred` (the install succeeded, you did not run it), `unverified` (someone told
you it is there). Then re-run `doctor.py` and keep both outputs: their difference is the change
you made to the experiment.
