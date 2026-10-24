# Failure Catalogue

**What this answers:** the specific, already-paid-for failures of Windows binary work — each one
produces a result that looks correct until something else breaks.

**When to load this:** before building anything, when a result is surprising, and whenever a
description of a symptom does not fit the plan.

Read it before you build, not after something breaks. Every entry below is a failure that produced a
working-looking artifact: a file that assembled, a process that started, a run that logged no error.
That is the shape worth fearing. A crash announces itself; these do not.

Each entry states the failure, the mechanism that makes it invisible, and the check that catches it.

P1-P25 are format and mechanism failures of Windows binaries; P26-P38 are failures of the *analysis*
itself — sampling read as observation, a self-built parser trusted, a verification that could not have
failed. Those are written with Windows examples because that is where they were paid for, but the
mechanism does not depend on the platform: read them on a managed assembly and a driver the same way.

---

**P1. A length change, made by someone who thought of it as "just adding a byte".**

A patch that occupies more or fewer bytes than the original moves every offset after it. What breaks
is not the patched instruction: it is the section table's raw pointers, the relocation block, the debug
directory's file offsets, the certificate table's location, and any internal pointer that was written
as a file offset rather than an RVA. The edit itself still looks right in a hex editor, and the file
may still parse.

*Check:* state the site's length before editing and compare it to the replacement. A patcher that
cannot compare them must report the length as **unproven** rather than as equal.

**P2. Editing bytes and leaving the checksum stale.**

A PE carries a checksum field. Some loaders, installers, packagers and signing pipelines check it,
and a mismatch surfaces far from the edit, often as a refusal to load rather than as a checksum
complaint.

*Check:* recompute it after every write, and record the declared-versus-computed pair in the result.
A checksum that agrees before the edit and disagrees after it is not a mystery.

**P3. Recording a runtime address without the module base and the build.**

"This check is at `0x7FF6A21C4B30`" is worthless one reboot later, because the address depends on the
load address (which moves with ASLR), the module it belongs to, and the exact build. Written down
without those, the finding has to be rediscovered.

*Check:* record module name, module base, offset from that base, the image hash, and the address.
Then the same site can be recomputed on the next run rather than searched for.

**P4. A breakpoint at the entry point that is never hit, on a program that plainly runs.**

The entry point is not necessarily the first thing that executes. A TLS callback runs before it, and
a protector's stub usually does. "My breakpoint did not fire" then reads as "the code never runs",
which is the wrong conclusion.

*Check:* look at the TLS directory before choosing the first breakpoint, and break on something the
program must do (an API it calls, a window it creates) rather than on a location.

**P5. Treating anti-analysis behaviour as a broken environment.**

When a program dies on attach, or refuses to start while a debugger is present, or exits at a constant
interval, the reflex is to suspect the analysis machine. The reflex is sometimes right and usually
expensive: minutes of host troubleshooting for something the target did deliberately.

*Check:* run the **unmodified original** under the same conditions. If it dies without a debugger too,
it is not your tooling. If it dies only with one, it is the target, and the mechanism is the thing to
find.

**P6. Reporting a patch as working because the bytes are in the file.**

"Present at the offset" and "reached at run time" are different claims, and only the second one is
what was asked for. A patch can be in the file, verified byte-for-byte, and never execute: the branch
that leads to it may be unreachable, a self-check may have replaced the region, or a different code
path may be taken on this configuration.

*Check:* break on the patched site, or change something observable and look at the outcome. Then
verify *that* — not the write.

**P7. Neutralising a check by making it never return.**

Replacing a decision with an infinite loop looks like a way to stop it from terminating the process.
It freezes the caller **while it holds whatever it held**, so unrelated threads wedge, the process
hangs with no crash record, and the eventual death is attributed to the wrong thing entirely.

*Check:* a neutralised check must **return**, with a benign value, and preferably a success value. If
the fix is a loop that cannot exit, the diagnosis is wrong.

**P8. A byte pattern that matches more than one site, taking the first hit.**

A pattern is a locator only while it is unique. On the build where it was written it may well have
been unique; the second match appears later, in a place nobody looked, and the patch lands on the
wrong instruction with no error.

*Check:* every pattern search reports its match count. A count above one is a result, not a detail:
anchor the pattern on surrounding structure before using it.

**P9. Assuming a memory breakpoint keeps working.**

A page-guard based breakpoint fires once, as an alert that the page was touched, and then the guard is
gone unless it is re-armed. Treating it as a watchpoint produces a single hit and a false conclusion
that the region is used once.

*Check:* decide whether the question is "was this touched" (guard, once) or "what value passes here"
(a hardware breakpoint on the datum, or a logging breakpoint).

**P10. Asking for a thread's context while it is running.**

A register read on a running thread is not a thing the platform will do for you; the call fails, and a
programmer who ignores the return value then reasons about a stale or zeroed structure.

*Check:* check the return value of every context query, and suspend or break the thread you are
asking about.

**P11. Planning a hardware-observation route without probing the host.**

Hardware breakpoints, instruction tracing and hypervisor-level observation are all conditional: they
need debug registers the host will let you use, a processor that reports the feature, a capture path,
signing or test mode, or a machine that is not already running under a hypervisor. A plan built on
"the CPU supports it" fails at the first step and looks like a tool problem.

*Check:* run the host probe and read the route table. The states it reports are `available`,
`needs-<something>`, and `unavailable`, and all three are answers.

**P12. Treating a memory dump as a runnable image.**

A dump is bytes, not a loader's work. The header may be wiped, sections may be misaligned relative to
the file layout the loader used, the import table may be destroyed or may point at resolved addresses
rather than names, and the relocations have already been applied. An image that "dumped fine" can be
unloadable.

*Check:* decide what the dump is for. Reading code out of it needs no repair; *running* it needs each
section mapped back to a file offset, the header restored, and the imports rebuilt.

**P13. Expecting a patched signed binary to stay "signed".**

Any edit outside the certificate blob invalidates the signature that covers the rest of the file. This
is not a security feature to defeat; it is arithmetic. Systems that verify the signature will refuse
the build, and the refusal will be reported as a policy problem rather than as the consequence of the
edit.

*Check:* record the signature state before and after, and decide early whether the deliverable needs to
be signed at all.

**P14. Hex-editing a managed assembly and expecting a behaviour change.**

In a managed assembly the logic is CIL and metadata, and the metadata tables describe where every
method body starts and how long it is. Editing bytes in the body without updating the tables produces
an assembly that loads and does something — often not what was intended — or one that fails to load
with a metadata error that points nowhere near the edit.

*Check:* classify the artifact first. If it has a CLR data directory, use managed tooling.

**P15. Treating a strong name as anti-tamper.**

Strong naming gives an assembly a unique identity. It is not a security boundary, and on modern .NET
the runtime does not validate the signature at load time. Work planned around "the strong name will
have to be defeated" is work planned against a mechanism that is not there.

*Check:* read what the runtime actually validates for this assembly's target framework, rather than
inferring protection from the presence of a signature.

**P16. Reading the timestamp field as a build time.**

Deterministic-build pipelines store a hash in the PE timestamp field. The date it decodes to can be
years in the future or in the past, and treating it as a build time makes the analysis wrong about
order and provenance.

*Check:* when a timestamp is implausible, treat it as a reproducibility hash rather than as a date, and
look for other ordering evidence.

**P17. Mixing 32-bit and 64-bit offsets.**

Optional-header field offsets differ between PE32 and PE32+, and the data directories sit at a
different offset. Reading a 64-bit image with the 32-bit layout — or the reverse — produces values
that are plausible numbers and completely wrong ones.

*Check:* branch on the optional-header magic, and assert the expected bitness before computing
anything from a raw offset.

**P18. Finding an expected string and believing the logic is nearby.**

In a protected or obfuscated target, strings are usually encrypted at rest and decrypted at the point
of use, sometimes into a stack buffer. A string you found in the file may exist nowhere in memory, and
a reference to it may be built by arithmetic rather than by an address.

*Check:* search for the string at run time rather than only in the file, and do not treat a missing
file-level string as evidence that the feature does not exist.

**P19. Concluding from a single observation.**

One run showing a behaviour, one patch producing a change, one crash — none of these is a comparison.
Without a control, a coincidence is indistinguishable from a cause, and the conclusion will be
attributed to the wrong variable.

*Check:* the unmodified original under identical conditions is the control. If two things changed
between the control and the test, the result teaches nothing about either.

**P20. Losing what was already proven.**

A long session accumulates findings — which paths were ruled out, which hypotheses were refuted, which
address corresponds to what. Held only in the conversation, they decay, and the same ground is
re-walked, sometimes with a different conclusion.

*Check:* keep a live record with sections for proven facts, refuted hypotheses, open questions and the
next action, and update it as you go rather than at the end.

**P21. Analysing on the machine you care about.**

Running an unknown binary on the machine that holds your tooling, notes and credentials makes the
experiment and the environment the same object. A target that modifies its own environment also
modifies your notes about it.

*Check:* isolated host, snapshot before the first execution, and a recorded hash of the sample copy.

**P22. Trusting decompiler output.**

Decompilation is a reconstruction. Data misidentified as code, a function boundary drawn where a tail
call happens to sit, an indirect jump that ends the listing — all of these produce output that is
readable, confident and wrong.

*Check:* confirm a surprising decompiled claim against the actual bytes, and treat a decompiler's
structure as a hypothesis.

**P23. Reporting a runtime result as a finished artifact.**

A live hook in a debugger session and a patched file that works elsewhere are different deliverables,
and the first is much easier to obtain. Presenting it in the language of the second ends the
investigation while the requester believes they have the second.

*Check:* say which form exists, and label the privileged or session-bound result as a fallback rather
than as the deliverable. The definition of done in the entry point has six items; a running process is
not one of them.

**P24. Patching a routine that everything calls.**

A helper with many callers is not a feature gate. Changing it to satisfy one path breaks every other
path, and because it is shared, the damage appears far from the patch.

*Check:* count the callers before editing a shared routine, and prefer a site specific to the behaviour.

**P25. Publishing the target along with the lesson.**

Analysis notes carry the product name, a version string, a licence value, a machine identifier and the
analyst's own profile path, because that is what was on screen while the notes were written. Published
once, it cannot be withdrawn from a history.

*Check:* scan before committing, and be as careful about over-redacting as about under-redacting:
removing tool names and format names destroys the reusable part and removes none of the identity.

**P26. The error disappeared and the symptom did not.**

The log line is gone, the dialog that used to appear is gone, and the report says fixed. The
requester then shows the same problem still on screen. The internal signal and the user-visible
outcome are different claims: suppressing one error path proves that path ran, not that the symptom
had only one producer.

*Check:* define the result as the observable the requester described, reproduce it before the change
so the "after" has something to compare against, and treat a quiet log as absence of evidence rather
than evidence of success.

**P27. "I did not observe it" treated as "it is not there".**

A breakpoint that never fires, an ETW provider that logs nothing, a screenshot loop that never
catches the dialog. Sampling is not observation: a transient state can fall entirely between samples,
a provider can be filtering the very event you want, and a breakpoint on a page that is already warm
misses the access. The captures are real and consistently empty, which reads as corroboration when it
is one blind spot repeated.

*Check:* name what the instrument can and cannot see before drawing a negative conclusion, and ask the
same question with an instrument of a different kind -- a hardware breakpoint instead of a software
one, a file-level search instead of a runtime one, a second provider.

**P28. Waiting for something only a person can advance.**

An automation loop polls for a state that will never arrive on its own: an installer's UAC prompt, a
licence dialog waiting for input, a captcha, a "click to continue" in a trial build. Polling looks
productive -- timestamps advance, the screen is unchanged -- and can run for a long time without the
possibility of progress.

*Check:* before waiting, say what would cause the state to change. If the answer is "a person", drive
the prompt programmatically or hand it back. Bound every wait by change, not by elapsed time.

**P29. "The search returned nothing" treated as "the bytes are not there".**

A scan for a known-present string returns zero hits and the route is written off. Usually the needle
was encoded differently from the haystack: UTF-16LE inside a resource or a wide-char table, a string
split across fragments, a compressed resource section, or text that exists only after decryption at
run time.

*Check:* search more than one encoding before concluding absence (`utf-8` and `utf-16-le` cover most
storage), search the shortest distinctive fragment, look inside containers before declaring the data
missing, and state the negative result with its scope -- "no UTF-8 or UTF-16LE literal in this file"
is a finding; "the string does not exist" is a guess.

**P30. Your own analysis script's defect, recorded as a target finding.**

A purpose-written parser prints a plausible table, count or verdict, and it is wrong. It ran clean and
fast, so it was trusted. Common shapes: an operator-precedence mistake that silently widens a mask, a
local helper whose name shadows a stdlib module inside a third-party package, a "precision" number
computed against an incomplete reference, an offset table built with the wrong RVA-to-file mapping.

*Check:* sanity-check the shape before the content -- a distribution that is implausible for the
format is a bug signal. Cross-check against an independently produced artifact, and exercise any
fallback path against a case whose answer you already know.

**P31. A verification that could not have failed.**

A check "passes" while having tested nothing, because the observable is identical whether or not the
change took effect. The patch removes a dialog that also does not appear in the state you tested in,
or the field you edited is not the field the UI reads.

*Check:* ask, before running it, **what would this look like if the change were absent?** If the
answer is the same, the measurement is void: record it as *not applicable under this condition*, never
as *passed*.

**P32. One observer's failure silently disarming the others.**

Several instruments are installed -- hooks in different modules, a debugger plus a logger, two ETW
sessions -- and one of them faults. On Windows the failure is often swallowed: a vectored exception
handler consumes the fault, a hook chain returns early, a thread dies while the process keeps running.
Everything installed after the failure stops reporting, and the absence is read as "nothing happened
there".

*Check:* after installing N observers, prove each one still fires on a known event. Install them one
at a time when the first fault is unexplained, and treat a sudden drop to zero events as a broken
instrument until proven otherwise.

**P33. Two tools disagree about the same artifact, and the disagreement is your parser.**

A disassembler, a PE viewer and a debugger report different entry points, different imports or
different section sizes. The reflex is to distrust the target. In practice the usual cause is a
difference in what each tool means: RVA versus file offset, virtual versus raw size, the section that
*contains* an address versus the section that *starts* at it, or a cached parse of an older copy of
the file.

*Check:* convert both readings into the same coordinate system (RVA, file offset, module base) before
comparing, and verify one value by hand from the headers. A disagreement you cannot restate in one
coordinate system is not yet a finding.

**P34. The shell mangled the command before the target ever saw it.**

A path with spaces, a quote inside an argument, a `--flag=value` that a wrapper re-splits: the tool
receives something other than what was typed and reports a usage error, a missing file, or -- worse --
succeeds against a different target. PowerShell adds its own layer (argument re-quoting, `--%`, and
`Start-Process -ArgumentList` joining a string differently from an array), and `cmd /c` adds another.

*Check:* when an argument-heavy command fails in a way that does not match its own parser, reproduce
it with the argument written to a file or passed as an array, and print the argv the child actually
received before changing the command.

**P35. A decrypted buffer that parses, treated as the buffer the process used.**

A buffer taken from memory is not a file that was read from disk. Loaders patch headers in place:
the magic and the version field can read as zero after the loader has consumed them, and the length
is not stored anywhere the file itself would carry it. A dump taken from the mapped view's size, the
allocation's size, or a constant therefore has a correct-looking header and a truncated or padded
tail, and the tool that consumes it reports a table read past its end, a count that disagrees with a
neighbouring table, or a parse that succeeds with nonsense after the truncation point.

*Check:* compute the length from the buffer's own structure — for a metadata-style header, the last
`(offset, count)` pair with a non-zero count bounds it — and cross-check the result against one
independent field (the largest `offset + count`, or a string table's declared end). Record the
header fields before and after restoring the ones the loader cleared. A dump that parses is a dump
that parsed; only the record of what it was taken from and what was restored makes it the buffer
the process used.

**P36. The version the file declares, believed over the structure that parses.**

A container, a metadata file or a code-object stream carries a version field, and a tool that reads
it selects a layout. After a custom build, a spliced layout or a hand-modified header, the field and
the layout can disagree — a version-31 header over a version-29 struct, one extra 32-bit field
shifting every following pointer by four bytes. The tool then reports a successful parse whose
records point four bytes off, which surfaces as method bodies that belong to other methods, names
attached to the wrong metadata, or a decompiler that produces something almost readable.

*Check:* when a version-sensitive parse produces records that are *plausible but misaligned*, parse
the same bytes under the neighbouring layout and compare which one yields pointers that land inside
the section they claim and counts that match their tables. A version field is a claim by the file;
the structure that produces consistent cross-references is the one that is executing, and the
disagreement itself is the finding to record.

**P37. The 32-bit view searched as though it were the only view.**

A 32-bit target on a 64-bit host does not read the paths its own code names. WOW64 redirects
`HKLM\SOFTWARE\Vendor` to `HKLM\SOFTWARE\Wow6432Node\Vendor` and `System32\` to `SysWOW64`, and both
redirections are silent: every call succeeds, every path exists, and the default tools show the
native view. A search of the native path therefore returns nothing, and the conclusion drawn from it
— "the target keeps no local configuration, so the decision must be remote" — is wrong in a way that
redirects the entire investigation to a layer that may not own the decision at all. A write that
"succeeded" can likewise land in a per-user virtual store when the process is unmanifested and not
elevated, so the setting is not in the key the code names either.

*Check:* establish the process bitness from the process, not from the image header
(`IsWow64Process2`), then search both the native key and its `Wow6432Node` twin, and both the
`System32` and `SysWOW64` copies of the file. Record which view was searched next to the negative
result. "Not found" is a statement about one view; only both views together make it a statement
about the machine.

**P38. An undefined result recorded as a defined one, on the machine that happened to be under the desk.**

A value the instruction manual calls undefined — the destination of a zero-input `bsf`, the overflow
flag after a variable shift, the flags after a multiply — is whatever the part in front of you left
there. Measure it on one machine and it looks like a rule; write the rule into a specification or a
patch and it becomes a requirement the other vendor's part does not meet. The same shape covers a
vendor-string dispatch and a spin loop tuned to one part's `pause`: the code worked, on the machine
that produced the note, and nothing in the note says which machine that was.

*Check:* every timing, flag and fault result is recorded with the vendor string and the
family/model/stepping — `scripts/hwprobe.py` prints all three. A sentence that states a value where
the manual says undefined is rewritten as undefined before the artifact or the specification leaves
the analysis. When the same OS build behaves differently on two hosts, compare the two CPUs before
the two builds.
