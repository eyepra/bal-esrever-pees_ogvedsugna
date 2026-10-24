# Findings

Defects that this repository's own tools, gates and fixtures found **in each other**, during the pass
that built it. Each entry states the symptom, the root cause, how it surfaced, and the check that now
catches it.

These are recorded because the interesting part is not the fix. It is that every one of these produced
output that looked correct: a table of plausible flag names, a resource count that was merely large, a
length guard that never fired. That is the failure shape this whole repository is organised against.

## Parser defects

**F1. The DLL-characteristics table was shifted by six bits, and produced a confident wrong answer.**

*Symptom:* parsing a stock system binary reported `no_seh, no_bind, wdm_driver, 32bit_dll`. Those
flags on a modern executable are implausible — a user-mode program with no exception handling, marked
as a kernel driver and as 32-bit, on a 64-bit host.

*Root cause:* the constant table was written from recall rather than from the specification, and every
entry was displaced: what the code called `no_seh` was the high-entropy-VA bit, and so on through the
whole table. The output was well-formed, self-consistent, and wrong.

*How it surfaced:* by parsing a **real** image whose expected flags are known, rather than by testing
against the parser's own fixtures. A fixture built from the same wrong table would have agreed with it.

*Fix and check:* the values were taken from the published format specification and the table now
records where it came from. The regression is a test asserting the exact flag **names** for a real
binary's header, not merely that a list is non-empty.

**F2. The section-alignment field was treated as a set of independent bits.**

*Symptom:* a code section reported two alignment flags at once.

*Root cause:* the alignment of a section is bits [23:20] of the characteristics field — an **index**,
not a set of bits — and the specification states the values are valid only for object files. Testing
them one bit at a time turns the execute and read bits into two imaginary alignment flags.

*How it surfaced:* the same real-image run, on a section whose characteristics value is a plain
execute|read pair.

*Fix and check:* alignment is decoded with a mask and the table carries the note about its scope. A
unit test asserts that a section with execute|read reports exactly those two flags and no alignment.

**F3. Resource counts are 16-bit fields read as 32-bit, which inflated one resource into 478.**

*Symptom:* a fixture with exactly one resource entry reported 478 entries.

*Root cause:* the resource directory's two count fields are 16 bits each. Reading either as a 32-bit
value swallows the first two bytes of the following entry and the walk then chases table bytes as if
they were entries.

*How it surfaced:* only after the fixture generator was written. Real system images hid it — their
counts and neighbouring bytes happen to combine into values that do not explode — while a fixture with
exactly one entry could not.

*Fix and check:* both counts are read as 16-bit. The fixture declares its expected entry count and a
test asserts the walk returns exactly that.

## Patcher defects

**F4. The ambiguity guard was defeated by its own default.**

*Symptom:* a pattern matching dozens of sites was silently patched at the first one.

*Root cause:* the command-line path always wrote an explicit hit index into the request, and its
default value was `0`. The guard exists to refuse a multi-site match unless a site is *chosen*, and a
default of zero counted as a choice.

*How it surfaced:* by testing the guard deliberately with a pattern that is obviously common (an
indirect call sequence) instead of with a pattern known to be unique.

*Fix and check:* the index is carried only when it was actually supplied, and the refusal now lists the
sites it found. A test calls the guard with the common pattern and asserts the refusal.

**F5. The equal-length check compared a value with itself, so it never fired.**

*Symptom:* the length guard existed, was documented, and could not fail.

*Root cause:* the "original" bytes were sliced to the length of the replacement, so the two lengths
were equal by construction. Worse, the script cannot in general know the length of a site without
disassembling it — which means the honest answer is not "equal" but "not established".

*How it surfaced:* by trying to make the guard fire. A guard that cannot fail is not a guard.

*Fix and check:* length is only judged when a reference exists (the expected bytes, or an explicit
declared length), and the three states — equal, changed, unproven — are printed distinctly. A test
asserts that a request with no reference prints the unproven marker, and that a declared length that
disagrees with the replacement is refused. The first version also printed the unproven case as a
length change, because a missing value is falsy; that is now a three-state marker.

## Fixture defects

**F6. `SizeOfHeaders` was computed without the section table.**

*Symptom:* every section's payload sat at a different file offset than the one the header declared.

*Root cause:* the header size calculation covered the DOS header, the PE signature, the file header
and the optional header, and omitted the section table — 40 bytes per section. The declared value was
therefore smaller than the real header block, and everything after it was misplaced.

*How it surfaced:* an assertion in the generator comparing the planted byte sequence at its declared
file offset with the bytes actually written there. Without that assertion the file would have been
written, would have parsed, and would have been wrong.

*Fix and check:* the section table is included in the calculation, with an assertion that the aligned
size is at least the computed size. The generator asserts every structural claim it makes.

**F7. Two structures were placed at estimated offsets, and overlapped.**

*Symptom:* the debug directory was written into the region the import table occupied.

*Root cause:* the first version of the generator gave the import table, the debug directory and the TLS
directory each a hand-picked offset. Two of those choices collided.

*How it surfaced:* while computing where the import table actually ended, which is not something one
does while *writing* estimated offsets.

*Fix and check:* the payload is laid out with a single cursor that allocates each structure in turn and
refuses to overflow the buffer. An overlap is now impossible by construction rather than by care.

**F8. The debug-directory structure had the wrong field count, and a file offset was filled with an RVA.**

*Symptom:* the generator failed to build, then — once it built — the record could not be located.

*Root cause:* the structure has eight fields, not seven, and its last field is a **file offset** while
the field before it is an RVA. Two different address spaces inside one 28-byte structure.

*Fix and check:* both fields are written correctly and the reader resolves the PDB path from the file
offset, which is a round-trip the test asserts.

## Probe defects

**F9. A pseudo-handle was passed as a 32-bit integer, and the probe looked like a policy denial.**

*Symptom:* the privilege probe reported that opening the process token failed with error 6
(`ERROR_INVALID_HANDLE`) on an elevated session.

*Root cause:* the pseudo-handle for the current process is `(HANDLE)-1`. Without an explicit pointer
return type the binding layer narrows it, the call receives the wrong value, and the failure looks
exactly like a machine where the operation is not permitted.

*How it surfaced:* by disbelieving the result. "Elevated session cannot query its own token" is not a
plausible measurement.

*Fix and check:* the call signature declares its types, and a test asserts the probe reports elevation
on this host rather than an error.

**F10. Long values were truncated by the printer.**

*Symptom:* a raw capability value printed as `0x000`, losing its significant digits.

*Root cause:* a fixed column width applied to a value string. The data was correct; the report was not.

*Fix and check:* long values wrap onto continuation lines instead of being cut. A test asserts a long
value survives into the output intact.

## Gate, harness and lint defects

**F11. The hard index-row limit was computed and then unable to fail anything.**

*Symptom:* none. The gate reported `ok` on an index row of 450 characters, past the 400-character
limit it declares, and CI stayed green.

*Root cause:* the finding was appended as `('warn' if hard else 'warn', ...)` -- both branches the
same expression. `INDEX_ROW_HARD` was defined, the comparison was performed, and the level was then
thrown away. The message text even said "that is a paragraph, not an index entry", which is what made
it read as enforcement.

*How it surfaced:* by injecting an over-long row into a scratch copy and requiring the gate to exit
non-zero. It exited 0. A gate that has only ever been seen passing is not evidence that it can see
anything, and this class of defect is invisible to every test that runs the gate on a conforming tree.

*Fix and check:* the escalated level is `fail`. `tests/unit/test_budget_measurement.py` asserts that a
row past `INDEX_ROW_HARD` produces `fail` and a row past `INDEX_ROW_SOFT` produces `warn`, so the two
thresholds cannot silently collapse into each other again.

**F12. The corpus measurement counted a bytecode cache, so its own number changed when a reader ran
the suite.**

*Symptom:* the budget gate reported `36 references + 27 scripts = 63 files` on a tree that ships 16
scripts. The count moved between runs on the same commit.

*Root cause:* the script half of the corpus was `glob(scripts/**/*)` filtered by `isfile`, which
includes `scripts/__pycache__/*.pyc`. Reading a directory is a measurement of the repository; reading
a directory that the reader has been scribbling in is a measurement of the reader.

*How it surfaced:* comparing the number the gate printed against the number of files the routing gate
said it covers. Two gates measuring the same tree disagreed, and that disagreement was the finding.

*Fix and check:* paths under `__pycache__` are excluded from the corpus. The count now matches the
routing inventory, and re-running the suite no longer changes it.

**F13. A test asserted a capability it never checked, so a host without it failed instead of skipping.**

*Symptom:* `test_prober_can_dump_raw_cpuid_registers` failed on a non-x64 host with "a raw dump was
requested but nothing was reported", while the probe's own report said CPUID was unavailable there.

*Root cause:* the test asserted that the dump was non-empty without asking whether the host could
produce one. The script was right and the test encoded a Windows assumption. It also contradicted the
suite's own rule that a missing prerequisite is a skip with a printed reason.

*Fix and check:* the test reads the probe's `cpu` row first and skips with that row's note when the
state is not `available`; the non-empty assertion still runs where CPUID is reachable. The skip text
names the reason, so a green run on Linux is not mistaken for a green run on Windows.

**F14. A configuration comment pointed at a document that does not exist.**

*Symptom:* `pytest.ini` sent a reader to `docs/tool-verification/EXTENSION-test-harness.md` for the
suite's coverage policy. No such file has ever been in this repository.

*Root cause:* the file was inherited from the Android-side repository along with the harness, and the
structural gates check the *skill* tree's references, not a comment in an ini file. A stale path in a
comment fails nothing, which is exactly why it survives.

*Fix and check:* the comment points at `tests/README.md`, which carries a "what it deliberately does
not do" section. Recorded here rather than silently repaired because the class -- a reference in a
non-markdown file that no gate walks -- is still open.

**F15. The type checker rejected a sentinel assignment the moment its optional dependency was installed.**

*Symptom:* `mypy *.py skills/exe-reverse/scripts/*.py` reported `check_repo.py:34: Incompatible types
in assignment (expression has type "None", variable has type Module)` on a machine with PyYAML, and
no error at all on a machine without it.

*Root cause:* `yaml = None` in the `except ImportError` branch is ill-typed only where the import
succeeded, which is the environment the lint job runs in. The repository had no lint job at the time,
so the two environments never had to agree.

*Fix and check:* the assignment carries `# type: ignore[assignment]`, with `warn_unused_ignores` off
(already the configuration) so the bare-machine environment stays clean too. `mypy.ini` and `.flake8`
are now enforced by the `lint` job in CI.

## What this list is for

Fifteen defects, all in code written or inherited during this pass, all of which produced output that looked right. The
pattern is consistent enough to state as a rule:

**A check that cannot fail is not a check, and a table written from recall is a table that is wrong in
one place you will not notice.** Both are why this repository prefers a value taken from a
specification with its source named, an assertion over an estimate, and a fixture that can disagree
with the tool reading it.
