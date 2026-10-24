# Tool Verification

**This directory is not part of the installed skill.** It is the evidence record for measurement
passes: what was actually run, on what, against which independent method, and what the target could
not exercise. It exists so the coverage claims in the skill can be checked against runs instead of
being trusted.

**When to read it:** when a claim's strength decides whether you rely on it, or when you are
extending the skill and want to know whether a route has ever been exercised.

## What is in here

| File | What it holds |
|---|---|
| `FINDINGS.md` | defects that this repository's own tools, gates and fixtures found in each other — each with its root cause and the check that now catches it |
| `TOOL-VERDICTS.md` | per-tool verdicts: present or absent on the development host, what was verified about it from a primary source, and what remains documentation-only |
| `REPO-DECISIONS.md` | the design decisions behind the layout, the strength vocabulary, and the gates, with the reason each was chosen |
| `EXTENSION-*.md` | one file per research pass: what the pass covered, what it verified externally, and what it deliberately did not assert |

## How to read a record here

Three things make a row usable, and a row missing any of them should be treated as a note rather than
as evidence:

1. **The command.** Not "the reader was tested" — the exact invocation, so anyone can re-run it.
2. **The output that matters.** The decisive line, not a log dump.
3. **The independent method.** A second way of arriving at the same answer. A parser agreeing with
   itself is not a check; a parser agreeing with the value the file declares, or with an independent
   tool, is.

## The rules this directory obeys

- **A claim carries its grade.** `observed` (a command and its output exist), `inferred` (reasoned
  from an observation), `unverified` (assumed, or reported elsewhere and never reproduced here).
- **A limit cites the measurement that set it.** A limit without a constraint behind it is a
  preference.
- **Missing coverage is `unknown`, never absence.** "The tool was not found" and "the tool does not
  exist" are different statements; the first names the search.
- **A measurement that disagrees with a recorded conclusion re-opens it.** The conclusion is not
  quietly edited; the change is described.
- **Nothing here names a target.** Binaries used for measurement are either built by this repository
  or are platform images that exist on any Windows installation; no third-party sample is required to
  reproduce a row, and none is committed.

## The relationship to `tests/`

They are different artifacts and neither substitutes for the other.

- `tests/` asserts what the **scripts** do. It runs on a bare checkout, offline, in seconds, and it is
  what CI gates on.
- `docs/tool-verification/` records what a **route** did against a real artifact, including the routes
  that cannot run in CI because they need a debugger, a driver, a second machine or hardware support.

A green test suite means the parsers and planners behave as documented. It says nothing about whether
a hardware route works on your machine, which is why `scripts/hwprobe.py` exists and why the hardware
rows in `references/evidence-summary.md` are graded `inferred` or `unverified` with what is missing.
