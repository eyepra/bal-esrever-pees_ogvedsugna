<!--
Fill this in. Three sections are read by a reviewer and one is not yours to fill.

An unchecked box is not evidence of absence: a pull-request template with a blank effect-surface
checklist has not been shown to be documentation-only, it has been shown to be unfinished
(CONTRIBUTING.md, section Review). The readiness declaration is left for a human owner; an agent
leaves it blank rather than writing a claim it cannot make.
-->

## What this changes

One paragraph. What changes, and what a reader can do afterwards that they could not before. If the
change is documentation only, say so here and again in the effect surface.

## Evidence

Every command below was run in this checkout. Paste the output that decides the question; a summary
of confidence is not a result, and `should pass` is not a run.

```
python check_repo.py
python check_refs.py
python check_budget.py
python check_routing.py
python check_commands.py
python -m pytest -q
mypy *.py skills/exe-reverse/scripts/*.py
flake8 *.py skills/exe-reverse/scripts/*.py
```

Output that matters:

```
<paste the decisive lines, and say what they decide>
```

Claims added or changed:

| Claim | Grade | What it rests on (command + result) |
|---|---|---|
| | observed / inferred / unverified | |

- [ ] No claim is graded above the weakest step in its chain.
- [ ] Every `observed` has the command and the output beside it.
- [ ] Every negative result names the range, the pattern and what was searched. A search that
      returned nothing is evidence about the search.
- [ ] Every limit cites the measurement or the constraint that set it, rather than a preference.

## Effect surface

Check each line that applies. `Documentation only` is a claim, so make it explicitly rather than
leaving the list blank.

- [ ] `SKILL.md` — the budget gate output is attached above; it is loaded in full on activation.
- [ ] `references/` — a new or renamed file is registered in `references/routing.md`, reachable from
      `SKILL.md` or the README, and carries a navigable head if it passes 100 lines.
- [ ] `references/pitfalls.md` — a new entry takes the next number and keeps the same shape.
- [ ] `scripts/` — a new script is in the routing script table, answers `--help` on a bare
      interpreter, and its argument table matches every command the docs tell a reader to run.
- [ ] `tests/` — a new script is added to `conftest.SCRIPT_FILES` or declared uncovered with a
      reason in `tests/cli/test_cli_coverage.py`; a fixed defect has a test that fails without it.
- [ ] `evidence/` and `docs/tool-verification/` — a capability claim moved in both, and the
      measurement record quotes the command it rests on.
- [ ] `README.md` and `README.zh-CN.md` — the two stay in step.
- [ ] `docs/tool-verification/FINDINGS.md` — a defect found by the repository's own tools is
      recorded with its symptom, root cause, how it surfaced, and the check that now catches it.
- [ ] Documentation only — no behaviour changed, and the gates above still pass.

## Readiness declaration (human owner only)

An agent does not fill this section in. Leave it blank; the reviewer completes it.

- [ ] The change belongs in this repository rather than in a fork or a downstream project.
- [ ] The boundary of what was not exercised is stated, not implied: every route that needs a
      debugger, a driver, a kernel component, a hypervisor, test signing or a second machine is
      named as not run here.
- [ ] The serialized evidence is committed, and nothing in it carries target identity or a
      machine-specific path.
- [ ] The commit is ready to be fast-forwarded onto `main`.
