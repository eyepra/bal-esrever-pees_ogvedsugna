# Extending beyond a file

**What this answers:** how to change this repository's own machinery, rather than add another
document to it: a new class of artifact, a reference family, the frontmatter or the metadata
contract, the budget that governs the always-loaded file, a new gate and its CI wiring, and the
procedure for demoting a claim when a measurement disagrees with it.

**When to load this:** when the change you want is not covered by the extension points in
[CONTRIBUTING.md](../CONTRIBUTING.md), or when it changes what a green build means.

Everything here rests on one distinction. Part of this repository's contract is enforced by scripts
at the root; the rest can only be judged by a reader. A change that moves a rule from the second half
into the first is a real improvement, and a change that looks machine-checked but is not is how a
guarantee rots. Where a class is maintained by a reader, this document says so.

## Ordinary, or a discussion first

| Change | Status | Why |
|---|---|---|
| A reference, a script, a pitfall entry, a case precedent, a measurement record, a capability row | Ordinary. Follow `CONTRIBUTING.md` | Each has a registration point and a gate that notices if the registration is missing |
| A new gate script, additive and read-only | Ordinary, if it cannot fail a change that used to pass | A gate that only adds a signal is cheap to review |
| Wiring an existing gate into CI | Ordinary | The sequence is in `.github/workflows/ci.yml`, and a missing gate is a visible gap |
| Recording a downgrade of a claim | Ordinary, and expected | The repository states that a measurement which disagrees re-opens the conclusion |
| A reference family (a subdirectory with its own index) | Ordinary, with one condition stated below | Its files are not resolved by any gate, so its index is the only entry point that exists |
| A whole new artifact class (a new tree, or a new format the tooling reads) | Discussion first | It changes what a reader must check by hand, and possibly what an installed skill ships |
| Adding a key to the `metadata` frontmatter block | Ordinary | No gate resolves those paths, so nothing depends on the key existing |
| Changing what an existing `metadata` key means, or the strength-label vocabulary | Discussion first | Every document in the corpus grades against that vocabulary |
| Changing a budget threshold, or the method that measures it | Discussion first, with a measurement | A threshold moved without a measurement is a preference with a number on it |
| Adding a new failure mode for contributors | Discussion first | A gate that blocks a reasonable change is bypassed, and then it protects nothing |

## What the tooling actually reads

Five facts about the layout decide how a new artifact is discovered, and none of them is stated in
the file you are adding.

1. `check_repo.py` discovers every `skills/*/SKILL.md` up to three levels deep, and a shallower
   `SKILL.md` shadows anything nested below it, which is the installer's own rule. Adding a second
   skill needs no change to the gates.
2. `check_repo.py` and `check_routing.py` look at `references/*.md` and `scripts/*.py|.js`
   **non-recursively**. A file in a subdirectory of either is invisible to the routing comparison.
3. `check_budget.py` counts the corpus recursively: `references/**/*.md`, plus every file under
   `scripts/`. The corpus note fires at 110 files or 26,000 lines, so a family is visible to the
   budget before it is visible to routing.
4. The path resolver patterns match `references/<name>.md` and `scripts/<name>.py` with no separator
   anywhere in the name, so a nested path such as `references/coverage/route-inventory.md` is not
   resolved by any gate. A dangling nested pointer fails nothing.
5. `check_commands.py` scans `README.md` and every `.md` under `skills/` and `docs/`, skipping
   directories named `fixtures`. A command in a nested file is still validated; a command in a file
   that no walker reaches is not.

The consequence is the rule for everything below: a new class needs one file that an existing gate
already walks, and that file must state honestly what is checked and what is not.

## Adding a whole new artifact class

A class is a set of files with a shared shape that a reader is expected to keep consistent: the
evidence companions, the coverage inventory and the case library are three examples of what is
already here.

1. **Decide whether it ships.** Inside `skills/exe-reverse/` is shipped to anyone who installs the
   skill; the repository root is maintenance tooling. `README.md`'s structure block states the split,
   and a class that ships belongs in that block with an explicit `skills/exe-reverse/...` path,
   because the README's path check fails a bare relative path.
2. **Find out whether any gate walks it.** If one does, its completeness is machine-checked and the
   class can rely on that. If none does, the class's own index must say so in a sentence a reader can
   act on, because a machine-checked guarantee that does not exist is the failure this repository
   keeps recording.
3. **Give the class an index that is discovered.** The cheapest reliable form is a top-level
   `references/<class>.md` that opens with the head shape (the title, a goal line, and
   `## When to load this`), registers itself in `routing.md`'s Reference index, and is named in
   `routing.md`'s Sub-indexes table as the class's index, which is how the coverage inventory and the
   case library are already registered.
4. **State the row contract in the index**, not in the individual files: what each entry must carry,
   which document holds the claim it supports, and which grade applies.
5. **Add the class's own test only if it has a mechanical part.** A class of prose files has nothing
   to test, and a test that asserts a file exists is not a guarantee about its content.

Two things to avoid. A class whose only index is named inside another document's prose is not
reachable, because nothing compares prose to a directory listing. And a class that duplicates a
registration duty that routing already owns will drift from it.

## Adding a reference family

A family is a directory of related files with an index, and it is worth the extra structure exactly
when the files are read together and would be misleading in the flat library.

1. Create `skills/exe-reverse/references/<family>/` and write `README.md` as the index: what the
   family is for, when to load it, the register or table of its members, and the template a new
   member follows. Copy the shape of `references/precedents/README.md`, which is both an index and a
   template.
2. Register the family index in `routing.md`, in the Sub-indexes table, as
   `references/<family>/README.md`, saying what the file holds.
3. If the family needs a top-level touchpoint as well (a symptom, a route), add that row to
   `SKILL.md` and to the mirror in `routing.md` in the same pass; the routing gate compares those two
   tables row by row and fails when one side has a row the other lacks.
4. Add each member to the family's own register at the same time you add the file, never later. The
   register is the only reachability that exists for a nested file.
5. Say in the index that the members are not resolved by any gate, so a reviewer knows the index must
   be read against the directory. This is a one-sentence honesty cost that makes the gap visible
   instead of implied.

Members of a family are still covered by the checks that scan every markdown file under `skills/`: a
`python <script>.py` command in one of them is validated against the script's argument table, and a
cross-file section reference is resolved against the target's real headings. `check_refs.py` reads
`README.md` and `skills/` only, so the same content placed under `docs/` is not checked that way.

## Evolving the frontmatter or the metadata contract

**What is enforced.** `check_repo.py` parses the frontmatter with a real YAML parser, because
frontmatter that satisfies a pattern can still be rejected by the parser the installer uses. It then
requires `name` to equal the skill's directory name and to match lowercase alphanumerics joined by
single hyphens, at most 64 characters, and `description` to be between 40 and 1024 characters. A
description whose value contains a colon followed by a space must be quoted; an unquoted one makes
the whole skill invisible to the installer. Where PyYAML is not installed the gate prints a warning
and falls back to a colon test, so the check degrades rather than disappearing.

**What is not enforced.** The `metadata` block. `capability_registry`, `host_probe`,
`evidence_summary` and `strength_labels` are promises about paths and vocabulary, and no gate
resolves any of them. A renamed file whose path still appears there is drift nothing will report, so
a rename has to be carried by hand and reviewed. Treat the block as documentation that happens to live
inside a parsed structure.

**The description is a loading decision, not a summary.** It is the only text an agent sees when
deciding whether this skill applies to its task. Adding a route to it is a budget decision against
the 1024-character ceiling, and the routes that earn their characters are the ones a wrong answer
would otherwise be given for.

**Changing the strength-label vocabulary needs a discussion**, because every reference, every
evidence row and every case grades against `observed | inferred | unverified`. The burden of proof is
that the existing three cannot express a distinction that changes a decision a reader makes. If a new
label is genuinely needed, the change is mechanical in its extent and semantic in its risk: every
document that states a grade has to be revisited in the same pass, and the frontmatter key that names
the vocabulary has to be updated with them.

## Changing the always-loaded budget

`SKILL.md` loads in full whenever the skill activates, so the budget is measured on the whole file,
including its index tables. `check_budget.py` reports:

| Measure | Soft | Hard | Fails the gate? |
|---|---|---|---|
| `SKILL.md` lines | 460 | 560 | at the hard limit |
| `SKILL.md` tokens | 13000 | 16000 | at the hard limit |
| Index-row description length | 250 characters | 400 | never: both branches are warnings |
| Long reference with no navigable head | 100 lines, head checked in the first 40 | not applicable | never: a warning |
| Corpus size | 110 files, 26000 lines | not applicable | never: a note |

The token count comes from `tiktoken`'s `cl100k_base` encoding when it is installed, and otherwise
from `characters / 4.285`. That fallback constant is calibrated against the real measurement rather
than guessed, and it exists for a stated reason: an earlier value made the gate reach **different
verdicts on different machines**, reporting an over-budget file where the tokenizer was absent and a
compliant one where it was present. The gate's answer must not depend on what the runner happens to
have installed, which is also why CI installs the tokenizer so the real path is exercised.

**To change a threshold:** produce the measurement that justifies the new number, keep the two
measurement paths agreeing, and update the numbers and the calibration note in the docstring in the
same change, because the docstring is the only place the calibration is recorded. A threshold that
moves because a document outgrew it is not a change to the budget; it is the budget being abandoned.

**The ordinary answer instead:** move the detail into a reference and leave a pointer. Two things
stay in the always-loaded body, and both are argued in the gate's own comment: the symptom index,
because a symptom-to-file lookup must stay one hop, and the gates with their pass criteria, because
"the idea is understood" does not clear a gate.

**Verify with both modes:** `python check_budget.py` reports the measured values and the notes;
`python check_budget.py --strict` turns every warning into a failure, which is how a warn-only rule
is checked when someone chooses to hold the line.

One known wording defect, reported here rather than copied: the docstrings of `check_routing.py` and
`check_budget.py` describe "the four gates with their pass criteria", while the entry point defines
five (G1 to G5). Comment text is checked by no gate. If you touch either file, correct the wording
instead of reproducing it.

## Adding a new gate script and wiring it into CI

**The shape a gate has here.** A root-level `check_<name>.py`, runnable from the repository root with
no arguments as `check_<name>.py` under the interpreter, printing a human-readable summary and, where a caller needs
to branch on the verdict, a final `RESULT=<token>` line. Exit 0 when the tree satisfies the rule and
non-zero when it does not. `--json` is the convention for machine-readable output, and the one place
it is deliberately absent from the text stream is a JSON payload: a `RESULT=` line appended to JSON
makes the stream unparseable for the caller that asked for JSON, so there the status is a field and
the exit code carries the meaning. `check_repo.py` and `check_refs.py` take no arguments at all;
`check_routing.py` takes only `--json`; `check_budget.py` adds `--strict`; `check_commands.py` adds
`--path`, `--fix-report`, `--include-workbench` and `--quiet`.

**Rules a gate follows here:**

1. **Read-only.** A gate must not modify the tree. The only root tool that writes is
   `build_scripts.py`, and it writes only under `--apply`, after an audit pass that is the default.
2. **Report the boundary of the check.** `check_commands.py` counts the invocations it could not
   verify rather than skipping them silently, because "no finding" from an interface it cannot read
   would be indistinguishable from coverage. A new gate that cannot see part of its surface should
   say so in its own output.
3. **Say when the surface is empty.** A gate that found nothing to check has not passed; it has run
   against nothing. `scan_leaks.py` has a dedicated exit code for exactly this.
4. **Prefer a narrow rule with a stated exemption over a broad rule that is wrong.** The gates here
   carry their exemptions in a table with a reason per entry, because a gate that gets switched off
   protects nothing.
5. **Do not restate another gate's rule without saying why.** Measured duplication exists here: the
   routing gate and the budget gate both check that a reference is reachable. The second copy is
   justified in a comment, because a dead reference is invisible in a way a broken path is not.
6. **Warn, do not fail, when the gate cannot judge.** Hedge detection, restatement and corpus size
   are notes; index-row length and navigability are warnings; only the ceilings fail. `--strict` is
   the opt-in that makes warnings fatal.

**Every gate needs a test.** A gate gets a subprocess contract test under `tests/cli/`: the flags it
accepts, the exit code per verdict, and the `RESULT=` token where it prints one. A mis-typed marker
is a harness failure rather than a warning, because the suite runs with `--strict-markers`.

**Lint and typing are free.** The CI lint job runs `mypy` and `flake8` over `*.py` at the root plus
the skill's scripts, so a new root gate is checked without a configuration change. Both tools read
their configuration from the repository root, and the job deliberately runs on an interpreter with
none of the optional dependencies installed, so a new gate must import them lazily or behind a
fallback with a stated behaviour.

**Wiring it in.** Add the step to the `test` job in `.github/workflows/ci.yml`, in the gate sequence
and before the regression suite. There is deliberately no `paths:` filter on the workflow: a filter
that watches only source files would skip the structural gates on exactly the commits they exist to
catch, which are documentation commits. A gate that can only run where a device, a debugger or a
network peer exists does not belong in CI; record that route in the measurement record instead and
let the test self-skip with a printed reason.

**Document it.** `README.md`'s repository-maintenance list names every root tool with what it
enforces, one line each. A tool that is not in that list is invisible to a contributor who never
opens the root directory.

**What needs a discussion first:** a gate that can fail a change which used to pass, a gate whose
rule is a matter of taste rather than a checkable property, and a gate that duplicates a rule another
gate already owns.

## Recording a downgrade when a measurement disagrees

The stop condition is stated in the entry point: a measurement that disagrees with a conclusion
recorded as settled re-opens the conclusion, and the measurement is not explained away. That is a
rule about behaviour; this is the procedure that makes it a change a repository can hold.

1. **Freeze the measurement first.** The command as it was run, its output, the artifact digest, the
   tool and its version, and the host build. Without those pins the disagreement is an anecdote, and
   it cannot raise or lower anything.
2. **Name the link that was weaker than recorded.** A chain is graded by its weakest link, so the
   question is not "was the conclusion wrong" but "which step was assumed". A tool that reports
   success is evidence about the tool; it was never evidence about the target.
3. **Move every document that states the claim, in one pass.** The coverage row
   (`references/coverage-and-limits.md`: the direction, the strongest defensible grade, what it rests
   on, and the dependency that is not shipped here), the evidence row
   (`references/evidence-summary.md`), and the machine-readable row under `skills/exe-reverse/evidence/`.
   A downgrade that lands in one of the three leaves the other two asserting the stronger grade, and
   the stronger grade is the one a reader will find.
4. **Record the negative result.** `docs/tool-verification/` is where the pass goes, with the command
   and its output, and with the scenarios the target could not exercise named. A route measured and
   failed on a named host is more useful than a route nobody ran.
5. **Add a pitfall entry only if the downgrade has a mechanism.** The catalogue's value is the
   mechanism that made the failure invisible, not the failure. If the earlier claim looked right for
   a reason a reader could hit, that reason is an entry; if the claim was merely optimistic, it is
   not. Cite the entry by number from anywhere else rather than restating it.
6. **Describe the demotion in the change.** The repository's own rule is that a corrected conclusion
   is described rather than quietly edited, and that a record keeps the wrong version beside the
   right one, because the retraction is the transferable part.

**Restate the grade for the whole chain**, not for the corrected step alone. A chain that ends in a
step nobody executed is `inferred` at best, and a chain whose weakest link was just replaced is
entitled to be re-graded only as far as the new weakest link.

**A downgrade is a result, not a failure.** The coverage file commits to this: a negative measurement
raises a row's honesty even while it lowers its grade, and a row with no measurement behind it is
worse than a row with a disappointing one. What a downgrade must not do is delete the earlier claim,
edit a conclusion without saying so, or leave a downstream document stating the grade that was just
withdrawn.

There is a precedent in this repository for the kind of error that forces a downgrade: the budget
gate's token fallback constant was first set to a value that made the gate reach different verdicts
on machines with and without the tokenizer, which is the shape of a claim that looks measured and is
not. Its docstring now records the calibration and the reason, which is what a downgrade should leave
behind.
