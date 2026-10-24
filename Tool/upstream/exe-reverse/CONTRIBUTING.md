# Contributing to exe-reverse

## What this repository is

`exe-reverse` is an Agent Skill for **Windows x86/x64 local-software reverse engineering**: a
`SKILL.md` entry point that loads in full on activation, a reference library loaded on demand, a
`scripts/` directory of runnable tools, and the evidence, coverage and regression layers that grade
what those tools have actually been shown to do. It is a method plus tooling. It ships no service, no
GUI, no target sample and no vendored third-party binary.

One rule governs every other rule here: **a claim carries its strength, and a route that was not run
is not a route that works.** Every factual assertion is graded `observed` (a command exists and its
output exists), `inferred` (reasoned from an observation, but the step itself was not executed), or
`unverified` (assumed, or reported elsewhere and never reproduced here). A claim is only as strong as
the weakest link in its chain, so one unexecuted step downgrades the whole chain. Missing coverage is
reported as `unknown`, never as absence: "I did not find it" is not "it is not there", and the first
statement must name the search it ran.

Read [pitfalls.md](skills/exe-reverse/references/pitfalls.md) before your first change to the skill
proper. Every entry is a failure that produced a working-looking artifact, and it explains why a rule
in the entry point is phrased as an absolute rather than as advice.

## The two halves of the contribution contract

Part of this contract is enforced by scripts at the repository root, and part of it can only be
judged by a person. Keeping the two apart is the point of this document: a green gate proves the
parts a script can see, and says nothing about the rest.

| Half | What it covers | Where it lives |
|---|---|---|
| Machine-checked | paths resolve, the inventory matches the tree, frontmatter parses the way the installer will read it, every script answers `--help`, every documented `python <script>.py` command matches the script's own argument table, section references land on real headings, the always-loaded file stays inside its budget, no machine-specific path or credential in a published script, no strong target identity on the tracked surface | the five gates and the audit tool, listed below |
| Reviewer-judged | whether a claim's grade is honest, whether a route is described from a real run, whether a limit cites the constraint that set it, whether coverage was updated, whether the material leaks target identity in a form a pattern cannot see | the pull-request template's evidence and readiness sections |

## Local setup

The interpreter is the only requirement to run anything here, at the minimum version the skill
declares (3.10 or newer). The skill's scripts import nothing outside the standard library; everything
else is optional and each consumer states what it uses.

| Dependency | Needed for | Notes |
|---|---|---|
| The interpreter, 3.10 or newer | every script and every gate | `skills/exe-reverse/SKILL.md` declares the floor as 3.10+, and `mypy.ini` type-checks against the same 3.10 so the documented floor and the checked floor cannot drift apart |
| `pytest` | the regression suite (`tests/`, declared in `pytest.ini`) | markers `unit`, `cli`, `integration` are declared, and `--strict-markers` is on |
| `PyYAML` | parsing `SKILL.md` frontmatter the way the installer's YAML parser will | `check_repo.py` falls back to a colon test and prints a `WARN` when it is absent |
| `tiktoken` | measuring the always-loaded body against the real tokenizer | without it `check_budget.py` uses a calibrated `characters / 4.285` fallback; CI installs it |
| `flake8`, `mypy` | the lint job's two commands, both configured in the repository root | not needed to run the gates |

```
python -m pip install pytest PyYAML tiktoken
python -m pip install flake8 mypy
```

### Run the skill from a checkout, without installing it

The skill is a directory of files, so a checkout works unmodified. From the repository root:

```
python skills/exe-reverse/scripts/hwprobe.py
python skills/exe-reverse/scripts/peutil.py <pe> --summary
python skills/exe-reverse/scripts/make_fixture_pe.py --out fixture.exe
```

Every script resolves its own siblings, so it does not matter which directory you invoke it from;
`hwprobe.py` is the cheapest first command, and it reports what this host can actually support rather
than what is generally possible. Toolchains that live outside `PATH` (a project-local tools
directory, a versioned SDK folder) are found through `EXEREV_TOOLS` or `EXE_REVERSE_TOOLS`, a
`;`-separated list of directories on Windows.

To have an agent load `SKILL.md` from this checkout, install the skill by name with the `skills` CLI
(`npx skills add <owner>/exe-reverse --skill exe-reverse -y`) or run it once without installing
(`npx skills use <owner>/exe-reverse@exe-reverse`). See the README's Install section; the CLI
symlinks the skill into an agent's skills directory by default.

### Run the gates

Run all of them from the repository root. They are independent, and each one prints its own verdict
line.

```
python check_repo.py         # layout, frontmatter, scripts answer --help, paths resolve, README paths explicit, identity scan
python check_refs.py         # every cross-file section reference reaches a real heading; every P<n> a real entry
python check_routing.py      # the on-demand inventory matches SKILL.md and the tree
python check_budget.py       # the always-loaded body, index-row length, navigability, hedges, corpus size
python check_commands.py     # every documented command matches the script's own argparse table
python -m pytest -q          # the regression suite
```

What each one returned at the revision this document was written against, stated so you can tell a
pre-existing condition from a regression you caused. This tree is under active construction, so
these lines are a snapshot rather than a stable baseline: re-run them, and record the failing lines
before your change so you can show you did not cause them.

| Gate | Observed output | Exit |
|---|---|---|
| `check_routing.py` | `symptom index : SKILL.md 33 rows / routing mirror 33 rows`; `reference table: 33 rows, covering 33 reference files`; `script table : 9 rows, covering 9 scripts`; `== routing: coherent ==`; `RESULT=ok` | 0 |
| `check_refs.py` | `== section references: 29 reachable ==`; `== result: 0 dangling, 0 warning(s) ==` | 0 |
| `check_budget.py` | `ok SKILL.md 296 lines (34 index = 11% of the file, and it is still loaded: ...), ~5552 tokens (tiktoken/cl100k_base; soft 13000)`; `== budget: 0 failure(s), 0 warning(s), 4 note(s) ==` | 0 |
| `check_commands.py` | `commands : 30 checked (30 clean, 0 drift, 0 warning)` against 7 script interfaces; `RESULT=commands_ok` | 0 |
| `check_repo.py` | every referenced path resolves and the README's paths are explicit; the leak step then reports strong findings on the tracked surface and crashes while printing them (`UnicodeEncodeError: 'gbk' codec can't encode character ... in check_leaks()`, because this host's console code page cannot encode the replacement character the scanner's decoded output contains) | 1 |
| `python -m pytest -q` | red while the suite was still being written: `no tests ran in 0.02s` and exit 5 against an empty tree, then `1 failed, 49 passed, 70 errors`, then `2 failed, 211 passed`, then `4 failed, 245 passed` | 1 |
| `build_scripts.py` | `== audit: 7 file(s) checked, 0 finding(s). Nothing was written.` in one run; an edit to the tool's own docstring then left the module unparseable (`SyntaxError: (unicode error) ... truncated \UXXXXXXXX escape`), so it does not run at all | 0, 2 on findings, 1 on usage |
| `scan_leaks.py` | `5 strong, 0 weak, 3 suppressed` in the skill tree, with `RESULT=findings`; the strong hits include shapes the desensitization reference predicts as false positives (a product-shaped name bound to a version, a dotted-quad version string read as an address) | 1 |

Three of those need their cause named rather than their number. An earlier `check_repo.py` run failed
with `MISSING` rows while the reference library was still incomplete, because it resolves every
`references/<name>.md` and `scripts/<name>.py` mention in the entry point, the README and the
references: a row written ahead of its file is a failure, and so is an entry-point pointer to a file
that has not landed. Its current failure is the identity step, and its crash there is a defect in the
gate's own reporting path rather than in the finding, which is genuine. `pytest` is red at this
revision, and its counts moved several times while the suite was being written, which is exactly why
recording the failing lines before your change matters. And the root tools are
parsed by nothing: `check_repo.py` parses and runs only `skills/*/scripts/*.py`, so a syntax error in
a root-level tool passes every gate and surfaces only under `mypy`/`flake8` or when someone runs it.
Run the lint pair.

The tree is under active construction, and the numbers above moved while this document was being
written: the reference library filled in, `tests/` appeared, and the tree became a git checkout,
which is why the leak step now runs instead of reporting that `git ls-files` was unavailable. Treat
every line as an example of the shape to expect and re-run the gate rather than trusting the count.

`build_scripts.py` is not a gate. It is the publish-side audit and sync tool: audit is the default
and writes nothing, `--apply` copies, `--scrub` neutralises absolute-path literals in the copies, and
audit mode exits 2 when it reports findings.

```
python build_scripts.py skills/exe-reverse/scripts out
```

### Run the lint pair

CI runs these on a bare interpreter with only the two tools installed, so a change to either
configuration must keep working with `frida`, `capstone`, `tiktoken` and `PyYAML` absent.

```
python -m mypy *.py skills/exe-reverse/scripts/*.py
python -m flake8 *.py skills/exe-reverse/scripts/*.py
```

## Where things live

```
skills/exe-reverse/SKILL.md            the entry point, loaded in full on activation
skills/exe-reverse/references/         one topic per file, loaded on demand
skills/exe-reverse/references/routing.md   the symptom mirror plus the reference and script indexes
skills/exe-reverse/scripts/            runnable, path-agnostic, no machine-specific defaults
skills/exe-reverse/evidence/           the machine-readable companions to the evidence summary
docs/tool-verification/                the evidence record for measurement passes (not shipped)
tests/                                 the regression suite (not shipped)
check_*.py, build_scripts.py           repository maintenance tools at the root (not shipped)
```

## Extension points

Each subsection below states what the artifact is for, what a script will refuse to accept, and the
recipe for adding one. The mechanical part is what a gate does; the rest is what a reviewer does.

### A reference under `references/`

**Purpose:** one topic, answering the question a reader arrives with, in the order they will ask it.
Length follows content; 100 to 300 lines is typical, and loadable is better than long.

**Mechanical constraints:**

1. `check_routing.py` fails when a top-level `references/*.md` file is not named in `routing.md`'s
   `## Reference index` table. The table's text is compared against the directory listing, so the
   basename must appear in a row.
2. `check_repo.py` fails the other direction: every `references/<name>.md` mention in `SKILL.md`,
   `README.md` or a reference must resolve to a file that exists. Registering a row before the file
   exists breaks the build.
3. `check_repo.py` also fails a file that is named in none of `SKILL.md`, `README.md` or
   `references/routing.md`: an unreachable reference is never loaded.
4. `check_budget.py` warns when a file of 100 lines or more has neither a table-of-contents heading
   nor a `when to load` / `what this answers` / `load this when` / `when this applies` line inside
   its first 40 lines. The format is only a warning unless someone runs the gate with `--strict`.
5. `check_commands.py` reads every `.md` under `skills/`, so a `python <script>.py --flag` line in
   your file must match that script's own argparse table. A flag that does not exist is drift and
   fails the gate.
6. `check_refs.py` resolves a cross-file section reference against the target file's headings and
   bold stand-alone lines, and resolves a bare `(P18)` or a `pitfalls.md` `P18` against the real
   entry numbers. A dangling one fails.
7. A nested path such as `references/coverage/route-inventory.md` is not resolved by any gate: the
   resolver patterns match `references/<name>.md` with no separator. Sub-indexed families are covered
   in [docs/extending.md](docs/extending.md).

**Recipe:**

1. Write `references/<topic>.md`: a `# Title`, one line stating the goal, then `## When to load
   this`. Open every factual assertion with its grade. State what the route cannot do in the same
   voice as what it can, and prefer a table where the content is a decision.
2. Add one row to the `## Reference index` table in `routing.md`, in the form
   `` | `references/<topic>.md` | load it when ... | ``. The row says when to load the file; the file
   says what is in it.
3. If the new file answers a symptom that has no row yet, add that row to **both** the symptom index
   in `SKILL.md` and the mirror in `routing.md`. `check_routing.py` compares those two tables row by
   row on their first cell and fails when either side has a row the other lacks.
4. Run the gates. `python check_routing.py` proves the registration, `python check_repo.py` proves
   the paths, `python check_commands.py` proves any command you wrote.

### A script under `scripts/`

**Purpose:** a runnable tool. Parameterised, path-agnostic, and honest about what it could not do.

**Mechanical constraints:**

1. `check_repo.py` parses every `scripts/*.py` with `ast.parse` and then runs
   `python -B <script> --help` from the repository root with UTF-8 decoding. A traceback fails the
   gate; a non-zero exit is accepted as long as the script printed something, because "print usage
   and exit 2" is a legitimate convention.
2. The script is named in `routing.md`'s `## Script index`, and `check_routing.py` compares that
   table against the `scripts/` listing for `.py` and `.js` files.
3. `check_repo.py` fails a script that is documented nowhere: the search covers `SKILL.md`,
   `README.md`, `routing.md`, every reference, `references/coverage/` and `references/precedents/`.
   The routing row normally satisfies it.
4. If the script is user-facing, the README's narrative is where a reader meets it. The README must
   name skill paths explicitly, as `skills/exe-reverse/scripts/<name>.py`; a bare `scripts/<name>.py`
   in the README is a failure, and so is an explicit path that does not exist.
5. At least one test must run the script. `pytest` collects from `tests/` with `--strict-markers`, so
   the test carries a declared marker (`cli` for a subprocess contract). A test that needs a
   debugger, a device or a network peer does not belong in the suite.
6. `build_scripts.py` audits the script for machine-specific leftovers: an absolute path that names
   one machine, and credential-shaped constants. Generic install locations and already-redacted
   paths carrying a `<placeholder>` are exempt; a real workbench path is a finding, and the fix is in
   the file rather than in the exemption list.
7. Everything targets the interpreter at the declared minimum version: no third-party import outside
   a `try`/`except` with a stated fallback, since `mypy` is configured against 3.10 and the gates run
   on a bare interpreter.

**Recipe:**

1. Write `scripts/<name>.py` with a module docstring that states why it exists, its usage, and its
   exit codes; an `argparse` parser, so `check_commands.py` can read the interface statically; and a
   bounded summary rather than an unbounded dump, with the complete record written to a path it
   reports.
2. Add a row to the `## Script index` table in `routing.md`, saying what it does, not how it is
   implemented.
3. Mention it in the README if a reader is expected to run it directly.
4. Add a test under `tests/cli/` that executes it and asserts the contract you documented.
5. Run `python check_repo.py` (which executes `--help`), `python check_commands.py` (which validates
   every documented flag), and the suite.

### A pitfall in `references/pitfalls.md`

**Purpose:** a failure that produced a working-looking artifact, written so a reader recognises it
while it is happening rather than after.

**Mechanical constraints:**

1. The anchor shape is a bold stand-alone line beginning `**P<n>. `. `check_refs.py` collects pitfall
   numbers from headings and bold stand-alone lines matching `P<n>.` or `P<n> ` across the skill and
   the README, and fails any `P<n>` citation whose number has no anchor.
2. Numbering is append-only. Take the next free number, never renumber an existing entry, and never
   reuse a number: every other document, including the case library, cites pitfalls by number rather
   than restating them, and a citation to a withdrawn number is a gate failure.
3. Keep the file's own shape: the failure, the mechanism that made it invisible, and the check that
   catches it. The mechanism is the part that makes the entry usable, because a failure mode that is
   only described is not recognised in the moment it matters.

**Recipe:** append the entry at the end of the file with the next free number, write the three
paragraphs, then run `python check_refs.py` to confirm the new anchor resolves and that no citation
elsewhere was left dangling.

### A case precedent under `references/precedents/`

**Purpose:** a route that already converged, recorded so the next reader repeats the sequence instead
of re-deriving it, including the dead ends and what each one cost.

**Mechanical constraints:**

1. The template is in `references/precedents/README.md`, which is both the index and the template.
   Keep its headings; the register's grade column is what stops a hypothesis drifting upward into a
   fact.
2. Register the case as a row in that README's table in the same pass as adding the file. A case that
   is not in the register is unreachable, and an unreachable case is the same as no case.
3. The must-not list at the end of that README is binding: no target identity, no licence material,
   no customer or personal data, no invented measurements, no wall of raw tool output, no route
   described as exhausted when it was abandoned, and no unlabelled provenance.
4. Nothing collects the register mechanically. Cases are inside `skills/`, so `check_refs.py` still
   validates a `P<n>` citation you write in one, and `check_commands.py` still validates any command
   you write there. Whether the register row exists is a reviewer's check.

**Recipe:** copy the template block from `references/precedents/README.md` into
`case-<n>-<slug>.md`, fill the identification table with a target *class* rather than a name, keep the
route in the order it happened, grade every assertion, record the measurements with their pins,
list the pits and their cost, state the reusable pattern, and name the files in the write-back
checklist. One case, one route: a case that establishes three unrelated things establishes none.

### A measurement record under `docs/tool-verification/`

**Purpose:** the record of a measurement pass: what each script actually did, which independent
method confirmed it, which scenarios the target could not exercise, and the defects found. It exists
so the coverage claims can be checked against runs instead of trusted, and it is not shipped with the
skill.

**Mechanical constraints:**

1. `check_commands.py` scans `docs/**/*.md`, so every `python <script>.py` command in the record is
   validated against that script's own argument table. A recorded command with a flag that no longer
   exists is drift and fails the gate. Directories named `fixtures` are excluded from that scan.
2. `check_budget.py` treats `docs/tool-verification/` as one of the two places whose job is to state
   results, so a concept recorded here does not count towards the restatement note. Recording it
   elsewhere instead is how a claim acquires a second home.
3. Nothing else checks these files. `check_refs.py` reads `README.md` and `skills/` only, so a
   section reference or a `P<n>` citation written inside a record is not machine-checked, and a
   record is not required to be reachable from any index.

**Recipe:** add one file per pass, naming the pass in the file name; open with the strength-label
rule the record uses; give each measurement the artifact and its digest, the tool and its version,
the command as it was run, the observed output, and the unit of comparison; separate what was
measured from what was only read; and state the negative results, including the scenarios the target
could not exercise.

### A capability row with its grade

**Purpose:** the machine-readable companion to the evidence summary:
`skills/exe-reverse/evidence/capability-matrix.json`. It holds one row per capability this skill
claims, so that a reader who has the installed skill but not this repository can check every claim
against the command the row names. The siblings in the same directory carry the tool versions and the
installer-facing limit list.

**Mechanical constraints:**

1. The file must be valid JSON. No gate parses it and no gate resolves the evidence paths inside it,
   so the honesty of a row is a reviewer's check rather than a script's.
2. The file is organised around its own vocabulary, not around prose: a `grade_legend` that defines
   the three grades, `rules_applied` that states the chain rule and the unknown rule, a
   `measurement_host` and a `measurement_window` that pin when the rows were produced, `script_pins`
   that record each shipped script's size and a truncated digest, and `tree_state_at_end_of_window`.
   A new row lands under `rows` and inherits all of that; if your measurement was taken outside the
   recorded window, or after the pinned scripts changed, the window or the pins move in the same
   change, because a row whose pins do not match the tree is not reproducible.
3. A row carries `id`, `capability`, `grade`, `grade_not_higher` (why the grade is not a level
   higher), `evidence`, `dependency_not_shipped`, `raise_grade` and `evidence_file_pointers`. The
   `evidence` entries name a script and a command, with the observed result as text; `raise_grade`
   states the measurement that would move the row. A row that says `observed` and names no command is
   incomplete.
4. The grade must agree with `references/evidence-summary.md` and with
   `references/coverage-and-limits.md` for the same capability. A tool's exit code is a statement
   about the tool, not about a target the tool was pointed at.
5. The matrix's own path convention is worth copying: where a real path would carry a user profile
   name, the entry uses a token such as `%TEMP%` and says so, rather than reproducing the literal
   path to be concrete.

**Recipe:** append a row to `rows` with the fields above; keep `raise_grade` and
`dependency_not_shipped` honest even when both are inconvenient; move the matching line in
`references/evidence-summary.md` in the same pass; if the row changes what this repository covers,
update the coverage table as described below.

## Adding a whole new capability

A capability is not added by writing the file for it. Three things have to land together, or the
result is a route that reads as covered while nothing behind it has been run.

1. **Its dependency is named.** The coverage table in `references/coverage-and-limits.md` has a
   column headed "Dependency not shipped here", and a row with an unshipped dependency is a named
   gap rather than a covered route. If your route needs a debugger, a capture path, a signing path, a
   second host or a purchase, that is a finding to record rather than a detail to omit.
2. **Its grade is chosen honestly.** `observed` requires a command and its recorded output;
   `inferred` is what a mechanism argument supports; `unverified` is what an assumption gets. Never
   promote a row because a neighbouring row is strong, and never because the claim was repeated.
3. **Its coverage is stated.** Add or amend the row in `references/coverage-and-limits.md`, and keep
   `references/evidence-summary.md` consistent with it. The coverage file's own rules are the
   standard: a route that was not executed is not a route that was excluded, and a row moves only
   when the missing evidence is produced and recorded with its pins.

**A route that was not run lands as `unverified`, not as documentation of a fact.** It belongs in the
coverage table with what is missing, and in the evidence summary's list of routes documented but not
run. If the route is conditional on the host, it is probed rather than assumed: `hwprobe.py` reports
a per-route verdict of `available`, `needs-<something>` or `unavailable`, and all three are answers.
Write the route so that the reader knows which of the four delivery forms it produces (a patched
binary, an in-memory patch, a standalone keygen, or a written report), because "verified" means
something different for each.

## Evidence discipline for contributions

1. **Invent nothing.** No command, flag, version number, API name, CPUID bit, MSR name, registry path
   or measurement that you did not run or read. A plausible-but-wrong flag is the worst possible
   output here, because a reader follows it and then blames their own environment.
2. **A command without its result is incomplete.** State the command and the output. If the output is
   long, quote the decisive lines and say what they decide.
3. **Distinguish `observed` from `inferred` from `unverified`** in every file, including commit
   messages and pull-request text. Two kinds of `observed` are not interchangeable: tool behaviour
   observed transfers to any host running that tool, and target behaviour observed transfers only to
   that build on that host.
4. **Name the search when you report that something was not found.** The range, the pattern, and what
   was searched. A search that returned nothing is evidence about the search.
5. **A limit must cite the measurement or the constraint that set it.** An assumed budget is a
   preference, not a limit.
6. **Grade the chain, not the step.** A strong observation at the start does not upgrade a later step
   that nobody executed.
7. **Record negative results.** A route measured and failed on a named host is more useful than a
   route nobody ran, and a measurement that disagrees with a recorded conclusion re-opens the
   conclusion rather than being explained away.

## Desensitization before you commit

Run the scanner before the commit, on the files you are about to publish, not on the files you
started from:

```
python skills/exe-reverse/scripts/scan_leaks.py
python skills/exe-reverse/scripts/scan_leaks.py --show-exempt
```

Exit codes: 0 clean at the requested strength, 1 findings, 2 error, 3 the scan surface was empty
(stated explicitly rather than reported as clean). By default only `strong` findings fail; a false
positive that blocks a commit teaches people to bypass the gate, which is why `weak` findings are
reported without failing. `check_repo.py` delegates the rule table to this script rather than
reimplementing it, and runs it over the output of `git ls-files`, so git-ignored material cannot
produce a finding; where git is unavailable, the leak step prints `SKIP`. A scanner error is reported
as a note, not as a leak.

Three details of the scan surface decide what a clean result means. The default root is the tree two
levels above the script, which is the skills directory, so the first command above does not scan the
repository root; pass `--root .` for that, and expect it to walk untracked workbench material, which
is why the gate passes an explicit tracked-file list through `--files-from` instead. `--only` and
`--skip` narrow the categories, and `--fail-on any` makes weak findings fatal. And the scan's own
header line states the root and the file count: read it before believing a result, because a scan
pointed at the wrong tree reports nothing and looks identical to a clean one.

One false-positive class is already on this tree and is worth recognising rather than fighting one hit
at a time: a language or runtime name followed by a version number satisfies the product-name rule,
and the entry point's own compatibility line is one such hit. That is a rule to narrow, argued with
the reason beside it, not a value to redact, because redacting it removes a fact a reader needs. Do
not widen the exemption list per hit, and do not reword a document purely to silence a rule that is
wrong.

**Must be removed:** product and vendor identity, the version resource strings embedded in an image,
licence and activation material, real endpoints, customer and organisation identifiers, personal and
machine identifiers including an absolute path under a user profile, target-derived file names,
target-derived hashes that serve as lookup keys, timestamps that pin one build, and raw host output
that carries an account or a path.

**Must not be removed, because redacting it destroys the reusable part:** tool names, library and
module names, file and container format vocabulary, CWE identifiers, public packer and protector
names, public challenge material, generic API and system names, architecture and instruction
vocabulary, and placeholder tokens such as `<image>`, `<sha256>` or `<offset>`.

The test that separates the two lists: does removing this string make the sentence less able to
teach? If it costs the reader nothing, it was identity and it goes. Two boundary cases are genuinely
boundary cases: a protector name that appears because the target uses that product is technique
vocabulary and stays, while the same name as the vendor identity of the artifact being analysed is
identity; and a tool version belongs in the report because a measurement without its pins is not
reusable, while a target's version does not.

The pass ends with a reader, not with a green scan. A scan decides whether a shape is present; it
cannot see identity that is described rather than quoted, and it cannot read a name, a heading or an
image. Never quote a hit value inside a published document that documents hits.

## Repository hygiene

Never commit any of the following. The `.gitignore` rules exist to express this list, and each rule
carries its reason next to it:

1. **Samples, dumps and extracted payloads**: executables, libraries, drivers, installers, packages,
   raw memory, disk images, core dumps. A target is someone else's software and never belongs in the
   tree.
2. **Reverser databases and tool state**: disassembler databases, listing and map files.
3. **Licence material and credentials**: keys, serials, certificate stores, keystores, private keys,
   credential databases. The purpose of the skill is to classify a mechanism, never to ship a key.
4. **Captures**: packet captures, session archives, traces, event-log exports.
5. **Build and bytecode output**: objects, libraries, classes, archives, and `__pycache__`.
6. **Local scratch**: `_tmp/`, `out/`, `work/`, `audit_out/`, `exports/`, `samples/`, `captures/`,
   logs.
7. **The workbench**: `tools/` for a locally cloned or extracted toolchain, and whatever directory a
   research pass uses for third-party write-ups. These are someone else's material or a local build,
   and one `git add -A` is all it would take to commit them.
8. **Sandbox install directories** created while testing the `skills` CLI against the repository.
9. **Screenshots.** An image is evidence while a task runs and never part of the tree; the text of
   what it showed belongs in the record instead.
10. **Anything a concurrent writer left behind.** `git add -A` stages whatever exists at that
    moment, including a helper script another pass created and never intended to ship. That is not
    hypothetical: a markdown re-wrapping script reached this repository's history exactly that way,
    harmless but unintended, and it had to be removed in a later commit. When more than one writer
    is active, stage by path, and read `git diff --cached --name-only` before committing. The check
    costs one command; the alternative is a file in the history that nobody chose.

Two things the ignore rules cannot do, and which the gates do instead: a text file can name a target
without containing a binary, which is what the leak scan is for; and an absolute path or a
credential-shaped constant can survive in a script, which is what `build_scripts.py` reports.

## Review

Reviewed, not scripted:

1. **Is the claim's grade honest?** A tool exiting zero is a statement about the tool. A single run
   without a control is not a causal result. A chain whose last step nobody executed is `inferred`.
2. **Is the route described from a real run?** A procedure that was reasoned out rather than executed
   is `unverified`, and saying so is not hedging.
3. **Is the limit real?** It cites the measurement or the constraint that set it, and it is stated in
   the same voice as the capability.
4. **Was coverage updated?** A new route that does not appear in the coverage table, or a measurement
   that contradicts a row and does not move it, is an incomplete change.
5. **Was the material desensitized?** Including names, headings and metadata, which no pattern scan
   reads.
6. **Is the smallest reproduction given?** The command, and the shortest artifact that shows the
   problem.

**An unchecked box is not evidence of absence.** A pull-request template with a blank effect-surface
checklist has not been shown to be documentation-only; it has been shown to be unfinished. The
reviewer asks for the checklist to be completed, or for the reason it cannot be.

## Style

1. Dense, direct, technical English. State mechanisms and consequences. No marketing register, no
   filler, no "simply".
2. Prefer a table when the content is a decision, and prose when it is a mechanism.
3. Length follows content. A reference is loadable, not exhaustive.
4. Label untrusted target-derived content as data: fence it, state its origin, and never present it in
   an instruction position.
5. Grade every factual assertion, in the file where it appears.
6. Do not name or cite another project, and do not describe this material as adapted from anything.
7. Prefer file pointers over section cross-references. If you do reference a section, name one that
   exists, because `check_refs.py` resolves the link and a stale one fails the build.
8. No nested bullet lists; a list that needs depth wants headings instead.

## Before you open the pull request

- [ ] The gates listed above were run from the repository root, and any new failure is either fixed
      or explained as pre-existing.
- [ ] Every new file is registered where its class requires it: `routing.md` for a reference or a
      script, the register table for a case, the coverage table for a capability.
- [ ] Every command in the change was run, and its output is quoted where the claim is made.
- [ ] Every grade in the change is one of `observed`, `inferred`, `unverified`, and no chain is
      graded above its weakest link.
- [ ] `scan_leaks.py` was run on the files being published, and its findings are resolved.
- [ ] The effect-surface checklist in the pull-request template is complete, including an explicit
      "documentation only" where that is the case.
- [ ] The readiness declaration is left for a human owner; an agent does not fill it in.
