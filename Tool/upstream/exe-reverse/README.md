<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <img src="assets/banner-light.svg" alt="exe-reverse" width="100%">
  </picture>
</p>

<p align="center">
  <b>English</b> · <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-49454F?style=flat-square" alt="license"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-49454F?style=flat-square&logo=python&logoColor=white" alt="python">
  <img src="https://img.shields.io/badge/platform-windows-49454F?style=flat-square" alt="platform">
  <img src="https://img.shields.io/badge/strength_labels-observed%20%7C%20inferred%20%7C%20unverified-49454F?style=flat-square" alt="strength labels">
</p>

<p align="center">
  <a href="#what-it-is-good-at">Capabilities</a> · <a href="#structure">Structure</a> · <a href="#install">Install</a> · <a href="#tooling">Tooling</a> · <a href="#scope">Scope</a> · <a href="#repository-maintenance">Maintenance</a>
</p>

# exe-reverse

An Agent Skill for Windows x86/x64 **local-software** reverse engineering: triage, byte-level
patching, signature work, debugging, injection, dump repair, licensing-mechanism classification,
algorithm recovery, packers and code virtualisation, managed assemblies, kernel drivers, and the
**hardware-observation layer** — instruction tracing, hardware breakpoints, and hypervisor-assisted
observation — that software tooling cannot substitute for.

It is a **skill**, not a tutorial: a short decision-oriented `skills/exe-reverse/SKILL.md`, references
loaded only when a step needs them, and parameterised scripts you can run directly.

## How an agent is expected to consume this

`SKILL.md` is written as a **procedure with gates**, not as advice, because the observed failure mode
is not ignorance — it is a model reading the whole thing, agreeing with it, and then reasoning from
first principles anyway. Four things in it are meant to be *acted on*:

- **Five operating rules (O1–O5).** Where they conflict with the plan, they win until evidence does.
- **A symptom index.** A matching row is a **stop signal**: load that file before the next command.
- **Five gates (G1–G5),** each an action with a pass criterion. "I understand the idea" clears none.
- **A two-strike rule and stop conditions.** Two failures of the same shape mean the model is wrong.

One thing is meant to be *withheld*: **"done" has a definition (six items)**, and a clean log is not
one of them. Anything short of six is a checkpoint, reported as one with what remains.

`python skills/exe-reverse/scripts/doctor.py` is the cheapest first command: it reports which
capabilities this host supports, whether every script in the kit runs as-is, and which host facts
would silently poison an experiment. `python skills/exe-reverse/scripts/hwprobe.py` goes deeper on
hardware, and `python skills/exe-reverse/scripts/capabilities.py --verbose` prints the next action
for anything blocked.

## What it is good at

- Deciding **fast** whether a request is achievable by changing the client at all, instead of burning
  hours on a decision the server owns.
- Establishing **which host you actually have** before a plan depends on it: a debugger installed, an
  elevated session, test signing, a second machine, or a hypervisor that intercepts the mechanism.
- Patching **without breaking the file**: equal-length edits, the checksum recomputed, the written
  bytes re-read from disk, and a length change reported as the structural edit it is.
- Making a signature **honest about itself**: how many sites it matched, whether that count changed
  between builds, and whether it is a locator or a coin flip.
- Classifying a **licence decision** before touching it (client-verified, client-rendered server
  data, server-authoritative), and separating "the bytes are in the file" from "the code runs".
- Reaching for the **hardware layer** when a debugger cannot, and stating what it requires and what
  it still cannot see.

## Structure

`SKILL.md`, `references/` and `scripts/` live inside the skill directory, `skills/exe-reverse/`.
Everything at the repository root is maintenance tooling, not part of an installed skill.

```
skills/exe-reverse/SKILL.md     a procedure with gates, not background reading:
                                five moves -> O1-O5 -> symptom index -> gates G1-G5
                                thirteen classification questions -> routing table
                                budget rules -> workflow -> done -> stops -> constraints
skills/exe-reverse/references/  loaded on demand, one topic each; the inventory with when to load
                                each one is skills/exe-reverse/references/routing.md
skills/exe-reverse/scripts/     parameterised and path-agnostic; runnable on a bare Python 3.10+
skills/exe-reverse/evals/       the with-skill / without-skill cases, and how to run them
skills/exe-reverse/evidence/    the machine-readable companions to the evidence summary
docs/tool-verification/         the evidence record for measurement passes (not shipped)
tests/                          the executable regression suite
```

The reference library is indexed, not memorised: `skills/exe-reverse/references/routing.md` carries
every reference with when to load it and every script with what it does. Read it once a route has
been chosen.

## Install

This is a **skills repository**: the skill lives at `skills/exe-reverse/`, the layout the `skills`
CLI resolves, and it is installed by name rather than by copying a directory.

```
npx skills add <owner>/exe-reverse                 # install every skill in the repo
npx skills add <owner>/exe-reverse --list          # list what is here, install nothing
npx skills add <owner>/exe-reverse --skill exe-reverse -y
npx skills use  <owner>/exe-reverse`exe-reverse    # use it once, without installing
```

The CLI symlinks the skill into your agent's skills directory by default (`--copy` makes independent
copies instead), `-g` installs for every project, and `-a` targets specific agents. With one skill in
the repository, `--skill exe-reverse` is redundant today; it is written out because it selects a
single skill once a second one exists. Once installed, the agent loads `SKILL.md` when a task matches
its description and pulls in `references/*` as needed: no global state, no build step.

## Tooling

Nothing is mandatory, and no tool needs to be on `PATH`: the scripts accept explicit paths for what
they shell out to, and a runnable archive or a script counts as installed. Three things decide which
routes exist at all — Python 3.10+, a disassembler/decompiler, and a debugger —
`skills/exe-reverse/scripts/capabilities.py` carries the full list as a probed registry, with an
executable next step and a cost estimate per entry, and `skills/exe-reverse/scripts/hwprobe.py`
reports which of them this host actually has, including the routes a virtualised host cannot take.

If the toolchain lives outside `PATH` (a project-local tools directory, a versioned SDK folder), set
`EXEREV_TOOLS`:

```
set EXEREV_TOOLS=<dir>;<dir>                     # Windows
export EXEREV_TOOLS=<dir>:<dir>                  # POSIX
```

A GUI-only tool is a request for a human, not a reason to substitute a weaker one.

## Scope

Built for working on your own software, samples you are authorized to analyse, and competition
sandboxes; published for learning, research and authorized security testing only. It ships no exploit
payloads, no target data and no vendored third-party binaries — it is a method, a set of scripts and
an evidence record.

What it covers, and what it deliberately does not, is stated in the skill itself
(`skills/exe-reverse/references/coverage-and-limits.md`). The short version: Windows PE on x86 and
x64, deep on the layers that have been worked through — triage, patching, signatures, licensing
classification, protectors, managed code, and the hardware-observation route map. Two
application-runtime layers — Unity IL2CPP metadata recovery and packaged Python — are documented
from public write-ups, and are graded `unverified` for that reason. Defeating a
server-side authority, a fully automated general-purpose devirtualiser, defeating a named commercial
protector as a product claim, and any guarantee on a Windows build this repository has not measured
are **not** covered, and the skill is written to say so and stop rather than apply the nearest
documented procedure to a target it was not written for.

Before building, read `skills/exe-reverse/references/pitfalls.md`. It is the most valuable file here
— every entry is a failure that produced a working-looking artifact.

## Repository maintenance

Six tools live at the root and are not part of the installed skill. Each carries its own docstring;
`CONTRIBUTING.md` states what a green run means.

| Tool | What it keeps honest |
|---|---|
| `check_repo.py` | every skill discovered, frontmatter valid, scripts runnable, documented and README paths resolving, no target identity on the tracked surface |
| `check_refs.py` | a cross-reference that names a section reaches a real heading |
| `check_routing.py` | the on-demand inventory still matches the entry point, row for row |
| `check_commands.py` | every documented command exists in the script's own argparse table |
| `check_budget.py` | the always-loaded part does not creep: SKILL.md lines and tokens, index rows, hedged rules |
| `build_scripts.py` | machine-specific leftovers: absolute paths, credentials |

Consistency has a natural counter-pressure — a broken path fails loudly and someone fixes it. Bloat
has none, which is why the budget gate exists.

Those six gates are half of a green run. The other half is `python -m pytest -q` plus the lint pair
(`mypy` and `flake8` over the same surface, configured by `mypy.ini` and `.flake8`).
`.github/workflows/ci.yml` runs all of it on every push — the six gates, the suite on Python
3.11–3.14, and the lint job — and states at the top what it deliberately does not run. A machine
without the optional dependencies is the environment both the lint configuration and the budget
gate's fallback path are required to keep working in.

`tests/benchmark.md` holds the regression matrix (dimension -> public target -> scripts exercised ->
measured result -> strength label), and `docs/tool-verification/` is the evidence record behind it:
what each script actually did, which independent method confirmed it, and what the target could not
exercise.

---

Proudly supported by the [LINUX DO](https://linux.do) community.

## Disclaimer

The material is provided *as is*, without warranty of any kind. Results are recorded as they were
measured on one machine at one time; nothing here promises that a route will work on your target,
your host or your toolchain. Verify before you trust, and work on copies.

Nothing here is a service, a product, or an endorsement of any particular use. Names of tools,
libraries, file formats and hardening products appear only to make the material reusable; they
belong to their respective owners, and this project is not affiliated with any of them.
