# tests/ — executable regression suite for the exe-reverse skill

The suite that proves the shipped scripts still do what their docstrings say, offline, with only
the standard library and pytest.

## When to load this

Read it before changing anything under `skills/exe-reverse/scripts/`, and read it before quoting
a coverage claim about this skill. It is the boundary between "the script was written to do X"
and "the script was measured doing X on this host".

## What it runs

| File | What it asserts |
| --- | --- |
| `conftest.py` | Shared fixtures: builds the synthetic PE images at test time, loads a script by path, runs a script as a subprocess with a timeout, and the two synthetic scan corpora. |
| `unit/test_peutil_reader.py` | Header fields against the fixture's declared metadata, RVA to file-offset round trips including the virtual-only tail, the PE32 versus PE32+ optional-header difference, the checksum against a second implementation, the resource tree, named and ordinal imports, the TLS callback, the RSDS/PDB record, relocation blocks, entropy and flag decoding, and the parser's rejections. |
| `unit/test_pepatch_patcher.py` | Pattern parsing and matching, the ambiguity refusal, the expect-mismatch refusal, the length-unproven and length-change cases, the resolver's refusals, the re-read verification, and the CLI-level facts that a dry run writes nothing and a real run leaves its input byte-identical. |
| `unit/test_aob_scan.py` | The verdict boundaries at both sides of each threshold, hit reporting with offsets, RVAs and sections, section filtering, context windows, and every accepted shape of a pattern file. |
| `unit/test_scan_leaks.py` | Every rule firing on a shaped sample, every exemption class staying silent, the three measured deviations from the exemption list, scan position reporting, and the file walk's skips. |
| `unit/test_capabilities_registry.py` | The capability table: every atom's kind, basis and probe name, the transitive closure against an independent walk, the dependency graph's acyclicity, `resolve` on missing atoms and on `file:` atoms that are and are not on disk, the declaration parser including the documentation template it must reject, and the `declared` / `mapped` / `unknown` classification. |
| `unit/test_doctor.py` | The static dependency pass (stdlib, siblings and a third-party name separated without executing the file), `discover_scripts` scanning rather than listing, the per-script table with an unclassified script still counted, and the environment facts with their keys and severity labels. |
| `unit/test_budget_measurement.py` | The budget gate's two measurement paths agree (real tokenizer versus the calibrated fallback), the fallback constant still matches a fresh measurement of `SKILL.md`, and a row past `INDEX_ROW_HARD` fails rather than warns. |
| `unit/test_dart_snapshot_strings.py` | The ELF reader against a generated container, both literal encodings recovered at the offsets the fixture placed them at, the length and limit gates, and the pool counts -- zero on an image carrying neither idiom and non-zero on hand-built bytes carrying each one. |
| `cli/test_cli_surface.py` | Help and usage exit codes for every script, the documented exit codes for each script's error paths, and the negative case that inspect-only runs write nothing into the working directory. |
| `cli/test_cli_coverage.py` | Coverage derived from the scripts directory rather than a hand-written list: every shipped `.py` is either exercised or declared uncovered with a reason, and every one answers `--help` with its usage block. A new script fails here until it is registered. |
| `cli/test_cli_json.py` | Each script's machine-readable output: keys, values, and the conventions that are not what a reader would assume -- including `pe_triage.py`'s identity block on a generated image (and that it writes nothing) and `pe_diff.py`'s self-comparison, which is the control for every other diff. |
| `cli/test_cli_registry_surface.py` | The registry and doctor subprocess contracts: `--list` / `--json` / single-capability exit codes and `RESULT=` tokens, the doctor's three blocks and its 0-versus-3 verdict, and the view flags that print one block only. |
| `cli/test_cli_dart_snapshot.py` | The snapshot reader's CLI: the refusals and their exit codes, `--find` case-insensitivity and the exit code a miss produces, `--at` by file offset and by virtual address, and the `--json` document. |
| `integration/test_pipeline_end_to_end.py` | Build, locate, patch, re-read: the patched bytes, the untouched control site, the recomputed checksum, and a control run in which nothing changes. |
| `integration/test_across_builds.py` | Pattern hit counts compared between two builds, including the case where a patch removes the very byte the pattern was located with. |
| `run_tests.py` | The one-command entry point; prints the install line and exits 3 when pytest is missing. |
| `benchmark.md` | The regression matrix: dimension, target, scripts, measured result, strength label. |

## How to run it

```
python -m pytest -q                     # from the repository root: the whole suite
python -m pytest -q -m unit             # one layer: unit, cli or integration
python tests/run_tests.py               # same thing, with a clear message if pytest is missing
python tests/run_tests.py -q -m unit    # arguments are forwarded to pytest
```

If pytest is not installed: `python -m pip install pytest`.

## What it deliberately does not do

It does not attach a debugger, load a driver, open a socket, read a device, or execute a target.
Those routes are conditional on host hardware and policy, and a suite that asserts them is either
fragile or dishonest. The recorded experiments for them live in `benchmark.md` with the strength
label that says whether they were reproduced here.

It does not commit or download a sample. Every PE input is generated into a temporary directory
by `make_fixture_pe.py` on the way in and removed with the session, so the suite carries no
binary, no licence question and no dependency on a target that changes underneath it.

It does not assert on timing. The only time in the suite is a generous per-process timeout, which
exists to turn a hang into a failure rather than to measure throughput. The timings in
`benchmark.md` were taken by hand and are recorded as measurements, not enforced as limits.

It does not test the reference documents' prose. Cross-reference, budget and routing checks belong
to the repository's own gates.

## Fixtures

`conftest.py` builds four images per session, addressing `make_fixture_pe.py`'s own recipes rather
than duplicating their shapes:

| Name | Recipe | Why it is in the suite |
| --- | --- | --- |
| `pe64` | `default` | PE32+ with every structure the builder can emit, five sections and the planted pair. |
| `pe32` | `pe32` | The 32-bit optional-header layout, whose field offsets differ. |
| `bare` | `bare` | No exports, resources, TLS or debug directory, so the absent cases are representable. |
| `fatalign` | `fat-align` | A 4 KiB file alignment, large enough that `.rdata` has no virtual-only tail. |

The builder's `no-virtual-tail` recipe is deliberately not used: with a zero virtual pad its own
guard rejects the layout it names, so the recipe exits 1 and writes nothing. `fatalign` covers the
same property. `cli/test_cli_surface.py` pins that failure so the recipe cannot quietly stay
broken.

`conftest.build_synthetic_elf` builds a second kind of input, because `dart_snapshot_strings.py`
reads an ELF shared object rather than a PE and no sample of any kind may be committed: a valid
ELF64 header, a `.text` of sixteen bytes carrying neither idiom the pool observer counts, a
`.rodata` holding one one-byte (ASCII) literal and one two-byte (UTF-16LE) literal at known
offsets, and a section-name string table. It is a container to hold the reader against, not a
Flutter snapshot: the counts the script's docstring records came from a real 26.8 MB `app.so` and
cannot be reproduced from a generated file, which is why the counting logic is asserted in both
directions -- zero on the fixture, non-zero on hand-built bytes -- and the real measurement stays a
recorded observation.

## Conventions

Marker is the layer: `unit` for pure functions and parsers, `cli` for subprocess contracts,
`integration` for the no-debugger flows. All three are declared in `pytest.ini`, and
`--strict-markers` is on, so an undeclared marker is an error rather than a warning. There is no
slow or deselected tier and therefore no `--runslow` switch: nothing in the suite needs one, and
declaring a marker that no test carries would be decoration.

A missing prerequisite skips with a printed reason: an interpreter older than the 3.9 the scripts
declare, or a local tool a check needs. A wrong result always fails. Nothing is skipped silently,
and no test was weakened to pass.

Untrusted sample text is assembled from fragments in `conftest.py` rather than quoted whole. The
suite has to contain strings shaped like pasted credentials and profile paths in order to prove
the scanner catches them; written whole they would also be caught by the repository's own
pre-publish scan. The runtime values are identical, and the source text matches nothing.

## Deviations the suite pins

Each of these is a measured behaviour that differs from what the corresponding docstring implies.
They are asserted as observations so a fix shows up as a test change instead of as a quietly
gained or lost result, and each is also recorded in `benchmark.md`.

| Where | Measured behaviour |
| --- | --- |
| `make_fixture_pe.py` | The `no-virtual-tail` recipe contradicts its own guard and cannot be built. |
| `peutil.py`, `pepatch.py` | A file truncated mid-header raises `struct.error` and prints a traceback instead of using the documented exit code; a fully non-PE input does use it. |
| `pepatch.py` | A missing `--spec` file reaches an unguarded `open()` and prints a traceback. |
| `aob_scan.py` | A bare JSON array of patterns raises `AttributeError`; only the object form is accepted. |
| `scan_leaks.py` | Exit code 3 is documented for an empty scan surface and is unreachable: an empty root reports `RESULT=clean` and exits 0. |
| `scan_leaks.py` | The bare-GUID exemption matches inside the machine-guid rule's own match text, so that rule cannot produce a finding. |
| `scan_leaks.py` | The `.NET` entry matches any `.net` TLD, so a hit inside such a host is suppressed as a platform term. |
| `scan_leaks.py` | The `<[a-z_]+>` placeholder alternative is wrapped in `\b`, so it cannot match bracketed prose. |
| `hwprobe.py` | Two route rows answer with a sentence instead of one of the three documented states. |
| `pepatch.py` | `--allow-resize` writes in place, so the file does not grow and the bytes after the site are overwritten rather than shifted. |

## Limits

Coverage is bounded by the fixture, not by the reader. A synthetic image exercises every structure
the builder emits and nothing it does not; a route that needs a device, a debugger, a driver or a
network is out of scope here and is listed as not run in `benchmark.md`. The suite also cannot say
whether a pattern will survive a build it has never seen, which is why the comparisons it does make
are between two images it built itself.

The scripts under `skills/exe-reverse/scripts/` were being edited while this suite was written, and
several assertions moved with them. Re-run the suite after any change to those files rather than
trusting a count recorded earlier.
