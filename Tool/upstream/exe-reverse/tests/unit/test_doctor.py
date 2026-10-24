"""Unit tests for skills/exe-reverse/scripts/doctor.py, the environment doctor.

Three properties of the doctor are what make its report a measurement, and each gets a test rather
than a description:

* its per-script dependency pass is static, so a file whose *execution* would raise is inspected
  without ever being imported -- proved with a script that writes a sentinel and imports a module
  that does not exist;
* `discover_scripts` scans the directory instead of holding a list, proved by pointing the doctor at
  a synthetic directory and checking that what it reports is what is there;
* a script with no capability is reported `unknown` and *counted*, because a denominator that
  shrinks quietly is how a report stops being a measurement.

The host facts come from a real probe, so a host where the probe cannot answer skips the fact tests
with a printed reason instead of failing them.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.unit


def write(root, name, body):
    path = root / name
    path.write_text(body, encoding="utf-8")
    return path


def synthetic_scripts_dir(tmp_path, sentinel=None):
    """A directory of the six shapes `scan_scripts` has to classify."""
    root = tmp_path / "scriptdir"
    root.mkdir()
    write(root, "declaring.py",
          '"""capability: pe_structure_read\n\nDeclares its own capability.\n"""\n'
          "import json\n\nprint('usage: declaring')\n")
    write(root, "aob_scan.py",
          '"""A script the map knows and that declares nothing.\n"""\n'
          "import os\n\nprint('usage: aob_scan')\n")
    write(root, "needs-tool.py",
          '"""Imports a module that is not installed, safely.\n"""\n'
          "try:\n    import zebra_kit\nexcept ImportError:\n    zebra_kit = None\n\n"
          "print('usage: needs-tool')\n")
    write(root, "broken.py",
          '"""Raises as soon as it is executed.\n"""\n'
          "raise RuntimeError('this script cannot start')\n")
    write(root, "stranger.py",
          '"""Neither declares nor is mapped.\n"""\n'
          "import sibling_helper\n\nprint('usage: stranger')\n")
    write(root, "helper.js", "// not a python script\n")
    write(root, "sibling_helper.py",
          '"""A file this directory ships, so it is not a third-party dependency.\n"""\n')
    if sentinel is not None:
        write(root, "sentinel_target.py",
              '"""Would write a sentinel the moment it were executed.\n"""\n'
              "import pathlib\n\n"
              "pathlib.Path(%r).write_text('executed')\n"
              "import zebra_kit_that_does_not_exist\n" % str(sentinel))
    return root


# --- static dependency pass --------------------------------------------------

def test_static_deps_separates_stdlib_siblings_and_third_party(load_script, tmp_path, monkeypatch):
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    assert doctor.static_python_deps(str(root / "declaring.py")) == (set(), None)
    assert doctor.static_python_deps(str(root / "aob_scan.py")) == (set(), None)
    assert doctor.static_python_deps(str(root / "stranger.py")) == (set(), None)
    deps, reason = doctor.static_python_deps(str(root / "needs-tool.py"))
    assert (deps, reason) == ({"zebra_kit"}, None)


def test_static_deps_sees_an_import_inside_a_try_block(load_script, tmp_path, monkeypatch):
    """The pass reads the AST, so an import that is guarded at run time is still a dependency."""
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    deps, _reason = doctor.static_python_deps(str(root / "needs-tool.py"))
    assert deps == {"zebra_kit"}


def test_static_deps_does_not_import_or_execute_the_file_it_inspects(load_script, tmp_path,
                                                                    monkeypatch):
    """The sentinel file is the proof: if the file were imported, it would exist -- or the import of
    the deliberately missing module would raise out of `static_python_deps` entirely."""
    doctor = load_script("doctor.py")
    sentinel = tmp_path / "sentinel.txt"
    root = synthetic_scripts_dir(tmp_path, sentinel=sentinel)
    monkeypatch.setattr(doctor, "HERE", str(root))
    deps, reason = doctor.static_python_deps(str(root / "sentinel_target.py"))
    assert deps == {"zebra_kit_that_does_not_exist"}
    assert reason is None
    assert not sentinel.exists(), "the inspected script was executed"
    assert "zebra_kit_that_does_not_exist" not in sys.modules


def test_static_deps_reports_a_syntax_error_instead_of_raising(load_script, tmp_path):
    doctor = load_script("doctor.py")
    write(tmp_path, "broken.py", "def f(:\n")
    deps, reason = doctor.static_python_deps(str(tmp_path / "broken.py"))
    assert deps == set()
    assert reason


def test_static_deps_reports_an_unreadable_path_instead_of_raising(load_script, tmp_path):
    doctor = load_script("doctor.py")
    deps, reason = doctor.static_python_deps(str(tmp_path / "absent.py"))
    assert deps == set()
    assert "absent.py" in reason


def test_every_shipped_script_is_standard_library_only(load_script):
    """The claim the skill's own README makes, measured on the scripts in the tree."""
    doctor = load_script("doctor.py")
    for name in doctor.discover_scripts():
        if not name.endswith(".py"):
            continue
        deps, reason = doctor.static_python_deps(os.path.join(doctor.HERE, name))
        assert reason is None, "%s could not be read: %s" % (name, reason)
        assert deps == set(), "%s needs %r, which the kit does not ship" % (name, sorted(deps))


# --- discovery ---------------------------------------------------------------

def test_discover_scripts_reports_whether_files_are_really_there(load_script):
    doctor = load_script("doctor.py")
    present = sorted(n for n in os.listdir(doctor.HERE) if n.endswith((".py", ".js")))
    assert doctor.discover_scripts() == present
    for name in ("capabilities.py", "doctor.py", "dart_snapshot_strings.py"):
        assert name in present


def test_discover_scripts_scans_a_directory_rather_than_a_fixed_list(load_script, tmp_path,
                                                                     monkeypatch):
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    found = doctor.discover_scripts()
    assert found == sorted(n for n in os.listdir(str(root)) if n.endswith((".py", ".js")))
    assert set(found) >= {"declaring.py", "aob_scan.py", "needs-tool.py", "broken.py",
                          "stranger.py", "helper.js", "sibling_helper.py"}
    assert "notes.txt" not in found
    write(root, "late_arrival.py", '"""Added after the scan.\n"""\n')
    assert "late_arrival.py" in doctor.discover_scripts()


def test_discover_scripts_ignores_files_that_are_not_scripts(load_script, tmp_path, monkeypatch):
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    write(root, "notes.txt", "not a script\n")
    write(root, "Makefile", "all:\n\ttrue\n")
    monkeypatch.setattr(doctor, "HERE", str(root))
    found = doctor.discover_scripts()
    assert "notes.txt" not in found
    assert "Makefile" not in found


# --- per-script table --------------------------------------------------------

@pytest.fixture(scope="module")
def capability_results(load_script):
    caps = load_script("capabilities.py")
    return caps.resolve_all(caps.Probe(tool_dirs=[]))


def test_scan_scripts_classifies_every_script_it_finds(load_script, tmp_path, monkeypatch,
                                                      capability_results):
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    rows = doctor.scan_scripts(capability_results)
    by_name = {row["script"]: row for row in rows}

    assert len(rows) == len(doctor.discover_scripts()) == 7
    assert by_name["declaring.py"]["capability_source"] == "declared"
    assert by_name["declaring.py"]["capabilities"] == ["pe_structure_read"]
    assert by_name["aob_scan.py"]["capability_source"] == "mapped"
    assert by_name["aob_scan.py"]["capabilities"] == ["aob_locate"]
    assert by_name["needs-tool.py"]["capability_source"] == "unknown"
    assert by_name["needs-tool.py"]["third_party"] == ["zebra_kit"]
    assert by_name["helper.js"]["runnable"] is True
    assert "not a python script" in by_name["helper.js"]["detail"]


def test_a_script_with_no_capability_is_unknown_counted_and_never_dropped(
        load_script, tmp_path, monkeypatch, capability_results):
    """The denominator is the number of scripts in the directory, unknown ones included."""
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    rows = doctor.scan_scripts(capability_results)

    unknown = [row for row in rows if row["capability_source"] == "unknown"]
    assert len(rows) == len(doctor.discover_scripts())
    assert {row["script"] for row in unknown} == {"needs-tool.py", "broken.py", "stranger.py",
                                                  "helper.js", "sibling_helper.py"}
    assert len(unknown) == 5, "the unknown rows stay in the table; only two scripts claim one"
    assert {row["script"] for row in rows if row["capability_source"] != "unknown"} == \
        {"declaring.py", "aob_scan.py"}
    for row in unknown:
        assert row["capabilities"] == []
        assert row["capability_state"] == "unknown"
        assert row["script"] in {r["script"] for r in rows}


def test_scan_scripts_marks_a_script_that_cannot_start(load_script, tmp_path, monkeypatch,
                                                       capability_results):
    doctor = load_script("doctor.py")
    root = synthetic_scripts_dir(tmp_path)
    monkeypatch.setattr(doctor, "HERE", str(root))
    row = {r["script"]: r for r in doctor.scan_scripts(capability_results)}["broken.py"]
    assert row["runnable"] is False
    assert "RuntimeError" in row["detail"]
    assert "Traceback" not in row["detail"]


def test_scan_scripts_agrees_with_the_registry_about_every_real_script(load_script,
                                                                       capability_results):
    """On the shipped directory, every script is classified and the states come from the registry."""
    doctor = load_script("doctor.py")
    caps = load_script("capabilities.py")
    rows = doctor.scan_scripts(capability_results)
    assert [row["script"] for row in rows] == doctor.discover_scripts()
    states = {result["id"]: result["state"] for result in capability_results}
    for row in rows:
        declared, source = caps.capabilities_for_script(row["script"],
                                                       os.path.join(doctor.HERE, row["script"]))
        assert row["capabilities"] == declared
        assert row["capability_source"] == source
        if not declared:
            assert row["capability_state"] == "unknown"
            continue
        assert row["capability_state"] == ("ok" if all(states[c] == "ok" for c in declared)
                                           else "blocked")


# --- environment facts -------------------------------------------------------

@pytest.fixture(scope="module")
def host_facts(load_script):
    """One environment report for the module: it runs a probe and shells out to logman."""
    doctor = load_script("doctor.py")
    report = doctor.environment_report()
    if len(report) == 1 and report[0].get("fact") == "host probe":
        pytest.skip("the host probe could not answer here (%s), so the fact table is inert"
                    % report[0].get("effect"))
    return report


def test_environment_report_is_a_list_of_facts_with_the_documented_keys(host_facts):
    assert isinstance(host_facts, list) and host_facts
    for fact in host_facts:
        assert set(fact) == {"fact", "value", "effect", "severity"}, sorted(fact)
        assert fact["fact"] and fact["value"] is not None and fact["effect"]


def test_every_environment_fact_is_labelled_note_or_warn(host_facts):
    """The label is the whole point: `warn` means it can change a result, and the doctor's exit
    token turns on that count."""
    for fact in host_facts:
        assert fact["severity"] in ("note", "warn"), fact


def test_environment_report_always_states_the_working_directory(host_facts):
    """Unconditional, so the fact table can never be empty on a host where the probe answers."""
    facts = {fact["fact"]: fact for fact in host_facts}
    assert "working directory" in facts
    assert facts["working directory"]["value"] == os.getcwd()
    assert facts["working directory"]["severity"] == "note"


def test_severity_summary_counts_only_warnings(load_script):
    doctor = load_script("doctor.py")
    assert doctor._severity_summary([]) == 0
    assert doctor._severity_summary([{"severity": "note"}, {"severity": "note"}]) == 0
    assert doctor._severity_summary([{"severity": "note"}, {"severity": "warn"},
                                     {"severity": "warn"}]) == 2


# --- primitives --------------------------------------------------------------

def test_run_reports_a_failure_instead_of_raising(load_script):
    doctor = load_script("doctor.py")
    code, output = doctor.run(["definitely-not-a-real-command-xyz"])
    assert code == -1
    assert output


def test_run_returns_the_code_and_combined_output(load_script):
    doctor = load_script("doctor.py")
    code, output = doctor.run([sys.executable, "-B", "-c", "print('probe')"])
    assert code == 0
    assert "probe" in output


def test_the_documented_exit_codes_and_tokens_are_the_ones_used(load_script):
    doctor = load_script("doctor.py")
    assert (doctor.EXIT_OK, doctor.EXIT_USE, doctor.EXIT_ENV, doctor.EXIT_INTERNAL) == (0, 2, 3, 4)
    assert doctor.TOKENS["ok"] == "env_ok"
    assert doctor.TOKENS["partial"] == "env_partial"
    assert doctor.TOKENS["blocked"] == "env_blocked"
    assert doctor.TOKENS["use"] == "usage_error"
    assert doctor.TOKENS["internal"] == "internal_error"
