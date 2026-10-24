"""Subprocess contract tests for the exit codes and usage surface of every script.

The exit codes asserted here are the ones each script's own docstring publishes, read from the
docstring rather than invented:

* peutil.py      0 parsed, 1 not a parseable PE, 2 usage error
* pepatch.py     0 applied and verified, 1 a patch failed, 2 usage error, 3 not a parseable PE
* aob_scan.py    0 every pattern unique, 1 a pattern matched zero or several times, 2 usage,
                 3 not a parseable PE
* hwprobe.py     0 report produced, 2 usage error (a limited machine is a finding, not a failure)
* make_fixture_pe.py  0 written, 2 usage error
* scan_leaks.py  0 clean, 1 findings, 2 error

One input path is pinned as a measured deviation: a missing ``--spec`` file reaches an unguarded
``open()``, so it prints a traceback instead of using the module's own exit-code vocabulary.
"""
import json

import pytest

pytestmark = pytest.mark.cli

SCRIPTS = ("peutil.py", "pepatch.py", "hwprobe.py", "aob_scan.py", "make_fixture_pe.py",
           "scan_leaks.py")


@pytest.mark.parametrize("script", SCRIPTS)
def test_help_exits_zero_with_usage_text(run_script, script):
    result = run_script(script, "--help")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip(), "no help text was printed"
    assert "usage:" in result.stdout.lower()
    assert script in result.stdout


@pytest.mark.parametrize("script", SCRIPTS)
def test_an_unknown_flag_is_a_usage_error(run_script, script):
    result = run_script(script, "--definitely-not-a-flag")
    assert result.returncode == 2
    assert result.stdout.strip() == ""
    assert "usage:" in result.stderr.lower()
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("script", [s for s in SCRIPTS if s != "scan_leaks.py"])
def test_a_script_with_no_arguments_never_hangs(run_script, script):
    """Each script either does its documented thing or reports a usage error; none hangs.

    The scanner is excluded here because its no-argument behaviour is to scan a tree rather than
    to fail; it has its own check below.
    """
    result = run_script(script, timeout=120)
    assert result.returncode in (0, 2), result


def test_scanner_with_no_arguments_scans_a_tree_and_states_its_verdict(run_script):
    """With no arguments it scans the tree its own script lives in, and says what it found."""
    result = run_script("scan_leaks.py", timeout=180)
    assert result.returncode in (0, 1), result
    assert "scanning" in result.stdout
    assert result.stdout.strip().endswith(
        "RESULT=clean" if result.returncode == 0 else "RESULT=findings")


# --- peutil ------------------------------------------------------------------

def test_reader_on_a_non_pe_exits_one_without_a_traceback(run_script, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("this is not a portable executable\n", encoding="utf-8")
    result = run_script("peutil.py", path)
    assert result.returncode == 1
    assert "error:" in result.stderr
    assert "no MZ signature" in result.stderr
    assert "Traceback" not in result.stderr
    assert result.stdout == ""


def test_reader_on_a_missing_file_exits_two(run_script, tmp_path):
    result = run_script("peutil.py", tmp_path / "absent.exe")
    assert result.returncode == 2
    assert "is not a file" in result.stderr
    assert "Traceback" not in result.stderr


def test_reader_on_a_truncated_image_reports_instead_of_raising(run_script, tmp_path, fixtures):
    """A file cut off mid-header goes through the exit-code contract, not through struct.

    A truncated image reaches an analyst as an interrupted download or a carved region far more
    often than as a malformed program, so what matters is the contract: one line on stderr and a
    documented code. Pinned after out-of-range reads were turned into a ParseError -- before that
    the caller got a traceback, which reads as a defect in the tool rather than a fact about the
    file.
    """
    path = tmp_path / "truncated.exe"
    path.write_bytes(fixtures.pe64.data[:0x100])
    result = run_script("peutil.py", path)
    assert result.returncode == 1
    assert "error:" in result.stderr
    assert "ends before" in result.stderr
    assert "Traceback" not in result.stderr


def test_reader_defaults_to_the_summary_view(run_script, fixtures):
    result = run_script("peutil.py", fixtures.pe64.path)
    assert result.returncode == 0
    assert "checksum" in result.stdout
    assert "sections" in result.stdout
    assert "amd64" in result.stdout


# --- pepatch -----------------------------------------------------------------

def test_patcher_on_a_non_pe_exits_three(run_script, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a PE\n", encoding="utf-8")
    result = run_script("pepatch.py", path, "--at-offset", "0", "--bytes", "CC", "--out",
                        tmp_path / "out.exe")
    assert result.returncode == 3
    assert "not a parseable PE" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "out.exe").exists()


def test_patcher_on_a_truncated_image_reports_instead_of_raising(run_script, tmp_path, fixtures):
    """Same contract as the reader's: a truncated image is an input, not a crash."""
    path = tmp_path / "truncated.exe"
    path.write_bytes(fixtures.pe64.data[:0x100])
    result = run_script("pepatch.py", path, "--at-offset", "0", "--bytes", "CC", "--out",
                        tmp_path / "out.exe")
    assert result.returncode == 3
    assert "not a parseable PE" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "out.exe").exists()


def test_patcher_on_a_missing_file_exits_two(run_script, tmp_path):
    result = run_script("pepatch.py", tmp_path / "absent.exe", "--at-offset", "0",
                        "--bytes", "CC", "--out", tmp_path / "out.exe")
    assert result.returncode == 2
    assert "is not a file" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("extra", [
    (),
    ("--bytes", "CC"),
    ("--at-offset", "0x410"),
])
def test_patcher_without_a_usable_spec_exits_two(run_script, fixtures, extra):
    result = run_script("pepatch.py", fixtures.pe64.path, *extra)
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_patcher_with_an_empty_patch_list_exits_two(run_script, fixtures, tmp_path):
    spec = tmp_path / "empty.json"
    spec.write_text('{"patches": []}', encoding="utf-8")
    result = run_script("pepatch.py", fixtures.pe64.path, "--spec", spec, "--out",
                        tmp_path / "out.exe")
    assert result.returncode == 2
    assert 'has no "patches" array' in result.stderr
    assert not (tmp_path / "out.exe").exists()


def test_patcher_with_a_missing_spec_file_uses_the_exit_code_vocabulary(run_script,
                                                                       fixtures, tmp_path):
    """A spec file that is not there is a usage error, and it says so in one line."""
    result = run_script("pepatch.py", fixtures.pe64.path, "--spec", tmp_path / "absent.json",
                        "--out", tmp_path / "out.exe")
    assert result.returncode == 2
    assert "is not a readable file" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "out.exe").exists()


# --- aob_scan ----------------------------------------------------------------

def test_locator_on_a_non_pe_exits_three(run_script, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a PE\n", encoding="utf-8")
    result = run_script("aob_scan.py", path, "--patterns", "48 8B")
    assert result.returncode == 3
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr


def test_locator_without_patterns_is_a_usage_error(run_script, fixtures):
    result = run_script("aob_scan.py", fixtures.pe64.path)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_locator_on_a_malformed_pattern_exits_nonzero_with_a_message(run_script, fixtures):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", "ZZ QQ")
    assert result.returncode == 1
    assert "not a byte" in result.stderr
    assert "Traceback" not in result.stderr


def test_locator_on_a_missing_file_exits_three(run_script, tmp_path):
    result = run_script("aob_scan.py", tmp_path / "absent.exe", "--patterns", "48 8B")
    assert result.returncode == 3
    assert "Traceback" not in result.stderr


# --- make_fixture_pe ---------------------------------------------------------

def test_fixture_builder_lists_its_recipes(run_script):
    result = run_script("make_fixture_pe.py", "--list-recipes")
    assert result.returncode == 0
    for recipe in ("default", "pe32", "bare", "fat-align", "thin-align", "no-virtual-tail"):
        assert recipe in result.stdout


def test_fixture_builder_without_an_output_path_is_a_usage_error(run_script):
    result = run_script("make_fixture_pe.py")
    assert result.returncode == 2
    assert "--out is required" in result.stderr
    assert "Traceback" not in result.stderr


def test_fixture_builder_rejects_an_unknown_recipe(run_script, tmp_path):
    result = run_script("make_fixture_pe.py", "--out", tmp_path / "x.exe",
                        "--recipe", "no-such-recipe")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_the_named_no_virtual_tail_recipe_builds(run_script, tmp_path):
    """The recipe names a property it removes, and it can be used to remove it.

    An earlier guard compared the .rdata payload against the requested tail itself, which
    inverted the relationship and made a zero-byte tail -- the whole point of the recipe --
    impossible to ask for. Pinned after the fix, because a recipe that is listed and cannot be
    built is a trap for whoever reads the list next.
    """
    out = tmp_path / "novtail.exe"
    result = run_script("make_fixture_pe.py", "--out", out, "--recipe", "no-virtual-tail")
    assert result.returncode == 0
    assert out.exists()
    assert "virtual_only_tail_bytes" in result.stdout or "wrote" in result.stdout


# --- scan_leaks --------------------------------------------------------------

def test_scanner_lists_its_rules_and_exemptions(run_script):
    result = run_script("scan_leaks.py", "--list-rules")
    assert result.returncode == 0
    assert "rules (18):" in result.stdout
    assert "exemptions (" in result.stdout
    assert "private-key-block" in result.stdout
    assert "tool or library name" in result.stdout


def test_scanner_on_a_missing_root_exits_two_and_states_the_result(run_script, tmp_path):
    result = run_script("scan_leaks.py", "--root", tmp_path / "absent")
    assert result.returncode == 2
    assert result.stdout.strip().endswith("RESULT=error")
    assert "is not a directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_scanner_on_a_clean_root_exits_zero(run_script, clean_scan_root):
    result = run_script("scan_leaks.py", "--root", clean_scan_root)
    assert result.returncode == 0
    assert "RESULT=clean" in result.stdout


def test_scanner_quiet_mode_prints_only_the_result_line(run_script, clean_scan_root):
    result = run_script("scan_leaks.py", "--root", clean_scan_root, "--quiet")
    assert result.returncode == 0
    assert result.stdout.strip() == "RESULT=clean"


def test_scanner_exit_code_three_is_documented_but_unreachable(run_script, tmp_path):
    """Measured deviation: the docstring promises 3 for an empty scan surface.

    No code path returns 3, so an empty surface is reported as `clean` with exit 0 -- the exact
    distinction the docstring says it is making. Pinned so the mismatch is visible.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    result = run_script("scan_leaks.py", "--root", empty)
    assert result.returncode == 0
    assert "RESULT=clean" in result.stdout
    assert "0 files" in result.stdout


def test_scanner_on_a_root_with_findings_exits_one(run_script, synthetic_leak_root):
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--quiet")
    assert result.returncode == 1
    assert result.stdout.strip() == "RESULT=findings"


def test_scanner_fail_on_any_raises_a_weak_only_surface_to_findings(run_script, tmp_path,
                                                                    weak_line):
    root = tmp_path / "weak"
    root.mkdir()
    (root / "note.md").write_text(weak_line + "\n", encoding="utf-8")
    default = run_script("scan_leaks.py", "--root", root, "--quiet")
    strict = run_script("scan_leaks.py", "--root", root, "--quiet", "--fail-on", "any")
    assert default.returncode == 0
    assert default.stdout.strip() == "RESULT=clean"
    assert strict.returncode == 1
    assert strict.stdout.strip() == "RESULT=findings"


def test_scanner_only_filter_selects_one_category(run_script, synthetic_leak_root):
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--only", "token",
                        "--format", "json")
    payload = json.JSONDecoder().raw_decode(result.stdout)[0]
    assert result.returncode == 1
    assert {hit["category"] for hit in payload["strong"]} == {"token"}
    assert payload["weak"] == []


def test_scanner_skip_filter_drops_a_category(run_script, synthetic_leak_root):
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--skip",
                        "token,path,device,endpoint,package,identity", "--format", "json")
    payload = json.JSONDecoder().raw_decode(result.stdout)[0]
    assert payload["strong"] == []
    assert payload["weak"] == []
    assert payload["verdict"] == "clean"
    assert result.returncode == 0


# --- hwprobe -----------------------------------------------------------------

def test_prober_reports_routes_without_failing_on_a_limited_host(run_script):
    """A missing capability is a finding, not a non-zero exit."""
    result = run_script("hwprobe.py", "--json", timeout=120)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["routes"]
    assert "Traceback" not in result.stderr


def test_prober_tool_inventory_mode_skips_the_cpu_rows(run_script):
    result = run_script("hwprobe.py", "--tools", "--json", timeout=120)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert "cpu" not in payload and "routes" not in payload
    assert payload["tools"] and payload["python_modules"]


def test_inspect_only_runs_leave_their_working_directory_clean(run_script, fixtures,
                                                               clean_scan_root):
    """A negative outcome: none of these inspect-only runs may write into the cwd or the input.

    The dry-run patcher is the case that matters: without ``--out`` it must report and stop.
    """
    workdir = fixtures.pe64.path.parent
    before = sorted(p.name for p in workdir.iterdir())
    digest = fixtures.pe64.sha256
    run_script("peutil.py", fixtures.pe64.path, cwd=workdir)
    run_script("aob_scan.py", fixtures.pe64.path, "--patterns", "48 8B", cwd=workdir)
    run_script("pepatch.py", fixtures.pe64.path, "--at-offset", "0x410", "--bytes", "CC",
               "--dry-run", cwd=workdir)
    run_script("scan_leaks.py", "--root", clean_scan_root, cwd=workdir)
    assert sorted(p.name for p in workdir.iterdir()) == before
    assert fixtures.pe64.sha256 == digest
