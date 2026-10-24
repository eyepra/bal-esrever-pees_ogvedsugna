"""Locator comparison between two builds of the same fixture.

`--across` answers one question: does the pattern still match the same number of sites on the
other build? A count that changes is a statement about the signature, not about the target, and
the point of these tests is that each of the three answers (same, changed, unusable either way)
is distinguishable in the output and in the exit code.
"""
import json
import shutil

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def rebuilt(run_script, tmp_path, fixtures):
    """A second, independently built copy of the same recipe."""
    out = tmp_path / "rebuilt.exe"
    result = run_script("make_fixture_pe.py", "--out", out, "--recipe", fixtures.pe64.recipe)
    assert result.returncode == 0, result.stderr
    return out


def test_same_recipe_reports_an_unchanged_hit_count(run_script, fixtures, rebuilt, hexpat):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", hexpat(b"fixture.pdb"),
                        "--across", rebuilt, "--json")
    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    entry = payload["patterns"][0]
    assert entry["hits"] == entry["across"]["hits"] == 1
    assert entry["across"]["same_count"] is True
    assert entry["across"]["verdict"] == "unique"
    assert payload["result"] == "ok"


def test_a_recipe_without_the_debug_directory_changes_the_hit_count(run_script, fixtures,
                                                                    hexpat):
    """The `bare` recipe has no debug directory, so the PDB pattern has nothing to match."""
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", hexpat(b"fixture.pdb"),
                        "--across", fixtures.bare.path, "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    entry = payload["patterns"][0]
    assert entry["hits"] == 1
    assert entry["across"]["hits"] == 0
    assert entry["across"]["same_count"] is False
    assert entry["across"]["verdict"] == "no-match"
    assert entry["across"]["sites"] == []
    assert payload["result"] == "needs-attention"


def test_an_equal_hit_count_is_not_the_same_as_a_usable_locator(run_script, fixtures):
    """Two hits on both sides: the count agrees and the pattern is still a coin flip."""
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", fixtures.pe64.plant,
                        "--across", fixtures.bare.path, "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    entry = payload["patterns"][0]
    assert entry["hits"] == entry["across"]["hits"] == 2
    assert entry["across"]["same_count"] is True
    assert entry["verdict"] == "ambiguous"
    assert payload["result"] == "needs-attention"


def test_the_text_view_explains_a_changed_count(run_script, fixtures, hexpat):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", hexpat(b"fixture.pdb"),
                        "--across", fixtures.bare.path)
    assert result.returncode == 1
    assert "hit count changed between builds" in result.stdout
    assert "across" in result.stdout


def test_the_text_view_explains_an_absent_pattern(run_script, fixtures, hexpat):
    result = run_script("aob_scan.py", fixtures.bare.path, "--patterns", hexpat(b"fixture.pdb"))
    assert result.returncode == 1
    assert "does not exist in this build" in result.stdout


def test_a_patch_invalidates_the_signature_it_was_located_with(run_script, fixtures, tmp_path,
                                                               hexpat):
    """The complete lesson of the two tools together, in one flow.

    The pattern that located the site includes the byte that gets patched, so after the patch the
    pattern no longer matches that site. `--across` between the original and the patched copy is
    what turns that from a silent hazard into a reported count change.
    """
    patched = tmp_path / "patched.exe"
    shutil.copyfile(str(fixtures.pe64.path), str(patched))
    applied = run_script("pepatch.py", patched, "--pattern", fixtures.pe64.plant,
                         "--at-hit", "0", "--expect", fixtures.pe64.plant,
                         "--bytes", " ".join(fixtures.pe64.plant.split()[:-2] + ["EB", "05"]),
                         "--out", patched)
    assert applied.returncode == 0, applied.stderr

    located_first = run_script("aob_scan.py", patched, "--patterns", fixtures.pe64.plant, "--json")
    assert located_first.returncode == 0
    after = json.loads(located_first.stdout)["patterns"][0]
    assert after["hits"] == 1, "the patched site no longer matches the pattern it was found with"
    assert after["verdict"] == "unique"
    assert after["sites"][0]["offset_hex"] == fixtures.pe64.meta["plant"]["second_file_offset"]

    # The hazard, made concrete: the same pattern with the same index now selects a different
    # site than it did before the patch, without any error from either tool.
    dry = run_script("pepatch.py", patched, "--pattern", fixtures.pe64.plant, "--at-hit", "0",
                     "--expect", fixtures.pe64.plant,
                     "--bytes", " ".join(fixtures.pe64.plant.split()[:-2] + ["EB", "05"]),
                     "--dry-run", "--json")
    assert dry.returncode == 0
    assert json.loads(dry.stdout)["applied"][0]["offset"] == \
        int(fixtures.pe64.meta["plant"]["second_file_offset"], 16)

    # Unpatched copy on the left, patched copy on the right: the counts disagree, and that is
    # reported rather than smoothed over.
    comparison = run_script("aob_scan.py", fixtures.pe64.path, "--patterns",
                            fixtures.pe64.plant, "--across", patched, "--json")
    assert comparison.returncode == 1
    entry = json.loads(comparison.stdout)["patterns"][0]
    assert entry["hits"] == 2
    assert entry["across"]["hits"] == 1
    assert entry["across"]["same_count"] is False


def test_comparing_against_a_non_pe_build_exits_three(run_script, fixtures, tmp_path):
    other = tmp_path / "not-a-pe.txt"
    other.write_text("this is not a portable executable\n", encoding="utf-8")
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", fixtures.pe64.plant,
                        "--across", other)
    assert result.returncode == 3
    assert "--across" in result.stderr
    assert "Traceback" not in result.stderr


def test_comparing_against_a_missing_build_exits_three(run_script, fixtures, tmp_path):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", fixtures.pe64.plant,
                        "--across", tmp_path / "absent.exe")
    assert result.returncode == 3
    assert "Traceback" not in result.stderr
