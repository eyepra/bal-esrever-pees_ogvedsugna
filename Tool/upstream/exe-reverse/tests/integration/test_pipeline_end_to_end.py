"""End-to-end flows over the generated fixture: locate, patch, re-read, verify.

No debugger, no driver, no network and no live target takes part. Every step is a script call,
and the assertions are on what the next script in the chain observes -- which is the property
that matters, because these tools are meant to agree with each other about one image.
"""
import hashlib
import json
import shutil

import pytest

pytestmark = pytest.mark.integration


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def work(tmp_path, fixtures):
    """An isolated copy of the PE32+ fixture, so a flow can never disturb another test."""
    target = tmp_path / "sample.exe"
    shutil.copyfile(str(fixtures.pe64.path), str(target))
    return target


def test_locate_patch_reread_round_trip(run_script, fixtures, work, tmp_path, hexpat):
    """The full chain, with each tool checked against what the next one reports."""
    patched = tmp_path / "patched.exe"
    first, second = fixtures.pe64.plant_offsets

    # 1. locate: the planted sequence is deliberately ambiguous, and the locator says so.
    located = run_script("aob_scan.py", work, "--patterns", fixtures.pe64.plant, "--json")
    assert located.returncode == 1
    plan = json.loads(located.stdout)
    assert plan["patterns"][0]["verdict"] == "ambiguous"
    site = plan["patterns"][0]["sites"][0]

    # 2. patch the first site only, keeping the replacement the same length as the site.
    replacement = " ".join(fixtures.pe64.plant.split()[:-2] + ["EB", "05"])
    applied = run_script("pepatch.py", work, "--pattern", fixtures.pe64.plant,
                         "--at-hit", "0", "--expect", fixtures.pe64.plant,
                         "--bytes", replacement, "--out", patched, "--json")
    assert applied.returncode == 0, applied.stderr
    result = json.loads(applied.stdout)
    claim = result["applied"][0]
    assert result["patches_applied"] == 1
    assert result["verify_problems"] == []

    # 3. the locator and the patcher must be talking about the same bytes.
    assert int(site["offset_hex"], 16) == claim["offset"] == first
    assert int(site["rva_hex"], 16) == int(claim["rva"], 16)
    assert claim["before"] == fixtures.pe64.plant
    assert claim["after"] == replacement
    assert claim["equal_length"] is True

    # 4. re-read the written file: the patch landed, the control site did not move, and the
    #    checksum was recomputed rather than left stale.
    reread = run_script("peutil.py", patched, "--summary", "--check-sum", "--json")
    assert reread.returncode == 0, reread.stderr
    report = json.loads(reread.stdout)
    assert report["summary"]["checksum_matches"] is True
    assert report["summary"]["checksum_declared"] == report["summary"]["checksum_computed"]
    assert report["checksum"]["matches"] is True
    assert report["summary"]["file_size"] == fixtures.pe64.size
    body = patched.read_bytes()
    assert body[first:first + 12] == bytes(int(b, 16) for b in replacement.split())
    assert body[second:second + 12] == fixtures.pe64.data[second:second + 12]

    # 5. nothing outside the site and the checksum field moved.
    checksum_field = int(fixtures.pe64.meta["checksum_offset"], 16)
    diff = {i for i, (a, b) in enumerate(zip(fixtures.pe64.data, body)) if a != b}
    assert diff - {first + 10} <= set(range(checksum_field, checksum_field + 4))
    assert first + 10 in diff


def test_control_run_that_changes_nothing_leaves_the_file_identical(run_script, fixtures, work,
                                                                   tmp_path):
    """The control for the flow above: a patch whose bytes equal the site's own bytes.

    This is the only zero-change run the pipeline has: a spec with an empty patch array is
    refused as a usage error, so a no-op patch is what "the pipeline ran and changed nothing"
    looks like. The output must be byte-identical to the input, checksum included.
    """
    out = tmp_path / "noop.exe"
    before = sha256(work)
    result = run_script("pepatch.py", work, "--at-offset", hex(fixtures.pe64.plant_offsets[0]),
                        "--expect", fixtures.pe64.plant, "--bytes", fixtures.pe64.plant,
                        "--out", out, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["checksum_recomputed"] is True
    assert payload["checksum_after"]["matches"] is True
    assert payload["output_sha256"] == payload["input_sha256"] == before
    assert sha256(out) == before
    assert sha256(work) == before


def test_an_empty_patch_array_is_refused_rather_than_writing_a_copy(run_script, fixtures, work,
                                                                    tmp_path):
    spec = tmp_path / "empty.json"
    spec.write_text('{"patches": []}', encoding="utf-8")
    out = tmp_path / "copy.exe"
    result = run_script("pepatch.py", work, "--spec", spec, "--out", out)
    assert result.returncode == 2
    assert not out.exists()
    assert sha256(work) == sha256(fixtures.pe64.path)


def test_the_flow_stops_before_writing_when_the_pattern_is_ambiguous(run_script, fixtures, work,
                                                                     tmp_path):
    out = tmp_path / "never.exe"
    before = sha256(work)
    result = run_script("pepatch.py", work, "--pattern", fixtures.pe64.plant,
                        "--bytes", "90 " * 12, "--out", out)
    assert result.returncode == 1
    assert "matched 2 sites" in result.stderr
    assert not out.exists()
    assert sha256(work) == before


def test_dry_run_reports_the_plan_and_writes_nothing(run_script, fixtures, work, tmp_path):
    out = tmp_path / "would-be.exe"
    before = sha256(work)
    result = run_script("pepatch.py", work, "--pattern", fixtures.pe64.plant, "--at-hit", "1",
                        "--expect", fixtures.pe64.plant, "--bytes", "CC " * 12,
                        "--dry-run", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["patches_applied"] == 1
    assert payload["applied"][0]["offset"] == fixtures.pe64.plant_offsets[1]
    assert not out.exists()
    assert sha256(work) == before


def test_a_spec_file_can_reach_a_branch_inside_a_longer_pattern(run_script, fixtures, work,
                                                               tmp_path):
    """The pattern-offset flow: anchor on a unique longer sequence, then patch the byte inside."""
    out = tmp_path / "branch.exe"
    site = fixtures.pe64.plant_offsets[0]
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({"patches": [{
        "name": "gate",
        "pattern": fixtures.pe64.plant + " CC",
        "pattern-offset": 10,
        "expect": "74",
        "bytes": "EB",
        "why": "invert the conditional branch, keeping the taken distance",
    }]}), encoding="utf-8")
    result = run_script("pepatch.py", work, "--spec", spec, "--out", out, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["patches_applied"] == 1
    record = payload["applied"][0]
    assert record["offset"] == site + 10
    assert record["before"] == "74"
    assert record["after"] == "EB"
    assert record["length_basis"] == "expect"
    assert record["why"].startswith("invert")

    reread = run_script("peutil.py", out, "--summary", "--check-sum", "--json")
    assert reread.returncode == 0
    assert json.loads(reread.stdout)["checksum"]["matches"] is True
    assert out.read_bytes()[site + 10] == 0xEB
    assert out.read_bytes()[site + 11] == 0x05


def test_a_length_change_is_refused_before_anything_is_written(run_script, fixtures, work,
                                                               tmp_path):
    out = tmp_path / "resized.exe"
    result = run_script("pepatch.py", work, "--at-offset", hex(fixtures.pe64.plant_offsets[0]),
                        "--expect", "48", "--bytes", "CC CC CC", "--out", out)
    assert result.returncode == 1
    assert "--allow-resize" in result.stderr
    assert not out.exists()

    allowed = tmp_path / "resized-allowed.exe"
    forced = run_script("pepatch.py", work, "--at-offset", hex(fixtures.pe64.plant_offsets[0]),
                        "--expect", "48", "--bytes", "CC CC CC", "--allow-resize",
                        "--out", allowed, "--json")
    assert forced.returncode == 0, forced.stderr
    payload = json.loads(forced.stdout)
    assert payload["structural"] == ["cli"]
    # One byte replaced by three: the file grows by two, and that is the structural edit the
    # caller asked for by passing --allow-resize.
    assert payload["output_size"] == payload["input_size"] + 2


def test_the_patched_output_still_parses_as_an_image(run_script, fixtures, work, tmp_path,
                                                     hexpat):
    """A patch that lands in the file must not damage a single header the reader trusts."""
    out = tmp_path / "patched.exe"
    result = run_script("pepatch.py", work, "--at-offset", "0x410", "--expect", "48 8B",
                        "--bytes", "CC 8B", "--out", out)
    assert result.returncode == 0, result.stderr
    full = run_script("peutil.py", out, "--summary", "--sections", "--imports", "--exports",
                      "--resources", "--tls", "--debug", "--relocs", "--check-sum", "--json")
    assert full.returncode == 0, full.stderr
    report = json.loads(full.stdout)
    assert report["summary"]["sha256"] == sha256(out)
    assert report["checksum"]["matches"] is True
    assert [s["name"] for s in report["summary"]["sections"]] == \
        [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    assert report["resources"][0]["path"] == ["VERSION", "1", "1033"]
    assert report["tls"]["callback_rvas"] == ["0x1000"]
    assert report["debug"][0]["format"] == "RSDS"
    assert report["imports"][0]["functions"][0]["name"] == "ImportedFunction"


def test_a_real_platform_image_reproduces_its_declared_checksum(run_script, platform_binary):
    """The fixture is synthetic; this is the same claim measured on a real system image."""
    result = run_script("peutil.py", platform_binary, "--summary", "--check-sum", "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["checksum_matches"] is True
    assert report["checksum"]["declared"] == report["checksum"]["computed"]
    assert report["summary"]["file_size"] == platform_binary.stat().st_size
    assert report["summary"]["sections"], "a platform image must have a section table"
