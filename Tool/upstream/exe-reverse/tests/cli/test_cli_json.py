"""Subprocess contract tests for the machine-readable output of every script.

One convention is not what a reader would assume, so it is asserted explicitly rather than
smoothed over: ``scan_leaks.py`` writes a JSON document and then a ``RESULT=`` line, so its
stdout as a whole is not valid JSON. The document parses from the front; the verdict line is
read from the end. A test pins that shape so a future change to either half is deliberate.
"""
import hashlib
import json

import pytest

pytestmark = pytest.mark.cli

# The reader's own view names, produced by the flags that populate them.
PEUTIL_VIEWS = {
    "--summary": "summary",
    "--sections": "section_detail",
    "--imports": "imports",
    "--exports": "exports",
    "--resources": "resources",
    "--rich": "rich_header",
    "--tls": "tls",
    "--debug": "debug",
    "--relocs": "base_relocations",
    "--entropy": "entropy",
    "--check-sum": "checksum",
}

# Always present, whatever the flags.
PEUTIL_ALWAYS = ("security_directory", "load_config")


def json_document(text):
    return json.JSONDecoder().raw_decode(text)[0]


def last_line(text):
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


# --- peutil ------------------------------------------------------------------

def test_reader_json_carries_the_summary_the_text_view_shows(run_script, fixtures):
    result = run_script("peutil.py", fixtures.pe64.path, "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert sorted(payload) == ["load_config", "security_directory", "summary"]
    summary = payload["summary"]
    assert summary["checksum_matches"] is True
    assert summary["checksum_declared"] == fixtures.pe64.meta["checksum"]
    assert summary["kind"] == "exe"
    assert summary["arch"] == "amd64"
    assert summary["file_size"] == fixtures.pe64.size
    assert summary["sections"] and len(summary["sections"]) == 5
    assert payload["security_directory"] is None
    assert payload["load_config"] is None


@pytest.mark.parametrize("flag,key", sorted(PEUTIL_VIEWS.items()))
def test_each_reader_view_lands_under_its_own_key(run_script, fixtures, flag, key):
    result = run_script("peutil.py", fixtures.pe64.path, flag, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert key in payload


def test_reader_json_with_every_view_present(run_script, fixtures):
    flags = [flag for flag in sorted(PEUTIL_VIEWS)]
    result = run_script("peutil.py", fixtures.pe64.path, *flags, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    for key in list(PEUTIL_VIEWS.values()) + list(PEUTIL_ALWAYS):
        assert key in payload, key
    assert payload["resources"][0]["path"] == ["VERSION", "1", "1033"]
    assert payload["tls"]["callback_rvas"] == ["0x1000"]
    assert payload["debug"][0]["format"] == "RSDS"
    assert payload["checksum"]["matches"] is True
    assert payload["imports"][0]["dll"] == "fixture-import.dll"
    assert payload["exports"]["dll_name"] == "fixture-export.dll"
    assert payload["rich_header"] is None          # the fixture has none, and says so
    assert payload["delay_imports"] == []
    assert payload["base_relocations"]["blocks"] == 1
    assert payload["section_detail"][0]["raw_tail"] == 0
    assert len(payload["entropy"]) == 5


def test_reader_json_of_a_bare_recipe_reports_the_absent_structures(run_script, fixtures):
    result = run_script("peutil.py", fixtures.bare.path, "--exports", "--resources", "--tls",
                        "--debug", "--json")
    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["exports"] is None
    assert payload["resources"] == []
    assert payload["tls"] is None
    assert payload["debug"] == []


def test_reader_json_is_decodable_ascii(run_script, fixtures):
    result = run_script("peutil.py", fixtures.pe64.path, "--json")
    assert result.stdout.isascii()


# --- pepatch -----------------------------------------------------------------

def test_patcher_dry_run_json_reports_the_plan_and_says_it_wrote_nothing(run_script, fixtures,
                                                                        tmp_path):
    out = tmp_path / "never.exe"
    result = run_script("pepatch.py", fixtures.pe64.path, "--at-offset", "0x410",
                        "--bytes", "CC CC", "--original-length", "2", "--dry-run", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["dry_run"] is True
    assert payload["patches_requested"] == 1
    assert payload["patches_applied"] == 1
    assert payload["errors"] == []
    assert payload["checksum_recomputed"] is False
    applied = payload["applied"][0]
    assert applied["offset"] == 0x410
    assert applied["rva"] == "0x1010"
    assert applied["before"] == "48 8B"
    assert applied["after"] == "CC CC"
    assert applied["equal_length"] is True
    assert applied["length_basis"] == "original-length"
    assert "output" not in payload
    assert not out.exists()


def test_patcher_real_run_json_reports_verification_and_the_new_checksum(run_script, fixtures,
                                                                        tmp_path):
    out = tmp_path / "patched.exe"
    result = run_script("pepatch.py", fixtures.pe64.path, "--at-offset", "0x410",
                        "--expect", "48 8B", "--bytes", "CC 8B", "--out", out, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["output"] == str(out)
    assert payload["output_size"] == payload["input_size"] == fixtures.pe64.size
    assert payload["verify_problems"] == []
    assert payload["checksum_after"]["matches"] is True
    assert payload["checksum_recomputed"] is True
    assert payload["signed_input"] is False
    assert payload["signature_note"] is None
    assert payload["structural"] == []
    assert payload["length_unproven"] == []
    assert out.read_bytes()[0x410:0x412] == b"\xCC\x8B"


def test_patcher_json_names_a_length_unproven_patch(load_script, run_script, fixtures, tmp_path):
    out = tmp_path / "unproven.exe"
    result = run_script("pepatch.py", fixtures.pe64.path, "--at-offset", "0x410",
                        "--bytes", "CC", "--out", out, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["applied"][0]["equal_length"] is None
    assert payload["length_unproven"] == ["cli"]
    assert payload["structural"] == []


def test_patcher_json_reports_a_refusal_without_an_output(run_script, fixtures, tmp_path):
    out = tmp_path / "never.exe"
    result = run_script("pepatch.py", fixtures.pe64.path, "--pattern", fixtures.pe64.plant,
                        "--bytes", "90 " * 12, "--out", out, "--json")
    assert result.returncode == 1
    assert not out.exists()
    assert "matched 2 sites" in result.stderr
    assert result.stdout.strip() == ""


# --- aob_scan ----------------------------------------------------------------

def test_locator_json_reports_a_unique_pattern_as_ok(run_script, fixtures, hexpat):
    pdb = hexpat(b"fixture.pdb")
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", pdb, "--json")
    assert result.returncode == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["result"] == "ok"
    assert payload["target_sections"] == [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    assert payload["section_filter"] is None
    entry = payload["patterns"][0]
    assert entry["hits"] == 1
    assert entry["verdict"] == "unique"
    assert entry["wildcards"] == 0
    assert entry["sites"][0]["section"] == ".rdata"


def test_locator_json_reports_the_planted_pair_as_ambiguous(run_script, fixtures):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", fixtures.pe64.plant,
                        "--json")
    assert result.returncode == 1, "an ambiguous pattern is the documented non-zero outcome"
    payload = json.loads(result.stdout)
    entry = payload["patterns"][0]
    assert entry["hits"] == 2
    assert entry["verdict"] == "ambiguous"
    assert payload["result"] == "needs-attention"
    offsets = [int(site["offset_hex"], 16) for site in entry["sites"]]
    assert offsets == list(fixtures.pe64.plant_offsets)
    assert [site["rva_hex"] for site in entry["sites"]] == \
        [fixtures.pe64.meta["plant"]["first_rva"], fixtures.pe64.meta["plant"]["second_rva"]]


def test_locator_json_reports_an_absent_pattern_as_a_no_match(run_script, fixtures):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", "DE AD BE EF CA FE",
                        "--json")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["patterns"][0]["hits"] == 0
    assert payload["patterns"][0]["verdict"] == "no-match"
    assert payload["patterns"][0]["sites"] == []


def test_locator_json_counts_wildcards_and_section_filtered_hits(run_script, fixtures):
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns",
                        "48 8B 05 ?? ?? ?? 00", "--section", ".text", "--json")
    payload = json.loads(result.stdout)
    entry = payload["patterns"][0]
    assert entry["wildcards"] == 3
    assert entry["hits"] == 2
    assert payload["section_filter"] == ".text"
    assert {site["section"] for site in entry["sites"]} == {".text"}


def test_locator_json_from_a_pattern_file_keeps_the_names(run_script, fixtures, tmp_path, hexpat):
    sigs = tmp_path / "sigs.txt"
    sigs.write_text("# comment\n%s\nnamed-site\t%s\n" % (fixtures.pe64.plant, hexpat(b"FIXT")),
                    encoding="utf-8")
    result = run_script("aob_scan.py", fixtures.pe64.path, "--patterns", sigs, "--json")
    payload = json.loads(result.stdout)
    names = [entry["name"] for entry in payload["patterns"]]
    assert names == ["sigs.txt:2", "named-site"]
    assert payload["patterns"][1]["hits"] >= 1


# --- scan_leaks --------------------------------------------------------------

def test_scanner_json_is_valid_json_ahead_of_the_result_line(run_script, synthetic_leak_root):
    """The document parses from the front; the RESULT line is not part of it."""
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--format", "json")
    assert result.returncode == 1
    payload = json_document(result.stdout)
    assert sorted(payload) == ["exempted", "files_scanned", "root", "strong", "verdict", "weak"]
    assert payload["verdict"] == "findings"
    assert payload["files_scanned"] >= 3
    assert last_line(result.stdout) == "RESULT=findings"


def test_scanner_json_stdout_is_not_valid_as_a_whole(run_script, synthetic_leak_root):
    """A negative outcome: nothing may treat this stdout as one JSON document."""
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--format", "json")
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stdout)


def test_scanner_json_reports_exactly_the_expected_rules(run_script, synthetic_leak_root):
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--format", "json",
                        "--show-exempt")
    payload = json_document(result.stdout)
    assert {hit["rule"] for hit in payload["strong"]} == {
        "private-key-block", "github-token", "aws-access-key", "slack-token",
        "generic-secret-assignment", "licence-blob-literal", "windows-user-profile",
        "posix-home", "windows-sid-literal", "volume-serial-literal",
        "literal-endpoint-with-creds", "public-ipv4-literal", "product-name-with-version",
    }
    assert {hit["rule"] for hit in payload["weak"]} == {
        "exe-name-with-version", "literal-host-with-path", "email-address",
        "vendor-copyright-line",
    }
    for hit in payload["strong"]:
        assert hit["strength"] == "strong"
        assert hit["file"].endswith("notes.md")
        assert hit["line"] > 0
        assert hit["context"]
    assert "machine-guid" not in {hit["rule"] for hit in payload["strong"]}


def test_scanner_json_show_exempt_records_the_suppressed_hits(run_script, synthetic_leak_root):
    """Measured: the machine-guid hit is suppressed by the bare-GUID exemption."""
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--format", "json",
                        "--show-exempt")
    payload = json_document(result.stdout)
    suppressed = {hit["rule"]: hit.get("exempt") for hit in payload["exempted"]}
    assert isinstance(payload["exempted"], list)
    assert suppressed.get("machine-guid") == \
        "a bare GUID is not machine identity without MachineGuid context"
    reasons = {hit["exempt"] for hit in payload["exempted"]
               if hit["rule"] == "product-name-with-version"}
    assert reasons and reasons <= {"tool or library name",
                                   "platform or vendor-of-the-platform term",
                                   "public protector/packer/managed tooling name"}


def test_scanner_json_without_show_exempt_reports_only_a_count(run_script, synthetic_leak_root):
    result = run_script("scan_leaks.py", "--root", synthetic_leak_root, "--format", "json")
    payload = json_document(result.stdout)
    assert isinstance(payload["exempted"], int)
    assert payload["exempted"] > 0


def test_scanner_json_on_a_clean_root_says_clean(run_script, clean_scan_root):
    result = run_script("scan_leaks.py", "--root", clean_scan_root, "--format", "json")
    assert result.returncode == 0
    payload = json_document(result.stdout)
    assert payload["verdict"] == "clean"
    assert payload["strong"] == []
    assert payload["weak"] == []


# --- make_fixture_pe ---------------------------------------------------------

def test_fixture_builder_json_describes_what_it_wrote(run_script, tmp_path):
    out = tmp_path / "described.exe"
    result = run_script("make_fixture_pe.py", "--out", out, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["path"] == str(out)
    assert payload["size"] == out.stat().st_size
    assert payload["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest()
    assert sorted(payload["sections"]) == [".data", ".rdata", ".reloc", ".rsrc", ".text"]
    plant = payload["plant"]
    assert plant["first_file_offset"] != plant["second_file_offset"]
    assert "planted twice" in plant["note"]
    assert payload["checksum"].startswith("0x")
    assert payload["virtual_only_tail_bytes"] > 0
    assert payload["executable_and_writable_code"] is True


def test_fixture_builder_is_byte_reproducible(run_script, tmp_path):
    first = tmp_path / "one.exe"
    second = tmp_path / "two.exe"
    a = run_script("make_fixture_pe.py", "--out", first, "--json")
    b = run_script("make_fixture_pe.py", "--out", second, "--json")
    assert a.returncode == b.returncode == 0
    assert json.loads(a.stdout)["sha256"] == json.loads(b.stdout)["sha256"]
    assert first.read_bytes() == second.read_bytes()


# --- hwprobe -----------------------------------------------------------------

# The route table is documented as three-state: available / needs-<x> / unavailable. Measured on
# this host, two rows carry a prose state instead of a vocabulary word. The values below are the
# ones actually produced; allowing them keeps the check honest without asserting the docstring.
ROUTE_STATES = ("available", "unavailable")
ROUTE_PROSE_STATES = (
    "CPU supports it, but a hypervisor is present",
    "needs-a-debugger, and a hypervisor is present",
    "no documented user-mode path on this platform",
)


def test_prober_json_reports_a_route_table(hwprobe_report):
    payload = hwprobe_report
    for key in ("python", "platform", "cpu", "os", "privilege", "routes", "tools",
                "python_modules"):
        assert key in payload, key
    assert payload["python"].startswith("3.")
    rows = payload["routes"]
    assert rows
    for row in rows:
        assert len(row) == 3, row
        name, state, why = row
        assert name and state and why
        assert name != state
    # The route that needs nothing but Python and a file on disk must be available when the
    # script that reports it is running at all.
    static = [row for row in rows if row[0].startswith("static PE analysis")]
    assert len(static) == 1
    assert static[0][1] == "available"


def test_route_states_use_the_vocabulary_or_a_measured_deviation(hwprobe_report):
    """Measured: not every route state is one of the three documented states.

    Two rows on this host answer with a sentence instead of a vocabulary word, so the
    three-state claim in the docstring holds for the table's shape but not for every cell. The
    measured sentence forms are listed rather than asserted as required, so a fix to the
    vocabulary passes and a new unmeasured sentence fails loudly.
    """
    for row in hwprobe_report["routes"]:
        state = row[1]
        assert state in ROUTE_STATES or state.startswith("needs-") \
            or state in ROUTE_PROSE_STATES, state


def test_prober_rows_carry_a_measurement_and_a_note(hwprobe_report):
    payload = hwprobe_report
    for group in ("cpu", "os", "privilege"):
        assert payload[group], group
        for row in payload[group]:
            assert set(row) >= {"state", "value", "note"}, (group, row)
            assert row["state"] in ROUTE_STATES or row["state"].startswith("needs-"), row


def test_prober_can_dump_raw_cpuid_registers(run_script, hwprobe_report):
    """A requested CPUID dump must be non-empty -- where CPUID is reachable at all.

    The probe's own report says which of those two situations this host is in, so the test reads it
    instead of assuming x64 Windows: on a non-x64 or non-Windows host the stub cannot run, and
    "nothing was reported" is the correct answer rather than a defect. A missing capability is a
    skip with the probe's own note, never a red test (tests/README.md, conftest.py).
    """
    cpu = hwprobe_report["cpu"][0]
    if cpu["state"] != "available":
        pytest.skip("CPUID is not reachable on this host, so there is no register dump to check: %s"
                    % cpu["note"])
    result = run_script("hwprobe.py", "--raw", "--json", timeout=120)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["raw_cpuid"], "a raw dump was requested but nothing was reported"


# --- pe_triage ---------------------------------------------------------------

def test_triage_reports_identity_and_leaves_the_sample_untouched(fixtures, run_script):
    """The first script a task should run: it parses, classifies, and must not write."""
    sample = fixtures.pe64
    before = sample.data
    result = run_script("pe_triage.py", sample.path, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["sha256"] == sample.sha256
    assert payload["identity"]["arch"] == "amd64"
    assert payload["identity"]["bitness"] == 64
    assert payload["identity"]["kind"] == "exe"
    assert sample.data == before, "triage modified the image it was reading"


# --- pe_diff -----------------------------------------------------------------

def test_diff_of_the_same_build_reports_no_material_change(fixtures, run_script):
    """Self-comparison is the control for every other diff: it must find nothing."""
    sample = fixtures.pe64
    result = run_script("pe_diff.py", sample.path, sample.path, "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["verdict"] == "identical-modulo-normalised-fields"
    assert payload["material_change"] is False
    assert payload["byte_diff"]["differ_bytes"] == 0
