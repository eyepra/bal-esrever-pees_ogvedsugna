"""Subprocess contract tests for skills/exe-reverse/scripts/capabilities.py and doctor.py.

The exit codes are the ones the two docstrings publish -- 0 all ok, 3 something blocked, 2 usage
error, 4 internal -- and the last stdout line is a `RESULT=<token>` for both.

One convention is pinned because it is not what a reader would assume: `capabilities.py --list`
prints `RESULT=capabilities_ok` whatever the registry says, because listing ids and names probes
nothing. The test asserts the contrast directly -- the same registry resolved through `--json` exits
3 on this host while `--list` exits 0 -- so a future change to either half is deliberate.
"""
import json

import pytest

pytestmark = pytest.mark.cli

BLOCKED_TOKEN = "capabilities_blocked"


def json_document(text):
    return json.JSONDecoder().raw_decode(text)[0]


def last_line(text):
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def result_token(text):
    line = last_line(text)
    assert line.startswith("RESULT="), "the last line was %r" % line
    return line.split("=", 1)[1]


# --- capabilities.py ---------------------------------------------------------

def test_list_prints_every_id_and_name(run_script, load_script):
    caps = load_script("capabilities.py")
    result = run_script("capabilities.py", "--list")
    for capability_id in caps.CAPABILITIES:
        assert capability_id in result.stdout, capability_id
    assert "%d capabilities." % len(caps.CAPABILITIES) in result.stdout
    # The list now carries a real verdict rather than an unconditional one, so the exit code and
    # the token have to agree with what resolving the same registry reports.
    token, code = caps.verdict(caps.resolve_all())
    assert result.returncode == code
    assert result.stdout.strip().endswith("RESULT=%s" % caps.TOKENS[token])


def test_list_and_json_agree_on_the_same_registry(run_script):
    """Two views of one table must not disagree about it.

    The list view used to print the ok token and exit 0 unconditionally while the JSON view of the
    same registry exited 3 on this host, because most of the table is blocked here by design --
    every `artifact:` row waits for an operator to supply one. A report that contradicts another
    report of the same data is worse than either alone: a reader cannot tell which to believe.
    """
    listed = run_script("capabilities.py", "--list")
    resolved = run_script("capabilities.py", "--json")
    assert result_token(listed.stdout) == result_token(resolved.stdout)
    assert listed.returncode == resolved.returncode


def test_json_reports_every_capability_with_its_closure(run_script, load_script):
    caps = load_script("capabilities.py")
    result = run_script("capabilities.py", "--json")
    assert result.returncode in (0, 3), result.stderr
    rows = json_document(result.stdout)
    assert [row["id"] for row in rows] == list(caps.CAPABILITIES)
    for row in rows:
        assert set(row) >= {"id", "name", "state", "required", "any_of", "depends_on",
                            "blocked_deps", "missing", "closure", "scripts", "note"}
        assert row["state"] in ("ok", "blocked")
        assert row["closure"][0] == row["id"]
    assert result_token(result.stdout) == (BLOCKED_TOKEN if result.returncode == 3
                                          else "capabilities_ok")


def test_one_capability_reports_its_closure_and_its_state(run_script):
    """`pe_structure_read` needs the interpreter and a script this kit ships, so it is ok anywhere."""
    result = run_script("capabilities.py", "pe_structure_read")
    assert result.returncode == 0, result.stderr
    assert "capability: Read a PE image's structure" in result.stdout
    assert "scripts   : peutil.py" in result.stdout
    assert "requires  : python310, file:peutil.py" in result.stdout
    assert "state     : ok" in result.stdout
    assert result.stdout.strip().endswith("RESULT=capabilities_ok")


def test_one_blocked_capability_names_the_atom_no_install_can_supply(run_script):
    result = run_script("capabilities.py", "commandline_debug")
    assert result.returncode == 3, result.stdout
    assert "state     : blocked" in result.stdout
    assert "missing atom : artifact:sample" in result.stdout
    assert "next action" not in result.stdout, "an artifact has no install line"
    assert result.stdout.strip().endswith("RESULT=%s" % BLOCKED_TOKEN)


def test_one_capability_as_json_carries_the_same_fields(run_script):
    result = run_script("capabilities.py", "pe_structure_read", "--json")
    assert result.returncode == 0, result.stderr
    row = json_document(result.stdout)
    assert row["id"] == "pe_structure_read"
    assert row["state"] == "ok"
    assert row["missing"] == []
    assert row["blocked_deps"] == []
    assert result.stdout.strip().endswith("RESULT=capabilities_ok")


def test_an_unknown_capability_is_a_usage_error_on_stdout_and_stderr(run_script):
    result = run_script("capabilities.py", "no_such_capability")
    assert result.returncode == 2
    assert result.stdout.strip() == "RESULT=usage_error"
    assert "no such capability" in result.stderr
    assert "Traceback" not in result.stderr


def test_verbose_prints_the_next_action_for_a_blocked_capability(run_script, load_script):
    caps = load_script("capabilities.py")
    installable = [caps.ATOMS[atom].get("install")
                   for row in caps.resolve_all(caps.Probe(tool_dirs=caps.extra_tool_dirs()))
                   if row["state"] != "ok"
                   for atom, _detail in row["missing"]
                   if caps.ATOMS.get(atom, {}).get("install")]
    if not installable:
        pytest.skip("this host has no blocked capability whose missing atom carries an install "
                    "line, so there is nothing for --verbose to print here")
    result = run_script("capabilities.py", "--verbose")
    assert result.returncode in (0, 3), result.stderr
    assert "missing atom" in result.stdout
    assert "next action  :" in result.stdout
    assert "est. minutes :" in result.stdout
    assert "(basis: " in result.stdout


def test_an_unknown_flag_is_a_usage_error(run_script):
    result = run_script("capabilities.py", "--definitely-not-a-flag")
    assert result.returncode == 2
    assert result.stdout.strip() == ""
    assert "usage:" in result.stderr.lower()
    assert "Traceback" not in result.stderr


def test_help_exits_zero(run_script):
    result = run_script("capabilities.py", "--help")
    assert result.returncode == 0
    assert "usage:" in result.stdout.lower()


def test_an_extra_tool_directory_can_turn_a_blocked_capability_ok(run_script, load_script,
                                                                 tmp_path):
    """`--tools-dir` is the documented second search path; a tool off PATH is not a missing tool."""
    caps = load_script("capabilities.py")
    baseline = caps.resolve("static_disassembly",
                            caps.Probe(tool_dirs=caps.extra_tool_dirs()))
    if baseline["state"] == "ok":
        pytest.skip("a disassembly backend is already reachable here (%s), so the extra directory "
                    "cannot demonstrate anything" % baseline["alternatives_present"])

    tools = tmp_path / "unpacked-tools"
    tools.mkdir()
    for name in ("ghidra", "ida64"):
        (tools / name).write_text("", encoding="utf-8")
    result = run_script("capabilities.py", "static_disassembly", "--tools-dir", tools)
    assert result.returncode == 0, result.stdout
    assert "present   :" in result.stdout
    assert "EXEREV_TOOLS" in result.stdout


# --- doctor.py ---------------------------------------------------------------

@pytest.fixture(scope="module")
def default_run(run_script):
    """One full doctor run for the module: it probes the host and answers --help for every script."""
    return run_script("doctor.py", timeout=180)


@pytest.fixture(scope="module")
def json_run(run_script):
    return run_script("doctor.py", "--json", timeout=180)


def test_the_doctor_exits_zero_or_three_and_never_with_a_traceback(default_run):
    assert default_run.returncode in (0, 3), default_run
    assert "Traceback" not in default_run.stdout + default_run.stderr


def test_the_doctor_prints_its_three_blocks_and_a_result_line(default_run, load_script):
    doctor = load_script("doctor.py")
    assert "== capabilities ==" in default_run.stdout
    assert "== scripts ==" in default_run.stdout
    assert "== environment facts that can change a result ==" in default_run.stdout
    assert "== result ==" in default_run.stdout
    assert "%d script(s) checked" % len(doctor.discover_scripts()) in default_run.stdout
    assert result_token(default_run.stdout) in ("env_ok", "env_partial", "env_blocked")


def test_the_result_token_follows_the_exit_code(default_run):
    token = result_token(default_run.stdout)
    if default_run.returncode == 3:
        assert token == "env_blocked"
    else:
        assert token in ("env_ok", "env_partial")


def test_the_script_table_counts_the_scripts_that_are_actually_there(default_run, load_script):
    doctor = load_script("doctor.py")
    total = len(doctor.discover_scripts())
    assert "registered/checked = %d / %d" % (total, total) in default_run.stdout


def test_json_carries_the_four_sections_and_a_summary(json_run, load_script):
    """The counts are cross-checked against the rows they summarise, so a script that stops being
    classified shows up as a mismatch rather than as a smaller denominator."""
    doctor = load_script("doctor.py")
    assert json_run.returncode in (0, 3), json_run.stderr
    payload = json_document(json_run.stdout)
    assert sorted(payload) == ["capabilities", "environment", "result", "scripts", "summary"]
    total = len(doctor.discover_scripts())
    assert len(payload["scripts"]) == total
    assert payload["summary"]["scripts_checked"] == total
    unknown = [row for row in payload["scripts"] if row["capability_source"] == "unknown"]
    assert payload["summary"]["scripts_with_unknown_capability"] == len(unknown)
    assert payload["summary"]["capabilities_total"] == len(payload["capabilities"])
    assert payload["result"] == result_token(json_run.stdout)
    for row in payload["scripts"]:
        assert set(row) == {"script", "capabilities", "capability_source", "capability_state",
                            "runnable", "third_party", "detail"}


def test_json_environment_facts_carry_the_documented_keys(json_run):
    payload = json_document(json_run.stdout)
    if len(payload["environment"]) == 1 and payload["environment"][0]["fact"] == "host probe":
        pytest.skip("the host probe could not answer here, so the fact table is inert")
    for fact in payload["environment"]:
        assert set(fact) == {"fact", "value", "effect", "severity"}
        assert fact["severity"] in ("note", "warn")


def test_each_view_flag_prints_only_its_own_block(run_script):
    scripts_only = run_script("doctor.py", "--scripts", timeout=180)
    assert scripts_only.returncode in (0, 3), scripts_only
    assert "== scripts ==" in scripts_only.stdout
    assert "== capabilities ==" not in scripts_only.stdout
    assert "== environment facts" not in scripts_only.stdout
    assert "RESULT=" in scripts_only.stdout

    environment_only = run_script("doctor.py", "--environment", timeout=180)
    assert environment_only.returncode in (0, 3), environment_only
    assert "== environment facts" in environment_only.stdout
    assert "== scripts ==" not in environment_only.stdout
    assert "== capabilities ==" not in environment_only.stdout


def test_an_unknown_flag_is_a_usage_error_without_a_traceback(run_script):
    result = run_script("doctor.py", "--definitely-not-a-flag")
    assert result.returncode == 2
    assert "usage:" in result.stderr.lower()
    assert "Traceback" not in result.stderr
    assert result.stdout.strip() == ""
