"""Unit tests for skills/exe-reverse/scripts/scan_leaks.py.

Two failure modes are tested at once, because only one of them is obvious. A scanner that misses
a pasted key is dangerous; a scanner that flags `x64dbg`, `PE32+` or a reserved documentation
address gets switched off, which is equally dangerous and much easier to do. So every rule is
asserted to fire on a shaped sample, and every exemption class is asserted to stay quiet.

Three measured observations are pinned here rather than hidden, because each is a false negative
or a dead branch in the rule table:

* the bare-GUID exemption matches inside the machine-guid rule's own match text, so that rule
  cannot produce a finding;
* the `.NET` entry in the platform list matches any `.net` TLD, so a hit inside such a URL or
  address is suppressed as a platform term;
* the ``<[a-z_]+>`` placeholder alternative is wrapped in ``\\b`` on both sides, so it cannot
  match bracketed prose.

The shaped samples come from the corpus in conftest.py, which assembles them from fragments so
that this suite does not itself trip the scan it tests.
"""
import pathlib

import pytest

# The rules the exemption list structurally suppresses: a hit exists, and an exemption claims
# it, so the rule cannot produce a finding. Measured, and re-asserted below so a fix shows up as
# a test change rather than as a quietly gained finding.
SUPPRESSED_RULES = ("machine-guid",)

pytestmark = pytest.mark.unit


def findings_in(scan_leaks, text):
    """What main() would report: hits that no exemption suppresses."""
    out = []
    for hit in scan_leaks.scan_text(text):
        if scan_leaks.exempt_reason(hit["match"]) or scan_leaks.exempt_reason(hit["context"]):
            continue
        out.append(hit)
    return out


@pytest.fixture
def corpus(leak_lines):
    return dict(leak_lines)


@pytest.fixture
def exemption_corpus(exempt_lines):
    return dict(exempt_lines)


# --- every rule fires --------------------------------------------------------

def test_every_rule_fires_on_its_shaped_sample(load_script, leak_lines):
    scan = load_script("scan_leaks.py")
    missing = []
    for rule, line in leak_lines:
        fired = {hit["rule"] for hit in scan.scan_text(line)}
        if rule not in fired:
            missing.append((rule, sorted(fired)))
    assert missing == []


def test_every_rule_except_the_suppressed_ones_is_reportable(load_script, leak_lines):
    scan = load_script("scan_leaks.py")
    suppressed = set(SUPPRESSED_RULES)
    unexpected = []
    for rule, line in leak_lines:
        reported = {hit["rule"] for hit in findings_in(scan, line)}
        if rule in suppressed:
            if rule in reported:
                unexpected.append((rule, "expected to be suppressed by the exemption list"))
        elif rule not in reported:
            unexpected.append((rule, "not reported"))
    assert unexpected == []
    assert suppressed == {"machine-guid"}


def test_the_rule_table_is_well_formed(load_script):
    scan = load_script("scan_leaks.py")
    names = [name for _c, _s, name, _p, _w in scan.RULES]
    assert len(names) == len(set(names)) == len(scan.RULES) == 18
    assert {strength for _c, strength, _n, _p, _w in scan.RULES} == {"strong", "weak"}
    for category, strength, name, pattern, why in scan.RULES:
        assert category and name and why, (category, name)
        assert strength in ("strong", "weak")
        assert pattern.pattern, name


# --- the three measured deviations ------------------------------------------

def test_machine_guid_rule_fires(load_script, corpus):
    scan = load_script("scan_leaks.py")
    hits = list(scan.scan_text(corpus["machine-guid"]))
    assert [h["rule"] for h in hits] == ["machine-guid"]


def test_machine_guid_finding_is_suppressed_by_the_bare_guid_exemption(load_script, corpus):
    """Measured: the bare-GUID exemption matches inside this rule's own match text.

    Recorded here so that a change to either list shows up as a test change instead of as a
    silently gained or lost finding.
    """
    scan = load_script("scan_leaks.py")
    line = corpus["machine-guid"]
    hit = list(scan.scan_text(line))[0]
    assert "bare GUID is not machine identity" in scan.exempt_reason(hit["match"])
    assert findings_in(scan, line) == []


def test_a_url_finding_is_not_swallowed_by_an_exemption(load_script, corpus):
    """A concrete host must still be reported, and only as the weak finding the rule declares.

    Measured, twice: while this suite was being written, a standard-name exemption alternative
    matched the `HTTP` inside every `https?://` URL and swallowed the rule's every hit. The
    assertion below is the state after that was corrected -- a URL hit is reported, at weak
    strength, with no exemption claiming it. `benchmark.md` records both states.
    """
    scan = load_script("scan_leaks.py")
    line = corpus["literal-host-with-path"]
    hits = list(scan.scan_text(line))
    assert [h["rule"] for h in hits] == ["literal-host-with-path"]
    assert hits[0]["strength"] == "weak"
    assert scan.exempt_reason(hits[0]["match"]) is None
    reported = findings_in(scan, line)
    assert [hit["rule"] for hit in reported] == ["literal-host-with-path"]


def test_a_net_domain_hides_a_hit_behind_the_platform_exemption(load_script, corpus,
                                                                exemption_corpus):
    """Measured deviation: `.NET` in the platform list matches any `.net` TLD.

    A bare domain under `.net` is therefore read as a platform term while the same domain under
    another TLD is not, which is a false negative rather than a rule. Pinned, not endorsed.
    """
    scan = load_script("scan_leaks.py")
    net_url = exemption_corpus["net tld"]
    org_url = corpus["literal-host-with-path"]
    assert net_url.endswith(".net/v2/activate") and org_url.endswith(".org/v2/activate")
    assert "platform or vendor" in scan.exempt_reason(net_url)
    # Isolate the cause to the TLD: the same names under another TLD claim no platform exemption.
    assert scan.exempt_reason("licensing.hexweld.net") is not None
    assert scan.exempt_reason("licensing.hexweld.org") is None


def test_the_bracketed_placeholder_form_is_unreachable_in_prose(load_script):
    """Measured: `<[a-z_]+>` sits inside `\\b...\\b`, so bracketed prose never matches."""
    scan = load_script("scan_leaks.py")
    assert scan.exempt_reason("<user>") is None
    assert scan.exempt_reason("a <user> b") is None
    assert scan.PLACEHOLDER_HINT.search("a <user> b") is None
    # Only word-character adjacency reaches it, which is why a bare TARGET is the form that works.
    assert scan.PLACEHOLDER_HINT.search("x<user>x") is not None
    assert scan.exempt_reason("TARGET") == "placeholder token"


# --- exemptions --------------------------------------------------------------

@pytest.mark.parametrize("sample,reason", [
    ("x64dbg", "tool or library name"),
    ("WinDbg", "tool or library name"),
    ("IDA", "tool or library name"),
    ("CFF Explorer", "tool or library name"),
    ("the copy is packed with UPX", "public protector/packer/managed tooling name"),
    ("Themida", "public protector/packer/managed tooling name"),
    ("IMAGE_NT_HEADERS", "format, standard or platform term"),
    ("CWE-119", "format, standard or platform term"),
    ("Authenticode", "format, standard or platform term"),
    ("Windows", "platform or vendor-of-the-platform term"),
    ("PowerShell", "platform or vendor-of-the-platform term"),
    ("TARGET", "placeholder token"),
    ("YOURAPP", "placeholder token"),
    ("REDACTED", "placeholder token"),
    ("x<user>x", "placeholder token"),
    ("192.0.2.44", "reserved documentation address"),
    ("198.51.100.7", "reserved documentation address"),
    ("203.0.113.9", "reserved documentation address"),
    ("127.0.0.1", "reserved documentation address"),
    ("S-1-5-18", "well-known SID"),
    ("3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071", "bare GUID is not machine identity"),
])
def test_exempt_reason_classifies_the_classes_that_must_stay(load_script, sample, reason):
    """The reason is asserted by the class it names, not by its exact prose.

    The wording of a reason is a message, and messages get reworded; which exemption class
    claims a sample is the behaviour under test.
    """
    assert reason in load_script("scan_leaks.py").exempt_reason(sample)


def test_exempt_reason_does_not_excuse_a_real_finding(load_script, corpus):
    """A negative outcome: the exemption list must not swallow target identity."""
    scan = load_script("scan_leaks.py")
    for rule in ("private-key-block", "github-token", "windows-user-profile", "posix-home",
                 "windows-sid-literal", "volume-serial-literal", "product-name-with-version"):
        assert scan.exempt_reason(corpus[rule]) is None, rule


@pytest.mark.parametrize("label", [
    "tool name", "protector name", "format term", "platform term", "placeholder token",
    "documentation address", "well-known SID", "loopback and example", "machine guid context",
    "net tld",
])
def test_exemption_classes_are_never_reported(load_script, exemption_corpus, label):
    assert findings_in(load_script("scan_leaks.py"), exemption_corpus[label]) == [], label


# --- scan_text ---------------------------------------------------------------

def test_scan_text_reports_position_and_strength(load_script, corpus):
    scan = load_script("scan_leaks.py")
    text = "line one is clean\nsecond line: " + corpus["private-key-block"] + "\n"
    hits = list(scan.scan_text(text))
    assert len(hits) == 1
    hit = hits[0]
    assert hit["line"] == 2
    assert hit["col"] == 14
    assert hit["strength"] == "strong"
    assert hit["category"] == "token"
    assert hit["rule"] == "private-key-block"
    assert hit["why"]
    assert corpus["private-key-block"] in hit["match"]
    assert hit["context"].startswith("second line:")


def test_clean_text_produces_no_hits_at_all(load_script):
    """A negative outcome: a clean note must not produce a single hit of any strength."""
    scan = load_script("scan_leaks.py")
    text = ("## Triage\n\nRead the section table with peutil.py and printed the entropy.\n"
            "The checksum matched the declared value, so the image was not hand-edited.\n")
    assert list(scan.scan_text(text)) == []


def test_scan_text_does_not_report_the_same_line_as_a_different_rule(load_script, corpus):
    scan = load_script("scan_leaks.py")
    hits = scan.scan_text(corpus["generic-secret-assignment"])
    assert [h["rule"] for h in hits] == ["generic-secret-assignment"]


# --- file selection ----------------------------------------------------------

def test_iter_files_skips_binaries_and_cache_directories(load_script, tmp_path, corpus):
    """A negative outcome: the scanner must not walk binaries, caches or VCS metadata."""
    scan = load_script("scan_leaks.py")
    root = tmp_path / "repo"
    (root / "__pycache__").mkdir(parents=True)
    (root / ".git").mkdir()
    (root / "notes.md").write_text("clean\n", encoding="utf-8")
    (root / "trap.exe").write_bytes(corpus["private-key-block"].encode("ascii") + b"\n")
    (root / "trap.png").write_bytes(corpus["github-token"].encode("ascii"))
    (root / "__pycache__" / "cached.md").write_text(corpus["private-key-block"] + "\n",
                                                    encoding="utf-8")
    (root / ".git" / "config.md").write_text(corpus["private-key-block"] + "\n",
                                             encoding="utf-8")
    found = sorted(pathlib.Path(p).relative_to(root).as_posix()
                   for p in scan.iter_files(str(root)))
    assert found == ["notes.md"]


def test_iter_files_honours_an_explicit_file_list(load_script, tmp_path):
    scan = load_script("scan_leaks.py")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.md").write_text("a\n", encoding="utf-8")
    (root / "b.md").write_text("b\n", encoding="utf-8")
    listing = tmp_path / "listed.txt"
    listing.write_text("a.md\nmissing.md\n\n", encoding="utf-8")
    found = sorted(pathlib.Path(p).relative_to(root).as_posix()
                   for p in scan.iter_files(str(root), str(listing)))
    assert found == ["a.md"]
