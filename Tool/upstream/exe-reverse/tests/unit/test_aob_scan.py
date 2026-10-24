"""Unit tests for skills/exe-reverse/scripts/aob_scan.py.

The tool's real output is the *verdict*: a pattern that matches twice is a coin flip, and the
whole point is that the caller is told so. The boundary table is asserted at both sides of each
threshold, and the pattern-file parser is tested in all four of its accepted shapes.
"""
import types

import pytest

pytestmark = pytest.mark.unit


def ns(**kwargs):
    base = {"patterns": []}
    base.update(kwargs)
    return types.SimpleNamespace(**base)


# --- verdict boundaries ------------------------------------------------------

@pytest.mark.parametrize("count,expected", [
    (0, "no-match"),
    (1, "unique"),
    (2, "ambiguous"),
    (3, "ambiguous"),
    (7, "ambiguous"),
    (8, "pervasive"),
    (64, "pervasive"),
])
def test_verdict_boundaries(load_script, count, expected):
    assert load_script("aob_scan.py").verdict(count, count) == expected


def test_verdict_thresholds_are_the_documented_ones(load_script):
    aob = load_script("aob_scan.py")
    assert aob.NOTICEABLE_AT == 8
    assert aob.AMBIGUOUS_AT == 2
    assert aob.verdict(aob.NOTICEABLE_AT - 1, 0) == "ambiguous"
    assert aob.verdict(aob.NOTICEABLE_AT, 0) == "pervasive"


def test_verdict_ignores_the_unused_total_argument(load_script):
    aob = load_script("aob_scan.py")
    assert aob.verdict(1, 999) == aob.verdict(1, 0) == "unique"


# --- locate ------------------------------------------------------------------

def test_locate_reports_offset_rva_and_section(load_script, fixtures):
    aob = load_script("aob_scan.py")
    peutil = load_script("peutil.py")
    pepatch = load_script("pepatch.py")
    pe = peutil.PE(fixtures.pe64.data, None)
    pat = pepatch.parse_bytes(fixtures.pe64.plant)[0]
    rows = aob.locate(pe, fixtures.pe64.data, pat)
    assert [r["offset"] for r in rows] == list(fixtures.pe64.plant_offsets)
    assert [r["rva_hex"] for r in rows] == [fixtures.pe64.meta["plant"]["first_rva"],
                                            fixtures.pe64.meta["plant"]["second_rva"]]
    assert [r["section"] for r in rows] == [".text", ".text"]
    assert rows[0]["offset_hex"] == fixtures.pe64.meta["plant"]["first_file_offset"]


def test_locate_section_filter_drops_hits_elsewhere(load_script, fixtures):
    aob = load_script("aob_scan.py")
    peutil = load_script("peutil.py")
    pat = [0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x2E, 0x70, 0x64, 0x62]   # "fixture.pdb"
    pe = peutil.PE(fixtures.pe64.data, None)
    assert [r["section"] for r in aob.locate(pe, fixtures.pe64.data, pat)] == [".rdata"]
    assert aob.locate(pe, fixtures.pe64.data, pat, section_filter=".text") == []
    assert len(aob.locate(pe, fixtures.pe64.data, pat, section_filter=".rdata")) == 1


def test_locate_context_is_centred_on_the_match(load_script, fixtures):
    aob = load_script("aob_scan.py")
    peutil = load_script("peutil.py")
    pepatch = load_script("pepatch.py")
    pe = peutil.PE(fixtures.pe64.data, None)
    pat = pepatch.parse_bytes(fixtures.pe64.plant)[0]
    rows = aob.locate(pe, fixtures.pe64.data, pat, context=8)
    assert "context" in rows[0]
    assert rows[0]["context_marks"] == "pre 8 bytes, match 12, post 8"
    assert len(pepatch.parse_bytes(rows[0]["context"])[0]) == len(pat) + 16


def test_locate_returns_no_rows_when_the_pattern_is_absent(load_script, fixtures):
    """A negative outcome: an absent pattern yields an empty list, not a nearest match."""
    aob = load_script("aob_scan.py")
    peutil = load_script("peutil.py")
    pe = peutil.PE(fixtures.bare.data, None)
    pat = [0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x2E, 0x70, 0x64, 0x62]
    assert aob.locate(pe, fixtures.bare.data, pat) == []


# --- load_patterns -----------------------------------------------------------

def test_load_patterns_accepts_an_inline_pattern(load_script):
    aob = load_script("aob_scan.py")
    assert aob.load_patterns(ns(patterns=["48 8B ?? 05"])) == [
        ("inline", [0x48, 0x8B, None, 0x05], "48 8B ?? 05")]


def test_load_patterns_without_patterns_is_empty(load_script):
    assert load_script("aob_scan.py").load_patterns(ns()) == []
    assert load_script("aob_scan.py").load_patterns(ns(patterns=[])) == []


def test_load_patterns_parses_a_text_file_with_comments_and_names(load_script, tmp_path):
    aob = load_script("aob_scan.py")
    path = tmp_path / "sigs.txt"
    path.write_text("# a comment\n\n48 8B 05\nuse-site\t90 90 90\n", encoding="utf-8")
    got = aob.load_patterns(ns(patterns=[str(path)]))
    assert got == [("sigs.txt:3", [0x48, 0x8B, 0x05], "48 8B 05"),
                   ("use-site", [0x90, 0x90, 0x90], "90 90 90")]


def test_load_patterns_parses_a_json_object(load_script, tmp_path):
    aob = load_script("aob_scan.py")
    obj = tmp_path / "named.json"
    obj.write_text('{"patterns": [{"name": "gate", "pattern": "74 05"}, "EB 05"]}',
                   encoding="utf-8")
    assert aob.load_patterns(ns(patterns=[str(obj)])) == [
        ("gate", [0x74, 0x05], "74 05"),
        ("named.json[1]", [0xEB, 0x05], "EB 05")]


def test_a_bare_json_list_is_accepted(load_script, tmp_path):
    """A top-level array is as reasonable a shape as an object with a "patterns" key.

    The reader used to call ``.get`` on whatever ``json.load`` returned, so a top-level array
    raised AttributeError instead of the SystemExit this module uses for every other bad input.
    Both shapes are read now, and anything else is refused with a message naming what was found.
    """
    aob = load_script("aob_scan.py")
    bare = tmp_path / "bare.json"
    bare.write_text('["CC CC"]', encoding="utf-8")
    assert aob.load_patterns(ns(patterns=[str(bare)])) == [("bare.json[0]", [0xCC, 0xCC], "CC CC")]


def test_a_json_scalar_is_refused_with_a_message(load_script, tmp_path):
    """The shape that is still not a pattern file says so instead of raising."""
    aob = load_script("aob_scan.py")
    scalar = tmp_path / "scalar.json"
    scalar.write_text('42', encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        aob.load_patterns(ns(patterns=[str(scalar)]))
    assert "must hold an array or an object" in str(excinfo.value)


@pytest.mark.parametrize("text,expected", [
    ("ZZ QQ", "not a byte"),
    ("?? ??", "empty or all wildcards"),
])
def test_load_patterns_exits_on_a_pattern_it_cannot_parse(load_script, tmp_path, text,
                                                          expected):
    aob = load_script("aob_scan.py")
    path = tmp_path / "bad.txt"
    path.write_text(text + "\n", encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        aob.load_patterns(ns(patterns=[str(path)]))
    assert expected in str(excinfo.value)
