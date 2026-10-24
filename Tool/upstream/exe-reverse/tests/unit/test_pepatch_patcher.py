"""Unit tests for skills/exe-reverse/scripts/pepatch.py.

The refusals matter more than the success path: a patcher that silently picks the wrong
occurrence, or accepts a length change, destroys the baseline it was supposed to preserve. Each
refusal below is asserted against the real exception text, and the CLI-level tests drive
``pepatch.main()`` in-process so no subprocess is required to prove that a dry run writes
nothing and that a real run leaves its input byte-identical.
"""
import hashlib
import shutil
import sys

import pytest

pytestmark = pytest.mark.unit


@pytest.fixture
def pillow(tmp_path, fixtures):
    """A privately owned copy of the fixture, so a test can never disturb another test."""
    dest = tmp_path / "input.exe"
    shutil.copyfile(str(fixtures.pe64.path), str(dest))
    return dest


@pytest.fixture
def plant(fixtures):
    """The byte sequence the fixture plants twice, as a spaced hex string."""
    return fixtures.pe64.plant


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_main(module, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", [getattr(module, "__file__", "pepatch.py")] + list(argv))
    return module.main()


# --- parse_bytes -------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("48 8B 05", [0x48, 0x8B, 0x05]),
    ("488B05", [0x48, 0x8B, 0x05]),
    ("48,8B,05", [0x48, 0x8B, 0x05]),
    ("0x48 0x8b", [0x48, 0x8B]),
    ("48 8B ??", [0x48, 0x8B, None]),
    ("?", [None]),
    ("**", [None]),
    ("xx", [None]),
    ("  48   8B  ", [0x48, 0x8B]),
    ("48", [0x48]),
])
def test_parse_bytes_accepts_the_documented_forms(load_script, text, expected):
    body, tokens = load_script("pepatch.py").parse_bytes(text)
    assert body == expected
    assert tokens


@pytest.mark.parametrize("text", ["", None, "   "])
def test_parse_bytes_of_nothing_is_empty(load_script, text):
    assert load_script("pepatch.py").parse_bytes(text) == ([], [])


@pytest.mark.parametrize("token", ["ZZ", "4", "ABC", "GG HH", "0x1", "48 8G"])
def test_parse_bytes_rejects_a_bad_token(load_script, token):
    with pytest.raises(ValueError, match="not a byte"):
        load_script("pepatch.py").parse_bytes(token)


def test_parse_bytes_returns_the_original_tokens(load_script):
    body, tokens = load_script("pepatch.py").parse_bytes("48 8B ??")
    assert tokens == ["48", "8B", "??"]
    assert body == [0x48, 0x8B, None]


# --- find_pattern ------------------------------------------------------------

def test_find_pattern_returns_every_occurrence(load_script, fixtures):
    """The fixture plants the same sequence twice, on purpose."""
    pepatch = load_script("pepatch.py")
    data = fixtures.pe64.data
    pattern = pepatch.parse_bytes(fixtures.pe64.plant)[0]
    first, second = fixtures.pe64.plant_offsets
    assert pepatch.find_pattern(data, pattern) == [first, second]
    assert data[first:first + len(pattern)] == bytes(pattern)
    assert data[second:second + len(pattern)] == bytes(pattern)


def test_find_pattern_honours_wildcards(load_script):
    pepatch = load_script("pepatch.py")
    data = bytes([0x00, 0x10, 0x99, 0x10, 0x00])
    assert pepatch.find_pattern(data, [None, 0x10]) == [0, 2]
    assert pepatch.find_pattern(data, [0x10, None]) == [1, 3]
    assert pepatch.find_pattern(data, [None, 0x10, None]) == [0, 2]


def test_find_pattern_start_and_limit(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    data = fixtures.pe64.data
    pattern = pepatch.parse_bytes(fixtures.pe64.plant)[0]
    first, second = fixtures.pe64.plant_offsets
    assert pepatch.find_pattern(data, pattern, start=first + 1) == [second]
    assert pepatch.find_pattern(data, pattern, limit=1) == [first]


def test_find_pattern_reports_no_hits_rather_than_guessing(load_script, fixtures):
    """A negative outcome: a pattern that is not there must not match somewhere else."""
    pepatch = load_script("pepatch.py")
    assert pepatch.find_pattern(fixtures.pe64.data, [0xDE, 0xAD, 0xBE, 0xEF]) == []
    assert pepatch.find_pattern(fixtures.pe64.data,
                                pepatch.parse_bytes("63 6F 6D 6D 6F 6E")[0]) == []


@pytest.mark.parametrize("pattern", [[], [None], [None, None]])
def test_find_pattern_refuses_an_empty_or_all_wildcard_pattern(load_script, pattern):
    with pytest.raises(ValueError, match="empty or entirely wildcards"):
        load_script("pepatch.py").find_pattern(b"\x00\x01\x02", pattern)


# --- length_mark -------------------------------------------------------------

def test_length_mark_distinguishes_three_states(load_script):
    pepatch = load_script("pepatch.py")
    assert pepatch.length_mark({"equal_length": True}) == ""
    assert "LENGTH CHANGE" in pepatch.length_mark({"equal_length": False})
    assert "length unproven" in pepatch.length_mark({"equal_length": None})


# --- apply_one ---------------------------------------------------------------

def test_ambiguous_pattern_is_refused(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    spec = {"name": "gate", "pattern": fixtures.pe64.plant, "bytes": "90 " * 12}
    with pytest.raises(pepatch.PatchError, match="matched 2 sites"):
        pepatch.apply_one(spec, pe, fixtures.pe64.data)


def test_explicit_index_selects_one_site(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    first, second = fixtures.pe64.plant_offsets
    spec = {"name": "gate", "pattern": fixtures.pe64.plant, "index": 1,
            "bytes": "90 " * 12, "expect": fixtures.pe64.plant}
    applied = pepatch.apply_one(spec, pe, fixtures.pe64.data)
    assert applied["offset"] == second
    assert applied["offset"] != first
    assert applied["equal_length"] is True
    assert applied["length_basis"] == "expect"


def test_allow_many_takes_the_first_hit(load_script, fixtures):
    """The documented escape hatch: it is not silent, and it still reports one site."""
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    spec = {"name": "gate", "pattern": fixtures.pe64.plant, "allow-many": True,
            "bytes": "90 " * 12, "expect": fixtures.pe64.plant}
    applied = pepatch.apply_one(spec, pe, fixtures.pe64.data)
    assert applied["offset"] == fixtures.pe64.plant_offsets[0]


def test_expect_mismatch_is_refused(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    with pytest.raises(pepatch.PatchError, match="the site moved or the wrong binary is open"):
        pepatch.apply_one({"name": "gate", "offset": "0x410", "expect": "90 90",
                           "bytes": "CC CC"}, pe, fixtures.pe64.data)


def test_length_is_unproven_without_expect_or_original_length(load_script, fixtures):
    """No disassembler, no honest claim: the marker must say the length is unknown."""
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    applied = pepatch.apply_one({"name": "site", "offset": "0x410", "bytes": "CC"},
                                pe, fixtures.pe64.data)
    assert applied["equal_length"] is None
    assert applied["length_basis"] == "unknown (no expect/original-length given)"
    assert "length unproven" in pepatch.length_mark(applied)


def test_length_change_is_refused_without_allow_resize(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    spec = {"name": "gate", "offset": "0x410", "expect": "48 8B", "bytes": "CC CC CC"}
    with pytest.raises(pepatch.PatchError, match="--allow-resize"):
        pepatch.apply_one(spec, pe, fixtures.pe64.data)


def test_length_change_is_marked_structural_with_allow_resize(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    spec = {"name": "gate", "offset": "0x410", "expect": "48 8B", "bytes": "CC CC CC"}
    applied = pepatch.apply_one(spec, pe, fixtures.pe64.data, allow_resize=True)
    assert applied["equal_length"] is False
    assert "LENGTH CHANGE" in pepatch.length_mark(applied)


@pytest.mark.parametrize("spec,expected", [
    ({"name": "wild", "offset": "0x410", "bytes": "CC ??"}, "no concrete replacement bytes"),
    ({"name": "tail", "rva": "0x2200", "bytes": "CC"}, "maps to no file offset"),
    ({"name": "eof", "offset": "0xFF8", "original-length": 16, "bytes": "CC"},
     "runs past end of file"),
    ({"name": "neg", "offset": -1, "bytes": "CC"}, "must not be negative"),
    ({"name": "nowhere", "bytes": "CC"}, "none of pattern/rva/offset"),
    ({"name": "oob", "pattern": "48 8B 05 11 22 33 00 48 85 C0 74 05", "index": 5,
      "bytes": "CC"}, "index 5 out of range"),
    ({"name": "none", "pattern": "DE AD BE EF", "bytes": "CC"}, "matched nothing"),
])
def test_resolve_refuses_specs_it_cannot_honour(load_script, fixtures, spec, expected):
    pepatch = load_script("pepatch.py")
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    with pytest.raises(pepatch.PatchError, match=expected):
        pepatch.resolve(spec, pe, fixtures.pe64.data)


# --- verify ------------------------------------------------------------------

def test_verify_reports_bytes_that_are_not_there(load_script, fixtures):
    """A negative outcome: the re-read step must fail when the patch did not land."""
    pepatch = load_script("pepatch.py")
    _pe, problems = pepatch.verify(str(fixtures.pe64.path),
                                   [{"name": "ghost", "offset": 0x410, "after": "CC"}])
    assert len(problems) == 1
    assert "ghost" in problems[0] and "expected CC" in problems[0]


def test_verify_is_satisfied_when_the_bytes_are_present(load_script, fixtures):
    pepatch = load_script("pepatch.py")
    first, _second = fixtures.pe64.plant_offsets
    present = pepatch.fmt_bytes(fixtures.pe64.data[first:first + 4])
    _pe, problems = pepatch.verify(str(fixtures.pe64.path),
                                   [{"name": "real", "offset": first, "after": present}])
    assert problems == []


# --- main() ------------------------------------------------------------------

def test_dry_run_writes_nothing(load_script, pillow, monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    before = sha256(pillow)
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--at-offset", "0x410", "--bytes", "CC", "--dry-run"])
    out = capsys.readouterr()
    assert code == 0
    assert "dry run" in out.out
    assert sha256(pillow) == before
    assert list(pillow.parent.iterdir()) == [pillow], "a dry run created a file"


def test_dry_run_reports_a_refusal_without_writing(load_script, pillow, monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--at-offset", "0x410", "--expect", "90 90",
                     "--bytes", "CC CC", "--dry-run"])
    out = capsys.readouterr()
    assert code == 1
    assert "FAIL" in out.out
    assert list(pillow.parent.iterdir()) == [pillow]


def test_out_is_required_to_write_a_patched_file(load_script, pillow, monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    before = sha256(pillow)
    code = run_main(pepatch, monkeypatch, [str(pillow), "--at-offset", "0x410",
                                           "--bytes", "CC"])
    err = capsys.readouterr().err
    assert code == 2
    assert "--out is required" in err
    assert sha256(pillow) == before
    assert list(pillow.parent.iterdir()) == [pillow]


def test_real_run_preserves_the_input_and_verifies_the_output(load_script, pillow, fixtures,
                                                              monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    peutil = load_script("peutil.py")
    before = sha256(pillow)
    first, _second = fixtures.pe64.plant_offsets
    replacement = "48 8B 05 11 22 33 00 48 85 C0 EB 05"
    out = pillow.parent / "patched.exe"
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--pattern", fixtures.pe64.plant, "--at-hit", "0",
                     "--expect", fixtures.pe64.plant, "--bytes", replacement, "--out", str(out)])
    text = capsys.readouterr().out
    assert code == 0, text
    assert "verified" in text
    assert sha256(pillow) == before, "the input file was modified"
    assert out.exists()

    pe_out = peutil.PE(out.read_bytes(), str(out))
    assert pe_out.file_size == fixtures.pe64.size
    assert out.read_bytes()[first:first + 12] == bytes(pepatch.parse_bytes(replacement)[0])
    # The second planted copy must be untouched: only the selected site moved.
    assert out.read_bytes()[_second:_second + 12] == bytes(
        pepatch.parse_bytes(fixtures.pe64.plant)[0])
    assert pe_out.checksum_ok() is True
    assert pe_out.checksum != 0


def test_input_and_output_differ_only_where_expected(load_script, pillow, fixtures,
                                                      monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    first, _second = fixtures.pe64.plant_offsets
    checksum_field = int(fixtures.pe64.meta["checksum_offset"], 16)
    out = pillow.parent / "one-byte.exe"
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--at-offset", hex(first), "--expect", "48 8B",
                     "--bytes", "CC 8B", "--out", str(out)])
    capsys.readouterr()
    assert code == 0
    diff = [i for i, (a, b) in enumerate(zip(pillow.read_bytes(), out.read_bytes())) if a != b]
    # The patched byte plus at most the four checksum bytes.
    assert first in diff
    assert len(diff) <= 5
    assert set(diff) - {first} <= set(range(checksum_field, checksum_field + 4))


def test_no_checksum_leaves_the_declared_field_stale(load_script, pillow, monkeypatch, capsys):
    pepatch = load_script("pepatch.py")
    peutil = load_script("peutil.py")
    out = pillow.parent / "stale.exe"
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--at-offset", "0x410", "--expect", "48 8B",
                     "--bytes", "90 90", "--no-checksum", "--out", str(out), "--json"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    import json
    payload = json.loads(captured.out)
    assert payload["checksum_recomputed"] is False
    assert payload["checksum_after"]["matches"] is False
    assert peutil.PE(out.read_bytes(), None).checksum_ok() is False


def test_allow_resize_shifts_the_following_bytes(load_script, pillow, fixtures,
                                                 monkeypatch, capsys):
    """A resize changes the file's length, and everything after the site moves with it.

    This is the behaviour the flag promises. An earlier version wrote exactly as many bytes as
    it read, so the file never grew while the documented contract said it would -- the flag's
    only real effect was to defeat the equal-length guard. The assertions below pin the genuine
    consequence, shift included, because a shifted file is a structural edit and the caller is
    entitled to see that stated rather than inferred.
    """
    pepatch = load_script("pepatch.py")
    first, _second = fixtures.pe64.plant_offsets
    original = pillow.read_bytes()
    out = pillow.parent / "resized.exe"
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--at-offset", hex(first), "--expect", "48",
                     "--bytes", "CC CC CC", "--allow-resize", "--out", str(out), "--json"])
    import json
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["structural"] == ["cli"]
    assert payload["output_size"] == payload["input_size"] + 2
    written = out.read_bytes()
    assert len(written) == len(original) + 2
    assert written[first:first + 3] == b"\xCC\xCC\xCC"
    # One byte was replaced by three, so the tail moved two bytes along.
    assert written[first + 3:first + 14] == original[first + 1:first + 12]


def test_failed_patches_stop_the_write(load_script, pillow, plant, monkeypatch, capsys):
    """An ambiguous pattern must fail the run instead of patching the first match."""
    pepatch = load_script("pepatch.py")
    before = sha256(pillow)
    out = pillow.parent / "never.exe"
    code = run_main(pepatch, monkeypatch,
                    [str(pillow), "--pattern", plant, "--bytes", "90 " * 12, "--out", str(out)])
    err = capsys.readouterr().err
    assert code == 1
    assert "refusing to write an output with failed patches" in err
    assert "matched 2 sites" in err
    assert not out.exists()
    assert sha256(pillow) == before
