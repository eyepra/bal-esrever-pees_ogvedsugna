"""Unit tests for skills/exe-reverse/scripts/fold.py, the bounded summariser.

What these tests hold is the promise the tool makes about itself: the summary is bounded, it says
what it withheld, and the numbers it prints are true of the file's actual shape.

The shape tests exist because the first version read a pretty-printed 32 MB JSON document line by
line -- its shape decision was the first byte plus a size cutoff, and both a document and a record
file begin with `{` -- and summarised it as 16,278 records with 1.7 million unparseable lines. Every
count in that summary was honestly computed and the summary described a file that did not exist.
The depth scan that replaced it is what the first three tests hold, including the case that breaks
naive counters: braces and escaped quotes inside string values.
"""
import json
import sys

import pytest

pytestmark = pytest.mark.unit


def run_fold(load_script, monkeypatch, capsys, tmp_path, name, content, extra=()):
    """Write the input, run main() as if from the command line, and return (code, stdout)."""
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    fold = load_script("fold.py")
    monkeypatch.setattr(sys, "argv", ["fold.py", str(path), *extra])
    code = fold.main()
    out = capsys.readouterr().out
    return code, out


# --- the shape is decided by the bytes, not the name or the size ----------------


def test_two_records_on_two_lines_are_records(load_script, monkeypatch, capsys, tmp_path):
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "a.jsonl",
                         '{"a": 1}\n{"a": 2}\n')
    assert code == 0
    assert "records    : 2" in out
    assert "RESULT=fold_ok" in out


def test_a_pretty_printed_document_is_one_value_not_many(load_script, monkeypatch, capsys,
                                                         tmp_path):
    # The string value carries braces, brackets and escaped quotes of its own: a naive depth count
    # is fooled by exactly this, the scanner must not be.
    doc = {"outer": {"s": 'a "{[quoted]}" body', "n": 3}, "arr": [1, 2, 3]}
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "graph.json",
                         json.dumps(doc, indent=2))
    assert code == 0
    assert "one JSON document" in out
    assert "records" not in out


def test_content_after_the_first_value_closes_means_records(load_script, monkeypatch, capsys,
                                                            tmp_path):
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "b.jsonl",
                         '{"a": 1}\n{"a": 2}\n{"a": 3}\n')
    assert code == 0
    assert "records    : 3" in out


def test_a_single_document_past_the_walk_limit_is_left_unwalked(load_script, monkeypatch, capsys,
                                                                tmp_path):
    fold = load_script("fold.py")
    path = tmp_path / "huge.json"
    path.write_text('{"a": "%s"}' % ("x" * 40), encoding="utf-8")
    monkeypatch.setattr(fold, "JSON_WALK_LIMIT", 8)
    monkeypatch.setattr(sys, "argv", ["fold.py", str(path)])
    assert fold.main() == 0
    out = capsys.readouterr().out
    assert "was not loaded" in out
    assert "RESULT=fold_ok" in out


# --- the summary admits its bounds ----------------------------------------------


def test_a_key_with_few_values_counts_them_exactly(load_script, monkeypatch, capsys, tmp_path):
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "c.jsonl",
                         '{"kind": "call"}\n{"kind": "call"}\n{"kind": "ret"}\n',
                         ("--key", "kind", "--limit", "4"))
    assert code == 0
    assert 'key "kind": 2 distinct value(s) seen (showing 2)' in out
    assert "x2" in out


def test_a_key_at_the_tracking_cap_is_reported_as_a_floor(load_script, monkeypatch, capsys,
                                                          tmp_path):
    fold = load_script("fold.py")
    body = "".join(json.dumps({"v": i}) + "\n" for i in range(fold.VALUE_TRACK_CAP + 5))
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "wide.jsonl", body,
                         ("--key", "v", "--limit", "3"))
    assert code == 0
    assert "at least" in out
    assert "floor" in out
    # The cap must not leak as an exact count: "at least" only ever prefixes the capped number.
    assert "2005 distinct" not in out


def test_grep_reports_how_many_matches_were_withheld(load_script, monkeypatch, capsys, tmp_path):
    text = "\n".join("hit %d premium" % i if i % 2 else "miss %d plain" % i
                     for i in range(10)) + "\n"
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "log.txt", text,
                         ("--grep", "premium", "--limit", "1"))
    assert code == 0
    assert "matches: 5 (showing 1)" in out
    assert "4 more match(es) withheld" in out


def test_text_input_never_touches_the_json_paths(load_script, monkeypatch, capsys, tmp_path):
    code, out = run_fold(load_script, monkeypatch, capsys, tmp_path, "notes.txt",
                         "first\nsecond\nthird\n", ("--limit", "2"))
    assert code == 0
    assert "shape      : text" in out
    assert "lines      : 3" in out


# --- the record itself is never the cost ----------------------------------------


def test_the_input_is_not_modified(load_script, monkeypatch, capsys, tmp_path):
    body = '{"a": 1}\n{"a": 2}\n'
    path = tmp_path / "keep.jsonl"
    path.write_text(body, encoding="utf-8")
    run_fold(load_script, monkeypatch, capsys, tmp_path, "keep.jsonl", body)
    assert path.read_text(encoding="utf-8") == body


def test_a_missing_file_is_a_usage_error_not_a_summary(load_script, monkeypatch, capsys,
                                                       tmp_path):
    fold = load_script("fold.py")
    monkeypatch.setattr(sys, "argv", ["fold.py", str(tmp_path / "absent.jsonl")])
    assert fold.main() == 2
    assert "RESULT=usage_error" in capsys.readouterr().out
