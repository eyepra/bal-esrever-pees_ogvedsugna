"""The budget gate must reach the same verdict whether or not `tiktoken` is installed.

This is a small test for a defect that cost two red CI runs upstream. `check_budget.py` measures the
always-loaded body in tokens, preferring `tiktoken` and falling back to `characters / N` when it is
absent. The first version's `N` was guessed (3.6) instead of calibrated, so a machine with tiktoken
saw ~10,900 tokens and passed while a machine without it saw ~13,200 and warned -- and the gate
runner (CI's oldest job, and any contributor's box) is the one without it.

A gate whose answer depends on which packages the runner happens to have installed is not a gate, so
both paths are forced here and compared.

The third test guards the other half of the same failure: a threshold that is computed and then
unable to fail anything.
"""
from __future__ import annotations

import importlib
import sys

import pytest

from conftest import REPO_ROOT

pytestmark = pytest.mark.unit

SKILL_MD = REPO_ROOT / "skills" / "exe-reverse" / "SKILL.md"


@pytest.fixture
def budget():
    sys.path.insert(0, str(REPO_ROOT))
    return importlib.import_module("check_budget")


def _has_tiktoken():
    """Whether a real tokenizer is available, reported rather than assumed.

    The comparison needs *two* implementations; where there is only one, the honest outcome is a
    skip with the install command, not a failure and not a silent pass. CI installs it, so the
    property is verified where it matters; a contributor without it has both gates agreeing anyway,
    because the fallback is calibrated to the same constant.
    """
    try:
        import tiktoken  # noqa: F401
        return True
    except Exception:
        return False


def test_the_fallback_estimate_agrees_with_the_real_tokenizer(budget):
    """Both measurement paths must land on the same side of the soft budget."""
    if not _has_tiktoken():
        pytest.skip("tiktoken is not installed here, so there is no measurement to compare against; "
                    "install it with `python -m pip install tiktoken`")
    text = SKILL_MD.read_text(encoding="utf-8")

    real, how_real = budget.token_estimate(text)
    assert "tiktoken" in how_real, how_real

    # Force the fallback path by handing the module a tokenizer that cannot be imported.
    saved = sys.modules.get("tiktoken")
    sys.modules["tiktoken"] = None          # `import tiktoken` raises here
    try:
        fallback, how_fallback = budget.token_estimate(text)
    finally:
        if saved is not None:
            sys.modules["tiktoken"] = saved
        else:
            sys.modules.pop("tiktoken", None)

    assert "estimate" in how_fallback, how_fallback
    drift = abs(real - fallback) / max(1, real)
    assert drift < 0.05, (
        "the fallback is %.1f%% away from tiktoken (%d vs %d): recalibrate TOKENS_PER_CHAR "
        "against a fresh measurement rather than a guess" % (100 * drift, fallback, real))
    assert (real <= budget.TOKEN_SOFT) == (fallback <= budget.TOKEN_SOFT), (
        "the two paths straddle the soft budget (%d real / %d fallback vs %d): the gate would "
        "answer differently on CI than on a developer machine"
        % (real, fallback, budget.TOKEN_SOFT))


def test_the_fallback_constant_is_the_calibrated_one(budget):
    """Pin the constant to a measurement: `chars / tokens` on SKILL.md, recomputed here."""
    text = SKILL_MD.read_text(encoding="utf-8")
    real, how = budget.token_estimate(text)
    if "tiktoken" not in how:
        pytest.skip("no tiktoken available, so there is no measurement to calibrate against")
    expected = len(text) / real
    assert abs(budget.TOKENS_PER_CHAR - expected) < 0.25, (
        "TOKENS_PER_CHAR is %.3f but this SKILL.md measures %.3f characters per token -- the "
        "document changed, so recalibrate" % (budget.TOKENS_PER_CHAR, expected))


def test_an_index_row_past_the_hard_limit_fails_rather_than_warns(budget):
    """The hard index-row limit must escalate, or the limit it names is decorative.

    It read `'warn' if hard else 'warn'` -- both branches identical -- so `INDEX_ROW_HARD` was
    defined, computed, and unable to fail anything: an index row could grow without bound while
    every gate stayed green. That is the same failure mode this file exists for, one level up: the
    measurement happened and the verdict did not follow. It was found by injecting an over-long row
    and requiring the gate to fail, which is the only way a dead limit shows itself -- a gate that
    has only ever been seen passing is not evidence that it can see anything.
    """
    def levels(desc_len):
        lines = [
            "## Symptom index",
            "| What you observe | Load first |",
            "| a row | %s |" % ("y" * desc_len),
        ]
        return {level for level, _ in budget.check_index_rows(lines)}

    assert levels(budget.INDEX_ROW_SOFT + 10) == {"warn"}
    assert levels(budget.INDEX_ROW_HARD + 10) == {"fail"}, (
        "a row past INDEX_ROW_HARD (%d chars) must fail the gate, not warn about it"
        % budget.INDEX_ROW_HARD)

def test_the_corpus_count_ignores_a_bytecode_cache(budget, tmp_path, monkeypatch):
    """A measurement that changes when a reader runs the suite measures the reader.

    The corpus note once counted scripts/__pycache__/*.pyc, so the same commit reported 27 scripts
    on a machine that had run pytest and 16 on a clean checkout. The routing gate said 16 the whole
    time; the disagreement between two gates about one tree is what surfaced it.
    """
    refs = tmp_path / "references"
    refs.mkdir()
    (refs / "one.md").write_text("# one\n", encoding="utf-8")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "one.py").write_text("print(1)\n", encoding="utf-8")
    cache = scripts / "__pycache__"
    cache.mkdir()
    (cache / "one.cpython-314.pyc").write_bytes(b"\x00" * 10)

    monkeypatch.setattr(budget, "REFS", str(refs))
    monkeypatch.setattr(budget, "SKILL_DIR", str(tmp_path))
    notes = budget.check_corpus()
    assert notes[0].startswith("corpus: 1 references + 1 scripts = 2 files"), notes[0]
