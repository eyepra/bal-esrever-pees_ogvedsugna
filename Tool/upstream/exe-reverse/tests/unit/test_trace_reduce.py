"""Unit tests for skills/exe-reverse/scripts/trace_reduce.py, the bit-vector reducer.

Three layers, each held separately because they make different promises:

* the rewriting core -- the classic mixed-boolean-arithmetic substitutions reduce to `x + y` and
  survive a sampling check, and a genuinely different pair is caught with a counterexample;
* the SMT emitter -- pure text, checked exactly, because the solver will execute it verbatim and a
  proof about wrongly-encoded semantics is worse than no proof. The shift-count mask is the case
  that matters: `evaluate()` masks a count to six bits, and the encoding must do the same or the
  solver proves a cleaner function than the one the samples ran on;
* the proof path -- driven against a stub solver (one line of output) and against a missing path,
  never against a real solver: CI has none, and a test that needs one is a test that skips.
"""
import sys

import pytest

pytestmark = pytest.mark.unit


def parse(tr, text):
    return tr.Parser(tr.tokenize(text)).parse()


# --- the rewriting core ---------------------------------------------------------


def test_the_two_classic_substitutions_reduce_to_add(load_script):
    tr = load_script("trace_reduce.py")
    for obfuscated in ("(x | y) + (x & y)", "(x ^ y) + 2 * (x & y)"):
        tree = parse(tr, obfuscated)
        reduced, steps = tr.reduce_all(tree, tr.MASK[32])
        assert reduced.text() == "x + y"
        assert steps, "a reduction with no recorded steps changed nothing"
        equal, counter, _ = tr.verify(tree, reduced, tr.MASK[32], 64)
        assert equal, "counterexample: %r" % (counter,)


def test_a_genuinely_different_pair_is_refuted_with_a_witness(load_script):
    tr = load_script("trace_reduce.py")
    original, other = parse(tr, "x + y"), parse(tr, "x | y")
    equal, counter, checked = tr.verify(original, other, tr.MASK[32], 64)
    assert checked > 0
    assert not equal
    # The witness is re-checked here rather than trusted: the point of a counterexample is that it
    # can be substituted by hand.
    env = counter["env"]
    assert tr.evaluate(original, env, tr.MASK[32]) != tr.evaluate(other, env, tr.MASK[32])


# --- the SMT emitter ------------------------------------------------------------


def test_a_constant_is_emitted_at_the_full_word_width(load_script):
    tr = load_script("trace_reduce.py")
    term = parse(tr, "0x2a")
    assert tr.smt2_term(term, 32) == "#x0000002a"
    assert tr.smt2_term(term, 8) == "#x2a"


def test_every_operator_maps_to_its_bit_vector_counterpart(load_script):
    tr = load_script("trace_reduce.py")
    assert tr.smt2_term(parse(tr, "x + y"), 32) == "(bvadd x y)"
    assert tr.smt2_term(parse(tr, "x - y"), 32) == "(bvsub x y)"
    assert tr.smt2_term(parse(tr, "x * y"), 32) == "(bvmul x y)"
    assert tr.smt2_term(parse(tr, "x & y"), 32) == "(bvand x y)"
    assert tr.smt2_term(parse(tr, "x | y"), 32) == "(bvor x y)"
    assert tr.smt2_term(parse(tr, "x ^ y"), 32) == "(bvxor x y)"
    assert tr.smt2_term(parse(tr, "~x"), 32) == "(bvnot x)"
    assert tr.smt2_term(parse(tr, "-x"), 32) == "(bvneg x)"


def test_a_shift_count_is_masked_exactly_as_evaluate_masks_it(load_script):
    tr = load_script("trace_reduce.py")
    # evaluate() shifts by `count & 63`; the encoding must assert the same thing, or the solver
    # proves a different function than the one the samples ran on.
    assert tr.smt2_term(parse(tr, "x << y"), 32) == "(bvshl x (bvand y #x0000003f))"
    assert tr.smt2_term(parse(tr, "x >> y"), 64) == "(bvlshr x (bvand y #x000000000000003f))"


def test_the_script_declares_variables_asserts_a_difference_and_asks(load_script):
    tr = load_script("trace_reduce.py")
    script = tr.smt2_for(parse(tr, "y + x"), parse(tr, "x + y"), 32)
    lines = script.strip().splitlines()
    assert lines[0] == "(set-logic QF_BV)"
    assert "(declare-fun x () (_ BitVec 32))" in lines
    assert "(declare-fun y () (_ BitVec 32))" in lines
    assert any(line.startswith("(assert (distinct") for line in lines)
    assert "(check-sat)" in lines
    assert "(get-model)" in lines


def test_a_model_is_read_into_an_environment_and_masked(load_script):
    tr = load_script("trace_reduce.py")
    model = """
sat
(
  (define-fun x () (_ BitVec 32) #x00000001)
  (define-fun y () (_ BitVec 32) #x00000003)
  (define-fun ignored () Int 7)
)
"""
    assert tr.model_env(model, tr.MASK[32]) == {"x": 1, "y": 3}
    assert tr.model_env("unsat", tr.MASK[32]) == {}


# --- the proof path, against stubs ----------------------------------------------


@pytest.fixture
def unsat_solver(tmp_path):
    """A stand-in solver that answers `unsat`: one line, no matter the question."""
    if sys.platform == "win32":
        path = tmp_path / "unsat.bat"
        path.write_text("@echo unsat\r\n", encoding="ascii")
    else:
        path = tmp_path / "unsat.sh"
        path.write_text("#!/bin/sh\necho unsat\n", encoding="ascii")
        path.chmod(0o755)
    return str(path)


@pytest.fixture
def lying_sat_solver(tmp_path):
    """A stand-in that says `sat` and shows a witness that does not distinguish the forms.

    The reducer's own rules are identities, so a real sat never appears in a run of this tool; a
    lying one is the case that must not be trusted on arrival, and this stub is how that is held.
    """
    body = ("sat\n(\n(define-fun x () (_ BitVec 32) #x00000000)\n"
            "(define-fun y () (_ BitVec 32) #x00000000)\n)\n")
    if sys.platform == "win32":
        path = tmp_path / "sat.bat"
        path.write_text("@echo sat\r\n@echo (\r\n@echo (define-fun x () (_ BitVec 32) "
                        "#x00000000)\r\n@echo (define-fun y () (_ BitVec 32) #x00000000)\r\n"
                        "@echo )\r\n", encoding="ascii")
    else:
        path = tmp_path / "sat.sh"
        path.write_text("#!/bin/sh\ncat <<'EOF'\n%s\nEOF\n" % body, encoding="ascii")
        path.chmod(0o755)
    return str(path)


def test_an_unsat_answer_upgrades_the_verdict_to_proved(load_script, unsat_solver):
    tr = load_script("trace_reduce.py")
    original, reduced = parse(tr, "(x ^ y) + 2 * (x & y)"), parse(tr, "x + y")
    verdict, info = tr.prove(original, reduced, tr.MASK[32], 32, unsat_solver, 10)
    assert verdict == "proved"


def test_a_witness_that_does_not_distinguish_is_not_believed(load_script, lying_sat_solver):
    tr = load_script("trace_reduce.py")
    original, reduced = parse(tr, "(x ^ y) + 2 * (x & y)"), parse(tr, "x + y")
    verdict, info = tr.prove(original, reduced, tr.MASK[32], 32, lying_sat_solver, 10)
    assert verdict == "no-verdict"
    assert "does not distinguish" in info["reason"]


def test_a_missing_solver_path_is_reported_not_crashed(load_script, tmp_path):
    tr = load_script("trace_reduce.py")
    original, reduced = parse(tr, "x + y"), parse(tr, "x + y")
    verdict, info = tr.prove(original, reduced, tr.MASK[32], 32,
                             str(tmp_path / "not-there.exe"), 10)
    assert verdict == "no-verdict"
    assert "does not exist" in info["reason"]


def test_prove_with_a_missing_path_is_a_usage_error_at_the_cli(load_script, monkeypatch, capsys,
                                                               tmp_path):
    tr = load_script("trace_reduce.py")
    monkeypatch.setattr(sys, "argv", ["trace_reduce.py", "x + 0",
                                      "--prove", str(tmp_path / "absent.exe")])
    assert tr.main() == 2
    out = capsys.readouterr()
    assert "RESULT=usage_error" in out.out


def test_a_proved_run_reports_the_proved_token(load_script, monkeypatch, capsys, unsat_solver):
    tr = load_script("trace_reduce.py")
    monkeypatch.setattr(sys, "argv", ["trace_reduce.py", "(x ^ y) + 2 * (x & y)",
                                      "--prove", unsat_solver])
    assert tr.main() == 0
    out = capsys.readouterr().out
    assert "RESULT=reduce_proved" in out
    assert "every input" in out
