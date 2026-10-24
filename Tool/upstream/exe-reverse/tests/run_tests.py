#!/usr/bin/env python3
"""Run the regression suite with one command, and fail usefully when it cannot run.

Why this exists next to `python -m pytest`: the interesting failure is not a failing test, it is
a suite that cannot start. "python -m pytest" answers a missing pytest with
``No module named pytest``, which reads like a bug in the suite rather than a missing
prerequisite. This runner states the prerequisite, prints the install line the repository
documents, and exits 3 -- the repository's environment-capability failure code -- instead of
letting a toolchain gap look like a test result.

Usage:
    python tests/run_tests.py                  # the whole suite
    python tests/run_tests.py -q -m unit       # anything pytest accepts is forwarded

Exit codes: pytest's own code (0 = passed, 1 = failures, 2 = interrupted, 4 = usage error,
5 = nothing collected), or 3 = the environment cannot run the suite at all. Note that pytest
also uses 3 for its own internal error; the printed message distinguishes the two.

Requirements: Python 3.9+ and pytest. No other third-party package, no debugger, no driver, no
network and no committed binary sample -- the PE inputs are generated into a temporary directory
at test time.
"""
import importlib.util
import os
import sys

MIN_PYTHON = (3, 9)
EXIT_ENVIRONMENT = 3
INSTALL_INSTRUCTION = "python -m pip install pytest"

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)


def _message(lines):
    for line in lines:
        sys.stderr.write("%s\n" % line)


def main(argv):
    if sys.version_info < MIN_PYTHON:
        _message([
            "This suite needs Python %d.%d or newer; this interpreter is %s."
            % (MIN_PYTHON[0], MIN_PYTHON[1], sys.version.split()[0]),
            "The tested scripts declare the same requirement in their own docstrings.",
            "Install a newer interpreter, then run this command again.",
        ])
        return EXIT_ENVIRONMENT

    if importlib.util.find_spec("pytest") is None:
        _message([
            "pytest is not installed, so the regression suite cannot run.",
            "",
            "  install: %s" % INSTALL_INSTRUCTION,
            "",
            "or run the suite after installing it: python tests/run_tests.py",
        ])
        return EXIT_ENVIRONMENT

    # pytest reads pytest.ini relative to the rootdir, so run from the repository root whatever
    # directory the caller used.
    os.chdir(REPO_ROOT)
    import pytest
    return pytest.main(list(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
