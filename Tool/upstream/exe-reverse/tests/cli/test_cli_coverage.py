"""Coverage of the shipped scripts, derived from the directory rather than a hand-written list.

Borrowed mechanism: the sibling apk-reverse repository derives its CLI contract cases from
skills/*/scripts/*.py and from each script's own --help output, so a new script is covered the day
it lands instead of the day someone remembers to add it. What is *not* borrowed is that repository's
single 0-4 exit-code table: this kit publishes a per-script vocabulary (pepatch.py uses 3 for "not a
parseable PE", where the table means "the environment lacks a capability"), and a test that rewrote
those meanings would assert a policy this repository deliberately does not have.

The guard here is therefore narrower, and it is about *coverage*, not exit codes:

  * every shipped .py is either in conftest.SCRIPT_FILES (some layer of this suite exercises it) or
    named in DECLARED_UNCOVERED together with the reason it is not;
  * every declared gap carries a real sentence, because "TODO" is how a gap becomes permanent;
  * every shipped script -- covered or declared -- answers --help with its usage block, which is the
    cheapest possible exercise of its argparse table and its import path.

A new script fails this file until one of those lists changes. That is the point: the alternative
is a suite that looks complete while silently ignoring half the kit.
"""
import subprocess
import sys

import pytest

from conftest import SCRIPTS_DIR, SCRIPT_FILES

pytestmark = pytest.mark.cli

# Scripts no layer exercises yet. Each entry is a recorded gap, not an exemption: the reason says
# what would be needed to close it, so the next pass can decide rather than rediscover.
DECLARED_UNCOVERED = {
    "plan.py":
        "composes capabilities.py and doctor.py into a route from a stated intent. Both halves have "
        "their own tests; the composition reads live host facts, so a fixture that pinned its output "
        "would pin this machine's capability set instead of the mapping. Closing it needs a stubbed "
        "probe, and that stub does not exist yet.",
    "preflight.py":
        "answers session readiness from live host facts (free space, route prerequisites) plus one "
        "sample. The sample half could be pinned to a generated PE; the host half has no generator, "
        "and asserting on the runner's environment would encode this machine as an expectation.",
}


def shipped_scripts():
    """Every runnable python script the skill ships, sorted."""
    return sorted(p.name for p in SCRIPTS_DIR.glob("*.py"))


def test_every_shipped_script_is_exercised_or_declared():
    """A script nobody tests must at least be a script somebody decided not to test."""
    shipped = set(shipped_scripts())
    assert shipped, "no scripts found under %s" % SCRIPTS_DIR
    silently_uncovered = shipped - set(SCRIPT_FILES) - set(DECLARED_UNCOVERED)
    assert not silently_uncovered, (
        "these scripts are shipped but neither exercised nor declared uncovered: %s. Add a test and "
        "register the script in conftest.SCRIPT_FILES, or add it to DECLARED_UNCOVERED with the "
        "reason." % sorted(silently_uncovered))


def test_declared_entries_are_neither_stale_nor_hollow():
    """A gap that was closed must leave the list; a gap with no reason is a hidden one."""
    both = set(SCRIPT_FILES) & set(DECLARED_UNCOVERED)
    assert not both, ("these scripts are in SCRIPT_FILES and also declared uncovered: %s -- the "
                      "declaration is stale" % sorted(both))
    for name, reason in DECLARED_UNCOVERED.items():
        assert (SCRIPTS_DIR / name).is_file(), "%s is declared uncovered but does not exist" % name
        assert len(reason.split()) >= 12, (
            "%s: the reason must say what would close the gap, not just mark it" % name)


@pytest.mark.parametrize("script", shipped_scripts())
def test_every_shipped_script_answers_help_with_usage(script):
    """The usage block is the script's published contract; it must render on every host."""
    proc = subprocess.run([sys.executable, str(SCRIPTS_DIR / script), "--help"],
                          capture_output=True, text=True, timeout=120,
                          encoding="utf-8", errors="replace")
    assert proc.returncode == 0, "%s --help exited %d: %s" % (script, proc.returncode, proc.stderr)
    assert "usage:" in proc.stdout.lower(), "%s printed no usage block" % script
    assert script in proc.stdout, "%s does not name itself in its usage line" % script
