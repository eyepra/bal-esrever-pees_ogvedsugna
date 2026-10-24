#!/usr/bin/env python3
"""capability: host_capability_probe

Turn a stated intent into a route: what this intent needs, what this host has, and what to do first.

WHY THIS EXISTS
---------------
Everything else in this kit answers a question about a **tool** or about a **host**. Nothing
answered the question a person actually arrives with, which is a wish: "I want the paid feature",
"this is packed and I want to know what it does", "recover the licence algorithm". A reader holding
a wish had to work out for themselves which of the thirty-odd references applied, which capabilities
that implied, and whether this machine could support any of it -- and the common failure was to
reach for the first familiar tool and spend the session somewhere the problem was not.

This script is the entry point for that wish. It is deliberately **deterministic**: a table maps an
intent to the capabilities it needs, the references that carry the method, the questions that decide
whether the intent is even well-posed, and the limits that will not go away. Nothing here is
generated prose, so two runs give the same plan and a dispute is about the table, not about a
paragraph.

WHAT IT DOES NOT DO
-------------------
It does not analyse a target, does not guess what a binary is, and does not decide for you. It
prints a plan with the capabilities resolved against this host: what is ready, what is missing, and
the executable next step for each gap. `--from-sample` will triage a file and *suggest* intents, but
the suggestion is a reading of the headers, never a conclusion about what you want.

Usage
-----
    python plan.py --list
    python plan.py unlock-tier
    python plan.py unpack --verbose
    python plan.py --from-sample target.exe
    python plan.py --from-sample target.exe --json

Exit codes: 0 = every capability the intent needs is available, 1 = the plan is readable but some
steps are blocked, 2 = usage error, 4 = internal error. The last line is `RESULT=<token>`.
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import capabilities as caps  # noqa: E402  (path is set above on purpose)

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_USE = 2
EXIT_INTERNAL = 4

TOKENS = {'ready': 'plan_ready', 'blocked': 'plan_blocked', 'use': 'usage_error',
          'internal': 'internal_error'}

# ---------------------------------------------------------------------------
# Intents. An intent is a wish, phrased the way it is actually said. `needs` names
# capabilities from the registry, so a plan cannot claim more than the registry can
# support; `reads` names the references that carry the method; `ask` is the part that
# decides whether the wish is well-posed, and it comes before any tool.
# ---------------------------------------------------------------------------
INTENTS = {
    'understand': {
        'name': 'Work out what an unknown binary is and what it does',
        'needs': ['host_capability_probe', 'pe_structure_read', 'pe_triage'],
        'reads': ['recon.md', 'pe-structure.md', 'static-analysis.md',
                  'compiler-fingerprints.md', 'anti-analysis.md', 'protectors-and-packers.md'],
        'ask': [
            'Is the file the program, or a container that has to be opened first? '
            'See `extract-payload` if the entry point sits outside the first code section.',
            'Which language built it? A compiler fingerprint decides which tools can read it at '
            'all, and a mismatched tool produces confident nonsense.',
        ],
        'then': [
            'python scripts/pe_triage.py <sample> --full-out work/triage.json   # bounded report, '
            'complete record kept',
            'read the signals, not the strings first: an entry point outside .text, an absent Rich '
            'Header, a section name no compiler emits, and a security directory each point at a '
            'different origin',
        ],
        'limits': [
            'Triage produces signals, never verdicts. "High entropy" is not "packed".',
            'Absent evidence is not evidence of absence: a stripped header is a fact about the '
            'builder, not a promise that nothing is there.',
        ],
    },
    'unpack': {
        'name': 'Get at the real code behind a packer or protector',
        'needs': ['pe_structure_read', 'static_disassembly', 'dump_capture', 'hardware_breakpoint'],
        'reads': ['protectors-and-packers.md', 'virtualization-and-flattening.md',
                  'memory-and-dumps.md', 'anti-analysis.md', 'dynamic-debugging.md'],
        'ask': [
            'Was it packed to save space or to be defended? The first unpacks itself and stops '
            'there; the second keeps running checks after the code is visible.',
            'Is the tail of a section missing on disk while present in memory? That is the '
            'signature of a runtime-unpacked image and it decides whether a static route can work '
            'at all.',
        ],
        'then': [
            'identify the protector from structural evidence before choosing a route: '
            '`scripts/hwprobe.py --tools` says whether an identifier is installed',
            'if the code only exists in memory, the route is capture-then-repair, and the section '
            'table is the map (`references/memory-and-dumps.md`)',
            'a hardware breakpoint on the first execution after unpacking leaves no byte changed, '
            'which is the point when the target checks its own code',
        ],
        'limits': [
            'A hardware breakpoint needs a debugger and cannot watch a read-only location; the '
            'architecture has no such watch, and a data watch on a code address never fires.',
            'The dump is bytes, not the loader\'s work. Repairing an image is arithmetic over the '
            'section table, and a dump that reads fine can still refuse to load.',
            'On a host walking a virtualisation layer, the debug exception can be intercepted '
            'rather than delivered. The probe states this before the plan is written.',
        ],
    },
    'unlock-tier': {
        'name': 'Reach a feature the target gates behind a paid tier',
        'needs': ['licence_classification', 'pe_structure_read', 'static_disassembly',
                  'equal_length_patch'],
        'reads': ['license-mechanisms.md', 'handoff-boundaries.md', 'network-activated-licensing.md',
                  'patching.md', 'integrity-checks.md', 'verification.md'],
        'ask': [
            'Where does the FEATURE run, as distinct from where the permission comes from? A gate '
            'whose work happens on this machine is reachable from this machine whatever issued the '
            'entitlement, and mistaking a remote permission for a remote feature ends an analysis '
            'that could have continued. The two questions are answered separately in '
            'license-mechanisms.md, with the four combinations and what each one reaches.',
            'Is the decision made on this machine at all? Classify that first: a client-side flag, '
            'a value the client renders but the server decides, and a server-authoritative '
            'entitlement need three different answers and only the first is a patch.',
            'What is the deliverable? A patched binary, a generator, or a written finding. The '
            'answer changes which route is even applicable, and it is a question for the person '
            'who asked, not for the tool.',
            'Does the file carry a signature over its own bytes? Any edit outside the signed blob '
            'invalidates it, and whether that matters depends on who verifies it.',
        ],
        'then': [
            'find the decision, not the string: a message that says a feature is unavailable is '
            'usually rendered after the decision, which is why patching around it changes nothing '
            'observable',
            'establish what verifies before editing: a length-changing patch moves every offset '
            'after it, so an equal-length change is the cheaper and more defensible route',
            're-read the patched bytes from the file you wrote, and recompute what the image '
            'expects recomputed',
        ],
        'limits': [
            'A server-side entitlement is not reachable from the client, and no amount of patching '
            'makes it so. Report that as the finding it is.',
            'A client-side gate can be removed and the feature can still fail, because the second '
            'check is elsewhere. One removed gate is one removed gate.',
            'Where the code is a compiled snapshot of another language (a Flutter payload, a '
            'managed assembly), the layer diagnosis comes before any patch and changes the route '
            'completely.',
        ],
    },
    'recover-algorithm': {
        'name': 'Recover a key, hash or licence algorithm',
        'needs': ['pe_structure_read', 'static_disassembly', 'algorithm_recovery',
                  'symbolic_reduce'],
        'reads': ['algorithm-recovery.md', 'symbolic-execution.md', 'aob-and-signatures.md',
                  'verification.md', 'pe-diff-and-versions.md'],
        'ask': [
            'Is the deliverable a description or a generator? A generator means every input must '
            'work, which is a much stronger claim than one observed input matching.',
            'Where do the constant tables come from? Identify the algorithm from its constants '
            'before reading it instruction by instruction.',
        ],
        'then': [
            'collect input/output pairs from the target itself first: they are the only ground '
            'truth, and a candidate that does not reproduce them is wrong however plausible',
            'lift a bounded range rather than the whole routine, and count the calls you had to '
            'stub -- that count predicts a wrong answer better than the constraint set size',
        ],
        'limits': [
            'A solver returning a model is not a validated answer. The project documentation says '
            'so in its own words, and a model can be one of many.',
            'Symbolic execution of code that calls the operating system needs those calls stubbed, '
            'and every stub is a choice about the answer.',
        ],
    },
    'compare-builds': {
        'name': 'Compare two builds of the same program',
        'needs': ['build_compare', 'aob_locate'],
        'reads': ['pe-diff-and-versions.md', 'aob-and-signatures.md', 'patching.md',
                  'verification.md'],
        'ask': [
            'What is being compared: two releases, or one release and a patched copy? The second '
            'is a verification question and has a correct answer; the first does not.',
        ],
        'then': [
            'python scripts/pe_diff.py <a> <b>   # volatile header fields are normalised, so a '
            'rebuild is not reported as a change and a same-size replacement is not missed',
            'python scripts/aob_scan.py <sample> --patterns <file> --across <build-b>   # a pattern '
            'that is unique in one build and ambiguous in the other was never a locator',
        ],
        'limits': [
            'A signature that survives one version boundary is not a signature that survives the '
            'next. The hit count is the claim; the pattern is a guess until it is measured across '
            'the builds you actually have.',
        ],
    },
    'observe-behaviour': {
        'name': 'Watch what a target does without changing its bytes',
        'needs': ['hardware_breakpoint', 'etw_capture'],
        'reads': ['dynamic-debugging.md', 'hardware-tracing.md', 'memory-and-dumps.md',
                  'anti-analysis.md', 'environment.md'],
        'ask': [
            'Would the target notice a software breakpoint? It can read its own code, and that is '
            'the only reason to pay the cost of the hardware route.',
            'Is the question "which path was taken" or "what value was compared"? A trace answers '
            'the first and not the second.',
        ],
        'then': [
            'python scripts/preflight.py --sample <sample> --route debug   # rights, space and '
            'leftovers, before the session rather than during it',
            'a data watch must be aligned and no wider than the architecture allows, and there is '
            'no read-only watch: watching a read means watching the write that precedes it',
        ],
        'limits': [
            'Four breakpoint slots exist on this architecture and a virtualisation layer may '
            'consume the exception. Both are per-host facts, and the probe reports them.',
            'Nothing here is invisible in principle: the honest claim is that the mechanism leaves '
            'no byte changed, not that it cannot be detected.',
        ],
    },
    'extract-payload': {
        'name': 'Get at an installer\'s contents without running it',
        'needs': ['installer_inspect'],
        'reads': ['installers-and-packaging.md'],
        'ask': [
            'Which builder made it? The container decides the extractor, and the builder is '
            'usually identifiable from two fields the triage report already prints.',
        ],
        'then': [
            'install the extractor rather than routing around it: a package manager answers the '
            'question in one command, and reasoning about a compressed blob from its strings '
            'produces nothing',
            'list before extracting: the inventory names the payload and costs a second',
            're-triage what came out. It is a new unknown, not the same target',
        ],
        'limits': [
            'The payload can be a different file format from the container. A Windows installer '
            'can deliver an ELF shared object, and a workflow that assumes otherwise stops there.',
            'A tool\'s declared version support is a signal about the tool, not a verdict on your '
            'file: run it and read the result.',
        ],
    },
    'analyze-flutter': {
        'name': 'Read a Flutter application\'s compiled Dart',
        'needs': ['flutter_static', 'installer_inspect'],
        'reads': ['flutter-and-dart-aot.md', 'static-analysis.md', 'license-mechanisms.md'],
        'ask': [
            'Is the Dart in a debug or a release shape? A release snapshot is stripped and '
            'position-independent, with no symbols to read.',
        ],
        'then': [
            'python scripts/dart_snapshot_strings.py <app.so> --find <keyword>   # literals survive '
            'AOT compilation, names do not',
            'read the reference-mechanism counts the same run prints: they tell you immediately '
            'whether instruction scanning can locate a literal\'s users at all',
        ],
        'limits': [
            'Locating the code that uses a literal needs the object pool parsed, and that needs '
            'tooling built for the exact Dart release. This kit stops at the literals and says so.',
            'A literal naming a feature is not the feature\'s decision site, and a client-side tier '
            'name says nothing about where the tier is decided.',
        ],
    },
    'analyze-managed': {
        'name': 'Read or change a .NET assembly',
        'needs': ['managed_inspect', 'pe_structure_read'],
        'reads': ['managed-dotnet.md', 'dotnet-decompilation.md', 'patching.md',
                  'integrity-checks.md'],
        'ask': [
            'Is the logic in CIL or in a native component the assembly loads? A managed wrapper '
            'around native code is a native problem wearing a managed shell.',
        ],
        'then': [
            'probe the installed runtimes rather than assuming one: a result is about the runtime '
            'that ran it, and a host can carry several at once',
            'editing metadata tables by hand produces an assembly that loads and does the wrong '
            'thing, which is worse than one that fails to load',
        ],
        'limits': [
            'A managed assembly is a different artifact with a different toolchain; hex-patching it '
            'is not a weaker method, it is the wrong one.',
        ],
    },
    'trace-execution': {
        'name': 'Record an instruction-level trace of a session',
        'needs': ['intel_pt_capture', 'ttd_record'],
        'reads': ['hardware-tracing.md', 'hypervisor-observation.md', 'environment.md'],
        'ask': [
            'Is the requirement a recording you can replay, or coverage you can query? They have '
            'different answers on this platform and only one of them is documented.',
        ],
        'then': [
            'python scripts/hwprobe.py   # the processor feature and the capture path are two '
            'different questions, and the probe reports them separately',
            'if the hardware route is closed, a recorded replay is the documented single-machine '
            'substitute, and it is read-only after the fact',
        ],
        'limits': [
            'The processor reporting the feature is not the same as a documented way to collect it. '
            'On this platform there is no first-party user-mode capture path, the in-box component '
            'is undocumented and tied to the hypervisor stack, and the tracing library documents '
            'one operating system\'s capture interface and no other. The remaining routes are that '
            'component or a kernel driver of your own with its signing constraints.',
            'A trace records control flow. It does not carry the values a program computed, with '
            'one narrow exception in the packet set, so a question about a compared value is not a '
            'trace question.',
        ],
    },
    'kernel-observe': {
        'name': 'Observe from a level the target cannot see',
        'needs': ['kernel_driver_load', 'hypervisor_observe'],
        'reads': ['hypervisor-observation.md', 'kernel-and-drivers.md', 'hardware-tracing.md',
                  'coverage-and-limits.md'],
        'ask': [
            'Is kernel access the requirement, or is it a means to an end that a user-mode route '
            'also reaches? The cost here is a reboot, a second machine, or a signature policy.',
        ],
        'then': [
            'python scripts/capabilities.py kernel_driver_load --verbose   # three separate gates, '
            'each with its own next action',
        ],
        'limits': [
            'One gate is not installable at all: whether a virtualisation layer already owns the '
            'level you want is a property of the machine.',
            'This kit documents this route and ships nothing for it. Do not read the reference as '
            'an implementation.',
        ],
    },
}

# A reading of the headers, used only to suggest intents. Keys are the signal ids `pe_triage.py`
# actually emits, plus three conditions this function derives for itself. It is a table of
# observations, never a verdict about what the operator wants -- measured against this file's own
# first version, which keyed on field names the triage report does not have and therefore suggested
# nothing for a target whose header clearly showed two triggers.
SAMPLE_HINTS = {
    'entry-point-outside-first-executable-section': ['extract-payload', 'unpack'],
    'high-entropy-section': ['unpack'],
    'authenticode-certificate-table-present': ['unlock-tier', 'observe-behaviour'],
    'relocations-absent': ['unpack'],
    'managed-directory-present': ['analyze-managed'],
    'installer-builder-stub': ['extract-payload'],
    'dart-snapshot': ['analyze-flutter'],
}


def verbosity_state(probe, intent):
    """Which of an intent's capabilities are ready, and what is missing from the rest."""
    ready, blocked = [], []
    for cid in INTENTS[intent]['needs']:
        result = caps.resolve(cid, probe)
        if result is None:
            blocked.append({'id': cid, 'reason': 'not a capability in the registry',
                            'missing': [], 'blocked_by': []})
            continue
        if result['state'] == 'ok':
            ready.append(cid)
        else:
            blocked.append({'id': cid, 'reason': 'blocked',
                            'missing': [[a, d] for a, d in result['missing']],
                            'blocked_by': [[d, s] for d, s in result['blocked_deps']]})
    return ready, blocked


def triage(path):
    """Run this kit's own triage and keep only what the intent table can read."""
    script = os.path.join(HERE, 'pe_triage.py')
    if not os.path.isfile(script):
        return None
    try:
        p = subprocess.run([sys.executable, '-B', script, path, '--json'],
                           capture_output=True, timeout=300, encoding='utf-8', errors='replace')
        return json.loads(p.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def elf_kind(path):
    """Is this an ELF image, and does it look like a Dart AOT snapshot?

    Read here rather than delegated, because the triage script refuses a non-PE input and a Flutter
    payload is exactly that: a Windows installer delivers an ELF shared object, so a planner that
    only understands PE cannot even name the intent for the file the user is holding.
    """
    try:
        with open(path, 'rb') as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if head[:4] != b'\x7fELF':
        return None
    if head[4] != 2:
        return 'elf'
    # A release Dart snapshot is stripped: a symbol table of a few dozen bytes and an unwinding
    # table that is a stub, beside a very large code section.
    return 'elf64'


def suggest_intents(report=None, kind=None):
    """Intents whose trigger conditions are actually shown. Never a conclusion about the aim."""
    shown = set()

    if kind in ('elf', 'elf64'):
        # Only one of the two can be told apart from a header, and only tentatively.
        shown.add('dart-snapshot')
        return (['analyze-flutter'],
                'the input is ELF%s, which a Windows triage cannot read at all; a compiled Dart '
                'snapshot is the common reason a Windows analysis meets one'
                % ('64' if kind == 'elf64' else ''))

    if not report:
        return [], 'triage could not be read'

    identity = report.get('identity') or {}
    build = report.get('build') or {}
    surface = report.get('surface') or {}
    sections = report.get('sections') or []

    for sig in report.get('signals') or []:
        sid = sig.get('id') if isinstance(sig, dict) else None
        if sid:
            shown.add(sid)
    if any((s.get('entropy') or 0) >= 7.2 for s in sections if isinstance(s, dict)):
        shown.add('high-entropy-section')
    if build.get('signed'):
        shown.add('authenticode-certificate-table-present')
    if build.get('managed') or build.get('clr_directory'):
        shown.add('managed-directory-present')
    entry_section = identity.get('entry_point_section') or ''
    if entry_section and entry_section not in ('.text', 'CODE', '.code'):
        shown.add('entry-point-outside-first-executable-section')
    # A builder's stub exports its loader. This is the signal that made a real target nameable.
    export_name = (surface.get('export_name') or '').lower()
    if export_name and ('setup' in export_name or 'loader' in export_name):
        shown.add('installer-builder-stub')

    out = []
    for trigger, intents in SAMPLE_HINTS.items():
        if trigger in shown:
            for i in intents:
                if i not in out:
                    out.append(i)
    return out, ('triggers observed: %s' % ', '.join(sorted(shown)) if shown
                 else 'no trigger in the header reading')


def print_plan(intent, ready, blocked, verbose, sample_note=None):
    spec = INTENTS[intent]
    print('intent: %s' % spec['name'])
    print('        %s' % intent)
    if sample_note:
        print('        %s' % sample_note)
    print()
    print('ask these first -- they decide whether the wish is well-posed:')
    for q in spec['ask']:
        print('  - %s' % q)
    print()
    print('capabilities this intent needs: %d ready, %d blocked' % (len(ready), len(blocked)))
    for cid in ready:
        print('  ok  %s' % cid)
    for row in blocked:
        print('  --  %s' % row['id'])
        for atom, detail in row['missing']:
            print('        missing : %s (%s)' % (atom, detail))
            aspec = caps.ATOMS.get(atom, {})
            if aspec.get('install'):
                print('        do this : %s' % aspec['install'])
        for dep, state in row['blocked_by']:
            print('        needs   : %s (%s) -- see `capabilities.py %s --verbose`'
                  % (dep, state, dep))
    print()
    print('first steps:')
    for step in spec['then']:
        print('  - %s' % step)
    print()
    print('read: %s' % ', '.join('skills/exe-reverse/references/%s' % r for r in spec['reads']))
    if verbose:
        print()
        print('limits that do not go away:')
        for lim in spec['limits']:
            print('  - %s' % lim)


def main():
    ap = argparse.ArgumentParser(
        description='Turn a stated intent into a route: what it needs, what this host has, and '
                    'what to do first.')
    ap.add_argument('intent', nargs='?', help='the intent id; --list prints them')
    ap.add_argument('--list', action='store_true', help='every intent this kit knows')
    ap.add_argument('--from-sample', metavar='PATH',
                    help='triage a file and suggest intents; a reading of the headers, not a wish')
    ap.add_argument('--verbose', action='store_true', help='include the limits')
    ap.add_argument('--tools-dir', action='append', default=[])
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.list:
        for i, spec in INTENTS.items():
            print('  %-18s %s' % (i, spec['name']))
        print('\n%d intent(s). Each resolves against the capability registry on this host.'
              % len(INTENTS))
        print('RESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    probe = caps.Probe(tool_dirs=(args.tools_dir or None))

    if args.from_sample:
        if not os.path.isfile(args.from_sample):
            sys.stderr.write('error: %s is not a file\n' % args.from_sample)
            print('RESULT=%s' % TOKENS['use'])
            return EXIT_USE
        kind = elf_kind(args.from_sample)
        report = None if kind else triage(args.from_sample)
        suggested, why = suggest_intents(report, kind)
        if args.json:
            print(json.dumps({'sample': args.from_sample, 'basis': why,
                              'suggested': suggested}, indent=2))
            print('RESULT=%s' % TOKENS['ready'])
            return EXIT_OK
        print('sample: %s' % args.from_sample)
        print('  %s' % why)
        print()
        if not suggested:
            print('  No intent follows from the headers alone. That is a reading, not a verdict:')
            print('  state the intent yourself with `plan.py <intent>`.')
            print('RESULT=%s' % TOKENS['ready'])
            return EXIT_OK
        print('  Suggested intents (a reading of the headers, never a conclusion about your aim):')
        for i in suggested:
            print('    %-18s %s' % (i, INTENTS[i]['name']))
        print('\n  Follow one with `plan.py <intent>`; `understand` is the safe default.')
        print('RESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    if not args.intent:
        sys.stderr.write('error: give an intent, or --list to see them\n')
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE
    if args.intent not in INTENTS:
        sys.stderr.write('error: no such intent: %s\n' % args.intent)
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    ready, blocked = verbosity_state(probe, args.intent)

    if args.json:
        print(json.dumps({'intent': args.intent, 'name': INTENTS[args.intent]['name'],
                          'ask': INTENTS[args.intent]['ask'],
                          'ready': ready, 'blocked': blocked,
                          'first_steps': INTENTS[args.intent]['then'],
                          'reads': INTENTS[args.intent]['reads'],
                          'limits': INTENTS[args.intent]['limits']}, indent=2))
        print('RESULT=%s' % (TOKENS['ready'] if not blocked else TOKENS['blocked']))
        return EXIT_OK if not blocked else EXIT_BLOCKED

    print_plan(args.intent, ready, blocked, args.verbose)
    print()
    if blocked:
        print('  %d capability(ies) blocked: the plan is readable and partly blocked, which is a '
              'finding to act on rather than a reason to stop.' % len(blocked))
    else:
        print('  everything this intent needs is available on this host.')
    print('RESULT=%s' % (TOKENS['ready'] if not blocked else TOKENS['blocked']))
    return EXIT_OK if not blocked else EXIT_BLOCKED


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERNAL)
