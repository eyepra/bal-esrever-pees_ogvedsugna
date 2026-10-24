#!/usr/bin/env python3
"""Environment doctor: what can actually run here, what is missing, and what will poison an
experiment if it is not noticed first.

WHY THIS EXISTS
---------------
This skill ships a set of scripts and describes a much larger set of routes. The most common
failure reported against a kit like this is not "the script is wrong" but "the script would not
start and I could not tell why" -- a module that is not importable on this interpreter, a tool
that is installed somewhere nothing searches, a route whose prerequisite is a processor feature
rather than an install. That costs a whole round before any analysis happens.

Run this once before a work block. It answers three questions:

  1. Which capabilities are available right now, with an executable next step for each one that
     is not?
  2. For every script in this directory, is it runnable as-is, and what does it need beyond the
     standard library?
  3. Are there environment facts that will silently poison experiments -- a virtualisation layer
     under the analysis host, a stale event-tracing session, a proxy left switched on, a clock
     that has moved, a launcher that is present but cannot actually do its job?

It never installs anything, never runs a debugger, and never touches a target.

WHAT THIS DOES NOT DO, AND WHY THAT IS STATED
---------------------------------------------
It cannot tell you whether a route works against a target, because it never opens one. Every
capability verdict here is about **this host**: whether the tool exists, whether the feature is
reported, whether the privilege is held. A route that is `ok` on this machine is a route that can
be attempted, not a route that has been proven.

THE THREE THINGS A REPORT MUST NOT DO
-------------------------------------
  * report a capability as available because a tool with that name exists -- the answer comes
    from the registry, which probes a capability's real closure;
  * drop a script it cannot classify -- those are printed as `unknown` and counted, because a
    denominator that quietly shrinks is how a report stops being a measurement;
  * import or run a script to find out what it needs -- dependencies come from a static pass, so
    the doctor cannot have side effects of its own.

Usage
-----
    python doctor.py                  # capability summary + script table + environment facts
    python doctor.py --scripts        # per-script runnability only
    python doctor.py --environment    # host facts that can poison an experiment
    python doctor.py --verbose        # + the next action for every blocked capability
    python doctor.py --json           # machine-readable

Exit codes: 0 = nothing blocked, 3 = at least one capability blocked, 2 = usage error,
4 = internal error. The last line is `RESULT=<token>`.
"""

import argparse
import ast
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL_DIR))

if HERE not in sys.path:
    sys.path.insert(0, HERE)
import capabilities as caps  # noqa: E402  (path is set above on purpose)

EXIT_OK = 0
EXIT_USE = 2
EXIT_ENV = 3
EXIT_INTERNAL = 4

TOKENS = {
    'ok': 'env_ok',
    'partial': 'env_partial',
    'blocked': 'env_blocked',
    'use': 'usage_error',
    'internal': 'internal_error',
}

_PROBE = caps.Probe()

# Names that look like a tool invocation inside a script's source. A literal outside this set is
# treated as data -- a subcommand, a shell builtin, a path fragment -- because guessing too
# eagerly reports a missing tool that was never needed, and a report full of those stops being
# read.
KNOWN_HOST_TOOLS = {
    'python', 'python3', 'py', 'git', 'dumpbin', 'link', 'editbin', 'signtool', 'mt',
    'ghidra', 'analyzeHeadless', 'ida', 'ida64', 'idat', 'idat64', 'binaryninja',
    'r2', 'radare2', 'rz-bin', 'rizin', 'cutter', 'diec', 'die', 'diel',
    'x64dbg', 'x32dbg', 'windbg', 'cdb', 'gdb', 'ttd',
    'frida', 'frida-trace', 'frida-ps', 'objection',
    'procdump', 'scylla', 'strings', 'objdump', 'nm', 'readelf', 'nasm',
    'wpr', 'xperf', 'tracelog', 'logman', 'tracerpt', 'tshark', 'dumpcap',
    'dotnet', 'ildasm', 'ilasm', 'corflags', 'msbuild', 'cl',
    'go', 'rustc', 'cargo', 'gcc', 'clang', 'cmake', 'make',
}


# ---------------------------------------------------------------- primitives

def run(cmd, timeout=20):
    """Run a command and return (returncode, combined output). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


# ---------------------------------------------------------------- static script analysis

def _module_names(tree):
    """Top-level module names imported anywhere in a module's AST."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split('.')[0])
    return names


def static_python_deps(path):
    """(third_party, unreadable_reason) for one script, from a static pass.

    Nothing is imported and nothing is executed: a doctor that runs a script to find out what
    it needs has side effects of its own, which is exactly what a diagnostic must not have.
    """
    try:
        with open(path, encoding='utf-8') as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError) as exc:
        return set(), str(exc)
    stdlib = getattr(sys, 'stdlib_module_names', None)
    siblings = {name[:-3] for name in os.listdir(HERE) if name.endswith('.py')}
    out = set()
    for name in _module_names(tree):
        if stdlib is not None and name in stdlib:
            continue
        if stdlib is None and name in ('os', 'sys', 'json', 're', 'ast', 'argparse', 'struct',
                                       'hashlib', 'math', 'collections', 'shutil', 'subprocess',
                                       'importlib', 'platform', 'time', 'ctypes', 'winreg',
                                       'tempfile', 'pathlib', 'textwrap', 'itertools',
                                       'datetime', 'io', 'zipfile', 'glob', 'typing'):
            continue
        if name in siblings:
            continue                       # a module this kit ships, not a dependency
        out.add(name)
    return out, None


def discover_scripts():
    """Every runnable file in this directory, scanned rather than listed.

    Scanned because a hand-written list goes stale the moment someone adds a script, and the
    report would then be quietly wrong about a file it never mentions.
    """
    found = []
    for name in sorted(os.listdir(HERE)):
        if name.endswith(('.py', '.js')):
            found.append(name)
    return found


def scan_scripts(capability_results):
    """Per-script: declared capability, third-party needs, and whether --help answers."""
    by_cap = {r['id']: r['state'] for r in capability_results}
    rows = []
    for name in discover_scripts():
        path = os.path.join(HERE, name)
        caps_decl, source = caps.capabilities_for_script(name, path)
        deps, broken = static_python_deps(path) if name.endswith('.py') else (set(), None)

        runnable, detail = None, ''
        if name.endswith('.py'):
            rc, out = run([sys.executable, '-B', path, '--help'], timeout=60)
            crashed = 'Traceback (most recent call last)' in out
            runnable = (not crashed) and bool(out.strip())
            if crashed:
                detail = out.strip().splitlines()[-1][:120]
            elif not out.strip():
                detail = 'no output from --help'
            elif rc != 0:
                detail = 'usage-ok rc=%d' % rc
        else:
            runnable, detail = True, 'not a python script; not run here'

        states = [by_cap.get(c, 'unknown') for c in caps_decl] if caps_decl else []
        if not caps_decl:
            cap_state = 'unknown'
        elif any(s != 'ok' for s in states):
            cap_state = 'blocked'
        else:
            cap_state = 'ok'

        rows.append({
            'script': name,
            'capabilities': caps_decl,
            'capability_source': source,
            'capability_state': cap_state,
            'runnable': runnable,
            'third_party': sorted(deps),
            'detail': detail,
        })
    return rows


# ---------------------------------------------------------------- environment facts

def environment_report():
    """Host facts that change a result without changing the target.

    Each row is a measurement, not an opinion, and each says what it would corrupt. The point
    is that these are the facts which make two runs incomparable while looking identical.
    """
    facts = []

    h = _PROBE.host()
    if 'error' in h:
        facts.append({'fact': 'host probe', 'value': 'unavailable',
                      'effect': h['error'], 'severity': 'note'})
        return facts

    def find(rows, needle):
        for r in rows:
            if needle.lower() in (r.get('note') or '').lower():
                return r
        return None

    cpu, osr, priv = h['cpu'], h['os'], h['privilege']

    hyp = find(cpu, 'ECX[31]')
    if hyp and hyp['value']:
        facts.append({
            'fact': 'walking a virtualisation layer',
            'value': 'a hypervisor reports itself present',
            'effect': 'the debug exception, single-stepping and the model-specific registers can '
                      'be intercepted rather than reaching your handler. A hardware route that '
                      'fails here is not necessarily misconfigured.',
            'severity': 'warn',
        })

    pt = find(cpu, 'EBX[25]')
    if pt:
        facts.append({
            'fact': 'processor trace capability',
            'value': 'reported' if pt['value'] else 'not reported',
            'effect': 'capability only. A trace also needs a way to reach its output, which on '
                      'this platform is not documented for user mode.',
            'severity': 'note',
        })

    elev = find(priv, 'TokenElevation')
    if elev:
        facts.append({
            'fact': 'session elevation',
            'value': 'elevated' if elev['value'] else 'not elevated',
            'effect': 'kernel event providers, driver loading and the replay recorder are '
                      'unavailable without it, and a script cannot raise it.',
            'severity': 'note' if elev['value'] else 'warn',
        })

    boot = find(osr, 'SystemStartOptions')
    if boot:
        flags = boot['value']
        facts.append({
            'fact': 'boot flags',
            'value': ', '.join(flags) if isinstance(flags, list) else str(flags),
            'effect': 'test signing is what lets your own driver load; its absence blocks that '
                      'route until a reboot changes it.',
            'severity': 'note',
        })

    dg = [r for r in osr if 'DeviceGuard' in (r.get('note') or '')]
    if dg and all(r['state'] == 'unavailable' for r in dg):
        facts.append({
            'fact': 'security-service state',
            'value': 'unknown (the values are absent and the cross-check was unavailable)',
            'effect': 'this is not the same as the feature being off. Treat it as unknown rather '
                      'than as disabled, because a plan that assumes "off" may be refused later.',
            'severity': 'note',
        })

    # Stale event-tracing sessions: a live session makes a new recording fail, and the failure
    # reads as a tool problem rather than as a leftover from an earlier run.
    if _PROBE.which('logman')[0]:
        rc, out = run(['logman', 'query', '-ets'], timeout=20)
        if rc == 0:
            lines = [ln for ln in out.splitlines()
                     if ln.strip() and 'Data Collector Set' not in ln and not ln.startswith(' The ')]
            if len(lines) > 2:
                facts.append({
                    'fact': 'event-tracing sessions',
                    'value': '%d line(s) reported by logman query -ets' % len(lines),
                    'effect': 'a session left running from an earlier block can make a new '
                              'recording fail. Stop it before recording.',
                    'severity': 'warn',
                })

    # A proxy left configured changes every network observation.
    for var in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if os.environ.get(var):
            facts.append({
                'fact': 'proxy environment',
                'value': '%s is set' % var,
                'effect': 'a capture taken through it describes the proxy hop, not the target.',
                'severity': 'warn',
            })
            break

    # Working directory: an output file written beside the input is easy to mistake for the
    # input later, and a read-only input is one of this kit's own rules.
    facts.append({
        'fact': 'working directory',
        'value': os.getcwd(),
        'effect': 'inputs are read-only by rule; write outputs somewhere you will recognise, and '
                  'keep the sample copy and its hash together.',
        'severity': 'note',
    })

    return facts


def _severity_summary(facts):
    warn = sum(1 for f in facts if f.get('severity') == 'warn')
    return warn


# ---------------------------------------------------------------- reporting

def print_capabilities(results, verbose):
    lines = caps.human_report(results, verbose=verbose)
    ok = sum(1 for r in results if r['state'] == 'ok')
    print('== capabilities ==')
    for line in lines:
        print(line)
    print('  %d ok, %d blocked of %d' % (ok, len(results) - ok, len(results)))
    if not verbose:
        blocked = [r['id'] for r in results if r['state'] != 'ok']
        if blocked:
            print('  blocked: %s' % ', '.join(blocked))
            print('  (--verbose prints the missing atom and the next action for each)')


def print_scripts(rows):
    print('== scripts ==')
    known = sum(1 for r in rows if r['capability_source'] != 'unknown')
    print('  registered/checked = %d / %d' % (known, len(rows)))
    width = max(len(r['script']) for r in rows) if rows else 10
    for r in rows:
        state = 'ok' if r['runnable'] and r['capability_state'] in ('ok', 'unknown') else 'check'
        extra = ''
        if r['third_party']:
            extra = '  needs: %s' % ', '.join(r['third_party'])
        if r['capability_source'] == 'unknown':
            extra += '  [capability unknown - counted, not skipped]'
        if r['detail']:
            extra += '  (%s)' % r['detail']
        print('  %-*s  %-5s %-24s%s' % (width, r['script'], state,
                                        ','.join(r['capabilities']) or '-', extra))
    unknown = [r['script'] for r in rows if r['capability_source'] == 'unknown']
    if unknown:
        print('  no capability declared or mapped: %s' % ', '.join(unknown))


def print_environment(facts):
    print('== environment facts that can change a result ==')
    for f in facts:
        print('  [%s] %s' % (f['severity'], f['fact']))
        print('        value : %s' % f['value'])
        print('        effect: %s' % f['effect'])


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write('error: %s\n' % message)
        sys.exit(EXIT_USE)


def main():
    ap = _Parser(description='What can run here, what is missing, and what would poison an '
                             'experiment.')
    ap.add_argument('--scripts', action='store_true', help='per-script runnability only')
    ap.add_argument('--environment', action='store_true', help='host facts only')
    ap.add_argument('--verbose', action='store_true', help='next action for every blocked item')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--tools-dir', action='append', default=[])
    args = ap.parse_args()

    if args.tools_dir:
        global _PROBE
        _PROBE = caps.Probe(tool_dirs=args.tools_dir)

    results = caps.resolve_all(_PROBE)
    rows = scan_scripts(results)
    facts = environment_report()

    v, rc = caps.verdict(results)
    warns = _severity_summary(facts)
    token = TOKENS['ok'] if rc == 0 and warns == 0 else (
        TOKENS['blocked'] if rc != 0 else TOKENS['partial'])

    if args.json:
        print(json.dumps({
            'capabilities': results,
            'scripts': rows,
            'environment': facts,
            'summary': {
                'capabilities_ok': sum(1 for r in results if r['state'] == 'ok'),
                'capabilities_total': len(results),
                'scripts_checked': len(rows),
                'scripts_with_unknown_capability': sum(
                    1 for r in rows if r['capability_source'] == 'unknown'),
                'environment_warnings': warns,
            },
            'result': token,
        }, indent=2))
        print('RESULT=%s' % token)
        return rc

    only_scripts = args.scripts and not args.environment
    only_env = args.environment and not args.scripts

    if not only_scripts and not only_env:
        print_capabilities(results, args.verbose)
        print()
    if not only_env:
        print_scripts(rows)
        print()
    if not only_scripts:
        print_environment(facts)
        print()

    print('== result ==')
    print('  %d/%d capabilities ok, %d script(s) checked, %d environment warning(s)'
          % (sum(1 for r in results if r['state'] == 'ok'), len(results), len(rows), warns))
    print('  Read this as a statement about this host, not about any target.')
    print('RESULT=%s' % token)
    return rc


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERNAL)
