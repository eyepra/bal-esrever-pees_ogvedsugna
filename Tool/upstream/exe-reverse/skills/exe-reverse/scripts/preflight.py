#!/usr/bin/env python3
"""capability: host_capability_probe

Pre-flight for one analysis session: is this experiment ready to start, and what will it cost?

WHY THIS IS SEPARATE FROM `doctor.py`
-------------------------------------
`doctor.py` answers a question about the **machine**: which capabilities exist here, what is
missing, and which host facts would poison an experiment in general. This script answers a
question about a **session**: given the sample in front of you and the route you intend to take,
is everything in place, and is there room to store what the route produces?

The distinction is not cosmetic. The failures this catches are the ones that appear twenty minutes
in: a recording that fills the disk, an output path that overwrites the previous run's evidence, a
sample whose hash was never taken so the result cannot be attributed to a specific input, or a
debug route that cannot start because a virtualisation layer is intercepting the mechanism. Every
one of those is cheap to check now and expensive to discover later.

WHAT IT CHECKS
--------------
  * the sample: present, readable, hashed, and a working copy rather than the only copy;
  * the destination: exists or can be created, is writable, is not the input's own directory, and
    has the free space the chosen route needs;
  * the route: for the routes whose cost is not in the tool but in the prerequisites, whether the
    host meets them -- elevation, a hypervisor-free host, test-signed driver loading, a debugger;
  * interference: leftover tracing sessions and live debuggers that make a run incomparable.

WHAT IT DOES NOT DO
-------------------
It never launches the sample, never opens a debugger, and never writes to the sample. It creates
the output directory if asked to and nothing else.

Usage
-----
    python preflight.py --sample target.exe
    python preflight.py --sample target.exe --out work --route trace
    python preflight.py --sample target.exe --out work --route kernel --json
    python preflight.py --sample target.exe --list-routes
    python preflight.py --space                      # every volume, and where a big route fits
    python preflight.py --cleanup E:\\exerev-work    # what a session left behind
    python preflight.py --cleanup E:\\exerev-work --yes   # remove exactly that

SPACE AND CLEANUP
-----------------
A route is not a plan until there is somewhere to put its output. The routes here differ by three
orders of magnitude in what they produce, and the largest ones fail in a way that is easy to
misread: a recording or a capture truncated by a full disk looks like a short one, and the result
gets interpreted rather than questioned.

So the space question is answered with a destination attached. When the chosen directory cannot
hold the route, the report names the volumes that can and gives the exact `--out` that fixes it,
because a check that says "not enough room here" without saying where there *is* room has turned a
one-flag correction into a dead end.

Every directory this script creates carries a manifest naming it as a session directory. That is
what makes cleanup safe: `--cleanup` considers only directories carrying the manifest, reports what
they occupy and what is large inside them, and deletes nothing until `--yes` is passed. A mistyped
path therefore cannot become a deleted document folder, which is the only acceptable behaviour for
a tool that removes things.

Exit codes: 0 = ready, 1 = ready with warnings, 3 = not ready, 2 = usage error.
The last line is `RESULT=<token>`.
"""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

EXIT_OK = 0
EXIT_WARN = 1
EXIT_USE = 2
EXIT_NOT_READY = 3

TOKENS = {'ready': 'preflight_ready', 'warn': 'preflight_ready_with_warnings',
          'not_ready': 'preflight_not_ready', 'use': 'usage_error'}

# Space a route needs beyond the sample itself. `basis` is the strength of the number: `observed`
# means this repository measured it, `unverified` means it is a planning aid. The point is not the
# figure's precision -- it is that a route with a large figure gets checked before it fills a disk,
# because the failure mode is a truncated recording that looks like a short one.
ROUTES = {
    'static': {
        'name': 'static analysis only',
        'needs_free_bytes': 64 * 1024 * 1024,
        'basis': 'observed',
        'why': 'text output, a patched copy, and a record. Measured: this repository\'s own scripts '
               'produced under 1 MB of output for a 31 MB target.',
        'requires': [],
    },
    'debug': {
        'name': 'interactive or command-line debugging',
        'needs_free_bytes': 256 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a dump taken mid-session is proportional to the process, and logs grow with the '
               'session length.',
        'requires': ['debugger'],
    },
    'dump': {
        'name': 'capture a process image',
        'needs_free_bytes': 4 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a full dump of a large process plus a repaired copy beside it. Treat this as a '
               'floor, not an estimate.',
        'requires': ['debugger'],
    },
    'trace': {
        'name': 'record a session for replay',
        'needs_free_bytes': 16 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'a replay recording is proportional to instructions executed and to the process\'s '
               'memory, and it is the largest artefact any route here produces. Establish the '
               'figure on a short run before recording a long one.',
        'requires': ['replay-recorder', 'elevation'],
    },
    'kernel': {
        'name': 'kernel-level observation',
        'needs_free_bytes': 2 * 1024 * 1024 * 1024,
        'basis': 'unverified',
        'why': 'kernel debug output, driver builds, and the artefacts of a restart cycle.',
        'requires': ['elevation', 'no-hypervisor', 'test-signing'],
    },
}


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, encoding='utf-8',
                           errors='replace')
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)


def volumes():
    """Every mounted volume with its free and total bytes, largest free space first.

    A route that needs sixteen gigabytes does not care which letter it lives on, and a check that
    reports "not enough room here" without naming where there *is* room turns a one-flag fix into a
    dead end. Standard library only: `os.listdrives` exists on newer interpreters, and the logical
    drive mask covers the rest without pulling in a dependency.
    """
    out = []
    drives = []
    if hasattr(os, 'listdrives'):
        try:
            drives = list(os.listdrives())
        except OSError:
            drives = []
    if not drives and os.name == 'nt':
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            drives = ['%s:\\' % chr(ord('A') + i) for i in range(26) if mask & (1 << i)]
        except (OSError, AttributeError):
            drives = []
    if not drives:
        drives = [os.path.abspath(os.sep)]
    for d in drives:
        try:
            usage = shutil.disk_usage(d)
        except OSError:
            continue                       # an empty optical drive, a disconnected share
        out.append((d, usage.free, usage.total))
    return sorted(out, key=lambda row: -row[1])


def gb(n):
    """Human-readable size. A megabyte reported as "0.0 GB" reads as nothing, which is exactly the
    wrong signal for an artefact someone is deciding whether to keep."""
    if n < 2 ** 20:
        return '%d KB' % (n / 1024)
    if n < 2 ** 30:
        return '%.1f MB' % (n / 2 ** 20)
    return '%.1f GB' % (n / 2 ** 30)


def volume_report(minimum_free=0):
    """A compact line per volume, and the best candidate for a large artefact."""
    vols = [v for v in volumes() if v[1] >= minimum_free] if minimum_free else volumes()
    if not vols:
        return [], None
    lines = ['%s %s free of %s' % (m, gb(free), gb(total)) for m, free, total in vols]
    return lines, vols[0]


# ---------------------------------------------------------------------------
# Cleanup. A route that needs sixteen gigabytes leaves something behind, and a
# work directory that nobody dares delete is a work directory that grows forever.
# The rule: this script deletes only a directory that carries its own manifest,
# so a mistyped path cannot become a deleted document folder.
# ---------------------------------------------------------------------------
MANIFEST = '.exerev-session.json'

# Artefacts this kit's routes produce that are large and disposable. Matched on suffix because the
# names come from the tools, not from here.
LARGE_SUFFIXES = ('.dmp', '.mdmp', '.etl', '.run', '.raw', '.trace', '.blob')


def write_manifest(out_dir, route, sample=None):
    """Leave a note in a directory saying who created it, and for what.

    Written on creation so that cleanup has something to verify. Without it, a cleanup pass is
    guessing which directories are its own, and guessing is how a tool deletes something it did not
    make.
    """
    import time
    path = os.path.join(out_dir, MANIFEST)
    if os.path.exists(path):
        return path
    doc = {'created_by': 'exe-reverse preflight', 'created_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
           'route': route, 'sample': os.path.abspath(sample) if sample else None,
           'note': 'This directory was created for one analysis session. Removing it removes that '
                   'session\'s artefacts. `preflight.py --cleanup <dir>` will only ever remove '
                   'directories carrying this file.'}
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(doc, fh, indent=2)
    except OSError:
        return None
    return path


def _tree_size(path):
    total = 0
    largest = []
    for dirpath, dirnames, files in os.walk(path):
        dirnames[:] = [d for d in dirnames if d != '__pycache__']
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            total += size
            if f.lower().endswith(LARGE_SUFFIXES):
                largest.append((size, p))
    largest.sort(reverse=True)
    return total, largest


def cleanup_scan(roots):
    """Every manifest-carrying directory under the given roots, with what it occupies."""
    found = []
    for root in roots:
        root = os.path.abspath(root)
        if os.path.isfile(os.path.join(root, MANIFEST)):
            candidates = [root]
        elif os.path.isdir(root):
            candidates = []
            for dirpath, dirnames, files in os.walk(root):
                if MANIFEST in files:
                    candidates.append(dirpath)
                    dirnames[:] = []          # do not descend into a session we already found
        else:
            continue
        for d in candidates:
            try:
                with open(os.path.join(d, MANIFEST), encoding='utf-8') as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                doc = {'note': 'manifest unreadable'}
            total, largest = _tree_size(d)
            found.append({'dir': d, 'bytes': total, 'manifest': doc,
                          'largest': [{'bytes': b, 'path': p} for b, p in largest[:8]]})
    return found


def cleanup_run(rows, confirm):
    """Remove what the scan found. Refuses anything that is not one of ours."""
    freed = 0
    removed = []
    for row in rows:
        d = row['dir']
        if not os.path.isfile(os.path.join(d, MANIFEST)):
            continue                          # re-verified immediately before the delete
        if not confirm:
            continue
        try:
            shutil.rmtree(d)
            freed += row['bytes']
            removed.append(d)
        except OSError:
            continue
    return freed, removed


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


class Check(object):
    """One finding, with the severity that decides the exit code."""

    def __init__(self, area, ok, detail, severity='block', fix=''):
        self.area = area
        self.ok = ok
        self.detail = detail
        self.severity = severity          # block | warn | note
        self.fix = fix

    def as_dict(self):
        return {'area': self.area, 'ok': self.ok, 'detail': self.detail,
                'severity': self.severity, 'fix': self.fix}


def check_sample(path, out_dir):
    checks = []
    if not path:
        return checks
    if not os.path.isfile(path):
        checks.append(Check('sample', False, '%s is not a file' % path,
                            fix='give the path to the sample you intend to analyse'))
        return checks
    size = os.path.getsize(path)
    digest = sha256_of(path)
    checks.append(Check('sample', True, '%s, %d bytes, sha256 %s' % (path, size, digest[:16]),
                        severity='note'))
    checks.append(Check('sample', True,
                        'record this hash with every result: a conclusion is about these bytes',
                        severity='note'))
    writable = os.access(path, os.W_OK)
    if writable:
        checks.append(Check('sample', False,
                            'the sample is writable, so it can be modified in place by accident',
                            severity='warn',
                            fix='work on a copy: this kit\'s patcher writes a new file, but a '
                                'debugger or a tool you did not write may not'))
    else:
        checks.append(Check('sample', True, 'the sample is not writable (a good default)',
                            severity='note'))
    if out_dir:
        same = os.path.abspath(os.path.dirname(os.path.abspath(path))) == \
            os.path.abspath(out_dir)
        if same:
            checks.append(Check('sample', False,
                                'the output directory is the sample\'s own directory',
                                severity='warn',
                                fix='write outputs elsewhere: an output beside an input of the same '
                                    'name is how the wrong file gets analysed next'))
    return checks


def check_destination(out_dir, route, sample=None):
    checks = []
    if not out_dir:
        return checks
    spec = ROUTES[route]
    abs_out = os.path.abspath(out_dir)
    if not os.path.isdir(abs_out):
        parent = os.path.dirname(abs_out) or '.'
        if not os.path.isdir(parent):
            checks.append(Check('destination', False,
                                '%s does not exist and neither does %s' % (abs_out, parent),
                                fix='create the parent, or name a directory that exists'))
            return checks
        try:
            os.makedirs(abs_out, exist_ok=True)
            checks.append(Check('destination', True, 'created %s' % abs_out, severity='note'))
        except OSError as exc:
            checks.append(Check('destination', False, 'could not create %s: %s' % (abs_out, exc),
                                fix='choose a path you can write to'))
            return checks
    # A manifest on creation is what makes the directory safely removable later.
    if os.path.isdir(abs_out) and os.access(abs_out, os.W_OK):
        write_manifest(abs_out, route, sample)
    if not os.access(abs_out, os.W_OK):
        checks.append(Check('destination', False, '%s is not writable' % abs_out,
                            fix='choose a writable path'))
        return checks

    try:
        usage = shutil.disk_usage(abs_out)
        need = spec['needs_free_bytes']
        here = os.path.splitdrive(abs_out)[0]
        if usage.free < need:
            # Name somewhere that *does* have room. A refusal without an alternative is the check
            # being unhelpful about the one thing it knows and the caller does not.
            roomier = [(m, f) for m, f, _t in volumes()
                       if m.rstrip('\\/').lower() != here.rstrip('\\/').lower() and f >= need]
            fix = ('free space, choose a cheaper route, or write to a volume that has room. A '
                   'recording truncated by a full disk looks exactly like a short one, which is '
                   'why this is checked before it starts.')
            if roomier:
                fix += (' Volumes with enough free space: %s. Re-run with --out %s and nothing '
                        'else has to change.'
                        % (', '.join('%s (%s free)' % (m, gb(f)) for m, f in roomier),
                           os.path.join(roomier[0][0], 'exerev-work')))
            checks.append(Check('destination', False,
                                'route "%s" needs about %s; %s free on %s'
                                % (route, gb(need), gb(usage.free), here or 'this volume'),
                                fix=fix))
        else:
            checks.append(Check('destination', True,
                                'route "%s" needs about %s; %s free on %s (cost basis: %s)'
                                % (route, gb(need), gb(usage.free), here or 'this volume',
                                   spec['basis']),
                                severity='note'))
    except OSError as exc:
        checks.append(Check('destination', True, 'free space unreadable: %s' % exc,
                            severity='warn'))
    return checks


def check_requirements(route, probe):
    """The route's prerequisites, from the same probe the rest of the kit uses."""
    checks = []
    spec = ROUTES[route]
    for req in spec['requires']:
        if req == 'elevation':
            v = probe._host_flag('elevation')
            checks.append(Check('route', bool(v),
                                'elevation: %s' % ('held' if v else 'not held'),
                                severity='note' if v else 'block',
                                fix='' if v else 'start an elevated shell; a script cannot raise '
                                                 'its own privilege'))
        elif req == 'no-hypervisor':
            v = probe._host_flag('hypervisor')
            checks.append(Check('route', bool(v),
                                'no virtualisation layer under this host: %s'
                                % ('yes' if v else 'no, one reports itself'),
                                severity='note' if v else 'block',
                                fix='' if v else 'the interception this route depends on may be '
                                                 'consumed by the layer. Move to a host without it, '
                                                 'or accept the route may not fire'))
        elif req == 'test-signing':
            v = probe._host_flag('test_signing')
            checks.append(Check('route', bool(v),
                                'test signing: %s' % ('enabled' if v else 'not enabled'),
                                severity='note' if v else 'block',
                                fix='' if v else 'bcdedit /set testsigning on, then reboot; a policy '
                                                 'may still refuse the driver'))
        elif req == 'debugger':
            found = [t for t in ('cdb', 'windbg', 'x64dbg', 'gdb') if probe.which(t)[0]]
            checks.append(Check('route', bool(found),
                                'debugger: %s' % (', '.join(found) if found else 'none found'),
                                severity='note' if found else 'block',
                                fix='' if found else 'install the debugging tools for Windows, or '
                                                     'route this question through a capability that '
                                                     'is available'))
        elif req == 'replay-recorder':
            found = [t for t in ('ttd', 'TTD') if probe.which(t)[0]]
            checks.append(Check('route', bool(found),
                                'replay recorder: %s' % ('present' if found else 'not found'),
                                severity='note' if found else 'block',
                                fix='' if found else 'it ships with the modern debugger package'))
    return checks


def host_in_use():
    """Is somebody using this machine right now?

    A dynamic route launches the target, opens windows, and may capture the screen. On a machine
    that is in use, all three are interference: a launched window steals focus from whatever the
    operator is doing, and a screen capture can contain their work rather than the target's -- which
    is both a privacy problem and a useless observation.

    This was learned the direct way. During one session a target was launched on a host whose owner
    was in the middle of a full-screen game, and the capture that came back was their game, not the
    target. Nothing was damaged, but the analysis had been adding load and taking pictures on a
    machine someone else was using, and no part of the kit had thought to check.

    Standard library only: the foreground window and the screen metrics come from the platform's own
    interface. A borderless window covering the screen is the interference case this check exists
    for. A merely maximised window is NOT: on this platform the operator routinely drives the agent
    through a maximised browser, so a rule that reads "maximised" as "owns the display" fires on the
    operator reading the agent's own output -- which it did, every round, for many rounds, and the
    interference it warned about never existed. The distinction is one flag: maximised windows keep
    their caption and their taskbar; full-screen ones are borderless.
    """
    if os.name != 'nt':
        return {'in_use': None, 'detail': 'not checked on this platform'}
    try:
        import ctypes
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return {'in_use': False, 'detail': 'no foreground window'}
        rect = ctypes.create_string_buffer(16)
        if not user32.GetWindowRect(hwnd, rect):
            return {'in_use': None, 'detail': 'foreground window unreadable'}
        left, top, right, bottom = struct.unpack('<4i', rect.raw)
        sw = user32.GetSystemMetrics(0)
        sh = user32.GetSystemMetrics(1)
        covers = (right - left) >= sw and (bottom - top) >= sh
        maximised = bool(user32.IsZoomed(hwnd))
        style = user32.GetWindowLongA(hwnd, -16)
        popup = bool(style & 0x80000000)
        fullscreen = covers and popup and not maximised
        # The title is the operator's, not ours: report that there is one, never what it says.
        if fullscreen:
            detail = 'a borderless full-screen window owns the display'
        elif covers and maximised:
            detail = ('the foreground window is maximised, not full-screen '
                      '(an operator reading a maximised agent window is not interference)')
        else:
            detail = 'the foreground window is not full-screen'
        return {'in_use': bool(fullscreen), 'detail': detail, 'screen': '%dx%d' % (sw, sh)}
    except (OSError, AttributeError) as exc:
        return {'in_use': None, 'detail': 'could not be determined: %s' % exc}


def check_host_use():
    """One check, worded so the reader knows what to do about it rather than only what is true."""
    state = host_in_use()
    if state.get('in_use'):
        return [Check('host', False,
                      'this machine appears to be in use: %s' % state['detail'],
                      severity='warn',
                      fix='do the dynamic part later, or on a machine nobody is using. Launched '
                          'windows take focus from whoever is working, and a screen capture can '
                          'contain their screen instead of the target -- ask before adding load '
                          'to somebody else\'s session')]
    if state.get('in_use') is None:
        return [Check('host', True, 'host use not determined (%s)' % state['detail'],
                      severity='note')]
    return [Check('host', True, 'no full-screen window is in the foreground', severity='note')]


def check_disk_room(route):
    """A nearly-full volume is a host fact that poisons every dynamic route, quietly.

    Measured on this codebase's own target: with the system volume at zero bytes free, the
    injection layer could not write its agent (attach fails with "no space left on device"),
    the target crashed writing its session data, and a test run produced two hundred errors
    that looked like code failures and were tmpdir creation failures. A warn, not a stop:
    free space or move the work to a roomier volume, then run.
    """
    try:
        import shutil
        total, used, free = shutil.disk_usage(os.path.dirname(os.path.abspath('.')) or '.')
        free_gb = free / (1024 ** 3)
    except (OSError, ValueError) as exc:
        return [Check('disk', True, 'free space not determined (%s)' % exc, severity='note')]
    floor_gb = 2.0
    if route == 'static':
        floor_gb = 0.5
    if free_gb < floor_gb:
        return [Check('disk', False,
                      '%.2f GB free on the working volume; a %s route wants at least %.1f GB'
                      % (free_gb, route, floor_gb),
                      severity='warn',
                      fix='free space or move the working directory to a roomier volume before '
                          'the dynamic part. A full volume does not refuse to start: the target '
                          'launches, then dies mid-run where it first writes -- and the crash '
                          'looks like the target\'s bug, not the disk\'s')]
    return [Check('disk', True, '%.2f GB free on the working volume' % free_gb, severity='note')]


def check_interference(probe):
    checks = []
    if probe.which('logman')[0]:
        rc, out = run(['logman', 'query', '-ets'], timeout=20)
        if rc == 0:
            sessions = [ln for ln in out.splitlines()
                        if ln.strip() and 'Data Collector Set' not in ln and '---' not in ln
                        and not ln.startswith(' The ')]
            checks.append(Check('interference', True,
                                '%d tracing session(s) currently active (most are part of a normal '
                                'Windows boot)' % len(sessions), severity='note'))
    for t in ('x64dbg', 'x32dbg', 'windbg', 'cdb'):
        path, _via = probe.which(t)
        if path:
            checks.append(Check('interference', True,
                                '%s is installed at %s' % (t, path), severity='note'))
            break

    proxy = [v for v in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')
             if os.environ.get(v)]
    if proxy:
        checks.append(Check('interference', False,
                            '%s set: any capture through it describes the proxy hop' % proxy[0],
                            severity='warn',
                            fix='unset it for this session, or state in the record that the '
                                'observation went through it'))
    return checks


def main():
    ap = argparse.ArgumentParser(
        description='Is this analysis session ready to start, and is there room for what it '
                    'will produce?')
    ap.add_argument('--sample', help='the file about to be analysed')
    ap.add_argument('--out', help='the directory this session will write to')
    ap.add_argument('--route', default='static', choices=sorted(ROUTES),
                    help='the route you intend to take (default: static)')
    ap.add_argument('--list-routes', action='store_true', help='what each route costs and needs')
    ap.add_argument('--space', action='store_true',
                    help='every mounted volume and how much room it has')
    ap.add_argument('--cleanup', nargs='*', metavar='ROOT',
                    help='find session directories created by this script under ROOT (default: the '
                         'working directory and the system temp directory) and report what they '
                         'occupy. Nothing is deleted without --yes, and only directories carrying '
                         'this script\'s own manifest are ever considered')
    ap.add_argument('--yes', action='store_true',
                    help='with --cleanup: actually delete, instead of reporting')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.list_routes:
        for key in sorted(ROUTES):
            spec = ROUTES[key]
            print('  %-8s %-40s ~%.1f GB  needs: %s'
                  % (key, spec['name'], spec['needs_free_bytes'] / 2**30,
                     ', '.join(spec['requires']) or 'nothing beyond the machine'))
            print('           %s' % spec['why'])
        print('\nRESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    if args.space:
        vols = volumes()
        if not vols:
            sys.stderr.write('error: no volume could be measured\n')
            print('RESULT=%s' % TOKENS['use'])
            return EXIT_USE
        print('volumes, largest free space first:')
        for m, free, total in vols:
            print('  %-8s %s free of %s' % (m, gb(free), gb(total)))
        need = ROUTES[args.route]['needs_free_bytes']
        ok = [v for v in vols if v[1] >= need]
        print('\n  route "%s" needs about %s' % (args.route, gb(need)))
        if ok:
            print('  write it to %s' % os.path.join(ok[0][0], 'exerev-work'))
        else:
            print('  no volume here has room for that route; pick a cheaper one with '
                  '--list-routes')
        print('RESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    if args.cleanup is not None:
        import tempfile
        roots = args.cleanup or [os.getcwd(), tempfile.gettempdir()]
        rows = cleanup_scan(roots)
        if args.json:
            print(json.dumps({'roots': roots, 'found': rows,
                              'total_bytes': sum(r['bytes'] for r in rows),
                              'deleted': bool(args.yes)}, indent=2))
        if not rows:
            print('nothing to clean under: %s' % ', '.join(roots))
            print('  only directories carrying %s are ever considered' % MANIFEST)
            print('RESULT=%s' % TOKENS['ready'])
            return EXIT_OK
        total = sum(r['bytes'] for r in rows)
        if not args.json:
            print('session directories this script created:')
            for r in rows:
                when = r['manifest'].get('created_at', 'unknown')
                route = r['manifest'].get('route', 'unknown')
                print('  %-58s %8s  route %s, created %s' % (r['dir'], gb(r['bytes']), route, when))
                for big in r['largest'][:3]:
                    print('        %8s  %s' % (gb(big['bytes']), os.path.basename(big['path'])))
            print('\n  %d director(y|ies), %s reclaimable' % (len(rows), gb(total)))
        if args.yes:
            freed, removed = cleanup_run(rows, confirm=True)
            print('  removed %d director(y|ies), freed %s' % (len(removed), gb(freed)))
        else:
            print('  nothing was deleted. Re-run with --yes to remove exactly these directories.')
        print('RESULT=%s' % TOKENS['ready'])
        return EXIT_OK

    if not args.sample and not args.out:
        sys.stderr.write('error: give --sample, --out, or both\n')
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    import capabilities as caps
    probe = caps.Probe()

    checks = []
    checks.extend(check_sample(args.sample, args.out))
    checks.extend(check_destination(args.out, args.route, args.sample))
    checks.extend(check_requirements(args.route, probe))
    checks.extend(check_host_use())
    checks.extend(check_disk_room(args.route))
    checks.extend(check_interference(probe))

    blocks = [c for c in checks if not c.ok and c.severity == 'block']
    warns = [c for c in checks if not c.ok and c.severity == 'warn']
    if blocks:
        token, code = TOKENS['not_ready'], EXIT_NOT_READY
    elif warns:
        token, code = TOKENS['warn'], EXIT_WARN
    else:
        token, code = TOKENS['ready'], EXIT_OK

    if args.json:
        print(json.dumps({'route': args.route, 'route_name': ROUTES[args.route]['name'],
                          'checks': [c.as_dict() for c in checks],
                          'blocks': len(blocks), 'warnings': len(warns),
                          'result': token}, indent=2))
        print('RESULT=%s' % token)
        return code

    print('pre-flight -- route: %s (%s)' % (args.route, ROUTES[args.route]['name']))
    print('  %s' % ROUTES[args.route]['why'])
    print()
    for c in checks:
        mark = 'ok  ' if c.ok else ('WARN' if c.severity == 'warn' else 'STOP')
        print('  %s %-12s %s' % (mark, c.area, c.detail))
        if not c.ok and c.fix:
            print('       %s' % c.fix)
    print()
    print('  %d blocking, %d warning(s)' % (len(blocks), len(warns)))
    print('  This is a statement about the session, not about the target.')
    print('RESULT=%s' % token)
    return code


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_USE)
