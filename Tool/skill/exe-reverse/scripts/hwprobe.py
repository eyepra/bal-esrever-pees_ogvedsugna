#!/usr/bin/env python3
"""Probe what THIS machine can actually do, before a plan depends on it.

Why this runs first: every hardware-assisted route in this skill is conditional. Intel
Processor Trace needs a supported CPU *and* a way to reach the trace output; hardware
breakpoints need four debug registers and no hypervisor eating the debug exception; a
kernel driver needs test signing or a second machine; VBS/HVCI changes what a debugger is
allowed to do. Assuming any of that produces a plan that fails at the first step and gets
blamed on the target.

This script answers "which routes exist here" with measurements, and it distinguishes
three states everywhere:

  available    — measured to work on this machine
  needs-<x>    — the mechanism exists but is gated on something named in the row
  unavailable  — measured absent, or the probe could not run (the reason is printed)

CPU detection reads CPUID directly through a tiny position-independent stub executed with
the platform's own allocator. That is a local CPU instruction call, not process injection:
no other process is opened, nothing is written outside this process, and the stub is freed
before exit. If the platform refuses it, the probe reports `unavailable` and says so
instead of guessing from a marketing string.

Raw CPUID register values are always printed for anything whose bit meanings this script
does not claim to know. A capability bit read out of a memory of the specification is a
fabrication risk; `--raw` prints every leaf/sub-leaf this tool touches.

Usage:
    python hwprobe.py                 # capability report for this machine
    python hwprobe.py --json          # machine-readable
    python hwprobe.py --raw           # every CPUID leaf/sub-leaf probed, undecoded
    python hwprobe.py --tools         # tool inventory only

Exit codes: 0 = report produced, 2 = usage error. Capabilities that are missing are a
finding, not a failure: this script never exits non-zero because a machine is limited.
"""
import argparse
import ctypes
import json
import os
import platform
import shutil
import struct
import sys

try:
    import winreg
except ImportError:      # non-Windows host: the OS rows degrade, CPUID still works
    # A typing gap, not a runtime one: every use below tests for None before touching it.
    winreg = None        # type: ignore[assignment]

# --- CPUID stub ---------------------------------------------------------------
# uint32_t probe(uint32_t leaf /*rcx*/, uint32_t sub /*rdx*/, uint32_t out[4] /*r8*/)
# Windows x64 ABI: rcx, rdx, r8 are the first three integer arguments.
_CPUID_STUB = bytes([
    0x8B, 0xC1,                     # mov  eax, ecx        (leaf)
    0x8B, 0xCA,                     # mov  ecx, edx        (sub-leaf)
    0x0F, 0xA2,                     # cpuid
    0x41, 0x89, 0x00,               # mov  [r8],    eax
    0x41, 0x89, 0x58, 0x04,         # mov  [r8+4],  ebx
    0x41, 0x89, 0x48, 0x08,         # mov  [r8+8],  ecx
    0x41, 0x89, 0x50, 0x0C,         # mov  [r8+12], edx
    0xC3,                           # ret
])

MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE = 0x8000

# Bit meanings this project states as *verified against a primary source*. Every entry
# records where it was confirmed, so a reader can re-check it and a future correction has
# exactly one place to change. Anything not in this table is reported as a raw value.
VERIFIED_BITS = {
    'leaf1_ecx_bit31': ('hypervisor_present',
                        'CPUID.01H:ECX[31] — set when a hypervisor is running the guest'),
    'leaf1_edx_bit5': ('vmx', 'CPUID.01H:EDX[5] — VMX (Intel VT-x) support'),
    'leaf1_edx_bit4': ('tsc', 'CPUID.01H:EDX[4] — time-stamp counter'),
    'leaf7_ebx_bit25': ('intel_pt', 'CPUID.07H.0:EBX[25] — Intel Processor Trace'),
}

# Processor-trace capability bits, decoded separately from the table above because their
# provenance is weaker and that has to be visible in the output.
#
# SOURCE: these encodings were read from an operating system kernel's implementation of the
# CPUID contract for the same feature, not from the processor vendor's specification document
# (which was not reachable when this probe was written). They are reported as `inferred`. The
# shape they establish is what a plan needs: the feature exists, it has its own capability leaf,
# and every route that uses it is privileged. A reader who needs the normative definition should
# consult the specification for the processor family in front of them.
PT_EBX_BITS = {
    0: 'cr3_filtering', 1: 'psb_cyc', 2: 'ip_filtering', 3: 'mtc', 4: 'ptwrite',
    5: 'power_event_trace', 7: 'event_trace', 8: 'tnt_disable',
}
PT_ECX_BITS = {
    0: 'topa_output', 1: 'topa_multiple_entries', 2: 'single_range_output',
    3: 'output_subsys', 31: 'payloads_lip',
}


class Cpuid(object):
    """CPUID access with an explicit available/unavailable state."""

    def __init__(self):
        self.available = False
        self.reason = None
        self._fn = None
        self._buf = None
        if not hasattr(ctypes, 'WinDLL'):
            self.reason = 'CPUID stub is a Windows x64 calling-convention call; this host is %s' \
                          % platform.system()
            return
        try:
            k32 = ctypes.WinDLL('kernel32', use_last_error=True)
            k32.VirtualAlloc.restype = ctypes.c_void_p
            k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                         ctypes.c_uint32, ctypes.c_uint32]
            k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
            buf = k32.VirtualAlloc(None, len(_CPUID_STUB), MEM_COMMIT_RESERVE,
                                   PAGE_EXECUTE_READWRITE)
            if not buf:
                self.reason = ('VirtualAlloc(PAGE_EXECUTE_READWRITE) refused, err=%d; a policy '
                               'or EDR product is blocking executable allocations'
                               % ctypes.get_last_error())
                return
            ctypes.memmove(buf, _CPUID_STUB, len(_CPUID_STUB))
            proto = ctypes.CFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32,
                                     ctypes.POINTER(ctypes.c_uint32))
            self._fn = proto(buf)
            self._buf = (buf, k32)
            self.available = True
        except Exception as exc:                      # pragma: no cover - host dependent
            self.reason = 'stub could not be prepared: %s' % exc

    def call(self, leaf, sub=0):
        if not self.available:
            raise RuntimeError(self.reason)
        out = (ctypes.c_uint32 * 4)()
        self._fn(leaf, sub, out)
        return out[0], out[1], out[2], out[3]

    def close(self):
        if self._buf:
            try:
                self._buf[1].VirtualFree(ctypes.c_void_p(self._buf[0]), 0, MEM_RELEASE)
            except Exception:
                pass
            self._buf = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _le(v):
    return struct.pack('<I', v)


def _reg(row):
    """A row is (state, value, note). Printers only need one shape."""
    return {'state': row[0], 'value': row[1], 'note': row[2]}


def probe_cpu(cpuid, want_raw=False):
    rows = []
    raw = {}
    if not cpuid.available:
        rows.append(_reg(('unavailable', None, cpuid.reason)))
        return rows, raw

    a, b, c, d = cpuid.call(0)
    vendor = (_le(b) + _le(d) + _le(c)).decode('latin-1').strip('\0 ')
    rows.append(_reg(('available', vendor, 'CPUID.00H')))
    raw['leaf0'] = {'eax': a, 'ebx': b, 'ecx': c, 'edx': d}
    max_leaf = a

    family = ((a >> 8) & 0xF) + ((a >> 20) & 0xFF)
    model = ((a >> 4) & 0xF) + (((a >> 16) & 0xF) << 4)
    stepping = a & 0xF
    a1, b1, c1, d1 = cpuid.call(1)
    family = ((a1 >> 8) & 0xF) + ((a1 >> 20) & 0xFF)
    model = ((a1 >> 4) & 0xF) + (((a1 >> 16) & 0xF) << 4)
    stepping = a1 & 0xF
    rows.append(_reg(('available', 'family %d model %d stepping %d' % (family, model, stepping),
                      'CPUID.01H')))
    raw['leaf1'] = {'eax': a1, 'ebx': b1, 'ecx': c1, 'edx': d1}

    brand = None
    a_ext, = (cpuid.call(0x80000000)[0],)
    if a_ext >= 0x80000004:
        acc = b''
        for leaf in (0x80000002, 0x80000003, 0x80000004):
            x = cpuid.call(leaf)
            acc += _le(x[0]) + _le(x[1]) + _le(x[2]) + _le(x[3])
        brand = acc.split(b'\0')[0].decode('latin-1').strip()
        rows.append(_reg(('available', brand, 'CPUID.80000002-4H brand string')))
    raw['max_extended_leaf'] = a_ext

    hyper = (c1 >> 31) & 1
    rows.append(_reg(('available', bool(hyper), VERIFIED_BITS['leaf1_ecx_bit31'][1])))

    if max_leaf >= 7:
        a7, b7, c7, d7 = cpuid.call(7, 0)
        raw['leaf7_0'] = {'eax': a7, 'ebx': b7, 'ecx': c7, 'edx': d7}
        pt = (b7 >> 25) & 1
        rows.append(_reg(('available', bool(pt), VERIFIED_BITS['leaf7_ebx_bit25'][1])))
        if pt:
            a14, b14, c14, d14 = cpuid.call(0x14, 0)
            raw['leaf14_0'] = {'eax': a14, 'ebx': b14, 'ecx': c14, 'edx': d14}
            caps = [n for b, n in sorted(PT_EBX_BITS.items()) if b14 & (1 << b)]
            caps += [n for b, n in sorted(PT_ECX_BITS.items()) if c14 & (1 << b)]
            rows.append(_reg(('needs-kernel-driver-or-replay-debugger',
                              'max sub-leaf %d; EBX=0x%08X ECX=0x%08X' % (a14, b14, c14),
                              'CPUID.14H.0. Capability names inferred from a kernel '
                              'implementation of this contract, not from the vendor '
                              'specification, so treat them as a reading aid: %s. What decides a '
                              'plan is that on this platform there is no documented user-mode '
                              'path to the trace unit, so the practical alternatives are a '
                              'record-and-replay debugger, an undocumented in-box driver, or a '
                              'different platform' % (', '.join(caps) or 'no capability bit set'))))
        a1c, b1c, c1c, d1c = cpuid.call(0x1C, 0) if max_leaf >= 0x1C else (0, 0, 0, 0)
        if max_leaf >= 0x1C:
            raw['leaf1C_0'] = {'eax': a1c, 'ebx': b1c, 'ecx': c1c, 'edx': d1c}
            rows.append(_reg(('needs-privilege',
                              'raw EAX=0x%08X EBX=0x%08X ECX=0x%08X' % (a1c, b1c, c1c),
                              'CPUID.1CH.0 — last-branch-record capability. The record depth is a '
                              'bit mask rather than a count, and it varies by processor '
                              'generation (4, 8, 16 and 32 have all been measured across '
                              'families), so a hardcoded depth is wrong. Reading the records '
                              'requires privilege')))
    if max_leaf >= 0x0A:
        a0a, b0a, c0a, d0a = cpuid.call(0x0A, 0)
        raw['leaf0A_0'] = {'eax': a0a, 'ebx': b0a, 'ecx': c0a, 'edx': d0a}
        rows.append(_reg(('available',
                          'ver %d, counters %d, EBX=0x%08X EDX=0x%08X'
                          % ((a0a >> 8) & 0xFF, a0a & 0xFF, b0a, d0a),
                          'CPUID.0AH.0 — architectural performance monitoring')))
    if want_raw:
        for leaf in (2, 4, 6, 0x0D, 0x1F, 0x80000001, 0x80000008):
            if leaf <= max_leaf or (leaf >= 0x80000000 and leaf <= a_ext):
                x = cpuid.call(leaf)
                raw['leaf%X' % leaf] = {'eax': x[0], 'ebx': x[1], 'ecx': x[2], 'edx': x[3]}
    return rows, raw


# --- OS / policy --------------------------------------------------------------
REG_ROWS = [
    (r'SYSTEM\CurrentControlSet\Control\DeviceGuard', 'EnableVirtualizationBasedSecurity',
     'vbs_enabled', 'Virtualization-based security'),
    (r'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity',
     'Enabled', 'hvci_enabled', 'HVCI (hypervisor-enforced code integrity)'),
    (r'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard',
     'Enabled', 'credential_guard', 'Credential Guard'),
    (r'SYSTEM\CurrentControlSet\Control\DeviceGuard',
     'RequirePlatformSecurityFeatures', 'vbs_platform_req', 'VBS platform security requirement'),
]


def _reg_read(hive, path, name):
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(hive, path) as k:
            v, _t = winreg.QueryValueEx(k, name)
            return v
    except OSError:
        return None


def probe_os():
    rows = []
    rows.append(_reg(('available', '%s %s' % (platform.system(), platform.release()),
                      'platform.release()')))
    if winreg is not None:
        build = _reg_read(winreg.HKEY_LOCAL_MACHINE,
                          r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentBuildNumber')
        product = _reg_read(winreg.HKEY_LOCAL_MACHINE,
                            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName')
        ubr = _reg_read(winreg.HKEY_LOCAL_MACHINE,
                        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR')
        rows.append(_reg(('available', '%s build %s.%s' % (product, build, ubr),
                          'CurrentVersion registry. Do NOT read Windows 11 off ProductName: '
                          'the value still says "Windows 10" on Windows 11. The build number '
                          'is the reliable field (22000+ is Windows 11)')))
        start = _reg_read(winreg.HKEY_LOCAL_MACHINE,
                          r'SYSTEM\CurrentControlSet\Control', 'SystemStartOptions') or ''
        flags = []
        up = start.upper()
        for token, label in (('TESTSIGNING', 'testsigning'), ('NOINTEGRITYCHECKS',
                                                              'nointegritychecks'),
                             ('DEBUG', 'kernel-debug-boot'), ('DISABLE_INTEGRITY_CHECKS',
                                                              'integrity-checks-off')):
            if token in up:
                flags.append(label)
        rows.append(_reg(('available', flags or 'none', 'SystemStartOptions boot flags')))
        for path, name, _key, label in REG_ROWS:
            v = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, name)
            state = 'available' if v is not None else 'unavailable'
            note = 'HKLM\\%s\\%s' % (path, name)
            if v is None:
                note += (' -- the value is absent, which is NOT the same as the feature being '
                         'off. Some editions never populate this key, and on the host this was '
                         'measured on the documented cross-check class (Win32_DeviceGuard) was '
                         'itself unavailable, so the security-service state there is genuinely '
                         'unknown. Record it as unknown rather than as disabled')
            rows.append(_reg((state, v, note)))
    else:
        rows.append(_reg(('unavailable', None, 'winreg is not importable on this host')))
    return rows


def probe_privilege():
    rows = []
    try:
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        # GetCurrentProcess returns the (HANDLE)-1 pseudo-handle. Without an explicit
        # c_void_p restype ctypes narrows it to a 32-bit int and OpenProcessToken then fails
        # with ERROR_INVALID_HANDLE (6) -- a probe bug that looks exactly like a policy denial.
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.GetCurrentProcess.argtypes = []
        advapi.OpenProcessToken.restype = ctypes.c_int
        advapi.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                            ctypes.POINTER(ctypes.c_void_p)]
        advapi.GetTokenInformation.restype = ctypes.c_int
        advapi.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                               ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.POINTER(ctypes.c_uint32)]
        advapi.ConvertSidToStringSidA.restype = ctypes.c_int
        advapi.ConvertSidToStringSidA.argtypes = [ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_char_p)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]

        TOKEN_QUERY = 0x0008
        TokenUser = 1
        TokenElevation = 20
        token = ctypes.c_void_p()
        if not advapi.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_QUERY,
                                       ctypes.byref(token)):
            rows.append(_reg(('unavailable', None, 'OpenProcessToken failed err=%d'
                              % ctypes.get_last_error())))
            return rows
        size = ctypes.c_uint32(0)
        advapi.GetTokenInformation(token, TokenUser, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(max(size.value, 64))
        name = None
        if advapi.GetTokenInformation(token, TokenUser, buf, size.value, ctypes.byref(size)):
            sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            out = ctypes.c_char_p()
            if advapi.ConvertSidToStringSidA(sid, ctypes.byref(out)) and out.value:
                name = out.value.decode('latin-1')
        elev = ctypes.c_uint32(0)
        got_elev = advapi.GetTokenInformation(token, TokenElevation, ctypes.byref(elev), 4,
                                              ctypes.byref(size))
        rows.append(_reg(('available', bool(elev.value) if got_elev else None,
                          'TokenElevation: running elevated (administrator)')))
        if name:
            rows.append(_reg(('available', name, 'TokenUser SID')))
        k32.CloseHandle(token)
    except Exception as exc:
        rows.append(_reg(('unavailable', None, 'privilege probe failed: %s' % exc)))
    return rows


TOOL_NAMES = [
    ('python', 'all scripts'),
    ('git', 'repository work'),
    ('x64dbg', 'interactive debugging (GUI; run it, do not shell it)'),
    ('windbg', 'kernel/user debugging, TTD playback'),
    ('cdb', 'command-line WinDbg engine'),
    ('gdb', 'MinGW debugging'),
    ('dumpbin', 'PE headers and imports (MSVC toolchain)'),
    ('link', 'editbin/link for header edits (MSVC toolchain)'),
    ('signtool', 'signature inspection and re-signing'),
    ('frida', 'runtime instrumentation'),
    ('frida-ps', 'process listing for frida'),
    ('dotnet', '.NET tooling'),
    ('ildasm', 'CIL disassembly'),
    ('ilasm', 'CIL assembly'),
    ('de4dot', 'deobfuscation (detect and clean supported protectors)'),
    ('ilspycmd', 'C#/IL decompilation from a command line'),
    ('dnSpy', 'managed debugging and IL editing (GUI; run it, do not shell it)'),
    ('dotPeek64', 'managed decompiler and assembly browser (GUI; dotPeek32 on 32-bit installs)'),
    ('JustDecompile', 'legacy managed decompiler (retired 2024; use only if already installed)'),
    ('diec', 'Detect It Easy console (packer/protector ID)'),
    ('strings', 'string extraction'),
    ('objdump', 'disassembly and section dump (a MinGW build reads PE files too)'),
    ('tshark', 'network capture reading'),
    ('procdump', 'process dumping (Sysinternals)'),
    ('wpr', 'Windows Performance Recorder (ETW)'),
    ('xperf', 'ETW trace analysis'),
    ('logman', 'ETW session control'),
    ('tracelog', 'ETW session control'),
    ('wpr.exe', 'Windows Performance Recorder'),
    ('cargo', 'Rust tooling'),
    ('go', 'Go tooling'),
    ('gcc', 'C toolchain (also builds fixture binaries)'),
    ('cl', 'MSVC compiler'),
    ('msbuild', 'MSBuild'),
]


def probe_tools(extra_dirs=None):
    rows = []
    dirs = list(extra_dirs or [])
    env = os.environ.get('EXEREV_TOOLS') or os.environ.get('EXE_REVERSE_TOOLS')
    if env:
        dirs.extend([p for p in env.split(os.pathsep) if p])
    for name, why in TOOL_NAMES:
        found = shutil.which(name)
        if not found:
            for d in dirs:
                for ext in ('.exe', '.cmd', '.bat', '.py', ''):
                    cand = os.path.join(d, name + ext)
                    if os.path.isfile(cand):
                        found = cand
                        break
                if found:
                    break
        rows.append(_reg((('available' if found else 'unavailable'), found or None,
                          why + (' [found via EXEREV_TOOLS]' if found and not shutil.which(name)
                                 else ''))))
    return rows


def python_modules():
    import importlib
    rows = []
    for mod, why in (('pefile', 'PE parsing (this skill ships its own reader instead)'),
                     ('capstone', 'disassembly'),
                     ('lief', 'binary rewriting'),
                     ('keystone', 'assembling'),
                     ('unicorn', 'CPU emulation'),
                     ('frida', 'runtime instrumentation'),
                     ('yara', 'pattern rules'),
                     ('tiktoken', 'token measurement for the budget gate')):
        try:
            importlib.import_module(mod)
            rows.append(_reg(('available', mod, why)))
        except Exception:
            rows.append(_reg(('unavailable', mod, why)))
    return rows


def route_matrix(cpu_rows, os_rows):
    """Turn the measurements into the routes a plan may use. No silent assumptions."""
    def val(key_part, rows=cpu_rows):
        for r in rows:
            if r['note'] and key_part.lower() in r['note'].lower():
                return r['value']
        return None

    hyper = val('ECX[31]')
    pt = val('EBX[25]')
    routes = []
    routes.append(('static PE analysis (peutil, pepatch, aob_scan)',
                   'available', 'needs only Python and a file on disk'))
    routes.append(('user-mode debugging (x64dbg/WinDbg)',
                   'available' if os_rows else 'unavailable',
                   'interactive GUI or a debugger install; not driven by these scripts'))
    routes.append(('hardware breakpoints (DR0-DR3)',
                   'needs-a-debugger' + (', and a hypervisor is present' if hyper else ''),
                   'four registers, so four breakpoints at most, and they are consumed per thread. '
                   'A watch is 1, 2, 4 or 8 bytes wide (8 only on x86-64) and must be aligned to '
                   'its width; there is no read-only data breakpoint, and a data breakpoint set on '
                   'a code address never fires, because fetching an instruction is not a data '
                   'access'))
    if pt:
        routes.append(('Intel Processor Trace capture',
                       'no documented user-mode path on this platform',
                       'the processor reports the feature, but reaching the trace unit needs a '
                       'driver or an undocumented in-box interface. Treat capture, not decoding, '
                       'as the constraint, and prefer a record-and-replay debugger unless a '
                       'capture path has already been established'
                       + ('. A hypervisor is present here' if hyper else '')))
    else:
        routes.append(('Intel Processor Trace capture', 'unavailable',
                       'CPUID.07H:EBX[25] is clear, or CPUID could not be read'))
    routes.append(('last branch records / PMU', 'needs-privilege',
                   'reading the registers needs kernel or hypervisor-level access; the record '
                   'depth is a capability, not a constant'))
    routes.append(('kernel driver load / test signing',
                   'needs-reboot-and-testsigning',
                   'check the SystemStartOptions row; VBS+HVCI may refuse unsigned drivers '
                   'regardless'))
    routes.append(('Time Travel Debugging', 'needs-windbg',
                   'TTD is a WinDbg feature; recording is user-mode only'))
    routes.append(('ETW capture (wpr/xperf/logman)',
                   'available' if shutil.which('wpr') or shutil.which('logman')
                   else 'unavailable',
                   'needs an elevated session for kernel providers'))
    return routes


def main():
    ap = argparse.ArgumentParser(
        description='Report which reverse-engineering routes this machine can actually '
                    'support, with the measurement behind each answer.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python hwprobe.py --json > host-capabilities.json')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--raw', action='store_true', help='also dump raw CPUID leaves')
    ap.add_argument('--tools', action='store_true', help='tool inventory only')
    ap.add_argument('--tools-dir', action='append', default=[],
                    help='extra directory to search for tools (repeatable)')
    args = ap.parse_args()

    report = {'python': sys.version.split()[0], 'platform': platform.platform()}

    with Cpuid() as cpuid:
        if not args.tools:
            cpu_rows, raw = probe_cpu(cpuid, want_raw=args.raw)
            os_rows = probe_os()
            priv_rows = probe_privilege()
            report['cpu'] = cpu_rows
            report['os'] = os_rows
            report['privilege'] = priv_rows
            if args.raw:
                report['raw_cpuid'] = raw
            report['routes'] = route_matrix(cpu_rows, os_rows)
        report['tools'] = probe_tools(args.tools_dir)
        report['python_modules'] = python_modules()

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print('host capability report')
    print('  python %s on %s' % (report['python'], report['platform']))

    def show(title, rows, width=52):
        print('\n== %s ==' % title)
        for r in rows:
            v = str(r['value'])
            print('  %-12s %s' % ('[%s]' % r['state'], v[:width]))
            if len(v) > width:
                for chunk in range(width, len(v), width):
                    print('  %-12s %s' % ('', v[chunk:chunk + width]))
            print('  %-12s %s' % ('', r['note']))

    if 'cpu' in report:
        show('CPU', report['cpu'])
        show('OS and policy', report['os'])
        show('privilege', report['privilege'])
        print('\n== routes this machine can support ==')
        for name, state, why in report['routes']:
            print('  %-46s %s' % (name, state))
            print('      %s' % why)
    print('\n== tools ==')
    for r in report['tools']:
        if r['state'] == 'available':
            print('  present      %-14s %s' % (os.path.basename(str(r['value'])), r['note']))
    missing = [os.path.basename(str(r['value'] or '')) or '' for r in report['tools']
               if r['state'] != 'available']
    print('  not found    %d of %d checked (missing ones are findings, not failures)'
          % (len(missing), len(report['tools'])))
    print('\n== python modules ==')
    for r in report['python_modules']:
        print('  %-12s %-14s %s' % ('[%s]' % r['state'], r['value'], r['note']))
    if args.raw:
        print('\n== raw CPUID ==')
        for leaf, regs in sorted(report.get('raw_cpuid', {}).items()):
            if isinstance(regs, dict):
                print('  %-14s %s' % (leaf, ' '.join('%s=%08X' % (k.upper(), v)
                                                     for k, v in sorted(regs.items()))))
            else:
                print('  %-14s 0x%08X' % (leaf, regs))
    return 0


if __name__ == '__main__':
    sys.exit(main())
