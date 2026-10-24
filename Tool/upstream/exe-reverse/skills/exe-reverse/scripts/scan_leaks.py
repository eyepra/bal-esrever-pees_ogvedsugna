#!/usr/bin/env python3
"""Scan a repository for target identity before publishing it.

The failure this prevents is specific and quiet: analysis notes are written while the target
is open, so the product name, a version string, a licence key, a machine identifier and the
analyst's own user path all arrive naturally in the text. Publishing that is not a style
problem -- it is publishing someone else's identity together with the fact that you worked on
it. It is also the one mistake that cannot be fixed by editing afterwards, because git keeps
what was committed.

Two lists, and both matter:

  * what must be **removed** -- a product or vendor name in a target context, a version
    string bound to a target, a serial or licence blob, a machine identifier, a real
    endpoint, an inline credential, a developer's absolute path.
  * what must **stay** -- tool names, library and API names, file-format names, CWE
    identifiers, public packer/protector names, public challenge and crackme names, and
    placeholder tokens. Redacting these destroys the reusable part of the material while
    removing none of the identity, and a scanner that flags them gets switched off.

That second list is why this reports `weak` findings by default and only fails on `strong`
ones: a false positive that blocks a commit teaches people to bypass the gate.

Usage:
    python scan_leaks.py                       # scan the repository this file lives in
    python scan_leaks.py --root .              # explicit root
    python scan_leaks.py --files-from list.txt # scan an explicit tracked-file list
    python scan_leaks.py --only token,path     # one or more categories
    python scan_leaks.py --format json         # machine-readable
    python scan_leaks.py --show-exempt         # print why each hit was suppressed
    python scan_leaks.py --list-rules
    python scan_leaks.py --fail-on any         # strict: weak findings fail too
    python scan_leaks.py --max 10              # cap printed findings

Exit codes: 0 = clean at the requested strength, 1 = findings, 2 = error, 3 = the scan
surface was empty (stated explicitly rather than reported as clean).
"""
import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Rules. Each entry: (category, strength, name, compiled pattern, why).
# `strength` is `strong` (a real finding) or `weak` (context needed).
# ---------------------------------------------------------------------------
PLACEHOLDER_HINT = re.compile(
    r'\b(APP|TARGET|SAMPLE|HOST|DOMAIN|REDACTED|EXAMPLE|PLACEHOLDER|ACME|FOO|BAR|BAZ|'
    r'DUMMY|SAMPLEAPP|YOURAPP|XXX+|<[a-z_]+>)\b', re.I)

RULES = [
    # --- credentials and keys: strong, no context needed -------------------
    ('token', 'strong', 'private-key-block',
     re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'),
     'a private key was pasted into the tree'),
    ('token', 'strong', 'github-token',
     re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
     'a GitHub token is a live credential'),
    ('token', 'strong', 'aws-access-key',
     re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
     'an AWS access key id'),
    ('token', 'strong', 'slack-token',
     re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}\b'),
     'a Slack token'),
    ('token', 'strong', 'generic-secret-assignment',
     re.compile(r'(?i)\b(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*'
                r'["\']([A-Za-z0-9+/=_\-]{20,})["\']'),
     'a long literal assigned to a secret-shaped name'),
    ('token', 'strong', 'licence-blob-literal',
     re.compile(r'(?i)\b(licen[cs]e|serial|activation|product)[_-]?(key|code|blob|token)\s*'
                r'[:=]\s*["\']([A-Za-z0-9+/=_\-]{12,})["\']'),
     'a literal licence value, as opposed to a described mechanism'),

    # --- machine and user identity: strong ---------------------------------
    ('path', 'strong', 'windows-user-profile',
     re.compile(r'(?i)\b[A-Z]:\\Users\\(?!<user>|Public\b|Default\b|YOURUSER\b)'
                r'[A-Za-z0-9._\-]{2,}'),
     'an absolute path containing a real profile name'),
    ('path', 'strong', 'posix-home',
     re.compile(r'(?<![\w/])/(?:home|Users)/(?!<user>|user\b|youruser\b)'
                r'[A-Za-z0-9._\-]{3,}'),
     'an absolute path containing a real home directory'),
    ('device', 'strong', 'machine-guid',
     re.compile(r'(?i)\bMachineGuid\b\s*[:=]\s*[0-9a-f]{8}-[0-9a-f]{4}-'
                r'[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
     'a machine GUID identifies one machine'),
    ('device', 'strong', 'windows-sid-literal',
     re.compile(r'\bS-1-5-21-\d{9,10}-\d{9,10}-\d{9,10}-\d{3,6}\b'),
     'a real Windows SID identifies a machine or account'),
    ('device', 'strong', 'volume-serial-literal',
     re.compile(r'(?i)\b(?:volume|disk)\s*serial\s*(?:number)?\s*[:=]\s*'
                r'[0-9A-F]{4}-[0-9A-F]{4}\b'),
     'a captured volume serial is a machine-binding artefact'),

    # --- endpoints: strong for a literal, weak for a bare host -------------
    ('endpoint', 'strong', 'literal-endpoint-with-creds',
     re.compile(r'\b[a-z][a-z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@[^\s/]+', re.I),
     'a URL carrying inline credentials'),
    ('endpoint', 'strong', 'public-ipv4-literal',
     # Precision matters more than recall for the strong rules: a false positive here blocks a
     # commit, and a gate that blocks commits wrongly is a gate people bypass.
     #
     # The negative lookahead drops a dotted quad whose every octet is 31 or below. That shape is
     # a version number far more often than it is an address -- `4.2.1.0` reached this rule from a
     # document field named ProductVersion -- while keeping the addresses that actually appear in
     # notes. An earlier attempt used `\d{1,2}` for the same purpose and was wrong in the other
     # direction: it also dropped `45.77.10.9`, which is exactly the shape this rule is for. The
     # distinction is the octet value, not its digit count.
     re.compile(r'(?<![\d.])(?!10\.|127\.|192\.168\.|0\.|255\.|169\.254\.)'
                r'(?!(?:\d|[12]\d|3[01])\.(?:\d|[12]\d|3[01])\.'
                r'(?:\d|[12]\d|3[01])\.(?:\d|[12]\d|3[01])(?![\d.]))'
                r'(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'),
     'a routable address in an analysis note is usually a captured target'),
    ('endpoint', 'weak', 'literal-host-with-path',
     re.compile(r'\bhttps?://[a-z0-9.\-]+\.[a-z]{2,}(?:/[^\s)"\']*)?', re.I),
     'a concrete URL; fine for a public documentation or tool reference, not for a target'),

    # --- target identity: strong only in a target context -------------------
    ('package', 'strong', 'product-name-with-version',
     re.compile(r'\b[A-Z][A-Za-z0-9]{2,}(?:\s[A-Z][A-Za-z0-9]{2,}){0,3}\s+v?\d+\.\d+'
                r'(?:\.\d+){0,2}\b'),
     'a capitalised product name bound to a version number'),
    ('package', 'weak', 'exe-name-with-version',
     re.compile(r'\b[A-Za-z0-9_\-]{3,}\.(?:exe|dll|sys)\s+v?\d+\.\d+', re.I),
     'a binary name with a version; a tool name here is fine, a target is not'),
    ('identity', 'weak', 'email-address',
     re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
     'a personal address in an analysis note'),
    ('identity', 'weak', 'vendor-copyright-line',
     # The repository's own licence line is not a target's copyright notice. Exempted by the
     # phrase below rather than by filename, so this stays a content rule.
     re.compile(r'(?i)\bCopyright\s*(?:\(c\)|©)?\s*(?:19|20)\d{2}\s+'
                r'(?![A-Za-z0-9 _.,&\-]*contributors\b)'
                r'[A-Z][A-Za-z0-9 ,.&\-]{3,40}'),
     'a vendor copyright line lifted out of a resource or a binary'),
]

# ---------------------------------------------------------------------------
# Exemptions: things that look like findings and must stay. Each entry carries
# its reason, and --show-exempt prints them, because an exclusion a reader
# cannot audit is a hole rather than a rule.
# ---------------------------------------------------------------------------
EXEMPT_TERMS = [
    # tools and libraries: naming them is how the material stays reusable
    (re.compile(r'(?i)\b(?:IDA|Ghidra|WinDbg|cdb|x64dbg|x32dbg|radare2|rizin|Cutter|'
                r'Binary Ninja|Hopper|objdump|readelf|dumpbin|link\.exe|signtool|'
                r'Detours|MinHook|PolyHook|funchook|Frida|Scylla|PE-bear|CFF Explorer|'
                r'Detect It Easy|diec|Procmon|Process Monitor|Process Explorer|'
                r'API Monitor|WinDbg Preview|VirusTotal|YARA|Unicorn|Capstone|Keystone|'
                r'pefile|LIEF|angr|Triton|Z3|libipt|HyperDbg|Cheat Engine|ReClass|'
                r'HxD|7-Zip|Wireshark|tshark|dumpbin)\b'),
     'tool or library name'),
    # protectors and packers: public products, and the whole point is to classify them
    (re.compile(r'(?i)\b(?:UPX|VMProtect|Themida|WinLicense|Enigma|ASProtect|ASPack|'
                r'MPRESS|Obsidium|Armadillo|ConfuserEx|SmartAssembly|\.NET Reactor|'
                r'Eazfuscator|de4dot|ILSpy|dnSpy|dotPeek|ildasm|ilasm)\b'),
     'public protector/packer/managed tooling name'),
    # Installer builders and packagers. Naming one of these is the *result* of the analysis rather
    # than the identity of the target: "the payload is a 6.1.0 archive from this builder" says how
    # the artifact was made, and that is exactly what the reader needs in order to extract it.
    # Only a name identifying the software under analysis is a leak. This class earned its own
    # entry by producing a false positive: a builder's version number was reported as a product
    # identity, which is the second time a legitimate evidence statement was read as a leak.
    (re.compile(r'(?i)\b(?:Inno Setup|NSIS|InstallShield|WiX|WixToolset|Advanced Installer|'
                r'MSI Factory|Squirrel|electron-builder|PyInstaller|py2exe|Nuitka|'
                r'MSIX Packaging|Makeself|InstallAnywhere)\b'),
     'installer builder or packager name (how the artifact was made, not whose it is)'),
    # Format, API and standards vocabulary
    (re.compile(r'(?i)\b(?:IMAGE_[A-Z_]+|CPUID|MSR|IOCTL|IRP|PE32|PE32\+|Authenticode|'
                r'RVA|RVA|PDB|RSDS|CodeView|Rich Header|TLS callback|IAT|EAT|CFG|'
                r'CWE-\d+|MITRE|ECMA-335|CIL|CLR|ETW|TTD|VBS|HVCI|EPT|VT-x|'
                r'WOW64|AppContainer|PPL|DR\d|PEB|TEB|SEH|VEH|APC|ToPA|PSB|TNT)\b'),
     'format, standard or platform term'),
    # Package indexes and specification registries. A name plus a version here is a **citation**,
    # not an identity: it says which artefact was installed or which specification was followed.
    #
    # This entry exists because the rule above it learned something three times. "A capitalised name
    # bound to a version number" produced a false positive on a specification version, on an
    # installer builder's version, and on a package-index version -- each time on a sentence a
    # reader needs in order to reproduce the work. The lesson is worth stating plainly: that pattern
    # is a **weak** signal, and whether a name is the target or the tooling is a judgement the
    # person reading the report makes. The rule keeps firing because it also catches the real case
    # (a product name in a path, a URL or a certificate subject); what it must not do is force a
    # citation to be rewritten to satisfy it.
    (re.compile(r'(?i)\b(?:PyPI|CRAN|NuGet|crates\.io|Maven Central|SMT-LIB|'
                r'RFC\s?\d+|ISO\s?\d+|IEEE\s?\d+|NIST|CVE-\d{4}-\d+|TPM\s?\d)\b'),
     'package index or specification registry name'),
    # Microsoft-owned identifiers that appear in every legitimate discussion
    (re.compile(r'(?i)\b(?:Windows|Microsoft|Redmond|Sysinternals|MSVC|MSBuild|Win32|'
                r'NTFS|winnt\.h|ntddk|WDK|Windows SDK|Visual Studio|\.NET|PowerShell)\b'),
     'platform or vendor-of-the-platform term'),
    # Language, runtime and format names followed by a version. Without these the
    # product-name-with-version rule fires on every mention of a toolchain version, which is
    # most of this repository's prose, and a gate whose output is mostly noise is one people
    # stop reading.
    (re.compile(r'(?i)\b(?:Python|CPython|PyPy|Node|Node\.js|npm|Java|JDK|JRE|Go|Golang|'
                r'Rust|Cargo|Delphi|Pascal|\.NET|NET|Visual C\+\+|C\+\+|PE32\+?|COFF|'
                r'Windows|Ghidra|IDA|WinDbg|x64dbg|radare2|rizin|Cutter|Unicorn|Capstone|'
                r'Keystone|Frida|YARA|tiktoken|pytest|flake8|mypy|PyYAML|Ubuntu|Debian|'
                r'macOS|Linux|Build|Version|v?CPUID|MSR|QEMU|VMware|VirtualBox|Hyper-V)\s*'
                r'v?\d+(?:\.\d+)*\b'),
     'a toolchain or platform version, not a target version'),
    # placeholders and obvious examples
    (PLACEHOLDER_HINT, 'placeholder token'),
    (re.compile(r'(?i)\b(?:example\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|'
                r'192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)\b'),
     'reserved documentation address'),
    (re.compile(r'(?i)\b(?:img\.shields\.io|shields\.io|badge\.svg|badges\.shields\.io)\b'),
     'a badge service, not a target endpoint'),
    (re.compile(r'\b(?:S-1-5-18|S-1-5-19|S-1-5-20|S-1-5-32-\d+)\b'),
     'well-known SID, not a machine identity'),
    (re.compile(r'(?i)\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b'),
     'a bare GUID is not machine identity without MachineGuid context'),
    # A standard name with a version, and a version *field* with a value. Both reached the
    # product-name rule in testing: `TPM 2.0` is a specification, `ProductVersion 4.2.1.0` is a
    # field name. Neither identifies a product, and a rule that reports them is a rule people
    # learn to skip.
    #
    # The version requirement belongs to *every* alternative. An earlier version of this entry
    # put the suffix inside the group but after only one of the alternatives, so the bare
    # protocol names matched on their own -- and `http` matched inside every `https://` URL.
    # Two entries with one requirement each is harder to get wrong than one entry with a
    # requirement that applies to some of its branches.
    (re.compile(r'(?i)\b(?:TPM|UEFI|ACPI|SMBIOS|PCIe|NVMe|SATA|DirectX|OpenGL|Vulkan)'
                r'\s*v?\d+(?:\.\d+)*\b'),
     'a hardware or platform specification version, not a product identity'),
    (re.compile(r'(?i)\b[A-Za-z]*(?:Version|Revision|Release|Build)\b\s*[:=]?\s*'
                r'v?\d+(?:\.\d+)*'),
     'a version field with its value, not a product identity'),
]

# Paths never scanned: build output, dependencies, caches, and this file's own
# rule table (which necessarily contains credential-shaped regex source).
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'build', 'dist',
             '.mypy_cache', '.pytest_cache', '.ruff_cache',
             # Local working directories. Without these, a scan of the tree rather than of the
             # tracked set walks whatever research material is on disk: measured here, an
             # unfiltered walk produced over four thousand findings from a scratch directory
             # that .gitignore already excludes from the repository, which made the tool
             # unusable at exactly the moment it was needed.
             '_recon', 'tools', 'samples', 'captures', 'exports', 'out', 'work',
             'audit_out', '_tmp', '_work', '.cache'}
SKIP_FILE_SUFFIX = ('.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.7z',
                    '.gz', '.exe', '.dll', '.sys', '.bin', '.so', '.pyc', '.woff',
                    '.woff2', '.ttf', '.jar', '.class', '.idb', '.i64', '.dmp')
MAX_BYTES = 4 * 1024 * 1024
SELF_NAME = os.path.basename(__file__)


def exempt_reason(match_text):
    for pattern, reason in EXEMPT_TERMS:
        if pattern.search(match_text):
            return reason
    return None


def iter_files(root, files_from=None):
    if files_from:
        with open(files_from, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line:
                    p = os.path.join(root, line)
                    if os.path.isfile(p):
                        yield p
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # A leading underscore marks a local work area, the same convention `.gitignore` uses. The
        # two lists have to agree: when they did not, a research directory that the repository
        # ignores still had its contents reported as findings, because it happened not to be in
        # this hardcoded set. A scanner that reports on material which cannot be published teaches
        # its reader to skim the result, which is worse than the noise itself.
        dirnames[:] = sorted(
            d for d in dirnames
            if not d.startswith('_')
            and ((d not in SKIP_DIRS and not d.startswith('.')) or d == '.github'))
        for name in sorted(filenames):
            if name.lower().endswith(SKIP_FILE_SUFFIX):
                continue
            yield os.path.join(dirpath, name)


def scan_text(text):
    for lineno, line in enumerate(text.splitlines(), 1):
        for category, strength, name, pattern, why in RULES:
            for m in pattern.finditer(line):
                yield {
                    'category': category, 'strength': strength, 'rule': name,
                    'why': why, 'line': lineno, 'col': m.start() + 1,
                    'match': m.group(0)[:200],
                    'context': line.strip()[:200],
                }


def main():
    ap = argparse.ArgumentParser(
        description='Scan a repository for target identity before publishing it.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Strong findings fail the scan; weak findings are reported and do not.')
    ap.add_argument('--root', default=None, help='repository root (default: two levels up)')
    ap.add_argument('--files-from', help='file listing paths relative to --root')
    ap.add_argument('--only', help='comma-separated categories to report')
    ap.add_argument('--skip', help='comma-separated categories to ignore')
    ap.add_argument('--format', choices=['text', 'json'], default='text')
    ap.add_argument('--show-exempt', action='store_true',
                    help='print each suppressed hit and the exemption that suppressed it')
    ap.add_argument('--list-rules', action='store_true')
    ap.add_argument('--fail-on', choices=['strong', 'any'], default='strong')
    ap.add_argument('--max', type=int, default=200, help='cap printed findings')
    ap.add_argument('--quiet', action='store_true', help='print only the RESULT line')
    args = ap.parse_args()

    if args.list_rules:
        print('rules (%d):' % len(RULES))
        for category, strength, name, _p, why in RULES:
            print('  %-10s %-7s %-28s %s' % (category, strength, name, why))
        print('\nexemptions (%d):' % len(EXEMPT_TERMS))
        for _p, reason in EXEMPT_TERMS:
            print('  %s' % reason)
        return 0

    root = args.root or os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if not os.path.isdir(root):
        sys.stderr.write('error: %s is not a directory\n' % root)
        print('RESULT=error')
        return 2

    try:
        only = set(x.strip() for x in args.only.split(',')) if args.only else None
        skip = set(x.strip() for x in args.skip.split(',')) if args.skip else set()
    except Exception as exc:
        sys.stderr.write('error: %s\n' % exc)
        print('RESULT=error')
        return 2

    findings = []
    exempted = []
    scanned = 0
    for path in iter_files(root, args.files_from):
        rel = os.path.relpath(path, root).replace('\\', '/')
        if os.path.basename(path) == SELF_NAME and rel.endswith('scripts/' + SELF_NAME):
            continue                       # the rule table itself is credential-shaped
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            continue
        scanned += 1
        for hit in scan_text(text):
            if only and hit['category'] not in only:
                continue
            if hit['category'] in skip:
                continue
            reason = exempt_reason(hit['match']) or exempt_reason(hit['context'])
            hit['file'] = rel
            if reason:
                hit['exempt'] = reason
                exempted.append(hit)
            else:
                findings.append(hit)

    strong = [f for f in findings if f['strength'] == 'strong']
    weak = [f for f in findings if f['strength'] != 'strong']
    verdict = 'clean' if not strong and (args.fail_on == 'strong' or not weak) else 'findings'

    if args.format == 'json':
        print(json.dumps({
            'root': root, 'files_scanned': scanned,
            'strong': strong, 'weak': weak,
            'exempted': exempted if args.show_exempt else len(exempted),
            'verdict': verdict,
        }, indent=2))
        print('RESULT=%s' % verdict)
        return 1 if verdict == 'findings' else 0

    if not args.quiet:
        print('scanning %s (%d files)' % (root, scanned))
        shown = 0
        for group, label in ((strong, 'STRONG'), (weak, 'weak')):
            for f in group:
                if shown >= args.max:
                    print('  ... %d more not shown (--max)'
                          % (len(strong) + len(weak) - shown))
                    shown = args.max + 1
                    break
                print('%s:%d:%d  [%s/%s]  %s'
                      % (f['file'], f['line'], f['col'], f['category'], f['strength'],
                         f['rule']))
                print('      match:   %s' % f['match'])
                print('      context: %s' % f['context'])
                print('      why:     %s' % f['why'])
                shown += 1
        if args.show_exempt:
            print('\nsuppressed by an exemption (%d):' % len(exempted))
            for f in exempted:
                print('  %s:%d  [%s/%s]  %s  <- %s'
                      % (f['file'], f['line'], f['category'], f['strength'], f['match'],
                         f['exempt']))
        elif exempted:
            print('\n%d hit(s) suppressed by the exemption list (--show-exempt prints why)'
                  % len(exempted))
        if not strong and not weak:
            print('  no findings')
        print('\n%d strong, %d weak, %d suppressed'
              % (len(strong), len(weak), len(exempted)))
    print('RESULT=%s' % verdict)
    return 1 if verdict == 'findings' else 0


if __name__ == '__main__':
    sys.exit(main())
