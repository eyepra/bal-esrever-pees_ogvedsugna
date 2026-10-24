#!/usr/bin/env python3
"""One-pass, bounded triage of an unknown PE image: the first script to run on a sample.

Why this exists as a script rather than "open it in a disassembler": the expensive mistake at
the start of a reverse-engineering task is not a missing detail, it is choosing the wrong
instrument. A .NET assembly, a kernel driver, a packed binary and an ordinary C++ build all
open in the same tools and fail in different ways. "What is this, and which route does it send
me to" is cheap only while it is answered from measured header facts rather than from the first
impression a disassembler gives.

**Entropy and section shape are reasons to look, never findings.** This report has no `packed`
field, no `protected` verdict and no confidence score, because none of those can be established
from headers alone. Every heuristic here prints the number it measured, the threshold it was
compared against, and what that measurement *suggests* a reader checks next. A high-entropy
section is equally consistent with packed code, compressed resources, a large embedded key
table, and a build that simply vectorises floating point. An executable-and-writable code
section is equally consistent with a protector and with a hand-written assembler routine. The
signals are ordered by how much they change the next command, not by severity, because there is
no severity to report.

What it reports, in the order a person asks:

  1. identity -- architecture, bitness, kind (exe/dll/driver), subsystem, entry point, image
     base, mapped size, sha256, and the PE checksum declared against the one computed from the
     bytes with Microsoft's own algorithm.
  2. build evidence -- Rich Header presence and its build ids, linker version from the optional
     header, the file-header timestamp with the reproducible-build caveat, debug directory and
     PDB path if present, and whether the image is managed (CLR directory).
  3. protective signals -- the per-section entropy table, executable-and-writable sections, a
     virtual size far above its raw size, an entry point outside the first executable section,
     an import table that resolves to very few functions, TLS callbacks, a certificate table,
     and stripped relocations.
  4. surface -- import DLL count and the largest ones, export count, resource type inventory, and
     a bounded sample of URLs, file paths and registry keys.
  5. what to do next -- a short list derived from what was found, naming the next script or
     reference rather than restating the finding.

Bounded by design: the text and `--json` reports cap every list and print the count next to the
cap, so a 40 MB driver with 900 sections cannot turn triage into an unreadable wall. Pass
`--full-out PATH` to write the complete record (every section, DLL, string sample and resource)
to a file and have its path reported, which is the repository's rule for any producer that can
emit more than a reader will read.

Cost: the checksum is the only O(file size) step and it is a pure-Python 16-bit loop. Measured on
this development host over a 7,691,168-byte system image (`shell32.dll`, with `--no-strings`), the
whole run took 0.95 s wall clock including interpreter start; the full run with the default string
scan over the same file took 1.17 s. So triage stays a first command on a multi-megabyte binary,
and `--no-checksum` removes the only part of it that scales with file size.

The timestamp caveat is observable rather than theoretical: on that same host `shell32.dll`
declares TimeDateStamp 0x963053E5, which renders as 2049-11-05. A date decades in the future is
what a deterministic-build pipeline writes into this field -- a content hash, not a build time.

Usage:
    python pe_triage.py sample.exe
    python pe_triage.py sample.exe --json
    python pe_triage.py sample.exe --full-out triage.json
    python pe_triage.py sample.exe --entropy-threshold 7.5 --max-strings 10 --no-strings

Exit codes: 0 = report produced, 1 = the input is not a parseable PE, 2 = usage error. Signals
are reasons to look, not failures, so finding them never changes the exit code.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peutil import (PE, ParseError, u8, bits, SUBSYSTEM, FILE_CHARACTERISTICS,   # noqa: E402
                    DLL_CHARACTERISTICS, DIR_BASERELOC, DIR_CLR, DIRECTORY_NAMES)

# Thresholds. Each one is a reporting threshold, not a correctness rule: it decides which rows
# are worth printing, and every row that passes prints both the measurement and the threshold it
# was compared against. An assumed budget is not a justification, so the defaults are stated as
# what they are -- a starting point for a conversation with the numbers, not a verdict.
DEFAULT_ENTROPY_HIGH = 7.2      # bits/byte; of 8.0 maximum, compressed data usually sits above 7.5
DEFAULT_ENTROPY_LOW = 1.5       # bits/byte; one repeated byte scores near 0
DEFAULT_VSIZE_RATIO = 2.0       # virtual size against raw size
VSIZE_MIN_GAP = 0x1000          # one page; below this the ratio is arithmetic, not structure
DEFAULT_IMPORT_THRESHOLD = 10   # named+ordinal functions across the whole import table
MIN_SECTION_BYTES = 512         # entropy over a handful of bytes says nothing
MAX_SECTIONS_SHOWN = 24
MAX_RANGES_SHOWN = 20
MATCH_CAP = 10000               # per string class; the count is reported as capped when hit

# String classes. The patterns are deliberately narrow: a triage report that lists every
# printable run is noise, and the value here is naming the framework, the endpoints and the
# configuration surface, not dumping the sample's text.
#
# The character classes exclude control bytes (0x00-0x1f) rather than merely whitespace: a
# NUL-padded string such as an RSDS PDB path sits in a field padded with zeros, and a class that
# admits NUL runs to its length limit and reports the padding as part of the path.
STRING_CLASSES = (
    ('url', re.compile(r'(?:https?|ftp)://[^\x00-\x20<>"\']{3,140}')),
    ('path', re.compile(r'[A-Za-z]:\\[^\x00-\x1f<>|"]{2,120}')),
    ('registry',
     re.compile(r'(?:HKEY_[A-Z_]{2,}|HKLM|HKCU|CurrentControlSet)[A-Za-z0-9 _.\-\\]{2,80}')),
)


def image_kind(pe):
    """exe / dll / driver / native, from the documented header bits.

    This does not use peutil.PE.is_driver, and the reason is a measurement rather than a
    preference. is_driver requires DLL_CHARACTERISTICS bit 0x1000, which peutil's own table names
    `appcontainer`; the WDM driver bit is 0x2000. Measured on this host over 80 images in
    System32\\drivers: is_driver returned True for 0 of them, and the 0x2000 bit was set in only 4,
    while subsystem == native (1) covered all 80. So neither bit alone identifies a driver here,
    and this function prefers the documented bit and falls back to the native subsystem. The
    disagreement with is_driver is reported as a note rather than hidden. peutil.py is not
    modified.
    """
    flags = bits(pe.dll_characteristics, DLL_CHARACTERISTICS)
    if 'wdm_driver' in flags:
        return 'driver'
    if pe.subsystem == 1:
        return 'native'
    if pe.is_dll:
        return 'dll'
    return 'exe'


def iso_utc(ts):
    """ISO-8601 UTC rendering of a 32-bit PE timestamp, or None when it is not a date.

    The file-header TimeDateStamp is not a build date in general: MSVC's /Brepro and other
    deterministic-build pipelines store a content hash in this field, which renders as a date
    decades in the future or before 1970. That is why every caller pairs this with the caveat
    rather than printing a date as if it were a fact about when the binary was built.
    """
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ')
    except (OverflowError, OSError, ValueError):
        return None


def collect_strings(data, limit_bytes, per_class, cap=MATCH_CAP):
    """Bounded URL/path/registry samples from the raw bytes.

    Two views are scanned because Windows carries both: single-byte text, and UTF-16LE text
    (which is what a registry path in a resource usually is). Decoding the whole buffer twice is
    what makes this fast -- a byte-at-a-time Python loop over a 12 MB image costs seconds, while
    two C-level decodes plus a regex pass cost milliseconds. The bytes from the sample are
    target-derived and untrusted; callers must label them as data, never as instructions.
    """
    window = data if not limit_bytes else data[:limit_bytes]
    views = (('ascii', window.decode('latin-1', 'replace'), 1),
             ('utf16le', window.decode('utf-16-le', 'ignore'), 2))
    out = {}
    for klass, pattern in STRING_CLASSES:
        count = 0
        seen = {}
        capped = False
        for view_name, text, width in views:
            for m in pattern.finditer(text):
                count += 1
                if count >= cap:
                    capped = True
                    break
                value = m.group(0)
                if value != value.strip():
                    value = value.strip()
                if not value:
                    count -= 1
                    continue
                if value not in seen and len(seen) < per_class:
                    seen[value] = {'value': value, 'view': view_name,
                                   'first_offset': hex(m.start() * width)}
            if capped:
                break
        out[klass] = {'count': count, 'count_capped': capped,
                      'samples': list(seen.values()),
                      'untrusted': True,
                      'origin': 'raw bytes of the sample, scanned as ascii and utf-16le'}
    return out


def build_signals(pe, data, args, imports_total, import_dlls):
    """Every heuristic as (id, measurement, suggests). No verdicts."""
    sig = []
    sections = sorted(pe.sections, key=lambda s: s.virtual_address)

    for s in sections:
        if (s.raw_size or 0) >= MIN_SECTION_BYTES and (s.entropy or 0) >= args.entropy_threshold:
            sig.append({
                'id': 'high-entropy-section',
                'where': s.name,
                'measurement': ('%s: entropy %.2f bits/byte over the first %d of %d raw bytes '
                                '(threshold %.2f of 8.0)'
                                % (s.name, s.entropy or 0.0,
                                   min(s.raw_size or 0, 65536), s.raw_size or 0,
                                   args.entropy_threshold)),
                'suggests': ('compressed or encrypted content, or a large embedded table. Read the '
                             'entry point before assuming the section is code; a resource section '
                             'and a packed code section can score the same.'),
            })
        if (s.raw_size or 0) >= MIN_SECTION_BYTES and 'mem_execute' in s.flags \
                and (s.entropy or 0) <= args.low_entropy_threshold:
            sig.append({
                'id': 'near-zero-entropy-executable-section',
                'where': s.name,
                'measurement': ('%s: entropy %.2f bits/byte over %d raw bytes, executable '
                                '(threshold <= %.2f)'
                                % (s.name, s.entropy or 0.0, s.raw_size or 0,
                                   args.low_entropy_threshold)),
                'suggests': ('a run of one repeated byte. Either the raw code is absent and the '
                             'real content arrives at run time, or the section is padding; an '
                             'empty code section and a stub-packed one look identical here.'),
            })
        if 'mem_execute' in s.flags and 'mem_write' in s.flags:
            sig.append({
                'id': 'executable-and-writable-section',
                'where': s.name,
                'measurement': ('%s: characteristics 0x%08X -> %s'
                                % (s.name, s.characteristics, ','.join(s.flags))),
                'suggests': ('self-modifying or unpacking code is representable here. A compiler '
                             'emits executable+read (0x60000020) for code; the write bit is '
                             'usually written by a protector, a JIT, or hand-written asm.'),
            })
        vsize = s.virtual_size or 0
        rawsize = s.raw_size or 0
        if rawsize and vsize > rawsize * args.vsize_ratio and (vsize - rawsize) >= VSIZE_MIN_GAP:
            sig.append({
                'id': 'virtual-size-far-above-raw-size',
                'where': s.name,
                'measurement': ('%s: virtual size %d vs raw size %d (ratio %.1f, gap %d bytes; '
                                'threshold ratio %.1f and gap >= %d)'
                                % (s.name, vsize, rawsize, vsize / float(rawsize),
                                   vsize - rawsize, args.vsize_ratio, VSIZE_MIN_GAP)),
                'suggests': ('a large zero-filled in-memory area. The tail maps to no file bytes, '
                             'so it is an unpacking target, an uninitialised buffer, or the '
                             'residue of a dumped image -- which one is decided by what writes '
                             'to it, not by the header.'),
            })

    exec_sections = [s for s in sections if 'mem_execute' in s.flags]
    entry = pe.address_of_entrypoint
    if not exec_sections:
        sig.append({
            'id': 'no-executable-section',
            'where': None,
            'measurement': 'no section carries mem_execute; entry point rva 0x%X' % entry,
            'suggests': ('the loader has nothing to map as code. Either the section table was '
                         'rewritten or the image is not meant to be loaded as it stands.'),
        })
    else:
        first = exec_sections[0]
        lo, hi = first.virtual_address, first.virtual_address + max(first.virtual_size or 0,
                                                                    first.raw_size or 0)
        if not (lo <= entry < hi):
            containing = pe.section_of_rva(entry)
            sig.append({
                'id': 'entry-point-outside-first-executable-section',
                'where': first.name,
                'measurement': ('entry rva 0x%X is outside the first executable section %s '
                                '(0x%X-0x%X); it falls in %s'
                                % (entry, first.name, lo, hi,
                                   containing.name if containing else 'no section')),
                'suggests': ('the entry point is not where a compiler would put it. Check whether '
                             'it is a stub that jumps or unpacks before the real code runs, and '
                             'put any breakpoint after that transfer.'),
            })
        if entry == 0:
            sig.append({
                'id': 'zero-entry-point',
                'where': None,
                'measurement': 'AddressOfEntryPoint is 0',
                'suggests': ('legal for a DLL that is loaded and called through its exports, '
                             'unusual for an exe; for an exe, read the section table before the '
                             'code.'),
            })

    if imports_total < args.import_threshold:
        sig.append({
            'id': 'few-imported-functions',
            'where': None,
            'measurement': ('the import table resolves %d function(s) across %d DLL(s) '
                            '(threshold < %d)' % (imports_total, len(import_dlls),
                                                  args.import_threshold)),
            'suggests': ('an import table this thin is often a loader stub: the real API names '
                         'are resolved at run time, so the listed imports describe the unpacker '
                         'rather than the program. Look for the resolution loop before trusting '
                         'this list.'),
        })

    tls = pe.tls()
    if tls and tls.get('callback_rvas'):
        callbacks = tls['callback_rvas']
        sig.append({
            'id': 'tls-callbacks-present',
            'where': None,
            'measurement': '%d TLS callback(s) at %s' % (len(callbacks), ', '.join(callbacks)),
            'suggests': ('TLS callbacks execute before AddressOfEntryPoint, so a breakpoint at '
                         'the entry point can be too late and a patch there can be preceded by a '
                         'check. Set the first breakpoint on the callback instead.'),
        })

    if pe.is_signed:
        sec = pe.security_directory() or {}
        sig.append({
            'id': 'authenticode-certificate-table-present',
            'where': None,
            'measurement': ('security directory at %s, declared size %s, type %s'
                            % (sec.get('offset'), sec.get('declared_size'),
                               sec.get('certificate_type'))),
            'suggests': ('the file carries a signature over its own bytes. Any edit outside the '
                         'blob invalidates it, and whether that matters depends on who verifies '
                         'it -- establish that before writing a patched file.'),
        })

    reloc_rva, reloc_size = pe.directories.get(DIR_BASERELOC, (0, 0))
    stripped_flag = 'relocs_stripped' in bits(pe.characteristics, FILE_CHARACTERISTICS)
    blocks = pe.base_relocations().get('blocks', 0)
    if stripped_flag or not reloc_rva or blocks == 0:
        sig.append({
            'id': 'relocations-absent',
            'where': None,
            'measurement': ('relocs_stripped flag %s; base-relocation directory rva 0x%X size %d; '
                            'blocks parsed %d; dynamic_base flag %s'
                            % ('set' if stripped_flag else 'clear', reloc_rva, reloc_size, blocks,
                               'set' if 'dynamic_base' in
                               bits(pe.dll_characteristics, DLL_CHARACTERISTICS) else 'clear')),
            'suggests': ('the image expects its preferred base. If dynamic_base is set at the same '
                         'time, the pair is contradictory: address randomisation needs the '
                         'relocation table it is not given. Read that pair as a fact to explain, '
                         'not as a feature list.'),
        })
    return sig


def next_steps(report):
    """The next action, derived from what the report found. Names a script or a reference."""
    ids = set(s['id'] for s in report['signals'])
    build = report['build']
    out = []
    if build.get('managed'):
        out.append('Managed image (CLR directory %s): do not start with a hex editor. patching '
                   'IL is a different activity from patching x86; load references/recon.md and '
                   'route to managed tooling.' % build.get('clr_directory'))
    if report['identity']['kind'] in ('driver', 'native'):
        out.append('Kernel driver (subsystem native): user-mode tooling stops at the boundary. '
                   'Plan a driver-load route and check what this host permits before it '
                   '(references/environment.md, references/coverage-and-limits.md).')
    if ids & {'high-entropy-section', 'near-zero-entropy-executable-section',
              'few-imported-functions', 'entry-point-outside-first-executable-section',
              'executable-and-writable-section', 'virtual-size-far-above-raw-size'}:
        out.append('Signals above are consistent with a packed or protected image, and they are '
                   'equally consistent with ordinary ones: read the entry point with a '
                   'disassembler and look for a jump or unpack loop before planning any patch '
                   '(references/recon.md).')
    if 'tls-callbacks-present' in ids:
        out.append('Set the first breakpoint on the TLS callback, not on the entry point '
                   '(references/pe-structure.md, references/dynamic-debugging.md).')
    if ids & {'relocations-absent', 'virtual-size-far-above-raw-size'}:
        out.append('Section and relocation facts that affect a memory patch or a dump are '
                   'covered by references/pe-structure.md and references/memory-and-dumps.md.')
    if 'authenticode-certificate-table-present' in ids:
        out.append('Before patching, decide whether the signature is verified by the target: '
                   'references/integrity-checks.md.')
    out.append('To locate and change a byte once the site is identified: python pepatch.py '
               '<file> --dry-run first (references/patching.md).')
    out.append('To compare two builds of this program before or after an edit: '
               'python pe_diff.py <a> <b> --summary.')
    out.append('To check what this host can actually support for a runtime route: '
               'python hwprobe.py, or python capabilities.py --check for the registry view.')
    return out


def build_report(pe, data, args):
    """The complete record. Text and --json print a bounded projection of this."""
    sha = hashlib.sha256(data).hexdigest()
    linker_major = u8(data, pe.optional_offset + 2)
    linker_minor = u8(data, pe.optional_offset + 3)
    rich = pe.rich_header()
    debug = pe.debug_directory()
    pdb = None
    for d in debug:
        if d.get('pdb'):
            pdb = {'path': d['pdb'], 'format': d.get('format'), 'type': d.get('type'),
                   'guid': d.get('guid'), 'age': d.get('age')}
            break
    clr_rva, clr_size = pe.directories.get(DIR_CLR, (0, 0))
    imports = pe.imports()
    delay = pe.delay_imports()
    exports = pe.exports()
    resources = pe.resources()
    import_dlls = [d['dll'] for d in imports]
    imports_total = sum(len(d['functions']) for d in imports)
    signals = build_signals(pe, data, args, imports_total, import_dlls)

    dir_present = {DIRECTORY_NAMES.get(k, str(k)): {'rva': hex(v[0]), 'size': v[1]}
                   for k, v in sorted(pe.directories.items()) if v[0]}

    res_types = {}
    for r in resources:
        name = r['path'][0] if r['path'] else '?'
        if name == 'str:':
            # peutil labels a named entry 'str:' + its name; an empty label is a name that read
            # back as the empty string, which is worth showing as such rather than as a bare 'str:'.
            name = 'str:(empty name)'
        res_types[name] = res_types.get(name, 0) + 1

    strings = {} if args.no_strings else collect_strings(data, args.scan_limit, args.max_strings)

    report = {
        'file': os.path.abspath(pe.path) if pe.path else None,
        'size': len(data),
        'sha256': sha,
        'identity': {
            'arch': pe.arch,
            'machine': hex(pe.machine),
            'bitness': 64 if pe.is_pe32plus else 32,
            'optional_header_magic': hex(pe.magic),
            'kind': image_kind(pe),
            'kind_basis': ('wdm_driver bit 0x2000 in DllCharacteristics, or subsystem native, '
                           'or the file dll bit 0x2000 in Characteristics'),
            'subsystem': SUBSYSTEM.get(pe.subsystem, str(pe.subsystem)),
            'entry_point_rva': hex(pe.address_of_entrypoint),
            'entry_point_section': (pe.section_of_rva(pe.address_of_entrypoint).name
                                    if pe.section_of_rva(pe.address_of_entrypoint) else None),
            'image_base': hex(pe.image_base),
            'size_of_image': pe.size_of_image,
            'size_of_headers': pe.size_of_headers,
            'section_alignment': hex(pe.section_alignment),
            'file_alignment': hex(pe.file_alignment),
            'file_characteristics': bits(pe.characteristics, FILE_CHARACTERISTICS),
            'dll_characteristics': bits(pe.dll_characteristics, DLL_CHARACTERISTICS),
            'checksum_declared': hex(pe.checksum),
            'checksum_computed': (None if args.no_checksum
                                  else hex(pe.computed_checksum() or 0)),
            'checksum_matches': (None if args.no_checksum else pe.checksum_ok()),
        },
        'build': {
            'timestamp_raw': pe.timestamp,
            'timestamp_iso': iso_utc(pe.timestamp),
            'timestamp_caveat': ('a deterministic build (/Brepro and equivalents) stores a content '
                                 'hash here, so the rendered date is meaningless for such an '
                                 'image. Treat this field as a build input, never as the build '
                                 'time'),
            'linker_version': '%d.%d (optional header MajorLinkerVersion.MinorLinkerVersion)'
                              % (linker_major, linker_minor),
            'rich_header_present': rich is not None,
            'rich_header': (pe.rich_summary() if rich else None),
            'rich_build_ids': (sorted(set(e['build'] for e in rich['entries'])) if rich else []),
            'debug_entries': debug,
            'pdb': pdb,
            'managed': bool(clr_rva and clr_size),
            'clr_directory': (hex(clr_rva) if clr_rva else None),
            'signed': pe.is_signed,
            'directories_present': dir_present,
        },
        'sections': [dict(s.as_dict(), raw_pointer_hex=hex(s.raw_pointer),
                          characteristics_hex=hex(s.characteristics),
                          raw_size=int(s.raw_size or 0),
                          entropy_measured_over='first 65536 raw bytes')
                     for s in sorted(pe.sections, key=lambda s: s.virtual_address)],
        'signals': signals,
        'surface': {
            'import_dll_count': len(imports),
            'import_function_count': imports_total,
            'import_dlls': [],
            'delay_import_dlls': [d['dll'] for d in delay],
            'export_count': exports['number_of_functions'] if exports else 0,
            'export_named_count': exports['number_of_names'] if exports else 0,
            'export_name': exports['dll_name'] if exports else None,
            'resources_total': len(resources),
            'resource_types': res_types,
            'strings': strings,
            'strings_untrusted': True,
            'strings_caveat': (
                'each sample is a raw byte window, so adjacent bytes can be included; a URL '
                'inside a certificate blob picks up the bytes that follow it. Verify a lead '
                'before relying on it'),
        },
        'notes': list(pe.warnings),
    }

    for d in sorted(imports, key=lambda d: (-len(d['functions']), d['dll'])):
        names = [f.get('name') or ('#%d' % f.get('ordinal', 0)) for f in d['functions']]
        report['surface']['import_dlls'].append({'dll': d['dll'], 'functions': len(names),
                                                 'names': names})
    kind = report['identity']['kind']
    if bool(pe.is_driver) != (kind in ('driver', 'native')):
        report['notes'].append(
            'this script reports kind=%s (WDM bit 0x2000 or subsystem native) while '
            'peutil.PE.is_driver reports %s: is_driver tests DLL_CHARACTERISTICS 0x1000, which '
            'peutil\'s own table names appcontainer -- measured on this host it returned True for '
            '0 of the 80 images in System32\\drivers. The header flags are printed above, so the '
            'disagreement is settled from the bytes rather than from either property.'
            % (kind, pe.is_driver))
    if args.no_checksum:
        report['notes'].append('checksum computation was skipped (--no-checksum); the declared '
                               'value is reported as declared and nothing is claimed about it')
    return report


def bounded(report, args):
    """The projection a reader sees: every list capped, every cap stated."""
    surface = dict(report['surface'])
    dlls = surface['import_dlls']
    surface['import_dlls'] = dlls[:args.max_dlls]
    surface['import_dlls_omitted'] = max(0, len(dlls) - len(surface['import_dlls']))
    sections = report['sections']
    limits = {
        'sections_shown': min(len(sections), MAX_SECTIONS_SHOWN),
        'sections_total': len(sections),
        'import_dlls_shown': len(surface['import_dlls']),
        'import_dlls_total': len(dlls),
        'strings_per_class': args.max_strings,
        'string_scan_bytes': args.scan_limit or report['size'],
        'note': ('lists are capped for reading; --full-out PATH writes the complete record'),
    }
    out = dict(report)
    out['surface'] = surface
    out['sections'] = sections[:MAX_SECTIONS_SHOWN]
    out['limits'] = limits
    return out


def print_text(rep, args):
    ident = rep['identity']
    build = rep['build']
    print('file        : %s' % rep['file'])
    print('size        : %d bytes   sha256 %s' % (rep['size'], rep['sha256']))
    print('identity    : %s / %d-bit / %s   optional header %s   subsystem %s'
          % (ident['arch'], ident['bitness'], ident['kind'], ident['optional_header_magic'],
             ident['subsystem']))
    print('entry point : %s (section %s)   image base %s   mapped size %d bytes'
          % (ident['entry_point_rva'], ident['entry_point_section'], ident['image_base'],
             ident['size_of_image']))
    print('align       : section %s / file %s   headers %d bytes'
          % (ident['section_alignment'], ident['file_alignment'], ident['size_of_headers']))
    if ident['checksum_computed'] is None:
        print('checksum    : declared %s (not computed: --no-checksum)'
              % ident['checksum_declared'])
    else:
        print('checksum    : declared %s computed %s -> %s'
              % (ident['checksum_declared'], ident['checksum_computed'],
                 'match' if ident['checksum_matches'] else 'MISMATCH'))
    if ident['file_characteristics']:
        print('file chars  : %s' % ', '.join(ident['file_characteristics']))
    if ident['dll_characteristics']:
        print('dll chars   : %s' % ', '.join(ident['dll_characteristics']))
    print('directories : %s' % (', '.join(sorted(build['directories_present'])) or '(none)'))

    print('\nbuild evidence')
    print('  timestamp      %s (raw 0x%X)' % (build['timestamp_iso'], build['timestamp_raw']))
    print('                 caveat: %s' % build['timestamp_caveat'])
    print('  linker version %s' % build['linker_version'])
    if build['rich_header_present']:
        r = build['rich_header']
        print('  rich header    present, %d entries, key %s, build ids %s'
              % (r['entries'], r['xor_key'], build['rich_build_ids']))
        print('                 %s' % r['note'])
    else:
        print('  rich header    absent -- the MSVC linker writes one, so either the toolchain is '
              'not MSVC, or the header was stripped. Absence is a signal, not a verdict.')
    if build['pdb']:
        print('  debug / pdb    %s (%s, age %s)' % (build['pdb']['path'], build['pdb']['format'],
                                                    build['pdb'].get('age')))
    else:
        print('  debug / pdb    no CodeView record in the debug directory'
              ' (entries: %d)' % len(build['debug_entries']))
    print('  managed        %s' % ('yes, CLR directory %s' % build['clr_directory']
                                   if build['managed'] else 'no CLR directory'))
    print('  certificate    %s' % ('present' if build['signed'] else 'no certificate table'))

    print('\nsections (entropy over each section\'s first 65536 raw bytes, not the whole section)')
    print('  %-10s %-10s %-9s %-9s %-6s %s' % ('name', 'va', 'vsize', 'rawsize', 'ent', 'flags'))
    for s in rep['sections']:
        print('  %-10s %-10s %-9d %-9d %-6.2f %s'
              % (s['name'], s['virtual_address'], s['virtual_size'], s['raw_size'],
                 s['entropy'], ','.join(s['flags'])))
    if rep['limits']['sections_total'] > rep['limits']['sections_shown']:
        print('  ... %d more section(s) not shown (--full-out keeps them)'
              % (rep['limits']['sections_total'] - rep['limits']['sections_shown']))

    print('\nsignals (%d) -- each row is a reason to look, with the number behind it'
          % len(rep['signals']))
    if not rep['signals']:
        print('  none of the heuristics fired. That is not a clean bill of health: the checks are '
              'header-level, and a protector that keeps the headers tidy produces the same '
              'report as an ordinary build.')
    for s in rep['signals']:
        print('  [%s] %s' % (s['id'], s['measurement']))
        print('      -> %s' % s['suggests'])

    surf = rep['surface']
    print('\nsurface')
    print('  imports        %d DLL(s), %d function(s)'
          % (surf['import_dll_count'], surf['import_function_count']))
    for d in surf['import_dlls']:
        shown = ', '.join(d['names'][:6]) + (' ...' if len(d['names']) > 6 else '')
        print('    %-28s %4d  %s' % (d['dll'], d['functions'], shown))
    if surf['import_dlls_omitted']:
        print('    ... %d more DLL(s) not shown (--full-out keeps them)'
              % surf['import_dlls_omitted'])
    if surf['delay_import_dlls']:
        print('  delay imports  %s' % ', '.join(surf['delay_import_dlls']))
    print('  exports        %d function(s), %d named, module %s'
          % (surf['export_count'], surf['export_named_count'], surf['export_name']))
    print('  resources      %d entries, types: %s'
          % (surf['resources_total'],
             ', '.join('%s=%d' % kv for kv in sorted(surf['resource_types'].items()))
             or '(none)'))
    if surf['strings']:
        print('  strings        UNTRUSTED target-derived content, presented as data and never as '
              'instructions:')
        print('                 each sample is a raw byte window, so adjacent bytes can be '
              'included (a URL inside a certificate blob picks up the bytes that follow it). '
              'Treat them as leads to verify, not as parsed values.')
        for klass in sorted(surf['strings']):
            entry = surf['strings'][klass]
            print('    %-9s %d found%s' % (klass, entry['count'],
                                           ' (count capped)' if entry['count_capped'] else ''))
            for sample in entry['samples']:
                print('      %s  [%s at file offset %s]'
                      % (sample['value'][:110], sample['view'], sample['first_offset']))
    elif args.no_strings:
        print('  strings        skipped (--no-strings)')

    if rep['notes']:
        print('\nnotes')
        for n in rep['notes']:
            print('  - %s' % n)

    print('\nwhat to do next')
    for step in rep['next']:
        print('  - %s' % step)
    print('\nsummary: %d signal(s), %d note(s), %d section(s), %d imported DLL(s). Read the '
          'signals before choosing a tool'
          % (len(rep['signals']), len(rep['notes']), rep['limits']['sections_total'],
             rep['surface']['import_dll_count']))


def main():
    ap = argparse.ArgumentParser(
        description='Bounded, decision-oriented triage of an unknown PE image.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Entropy and section shape are reported as signals with their measurements, never '
               'as verdicts. Example:\n  python pe_triage.py sample.exe --full-out triage.json')
    ap.add_argument('pe', help='path to a PE file (.exe/.dll/.sys/.ocx/.cpl)')
    ap.add_argument('--json', action='store_true', help='emit the bounded report as JSON')
    ap.add_argument('--full-out', metavar='PATH',
                    help='write the complete record as JSON to PATH and report the path')
    ap.add_argument('--max-dlls', type=int, default=5, help='import DLLs listed (default 5)')
    ap.add_argument('--max-strings', type=int, default=5,
                    help='string samples kept per class (default 5)')
    ap.add_argument('--no-strings', action='store_true', help='skip the string scan')
    ap.add_argument('--no-checksum', action='store_true', help='skip the O(file size) checksum')
    ap.add_argument('--scan-limit', type=int, default=16 * 1024 * 1024, metavar='BYTES',
                    help='string scan reads at most this many bytes from the start of the file '
                         '(default 16777216); the effective value is reported in limits')
    ap.add_argument('--entropy-threshold', type=float, default=DEFAULT_ENTROPY_HIGH,
                    help='entropy at or above which a section is reported (default %.1f of 8.0)'
                         % DEFAULT_ENTROPY_HIGH)
    ap.add_argument('--low-entropy-threshold', type=float, default=DEFAULT_ENTROPY_LOW,
                    help='entropy at or below which an executable section is reported '
                         '(default %.1f)' % DEFAULT_ENTROPY_LOW)
    ap.add_argument('--vsize-ratio', type=float, default=DEFAULT_VSIZE_RATIO,
                    help='virtual/raw size ratio at which a section is reported (default %.1f)'
                         % DEFAULT_VSIZE_RATIO)
    ap.add_argument('--import-threshold', type=int, default=DEFAULT_IMPORT_THRESHOLD,
                    help='report when the import table resolves fewer functions than this '
                         '(default %d)' % DEFAULT_IMPORT_THRESHOLD)
    args = ap.parse_args()

    if not os.path.isfile(args.pe):
        sys.stderr.write('error: %s is not a file\n' % args.pe)
        return 2
    try:
        with open(args.pe, 'rb') as fh:
            data = fh.read()
        pe = PE(data, args.pe)
    except (ParseError, OSError) as exc:
        sys.stderr.write('error: %s: %s\n' % (args.pe, exc))
        return 1

    report = build_report(pe, data, args)
    report['next'] = next_steps(report)

    written = None
    if args.full_out:
        try:
            with open(args.full_out, 'w', encoding='utf-8') as fh:
                json.dump(report, fh, indent=2, ensure_ascii=True)
            written = os.path.abspath(args.full_out)
        except OSError as exc:
            sys.stderr.write('error: cannot write --full-out %s: %s\n' % (args.full_out, exc))
            return 2

    rep = bounded(report, args)
    if written:
        rep['limits']['full_record'] = written

    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=True))
    else:
        print_text(rep, args)
        if written:
            print('\ncomplete record written to %s (%d bytes)'
                  % (written, os.path.getsize(written)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
