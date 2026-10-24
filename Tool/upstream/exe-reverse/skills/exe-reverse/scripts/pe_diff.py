#!/usr/bin/env python3
"""Compare two builds of the same program at the header and section level.

**A diff shows change, never intent.** Two builds that differ in one byte differ by one byte; it
says nothing about what that byte does, whether it was written by a compiler, a packer or a
person, and whether it matters. **And identical bytes do not prove identical behaviour**: the same
image run against a different configuration file, a different server response, a different licence
or a different OS build will behave differently with a byte-identical file on disk. This script
answers "what changed between these two files", and every sentence in its output is a statement
about bytes.

Why the volatile fields are normalised instead of compared: a rebuild of the same source with the
same compiler changes the file-header TimeDateStamp, the PE checksum, the Rich Header and the
resource timestamps, and any build machine path change rewrites the PDB path in the debug
directory. Compared naively, those fields dominate every row of the report and hide the one section
that actually changed. So they are zeroed in a private copy of each image before the comparison,
the list of what was normalised is printed with its byte count, and the raw hashes are printed
beside the normalised ones so nothing is hidden by the normalisation. Pass `--no-normalise` to
compare the bytes as they are, and read that mode as "these two files are not byte-identical"
rather than as "this code changed".

What it reports:

  1. identity of both files, and a comparability note when they are not the same architecture,
     bitness, subsystem or machine -- a byte diff across those is still computed, but it is not a
     build comparison.
  2. every volatile field that was normalised, with the value from each side, so the difference is
     visible even though it is not counted as content.
  3. per-section content hashes: raw sha256 and normalised sha256, each side, with a verdict of
     identical, differs-in-normalised-fields-only, changed, added or removed. Hashing the section
     bytes rather than comparing lengths is what catches a same-size replacement, which is the
     common case for a byte patch and the one a "size changed?" check misses.
  4. the byte-level difference count and the differing ranges, each range mapped to its RVA and
     its containing section on both sides, with ranges closer than `--merge-gap` merged so a
     repacked section does not produce thousands of one-byte rows.
  5. the sections that changed in a way the normalisation does not explain -- the short list a
     reader actually needs.

Bounded by design: the range list and the section table are capped and the caps are printed with
the totals, so a diff between two unrelated multi-megabyte images cannot produce an unreadable
report. `--full-out PATH` writes the complete record as JSON and reports the path. The byte walk
stops after `--diff-budget` differing bytes (default 4 MiB) and says so: past that point the two
files are not two builds of one program, and a range list stops being information.

Usage:
    python pe_diff.py old.exe new.exe
    python pe_diff.py old.exe new.exe --summary
    python pe_diff.py old.exe new.exe --json --full-out diff.json
    python pe_diff.py old.exe new.exe --no-normalise --max-ranges 40

Exit codes: 0 = identical once the normalised fields are excluded, 1 = the images differ in content,
2 = usage error, 3 = an input is not a parseable PE. Exit 1 means "these files are not the same
bytes", never "this build is malicious" or "the change is meaningful".
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peutil import (PE, ParseError, u16, u32, SUBSYSTEM, DIR_RESOURCE, DIR_DEBUG,   # noqa: E402
                    DLL_CHARACTERISTICS, bits)

DEFAULT_MERGE_GAP = 8                  # bytes between differences that still count as one range
DEFAULT_MAX_RANGES = 20                # ranges printed before the report is summarised
MAX_SECTIONS_SHOWN = 32
DEFAULT_DIFF_BUDGET = 4 * 1024 * 1024  # differing bytes after which the byte walk stops
CHUNK = 4096                           # chunk-compare granularity; keeps the walk C-level


def resource_data_entry_offsets(pe, data, limit=4096):
    """File offsets of every IMAGE_RESOURCE_DATA_ENTRY, so its TimeDateStamp can be normalised.

    peutil.resources() reports the data entry's contents (data RVA, size, codepage) but not where
    the entry itself lives, and the entry's own TimeDateStamp lives at +4. Normalising resource
    timestamps therefore needs the entry offsets, and this walk is the smallest way to get them.
    The two 16-bit counts are read the way peutil reads them: reading either as 32-bit swallows the
    first bytes of the following entry and inflates the count.
    """
    out = []
    base_rva, _size = pe.directories.get(DIR_RESOURCE, (0, 0))
    if not base_rva:
        return out
    stack = [0]
    seen = set()
    while stack and len(out) < limit:
        rel = stack.pop()
        if rel in seen:
            continue
        seen.add(rel)
        p = pe.rva_to_offset(base_rva + rel)
        if p is None or p + 16 > len(data):
            continue
        named = u16(data, p + 12)
        ids = u16(data, p + 14)
        for i in range(named + ids):
            e = p + 16 + i * 8
            if e + 8 > len(data):
                break
            off_field = u32(data, e + 4)
            if off_field & 0x80000000:
                stack.append(off_field & 0x7FFFFFFF)
            else:
                dp = pe.rva_to_offset(base_rva + off_field)
                if dp is not None and dp + 16 <= len(data):
                    out.append(dp)
    return out


def normalisation_regions(pe, data):
    """[(file_offset, length, label)] for every field that changes on a rebuild."""
    regions = []
    if pe.e_lfanew + 12 <= len(data):
        regions.append((pe.e_lfanew + 8, 4, 'file-header TimeDateStamp'))
    if pe.optional_offset + 68 <= len(data):
        regions.append((pe.optional_offset + 64, 4, 'optional-header CheckSum'))
    rich = pe.rich_header()
    if rich:
        rich_off = data.find(b'Rich', rich['offset'])
        if rich_off > 0 and rich_off + 8 <= len(data):
            regions.append((rich['offset'], rich_off + 8 - rich['offset'],
                            'Rich Header (DanS block through Rich signature)'))
    rva, size = pe.directories.get(DIR_DEBUG, (0, 0))
    dp = pe.rva_to_offset(rva) if rva else None
    if dp is not None:
        for i in range(max(0, size // 28)):
            e = dp + i * 28
            if e + 28 > len(data):
                break
            regions.append((e + 4, 4, 'debug-directory[%d] TimeDateStamp' % i))
            blob_ptr = u32(data, e + 24)
            blob_size = u32(data, e + 16)
            if blob_size and blob_ptr + blob_size <= len(data):
                regions.append((blob_ptr, blob_size,
                                'debug-directory[%d] data (CodeView path, GUID and age)' % i))
    for i, off in enumerate(resource_data_entry_offsets(pe, data)):
        regions.append((off + 4, 4, 'resource data-entry[%d] TimeDateStamp' % i))
    return [r for r in regions if r[1] > 0 and r[0] + r[1] <= len(data)]


def normalise(data, regions):
    """A private copy of the bytes with every region zeroed. The input is never modified."""
    out = bytearray(data)
    zeroed = 0
    for off, length, _label in regions:
        out[off:off + length] = b'\x00' * length
        zeroed += length
    return out, zeroed


def section_bytes(data, section):
    if section.raw_pointer is None or section.raw_size in (None, 0):
        return b''
    end = min(len(data), section.raw_pointer + section.raw_size)
    return bytes(data[section.raw_pointer:end])


def diff_ranges(a, b, merge_gap, budget):
    """(differing bytes, [(start, end)], truncated) over the common prefix of two buffers.

    Chunks are compared whole so the common case -- two builds that agree almost everywhere -- is
    handled by C-level comparison instead of a Python loop over every byte.
    """
    n = min(len(a), len(b))
    differ = 0
    ranges = []
    cur = None
    truncated = False
    for start in range(0, n, CHUNK):
        end = min(start + CHUNK, n)
        if a[start:end] == b[start:end]:
            continue
        i = start
        while i < end:
            if a[i] != b[i]:
                differ += 1
                if cur is None:
                    cur = [i, i + 1]
                elif i - cur[1] <= merge_gap:
                    cur[1] = i + 1
                else:
                    ranges.append(cur)
                    cur = [i, i + 1]
            i += 1
        if differ > budget:
            truncated = True
            break
    if cur:
        ranges.append(cur)
    return differ, ranges, truncated


def identity_of(pe, data):
    return {
        'path': os.path.abspath(pe.path) if pe.path else None,
        'size': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'arch': pe.arch,
        'bitness': 64 if pe.is_pe32plus else 32,
        'machine': hex(pe.machine),
        'subsystem': SUBSYSTEM.get(pe.subsystem, str(pe.subsystem)),
        'entry_point_rva': hex(pe.address_of_entrypoint),
        'image_base': hex(pe.image_base),
        'size_of_image': pe.size_of_image,
        'section_count': len(pe.sections),
        'checksum_declared': hex(pe.checksum),
        'timestamp_raw': pe.timestamp,
        'dll_characteristics': bits(pe.dll_characteristics, DLL_CHARACTERISTICS),
    }


def volatile_report(pe_a, pe_b, data_a, data_b):
    """The normalised fields, with both values, so the difference stays visible."""
    def rich_builds(pe):
        r = pe.rich_header()
        return sorted(set(e['build'] for e in r['entries'])) if r else None

    def pdb(pe):
        for d in pe.debug_directory():
            if d.get('pdb'):
                return {'path': d['pdb'], 'format': d.get('format'), 'age': d.get('age')}
        return None

    return {
        'timestamp': {'a': hex(pe_a.timestamp), 'b': hex(pe_b.timestamp),
                      'same': pe_a.timestamp == pe_b.timestamp,
                      'note': 'a rebuild changes this; a deterministic build stores a content '
                              'hash here, so an equal value can also mean an identical file'},
        'checksum': {'a': hex(pe_a.checksum), 'b': hex(pe_b.checksum),
                     'same': pe_a.checksum == pe_b.checksum,
                     'note': 'the PE checksum covers the whole file, so it changes whenever any '
                             'other byte does'},
        'rich_header': {'a_builds': rich_builds(pe_a), 'b_builds': rich_builds(pe_b),
                        'same': rich_builds(pe_a) == rich_builds(pe_b),
                        'note': 'the MSVC toolchain fingerprint; different builds frequently '
                                'differ here without any source change'},
        'pdb': {'a': pdb(pe_a), 'b': pdb(pe_b), 'same': pdb(pe_a) == pdb(pe_b),
                'note': 'the PDB path records the build machine, so it changes with the build '
                        'location rather than with the code'},
        'resource_timestamps': {
            'a_entries': len(resource_data_entry_offsets(pe_a, data_a)),
            'b_entries': len(resource_data_entry_offsets(pe_b, data_b)),
        },
    }


def compare_sections(pe_a, pe_b, nrm_a, nrm_b, show_max):
    """Per-section raw and normalised digests, plus the content verdict."""
    def index(pe):
        out = {}
        for s in pe.sections:
            out.setdefault(s.name, []).append(s)
        return out

    ia, ib = index(pe_a), index(pe_b)
    names = [s.name for s in pe_a.sections] + [s.name for s in pe_b.sections if s.name not in ia]
    rows = []
    for name in names:
        sa = ia.get(name, [None])[0]
        sb = ib.get(name, [None])[0]
        row = {'name': name}
        if sa is None or sb is None:
            row['verdict'] = 'added' if sa is None else 'removed'
            row['present_in'] = 'b' if sa is None else 'a'
            rows.append(row)
            continue
        body_a_raw = section_bytes(pe_a.d, sa)
        body_b_raw = section_bytes(pe_b.d, sb)
        body_a_nrm = section_bytes(nrm_a, sa)
        body_b_nrm = section_bytes(nrm_b, sb)
        row['raw_sha256_a'] = hashlib.sha256(body_a_raw).hexdigest()[:16]
        row['raw_sha256_b'] = hashlib.sha256(body_b_raw).hexdigest()[:16]
        row['normalised_sha256_a'] = hashlib.sha256(body_a_nrm).hexdigest()[:16]
        row['normalised_sha256_b'] = hashlib.sha256(body_b_nrm).hexdigest()[:16]
        raw_same = row['raw_sha256_a'] == row['raw_sha256_b']
        nrm_same = row['normalised_sha256_a'] == row['normalised_sha256_b']
        row['raw_identical'] = raw_same
        row['same_size'] = sa.raw_size == sb.raw_size
        row['layout_changed'] = (sa.raw_pointer != sb.raw_pointer
                                 or sa.virtual_address != sb.virtual_address
                                 or sa.virtual_size != sb.virtual_size
                                 or sa.characteristics != sb.characteristics)
        if raw_same:
            row['verdict'] = 'identical'
        elif nrm_same:
            row['verdict'] = 'differs-in-normalised-fields-only'
        else:
            row['verdict'] = 'changed'
            row['a'] = {'raw_size': sa.raw_size, 'entropy': round(sa.entropy or 0.0, 4)}
            row['b'] = {'raw_size': sb.raw_size, 'entropy': round(sb.entropy or 0.0, 4)}
            row['entropy_delta'] = round((sb.entropy or 0.0) - (sa.entropy or 0.0), 4)
        rows.append(row)
    return rows[:show_max], rows


def range_detail(start, end, pe_a, pe_b):
    """Map a file-offset range to the RVA and section it belongs to on both sides.

    A range inside the headers is reported as headers rather than as an RVA: peutil.offset_to_rva
    returns the offset unchanged below SizeOfHeaders, which makes a header offset *look* like an
    RVA. It is not one -- header bytes are addressed by offset, and only section bytes have an RVA
    that a debugger or a patch site can use.
    """
    def side(pe):
        in_headers = start < (pe.size_of_headers or 0)
        rva = pe.offset_to_rva(start)
        sec = pe.section_of_rva(rva) if (rva is not None and not in_headers) else None
        return {'rva': (None if in_headers else (hex(rva) if rva is not None else None)),
                'in_headers': bool(in_headers),
                'section': sec.name if sec else None}
    out = {'offset': hex(start), 'end': hex(end), 'length': end - start}
    out['a'] = side(pe_a)
    out['b'] = side(pe_b)
    return out


def summarise_regions(regions):
    """Collapse repeated region labels into one row each, keeping the count and the byte total.

    A resource section with thirty entries produces thirty one-line rows that all say the same
    thing, which is how a normalisation table turns into the wall of output this repository tells
    its scripts not to print. The full list is still in the record; this is only the text view.
    """
    order = []
    agg = {}
    for off, length, label in regions:
        key = re.sub(r'\[\d+\]', '[*]', label)
        if key not in agg:
            agg[key] = [1, length, off]
            order.append(key)
        else:
            agg[key][0] += 1
            agg[key][1] += length
            agg[key][2] = off
    return [(key, agg[key][0], agg[key][1], agg[key][2]) for key in order]


def describe_site(site):
    if site.get('in_headers'):
        return 'headers'
    rva = site.get('rva')
    if rva is None:
        return 'no file mapping'
    return 'rva %s %s' % (rva, site.get('section') or '(no section)')


def main():
    ap = argparse.ArgumentParser(
        description='Compare two builds of the same program at the header, section and byte '
                    'level, with the volatile rebuild fields normalised.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='A diff shows change, never intent; identical bytes do not prove identical '
               'behaviour. Example:\n  python pe_diff.py old.exe new.exe --summary')
    ap.add_argument('old', help='the first build (the baseline)')
    ap.add_argument('new', help='the second build (the candidate)')
    ap.add_argument('--summary', action='store_true',
                    help='one line per section plus the totals, without the byte ranges')
    ap.add_argument('--json', action='store_true', help='emit the report as JSON')
    ap.add_argument('--full-out', metavar='PATH',
                    help='write the complete record as JSON to PATH and report the path')
    ap.add_argument('--no-normalise', action='store_true',
                    help='compare the bytes as they are, including TimeDateStamp and CheckSum')
    ap.add_argument('--merge-gap', type=int, default=DEFAULT_MERGE_GAP,
                    help='differences closer than this many bytes are reported as one range '
                         '(default %d)' % DEFAULT_MERGE_GAP)
    ap.add_argument('--max-ranges', type=int, default=DEFAULT_MAX_RANGES,
                    help='differing ranges printed before the rest is summarised (default %d)'
                         % DEFAULT_MAX_RANGES)
    ap.add_argument('--diff-budget', type=int, default=DEFAULT_DIFF_BUDGET, metavar='BYTES',
                    help='stop the byte walk after this many differing bytes (default %d)'
                         % DEFAULT_DIFF_BUDGET)
    args = ap.parse_args()

    loaded = []
    for path in (args.old, args.new):
        if not os.path.isfile(path):
            sys.stderr.write('error: %s is not a file\n' % path)
            return 2
        try:
            with open(path, 'rb') as fh:
                blob = fh.read()
            loaded.append((PE(blob, path), blob))
        except (ParseError, OSError) as exc:
            sys.stderr.write('error: %s: %s\n' % (path, exc))
            return 3
    (pe_a, data_a), (pe_b, data_b) = loaded

    reg_a = [] if args.no_normalise else normalisation_regions(pe_a, data_a)
    reg_b = [] if args.no_normalise else normalisation_regions(pe_b, data_b)
    nrm_a, zeroed_a = normalise(data_a, reg_a)
    nrm_b, zeroed_b = normalise(data_b, reg_b)

    sections_shown, sections_all = compare_sections(pe_a, pe_b, nrm_a, nrm_b, MAX_SECTIONS_SHOWN)
    differ, ranges, truncated = diff_ranges(nrm_a, nrm_b, args.merge_gap, args.diff_budget)

    comparability = {
        'same_machine': pe_a.machine == pe_b.machine,
        'same_bitness': pe_a.is_pe32plus == pe_b.is_pe32plus,
        'same_subsystem': pe_a.subsystem == pe_b.subsystem,
        'same_section_count': len(pe_a.sections) == len(pe_b.sections),
    }
    warnings = []
    if not comparability['same_machine']:
        warnings.append('different Machine (%s vs %s): not the same target architecture, so this '
                        'is not a build comparison' % (pe_a.arch, pe_b.arch))
    if not comparability['same_bitness']:
        warnings.append('different optional-header magic: a 32-bit and a 64-bit image share no '
                        'layout, and the byte diff mostly reflects that')
    if not comparability['same_subsystem']:
        warnings.append('different subsystem (%s vs %s)'
                        % (identity_of(pe_a, data_a)['subsystem'],
                           identity_of(pe_b, data_b)['subsystem']))

    material = [r['name'] for r in sections_all
                if r.get('verdict') in ('changed', 'added', 'removed')]

    report = {
        'a': identity_of(pe_a, data_a),
        'b': identity_of(pe_b, data_b),
        'comparability': dict(comparability, warnings=warnings),
        'normalisation': {
            'enabled': not args.no_normalise,
            'regions_a': [{'label': lbl, 'offset': hex(off), 'length': ln}
                          for off, ln, lbl in reg_a],
            'regions_b': [{'label': lbl, 'offset': hex(off), 'length': ln}
                          for off, ln, lbl in reg_b],
            'bytes_zeroed_a': zeroed_a,
            'bytes_zeroed_b': zeroed_b,
            'note': ('zeroed in a private copy before comparison; the raw hashes below are '
                     'computed over the untouched bytes, so nothing is hidden by this'),
        },
        'volatile_fields': (volatile_report(pe_a, pe_b, data_a, data_b)
                            if not args.no_normalise else None),
        'sections': sections_shown,
        'sections_total': len(sections_all),
        'sections_changed_materially': material,
        'byte_diff': {
            'differ_bytes': differ,
            'differ_bytes_is_lower_bound': truncated,
            'truncated': truncated,
            'diff_budget': args.diff_budget,
            'merge_gap': args.merge_gap,
            'ranges_total': len(ranges),
            'ranges': [range_detail(s, e, pe_a, pe_b) for s, e in ranges[:args.max_ranges]],
            'length_delta': len(data_b) - len(data_a),
            'note': ('counted over the common prefix of the two normalised images; a size '
                     'difference is reported as length_delta and its tail is not walked'),
        },
        'notes': [],
    }
    if truncated:
        report['notes'].append(
            'the images differ in more than %d bytes, so the byte walk stopped: past that point '
            'they are not two builds of one program and a range list is not information'
            % args.diff_budget)
    if args.no_normalise:
        report['notes'].append(
            'normalisation is off, so TimeDateStamp, CheckSum, the Rich Header and the debug '
            'records were compared as content. A difference in this mode means "not byte-'
            'identical", not "the code changed"')
    if any(not r.get('same_size', True) for r in sections_all
           if r.get('verdict') == 'changed'):
        report['notes'].append(
            'at least one changed section also changed raw size, so the comparison inside it is '
            'positional from its start and a shift early in the section makes every later byte '
            'differ')
    if pe_a.is_signed or pe_b.is_signed:
        report['notes'].append(
            'a certificate table is present on at least one side (%s / %s). Editing any byte '
            'outside that blob invalidates the signature, so a patched build is expected to '
            'differ here even if nothing else changed'
            % ('signed' if pe_a.is_signed else 'unsigned',
               'signed' if pe_b.is_signed else 'unsigned'))

    if material or differ or report['byte_diff']['length_delta']:
        verdict = 'changed'
    else:
        verdict = 'identical-modulo-normalised-fields'
    report['verdict'] = verdict
    report['material_change'] = bool(material)

    written = None
    if args.full_out:
        try:
            with open(args.full_out, 'w', encoding='utf-8') as fh:
                json.dump(report, fh, indent=2, ensure_ascii=True)
            written = os.path.abspath(args.full_out)
        except OSError as exc:
            sys.stderr.write('error: cannot write --full-out %s: %s\n' % (args.full_out, exc))
            return 2
    if written:
        report['notes'].append('complete record written to %s' % written)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0 if verdict == 'identical-modulo-normalised-fields' else 1

    ia, ib = report['a'], report['b']
    print('A  %s' % ia['path'])
    print('B  %s' % ib['path'])
    print('   A: %d bytes, %s / %d-bit / %s, entry %s, sha256 %s'
          % (ia['size'], ia['arch'], ia['bitness'], ia['subsystem'], ia['entry_point_rva'],
             ia['sha256'][:24]))
    print('   B: %d bytes, %s / %d-bit / %s, entry %s, sha256 %s'
          % (ib['size'], ib['arch'], ib['bitness'], ib['subsystem'], ib['entry_point_rva'],
             ib['sha256'][:24]))
    for w in warnings:
        print('   ! %s' % w)

    norm = report['normalisation']
    if norm['enabled']:
        print('\nnormalised (never compared as content; %d bytes in A, %d in B)'
              % (norm['bytes_zeroed_a'], norm['bytes_zeroed_b']))
        if reg_a == reg_b:
            print('   identical region list on both sides (%d region(s), %d bytes per side):'
                  % (len(reg_a), norm['bytes_zeroed_a']))
            for label, count, total, last_off in summarise_regions(reg_a):
                if count == 1:
                    print('     0x%-8X %6d  %s' % (last_off, total, label))
                else:
                    print('     %-3d x %-5d  %s (last at 0x%X)'
                          % (count, total // count, label, last_off))
        else:
            for side, regs in (('A', reg_a), ('B', reg_b)):
                for label, count, total, last_off in summarise_regions(regs):
                    if count == 1:
                        print('   %s 0x%-8X %6d  %s' % (side, last_off, total, label))
                    else:
                        print('   %s %-3d x %-5d  %s (last at 0x%X)'
                              % (side, count, total // count, label, last_off))
        vol = report['volatile_fields']
        print('   observed values: timestamp %s vs %s, checksum %s vs %s, rich builds %s vs %s, '
              'pdb %s vs %s'
              % (vol['timestamp']['a'], vol['timestamp']['b'], vol['checksum']['a'],
                 vol['checksum']['b'], vol['rich_header']['a_builds'],
                 vol['rich_header']['b_builds'],
                 (vol['pdb']['a'] or {}).get('path'), (vol['pdb']['b'] or {}).get('path')))
    else:
        print('\nnormalisation: OFF (--no-normalise)')

    print('\nsections (%d)' % report['sections_total'])
    print('   %-10s %-18s %-18s %s' % ('name', 'raw A / B', 'normalised A / B', 'verdict'))
    for r in report['sections']:
        if 'raw_sha256_a' not in r:
            print('   %-10s %-18s %-18s %s' % (r['name'], '-', '-', r['verdict']))
            continue
        print('   %-10s %-18s %-18s %s%s'
              % (r['name'], '%s/%s' % (r['raw_sha256_a'][:8], r['raw_sha256_b'][:8]),
                 '%s/%s' % (r['normalised_sha256_a'][:8], r['normalised_sha256_b'][:8]),
                 r['verdict'],
                 '' if not r.get('layout_changed') else '  [layout changed]'))
    if report['sections_total'] > len(report['sections']):
        print('   ... %d more section(s) (--full-out keeps them)'
              % (report['sections_total'] - len(report['sections'])))

    print('\nsections that changed in a way the normalisation does not explain: %s'
          % (', '.join(material) if material else 'none'))

    bd = report['byte_diff']
    if args.summary:
        print('byte diff: %d differing byte(s) in %d range(s); length delta %+d'
              % (bd['differ_bytes'], bd['ranges_total'], bd['length_delta']))
    else:
        print('\nbyte diff: %d differing byte(s) in %d range(s), length delta %+d%s'
              % (bd['differ_bytes'], bd['ranges_total'], bd['length_delta'],
                 ' (walk stopped at the budget)' if bd['truncated'] else ''))
        for r in bd['ranges']:
            print('   file %-10s len %-5d A %-26s   B %s'
                  % (r['offset'], r['length'], describe_site(r['a']), describe_site(r['b'])))
        if bd['ranges_total'] > len(bd['ranges']):
            print('   ... %d more range(s), and narrower rows, with --max-ranges or --full-out'
                  % (bd['ranges_total'] - len(bd['ranges'])))

    if report['notes']:
        print('\nnotes')
        for n in report['notes']:
            print('   - %s' % n)

    print('\nverdict: %s. A diff shows change, never intent; identical bytes do not prove '
          'identical behaviour.' % verdict)
    return 0 if verdict == 'identical-modulo-normalised-fields' else 1


if __name__ == '__main__':
    sys.exit(main())
