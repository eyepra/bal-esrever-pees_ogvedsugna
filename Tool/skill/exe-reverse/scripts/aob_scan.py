#!/usr/bin/env python3
"""Locate a site in a PE by byte pattern, and report exactly how well the pattern performs.

Why this is a tool rather than a `grep`: the interesting output is not the match, it is the
**match count and where each hit lives**. A pattern that matches once is a locator. A pattern
that matches forty times is a coin flip that will silently pick the wrong site on the next
build, and a pattern that matches zero times on the new version is the moment a signature has
to be migrated rather than re-typed. This script makes those three outcomes distinguishable
before anyone patches anything.

What it reports per hit: file offset, the RVA it maps to, the containing section, and (with
`--context`) the surrounding bytes. What it reports per pattern: the hit count and a verdict,
so "ambiguous" is a stated result rather than something a caller has to notice.

Two modes:

  * **locate** (default) -- search one image; the text and JSON output are both built to be
    read by a person deciding whether to trust the pattern.
  * **`--across OLD_PE`** -- migrate: run the pattern against a second build of the same
    program and report which sites survived. A pattern whose hit count changes between builds
    is described as what it is: it matched something, and the match is not the same thing on
    both sides until the surrounding structure agrees.

Signature files hold one pattern per line, or a JSON object; `--patterns` accepts a file or an
inline pattern, and both forms may be mixed.

Usage:
    python aob_scan.py sample.exe --patterns "48 8B 05 ?? ?? ?? ??"
    python aob_scan.py sample.exe --patterns sigs.txt --section .text --context 16
    python aob_scan.py sample.exe --patterns sigs.txt --json
    python aob_scan.py new.exe --patterns sigs.txt --across old.exe

Exit codes: 0 = every pattern matched and each was unambiguous, 1 = at least one pattern
matched zero times or more than once, 2 = usage error, 3 = the input is not a parseable PE.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peutil import PE, ParseError                      # noqa: E402
from pepatch import find_pattern, parse_bytes, fmt_bytes   # noqa: E402

# A hit count above this is not a locator any more; it is a byte sequence that happens to be
# common. The number is a reporting threshold, not a correctness rule.
AMBIGUOUS_AT = 2
NOTICEABLE_AT = 8


def load_patterns(args):
    """[(name, bytes_list, source_text)] from --patterns, in file or inline form."""
    out = []
    if not args.patterns:
        return out
    for entry in args.patterns:
        if os.path.isfile(entry):
            if entry.lower().endswith('.json'):
                try:
                    with open(entry, encoding='utf-8') as fh:
                        doc = json.load(fh)
                except (OSError, ValueError) as exc:
                    raise SystemExit('error: %s: %s' % (entry, exc))
                # A bare array is as reasonable a shape as an object with a "patterns" key, and
                # calling .get() on a list is what made an earlier version raise AttributeError
                # instead of reading the file.
                if isinstance(doc, list):
                    items = doc
                elif isinstance(doc, dict):
                    items = doc.get('patterns', [])
                else:
                    raise SystemExit('error: %s: a JSON pattern file must hold an array or an '
                                     'object with a "patterns" key, not a %s'
                                     % (entry, type(doc).__name__))
                for i, item in enumerate(items):
                    if isinstance(item, str):
                        out.append(('%s[%d]' % (os.path.basename(entry), i), item))
                    else:
                        out.append((item.get('name') or '%s[%d]' % (os.path.basename(entry), i),
                                    item.get('pattern') or item.get('bytes') or ''))
            else:
                with open(entry, encoding='utf-8') as fh:
                    for lineno, line in enumerate(fh, 1):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        if '\t' in line:
                            name, _, pat = line.partition('\t')
                            out.append((name.strip(), pat.strip()))
                        else:
                            out.append(('%s:%d' % (os.path.basename(entry), lineno), line))
        else:
            out.append(('inline', entry))
    parsed = []
    for name, text in out:
        try:
            pat, _ = parse_bytes(text)
        except ValueError as exc:
            raise SystemExit('error: %s: %s' % (name, exc))
        if not pat or all(b is None for b in pat):
            raise SystemExit('error: %s: pattern is empty or all wildcards' % name)
        parsed.append((name, pat, text))
    return parsed


def locate(pe, data, pat, section_filter=None, context=0, limit=64):
    hits = find_pattern(data, pat, limit=limit)
    rows = []
    for off in hits:
        sec = None
        for s in pe.sections:
            if s.raw_pointer <= off < s.raw_pointer + s.raw_size:
                sec = s
                break
        row = {
            'offset': off,
            'offset_hex': hex(off),
            'rva': pe.offset_to_rva(off),
            'section': sec.name if sec else None,
        }
        if row['rva'] is not None:
            row['rva_hex'] = hex(row['rva'])
        if sec and section_filter and sec.name != section_filter:
            continue
        if context:
            lo = max(0, off - context)
            hi = min(len(data), off + len(pat) + context)
            row['context'] = fmt_bytes(data[lo:hi])
            row['context_marks'] = 'pre %d bytes, match %d, post %d' % (
                off - lo, len(pat), hi - (off + len(pat)))
        rows.append(row)
    return rows


def verdict(count, total):
    if count == 0:
        return 'no-match'
    if count == 1:
        return 'unique'
    if count >= NOTICEABLE_AT:
        return 'pervasive'
    return 'ambiguous'


def main():
    ap = argparse.ArgumentParser(
        description='Locate byte patterns in a PE, with the match count that decides whether '
                    'the pattern is usable as a locator.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='A wildcard is ? or ??. Use --section to restrict hits and --across to compare '
               'two builds of the same program.')
    ap.add_argument('pe', help='the PE to search')
    ap.add_argument('--patterns', action='append', default=[],
                    help='a pattern, or a file of patterns (one per line, or JSON). Repeatable')
    ap.add_argument('--section', help='only report hits inside this section (e.g. .text)')
    ap.add_argument('--context', type=int, default=0,
                    help='bytes of context to print around each hit')
    ap.add_argument('--limit', type=int, default=64, help='stop after this many hits per pattern')
    ap.add_argument('--across', help='a second build of the same program, to compare hit counts')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--quiet', action='store_true', help='one line per pattern')
    args = ap.parse_args()

    patterns = load_patterns(args)
    if not patterns:
        ap.error('at least one --patterns value is required')

    try:
        pe = PE(open(args.pe, 'rb').read(), args.pe)
    except (ParseError, OSError) as exc:
        sys.stderr.write('error: %s: %s\n' % (args.pe, exc))
        return 3
    with open(args.pe, 'rb') as fh:
        data = fh.read()

    other = None
    other_data = None
    if args.across:
        try:
            other_data = open(args.across, 'rb').read()
            other = PE(other_data, args.across)
        except (ParseError, OSError) as exc:
            sys.stderr.write('error: --across: %s: %s\n' % (args.across, exc))
            return 3

    report = {
        'target': args.pe, 'target_sections': [s.name for s in pe.sections],
        'section_filter': args.section, 'patterns': [],
    }
    worst = 0

    for name, pat, text in patterns:
        rows = locate(pe, data, pat, args.section, args.context, args.limit)
        count = len(rows)
        entry = {
            'name': name, 'pattern': text,
            'length': len(pat), 'wildcards': sum(1 for b in pat if b is None),
            'hits': count, 'verdict': verdict(count, count), 'sites': rows,
        }
        if other is not None:
            other_rows = locate(other, other_data, pat, args.section, 0, args.limit)
            entry['across'] = {
                'target': args.across,
                'hits': len(other_rows),
                'verdict': verdict(len(other_rows), len(other_rows)),
                'same_count': len(other_rows) == count,
                'sites': [{'offset_hex': r['offset_hex'], 'rva_hex': r.get('rva_hex'),
                           'section': r['section']} for r in other_rows],
            }
            if len(other_rows) != count:
                worst = max(worst, 1)
        if count != 1:
            worst = max(worst, 1)
        report['patterns'].append(entry)

    report['result'] = 'ok' if worst == 0 else 'needs-attention'

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if worst == 0 else 1

    print('%s' % report['target'])
    print('  sections: %s' % ', '.join(report['target_sections']))
    for e in report['patterns']:
        if args.quiet:
            print('  %-24s %-11s %d hit(s)' % (e['name'], e['verdict'], e['hits']))
            continue
        print('  %s' % e['name'])
        print('    pattern   %s   (%d bytes, %d wildcard%s)'
              % (e['pattern'], e['length'], e['wildcards'],
                 '' if e['wildcards'] == 1 else 's'))
        print('    hits      %d  ->  %s' % (e['hits'], e['verdict']))
        for r in e['sites']:
            print('      file 0x%-8X rva %-9s %s'
                  % (r['offset'], r.get('rva_hex') or '-', r['section'] or '(no section)'))
            if 'context' in r:
                print('        %s   [%s]' % (r['context'], r['context_marks']))
        if e['hits'] == 0:
            print('      -> the pattern does not exist in this build. Do not re-type it from '
                  'the disassembly: find the site again by structure, then write the pattern '
                  'from the new bytes.')
        elif e['hits'] > 1:
            print('      -> %d sites. A pattern is only a locator when it is unique; anchor it '
                  'on surrounding structure (a neighbouring call, a referenced string) before '
                  'using it.' % e['hits'])
        if 'across' in e:
            a = e['across']
            print('    across    %s: %d hit(s) -> %s'
                  % (a['target'], a['hits'], a['verdict']))
            if not a['same_count']:
                print('      -> hit count changed between builds (%d vs %d). The pattern still '
                      'matches something; it is not established that it matches the same '
                      'thing. Compare the surrounding structure at each site.'
                      % (e['hits'], a['hits']))
    print('\n%d pattern(s): %s' % (len(report['patterns']), report['result']))
    return 0 if worst == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
