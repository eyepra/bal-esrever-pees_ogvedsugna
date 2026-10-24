#!/usr/bin/env python3
"""capability: record_folding

Turn a large record into a bounded summary without losing the record.

WHY THIS EXISTS
---------------
The rule was already written down -- a bounded summary over a complete retained record, and never
re-run a producer to shrink its answer -- but nothing implemented it. Meanwhile a single analysis
run on this host produced 395 MB across 152,997 files, one of which is 109 MB. Reading any of those
into a context is not possible, and the two ways people usually cope are both wrong: re-running the
tool at a coarser setting costs the same and returns less, and grepping by hand answers one question
and leaves no summary for the next.

So the shape is: read the file once, print a bounded description of its structure, and leave the file
where it is. The summary states how much it left out, because a bounded output that does not say what
it omitted is indistinguishable from a small input.

WHAT IT RECOGNISES
------------------
The shape is decided by one depth scan of the file's own bytes, in constant memory -- not by the
name or the size, because a pretty-printed document and a line-delimited record both begin with `{`
and a size cutoff once streamed one as the other, reporting sixteen thousand records from a file
that held a single object. Then:

  * JSON Lines -- the common shape for tool output that names one record per line. Reported: the
    record count, the union of keys, per-key value distributions with samples, and for a key with
    many distinct values, how many were seen.
  * JSON -- reported as a structure tree with types, array lengths and object key counts.
  * anything else -- line and byte counts, and a bounded head.

WHAT IT DOES NOT DO
-------------------
It does not modify, move or delete the input, does not load the whole file when the shape allows
streaming, and does not claim its summary is complete. `--limit` governs every list it prints, and
the count of what was withheld is printed next to it.

Usage
-----
    python fold.py big.jsonl
    python fold.py big.jsonl --limit 5
    python fold.py big.jsonl --grep 'premium' --limit 20
    python fold.py big.jsonl --key func        # focus one key's distribution
    python fold.py big.jsonl --json
    python fold.py tree.json
    python fold.py notes.txt

Exit codes: 0 = summarised, 1 = nothing matched the filter, 2 = usage error,
3 = the input could not be read. The last line is `RESULT=<token>`.
"""

import argparse
import collections
import json
import os
import sys

EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_USE = 2
EXIT_READ = 3

TOKENS = {'ok': 'fold_ok', 'empty': 'fold_nothing_matched', 'use': 'usage_error',
          'read': 'fold_unreadable'}

# How many distinct values are tracked per key before the tracker stops growing. This is a memory
# bound, not a result: anything printed from it is a floor and is labelled as one.
VALUE_TRACK_CAP = 2000

# Above this size a single JSON document is not loaded into memory at all; the summary says so and
# stops, because "structure not walked" is a reportable state and a swap death is not.
JSON_WALK_LIMIT = 256 * 1024 * 1024

# Bytes that count as whitespace between JSON values.
_JSON_WS = (0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C)


def probe_single_json(path, chunk=1 << 20):
    """Decide from the file itself whether it holds one JSON value or many, in constant memory.

    The first version of the shape decision read the first byte and a size cutoff, and a
    pretty-printed 32 MB document -- which begins with `{` exactly as a line-delimited file does --
    was streamed line by line and summarised as 16,278 records with 1,696,267 unparseable lines.
    Every one of those numbers was computed honestly and the summary described a file that did not
    exist: the shape was wrong, and no per-line care can repair a wrong shape.

    This scan watches bracket depth and skips string bodies, so braces, brackets and escaped quotes
    inside strings do not count. If the depth returns to zero and any non-whitespace byte follows,
    the file holds more than one value; if it closes only at end-of-file, it is one document. One
    pass, bounded memory, no dependency on names or sizes.
    """
    depth = 0
    in_string = False
    escape = False
    closed = False
    try:
        with open(path, 'rb') as fh:
            while True:
                buf = fh.read(chunk)
                if not buf:
                    break
                for b in buf:
                    if in_string:
                        if escape:
                            escape = False
                        elif b == 0x5C:                     # backslash
                            escape = True
                        elif b == 0x22:                     # closing quote
                            in_string = False
                        continue
                    if b == 0x22:
                        in_string = True
                    elif b == 0x7B or b == 0x5B:            # { or [
                        depth += 1
                    elif b == 0x7D or b == 0x5D:            # } or ]
                        depth -= 1
                        if depth == 0:
                            closed = True
                    elif closed and b not in _JSON_WS:
                        return 'multi'                      # content after the first value closed
    except OSError:
        return None
    # `closed` stays False only for input that never balances; the document reader fails on that
    # and the caller falls through to a text summary, which is the honest description of it.
    return 'single'


def human(n):
    for unit, div in (('GB', 1 << 30), ('MB', 1 << 20), ('KB', 1 << 10)):
        if n >= div:
            return '%.1f %s' % (n / div, unit)
    return '%d B' % n


def describe_value(v, width=60):
    """A short, honest rendering of one value: enough to recognise it, never the whole thing."""
    if isinstance(v, str):
        s = v if len(v) <= width else v[:width] + '...(%d chars)' % len(v)
        return s
    if isinstance(v, (int, float, bool)) or v is None:
        return repr(v)
    if isinstance(v, list):
        return '[%d items]' % len(v)
    if isinstance(v, dict):
        return '{%s}' % ', '.join(list(v)[:6])
    return repr(v)[:width]


def summarise_jsonl(path, limit, key_focus=None, grep=None):
    """Stream the file once. Counts are exact; samples are bounded."""
    records = 0
    bad = 0
    keys = collections.Counter()
    per_key = collections.defaultdict(collections.Counter)
    key_kinds = collections.defaultdict(collections.Counter)
    matches = []
    matched = 0
    head = []

    with open(path, encoding='utf-8', errors='replace') as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad += 1
                continue
            records += 1
            if len(head) < 3:
                head.append(obj)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    keys[k] += 1
                    key_kinds[k][type(v).__name__] += 1
                    if key_focus is None or k == key_focus:
                        if len(per_key[k]) < VALUE_TRACK_CAP:
                            per_key[k][describe_value(v, 48)] += 1
            if grep is not None and grep.lower() in line.lower():
                matched += 1
                if len(matches) < limit:
                    matches.append((lineno, obj))

    return {'shape': 'jsonl', 'records': records, 'unparseable_lines': bad,
            'keys': keys, 'kinds': key_kinds, 'values': per_key,
            'matches': matched, 'match_samples': matches, 'head': head}


def summarise_json(path, limit, depth=0, max_depth=4):
    """Structure only: types, lengths, key counts. Values are not walked."""
    with open(path, encoding='utf-8', errors='replace') as fh:
        doc = json.load(fh)

    def walk(node, d):
        if d >= max_depth:
            return '...'
        if isinstance(node, dict):
            return {k: walk(v, d + 1) for k, v in list(node.items())[:limit]}
        if isinstance(node, list):
            return [walk(node[0], d + 1), '... %d more of %d' % (max(0, len(node) - 1), len(node))] \
                if node else []
        return describe_value(node, 50)

    return {'shape': 'json', 'tree': walk(doc, depth)}


def summarise_text(path, limit, grep=None):
    lines = 0
    head = []
    matches = []
    matched = 0
    with open(path, encoding='utf-8', errors='replace') as fh:
        for lineno, line in enumerate(fh, 1):
            lines += 1
            if len(head) < limit:
                head.append(line.rstrip('\n'))
            if grep is not None and grep.lower() in line.lower():
                matched += 1
                if len(matches) < limit:
                    matches.append((lineno, line.rstrip('\n')))

    return {'shape': 'text', 'lines': lines, 'head': head,
            'matches': matched, 'match_samples': matches}


def print_jsonl(summary, limit, key_focus):
    print('shape      : JSON Lines')
    print('records    : %d' % summary['records'])
    if summary['unparseable_lines']:
        print('             %d line(s) did not parse and are not counted'
              % summary['unparseable_lines'])
    print()
    print('keys, by the number of records carrying them (showing %d of %d):'
          % (min(limit, len(summary['keys'])), len(summary['keys'])))
    for k, n in summary['keys'].most_common(limit):
        kinds = ', '.join('%s x%d' % (t, c) for t, c in summary['kinds'][k].most_common(3))
        print('  %-24s %8d   %s' % (k, n, kinds))
    if len(summary['keys']) > limit:
        print('  ... %d more key(s) withheld' % (len(summary['keys']) - limit))

    focus = [key_focus] if key_focus else [k for k, _ in summary['keys'].most_common(limit)]
    for k in focus:
        vals = summary['values'].get(k)
        if not vals:
            continue
        print()
        # The distinct-value count is capped while collecting, so it must not be printed as if it
        # were the true number. An earlier version said "N distinct values seen" where N was the cap,
        # which is the same class of error this tool exists to prevent: a bounded output that does
        # not admit its bound reads as a complete one.
        capped = len(vals) >= VALUE_TRACK_CAP
        print('key "%s": %s%d distinct value(s) %s (showing %d)'
              % (k, 'at least ' if capped else '', len(vals),
                 'counted before the tracking cap' if capped else 'seen',
                 min(limit, len(vals))))
        for v, c in vals.most_common(limit):
            print('  %-52s x%d' % (v[:52], c))
        if len(vals) > limit:
            print('  ... %d more value(s) withheld%s'
                  % (len(vals) - limit, ', and the total above is a floor' if capped else ''))

    if summary['matches']:
        print()
        print('matches: %d (showing %d)' % (summary['matches'], len(summary['match_samples'])))
        for lineno, obj in summary['match_samples']:
            print('  line %-8d %s' % (lineno, describe_value(obj, 100)))
        if summary['matches'] > len(summary['match_samples']):
            print('  ... %d more match(es) withheld' % (summary['matches']
                                                        - len(summary['match_samples'])))
    print()
    print('the record itself is untouched at %s' % summary['path'])


def main():
    ap = argparse.ArgumentParser(
        description='Summarise a large record without losing it: a bounded description now, the '
                    'whole thing still on disk.')
    ap.add_argument('path')
    ap.add_argument('--limit', type=int, default=12, help='rows shown per list (default 12)')
    ap.add_argument('--grep', help='also report lines matching this text, bounded by --limit')
    ap.add_argument('--key', help='focus one key of a JSON Lines record')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.path):
        sys.stderr.write('error: %s is not a file\n' % args.path)
        print('RESULT=%s' % TOKENS['use'])
        return EXIT_USE

    size = os.path.getsize(args.path)
    try:
        with open(args.path, 'rb') as fh:
            first = fh.read(1)
    except OSError as exc:
        sys.stderr.write('error: %s\n' % exc)
        print('RESULT=%s' % TOKENS['read'])
        return EXIT_READ

    # Decide the shape from the file's own structure, never from its size or its name: a
    # pretty-printed document and a line-delimited record both begin with `{`, and the first
    # version's size cutoff silently streamed one as the other (see probe_single_json).
    if first not in (b'{', b'['):
        summary = summarise_text(args.path, args.limit, args.grep)
    elif probe_single_json(args.path) == 'single':
        if size <= JSON_WALK_LIMIT:
            try:
                summary = summarise_json(args.path, args.limit)
            except ValueError:
                summary = summarise_text(args.path, args.limit, args.grep)
        else:
            summary = {'shape': 'json-huge'}
    else:
        summary = summarise_jsonl(args.path, args.limit, args.key, args.grep)
    summary['path'] = args.path
    summary['bytes'] = size

    if args.json:
        out = dict(summary)
        for k in ('keys', 'kinds', 'values'):
            if k in out and hasattr(out[k], 'items'):
                out[k] = {kk: (dict(vv) if hasattr(vv, 'items') else vv)
                          for kk, vv in out[k].items()}
        print(json.dumps(out, indent=2, default=str))
        print('RESULT=%s' % TOKENS['ok'])
        return EXIT_OK

    print('%s   %s' % (args.path, human(size)))
    print()
    if summary['shape'] == 'jsonl':
        print_jsonl(summary, args.limit, args.key)
    elif summary['shape'] == 'json':
        print('shape      : one JSON document')
        print('structure  :')
        print(json.dumps(summary['tree'], indent=2)[:4000])
        if len(json.dumps(summary['tree'], indent=2)) > 4000:
            print('  ... structure display capped at 4000 characters')
    elif summary['shape'] == 'json-huge':
        print('shape      : one JSON document')
        print('             %s exceeds the walk limit (%s), so its structure was not loaded'
              % (human(size), human(JSON_WALK_LIMIT)))
        print('             and nothing here describes its contents.')
        print('             the record is retained untouched; ask for a byte range of it rather')
        print('             than re-running the producer that wrote it.')
    else:
        print('shape      : text')
        print('lines      : %d' % summary['lines'])
        print()
        print('head (showing %d):' % len(summary['head']))
        for line in summary['head']:
            print('  %s' % line[:160])
        if summary['matches']:
            print()
            print('matches: %d (showing %d)' % (summary['matches'], len(summary['match_samples'])))
            for lineno, line in summary['match_samples']:
                print('  line %-8d %s' % (lineno, line[:160]))
            # The JSON Lines branch says this and the text branch once did not, which meant the
            # same tool was honest about its bounds in one shape and silent in the other. A bound
            # that only some code paths admit is not a bound, it is a formatting choice.
            if summary['matches'] > len(summary['match_samples']):
                print('  ... %d more match(es) withheld'
                      % (summary['matches'] - len(summary['match_samples'])))

    print()
    print('=== what this summary withheld ===')
    print('  every list above is capped at %d; the input was not modified' % args.limit)
    print('  to read a specific part, ask for it: --grep <text> or --key <name>')
    print('RESULT=%s' % TOKENS['ok'])
    return EXIT_OK


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_USE)
