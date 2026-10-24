#!/usr/bin/env python3
"""Apply byte patches to a PE image, with the discipline the task demands built in.

Why a purpose-built patcher instead of a hex editor: the failures that cost the most in
binary patching are not "I could not find the byte". They are:

  * patching a copy of a copy, so the original baseline is gone;
  * a patch that silently changed a *different* occurrence than the one intended;
  * a length change that shifted every later offset, invalidating the section table,
    the relocation table and the security directory at once;
  * a patch that landed in the file but is never reached at run time;
  * the file checksum no longer matching, which some loaders and installers check.

Each of those is a rule here rather than a caution in prose:

  - the input file is opened read-only and never written; output is a new file;
  - every patch has a *site* (RVA or file offset) or a *pattern*, and a pattern must match
    exactly once unless `--index` selects a specific hit;
  - a patch whose replacement is a different length than the original is refused unless
    `--allow-resize` is given, and then it is reported as a structural change;
  - `--expect` pins the bytes you believe are there, so a moved target fails loudly;
  - after writing, the output is re-parsed and every patched byte is re-read and compared;
  - the PE checksum is recomputed (Microsoft's algorithm) and the Authenticode state is
    reported, because editing an image invalidates a signature over it.

Usage:
    python pepatch.py <input-pe> --spec patches.json --out patched.exe [--dry-run]
    python pepatch.py <input-pe> --at-rva 0x1234 --bytes 9090 --out patched.exe --dry-run
    python pepatch.py <input-pe> --pattern "48 8B ?? ?? E8" --bytes 9090909090 --at-hit 0 --out p.exe

Spec file shape (JSON):
    {"patches": [
       {"name": "gate 1", "rva": "0x2a10", "expect": "74 0A", "bytes": "EB 0A",
        "why": "invert the branch, keeps the taken distance"},
       {"name": "site 2", "pattern": "E8 ?? ?? ?? ?? 85 C0 74", "pattern-offset": 5,
        "bytes": "75", "expect": "74"}
    ]}

Exit codes: 0 = all patches applied and verified, 1 = a patch failed to apply or verify,
2 = usage error, 3 = the input is not a parseable PE.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from peutil import PE, ParseError                      # noqa: E402


# --- pattern handling ---------------------------------------------------------
def parse_bytes(text):
    """'48 8B ?? E8' or '488BE8' -> (list[int|None], original_tokens)."""
    if text is None:
        return [], []
    text = text.strip()
    if not text:
        return [], []
    tokens = text.replace(',', ' ').split()
    if len(tokens) == 1 and len(text) >= 2 and '?' not in text:
        tokens = [text[i:i + 2] for i in range(0, len(text), 2)]
    out = []
    for tok in tokens:
        tok = tok.strip()
        if tok in ('??', '?', '**', 'xx', 'XX'):
            out.append(None)
        else:
            if tok.lower().startswith('0x'):
                tok = tok[2:]
            if len(tok) != 2 or any(c not in '0123456789abcdefABCDEF' for c in tok):
                raise ValueError('not a byte: %r' % tok)
            out.append(int(tok, 16))
    return out, tokens


def find_pattern(data, pattern, start=0, limit=64):
    """Every file offset where `pattern` matches. None entries are wildcards."""
    if not pattern or all(p is None for p in pattern):
        raise ValueError('pattern is empty or entirely wildcards')
    hits = []
    n = len(pattern)
    first = next((i for i, p in enumerate(pattern) if p is not None), 0)
    needle = pattern[first]
    pos = start
    while True:
        pos = data.find(bytes([needle]), pos)
        if pos < 0:
            break
        base = pos - first
        if base >= 0 and base + n <= len(data):
            if all(p is None or data[base + i] == p for i, p in enumerate(pattern)):
                hits.append(base)
                if len(hits) >= limit:
                    break
        pos += 1
    return hits


def length_mark(a):
    """Three-state marker: an unproven length is not the same as a proven change."""
    if a['equal_length'] is True:
        return ''
    if a['equal_length'] is False:
        return '  [LENGTH CHANGE]'
    return '  [length unproven: pass expect or original-length]'


def fmt_bytes(data):
    return ' '.join('%02X' % b for b in data)


# --- patch resolution ---------------------------------------------------------
class PatchError(Exception):
    pass


def resolve(spec, pe, data, index_default=0):
    """Resolve one spec entry to (offset, original_span, replacement, declared_length).

    `declared_length` is the number of bytes the site is *believed* to occupy. It comes from
    `expect` (the bytes you assert are there) or from an explicit `original-length`, and it is
    the only basis on which this script can claim a patch is equal-length. Without one, the
    honest answer is "unknown": deciding an instruction's length requires a disassembler, and
    guessing it is how a length change slips through unnoticed.
    """
    where = spec.get('offset')
    rva = spec.get('rva')
    pattern = spec.get('pattern')
    body, _ = parse_bytes(spec.get('bytes'))
    if not body or any(b is None for b in body):
        raise PatchError('patch %r has no concrete replacement bytes' % spec.get('name', '?'))

    declared = None
    if spec.get('original-length') is not None:
        try:
            declared = int(str(spec['original-length']), 0)
        except ValueError:
            raise PatchError('original-length %r is not an integer'
                             % spec['original-length'])
        if declared <= 0:
            raise PatchError('original-length must be positive')
    elif spec.get('expect'):
        declared = len(parse_bytes(spec['expect'])[0])

    if pattern:
        pat, _ = parse_bytes(pattern)
        hits = find_pattern(data, pat)
        if not hits:
            raise PatchError('pattern %r matched nothing' % pattern)
        want = spec.get('index', index_default)
        if len(hits) > 1 and 'index' not in spec and not spec.get('allow-many'):
            preview = ', '.join('%s%s' % (hex(h), ' (rva %s)' % hex(pe.offset_to_rva(h) or 0))
                                for h in hits[:6])
            raise PatchError('pattern %r matched %d sites (%s%s); pass "index" to choose one, '
                             '"allow-many": true to accept all, or make the pattern longer '
                             'with surrounding context'
                             % (pattern, len(hits), preview,
                                ', ...' if len(hits) > 6 else ''))
        if want >= len(hits):
            raise PatchError('index %d out of range (%d hits)' % (want, len(hits)))
        off = hits[want]
        po = spec.get('pattern-offset', 0)
        off += int(po)
    elif rva is not None:
        off = pe.rva_to_offset(int(str(rva), 0))
        if off is None:
            raise PatchError('rva %s maps to no file offset (virtual-only or outside '
                             'any section)' % rva)
    elif where is not None:
        off = int(str(where), 0)
    else:
        raise PatchError('patch %r has none of pattern/rva/offset' % spec.get('name', '?'))

    if off < 0:
        raise PatchError('patch offset must not be negative')
    span = max(len(body), declared or 0)
    if off + span > len(data):
        raise PatchError('patch at 0x%X (span %d bytes) runs past end of file (%d bytes)'
                         % (off, span, len(data)))
    original = bytes(data[off:off + span])
    return off, original, body, declared


def apply_one(spec, pe, data, allow_resize=False):
    off, original, body, declared = resolve(spec, pe, data)
    expect = spec.get('expect')
    if expect:
        exp, _ = parse_bytes(expect)
        got = original[:len(exp)]
        if not all(e is None or e == g for e, g in zip(exp, got)):
            raise PatchError('expect %s but found %s at 0x%X -- the site moved or the wrong '
                             'binary is open' % (fmt_bytes([e if e is not None else 0
                                                            for e in exp]),
                                                 fmt_bytes(got), off))
    if declared is None:
        equal = None
        basis = 'unknown (no expect/original-length given)'
    else:
        equal = (declared == len(body))
        basis = 'expect' if expect else 'original-length'
    if equal is False and not allow_resize:
        raise PatchError('replacement is %d bytes over a site declared as %d bytes at 0x%X; '
                         'a length change moves every later offset in the file and can '
                         'invalidate the section table, the relocations and the security '
                         'directory at once. Rewrite it at equal length, or pass '
                         '--allow-resize and treat the result as a structural edit'
                         % (len(body), declared, off))
    return {'name': spec.get('name') or 'patch', 'offset': off,
            'rva': hex(pe.offset_to_rva(off) or 0),
            'before': fmt_bytes(original), 'after': fmt_bytes(body),
            'declared_length': declared, 'length_basis': basis,
            'equal_length': equal,
            'why': spec.get('why')}


def verify(pe_path, applied):
    """Re-open the written file and prove each patched byte is really there."""
    pe = PE(open(pe_path, 'rb').read(), pe_path)
    with open(pe_path, 'rb') as fh:
        data = fh.read()
    problems = []
    for a in applied:
        want, _ = parse_bytes(a['after'])
        got = data[a['offset']:a['offset'] + len(want)]
        if list(got) != want:
            problems.append('%s: at 0x%X expected %s, file has %s'
                            % (a['name'], a['offset'], fmt_bytes(want), fmt_bytes(got)))
    return pe, problems


def main():
    ap = argparse.ArgumentParser(
        description='Apply verified, equal-length byte patches to a PE image.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='The input file is never modified. Output is written to --out.')
    ap.add_argument('pe', help='input PE file (opened read-only)')
    ap.add_argument('--out', help='output file (required unless --dry-run with no --out)')
    ap.add_argument('--spec', help='JSON patch spec, {"patches":[...]}')
    ap.add_argument('--pattern', help='single-patch mode: a byte pattern to locate')
    ap.add_argument('--pattern-offset', type=int, default=0,
                    help='offset added to a --pattern match (e.g. 5 to reach a branch)')
    ap.add_argument('--at-rva', help='single-patch mode: patch at an RVA')
    ap.add_argument('--at-offset', help='single-patch mode: patch at a file offset')
    ap.add_argument('--bytes', help='replacement bytes, e.g. "EB 0A" or E B0A')
    ap.add_argument('--expect', help='bytes you believe are at the site; mismatch aborts, and '
                                     'its length becomes the equal-length reference')
    ap.add_argument('--original-length', type=int, default=None,
                    help='declared byte length of the site, when you have no byte-level expect')
    ap.add_argument('--at-hit', type=int, default=None,
                    help='which pattern hit to patch. Omit it and a pattern that matches more '
                         'than once is refused rather than silently taking the first match')
    ap.add_argument('--allow-resize', action='store_true',
                    help='permit a length change (structural: offsets shift)')
    ap.add_argument('--no-checksum', action='store_true',
                    help='do not recompute the PE checksum')
    ap.add_argument('--dry-run', action='store_true', help='resolve and report, write nothing')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.pe):
        sys.stderr.write('error: %s is not a file\n' % args.pe)
        return 2
    try:
        with open(args.pe, 'rb') as fh:
            data = bytearray(fh.read())
        pe = PE(bytes(data), args.pe)
    except (ParseError, OSError) as exc:
        sys.stderr.write('error: not a parseable PE: %s\n' % exc)
        return 3

    specs = []
    if args.spec:
        if not os.path.isfile(args.spec):
            sys.stderr.write('error: --spec %s is not a readable file\n' % args.spec)
            return 2
        try:
            with open(args.spec, encoding='utf-8') as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            sys.stderr.write('error: --spec %s could not be parsed as JSON: %s\n'
                             % (args.spec, exc))
            return 2
        if not isinstance(doc, dict):
            sys.stderr.write('error: --spec must hold an object with a "patches" array, '
                             'not a bare %s\n' % type(doc).__name__)
            return 2
        specs = doc.get('patches', [])
        if not specs:
            sys.stderr.write('error: %s has no "patches" array\n' % args.spec)
            return 2
    elif args.bytes and (args.pattern or args.at_rva or args.at_offset):
        one = {'name': 'cli', 'bytes': args.bytes}
        if args.pattern:
            one['pattern'] = args.pattern
            one['pattern-offset'] = args.pattern_offset
            # Only carry an index when the caller actually chose one: a default of 0 would
            # count as an explicit choice and silently defeat the ambiguity guard.
            if args.at_hit is not None:
                one['index'] = args.at_hit
        if args.at_rva:
            one['rva'] = args.at_rva
        if args.at_offset:
            one['offset'] = args.at_offset
        if args.expect:
            one['expect'] = args.expect
        if args.original_length is not None:
            one['original-length'] = args.original_length
        specs = [one]
    else:
        sys.stderr.write('error: give --spec, or --bytes together with '
                         '--pattern/--at-rva/--at-offset\n')
        return 2

    if args.allow_resize and len(specs) > 1:
        sys.stderr.write('error: --allow-resize changes the length of the file, which moves '
                         'every offset after the site. With more than one patch, the later '
                         "patches' offsets no longer mean what they did when they were "
                         'resolved, and a patch would land somewhere unintended. Apply a '
                         'resizing edit on its own, or make every patch equal-length.\n')
        return 2

    src_sha = hashlib.sha256(bytes(data)).hexdigest()
    applied = []
    errors = []
    for spec in specs:
        try:
            a = apply_one(spec, pe, bytes(data), allow_resize=args.allow_resize)
        except (PatchError, ValueError) as exc:
            errors.append('%s: %s' % (spec.get('name', '?'), exc))
            continue
        applied.append(a)
        new, _ = parse_bytes(a['after'])
        # Replace the *declared* span, not the replacement's own length. Slicing by the
        # replacement's length is what made an earlier version's resize a no-op: the assignment
        # wrote exactly as many bytes as it read, so a shorter replacement left the tail of the
        # site in place and a longer one overwrote whatever followed it -- neither of which is a
        # length change, and the second of which is silent corruption.
        span = a['declared_length'] if a['declared_length'] else len(new)
        data[a['offset']:a['offset'] + span] = bytes(new)

    changed_checksum = False
    if applied and not args.no_checksum and not args.dry_run:
        field = pe.optional_offset + 64
        data[field:field + 4] = b'\0\0\0\0'
        tmp = PE(bytes(data), args.pe)
        new_sum = tmp.computed_checksum() or 0
        import struct
        data[field:field + 4] = struct.pack('<I', new_sum)
        changed_checksum = True

    result = {
        'input': args.pe, 'input_sha256': src_sha, 'input_size': len(bytearray(open(
            args.pe, 'rb').read())),
        'patches_requested': len(specs), 'patches_applied': len(applied),
        'applied': applied, 'errors': errors,
        'resolved_in_rva': None, 'dry_run': args.dry_run,
        'checksum_recomputed': changed_checksum,
        'signed_input': pe.is_signed,
        'signature_note': ('this input carries an Authenticode blob; editing any byte '
                           'outside it invalidates that signature') if pe.is_signed else None,
    }

    if args.dry_run or not args.out:
        if not args.out and not args.dry_run and applied:
            sys.stderr.write('error: --out is required to write a patched file\n')
            return 2
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print('dry run over %s (%s)' % (args.pe, src_sha[:16]))
            for a in applied:
                print('  would patch %-18s at 0x%-8X %s -> %s%s'
                      % (a['name'], a['offset'], a['before'], a['after'], length_mark(a)))
            for e in errors:
                print('  FAIL %s' % e)
        return 1 if errors else 0

    if errors:
        sys.stderr.write('error: refusing to write an output with failed patches:\n')
        for e in errors:
            sys.stderr.write('  %s\n' % e)
        return 1

    with open(args.out, 'wb') as fh:
        fh.write(bytes(data))
    with open(args.out, 'rb') as fh:
        out_data = fh.read()

    pe_out, problems = verify(args.out, applied)
    result['output'] = args.out
    result['output_sha256'] = hashlib.sha256(out_data).hexdigest()
    result['output_size'] = len(out_data)
    result['verify_problems'] = problems
    result['checksum_after'] = {'declared': hex(pe_out.checksum),
                                'computed': hex(pe_out.computed_checksum() or 0),
                                'matches': pe_out.checksum_ok()}
    result['structural'] = [a['name'] for a in applied if a['equal_length'] is False]
    result['length_unproven'] = [a['name'] for a in applied if a['equal_length'] is None]

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('patched %s -> %s' % (args.pe, args.out))
        print('  input  sha256 %s' % src_sha)
        print('  output sha256 %s' % result['output_sha256'])
        for a in applied:
            print('  %-18s 0x%-8X %s -> %s%s'
                  % (a['name'], a['offset'], a['before'], a['after'], length_mark(a)))
        print('  checksum  %s' % ('recomputed' if changed_checksum else 'left as-is'))
        if pe_out.is_signed:
            print('  signature : Authenticode blob present -- it is now invalid')
        if problems:
            print('  VERIFY FAILED')
            for p in problems:
                print('    %s' % p)
            return 1
        print('  verified  : every patched byte re-read from the written file')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
