#!/usr/bin/env python3
"""capability: static_disassembly

Recover string literals from a Dart AOT snapshot (the `app.so` of a Flutter application).

WHY THIS EXISTS
---------------
A release build of a Flutter application compiles its Dart into an **ELF shared object** named
`app.so`, even on Windows. That image is not a PE, so every other script in this kit refuses it
and the usual first move -- "look at the imports, then the strings" -- has no tool behind it. The
image is also stripped: `app.so` carries no useful symbol table and its unwinding table is a stub,
so the only way in is through the data the code must reference, and a string literal survives both
AOT compilation and minification.

WHAT THIS DELIBERATELY DOES NOT DO, AND WHY
-------------------------------------------
It does not locate the code that references a literal, and the reason is a **withdrawn
measurement** rather than a scope choice. An earlier version scanned `.text` for instruction shapes
by byte pattern and reported counts -- a load through a register-held base appearing 110,641 times,
a self-relative load appearing 5 times -- and built a mechanism on them. A real disassembler
disproves it: byte patterns over variable-length code match *inside* operands and inside data, the
ELF entry point here is 0 because the artifact is a shared object, and `.text` opens on zero
padding, so there is no valid address to sweep from. Decoded at real boundaries, the writes to that
register number **zero**.

The counts are gone, the mechanism claim is gone, and what remains is what can be verified without
instruction boundaries: printable runs with their offsets, and the section layout. Locating the
sites that use a literal needs the snapshot's own layout parsed, which needs tooling built for the
exact release that produced the file. See `flutter-and-dart-aot.md` for the full account, including
why the wrong model was convincing.

So the reference path runs through Dart's **object pool**, reached with a register-held base, and
a scan for self-relative address loads finds nothing. Reporting "0 references" from such a scan
would be a wrong answer dressed as a negative one, which is the failure this kit is organised
against. Locating the sites that use a literal needs the pool structure parsed, and that needs the
version-matched snapshot tooling (`blutter` or an equivalent) built for the exact Dart release that
produced the file. This script tells you what is in the snapshot and stops there.

The pool mechanism is still reported, as counts, because those counts are the evidence for the
paragraph above and they tell a reader immediately which family of image they are looking at.

Usage
-----
    python dart_snapshot_strings.py app.so --find premium
    python dart_snapshot_strings.py app.so --find premium,license,vip --min-length 6
    python dart_snapshot_strings.py app.so --list --min-length 8 --limit 200
    python dart_snapshot_strings.py app.so --at 0x544550
    python dart_snapshot_strings.py app.so --json --find premium

Exit codes: 0 = ran, 1 = nothing matched the requested filter, 2 = usage error,
3 = the input is not an ELF image.
"""
import argparse
import json
import struct
import sys

PRINTABLE = set(range(0x20, 0x7F))
ELF_MAGIC = b'\x7fELF'
# x86-64 RIP-relative addressing: REX(48-4F) then an opcode that takes a memory operand, then a
# ModRM byte whose low three bits are 101 and whose top two bits are 00.
RIPREL_OPS = (0x8D, 0x8B, 0x8C, 0x89, 0x88, 0x8A, 0x03, 0x01, 0x3B, 0x39, 0xC7, 0xFF, 0xBE,
              0xB6, 0xBF, 0xB7)


class Elf(object):
    """Minimal ELF64 reader: section headers, names, and a vaddr/file-offset map."""

    def __init__(self, data, path=None):
        self.d = data
        self.path = path
        if len(data) < 0x40 or data[:4] != ELF_MAGIC:
            raise ValueError('not an ELF image (magic %r)' % data[:4])
        if data[4] != 2:
            raise ValueError('not a 64-bit ELF (class %d)' % data[4])
        if data[5] != 1:
            raise ValueError('not little-endian (data encoding %d)' % data[5])
        self.machine = struct.unpack_from('<H', data, 18)[0]
        self.etype = struct.unpack_from('<H', data, 16)[0]
        e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
        e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
        e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]

        self.sections = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if off + 64 > len(data):
                break
            (name, typ, flags, addr, offset, size,
             _link, _info, _align, _entsize) = struct.unpack_from('<IIQQQQIIQQ', data, off)
            self.sections.append({'name_off': name, 'type': typ, 'flags': flags,
                                  'vaddr': addr, 'offset': offset, 'size': size})
        self.strtab = b''
        if e_shstrndx < len(self.sections):
            s = self.sections[e_shstrndx]
            self.strtab = data[s['offset']:s['offset'] + s['size']]
        for s in self.sections:
            s['name'] = self._name(s['name_off'])

    def _name(self, off):
        end = self.strtab.find(b'\x00', off)
        if end < 0:
            return ''
        return self.strtab[off:end].decode('latin-1', 'replace')

    def section(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def vaddr_to_offset(self, va):
        for s in self.sections:
            if s['type'] != 8 and s['vaddr'] <= va < s['vaddr'] + s['size']:
                return s['offset'] + (va - s['vaddr'])
        return None

    def offset_to_vaddr(self, off):
        for s in self.sections:
            if s['type'] != 8 and s['offset'] <= off < s['offset'] + s['size']:
                return s['vaddr'] + (off - s['offset'])
        return None

    def describe(self):
        return {
            'machine': 'x86-64' if self.machine == 0x3E else 'machine_0x%04X' % self.machine,
            'type': {1: 'relocatable', 2: 'executable', 3: 'shared-object'}.get(
                self.etype, str(self.etype)),
            'sections': [{'name': s['name'], 'vaddr': hex(s['vaddr']),
                          'offset': hex(s['offset']), 'size': s['size']}
                         for s in self.sections if s['size']],
        }


def recover_strings(data, sec, min_length=6, limit=4000):
    """Literals inside one section, as (offset, vaddr, text, encoding).

    Both encodings are recovered because Dart's snapshot carries a one-byte form for Latin text
    and a two-byte form for everything else, and a keyword search that only reads ASCII misses
    half the literals in a localised application.

    A run of printable bytes is a *candidate*: there is no framing to verify it against without
    the version-matched snapshot tooling, so the caller gets offsets rather than an interpretation.
    """
    base = sec['offset']
    end = min(len(data), sec['offset'] + sec['size'])
    out = []

    # one-byte (ASCII) runs
    ascii_spans = []
    i = base
    while i < end and len(out) < limit:
        if data[i] in PRINTABLE:
            j = i
            while j < end and data[j] in PRINTABLE:
                j += 1
            if j - i >= min_length:
                out.append((i, sec['vaddr'] + (i - base),
                            data[i:j].decode('latin-1'), 'one-byte'))
                ascii_spans.append((i, j))
            i = j
        else:
            i += 1

    def inside_ascii(pos):
        return any(lo <= pos < hi for lo, hi in ascii_spans)

    # two-byte (UTF-16LE) runs. Two properties have to hold at once and neither can be read from
    # the two bytes alone:
    #
    #   * the scan must advance **one byte at a time**. Stepping by two from the section base locks
    #     the phase to that base, so a run shifted to an odd offset -- which one odd-length literal
    #     is enough to do -- is never examined and is missed whole.
    #   * a candidate must not sit **inside a one-byte run**. An ASCII literal of even length ends
    #     with a printable character followed by its alignment byte, which is exactly the shape of a
    #     UTF-16 character: without this check the tail of "even_phase_liter" starts a run that reads
    #     as "rvip_pass", a literal that does not exist, while the real run that follows it is
    #     skipped as an interior position. Both of those were measured on a synthetic fixture.
    i = base
    while i < end - 1 and len(out) < limit:
        if data[i] in PRINTABLE and data[i + 1] == 0 and not inside_ascii(i):
            j = i
            chars = []
            while j < end - 1 and data[j] in PRINTABLE and data[j + 1] == 0:
                chars.append(chr(data[j]))
                j += 2
            if len(chars) >= min_length:
                out.append((i, sec['vaddr'] + (i - base), ''.join(chars), 'two-byte'))
            i = j
        else:
            i += 1
    return out


def section_shape(elf):
    """The section layout, which is how this family of image is identified.

    This replaced an instruction-count observation that has been withdrawn. The earlier version
    scanned `.text` for `[r15 + disp]` shapes by byte pattern and reported large counts, then used
    those counts as evidence for how the snapshot reaches its data. A real disassembler shows the
    counts were artifacts: byte patterns match inside operands and inside data, and on this artifact
    the ELF entry point is 0 with `.text` opening on zero padding, so there is no valid address to
    sweep from. Reporting a wrong mechanism confidently was worse than reporting nothing, so the
    measurement is gone and the shape it was standing in front of is reported instead.
    """
    return [{'name': s['name'], 'vaddr': hex(s['vaddr']), 'size': s['size']}
            for s in elf.sections if s['size']]


def main():
    ap = argparse.ArgumentParser(
        description='Recover string literals from a Dart AOT snapshot (the app.so of a Flutter '
                    'application) and find the code that references them.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='The reference scan decodes x86-64 RIP-relative loads, so it reports addresses '
               'rather than function names: a stripped snapshot has none.')
    ap.add_argument('image', help='the Dart AOT snapshot (an ELF shared object named app.so)')
    ap.add_argument('--find', help='comma-separated keywords; only matching literals are reported')
    ap.add_argument('--at', help='report the literal containing this file offset or vaddr')
    ap.add_argument('--min-length', type=int, default=6)
    ap.add_argument('--limit', type=int, default=4000, help='cap literals recovered per section')
    ap.add_argument('--sections', nargs='*', default=['.rodata', '.data', '.data.rel.ro'],
                    help='sections to search for literals')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    try:
        data = open(args.image, 'rb').read()
    except OSError as exc:
        sys.stderr.write('error: %s\n' % exc)
        return 2
    try:
        elf = Elf(data, args.image)
    except ValueError as exc:
        sys.stderr.write('error: %s: %s\n' % (args.image, exc))
        return 3

    text = elf.section('.text')
    if text is None:
        sys.stderr.write('error: no .text section; this is not an AOT code image\n')
        return 3

    literals = []
    for name in args.sections:
        sec = elf.section(name)
        if sec and sec['size']:
            literals.extend(recover_strings(data, sec, args.min_length, args.limit))

    keywords = [k.strip().lower() for k in args.find.split(',')] if args.find else []
    if keywords:
        literals = [lit for lit in literals
                    if any(k in lit[2].lower() for k in keywords)]

    if args.at:
        want = int(str(args.at), 0)
        if want > len(data):                        # given as a vaddr
            off = elf.vaddr_to_offset(want)
            want = off if off is not None else want

        def byte_length(lit):
            # A two-byte literal occupies two bytes per character, so `len(text)` covered only the
            # first half of it and an offset in the second half was reported as a miss.
            return len(lit[2]) * (2 if lit[3] == 'two-byte' else 1)

        literals = [lit for lit in literals if lit[0] <= want < lit[0] + byte_length(lit)]

    report = {'image': args.image, 'elf': elf.describe(),
              'literals_recovered': len(literals),
              'section_shape': section_shape(elf), 'matches': []}

    for off, va, text_value, enc in literals[:args.limit]:
        report['matches'].append({'offset': hex(off), 'vaddr': hex(va),
                                  'text': text_value, 'encoding': enc})

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
        # The exit code means the same thing in both output modes. It used to return 0 here and 1
        # from the text path for the identical run, so a script that asked for JSON could not tell
        # a filter that matched from one that did not.
        filtered = bool(args.find or args.at)
        return 0 if report['matches'] or not filtered else 1

    e = report['elf']
    print('%s' % args.image)
    print('  %s, %s, %d section(s) with content' % (e['machine'], e['type'],
                                                    len(e['sections'])))
    print('  literals recovered  : %d   (>= %d chars, sections: %s)'
          % (len(literals), args.min_length, ', '.join(args.sections)))
    print()
    for entry in report['matches']:
        print('  %s  [%s]  %s' % (entry['vaddr'], entry['encoding'], entry['text'][:110]))
    print('\n%d literal(s) reported.' % len(report['matches']))
    return 0 if report['matches'] else 1


if __name__ == '__main__':
    sys.exit(main())
