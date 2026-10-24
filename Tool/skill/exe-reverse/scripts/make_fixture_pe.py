#!/usr/bin/env python3
"""Build a synthetic PE image for testing this skill's own tools, offline.

Why this exists: every parser and patcher in this repository needs something to run against,
and the two alternatives are both bad. Committing a real binary is a licensing and provenance
problem; downloading one makes the suite depend on the network and on a target that changes
underneath it. So the fixtures are *built*: deterministic, byte-for-byte reproducible, and
carrying deliberately awkward features so the tools are tested against the cases that break
naive implementations.

Design rule for this file: **every structure offset is computed, never estimated.** The
first version placed the debug directory at a hardcoded offset and overlapped the import
table -- a fixture defect that would have silently corrupted a test. The layout below is a
single cursor over one buffer, so an overlap is impossible, and every structure's offset is
asserted into the fixture metadata so a test can check it.

What the generated image contains, and why each part is there:

  * a DOS header with a stub and a non-default ``e_lfanew`` (0x80) -- a parser that assumes
    0x40 fails here instead of in the field
  * PE32 and PE32+ variants -- the optional-header field offsets differ, and reading the
    PE32+ layout from a PE32 file produces plausible nonsense
  * five sections, including a code section that is executable **and writable** (a protector
    signal) and an ``.rdata`` whose virtual size exceeds its raw size, so the zero-filled
    virtual-only tail with **no bytes on disk** is representable
  * an import table with a named import, an import by ordinal, and a descriptor terminator
  * an export directory with one named function
  * a resource directory with a real three-level tree (type -> name -> language -> data entry)
  * one relocation block
  * a TLS directory whose callback pointer is set, so "the entry point is too late" is
    representable
  * a debug directory carrying an RSDS/CodeView record and a fake PDB path
  * the plant sequence written **twice** into ``.text`` so a patch test has a target and an
    ambiguous-match test has one too
  * a correct PE checksum, computed with the same algorithm the reader verifies

The output is a **structurally valid PE image, not a runnable program**: there is no real
code, the entry point is a stub, and this tool does not claim it will load. That is the point
-- it is a fixture for parsers and patchers. A runnable test binary is a separate problem:
compile one with the local C toolchain.

Usage:
    python make_fixture_pe.py --out fixtures/sample64.exe
    python make_fixture_pe.py --out fixtures/sample32.exe --pe32
    python make_fixture_pe.py --out f.exe --recipe bare --json
    python make_fixture_pe.py --list-recipes

Exit codes: 0 = written, 2 = usage error.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
RSDS_GUID = bytes(range(16))
# A fixed timestamp keeps the fixture byte-reproducible across runs.
FIXED_TIMESTAMP = 0x5F5E1000

PLANT = bytes([0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x00,   # mov rax,[rip+0x332211]
               0x48, 0x85, 0xC0,                           # test rax,rax
               0x74, 0x05])                                # je +5
PLANT_OFFSET_IN_TEXT = 16


def align_up(value, alignment):
    return value if alignment <= 1 else (value + alignment - 1) // alignment * alignment


def pe_checksum(image):
    """Microsoft's algorithm: 16-bit words with end-around carry, plus the file length.

    The four CheckSum bytes participate as zero. Callers must zero the field first, or clear
    it, which is why this takes a bytearray and does not modify it.
    """
    total = 0
    limit = len(image) - (len(image) % 2)
    for i in range(0, limit, 2):
        total += image[i] | (image[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if len(image) % 2:
        total += image[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(image)) & 0xFFFFFFFF


class Layout(object):
    """A single cursor over one buffer. Offsets are allocated, never guessed."""

    def __init__(self, size):
        self.buf = bytearray(b'\x00' * size)
        self.cursor = 0
        self.offsets = {}

    def claim(self, name, length, fill=None):
        off = self.cursor
        if off + length > len(self.buf):
            raise ValueError('layout overflow: %s needs %d bytes at 0x%X but the buffer is %d'
                             % (name, length, off, len(self.buf)))
        self.offsets[name] = off
        if fill is not None:
            self.buf[off:off + length] = fill
        self.cursor = off + length
        return off

    def put(self, name, data):
        off = self.offsets[name]
        self.buf[off:off + len(data)] = data

    def pad_to(self, alignment):
        self.cursor = align_up(self.cursor, alignment)


def build_pe(pe32=False, section_align=SECTION_ALIGN, file_align=FILE_ALIGN, plant=None,
             with_tls=True, with_debug=True, with_resources=True, with_exports=True,
             entry_rva=0x1000, image_base=None, rdata_virtual_pad=0x400):
    """Return (image_bytes, metadata)."""
    if plant is None:
        plant = PLANT
    plant = bytes(plant)
    is64 = not pe32
    if image_base is None:
        image_base = 0x140000000 if is64 else 0x400000

    thunk = 8 if is64 else 4
    ordinal_flag = (1 << 63) if is64 else (1 << 31)
    pack_thunk = '<Q' if is64 else '<I'

    # ---- .text: the plant twice, plus a ret terminator -----------------------
    text = bytearray()
    text += b'\x90' * PLANT_OFFSET_IN_TEXT
    text += plant
    text += b'\xCC' * 8
    text += plant
    text += b'\xC3'
    text = text.ljust(0x400, b'\x90')

    # ---- .rdata: one computed layout for every structure ---------------------
    imp_dll = b'fixture-import.dll\x00'
    imp_fn = b'ImportedFunction\x00'
    exp_dll = b'fixture-export.dll\x00'
    exp_fn = b'ExportedFunction\x00'
    hint_name = struct.pack('<H', 7) + imp_fn
    if len(hint_name) % 2:
        hint_name += b'\x00'
    pdb_path = b'C:\\build\\fixture.pdb\x00'
    rsds = b'RSDS' + RSDS_GUID + struct.pack('<I', 1) + pdb_path
    rsds = rsds.ljust(align_up(len(rsds), 4), b'\x00')

    lay = Layout(0x800)
    lay.claim('ilt', (2 + 1) * thunk)
    lay.claim('iat', (2 + 1) * thunk)
    lay.claim('imp_desc', 40)
    lay.claim('hint_name', len(hint_name))
    lay.claim('imp_dll', len(imp_dll))
    if with_exports:
        lay.claim('exp_dir', 40)
        lay.claim('exp_funcs', 4)
        lay.claim('exp_names', 4)
        lay.claim('exp_ords', 2)
        lay.claim('exp_dll', len(exp_dll))
        lay.claim('exp_fn', len(exp_fn))
    if with_tls:
        lay.pad_to(8)
        lay.claim('tls_dir', 40)
        lay.claim('tls_cb', 2 * thunk)
    if with_debug:
        lay.pad_to(4)
        lay.claim('dbg_dir', 28)
        lay.claim('dbg_rsds', len(rsds))
    lay.pad_to(0x10)
    rdata_payload_len = lay.cursor
    # `Layout.claim` already refuses to overflow its buffer, so the only thing left to check is
    # that the structures fit before whatever virtual tail was requested. An earlier guard
    # compared the payload against the tail itself, which inverted the relationship and made the
    # `no-virtual-tail` recipe -- tail of zero -- impossible to build.
    if rdata_payload_len + rdata_virtual_pad > len(lay.buf):
        raise ValueError('the .rdata structures (%d bytes) plus a %d-byte virtual tail exceed '
                         'the reserved buffer (%d bytes)'
                         % (rdata_payload_len, rdata_virtual_pad, len(lay.buf)))

    # ---- section table and RVA assignment -----------------------------------
    sections = [
        {'name': '.text', 'payload': bytes(text), 'characteristics': 0xE0000020},
        # 0xE0000020 = CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE  (executable + writable:
        # a normal compiler emits 0x60000020; the W bit is a protector/packer signal the
        # fixture must be able to represent)
        {'name': '.rdata', 'payload': bytes(lay.buf[:rdata_payload_len + 0x20]),
         'characteristics': 0x40000040,
         'virtual_size': rdata_payload_len + 0x20 + rdata_virtual_pad},
        {'name': '.data', 'payload': b'FIXTURE\x00' + b'\x00' * 0x18, 'characteristics': 0xC0000040},
    ]
    rsrc_payload = bytearray(b'\x00' * 0x100)
    if with_resources:
        # type(16=VERSION) -> name(1) -> language(0x409) -> one data entry
        struct.pack_into('<IIHHHH', rsrc_payload, 0x00, 0, 0, 0, 0, 0, 1)
        struct.pack_into('<II', rsrc_payload, 0x10, 16, 0x80000000 | 0x20)
        struct.pack_into('<IIHHHH', rsrc_payload, 0x20, 0, 0, 0, 0, 0, 1)
        struct.pack_into('<II', rsrc_payload, 0x30, 1, 0x80000000 | 0x40)
        struct.pack_into('<IIHHHH', rsrc_payload, 0x40, 0, 0, 0, 0, 0, 1)
        struct.pack_into('<II', rsrc_payload, 0x50, 0x409, 0x60)
        # data entry: OffsetToData is an RVA, filled after RVAs are known
        struct.pack_into('<IIII', rsrc_payload, 0x60, 0, 4, 1200, 0)
    sections.append({'name': '.rsrc', 'payload': bytes(rsrc_payload),
                     'characteristics': 0x40000040})
    reloc_block = struct.pack('<II', 0x1000, 12) + struct.pack('<HH',
                                                               (3 << 12) | 0x010,
                                                               (10 << 12) | 0x020)
    sections.append({'name': '.reloc', 'payload': reloc_block.ljust(16, b'\x00'),
                     'characteristics': 0x42000040})

    num_sections = len(sections)
    opt_size = (112 if is64 else 96) + 16 * 8
    # The headers include the DOS header, the PE signature, the file header, the optional
    # header AND the section table. Omitting the section table (40 bytes per section) makes
    # SizeOfHeaders smaller than the real headers, and every section then claims a raw offset
    # that its bytes do not actually occupy -- which is exactly the class of defect this
    # fixture exists to expose, so it must not contain one itself.
    headers_size = 0x80 + 4 + 20 + opt_size + num_sections * 40
    size_of_headers = align_up(headers_size, file_align)
    assert size_of_headers >= headers_size

    cursor = size_of_headers
    for s in sections:
        s['raw_pointer'] = cursor
        s['raw_size'] = align_up(len(s['payload']), file_align)
        s.setdefault('virtual_size', len(s['payload']))
        cursor += s['raw_size']

    va = section_align
    for s in sections:
        s['rva'] = va
        va = align_up(va + max(s['virtual_size'], s['raw_size']), section_align)
    size_of_image = va

    by_name = {s['name']: s for s in sections}

    def srva(name, offset=0):
        return by_name[name]['rva'] + offset

    # ---- fill the structures now that RVAs exist ----------------------------
    base = by_name['.rdata']['rva']

    def r(nm):
        return base + lay.offsets[nm]

    lay.put('ilt', struct.pack(pack_thunk, r('hint_name')) +
            struct.pack(pack_thunk, ordinal_flag | 0x2A) +
            struct.pack(pack_thunk, 0))
    lay.put('iat', struct.pack(pack_thunk, r('hint_name')) +
            struct.pack(pack_thunk, ordinal_flag | 0x2A) +
            struct.pack(pack_thunk, 0))
    lay.put('imp_desc', struct.pack('<IIIII', 0, 0, 0, r('imp_dll'), r('iat')))
    lay.put('hint_name', hint_name)
    lay.put('imp_dll', imp_dll)
    if with_exports:
        lay.put('exp_dir', struct.pack('<IIHHIIIIIII',
                                       0, FIXED_TIMESTAMP, 0, 0,
                                       r('exp_dll'), 1, 1, 1,
                                       r('exp_funcs'), r('exp_names'), r('exp_ords')))
        lay.put('exp_funcs', struct.pack('<I', entry_rva))
        lay.put('exp_names', struct.pack('<I', r('exp_fn')))
        lay.put('exp_ords', struct.pack('<H', 0))
        lay.put('exp_dll', exp_dll)
        lay.put('exp_fn', exp_fn)
    if with_tls:
        lay.put('tls_dir', struct.pack('<QQQQII' if is64 else '<IIIIII',
                                       image_base, image_base, image_base,
                                       image_base + r('tls_cb'), 0, 0))
        lay.put('tls_cb', struct.pack(pack_thunk, image_base + entry_rva) +
                struct.pack(pack_thunk, 0))
    if with_debug:
        # IMAGE_DEBUG_DIRECTORY is 8 fields / 28 bytes, and the last one,
        # PointerToRawData, is a FILE OFFSET while AddressOfRawData is an RVA. Writing an
        # RVA into the pointer field is a real mistake this fixture would otherwise hide.
        dbg_foa = by_name['.rdata']['raw_pointer'] + lay.offsets['dbg_rsds']
        lay.put('dbg_dir', struct.pack('<IIHHIIII', 0, FIXED_TIMESTAMP, 0, 0, 2, len(rsds),
                                       r('dbg_rsds'), dbg_foa))
        lay.put('dbg_rsds', rsds)
    # Re-seat .rdata's payload now that the reserved regions are filled.
    by_name['.rdata']['payload'] = bytes(lay.buf[:len(by_name['.rdata']['payload'])])

    if with_resources:
        rsrc = bytearray(by_name['.rsrc']['payload'])
        struct.pack_into('<I', rsrc, 0x60, srva('.rsrc', 0x90))
        rsrc[0x90:0x94] = b'FIXT'
        by_name['.rsrc']['payload'] = bytes(rsrc)

    # ---- directories --------------------------------------------------------
    directories = [(0, 0)] * 16
    directories[1] = (r('imp_desc'), 40)
    if with_resources:
        directories[2] = (by_name['.rsrc']['rva'], 0x100)
    directories[5] = (by_name['.reloc']['rva'], 12)
    if with_debug:
        directories[6] = (r('dbg_dir'), 28)
    if with_tls:
        directories[9] = (r('tls_dir'), 40)
    if with_exports:
        directories[0] = (r('exp_dir'), 40)

    # ---- headers ------------------------------------------------------------
    dos = bytearray(b'\x00' * 0x80)
    dos[0:2] = b'MZ'
    dos[0x3C:0x40] = struct.pack('<I', 0x80)
    stub = (b'\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21'
            b'This program cannot be run in DOS mode.\r\r\n$')
    dos[0x40:0x40 + len(stub)] = stub

    file_header = struct.pack('<HHIIIHH',
                              0x8664 if is64 else 0x014C,
                              num_sections, FIXED_TIMESTAMP, 0, 0, opt_size,
                              0x0022)                    # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    common = struct.pack('<HBBIIIII', 0x20B if is64 else 0x10B, 14, 0,
                         0x400, 0x600, 0, entry_rva, 0x1000)
    if is64:
        optional = common + struct.pack('<Q', image_base)
    else:
        optional = common + struct.pack('<II', 0x2000, image_base)
    optional += struct.pack('<II', section_align, file_align)
    optional += struct.pack('<HHHHHH', 6, 0, 0, 0, 6, 0)
    optional += struct.pack('<I', 0)                     # Win32VersionValue
    optional += struct.pack('<III', size_of_image, size_of_headers, 0)
    optional += struct.pack('<HH', 3, 0x8160)   # CUI; HIGH_ENTROPY|DYNAMIC_BASE|NX|GUARD_CF
    optional += struct.pack('<QQQQ' if is64 else '<IIII', 0x100000, 0x1000, 0x100000, 0x1000)
    optional += struct.pack('<II', 0, 16)
    optional += b''.join(struct.pack('<II', a, b) for a, b in directories)
    assert len(optional) == opt_size, (len(optional), opt_size)

    section_table = b''
    for s in sections:
        section_table += struct.pack('<8sIIIIIIHHI',
                                     s['name'].encode('latin-1')[:8].ljust(8, b'\x00'),
                                     s['virtual_size'], s['rva'], s['raw_size'],
                                     s['raw_pointer'], 0, 0, 0, 0, s['characteristics'])

    image = bytearray()
    image += bytes(dos) + b'PE\x00\x00' + file_header + optional + section_table
    image += b'\x00' * (size_of_headers - len(image))
    for s in sections:
        payload = s['payload']
        image += payload + b'\x00' * (s['raw_size'] - len(payload))

    checksum_offset = 0x80 + 4 + 20 + 64
    image[checksum_offset:checksum_offset + 4] = b'\x00' * 4
    checksum = pe_checksum(image)
    struct.pack_into('<I', image, checksum_offset, checksum)

    plant_foa = by_name['.text']['raw_pointer'] + PLANT_OFFSET_IN_TEXT
    second_plant_foa = by_name['.text']['raw_pointer'] + PLANT_OFFSET_IN_TEXT + len(plant) + 8
    assert image[plant_foa:plant_foa + len(plant)] == plant
    assert image[second_plant_foa:second_plant_foa + len(plant)] == plant

    meta = {
        'size': len(image),
        'sha256': hashlib.sha256(bytes(image)).hexdigest(),
        'pe32_plus': is64,
        'machine': hex(0x8664 if is64 else 0x014C),
        'entry_rva': hex(entry_rva),
        'image_base': hex(image_base),
        'size_of_image': size_of_image,
        'size_of_headers': size_of_headers,
        'section_alignment': hex(section_align),
        'file_alignment': hex(file_align),
        'checksum': hex(checksum),
        'checksum_offset': hex(checksum_offset),
        'sections': {s['name']: {'rva': hex(s['rva']), 'raw_pointer': hex(s['raw_pointer']),
                                 'raw_size': s['raw_size'], 'virtual_size': s['virtual_size'],
                                 'characteristics': hex(s['characteristics'])}
                     for s in sections},
        'rdata_structure_rvas': {k: hex(base + v) for k, v in sorted(lay.offsets.items())},
        'plant': {
            'bytes': ' '.join('%02X' % b for b in plant),
            'length': len(plant),
            'first_file_offset': hex(plant_foa),
            'first_rva': hex(by_name['.text']['rva'] + PLANT_OFFSET_IN_TEXT),
            'second_file_offset': hex(second_plant_foa),
            'second_rva': hex(by_name['.text']['rva'] + PLANT_OFFSET_IN_TEXT + len(plant) + 8),
            'note': 'planted twice on purpose: a patch test wants one site, an '
                    'ambiguous-pattern test wants two',
        },
        'import_descriptor_rva': hex(directories[1][0]),
        'import_dll': imp_dll.rstrip(b'\x00').decode(),
        'import_named': imp_fn.rstrip(b'\x00').decode(),
        'import_ordinal': hex(0x2A),
        'export_dir_rva': hex(directories[0][0]) if with_exports else None,
        'export_name': exp_fn.rstrip(b'\x00').decode() if with_exports else None,
        'resource_dir_rva': hex(directories[2][0]) if with_resources else None,
        'tls_directory_rva': hex(directories[9][0]) if with_tls else None,
        'tls_callback_rva': hex(r('tls_cb')) if with_tls else None,
        'debug_directory_rva': hex(directories[6][0]) if with_debug else None,
        'pdb_path': pdb_path.rstrip(b'\x00').decode() if with_debug else None,
        'reloc_block_rva': hex(directories[5][0]),
        'executable_and_writable_code': True,
        'virtual_only_tail_bytes': rdata_virtual_pad,
        'note': ('structurally valid PE image for parser and patcher tests. NOT a runnable '
                 'program: the entry point is a stub and no real code is present'),
    }
    return bytes(image), meta


RECIPES = {
    'default': {},
    'pe32': {'pe32': True},
    'fat-align': {'section_align': 0x2000, 'file_align': 0x1000},
    'thin-align': {'section_align': 0x1000, 'file_align': 0x200},
    'bare': {'with_tls': False, 'with_debug': False, 'with_resources': False,
             'with_exports': False},
    'no-virtual-tail': {'rdata_virtual_pad': 0},
}


def main():
    ap = argparse.ArgumentParser(
        description="Build a synthetic PE image for offline testing of this skill's tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='The output parses as a PE and is safe to patch; it is not a runnable program.')
    ap.add_argument('--out', help='path to write')
    ap.add_argument('--pe32', action='store_true', help='emit PE32 instead of PE32+')
    ap.add_argument('--section-align', type=lambda v: int(v, 0))
    ap.add_argument('--file-align', type=lambda v: int(v, 0))
    ap.add_argument('--recipe', choices=sorted(RECIPES), help='a named fixture shape')
    ap.add_argument('--list-recipes', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.list_recipes:
        for name, kw in sorted(RECIPES.items()):
            print('  %-16s %s' % (name, kw or '(defaults)'))
        return 0
    if not args.out:
        ap.error('--out is required (or use --list-recipes)')

    kw = dict(RECIPES.get(args.recipe or 'default', {}))
    if args.pe32:
        kw['pe32'] = True
    if args.section_align:
        kw['section_align'] = args.section_align
    if args.file_align:
        kw['file_align'] = args.file_align

    data, meta = build_pe(**kw)
    out = os.path.abspath(args.out)
    if os.path.dirname(out):
        os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'wb') as fh:
        fh.write(data)

    if args.json:
        print(json.dumps(dict(meta, path=out), indent=2))
        return 0
    print('wrote %s (%d bytes)' % (out, len(data)))
    print('  sha256        %s' % meta['sha256'])
    print('  arch          %s' % ('PE32+' if meta['pe32_plus'] else 'PE32'))
    print('  entry rva     %s   image base %s' % (meta['entry_rva'], meta['image_base']))
    print('  checksum      %s' % meta['checksum'])
    print('  sections')
    for name, s in meta['sections'].items():
        print('    %-8s rva=%-9s raw=%-9s rsize=%-6d vsize=%-6d chars=%s'
              % (name, s['rva'], s['raw_pointer'], s['raw_size'], s['virtual_size'],
                 s['characteristics']))
    print('  plant         %s' % meta['plant']['bytes'])
    print('    first  file %s / rva %s' % (meta['plant']['first_file_offset'],
                                           meta['plant']['first_rva']))
    print('    second file %s / rva %s' % (meta['plant']['second_file_offset'],
                                           meta['plant']['second_rva']))
    print('  imports       %s (%s, ordinal %s)'
          % (meta['import_dll'], meta['import_named'], meta['import_ordinal']))
    if meta['export_dir_rva']:
        print('  exports       %s' % meta['export_name'])
    print('  tls callback  %s' % meta['tls_callback_rva'])
    print('  pdb           %s' % meta['pdb_path'])
    print('  note          %s' % meta['note'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
