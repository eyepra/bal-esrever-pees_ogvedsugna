#!/usr/bin/env python3
"""Dependency-free PE (Portable Executable) reader for Windows x86/x64 images.

Why this exists rather than "just use pefile": every other script in this skill needs
to agree on *one* interpretation of a header field, and a reader you can read is the only
way to debug the case where two tools disagree about the same binary. It has no third-party
imports, so it runs on a bare Python 3.9+ install and inside a locked-down analysis VM.

What it parses:
  * DOS header, DOS stub, Rich Header (the MSVC toolchain fingerprint)
  * NT file header, optional header (PE32 and PE32+), data directories
  * section table, plus RVA <-> file-offset translation in both directions
  * import descriptors and their thunks (by name and by ordinal)
  * delay-load imports, exports (named and forwarded)
  * resources (type/name/language tree walk)
  * base relocations, TLS callbacks, debug directory (CodeView/PDB), load config
  * the Authenticode certificate table location, and the file checksum Microsoft's
    own algorithm would compute
  * per-section Shannon entropy (a shell heuristic, not a verdict)

What it deliberately does not do: disassemble, decompile, follow a packer, or repair a
damaged image. Attach a disassembler (or a debugger) for those; this file exists so the
decision *about* those tools is made from measured header facts.

Usage:
    python peutil.py <pe-file> [--json] [--sections] [--imports] [--exports]
                              [--resources] [--rich] [--tls] [--debug] [--relocs]
                              [--entropy] [--check-sum] [--summary]

Exit codes: 0 = parsed, 1 = not a parseable PE, 2 = usage error.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys

# --- data directory indices (IMAGE_DIRECTORY_ENTRY_*) -------------------------
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4          # file offset, not an RVA
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_ARCH = 7
DIR_GLOBALPTR = 8
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_BOUND_IMPORT = 11
DIR_IAT = 12
DIR_DELAY_IMPORT = 13
DIR_CLR = 14

DIRECTORY_NAMES = {
    DIR_EXPORT: 'export', DIR_IMPORT: 'import', DIR_RESOURCE: 'resource',
    DIR_EXCEPTION: 'exception', DIR_SECURITY: 'security', DIR_BASERELOC: 'basereloc',
    DIR_DEBUG: 'debug', DIR_ARCH: 'architecture', DIR_GLOBALPTR: 'globalptr',
    DIR_TLS: 'tls', DIR_LOAD_CONFIG: 'load_config', DIR_BOUND_IMPORT: 'bound_import',
    DIR_IAT: 'iat', DIR_DELAY_IMPORT: 'delay_import', DIR_CLR: 'clr',
}

MACHINE = {
    0x014C: 'i386', 0x0166: 'mips', 0x01C0: 'arm', 0x01C4: 'armv7',
    0x0200: 'ia64', 0x0266: 'mips16', 0x0366: 'mipsfpu', 0x0EBC: 'efi_bytecode',
    0x8664: 'amd64', 0xAA64: 'arm64', 0x01F0: 'powerpc',
    0x0000: 'unknown',
}

SUBSYSTEM = {
    1: 'native', 2: 'windows_gui', 3: 'windows_cui', 5: 'os2_cui',
    7: 'posix_cui', 9: 'windows_ce', 10: 'efi_application',
    11: 'efi_boot_service_driver', 12: 'efi_runtime_driver',
    13: 'efi_rom', 14: 'xbox', 16: 'windows_boot_application',
    17: 'xbox_code_catalog',
}

FILE_CHARACTERISTICS = {
    0x0001: 'relocs_stripped', 0x0002: 'executable_image', 0x0004: 'line_nums_stripped',
    0x0008: 'local_syms_stripped', 0x0010: 'aggressive_ws_trim', 0x0020: 'large_address_aware',
    0x0100: '32bit_machine', 0x0200: 'debug_stripped', 0x1000: 'system',
    0x2000: 'dll', 0x4000: 'up_system_only',
}

# Values below are the ones published in the Microsoft PE format specification
# ("Optional Header Windows-Specific Fields" -> DllCharacteristics, and "Section Flags").
# 0x0001-0x0008 are documented as reserved and must be zero; a non-zero value there is a
# signal worth looking at rather than a feature name.
DLL_CHARACTERISTICS = {
    0x0020: 'high_entropy_va', 0x0040: 'dynamic_base', 0x0080: 'force_integrity',
    0x0100: 'nx_compat', 0x0200: 'no_isolation', 0x0400: 'no_seh', 0x0800: 'no_bind',
    0x1000: 'appcontainer', 0x2000: 'wdm_driver', 0x4000: 'control_flow_guard',
    0x8000: 'terminal_server_aware',
}
DLL_CHARACTERISTICS_RESERVED = 0x000F

SECTION_CHARACTERISTICS = {
    0x00000008: 'type_no_pad', 0x00000020: 'cnt_code',
    0x00000040: 'cnt_initialized_data', 0x00000080: 'cnt_uninitialized_data',
    0x00000100: 'lnk_other', 0x00000200: 'lnk_info', 0x00000800: 'lnk_remove',
    0x00001000: 'lnk_comdat', 0x00008000: 'gprel',
    0x00020000: 'mem_purgeable',  # same value as the older MEM_16BIT alias
    0x00040000: 'mem_locked', 0x00080000: 'mem_preload',
    0x01000000: 'lnk_nreloc_ovfl', 0x02000000: 'mem_discardable',
    0x04000000: 'mem_not_cached', 0x08000000: 'mem_not_paged',
    0x10000000: 'mem_shared', 0x20000000: 'mem_execute',
    0x40000000: 'mem_read', 0x80000000: 'mem_write',
}
# The alignment field is NOT a set of independent bits: bits [23:20] hold an index, so
# testing them one bit at a time reports nonsense (0x60000000 is execute|read, not two
# alignment flags). The spec also states these values are valid only for object files.
ALIGN_MASK = 0x00F00000
ALIGN_NAMES = {
    0x00100000: 'align_1', 0x00200000: 'align_2', 0x00300000: 'align_4',
    0x00400000: 'align_8', 0x00500000: 'align_16', 0x00600000: 'align_32',
    0x00700000: 'align_64', 0x00800000: 'align_128', 0x00900000: 'align_256',
    0x00A00000: 'align_512', 0x00B00000: 'align_1024', 0x00C00000: 'align_2048',
    0x00D00000: 'align_4096', 0x00E00000: 'align_8192',
}


def section_align(value):
    """Decoded IMAGE_SCN_ALIGN_* index, or None when the field is zero (the image case)."""
    return ALIGN_NAMES.get(value & ALIGN_MASK)


# Resource type IDs that carry an ordinal name rather than a string.
RESOURCE_TYPES = {
    1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING',
    7: 'FONTDIR', 8: 'FONT', 9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE',
    12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE',
    19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML',
    24: 'MANIFEST',
}

DEBUG_TYPES = {
    1: 'coff', 2: 'codeview', 3: 'fpo', 4: 'misc', 5: 'exception',
    6: 'fixup', 9: 'borland', 10: 'reserved10', 11: 'clsid', 12: 'vc_feature',
    13: 'pogo', 14: 'iltcg', 16: 'repro',
}


def u8(b, o):
    return b[o]


def _guard(fn, width, name):
    """Run a fixed-width read, turning an out-of-range read into a ParseError.

    A file truncated in the middle of a header is a normal input, not an exotic one: it is what
    a partial download or a carved region looks like. Reported as `struct.error` it reaches the
    caller as a traceback, which reads like a defect in the tool rather than a fact about the
    file -- and the documented exit code for an unparseable image never gets used.
    """
    def read(b, o):
        try:
            return fn(b, o)
        except struct.error as exc:
            raise ParseError('file ends before the %s at offset 0x%X (length %d)'
                             % (name, o, len(b))) from exc
    return read


def u16(b, o):
    return _u16(b, o)


def u32(b, o):
    return _u32(b, o)


def s32(b, o):
    return _s32(b, o)


def u64(b, o):
    return _u64(b, o)


_u16 = _guard(lambda b, o: struct.unpack_from('<H', b, o)[0], 2, 'word')
_u32 = _guard(lambda b, o: struct.unpack_from('<I', b, o)[0], 4, 'dword')
_s32 = _guard(lambda b, o: struct.unpack_from('<i', b, o)[0], 4, 'signed dword')
_u64 = _guard(lambda b, o: struct.unpack_from('<Q', b, o)[0], 8, 'qword')


def bits(value, table):
    """Names for every set flag in `value`, in table order."""
    return [name for bit, name in sorted(table.items()) if value & bit]


def entropy(data):
    """Shannon entropy in bits/byte (0-8). Empty input is 0.0."""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    out = 0.0
    for c in counts.values():
        p = c / n
        out -= p * math.log2(p)
    return out


class ParseError(Exception):
    """The bytes are not a PE this reader can walk."""


class Section(object):
    __slots__ = ('name', 'virtual_size', 'virtual_address', 'raw_size',
                 'raw_pointer', 'characteristics', 'entropy', 'raw_tail')

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def flags(self):
        out = bits(self.characteristics or 0, SECTION_CHARACTERISTICS)
        a = section_align(self.characteristics or 0)
        if a:
            out.append(a)
        return out

    @property
    def va_end(self):
        return (self.virtual_address or 0) + (self.virtual_size or 0)

    @property
    def raw_end(self):
        return (self.raw_pointer or 0) + (self.raw_size or 0)

    def as_dict(self):
        return {
            'name': self.name, 'virtual_address': hex(self.virtual_address),
            'virtual_size': self.virtual_size, 'raw_pointer': hex(self.raw_pointer),
            'raw_size': self.raw_size, 'entropy': round(self.entropy or 0.0, 4),
            'virtual_ge_raw': (self.virtual_size or 0) > (self.raw_size or 0),
            'align': section_align(self.characteristics or 0),
            'flags': self.flags,
        }


class PE(object):
    """A parsed PE image. Construct with bytes; inspect fields; walk structures."""

    def __init__(self, data, path=None):
        self.d = data
        self.path = path
        if len(data) < 0x40 or data[0:2] != b'MZ':
            raise ParseError('no MZ signature at offset 0')
        self.e_lfanew = u32(data, 0x3C)
        if self.e_lfanew + 0x18 > len(data):
            raise ParseError('e_lfanew (0x%X) points past end of file' % self.e_lfanew)
        if data[self.e_lfanew:self.e_lfanew + 4] != b'PE\0\0':
            raise ParseError('no PE\\0\\0 signature at e_lfanew 0x%X' % self.e_lfanew)

        fh = self.e_lfanew + 4
        self.machine = u16(data, fh)
        self.number_of_sections = u16(data, fh + 2)
        self.timestamp = u32(data, fh + 4)
        self.pointer_to_symtab = u32(data, fh + 8)
        self.number_of_symbols = u32(data, fh + 12)
        self.size_of_optional_header = u16(data, fh + 16)
        self.characteristics = u16(data, fh + 18)

        oh = fh + 20
        self.optional_offset = oh
        if self.size_of_optional_header == 0:
            raise ParseError('no optional header: object file, not an image')
        self.magic = u16(data, oh)
        if self.magic == 0x10B:
            self.is_pe32plus = False
        elif self.magic == 0x20B:
            self.is_pe32plus = True
        else:
            raise ParseError('unexpected optional-header magic 0x%04X' % self.magic)

        self.address_of_entrypoint = u32(data, oh + 16)
        if self.is_pe32plus:
            self.image_base = u64(data, oh + 24)
            self.section_alignment = u32(data, oh + 32)
            self.file_alignment = u32(data, oh + 36)
            self.size_of_image = u32(data, oh + 56)
            self.size_of_headers = u32(data, oh + 60)
            self.checksum = u32(data, oh + 64)
            self.subsystem = u16(data, oh + 68)
            self.dll_characteristics = u16(data, oh + 70)
            self.stack_reserve = u64(data, oh + 72)
            self.heap_reserve = u64(data, oh + 88)
            self._num_dir_off = oh + 108
            self._dir_off = oh + 112
        else:
            self.image_base = u32(data, oh + 28)
            self.section_alignment = u32(data, oh + 32)
            self.file_alignment = u32(data, oh + 36)
            self.size_of_image = u32(data, oh + 56)
            self.size_of_headers = u32(data, oh + 60)
            self.checksum = u32(data, oh + 64)
            self.subsystem = u16(data, oh + 68)
            self.dll_characteristics = u16(data, oh + 70)
            self.stack_reserve = u32(data, oh + 72)
            self.heap_reserve = u32(data, oh + 88)
            self._num_dir_off = oh + 92
            self._dir_off = oh + 96

        self.number_of_rva_and_sizes = u32(data, self._num_dir_off)
        self.directories = {}
        n = min(self.number_of_rva_and_sizes, 16)
        for i in range(n):
            rva = u32(data, self._dir_off + i * 8)
            size = u32(data, self._dir_off + i * 8 + 4)
            self.directories[i] = (rva, size)

        self.sections = []
        sh = oh + self.size_of_optional_header
        for i in range(self.number_of_sections):
            off = sh + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].split(b'\0')[0]
            raw_ptr = u32(data, off + 20)
            raw_size = u32(data, off + 16)
            body = data[raw_ptr:raw_ptr + raw_size] if raw_ptr < len(data) else b''
            self.sections.append(Section(
                name=name.decode('latin-1'),
                virtual_size=u32(data, off + 8),
                virtual_address=u32(data, off + 12),
                raw_size=raw_size,
                raw_pointer=raw_ptr,
                characteristics=u32(data, off + 36),
                entropy=entropy(body[:65536]),
                raw_tail=max(0, raw_size - min(raw_size, max(0, len(body)))),
            ))

        self.warnings = []
        self._sanity()

    # --- basic derivations ----------------------------------------------------
    def _sanity(self):
        if self.file_alignment not in (0, 0x200, 0x1000) and self.file_alignment > 0x1000:
            self.warnings.append('file_alignment 0x%X is unusual (0x200 is the documented norm)'
                                 % self.file_alignment)
        if self.file_alignment and self.section_alignment % self.file_alignment != 0:
            self.warnings.append('section_alignment (0x%X) is not a multiple of file_alignment '
                                 '(0x%X); loader rejects this' % (self.section_alignment,
                                                                  self.file_alignment))
        declared = self.size_of_headers
        first_raw = min([s.raw_pointer for s in self.sections if s.raw_pointer] or [declared])
        if declared and first_raw < declared:
            self.warnings.append('first section raw_pointer (0x%X) is inside SizeOfHeaders '
                                 '(0x%X); overlapping headers are a tamper signal'
                                 % (first_raw, declared))
        if self.address_of_entrypoint == 0:
            self.warnings.append('AddressOfEntryPoint is 0')
        for s in self.sections:
            if s.raw_pointer and s.raw_pointer < self.size_of_headers:
                self.warnings.append('section %s raw data starts inside the headers' % s.name)
                break

    @property
    def is_dll(self):
        return bool(self.characteristics & 0x2000)

    @property
    def is_driver(self):
        """A kernel-mode image, from two documented signals: a native subsystem and the DLL flag.

        A third signal exists and is deliberately not required -- `IMAGE_DLLCHARACTERISTICS_WDM_DRIVER`
        (0x2000) -- because it is set by WDM drivers specifically, so requiring it would miss other
        kernel images. An earlier version of this property tested 0x1000, which the table in this
        file (correctly) names `appcontainer`: measured over the driver directory of one Windows
        installation, that test reported a kernel image zero times out of eighty. A wrong bit that
        produces a plausible boolean is the failure shape this repository is organised against, so
        the bit that is tested is the one the specification names.
        """
        return self.subsystem == 1 and bool(self.characteristics & 0x2000)

    @property
    def is_dotnet(self):
        rva, size = self.directories.get(DIR_CLR, (0, 0))
        return rva != 0 and size != 0

    @property
    def is_signed(self):
        off, size = self.directories.get(DIR_SECURITY, (0, 0))
        return off != 0 and size != 0

    @property
    def file_size(self):
        return len(self.d)

    @property
    def arch(self):
        return MACHINE.get(self.machine, 'machine_0x%04X' % self.machine)

    def section_of_rva(self, rva):
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s
        return None

    def rva_to_offset(self, rva):
        """RVA -> file offset, or None when the RVA is only in memory (uninitialized tail)."""
        if rva < self.size_of_headers:
            return rva
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                delta = rva - s.virtual_address
                if delta >= s.raw_size:
                    return None            # virtual-only tail: zero-filled at load
                return s.raw_pointer + delta
        return None

    def offset_to_rva(self, off):
        for s in self.sections:
            if s.raw_pointer <= off < s.raw_pointer + s.raw_size:
                return s.virtual_address + (off - s.raw_pointer)
        if off < self.size_of_headers:
            return off
        return None

    def rva_bytes(self, rva, size):
        off = self.rva_to_offset(rva)
        if off is None:
            return b''
        return self.d[off:off + size]

    def read_cstring(self, off, limit=512):
        if off is None or off < 0 or off >= len(self.d):
            return ''
        end = self.d.find(b'\0', off, min(len(self.d), off + limit))
        if end < 0:
            end = min(len(self.d), off + limit)
        return self.d[off:end].decode('latin-1', 'replace')

    # --- checksum -------------------------------------------------------------
    def computed_checksum(self):
        """Microsoft's own PE checksum algorithm (the one CheckSumMappedFile implements).

        Only the 4-byte CheckSum field participates as zero, and the file is summed as
        16-bit words with end-around carry. The final value folds in the file length.
        """
        data = bytearray(self.d)
        off_field = self.optional_offset + 64
        if off_field + 4 > len(data):
            return None
        data[off_field:off_field + 4] = b'\0\0\0\0'
        total = 0
        limit = len(data) - (len(data) % 2)
        for i in range(0, limit, 2):
            total += data[i] | (data[i + 1] << 8)
            total = (total & 0xFFFF) + (total >> 16)
        if len(data) % 2:
            total += data[-1]
            total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        return (total + len(data)) & 0xFFFFFFFF

    def checksum_ok(self):
        want = self.computed_checksum()
        if want is None:
            return None
        return want == self.checksum

    # --- structures -----------------------------------------------------------
    def rich_header(self):
        """MSVC Rich Header: the DanS-keyed build fingerprint between DOS stub and PE.

        **This block is not in the Microsoft PE/COFF specification.** The published format
        document does not describe it at all; the layout here (a `DanS` marker followed by
        (key-XORed value, count) pairs, ending at the `Rich` marker with a 32-bit key) comes
        from how tooling implements it, not from a normative source. Treat this parser as
        reading an undocumented structure: it is useful as a toolchain signal and it must not
        be presented as specification-defined.

        Returns {xor_key, entries:[{id, build, count}], offset} or None. `id` is the
        product/tool id in the high 16 bits of the value XORed by the key.
        """
        lo, hi = 0x40, min(self.e_lfanew, len(self.d))
        body = self.d[lo:hi]
        idx = body.find(b'Rich')
        if idx < 0:
            return None
        rich_off = lo + idx
        key = u32(self.d, rich_off + 4)
        dans_off = body.find(struct.pack('<I', 0x536E6144 ^ key))   # 'DanS' ^ key
        if dans_off < 0:
            return None
        start = lo + dans_off
        entries = []
        p = start + 16
        while p + 8 <= rich_off:
            value = u32(self.d, p)
            count = u32(self.d, p + 4)
            if count == 0 and value == 0:
                break
            comp = value ^ key
            entries.append({
                'id': (comp >> 16) & 0xFFFF,
                'build': comp & 0xFFFF,
                'count': count,
            })
            p += 8
        return {'xor_key': key, 'entries': entries, 'offset': start}

    def imports(self):
        """[{dll, functions:[{name|ordinal, hint, iat_rva}], descriptor_rva}]"""
        rva, size = self.directories.get(DIR_IMPORT, (0, 0))
        out = []
        if not rva:
            return out
        p = self.rva_to_offset(rva)
        if p is None:
            return out
        thunk_size = 8 if self.is_pe32plus else 4
        ordinal_flag = (1 << 63) if self.is_pe32plus else (1 << 31)
        for _ in range(1024):
            if p + 20 > len(self.d):
                break
            orig = u32(self.d, p)
            name_rva = u32(self.d, p + 12)
            first_thunk = u32(self.d, p + 16)
            if orig == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll = self.read_cstring(self.rva_to_offset(name_rva))
            thunk_rva = orig or first_thunk
            funcs = []
            tp = self.rva_to_offset(thunk_rva)
            if tp is not None:
                for j in range(65536):
                    if tp + thunk_size > len(self.d):
                        break
                    value = u64(self.d, tp) if self.is_pe32plus else u32(self.d, tp)
                    if value == 0:
                        break
                    entry = {'iat_rva': first_thunk + j * thunk_size}
                    if value & ordinal_flag:
                        entry['ordinal'] = value & 0xFFFF
                    else:
                        hint = self.rva_to_offset(value)
                        if hint is not None and hint + 2 <= len(self.d):
                            entry['hint'] = u16(self.d, hint)
                            entry['name'] = self.read_cstring(hint + 2)
                        else:
                            entry['name'] = None
                    funcs.append(entry)
                    tp += thunk_size
            out.append({'dll': dll, 'functions': funcs, 'descriptor_rva': rva,
                        'first_thunk_rva': first_thunk, 'original_thunk_rva': orig})
            p += 20
        return out

    def delay_imports(self):
        """Delay-load descriptors. Addresses may be RVAs or (rarely) pre-bound VAs."""
        rva, size = self.directories.get(DIR_DELAY_IMPORT, (0, 0))
        out = []
        if not rva:
            return out
        p = self.rva_to_offset(rva)
        if p is None:
            return out
        for _ in range(256):
            if p + 32 > len(self.d):
                break
            attrs = u32(self.d, p)
            name_v = u32(self.d, p + 4)
            iat_v = u32(self.d, p + 12)
            if name_v == 0 and iat_v == 0:
                break
            va_based = not (attrs & 1)
            name_rva = name_v - self.image_base if va_based else name_v
            out.append({
                'dll': self.read_cstring(self.rva_to_offset(name_rva)),
                'va_based': va_based,
                'iat_rva': iat_v - self.image_base if va_based else iat_v,
            })
            p += 32
        return out

    def exports(self):
        """{dll_name, base, functions:[{name, ordinal, rva, forwarder}], total}"""
        rva, size = self.directories.get(DIR_EXPORT, (0, 0))
        if not rva:
            return None
        p = self.rva_to_offset(rva)
        if p is None or p + 40 > len(self.d):
            return None
        ordinal_base = u32(self.d, p + 16)
        num_funcs = u32(self.d, p + 20)
        num_names = u32(self.d, p + 24)
        addr_funcs = u32(self.d, p + 28)
        addr_names = u32(self.d, p + 32)
        addr_ords = u32(self.d, p + 36)
        dll_name = self.read_cstring(self.rva_to_offset(u32(self.d, p + 12)))
        names = {}
        np_ = self.rva_to_offset(addr_names)
        if np_ is not None:
            for i in range(min(num_names, 65536)):
                if np_ + i * 4 + 4 > len(self.d):
                    break
                n_rva = u32(self.d, np_ + i * 4)
                o_off = self.rva_to_offset(addr_ords)
                if o_off is None:
                    break
                names[u16(self.d, o_off + i * 2)] = self.read_cstring(self.rva_to_offset(n_rva))
        funcs = []
        fp = self.rva_to_offset(addr_funcs)
        if fp is not None:
            fwd_lo = rva
            fwd_hi = rva + size
            for i in range(min(num_funcs, 65536)):
                if fp + i * 4 + 4 > len(self.d):
                    break
                frva = u32(self.d, fp + i * 4)
                if frva == 0:
                    continue
                item = {'ordinal': ordinal_base + i, 'name': names.get(i),
                        'rva': hex(frva)}
                if fwd_lo <= frva < fwd_hi:
                    item['forwarder'] = self.read_cstring(self.rva_to_offset(frva))
                funcs.append(item)
        return {'dll_name': dll_name, 'ordinal_base': ordinal_base,
                'number_of_functions': num_funcs, 'number_of_names': num_names,
                'functions': funcs}

    def _walk_resource_dir(self, base_rva, rel, depth, out, path=()):
        p = self.rva_to_offset(base_rva + rel)
        if p is None or p + 16 > len(self.d) or depth > 4:
            return
        # Both counts are 16-bit. Reading either as a 32-bit value swallows the first two
        # bytes of the following directory entry, which inflates the entry count wildly
        # (measured: one resource walked as 478). Real system images can hide this; a fixture
        # with exactly one entry cannot.
        named = u16(self.d, p + 12)
        ids = u16(self.d, p + 14)
        for i in range(named + ids):
            e = p + 16 + i * 8
            if e + 8 > len(self.d):
                return
            name_field = u32(self.d, e)
            offset_field = u32(self.d, e + 4)
            if name_field & 0x80000000:
                no = self.rva_to_offset(base_rva + (name_field & 0x7FFFFFFF))
                label = self.read_cstring(no, 128) if no is not None else '?'
                label = 'str:' + label
            else:
                label = str(name_field)
                if depth == 0:
                    label = RESOURCE_TYPES.get(name_field, label)
            if offset_field & 0x80000000:
                self._walk_resource_dir(base_rva, offset_field & 0x7FFFFFFF,
                                        depth + 1, out, path + (label,))
            else:
                dp = self.rva_to_offset(base_rva + offset_field)
                if dp is None or dp + 16 > len(self.d):
                    continue
                out.append({
                    'path': list(path + (label,)),
                    'data_rva': hex(u32(self.d, dp)),
                    'size': u32(self.d, dp + 4),
                    'codepage': u32(self.d, dp + 8),
                })

    def resources(self):
        rva, size = self.directories.get(DIR_RESOURCE, (0, 0))
        out = []
        if rva:
            self._walk_resource_dir(rva, 0, 0, out)
        return out

    def tls(self):
        rva, size = self.directories.get(DIR_TLS, (0, 0))
        if not rva:
            return None
        p = self.rva_to_offset(rva)
        if p is None or p + 40 > len(self.d):
            return None
        if self.is_pe32plus:
            start_raw = u64(self.d, p)
            end_raw = u64(self.d, p + 8)
            addr_index = u64(self.d, p + 16)
            callbacks = u64(self.d, p + 24)
            zero_fill = u32(self.d, p + 32)
            chars = u32(self.d, p + 36)
        else:
            start_raw = u32(self.d, p)
            end_raw = u32(self.d, p + 4)
            addr_index = u32(self.d, p + 8)
            callbacks = u32(self.d, p + 12)
            zero_fill = u32(self.d, p + 16)
            chars = u32(self.d, p + 20)
        cb_rvas = []
        if callbacks:
            cp = self.rva_to_offset(callbacks - self.image_base)
            ptr = 8 if self.is_pe32plus else 4
            if cp is not None:
                for i in range(256):
                    if cp + i * ptr + ptr > len(self.d):
                        break
                    v = u64(self.d, cp + i * ptr) if self.is_pe32plus else u32(self.d, cp + i * ptr)
                    if v == 0:
                        break
                    cb_rvas.append(hex(v - self.image_base))
        return {'start_raw_rva': hex(start_raw - self.image_base),
                'end_raw_rva': hex(end_raw - self.image_base),
                'address_of_index': hex(addr_index - self.image_base),
                'callbacks_rva': hex(callbacks - self.image_base) if callbacks else None,
                'callback_rvas': cb_rvas,
                'size_of_zero_fill': zero_fill, 'characteristics': chars,
                'note': ('TLS callbacks run before AddressOfEntryPoint; a breakpoint at the '
                         'entry point can be too late') if cb_rvas else None}

    def debug_directory(self):
        rva, size = self.directories.get(DIR_DEBUG, (0, 0))
        out = []
        if not rva:
            return out
        p = self.rva_to_offset(rva)
        if p is None:
            return out
        for i in range(max(0, size // 28)):
            e = p + i * 28
            if e + 28 > len(self.d):
                break
            etype = u32(self.d, e + 12)
            size_of_data = u32(self.d, e + 16)
            addr_raw = u32(self.d, e + 20)
            ptr_raw = u32(self.d, e + 24)
            item = {'type': DEBUG_TYPES.get(etype, str(etype)), 'type_id': etype,
                    'size_of_data': size_of_data,
                    # Both address spaces, because the two fields are easy to confuse: this one
                    # is an RVA, the next is a file offset.
                    'address_of_raw_data': hex(addr_raw),
                    'pointer_to_raw_data': hex(ptr_raw)}
            if etype == 2 and ptr_raw + 24 <= len(self.d):
                sig = self.d[ptr_raw:ptr_raw + 4]
                if sig == b'RSDS':
                    item['pdb'] = self.read_cstring(ptr_raw + 24, 260)
                    item['guid'] = hashlib.md5(self.d[ptr_raw + 4:ptr_raw + 20]).hexdigest()
                    item['age'] = u32(self.d, ptr_raw + 20)
                    item['format'] = 'RSDS'
                elif sig == b'NB10':
                    item['pdb'] = self.read_cstring(ptr_raw + 16, 260)
                    item['format'] = 'NB10'
            out.append(item)
        return out

    def base_relocations(self):
        rva, size = self.directories.get(DIR_BASERELOC, (0, 0))
        out = {'blocks': 0, 'entries': 0, 'types': {}, 'truncated': False}
        if not rva:
            return out
        p = self.rva_to_offset(rva)
        if p is None:
            return out
        end = min(len(self.d), (self.rva_to_offset(rva + size) or (p + size)))
        while p + 8 <= end:
            page = u32(self.d, p)
            block_size = u32(self.d, p + 4)
            if block_size < 8:
                out['truncated'] = True
                break
            out['blocks'] += 1
            n = (block_size - 8) // 2
            for i in range(n):
                e = p + 8 + i * 2
                if e + 2 > end:
                    out['truncated'] = True
                    break
                value = u16(self.d, e)
                t = value >> 12
                out['entries'] += 1
                out['types'][t] = out['types'].get(t, 0) + 1
            if page == 0 and block_size == 0:
                break
            p += block_size
        out['types'] = {str(k): v for k, v in sorted(out['types'].items())}
        return out

    def load_config(self):
        rva, size = self.directories.get(DIR_LOAD_CONFIG, (0, 0))
        if not rva:
            return None
        p = self.rva_to_offset(rva)
        if p is None or p + 4 > len(self.d):
            return None
        cfg_size = u32(self.d, p)
        out = {'size': cfg_size}
        if cfg_size >= 0x5C:
            out['security_cookie'] = hex(u64(self.d, p + 0x58) if self.is_pe32plus
                                         else u32(self.d, p + 0x3C))
        if cfg_size >= 0x70:
            out['se_handler_table'] = hex(u32(self.d, p + (0x68 if self.is_pe32plus else 0x40)))
        if cfg_size >= 0x7C:
            gf = u16(self.d, p + (0x72 if self.is_pe32plus else 0x48))
            out['guard_flags'] = hex(gf)
            names = []
            if gf & 0x0100:
                names.append('CF_INSTRUMENTED')
            if gf & 0x0200:
                names.append('CFW_INSTRUMENTED')
            if gf & 0x0400:
                names.append('CF_FUNCTION_TABLE_PRESENT')
            if gf & 0x0800:
                names.append('SECURITY_COOKIE_UNUSED')
            if gf & 0x1000:
                names.append('PROTECT_DELAYLOAD_IAT')
            if gf & 0x4000:
                names.append('EH_CONTINUATION_TABLE_PRESENT')
            out['guard_flags_names'] = names
        return out

    def security_directory(self):
        off, size = self.directories.get(DIR_SECURITY, (0, 0))
        if not off:
            return None
        if off + 8 > len(self.d):
            return {'offset': hex(off), 'size': size, 'note': 'offset past end of file'}
        length = u32(self.d, off)
        revision = u16(self.d, off + 4)
        cert_type = u16(self.d, off + 6)
        names = {0x0001: 'X509', 0x0002: 'PKCS_SIGNED_DATA', 0x0003: 'RESERVED_1',
                 0x0004: 'TS_STACK_SIGNED'}
        return {'offset': hex(off), 'declared_size': size, 'length': length,
                'revision': hex(revision), 'certificate_type': names.get(cert_type, cert_type),
                'note': ('this directory holds a file offset, not an RVA, and the blob sits '
                         'outside every section; appending or editing after it invalidates it')}

    def rich_summary(self):
        r = self.rich_header()
        if not r:
            return None
        builds = collections.Counter(e['build'] for e in r['entries'])
        return {'xor_key': hex(r['xor_key']),
                'entries': len(r['entries']),
                'distinct_builds': sorted(builds),
                'note': ('Rich Header is written by the MSVC linker; a stripped or rewritten '
                         'one is a toolchain/tamper signal, not proof of either')}

    # --- report ---------------------------------------------------------------
    def summary(self):
        oh = self.directories
        return {
            'path': self.path,
            'file_size': self.file_size,
            'sha256': hashlib.sha256(self.d).hexdigest(),
            'arch': self.arch,
            'machine': hex(self.machine),
            'kind': 'driver' if self.is_driver else ('dll' if self.is_dll else 'exe'),
            'is_dotnet': self.is_dotnet,
            'is_signed': self.is_signed,
            'timestamp': self.timestamp,
            'timestamp_iso': _iso(self.timestamp),
            'entry_point_rva': hex(self.address_of_entrypoint),
            'image_base': hex(self.image_base),
            'size_of_image': self.size_of_image,
            'size_of_headers': self.size_of_headers,
            'section_alignment': hex(self.section_alignment),
            'file_alignment': hex(self.file_alignment),
            'subsystem': SUBSYSTEM.get(self.subsystem, str(self.subsystem)),
            'file_characteristics': bits(self.characteristics, FILE_CHARACTERISTICS),
            'dll_characteristics': bits(self.dll_characteristics, DLL_CHARACTERISTICS),
            'directories': {DIRECTORY_NAMES.get(k, str(k)): {'rva': hex(v[0]), 'size': v[1]}
                            for k, v in sorted(oh.items()) if v[0]},
            'sections': [s.as_dict() for s in self.sections],
            'checksum_declared': hex(self.checksum),
            'checksum_computed': hex(self.computed_checksum() or 0),
            'checksum_matches': self.checksum_ok(),
            'warnings': self.warnings,
        }


def _iso(ts):
    """ISO-8601 UTC rendering of the file-header TimeDateStamp.

    A timestamp far in the future is common and not a defect: MSVC's /Brepro and
    deterministic-build pipelines store a content hash in this field, so the displayed date
    is meaningless for builds produced that way.
    """
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return None


def load(path):
    with open(path, 'rb') as fh:
        return PE(fh.read(), path)


def main():
    ap = argparse.ArgumentParser(
        description='Dependency-free PE structure reader (Windows x86/x64 images).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python peutil.py notepad.exe --summary --sections --entropy')
    ap.add_argument('pe', help='path to a PE file (.exe/.dll/.sys/.ocx/.cpl)')
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text')
    ap.add_argument('--summary', action='store_true', help='header + section overview')
    ap.add_argument('--sections', action='store_true')
    ap.add_argument('--imports', action='store_true')
    ap.add_argument('--exports', action='store_true')
    ap.add_argument('--resources', action='store_true')
    ap.add_argument('--rich', action='store_true')
    ap.add_argument('--tls', action='store_true')
    ap.add_argument('--debug', action='store_true')
    ap.add_argument('--relocs', action='store_true')
    ap.add_argument('--entropy', action='store_true')
    ap.add_argument('--check-sum', dest='check_sum', action='store_true',
                    help='compare the declared checksum with the computed one')
    args = ap.parse_args()

    if not os.path.isfile(args.pe):
        sys.stderr.write('error: %s is not a file\n' % args.pe)
        return 2
    try:
        pe = load(args.pe)
    except (ParseError, OSError) as exc:
        sys.stderr.write('error: %s: %s\n' % (args.pe, exc))
        return 1

    want_any = any([args.summary, args.sections, args.imports, args.exports, args.resources,
                    args.rich, args.tls, args.debug, args.relocs, args.entropy, args.check_sum])
    if not want_any:
        args.summary = True

    report = {}
    if args.summary:
        report['summary'] = pe.summary()
    if args.sections:
        report['section_detail'] = [dict(s.as_dict(), raw_tail=s.raw_tail) for s in pe.sections]
    if args.imports:
        report['imports'] = pe.imports()
        report['delay_imports'] = pe.delay_imports()
    if args.exports:
        report['exports'] = pe.exports()
    if args.resources:
        report['resources'] = pe.resources()
    if args.rich:
        report['rich_header'] = pe.rich_summary()
    if args.tls:
        report['tls'] = pe.tls()
    if args.debug:
        report['debug'] = pe.debug_directory()
    if args.relocs:
        report['base_relocations'] = pe.base_relocations()
    if args.entropy:
        report['entropy'] = [{'name': s.name, 'entropy': round(s.entropy or 0.0, 4),
                              'raw_size': s.raw_size} for s in pe.sections]
    if args.check_sum:
        report['checksum'] = {'declared': hex(pe.checksum),
                              'computed': hex(pe.computed_checksum() or 0),
                              'matches': pe.checksum_ok()}
    report['security_directory'] = pe.security_directory()
    report['load_config'] = pe.load_config()

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
        return 0

    s = report.get('summary')
    if s:
        print('file        : %s' % s['path'])
        print('size        : %d bytes' % s['file_size'])
        print('sha256      : %s' % s['sha256'])
        print('arch/kind   : %s / %s%s' % (s['arch'], s['kind'],
                                           ' (.NET)' if s['is_dotnet'] else ''))
        print('signed      : %s' % ('yes' if s['is_signed'] else 'no'))
        print('timestamp   : %s (%s)' % (s['timestamp_iso'], s['timestamp']))
        print('entry point : %s   image base %s' % (s['entry_point_rva'], s['image_base']))
        print('alignment   : section %s / file %s' % (s['section_alignment'], s['file_alignment']))
        print('subsystem   : %s' % s['subsystem'])
        print('checksum    : declared %s computed %s -> %s'
              % (s['checksum_declared'], s['checksum_computed'],
                 'match' if s['checksum_matches'] else 'MISMATCH'))
        if s['dll_characteristics']:
            print('dll chars   : %s' % ', '.join(s['dll_characteristics']))
        print('directories : %s' % ', '.join(sorted(s['directories'])) or '(none)')
        print('sections    :')
        for row in s['sections']:
            print('  %-9s va=%-10s vsize=%-8d raw=%-10s rsize=%-8d ent=%.2f %s'
                  % (row['name'], row['virtual_address'], row['virtual_size'],
                     row['raw_pointer'], row['raw_size'], row['entropy'],
                     ','.join(row['flags'][:4])))
        for w in s['warnings']:
            print('  WARN %s' % w)
    if 'entropy' in report and not args.json:
        print('entropy     : %s' % ', '.join('%s=%.2f' % (e['name'], e['entropy'])
                                             for e in report['entropy']))
    if report.get('rich_header'):
        r = report['rich_header']
        print('rich header : key %s, %d entries, builds %s'
              % (r['xor_key'], r['entries'], r['distinct_builds']))
    if report.get('tls'):
        t = report['tls']
        print('tls         : callbacks %s' % (t['callback_rvas'] or '(none)'))
        if t['callback_rvas']:
            print('              note: %s' % t['note'])
    if 'imports' in report and report['imports']:
        print('imports     :')
        for d in report['imports']:
            named = [f.get('name') or ('#%d' % f.get('ordinal', 0)) for f in d['functions']]
            print('  %-28s %3d %s' % (d['dll'], len(d['functions']),
                                      ', '.join(named[:6]) + (' ...' if len(named) > 6
                                                              else '')))
    if report.get('exports'):
        e = report['exports']
        print('exports     : %s base=%d funcs=%d names=%d'
              % (e['dll_name'], e['ordinal_base'], e['number_of_functions'],
                 e['number_of_names']))
    if report.get('debug'):
        for d in report['debug']:
            if d.get('pdb'):
                print('debug pdb   : %s (%s)' % (d['pdb'], d.get('format')))
    if report.get('base_relocations', {}).get('blocks'):
        r = report['base_relocations']
        print('relocations : %d blocks, %d entries, types %s%s'
              % (r['blocks'], r['entries'], r['types'],
                 ' (TRUNCATED)' if r['truncated'] else ''))
    if report.get('resources'):
        print('resources   : %d entries' % len(report['resources']))
    if report.get('security_directory'):
        sd = report['security_directory']
        print('signature   : %s at %s, type %s' % ('present', sd['offset'],
                                                   sd.get('certificate_type')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
