"""Unit tests for skills/exe-reverse/scripts/peutil.py.

Everything here runs against the generated fixtures, whose declared metadata (section RVAs,
plant offsets, checksum) is asserted against the parser instead of being re-derived from it, so
a parser change cannot make its own test pass.

The checksum check is deliberately a second implementation: if the test called the parser's own
function to produce the expected value, a wrong algorithm would agree with itself.
"""
import hashlib
import struct

import pytest

pytestmark = pytest.mark.unit


def ms_checksum(data, field_offset):
    """The published Microsoft PE checksum, written independently of peutil.py."""
    buf = bytearray(data)
    buf[field_offset:field_offset + 4] = b"\x00\x00\x00\x00"
    total = 0
    for i in range(0, len(buf) - (len(buf) % 2), 2):
        total += buf[i] | (buf[i + 1] << 8)
        total = (total & 0xFFFF) + (total >> 16)
    if len(buf) % 2:
        total += buf[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + len(buf)) & 0xFFFFFFFF


# --- header fields -----------------------------------------------------------

def test_pe32plus_fixture_header_fields_match_the_recipe(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, str(fixtures.pe64.path))
    meta = fixtures.pe64.meta
    assert pe.is_pe32plus is True
    assert pe.magic == 0x20B
    assert pe.machine == 0x8664
    assert pe.arch == "amd64"
    assert pe.number_of_sections == 5
    assert pe.number_of_rva_and_sizes == 16
    assert [s.name for s in pe.sections] == [".text", ".rdata", ".data", ".rsrc", ".reloc"]
    assert pe.address_of_entrypoint == int(meta["entry_rva"], 16) == 0x1000
    assert pe.image_base == int(meta["image_base"], 16) == 0x140000000
    assert pe.size_of_image == meta["size_of_image"]
    assert pe.size_of_headers == meta["size_of_headers"]
    assert pe.section_alignment == 0x1000
    assert pe.file_alignment == 0x200
    assert pe.subsystem == 3
    assert pe.timestamp == 0x5F5E1000
    assert pe.file_size == meta["size"] == 4096
    assert pe.e_lfanew == 0x80


def test_pe32_fixture_reports_the_32bit_layout(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe32.data, str(fixtures.pe32.path))
    assert pe.is_pe32plus is False
    assert pe.magic == 0x10B
    assert pe.machine == 0x014C
    assert pe.arch == "i386"
    assert pe.image_base == 0x400000
    assert pe.number_of_sections == 5


@pytest.mark.parametrize("name,plus", [("pe64", True), ("pe32", False)])
def test_optional_header_field_offsets_follow_the_magic(load_script, fixtures, name, plus):
    """The PE32 and PE32+ optional headers are different layouts, not different sizes."""
    pe = load_script("peutil.py").PE(fixtures[name].data, None)
    oh = pe.optional_offset
    assert pe._num_dir_off - oh == (108 if plus else 92)
    assert pe._dir_off - oh == (112 if plus else 96)
    assert pe.checksum == struct.unpack_from("<I", pe.d, oh + 64)[0]
    if plus:
        assert pe.image_base == struct.unpack_from("<Q", pe.d, oh + 24)[0]
    else:
        assert pe.image_base == struct.unpack_from("<I", pe.d, oh + 28)[0]


@pytest.mark.parametrize("name", ["pe64", "pe32"])
def test_reading_the_other_layout_yields_a_wrong_directory_count(load_script, fixtures, name):
    """The trap the fixture exists to expose: the wrong layout parses without error."""
    pe = load_script("peutil.py").PE(fixtures[name].data, None)
    wrong = pe._num_dir_off - pe.optional_offset
    other = 92 if wrong == 108 else 108
    misread = struct.unpack_from("<I", pe.d, pe.optional_offset + other)[0]
    assert pe.number_of_rva_and_sizes == 16
    assert misread != 16, "the two layouts are not distinguishable on this fixture"


def test_characteristics_and_kind_derivations(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    assert pe.is_dll is False
    assert pe.is_driver is False
    assert pe.is_dotnet is False
    assert pe.is_signed is False
    assert pe.security_directory() is None
    assert "executable_image" in pe.summary()["file_characteristics"]
    assert "large_address_aware" in pe.summary()["file_characteristics"]


def test_fixture_is_well_formed_so_no_warnings_are_raised(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    assert pe.warnings == []


# --- RVA <-> file offset -----------------------------------------------------

@pytest.mark.parametrize("section", [".text", ".rdata", ".data", ".rsrc", ".reloc"])
def test_rva_to_file_offset_round_trips_every_section(load_script, fixtures, section):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    decl = fixtures.pe64.section(section)
    rva = int(decl["rva"], 16)
    raw = int(decl["raw_pointer"], 16)
    assert pe.rva_to_offset(rva) == raw
    assert pe.offset_to_rva(raw) == rva
    for delta in (1, decl["raw_size"] // 2, decl["raw_size"] - 1):
        assert pe.rva_to_offset(rva + delta) == raw + delta
        assert pe.offset_to_rva(raw + delta) == rva + delta
    assert pe.section_of_rva(rva).name == section


def test_header_rvas_map_identity_below_size_of_headers(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    for rva in (0, 0x40, 0x98, pe.size_of_headers - 1):
        assert pe.rva_to_offset(rva) == rva
        assert pe.offset_to_rva(rva) == rva


def test_virtual_only_tail_has_no_bytes_on_disk(load_script, fixtures):
    """The .rdata tail is allocated in memory and zero-filled at load, so it has no file bytes."""
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    decl = fixtures.pe64.section(".rdata")
    rva = int(decl["rva"], 16)
    raw_size = decl["raw_size"]
    # Measured shape of this fixture: a 384-byte payload aligned up to a 512-byte raw span,
    # plus the recipe's 1024-byte virtual pad, gives 1408 virtual bytes -- so 896 of them have
    # no file image at all.
    assert decl["virtual_size"] - raw_size == 896
    assert fixtures.pe64.meta["virtual_only_tail_bytes"] == 1024
    # Last byte with a file image, then the first byte without one.
    assert pe.rva_to_offset(rva + raw_size - 1) == int(decl["raw_pointer"], 16) + raw_size - 1
    assert pe.rva_to_offset(rva + raw_size) is None
    assert pe.rva_to_offset(rva + decl["virtual_size"] - 1) is None
    assert pe.rva_bytes(rva + raw_size, 4) == b""
    assert pe.section_of_rva(rva + raw_size).name == ".rdata"
    # The RVA still exists, it just does not resolve to a file offset.
    assert pe.rva_to_offset(rva) is not None


def test_recipe_without_a_virtual_tail_has_none(load_script, fixtures):
    """A 4 KiB file alignment is large enough that every virtual byte has a file image."""
    pe = load_script("peutil.py").PE(fixtures.fatalign.data, None)
    decl = fixtures.fatalign.section(".rdata")
    rva = int(decl["rva"], 16)
    assert decl["virtual_size"] <= decl["raw_size"]
    assert pe.rva_to_offset(rva + decl["virtual_size"] - 1) is not None
    assert pe.rva_to_offset(rva + decl["raw_size"]) is None


def test_offset_to_rva_returns_none_outside_every_mapping(load_script, fixtures):
    """A negative outcome: an offset with no mapping must not be reported as RVA 0."""
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    assert pe.offset_to_rva(pe.file_size) is None
    assert pe.offset_to_rva(pe.file_size + 0x1000) is None


def test_rva_to_offset_rejects_unmapped_rvas(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    assert pe.rva_to_offset(0x900000) is None
    assert pe.section_of_rva(0x900000) is None
    assert pe.read_cstring(None) == ""
    assert pe.read_cstring(pe.file_size + 1) == ""


# --- checksum ----------------------------------------------------------------

@pytest.mark.parametrize("name", ["pe64", "pe32", "bare", "fatalign"])
def test_checksum_reproduces_the_declared_value(load_script, fixtures, name):
    built = fixtures[name]
    pe = load_script("peutil.py").PE(built.data, str(built.path))
    declared = int(built.meta["checksum"], 16)
    assert pe.checksum == declared
    assert pe.computed_checksum() == declared
    assert pe.checksum_ok() is True
    # Independent implementation of the same published algorithm.
    assert ms_checksum(built.data, int(built.meta["checksum_offset"], 16)) == declared


def test_checksum_mismatch_is_reported_not_hidden(load_script, fixtures):
    data = bytearray(fixtures.pe64.data)
    data[int(fixtures.pe64.meta["checksum_offset"], 16)] ^= 0xFF   # corrupt one byte
    pe = load_script("peutil.py").PE(bytes(data), None)
    assert pe.checksum_ok() is False
    assert pe.computed_checksum() != pe.checksum


# --- structures --------------------------------------------------------------

def test_resource_walk_returns_exactly_the_declared_entries(load_script, fixtures):
    """type(16=VERSION) -> name(1) -> language(1033) -> one data entry, and nothing else.

    A 32-bit read of either directory count would swallow the next entry and inflate this to a
    much larger number, which is why the exact count is asserted rather than "at least one".
    """
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    entries = pe.resources()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["path"] == ["VERSION", "1", "1033"]
    assert entry["size"] == 4
    assert entry["codepage"] == 1200
    assert int(entry["data_rva"], 16) == int(fixtures.pe64.section(".rsrc")["rva"], 16) + 0x90
    assert pe.rva_bytes(int(entry["data_rva"], 16), 4) == b"FIXT"


def test_recipe_without_resources_reports_an_empty_tree(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.bare.data, None)
    assert pe.resources() == []


def test_imports_include_one_named_import_and_one_by_ordinal(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    imports = pe.imports()
    assert len(imports) == 1
    desc = imports[0]
    assert desc["dll"] == fixtures.pe64.meta["import_dll"] == "fixture-import.dll"
    assert desc["descriptor_rva"] == int(fixtures.pe64.meta["import_descriptor_rva"], 16)
    funcs = desc["functions"]
    assert len(funcs) == 2, "the descriptor terminator must stop the walk"
    named = funcs[0]
    assert named["name"] == fixtures.pe64.meta["import_named"] == "ImportedFunction"
    assert named["hint"] == 7
    assert "ordinal" not in named
    by_ordinal = funcs[1]
    assert by_ordinal["ordinal"] == int(fixtures.pe64.meta["import_ordinal"], 16) == 0x2A
    assert "name" not in by_ordinal
    assert funcs[1]["iat_rva"] > funcs[0]["iat_rva"]
    assert pe.delay_imports() == []


@pytest.mark.parametrize("name", ["pe64", "pe32"])
def test_export_directory_has_one_named_function(load_script, fixtures, name):
    pe = load_script("peutil.py").PE(fixtures[name].data, None)
    exports = pe.exports()
    assert exports["dll_name"] == "fixture-export.dll"
    assert exports["ordinal_base"] == 1
    assert exports["number_of_functions"] == 1
    assert exports["number_of_names"] == 1
    funcs = exports["functions"]
    assert len(funcs) == 1
    assert funcs[0]["name"] == "ExportedFunction"
    assert funcs[0]["ordinal"] == 1
    assert funcs[0]["rva"] == "0x1000"
    assert "forwarder" not in funcs[0]


def test_recipe_without_exports_returns_none(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.bare.data, None)
    assert pe.exports() is None


def test_tls_callback_rva_is_reachable(load_script, fixtures):
    """The callback pointer is stored as a VA, so the reported RVA needs image-base subtraction."""
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    tls = pe.tls()
    assert tls is not None
    assert tls["callback_rvas"] == [fixtures.pe64.meta["entry_rva"]] == ["0x1000"]
    assert tls["callbacks_rva"] == fixtures.pe64.meta["tls_callback_rva"]
    assert tls["note"], "a callback that runs before the entry point must be flagged"
    assert pe.imports() and tls["callbacks_rva"] != fixtures.pe64.meta["import_descriptor_rva"]


def test_recipe_without_tls_reports_none(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.bare.data, None)
    assert pe.tls() is None


def test_debug_record_carries_the_rsds_pdb_path(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    records = pe.debug_directory()
    assert len(records) == 1
    rec = records[0]
    assert rec["type"] == "codeview" and rec["type_id"] == 2
    assert rec["format"] == "RSDS"
    assert rec["pdb"] == fixtures.pe64.meta["pdb_path"] == "C:\\build\\fixture.pdb"
    assert rec["age"] == 1
    assert rec["guid"] == hashlib.md5(bytes(range(16))).hexdigest()
    # PointerToRawData is a file offset while AddressOfRawData is an RVA: prove the pair agrees.
    rsds_rva = int(fixtures.pe64.meta["rdata_structure_rvas"]["dbg_rsds"], 16)
    assert pe.rva_to_offset(rsds_rva) == int(rec["pointer_to_raw_data"], 16)
    assert pe.d[pe.rva_to_offset(rsds_rva):pe.rva_to_offset(rsds_rva) + 4] == b"RSDS"


def test_recipe_without_debug_directory_reports_no_records(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.bare.data, None)
    assert pe.debug_directory() == []


def test_base_relocations_block_is_parsed_by_type(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    relocs = pe.base_relocations()
    assert relocs["blocks"] == 1
    assert relocs["entries"] == 2
    assert relocs["truncated"] is False
    assert relocs["types"] == {"3": 1, "10": 1}


def test_absent_load_config_is_reported_as_none(load_script, fixtures):
    pe = load_script("peutil.py").PE(fixtures.pe64.data, None)
    assert pe.load_config() is None
    assert pe.rich_header() is None, "the fixture has no Rich header; none may be invented"


def test_summary_is_json_serialisable_and_names_the_documented_keys(load_script, fixtures):
    import json
    pe = load_script("peutil.py").PE(fixtures.pe64.data, str(fixtures.pe64.path))
    summary = pe.summary()
    text = json.dumps(summary)
    assert '"checksum_matches": true' in text
    for key in ("path", "file_size", "sha256", "arch", "kind", "sections", "directories",
                "checksum_declared", "checksum_computed", "checksum_matches", "warnings"):
        assert key in summary
    assert summary["sha256"] == hashlib.sha256(fixtures.pe64.data).hexdigest()


# --- pure helpers ------------------------------------------------------------

def test_entropy_bounds(load_script):
    peutil = load_script("peutil.py")
    assert peutil.entropy(b"") == 0.0
    assert peutil.entropy(b"\x00" * 256) == 0.0
    assert peutil.entropy(bytes(range(256))) == pytest.approx(8.0, abs=1e-9)
    assert 0.0 <= peutil.entropy(bytes(range(128)) * 2) <= 8.0


def test_section_align_is_an_index_not_a_set_of_bits(load_script):
    """Bits [23:20] hold an alignment index, so a normal image reports no alignment name."""
    peutil = load_script("peutil.py")
    assert peutil.section_align(0x00600000) == "align_32"
    assert peutil.section_align(0xE0000020) is None      # the fixture's .text
    assert peutil.section_align(0x60000020) is None      # a normal compiler's .text


def test_flag_decoding_is_ordered_and_complete(load_script):
    peutil = load_script("peutil.py")
    assert peutil.bits(0x0022, peutil.FILE_CHARACTERISTICS) == ["executable_image",
                                                                "large_address_aware"]
    assert peutil.bits(0, peutil.FILE_CHARACTERISTICS) == []
    assert "mem_execute" in peutil.bits(0xE0000020, peutil.SECTION_CHARACTERISTICS)
    assert "mem_write" in peutil.bits(0xE0000020, peutil.SECTION_CHARACTERISTICS)


def test_integer_readers_are_little_endian(load_script):
    peutil = load_script("peutil.py")
    blob = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert peutil.u8(blob, 0) == 0x01
    assert peutil.u16(blob, 0) == 0x0201
    assert peutil.u32(blob, 0) == 0x04030201
    assert peutil.u64(blob, 0) == 0x0807060504030201
    assert peutil.s32(b"\xFF\xFF\xFF\xFF", 0) == -1


# --- rejection ---------------------------------------------------------------

@pytest.mark.parametrize("blob,expected", [
    (b"", "no MZ signature"),
    (b"MZ", "no MZ signature"),
    (b"this is not a PE file at all, just text" * 4, "no MZ signature"),
])
def test_parse_error_on_non_pe_input(load_script, blob, expected):
    peutil = load_script("peutil.py")
    with pytest.raises(peutil.ParseError, match=expected):
        peutil.PE(blob, None)


def test_parse_error_when_e_lfanew_points_past_end_of_file(load_script):
    peutil = load_script("peutil.py")
    blob = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0xFFFFFF) + b"\x00" * 8
    with pytest.raises(peutil.ParseError, match="points past end of file"):
        peutil.PE(blob, None)


def test_parse_error_without_the_pe_signature(load_script):
    peutil = load_script("peutil.py")
    blob = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"\x00" * 0x40
    with pytest.raises(peutil.ParseError, match=r"no PE\\0\\0 signature"):
        peutil.PE(blob, None)


def test_parse_error_on_an_unexpected_optional_header_magic(load_script, fixtures):
    peutil = load_script("peutil.py")
    data = bytearray(fixtures.pe64.data)
    struct.pack_into("<H", data, 0x98, 0x999)
    with pytest.raises(peutil.ParseError, match="unexpected optional-header magic 0x0999"):
        peutil.PE(bytes(data), None)


def test_parse_error_on_an_object_file_with_no_optional_header(load_script, fixtures):
    peutil = load_script("peutil.py")
    data = bytearray(fixtures.pe64.data)
    struct.pack_into("<H", data, 0x80 + 4 + 16, 0)
    with pytest.raises(peutil.ParseError, match="object file, not an image"):
        peutil.PE(bytes(data), None)


def test_load_rejects_a_missing_path(tmp_path, load_script):
    peutil = load_script("peutil.py")
    with pytest.raises(OSError):
        peutil.load(str(tmp_path / "absent.exe"))


def test_load_sets_the_path_on_the_parsed_image(load_script, fixtures):
    pe = load_script("peutil.py").load(str(fixtures.pe64.path))
    assert pe.path == str(fixtures.pe64.path)
    assert pe.file_size == fixtures.pe64.size
