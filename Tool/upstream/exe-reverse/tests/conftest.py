"""Shared fixtures for the exe-reverse regression suite.

What this file guarantees:

* every input is *built*, never committed and never downloaded -- the synthetic PE images come
  from ``skills/exe-reverse/scripts/make_fixture_pe.py`` at test time, into a pytest temporary
  directory that disappears with the session;
* the scripts under test are loaded by path, because ``skills/exe-reverse/scripts/`` is a flat
  directory of runnable files, not an importable package;
* a missing prerequisite -- an older interpreter, an absent local tool -- is a *skip with a
  printed reason*, never a failure. A wrong result is always a failure.

Nothing here touches the network, a debugger, a device or a kernel component.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "skills" / "exe-reverse" / "scripts"

# The scripts declare "Python 3.9+" in their own docstrings.
MIN_PYTHON = (3, 9)

# Every script this suite may load by name or run as a subprocess. The last five were added with
# their own layers of the suite: the capability registry and the environment doctor answer questions
# about this host, the Dart snapshot reader takes an ELF rather than a PE (so its input is generated
# here by `build_synthetic_elf` instead of by `make_fixture_pe.py`), the folder summarises records
# too large to read (its tests assert on the bounds of its output rather than on fixtures of any
# particular size), and the reducer's proof path drives an external solver, so its solver-facing
# tests run against a stub and the pure parts against plain text.
SCRIPT_FILES = (
    "peutil.py",
    "pepatch.py",
    "hwprobe.py",
    "aob_scan.py",
    "make_fixture_pe.py",
    "scan_leaks.py",
    "capabilities.py",
    "doctor.py",
    "dart_snapshot_strings.py",
    "fold.py",
    "trace_reduce.py",
    # The two route helpers: the first script a task should run on an unknown image, and the
    # two-build comparison. Added with tests/cli/test_cli_coverage.py, which fails if a shipped
    # script is neither in this tuple nor declared uncovered with a reason.
    "pe_triage.py",
    "pe_diff.py",
)

# A hang detector, not a performance assertion. Nothing in this suite is meant to be slow.
RUN_TIMEOUT = 180

# Suite name -> recipe name in make_fixture_pe.py, so recipes are referenced rather than
# duplicated. `default` is PE32+ with every structure; `pe32` is the 32-bit layout; `bare`
# drops exports/resources/TLS/debug; `fatalign` uses a 4 KiB file alignment, which is large
# enough that .rdata has no virtual-only tail at all.
#
# The `no-virtual-tail` recipe is deliberately NOT used: with `rdata_virtual_pad = 0` its own
# guard (`rdata_payload_len > rdata_virtual_pad`) rejects the layout it names, so the recipe
# cannot be built and exits 1. `fatalign` covers the same property. Recorded in benchmark.md.
FIXTURE_RECIPES = {
    "pe64": "default",
    "pe32": "pe32",
    "bare": "bare",
    "fatalign": "fat-align",
}

# --- synthetic leak corpus ---------------------------------------------------
# One line per rule in scan_leaks.py. Each line is shaped like the thing its rule targets, and
# (except for machine-guid, which is a measured observation -- see the unit tests) is not
# suppressed by the exemption list.
#
# Every sample is assembled from fragments at import time rather than quoted whole. The suite
# deliberately contains strings shaped like a pasted key, a token and a real profile path; if
# they were written whole, the repository's own pre-publish scan would report this file the
# moment it walked the tracked surface. Splitting them keeps the runtime value matched by the
# rule while the source text matches nothing. A scanner's own fixtures have to be written this
# way, and that is a property of the scan surface, not a trick.
def parts(*chunks):
    """Join string fragments at run time (see the note above)."""
    return "".join(chunks)


LEAK_LINES = (
    ("private-key-block", parts("-----BEGIN RSA ", "PRIVATE KEY-----")),
    ("github-token", parts("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")),
    ("aws-access-key", parts("AKIA", "Q7ZK3MNP2RVW8XTD")),
    ("slack-token", parts("xoxb-", "1234567890abcdef")),
    ("generic-secret-assignment", parts('api_key = "', "QwErTyUiOpAsDfGhJkLzXcVb", '"')),
    ("licence-blob-literal", parts('license_key: "', "ABCDEFGH1234", '"')),
    ("windows-user-profile", parts("C:\\Users\\", "mkorvin", "\\notes.md")),
    ("posix-home", parts("/home/", "mkorvin", "/notes.md")),
    ("machine-guid", parts("MachineGuid = ", "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071")),
    ("windows-sid-literal", parts("S-1-5-21-", "1004336348-1177238915-682003330-", "1001")),
    ("volume-serial-literal", parts("Volume Serial Number: ", "1A2B-3C4D")),
    ("literal-endpoint-with-creds", parts("ftp://", "deploy:Sup3rSecret@", "45.77.", "10.199/pub")),
    ("public-ipv4-literal", parts("45.77.", "10.199")),
    ("literal-host-with-path", parts("https://licensing.", "hexweld.", "org/v2/activate")),
    ("product-name-with-version", parts("Hexweld Editor ", "4.2.1")),
    ("exe-name-with-version", parts("build: hexweld", ".exe v4.2")),
    ("email-address", parts("k.morozov@", "hexweld.org")),
    ("vendor-copyright-line", parts("Copyright (c) 2024 ", "Hexweld Systems")),
)

# Lines that must never be reported: tool names, protector names, format vocabulary, platform
# terms, placeholder tokens, reserved documentation addresses, well-known SIDs.
EXEMPT_LINES = (
    ("tool name", "IDA Pro 9.0.2 opened the image"),
    ("protector name", "the UPX 4.2 stub wraps a Themida section"),
    ("format term", "RVA versus file offset; the PDB is RSDS CodeView"),
    ("platform term", "Microsoft Windows 11.0 build 26100 with PowerShell"),
    ("placeholder token", "TARGET: APP_URL and SAMPLE with PLACEHOLDER values"),
    ("documentation address", "203.0.113.9 and 198.51.100.7 and 192.0.2.44"),
    ("well-known SID", "S-1-5-18 and S-1-5-32-544 are not machine identity"),
    ("loopback and example", "127.0.0.1 and localhost and example.com"),
    ("machine guid context", parts("MachineGuid = ", "3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071")),
    ("net tld", parts("https://licensing.", "hexweld.", "net/v2/activate")),
)

# Measured deviations from the exemption list, pinned as observations rather than wishes. Each
# is asserted by a unit test so a change to either list is visible instead of silent:
#   * the bare-GUID exemption matches inside the machine-guid rule's own match text, so that
#     rule cannot produce a finding;
#   * the `.NET` entry matches any `.net` TLD, so a hit inside such a URL or address is
#     suppressed as a platform term;
#   * the `<[a-z_]+>` placeholder alternative is surrounded by `\b` on both sides, so it cannot
#     match bracketed prose; only word-character adjacency reaches it.
#
# A fourth deviation was measured and then corrected while this suite was being written: for one
# revision of the exemption list, a standard-name alternative matched the `HTTP` inside every
# `https?://` URL and swallowed every literal-host-with-path hit. benchmark.md records both
# states; the suite asserts the corrected one.
SUPPRESSED_RULES = ("machine-guid",)

# Lines that must never be reported: tool names, protector names, format vocabulary, platform
# terms, placeholder tokens, reserved documentation addresses, well-known SIDs.
EXEMPT_LINES = (
    ("tool name", "IDA Pro 9.0.2 opened the image"),
    ("protector name", "the UPX 4.2 stub wraps a Themida section"),
    ("format term", "RVA versus file offset; the PDB is RSDS CodeView"),
    ("platform term", "Microsoft Windows 11.0 build 26100 with PowerShell"),
    ("placeholder token", "TARGET: APP_URL and SAMPLE with PLACEHOLDER values"),
    ("documentation address", "203.0.113.9 and 198.51.100.7 and 192.0.2.44"),
    ("well-known SID", "S-1-5-18 and S-1-5-32-544 are not machine identity"),
    ("loopback and example", "127.0.0.1 and localhost and example.com"),
    ("machine guid context", "MachineGuid = 3f2a1b4c-5d6e-7f80-9a1b-2c3d4e5f6071"),
    ("net tld", "https://licensing.hexweld.net/v2/activate"),
)

# The one rule whose hits are suppressed by the exemption list. Measured, not assumed: the
# bare-GUID exemption matches inside the machine-guid rule's own match text. Pinned by a unit
# test so a change in either list is visible instead of silent.
SUPPRESSED_RULES = ("machine-guid",)


# --- synthetic ELF64 for dart_snapshot_strings.py -----------------------------
# That script's input is a Dart AOT snapshot -- an ELF shared object named `app.so` -- and this
# repository may never carry a sample, not even a small one. So the suite builds the container
# instead: a valid ELF64 header, a `.text` of a handful of bytes, a `.rodata` holding one one-byte
# (ASCII) literal and one two-byte (UTF-16LE) literal at known offsets, and a section-name string
# table. A few hundred bytes, written at test time into the session temporary directory.
#
# What this image is *not*: a real snapshot. It exists so the reader can be held against a container
# whose offsets are known in advance, which is what proves the literal-recovery logic. The
# instruction-level counts an earlier version of the reader reported were withdrawn -- a byte scan
# cannot read this format, and the reference records why -- so nothing here stands in for them.

# Neither `49 8B /r` (a pool load through r15) nor `4X 8B|8D 05` (a RIP-relative load) appears in
# these bytes, which is what makes the zero counts below a measurement rather than an artifact.
ELF_TEXT_BYTES = bytes((0x90, 0x90, 0xC3, 0xCC, 0x55, 0x48, 0x89, 0xE5,
                        0x5D, 0xC3, 0x0F, 0x1F, 0x44, 0x00, 0x00, 0x90))
ELF_TEXT_VADDR = 0x1000
# Large enough that a virtual address is never mistaken for a file offset: the reader treats an
# `--at` value above the file size as a vaddr, and this image is under 1 KiB.
ELF_RODATA_VADDR = 0x400000

# (offset within .rodata, vaddr offset, text, encoding). The ASCII run at 0x00 and the UTF-16LE run
# at 0x1C are the two shapes the reader documents; the NUL padding between them keeps the two-byte
# run on the phase the scan walks, because that scan advances from the section base in steps of two.
# That phase dependency is a defect in the reader rather than a property of a snapshot, and it is
# pinned in unit/test_dart_snapshot_strings.py; the fixture places its literals so the recovery path
# can be measured at all.
ELF_LITERALS = (
    (0x00, "premium_license", "one-byte"),
    (0x10, "trial_mode", "one-byte"),
    (0x1C, "vip_pass", "two-byte"),
)


def _elf_section_header(name_off, typ, flags, addr, offset, size, align=8, entsize=0,
                        link=0, info=0):
    """One 64-byte ELF64 section header, in the order the reader unpacks it."""
    return struct.pack("<IIQQQQIIQQ", name_off, typ, flags, addr, offset, size,
                       link, info, align, entsize)


def build_synthetic_elf(with_text=True):
    """(data, meta) for a minimal ELF64 whose `.rodata` holds three known literals.

    The layout is derived here rather than asserted from a table, so a change to any literal's size
    moves the offsets with it and the tests still compare against where the fixture *did* put them.
    """
    text = ELF_TEXT_BYTES
    rodata = b"premium_license\x00" + b"trial_mode\x00\x00"
    rodata += "vip_pass".encode("utf-16-le") + b"\x00\x00"
    rodata += b"\x00" * ((8 - len(rodata) % 8) % 8)
    shstr = b"\x00.text\x00.rodata\x00.shstrtab\x00"

    ehdr_size = 64
    text_off = 0x40
    rodata_off = text_off + (len(text) if with_text else 0)
    shstr_off = rodata_off + len(rodata)
    shoff = shstr_off + len(shstr)
    shoff += (8 - shoff % 8) % 8

    sections = [
        # The NULL section every image starts with; the reader does not special-case it.
        _elf_section_header(0, 0, 0, 0, 0, 0, align=0),
    ]
    if with_text:
        sections.append(_elf_section_header(1, 1, 0x6, ELF_TEXT_VADDR, text_off,
                                            len(text)))
    sections.append(_elf_section_header(7, 1, 0x2, ELF_RODATA_VADDR, rodata_off,
                                       len(rodata)))
    sections.append(_elf_section_header(15, 3, 0, 0, shstr_off, len(shstr), align=1))
    shnum = len(sections)

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH",
                               3,             # e_type = ET_DYN, a shared object
                               0x3E,          # e_machine = EM_X86_64
                               1,             # e_version
                               0,             # e_entry
                               0,             # e_phoff: no program headers
                               shoff,         # e_shoff
                               0,             # e_flags
                               ehdr_size,     # e_ehsize
                               0,             # e_phentsize
                               0,             # e_phnum
                               64,            # e_shentsize
                               shnum,         # e_shnum
                               shnum - 1)     # e_shstrndx: the last section is .shstrtab

    data = bytearray(b"\x00" * shoff)
    data[0:ehdr_size] = ehdr
    if with_text:
        data[text_off:text_off + len(text)] = text
    data[rodata_off:rodata_off + len(rodata)] = rodata
    data[shstr_off:shstr_off + len(shstr)] = shstr
    data.extend(b"".join(sections))

    meta = {
        "size": len(data),
        "text": {"offset": text_off, "vaddr": ELF_TEXT_VADDR, "size": len(text)},
        "rodata": {"offset": rodata_off, "vaddr": ELF_RODATA_VADDR, "size": len(rodata)},
        "literals": [
            {"offset": rodata_off + rel, "vaddr": ELF_RODATA_VADDR + rel,
             "text": value, "encoding": encoding}
            for rel, value, encoding in ELF_LITERALS
        ],
    }
    return bytes(data), meta


class SyntheticElf(object):
    """A generated ELF image plus the offsets its literals were placed at."""

    __slots__ = ("path", "data", "meta")

    def __init__(self, path, data, meta):
        self.path = path
        self.data = data
        self.meta = meta

    @property
    def size(self):
        return len(self.data)

    @property
    def text(self):
        return self.meta["text"]

    @property
    def rodata(self):
        return self.meta["rodata"]

    @property
    def literals(self):
        return self.meta["literals"]

    def literal(self, value):
        """The fixture record for one literal, by its text."""
        for entry in self.literals:
            if entry["text"] == value:
                return entry
        raise KeyError("%r is not one of the fixture's literals: %r"
                       % (value, [e["text"] for e in self.literals]))

    def __repr__(self):
        return "SyntheticElf(%s, %d bytes)" % (self.path, self.size)


def pytest_report_header(config):
    return [
        "exe-reverse suite: python %s, scripts %s" % (sys.version.split()[0], SCRIPTS_DIR),
    ]


class ScriptResult(object):
    """One script run: returncode, stdout, stderr, plus the argv that produced it."""

    __slots__ = ("returncode", "stdout", "stderr", "argv")

    def __init__(self, returncode, stdout, stderr, argv):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.argv = argv

    def __iter__(self):
        return iter((self.returncode, self.stdout, self.stderr))

    def __repr__(self):
        return "ScriptResult(returncode=%r, argv=%r)" % (self.returncode, self.argv)


class BuiltFixture(object):
    """A generated fixture image plus the metadata make_fixture_pe.py returned for it."""

    __slots__ = ("name", "path", "meta", "recipe")

    def __init__(self, name, path, meta, recipe):
        self.name = name
        self.path = path
        self.meta = meta
        self.recipe = recipe

    @property
    def data(self):
        return self.path.read_bytes()

    @property
    def size(self):
        return len(self.data)

    @property
    def sha256(self):
        return hashlib.sha256(self.data).hexdigest()

    @property
    def plant(self):
        """The byte sequence planted twice in .text, as a spaced hex string."""
        return self.meta["plant"]["bytes"]

    @property
    def plant_offsets(self):
        return (int(self.meta["plant"]["first_file_offset"], 16),
                int(self.meta["plant"]["second_file_offset"], 16))

    def section(self, name):
        return self.meta["sections"][name]

    def __repr__(self):
        return "BuiltFixture(%r, %s)" % (self.name, self.path)


class FixtureSet(object):
    """Attribute and index access to the built fixtures."""

    def __init__(self, items):
        self._items = dict(items)

    def __getattr__(self, name):
        try:
            return self._items[name]
        except KeyError:
            raise AttributeError(name)

    def __getitem__(self, name):
        return self._items[name]

    def names(self):
        return sorted(self._items)


@pytest.fixture(scope="session", autouse=True)
def interpreter_gate():
    """Skip everything, with a reason, when the interpreter is older than the scripts require."""
    if sys.version_info < MIN_PYTHON:
        pytest.skip("skills/exe-reverse/scripts declare Python %d.%d+; this session is running "
                    "%s -- install a newer interpreter to exercise the suite"
                    % (MIN_PYTHON[0], MIN_PYTHON[1], sys.version.split()[0]))


@pytest.fixture(scope="session")
def require_local_tool():
    """Skip a check, with a reason, when a tool it needs is not installed."""

    def _need(tool):
        found = shutil.which(tool)
        if not found:
            pytest.skip("local tool %r is not on PATH; this check is inert without it" % tool)
        return found

    return _need


@pytest.fixture(scope="session")
def load_script():
    """Import a tested script by path, once per session.

    ``pepatch.py`` and ``aob_scan.py`` put their own directory on ``sys.path`` and then import
    ``peutil`` by bare name. Registering one shared module per name keeps a single PE class in
    the process instead of two classes that compare unequal.
    """
    cache = {}

    def _load(filename):
        if filename not in SCRIPT_FILES:
            raise ValueError("%r is not one of the tested scripts: %r" % (filename, SCRIPT_FILES))
        name = filename[:-3]
        if name in cache:
            return cache[name]
        if str(SCRIPTS_DIR) not in sys.path:
            sys.path.insert(0, str(SCRIPTS_DIR))
        spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        cache[name] = module
        return module

    return _load


@pytest.fixture(scope="session")
def run_script():
    """Run a tested script as a subprocess and return (returncode, stdout, stderr)."""

    def _run(filename, *args, **kwargs):
        if filename not in SCRIPT_FILES:
            raise ValueError("%r is not one of the tested scripts: %r" % (filename, SCRIPT_FILES))
        timeout = kwargs.pop("timeout", RUN_TIMEOUT)
        cwd = kwargs.pop("cwd", None)
        if kwargs:
            raise TypeError("unexpected keyword arguments: %r" % sorted(kwargs))
        argv = [sys.executable, str(SCRIPTS_DIR / filename)] + [str(a) for a in args]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                  cwd=cwd, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            pytest.fail("%s did not finish within %ds: %r" % (filename, timeout, argv))
        return ScriptResult(proc.returncode, proc.stdout, proc.stderr, argv)

    return _run


@pytest.fixture(scope="session")
def fixture_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("exe-reverse-fixtures")


@pytest.fixture(scope="session")
def build_fixture(fixture_dir, load_script, run_script):
    """Build one named fixture through the real CLI and cross-check it against build_pe()."""
    maker = load_script("make_fixture_pe.py")
    cache = {}

    def _build(name):
        if name in cache:
            return cache[name]
        if name not in FIXTURE_RECIPES:
            raise ValueError("unknown fixture %r; known: %r" % (name, sorted(FIXTURE_RECIPES)))
        recipe = FIXTURE_RECIPES[name]
        dest = fixture_dir / (name + ".exe")
        result = run_script("make_fixture_pe.py", "--out", dest, "--recipe", recipe)
        if result.returncode != 0:
            pytest.fail("make_fixture_pe.py --recipe %s failed with %d: %s"
                        % (recipe, result.returncode, result.stderr))
        data, meta = maker.build_pe(**maker.RECIPES[recipe])
        if dest.read_bytes() != data:
            pytest.fail("make_fixture_pe.py wrote bytes that differ from its own build_pe() "
                        "output -- the CLI and the library disagree")
        built = BuiltFixture(name, dest, meta, recipe)
        cache[name] = built
        return built

    return _build


@pytest.fixture(scope="session")
def fixtures(build_fixture):
    """The four generated images, addressed as ``fixtures.pe64`` / ``fixtures['pe32']``."""
    return FixtureSet({name: build_fixture(name) for name in FIXTURE_RECIPES})


@pytest.fixture(scope="session")
def synthetic_elf(fixture_dir):
    """The generated ELF64, written once for the whole session."""
    data, meta = build_synthetic_elf()
    path = fixture_dir / "app.so"
    path.write_bytes(data)
    return SyntheticElf(path, data, meta)


@pytest.fixture(scope="session")
def synthetic_elf_without_text(fixture_dir):
    """The same image with no `.text`, for the reader's "not an AOT code image" path."""
    data, meta = build_synthetic_elf(with_text=False)
    path = fixture_dir / "no-text.so"
    path.write_bytes(data)
    return SyntheticElf(path, data, meta)


@pytest.fixture(scope="session")
def hwprobe_report(run_script):
    """One host capability report for the whole session.

    The probe executes a CPUID stub, so re-running it per assertion would buy nothing and cost
    seconds. It is a host fact, not a per-test one.
    """
    result = run_script("hwprobe.py", "--json")
    if result.returncode != 0:
        pytest.fail("hwprobe.py --json exited %d: %s" % (result.returncode, result.stderr))
    return json.loads(result.stdout)


@pytest.fixture(scope="session")
def hexpat():
    """Render bytes as the spaced hex form the scripts accept."""

    def _hexpat(obj):
        if isinstance(obj, str):
            return " ".join("%02X" % b for b in obj.encode("latin-1"))
        return " ".join("%02X" % b for b in bytearray(obj))

    return _hexpat


@pytest.fixture(scope="session")
def leak_lines():
    return LEAK_LINES


@pytest.fixture(scope="session")
def exempt_lines():
    return EXEMPT_LINES


@pytest.fixture(scope="session")
def weak_line(leak_lines):
    """A sample that produces exactly one weak finding and no strong one."""
    return dict(leak_lines)["vendor-copyright-line"]


@pytest.fixture(scope="session")
def strong_line(leak_lines):
    """A sample that produces a strong finding."""
    return dict(leak_lines)["windows-user-profile"]


@pytest.fixture
def synthetic_leak_root(tmp_path):
    """A scan surface holding one shaped leak per rule, plus exemption lines."""
    root = tmp_path / "leakroot"
    root.mkdir()
    body = ["# synthetic analysis notes"] + [line for _rule, line in LEAK_LINES]
    (root / "notes.md").write_text("\n".join(body) + "\n", encoding="utf-8")
    (root / "exempt.md").write_text("\n".join(line for _cls, line in EXEMPT_LINES) + "\n",
                                    encoding="utf-8")
    nested = root / "skills" / "exe-reverse" / "references"
    nested.mkdir(parents=True)
    (nested / "deep.md").write_text("no identity here\n", encoding="utf-8")
    return root


@pytest.fixture
def clean_scan_root(tmp_path):
    """A scan surface with nothing to report."""
    root = tmp_path / "clean"
    root.mkdir()
    (root / "notes.md").write_text(
        "Static PE analysis of the generated fixture: sections, imports, checksum.\n",
        encoding="utf-8")
    return root


@pytest.fixture
def platform_binary(require_local_tool):
    """A real platform image to parse, or a skip when this host has none."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for rel in (r"System32\notepad.exe", r"System32\kernel32.dll", r"System32\ntdll.dll"):
        candidate = pathlib.Path(root) / rel
        if candidate.is_file():
            return candidate
    pytest.skip("no platform image under %s (System32 not present); this check is inert here"
                % root)
