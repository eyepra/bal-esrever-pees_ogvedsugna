# Regression matrix — exe-reverse

The measured record behind `tests/`: one row per dimension, with the target, the scripts it
exercised, the result this host produced, and how strong that result is.

## When to load this

Read it when you need to know what was actually run rather than what the suite covers, or when a
coverage claim needs a target and a number behind it. `tests/README.md` describes the suite;
this file records its output.

## How a row is filled in

Every row below was produced by running the command in it on this host, except where the row says
otherwise in the result column. Rows that were not run say so and are not filled with an estimate.
Strength labels follow the repository convention: `observed` means the command and its output
exist, `inferred` means the result is reasoned from an observation, `unverified` means it is
reported but was not reproduced here.

Targets are public and legally usable: the generated fixture, and platform binaries that ship with
the operating system. No third-party product is a target, and no sample is stored in the
repository — the images are built at test time into a temporary directory.

Environment: Windows 11 build 26100, Python 3.14.0, pytest 8.4.1.

## The matrix

| Dimension | Target | Scripts exercised | Measured result | Strength |
| --- | --- | --- | --- | --- |
| PE32+ header surface | generated fixture, `default` recipe | `peutil.py` | 4096 bytes, 5 sections, magic 0x20B, entry RVA 0x1000, image base 0x140000000, declared checksum 0x10bad, zero warnings | observed |
| PE32 header surface | generated fixture, `pe32` recipe | `peutil.py` | magic 0x10B, machine 0x014C, image base 0x400000, same five sections | observed |
| Optional-header layout difference | both fixtures | `peutil.py` | number-of-directories lives at optional+92 (PE32) or optional+108 (PE32+), directories at +96 or +112; reading the other layout yields 40 and 0 respectively, neither being the real count 16 | observed |
| RVA to file offset, both directions | generated fixture | `peutil.py` | 0x1010 to 0x410 and back; header RVAs identity below SizeOfHeaders 0x400; an RVA in no section maps to nothing | observed |
| Virtual-only tail | generated fixture | `peutil.py` | `.rdata` has 1408 virtual and 512 raw bytes, so 896 bytes have no file image; RVA 0x2200 resolves to nothing while 0x21FF resolves to 0x9FF | observed |
| PE checksum | four generated recipes | `peutil.py` | declared equals computed equals a second, independent implementation of the published algorithm | observed |
| PE checksum on real images | platform binaries under `%SystemRoot%\System32` | `peutil.py` | `notepad.exe` (360448 bytes) declared 0x5e673 equals computed; `kernel32.dll` and `ntdll.dll` parse with matching checksums | observed |
| Imports | generated fixture | `peutil.py` | one DLL with one named import (hint 7) and one import by ordinal 0x2A, descriptor terminator respected, no delay imports | observed |
| Exports, resources, TLS, debug, relocations | generated fixture | `peutil.py` | one named export; the resource tree is exactly VERSION / 1 / 1033 with a 4-byte leaf; TLS callback RVA 0x1000; RSDS record with the fixture's PDB path and age 1; one relocation block with two entries | observed |
| Pattern locating, three verdicts | generated fixture | `aob_scan.py` | the planted pair reports 2 hits as `ambiguous` and exits 1; the PDB string reports 1 hit as `unique` and exits 0; an absent pattern reports 0 as `no-match` and exits 1 | observed |
| Verdict boundaries | generated fixture | `aob_scan.py` | 0 to `no-match`, 1 to `unique`, 2 through 7 to `ambiguous`, 8 and above to `pervasive` | observed |
| Equal-length patch and verification | generated fixture | `pepatch.py`, `peutil.py` | one patch at 0x410 pinned with `--expect`; the written file re-reads with no verification problems and a recomputed checksum of 0x10c24; exactly 3 bytes differ from the input, the patched byte and 2 checksum bytes | observed |
| Ambiguity refusal | generated fixture | `pepatch.py` | exit 1, `matched 2 sites`, no output file created, input hash unchanged | observed |
| Expect-mismatch refusal | generated fixture | `pepatch.py` | exit 1 with `the site moved or the wrong binary is open` | observed |
| Length discipline | generated fixture | `pepatch.py` | no `--expect` and no `--original-length` reports `[length unproven: pass expect or original-length]`; a 1-into-3 byte patch is refused without `--allow-resize`; with it, the run is marked structural and the file length is unchanged because the write is in place | observed |
| Dry run | generated fixture | `pepatch.py` | exit 0, no file created, input hash unchanged | observed |
| Control run, no-op patch | generated fixture | `pepatch.py` | output SHA-256 equals input SHA-256: the file is byte-identical, checksum included | observed |
| Cross-build comparison | two independently built fixtures | `aob_scan.py` | same recipe 1 versus 1, exit 0; `bare` recipe 1 versus 0, exit 1; patched build 2 versus 1, exit 1; a pattern with 2 hits on both sides still exits 1 because the count agreeing is not the same as the pattern being usable | observed |
| Identity scan, rules | synthetic corpus in a temporary root | `scan_leaks.py` | all 18 rules fire on their shaped samples; the corpus reports 13 strong findings and 4 weak, exit 1 | observed |
| Identity scan, exemptions | same corpus | `scan_leaks.py` | tool, protector, format, platform, placeholder, documentation-address and well-known-SID samples produce no finding; 19 hits suppressed | observed |
| Identity scan, clean surface | temporary root with no identity in it | `scan_leaks.py` | `RESULT=clean`, exit 0 | observed |
| Identity scan, this suite's own surface | `tests/` | `scan_leaks.py` | `RESULT=clean` with 0 strong, 0 weak and 19 suppressed hits | observed |
| Identity scan, the skill's own default surface | `skills/` (the root the script resolves with no arguments) | `scan_leaks.py` | 1 strong finding — a standard platform name read as a product identity bound to a version — with 18 suppressed, exit 1 | observed |
| Host capability probe | this machine | `hwprobe.py` | 8 routes, 3 of them `available`, exit 0; 2 rows answer with a sentence instead of one of the three documented states | observed |
| Suite runtime | this machine | `pytest` | 269 tests in 23.2 s: unit 1.5 s, cli 19.7 s, integration 4.6 s | observed |
| Reader throughput | 360448-byte platform image | `peutil.py` | `--summary` took 159 / 162 / 157 ms over three runs | observed |
| Feature-probe cost | this machine | `hwprobe.py` | `--json` took 1834 / 1821 ms over two runs | observed |
| Fixture reproducibility | generated fixture | `make_fixture_pe.py` | the same recipe produces the same SHA-256 and the same bytes on repeated runs; the `no-virtual-tail` recipe exits 1 and writes nothing | observed |
| Truncated-image handling | fixture cut off mid-header | `peutil.py`, `pepatch.py` | both print a traceback and exit non-zero instead of using their documented exit codes; a fully non-PE input does use them | observed |
| Missing spec file | `pepatch.py` with an absent `--spec` | `pepatch.py` | traceback rather than the documented usage error | observed |
| Bare JSON pattern array | `aob_scan.py` with a top-level array | `aob_scan.py` | `AttributeError`; only the object form is accepted | observed |
| Documented empty-surface exit code | `scan_leaks.py` over an empty directory | `scan_leaks.py` | exit 0 with `RESULT=clean`; the documented exit 3 has no code path | observed |
| Patched image launch | a copy of a platform binary patched at the entry point | `pepatch.py` | not run by this suite. Recorded from the project's measurement pass: one byte changed 48 to CC, exactly two bytes differed from the original (the patched byte and the checksum field), and the process terminated with exit code 0x80000003 about 4.0 s after launch while the unpatched copy showed no surviving process | unverified here |
| Device, debugger, network and driver routes | none | none | not run. This suite has no device, no debugger, no network and no kernel component; those routes are conditional host facts and are reported by `hwprobe.py` instead | unknown |

## Measurements obtained in this run

Reader throughput on a 360448-byte platform image, `peutil.py --summary`, three consecutive runs:
159 ms, 162 ms, 157 ms. Host capability probe, `hwprobe.py --json`, two runs: 1834 ms and 1821 ms.
Both sit within a few percent of the values recorded during the project's earlier measurement pass
(158/166/167 ms and 1858 ms), which is the expected spread for process startup on a busy desktop.

Suite runtime, `python -m pytest -q` from the repository root: 269 passed in 23.2 s. The cli layer
dominates because it starts a fresh interpreter per assertion, twice over for the feature probe.

Exact byte-level effect of a two-byte patch at file offset 0x410: three bytes differ from the
input, at 0x410, 0xD8 and 0xD9. The checksum field is four bytes wide, so a patch that changes two
bytes of image data can leave part of the old checksum value already correct.

## Rows not run

No row in the matrix covers a debugger attach, a hardware breakpoint, a trace capture, a driver
load, a network endpoint, a device, or a live target process. That is the suite's stated boundary,
not an oversight: none of those can be asserted deterministically on a bare checkout, and a row
that claims them would be describing a different machine on a different day.

Two further dimensions were considered and left out. Mass-scanning a large directory of real
images was left out because the time it takes depends on the machine's disk rather than on the
scripts. Comparing two builds of the same third-party product was left out because no such pair is
publicly usable here; the two-build comparison in the matrix uses two images this repository
builds itself.

## Notes for a reader of the results

The one strong finding on the skill's own default surface is also the only failing repository gate
at the time of writing: the tracked-surface scan reads the standard platform name `TPM 2.0` in a
shipped reference as a product bound to a version. Nothing in `tests/` contributes to it — this
suite's own surface reports 0 strong and 0 weak.

The scripts under `skills/exe-reverse/scripts/` were being edited while this matrix was being
produced, and two of its rows moved with them: the public-address rule gained an exclusion that
stops it reading a four-part version number as an address, and a standard-name exemption that had
suppressed every URL finding was corrected. Both the suite and this file record the state after
those corrections. Re-run the matrix after any further change to those scripts rather than
trusting these numbers.
