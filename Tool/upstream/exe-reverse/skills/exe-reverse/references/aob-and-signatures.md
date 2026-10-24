# Array-of-bytes signatures

Goal: a pattern that finds the same site on the next build, with a recorded match count and the build
identity it was verified against. A signature is a hypothesis, and it is only as good as its record.

## When to load this

- The same patch has to be applied to several versions or several builds.
- A signature-based patch worked on one version and misses on the next.
- A pattern matched, the patch applied, and the behaviour did not change.
- You are writing a signature down for someone else to reuse.

## What a signature can and cannot promise

A signature finds bytes. It does not know what those bytes mean, which function they belong to, or
whether the code path is reached. Every failure in this file is a version of that gap, and the
discipline that closes it is: anchor on something structural, count the matches, and verify by
behaviour rather than by byte equality.

## Which bytes are volatile, and therefore wildcards

| Byte class | Why it moves between builds | Wildcard? |
|---|---|---|
| Relative call or jump displacement | the target's distance changes whenever anything between the two sites is added, removed or reordered | yes, always |
| Immediate operand | a constant, an index, or a small enum value that is edited independently of the structure | yes, unless the constant is itself the anchor |
| RIP-relative displacement | the distance from the instruction to the referenced data depends on both sections' layouts | yes |
| Register encoded in a ModRM, SIB or REX byte | register allocation changes with the surrounding code | usually yes; keep the opcode, wildcard the register bits |
| Stack frame size, spill slots | function body changes | yes |
| Opcode of a branch you are about to edit | this is the site, not context | no, it must be exact |
| Structural context (prologue shape, neighbouring call, string reference) | stable under editing of unrelated code | no |

The platform's own relocation records exist because of the first and third rows: on x64, a relative
displacement in the code is described by a relocation whose type is relative to the byte following the
relocation (`observed`; PE Format specification, x64 relocation type indicators such as
`IMAGE_REL_AMD64_REL32`). Anywhere such a relocation can exist, the four bytes are recomputed by the
toolchain on the next build and cannot be part of an exact pattern.

A practical pattern reads as: three to eight bytes of opcode-level structure, with wildcards over every
displacement, immediate and register field, plus enough of the following instruction to pin the
distinction between similar sites.

## Over-broad and over-narrow

| Symptom | Diagnosis | Move |
|---|---|---|
| Matches many sites, or matches in data as well as code | the pattern encodes nothing distinctive | add the instructions after the site, or add a reference to a nearby string or import |
| Matches exactly once today and zero times after a rebuild | the pattern contains a displacement, an immediate, or a register encoding | wildcard the volatile bytes and re-verify on both builds |
| Matches exactly once, and the patched behaviour is unchanged | the site is real but is not the gate; or the same shape exists in an unrelated routine that was reached first | anchor on structure that is unique to the owning routine, and confirm by a call-chain or a breakpoint |
| Matches exactly once in every build you have, and fails on the next minor release | one build configuration was represented in your sample set | verify on a debug build, a 32-bit build, and a differently optimised build before publishing |
| Matches inside an overlay, resource or packed region | the region is data, not the code you are thinking of | constrain the search to executable sections and confirm the hit's section is one that holds code |

An over-broad pattern is worse than a miss, because a miss is visible. An over-broad pattern applies
the edit to the wrong site, the target still starts, and the failure appears somewhere else entirely.

## Match counts

One match is the default that needs no justification. More than one match is acceptable only when the
extra matches are explained and the chosen one is pinned explicitly:

- **Refuse ambiguity rather than taking the first hit.** The patcher raises an error on a multi-match
  pattern unless an index is supplied, and prints the candidate offsets and their RVAs in the error, so
  the refusal is also the information you need to disambiguate (`observed`; reported behaviour of
  `scripts/pepatch.py`).
- **A pinned index is part of the signature, not a detail.** Record the index, and record the offsets
  it resolved to on the build you verified. An index means "the third match", and the third match is a
  different site as soon as a match is added or removed earlier in the file.
- **`allow-many`-style bulk application is for a genuinely repeated edit** such as neutralising the
  same inlined comparison of a shared helper. It is not a way to avoid making the pattern specific.

## Anchoring on structure instead of on bytes that moved

When migrating a signature to a new version, decide what you are anchoring on, in this order:

1. **The call graph.** The routine's callers and callees move less than its body. Anchor on a call to an
   imported function that only this routine makes, with wildcards over the displacement.
2. **String and data references.** A reference to a message, a registry path, a file name or a format
   string that belongs to the feature. The reference is relative and therefore wildcarded; the address
   it resolves to is checked separately by reading the referenced data, not by trusting the bytes.
3. **The prologue's shape.** Stack frame size, the number and order of callee-saved registers pushed,
   and the presence of a stack cookie are usually stable across unrelated edits, though a compiler
   upgrade or a different optimisation level changes them.
4. **The surrounding basic-block structure.** The sequence of compares and branches around the site,
   with all constants wildcarded.
5. **The immediate that encodes the decision.** Last, because it is the value a rebuild is most likely
   to change, and because on a new version the comparison may have been folded into a different
   instruction form.

The migration procedure:

1. Find the site in the new build with the loosest pattern you can justify, and count the matches.
2. Tighten the pattern until the count is one, adding constraints that are structural rather than
   byte-exact.
3. Re-run the tightened pattern against every older build you have. A pattern that only fits the newest
   build is a per-build pattern, and it should be labelled as one rather than sold as durable.
4. Resolve the site, read the expected bytes, and confirm they are what the edit assumes. An edit whose
   premise is wrong is how a migration produces a silent no-op.
5. Apply, re-read the written file, and verify by behaviour on the new build.

```
python scripts/pepatch.py APP.dll --pattern "E8 ?? ?? ?? ?? 85 C0 74" --pattern-offset 5 --bytes "75" --expect "74" --at-hit 0 --out APP.patched.dll --dry-run
python scripts/pepatch.py APP.dll --pattern "48 8B 0D ?? ?? ?? ?? 48 85 C9 74" --pattern-offset 14 --bytes "EB" --expect "74" --out APP.patched.dll
```

## Failure modes

**The pattern matches data rather than code.** A sequence of identical or near-identical bytes exists in
a table, a resource, a string, or an embedded blob. Tells: the hit's section is not the code section;
the bytes after the match do not decode as a plausible continuation; the same pattern also matches in a
file that does not contain the feature at all. Constrain the search to executable sections, and confirm
the hit by decoding forward from it.

**The pattern survives the rebuild but points at a different function.** Linkers place identical
functions with the same shape in unpredictable order, compilers emit identical thunks, and small
helpers are inlined into several callers. A pattern built from a short common shape will match the same
number of times in a new build while pointing at a different member of the set. Tell: the match count
is unchanged but the resolved RVA no longer corresponds to the routine you identified, checked by
walking to the owning function from the hit rather than by trusting the match.

**The pattern only works for one build configuration.** Four configurations defeat most signatures:
optimised versus unoptimised, 32-bit versus 64-bit, static versus dynamic runtime linkage, and inlining
or link-time code generation on versus off. Signature bytes are not portable across them, and a
signature verified on one says nothing about the others. State which configuration each signature was
verified on.

**The pattern relies on a fixed file offset.** Any insertion earlier in the file invalidates it. A
pattern is the fix, not the complement, and a file offset may be recorded only as the verification
result for one build.

**The pattern spans a relocation.** The four bytes in the middle are recomputed at link time; the
pattern works on your build and on no other. This is the most common cause of a signature that is
stable across a rebuild of the *same* source but missing after any code change at all.

## Recording a signature so it is reusable

Record enough that another person can decide whether it applies to their build without re-deriving it.
The build identity matters as much as the pattern: the format's own timestamp field is explicitly not
meaningful when it is zero or all-ones, and it is a field a build system may write for reasons other
than wall-clock time, so it is a weak ordering key (`observed`; PE Format specification, date/time stamp
row). Use the file hash as the identity and the metadata as the description.

```
site:            licence comparison in the validate routine
pattern:         E8 ?? ?? ?? ?? 85 C0 74
wildcards:       call displacement (rel32)
pattern-offset:  +5  (the conditional)
expected bytes:  74  (Jcc rel8, short distance)
replacement:     75  (inverted condition)
build identity:  ProductVersion 4.2.1.0, x64, release, static runtime
file hashes:     original  <sha256>, patched <sha256>
matches:         1  (offset 0x0009A2C6, rva 0x0009B8C6)
verified against: old 4.1.7 (1 match, same site), new 4.2.1 (1 match)
reached at run time: yes, the feature under test changed behaviour; observed / not observed
```

Two fields are usually left out and both are the ones a later reader needs: the match count with the
resolved offsets, and the statement that the site was reached at run time. A signature with only a
pattern and a replacement is a claim that a patch lands, and landing is not the interesting part.
