# Recovering a key, hash or licence algorithm

Goal: try the cheapest identification first, and treat a recovered algorithm as an inferred equivalence
until it reproduces the target's own outputs on real inputs.

## When to load this

- A licence, activation or key-derivation routine has to be understood well enough to reproduce its
  output.
- The algorithm is clear in shape but the constants come from somewhere you cannot see.
- You have found a signature or hash routine and need to know whether it is a standard one.
- Someone has asked for a key generator rather than a patch.

## The order that costs least

1. **Identify a known algorithm from constants.** Free when it works, and it works more often than any
   other step here.
2. **Identify from tables.** A 256-entry substitution table is a fingerprint even when the constants you
   see are only the table's first bytes.
3. **Identify from instruction patterns.** Round structure and the mix of operations narrows the family
   when the constants are obfuscated.
4. **Identify from library calls.** If the target calls into the platform's cryptography, the algorithm
   is named in a parameter, and there is nothing to reverse.
5. **Only then reverse the routine.** This is the expensive step, and it is the one people start with.

## Constants that identify a primitive

These are the values to search for first. Each is a primary-source fact, not a recollection.

| Algorithm | Distinguishing constants | Source |
|---|---|---|
| SHA-256 | round constants begin `428a2f98 71374491 b5c0fbcf e9b5dba5`; initial hash value `H(0)0 = 6a09e667` through `H(0)7 = 5be0cd19` | `observed`; RFC 6234 (US Secure Hash Algorithms) text |
| MD5 | state initialised to `0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476` | `observed`; RFC 1321 (the MD5 reference implementation in its appendix) |
| CRC-32 (IEEE 802.3 form) | the reflected polynomial `0xedb88320`, used in the table-generation loop as `c = 0xedb88320 ^ (c >> 1)` | `observed`; RFC 1952 (gzip) sample code |

Three more shapes worth recognising without a constant:

- **A 16-byte block of near-random constants used as a state initialiser** indicates a digest in the
  MD/SHA family; the count of 32-bit words tells you which one, and the word count follows from the
  digest length.
- **A four-entry state with a 64-entry constant table of 32-bit values and a per-round rotate amount** is
  the MD5 family; the same shape with 64 constants followed by 16 more constants is the SHA-2 family.
- **A 256-entry table of 32-bit words** is a CRC table when the values share a structure (each entry is
  the previous one shifted and conditionally XORed) and a key-schedule table when they do not.

## Tables as fingerprints

| Table shape | Read as |
|---|---|
| 256 bytes, a permutation of the byte range, no arithmetic relation between neighbours | a substitution box; the cipher standard's own table also ships its inverse as a second 256-byte table, and the pair together is stronger evidence than either alone. Compare the byte values against the published standard (the AES publication, FIPS 197) rather than recalling them |
| 256 bytes containing the identity sequence `00 01 02 ... FF` at initialisation, later shuffled by a swap loop driven by a key | the key-schedule setup of a byte-oriented stream cipher. This cue is descriptive of the algorithm rather than reproduced from a primary source in this pass, so treat it as `unverified` until you confirm it against the algorithm's definition |
| 256 entries of 32 or 64 bits | a CRC table or a key-schedule constant table; distinguish by the shift-and-xor relation between neighbours |
| 52 or 64 bytes of mixed values used as a round-key expansion source | a block cipher key schedule, not a hash |
| A table whose entries are addresses | a dispatch table, not cryptography. Read it as control flow, not as key material |

The refinement step that turns a shape into an identification: dump the table, check whether it is a
permutation (every value present exactly once) or a general mapping, test whether the second table is
the inverse of the first, and compare the first handful of entries against the standard. Do not identify
a cipher from one byte.

## Instruction-pattern fingerprints

- **Repeating identical round blocks.** The same sequence of rotate, add, XOR and message-schedule
  operations repeated 16, 20, 64 or 80 times, with only the round constant changing, is an unrolled hash
  or block cipher. The repetition count is itself an identifier: a modified round count is the single
  most common way a standard primitive stops being standard.
- **A rotate-and-add mixture with a delta constant.** Small 32-bit deltas added repeatedly, with shifts
  and XORs, indicate a Tiny Encryption Algorithm-family cipher rather than a standard one. These are
  custom by construction, and the recurrence is usually short enough to read directly.
- **A long chain of byte-wise table lookups with no arithmetic.** Substitution-heavy code with one
  table read per output byte is a stream cipher or a byte-oriented cipher; the interesting part is where
  the key enters, not the loop.
- **A multiply by a large odd constant followed by a rotate.** General-purpose hashing (non-cryptographic
  mixing) rather than a cryptographic primitive.
- **Bytes loaded from a table addressed by an index derived from the input, with the table read
  once per output byte and the index itself updated by a second table read.** This is the shape of a
  permutation-based keyed transform; identify the two tables before reading the loop.

## Library calls that remove the work

When the target uses the platform's cryptography, the algorithm is a parameter, not code:

- The modern primitive interface takes the algorithm as a **string**: the documented provider-opening
  entry point accepts a Unicode algorithm identifier that is "one of the standard CNG Algorithm
  Identifiers" or a registered alternative (`observed`; `BCryptOpenAlgorithmProvider`, `pszAlgId`).
  Consequence: the algorithm name is ordinary data in the image, findable as a string, and the
  identification step is a string lookup rather than a reversing problem.
- The older interface passes an **numeric algorithm identifier**, so the value is a small immediate
  rather than a name. Read the constant table from the headers the toolchain ships instead of recalling
  what a number means; a misremembered identifier sends you looking for the wrong primitive.
- Key-derivation helpers exist as documented functions; when the target calls one, the interesting
  question becomes the input (password, salt, iteration count) rather than the algorithm.

Search order for this step: the import table first, then strings for algorithm names, then the
argument setup around any call into a cryptography module.

## Standard, modified, or standard-with-a-modified-input

These are three different findings with three different consequences for a key generator.

| Finding | Evidence | Consequence |
|---|---|---|
| Standard primitive | constants match the standard; the round count and state sizes match; the digest of a known input matches a published test vector | Reproduce with a standard implementation; the work moves to the input |
| Modified primitive | constants match but the round count, the initial state, the constant order or the output truncation differs | A standard implementation will not reproduce the output; the modification has to be recovered |
| Standard primitive, non-standard input | the primitive is standard and its input is not the obvious message | The algorithm is not the problem; locate how the input is assembled, including any per-machine or per-run component |

The four modifications that appear most often, in order of frequency: a non-standard initial state, a
changed round count, an extra operation folded into the final step (an additional XOR or add with a
constant), and byte-order changes on the input or the output. Each of these is cheap to test: run the
standard implementation and compare on a known input, then change one thing at a time.

## Where the key material comes from

| Provenance | How it looks in the binary | What it changes about the deliverable |
|---|---|---|
| Embedded | a byte array in a data section referenced by the routine, or an immediate built up with shifts and ORs | Portable: the key travels with the algorithm |
| Derived from the host | an input assembled from machine identity values before the key derivation | Not portable: the same algorithm produces a different result on another host |
| Fetched | an input that arrives from a network response, or from a file written by another component | The algorithm alone is insufficient; the transport is part of the input |
| Obfuscated as arithmetic | no key array at all, only constants combined by XOR, rotate and add sequences, sometimes inside the loop | The value exists only at run time; dump it after the computation instead of reading the code |
| The output of the check itself | the routine consumes the licence's own fields as key material | Two problems, one shape: the algorithm and the licence format are entangled |

Two details that decide whether a key generator is even possible: whether the key is **fixed** for the
product or **per-licence** (per-licence means the generator needs the issuing side's private input), and
whether any input is **per-run** (a timestamp, a nonce, a session value). If either is true, a generator
is the wrong deliverable and the honest answer is a patch or a report.

## A constant that is computed at run time

The tell is a data reference that is written before it is read, or a routine that runs before the
licence code and populates a buffer later used as a key. Three shapes:

1. **Arithmetic on immediates.** A loop that builds a key from constants and a small operation. Dump the
   buffer after the loop, or emulate the loop, rather than reading its disassembly.
2. **A value that depends on the host or the clock.** The computed value differs between runs; two dumps
   taken at different times do not match, which is the diagnostic. Record both dumps and the inputs.
3. **A value that arrives from outside.** The buffer is written by a routine whose argument came from a
   file, a registry value or a response. Follow the data, not the arithmetic.

In all three, the efficient move is to obtain the value rather than to derive it: instrument the moment
it is used, or dump the buffer immediately before the call that consumes it, then work backwards from a
known-good value.

## Validating a candidate implementation

Never validate against your reading of the disassembly. Validate against the target's own outputs:

1. **Collect input/output pairs from the target.** Instrument the routine's entry and exit, or drive the
   feature with inputs you control and record what the target produces. Thirty pairs beat one.
2. **Implement the candidate and compare.** Bit-for-bit on the output; a partial match means the shape is
   right and a detail (round count, initial state, byte order) is wrong.
3. **Include at least one input outside the comfortable range**, such as an empty input, a length that is
   an exact block multiple, and a length that is one byte over. A candidate that matches on aligned
   inputs and fails on the boundary usually has the padding or the finalisation wrong.
4. **Re-run the comparison after any change**, and keep the passing pair set as the evidence.

| Evidence | What it supports |
|---|---|
| Constants match a standard, nothing else tested | identification of the primitive, `inferred` |
| Candidate reproduces the target's output on N recorded pairs | equivalence demonstrated for those inputs, `observed` |
| Candidate reproduces the output on inputs outside the recorded set, produced independently from the target | equivalence beyond the sample, still `inferred` for untested inputs |
| Candidate reproduces the output on every input type the feature accepts, as exercised end to end | the closest thing to a proof available from outside, and it still expires with the next version |

## The honest boundary

A recovered algorithm is an **inferred equivalence** until it is exercised against real inputs. Before
that point it is a reading of a disassembly, and readings of disassemblies are the least reliable
artifact in this domain: a single wrong round count or a swapped byte order produces output that looks
plausible and is wrong for every input but the one you tried.

State the boundary explicitly in the result: which inputs the equivalence was demonstrated on, which
inputs it was not, and what would falsify it. Two consequences worth writing down rather than
discovering later. An equivalence demonstrated on the outputs of one build is not automatically valid
on the next build of the same product. And an equivalence that holds for the values you captured may
still fail on a value the target derives from its environment, which is the case where a generator
appears to work for the author and fails for everyone else.
