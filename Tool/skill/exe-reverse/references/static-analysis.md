# Static analysis: what the listing gives you, and where it lies

Goal: locate the routine that owns a behaviour by following references, before decompiling anything, and
know the point at which static reading stops producing facts.

## When to load this

Load this when you have a binary and no location; when you must decide which routine owns a check before
a debugger session; when a decompiler's output looks convincing and you have no way to check it; when a
listing contains regions that decode into nonsense; when you need function boundaries in a stripped
build; and when you are deciding whether the next step is more reading or a debugger.

## What a disassembler gives you, and its four honest failure modes

A disassembler converts bytes to instructions. It does not know where code starts, where it ends, or
which bytes are code at all. Four failures follow from that, and all four produce output that looks like
a correct listing.

**Data decoded as code.** Bytes reached by fall-through from real code are decoded as instructions even
when they are a jump table, an alignment pad, a string, or a structure. Alignment padding between
functions is the commonest source of nonsense instructions in an otherwise clean listing, and a listing
that shows a long run of plausible-looking instructions in a section that should hold data is telling you
about your disassembler, not about the program.

**A wrong function boundary.** A **tail call** — a final `jmp` to another function instead of a `call` —
makes two functions read as one, because nothing in the bytes marks the transition. Two functions that
share an epilogue at the end of a compiler-merged region produce the same effect. A function with
multiple entry points decodes as overlapping code, so no single boundary is right for both entries. Any
claim of the form "this routine does X" that rests on a boundary the tool inferred should be labelled
`inferred` until a second source agrees.

**An indirect transfer that breaks the listing.** A jump or call through a register, a memory location,
or a table read at run time has no static target. The listing continues at the next byte and decodes
whatever follows, and the real successors of that block are absent from the graph. This is the mechanism
behind every "the decompiler lost half the function" symptom, and behind the classic `switch`: the
dispatch is a table, the table lives in a data section, and the targets are data until you read that data.

**Position-dependent values.** Absolute addresses in the listing are RVAs or preferred-base-relative
values, not run-time addresses, unless the image is loaded at its preferred base. The specification
states that a VA "is not as predictable as an RVA because the loader might not load the image at its
preferred location". A breakpoint set from a listing address is a breakpoint at the wrong place whenever
the image was rebased, and that failure is indistinguishable from "the code was never reached".

## The order that works

Work from the surface inward, and do not decompile a function until you have a reason to believe it owns
the behaviour.

1. **Enumerate the strings and resources**, with their addresses. This is the cheapest surface and the
   one that usually names the feature, the framework and the licence mechanism (`recon.md`).
2. **Find the references to the string you care about.** In a compiled language the address of a literal
   appears as an immediate, a displacement, or a load from a data slot; a string used by a whole feature
   is referenced from the routine that decides about that feature.
3. **Read the referencing routine, not the whole program.** One function, its calls, and its immediate
   branches.
4. **Count the callers of anything you plan to change.** A helper with many callers is not a feature
   gate, and patching it produces the artifact that runs and does the wrong thing.
5. **Only then decompile**, and only to answer a specific question ("does this comparison decide the
   branch, and what does the other side do").
6. **Decide whether static produced the answer.** If the value you need is computed at run time, stop and
   take a debugger or a trace.

## Cross-references: what generates one and how to read it

A cross-reference exists wherever an address is materialised. On 32-bit builds that is usually an
absolute immediate in the instruction stream; on 64-bit builds it is usually a RIP-relative
displacement, which the listing already resolves. Data-driven references — a pointer table holding the
address of a string or a function — produce **no** instruction-stream reference at all, which is why a
string with no xrefs is not evidence that the string is unused; it may be reachable only through a table.

Consequences for your search:

- If a reference-based search finds nothing for a literal you know is used, search for the address bytes
  of that literal in every section, not only in the code section. You are looking for the pointer, not
  the use.
- For a candidate constant, search for the value and for its near neighbours (value ± small delta), since
  a compiler may fold an offset into the displacement.
- Record which search you ran and over what. A negative result is `unknown` with a named search, never
  "the program does not contain it".

## The exception directory is a function table (x64)

Every x64 function the toolchain gave unwind data to has a **runtime function entry** in `.pdata`, and
data directory 3 (the exception directory) points at the array. Each entry is three 32-bit RVAs — begin
address, end address, unwind-info address — and the array is sorted by begin address (`inferred` from
the x64 unwind convention; `observed` that the shipped reader reports the directory and its size).

That makes it the only **exhaustive** function table in a stripped image, and it is worth reading before
any disassembly:

- It gives real boundaries, so the tail-call merge and the shared epilogue described above stop being
  guesses.
- It bounds a function the disassembler would otherwise run past, because the end address is recorded.
- It gives the frame without executing it: the unwind record carries the prologue size, the frame
  register — zero when the frame pointer was omitted — and one code per non-volatile register that was
  saved, with where.

Read it before disassembling. `python scripts/peutil.py APP.exe --summary` reports whether directory 3
is populated and how large it is, and `--json` gives the section table so the RVAs can be mapped to
file offsets. Three checks say whether what you parsed is really a table: begin below end, end inside an
executable section, and entries in ascending order. A record that fails one of them means a different
record layout or a packed image, not a table to be repaired.

Three limits. **Leaf functions may have no entry**, because there is nothing to unwind; a call target
outside every range is therefore a leaf, a hand-written routine assembled without unwind data, or a
splice, and which one it is needs a second observation. **x86 has no such table** — the directory is
normally empty and the exception mechanism is stack-linked instead, so on 32-bit the boundaries come
from exports, symbols, call sites and the frame shapes in `references/assembly-idioms.md`. And **the
record layout is architecture-specific**: an ARM64 image populates the same directory with a packed
encoding, so parse the 12-byte x64 record only when the machine field says `0x8664`.

## Call graph and caller counting

The call graph is the cheapest structure in the file, and it is the one that prevents the single most
common destructive edit. Before changing a routine, answer: how many sites call it, from which code, and
does its return value feed a decision elsewhere?

- Many callers, small body: a helper. Not a gate. Editing it changes behaviour everywhere.
- One or two callers, and those callers sit near the feature's strings: a candidate owner. Read the
  callers before editing the callee.
- Zero static callers, non-trivial body: either a dispatcher target (reachable through a table), an
  exported entry, or genuinely dead. Determine which before assuming dead — with a call table in play, a
  zero-in-degree node is not evidence of unreachability.
- A routine whose result is immediately tested and branched on is a better gate candidate than a routine
  whose result is stored and read much later. The second kind is where "I patched the check and nothing
  happened" comes from.

## Recovering structures from access patterns

Structures do not exist in the file; they exist in how the code reads memory. Recover them from
repetition:

- A base register plus a constant offset used consistently across several functions is one structure.
  Group the offsets you have seen from the same base and treat the gaps as unknown fields.
- The **width** of the access tells you the field size: a byte move, a 2-byte move, a 4-byte move. A
  4-byte slot touched only in the low byte is padding or a flag, not a counter.
- A field compared against a small set of values is likely an enum or a state; a field written and read
  around a call is likely a handle or a result.
- A pointer field followed by a 4-byte length at the next offset is the ordinary shape of a buffer
  descriptor; a table of such pairs is an array of them.

Write the reconstruction down as offsets with your evidence, and keep the field names provisional. A
structure recovered from three accesses is a hypothesis, and a decompiler that accepts your hypothesis
will then render every subsequent access in terms of it — including the accesses that contradict it.

## Reading a switch or a dispatch

A dispatch has three parts and each is checkable. A **bounds check** against a value — a compare against
a small number, or a subtract-then-compare idiom. A **table**: an array in a data section indexed by the
value, holding either addresses or offsets. A **transfer** through that entry.

Static reading gives you the bounds and the transfer; it cannot give you the table's contents, because
the table is data. So the honest sequence is: confirm the bounds check statically, then read the table
from the file at its known address, and only then claim you know the set of targets. A dispatch whose
table contents you have not read is a dispatch with unknown targets — and if the value being dispatched
on is loaded from memory rather than computed nearby, you are looking at a different problem class:
`virtualization-and-flattening.md`.

## When decompiler output is trustworthy

Decompiled code is a **hypothesis about the program**, rendered confidently. Treat it as trustworthy when
several independent readings agree.

| Trustworthy | Suspect |
|---|---|
| Small function, few local variables, no indirect transfers | Heavy indirect calls or a dispatch whose table was not read |
| The call sequence matches the listing instruction for instruction | A call target the tool "resolved" through a cast you cannot see |
| Stack frame and parameter count match the actual accesses | Parameters whose count was inferred from a convention rather than from accesses |
| The reconstructed types do not explain away an access | Two variables that overlap the same stack slot |
| The control flow survives a re-read of the listing | A single expression with many `goto`s and one enormous condition |

Two counter-checks cost little and catch most fabrications. First, pick one block of the decompiled
output and verify each instruction against the listing: if the tool invented a call, it will show up.
Second, look for a **missing side effect** — a store, a flag write, or a call that the decompiler dropped
because it did not understand the target. A decompiled function that is shorter than the listing it came
from is a decompiler that discarded something.

## Symbols and types, and what to do without them

Sources of names, in order of cost:

- The debug directory's CodeView record gives a symbol-file path and a build identity. A matching symbol
  file is the whole problem solved; a mismatched one is worse than none, because it produces confident
  wrong names.
- The export table gives names for the library's public surface; it gives nothing for internal routines.
- A `.symtab` section present in an image gives symbol names even in some statically linked builds
  (`compiler-fingerprints.md` documents a real case).
- C++ runtime type information and exception handling give class names and, on 64-bit images, function
  extents that bound the disassembler's guesses.
- Absent all of the above, names come from behaviour: the string a routine references, the API it calls,
  the resource it reads. Name by evidence and mark the name as yours.

## Where static analysis stops

Stop reading and instrument when:

- The value you need is produced at run time — a decryption result, an environment query, a server
  response, a hash of the running image. Reading the producer tells you the shape of the value, not its
  value.
- The code you are reading is not the code that runs: packed, decrypted in place, or generated. The
  listing is of the stub.
- The decision depends on state you cannot see in the file: registry, licence storage, a clock, a server
  answer.
- You have read the same function three times and cannot state what its return value means. That is not a
  reading problem; it is a missing measurement.

Then take `dynamic-debugging.md`, and prefer a hardware breakpoint or a trace when the target treats
software breakpoints as evidence (`anti-analysis.md`, `hardware-tracing.md`).

## The limit that applies to everything above

Reading is not reachability. Static analysis can show you exactly what a routine would do and prove
nothing about whether it runs on your host, in your configuration, for your account. Every conclusion of
the form "this is the check" is a location claim, and location claims are verified by observation — by
hitting the routine, by seeing the branch taken, by watching the outcome change. Until then it is
`inferred`, and it must be reported as `inferred`.
