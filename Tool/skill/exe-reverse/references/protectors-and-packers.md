# Protectors and Packers

Goal: decide whether the layer you are looking at is a **compressor** or a **protector**, then reach code
you can analyse or patch by the cheapest route that actually produces the deliverable.

## When to load this

Load it when the file does not want to be read:

- the first code section looks like noise, or its entropy is flat and high across the whole section
- the entry point is outside the first code section, or inside a section marked executable and writable
- the import table resolves to almost nothing, or to names that are obviously wrong
- strings you expect from the user interface are absent
- the sample contains a large writable-and-executable region that is empty on disk
- a dump runs, but every call lands in a jump table, or the code differs after a restart
- you are about to write off the target as impossible

The last row is the one that matters. "It is packed" is a diagnosis with several routes behind it, and
exactly one of them is unpacking.

## Two layers, and why the distinction decides the route

| | Compressor | Protector |
|---|---|---|
| What is on disk | The original image, compressed as one stream | Selected regions transformed, with checks interleaved |
| What runs first | A stub that decompresses the whole image, then transfers control | A stub that decrypts on demand, and stays resident |
| Restored code | Byte-identical to the original, at one moment in time | Restored in pieces, possibly re-transformed later |
| Import table | Usually intact and readable, unless the packer goes out of its way | Frequently destroyed, hidden, or rebuilt at run time |
| Route | Decompress, then analyse the original | Recover the entry point, dump, and repair |
| Cost profile | Bounded: one procedure, then ordinary work | Unbounded: each mechanism is its own problem |

**Compressor.** The original code exists on disk, in compressed form, and is restored wholesale. The
compression ratio is the point, and the packer usually advertises that it is not a protection tool at all.
One documented open compressor states in its own README that it will never add protection or encryption
and calls the confidence such features give false (`observed` in this project's vendor-documentation
pass). A file packed this way is a file you can usually return to its original bytes, and then the work
is ordinary reverse engineering.

**Protector.** Code is decrypted selectively, and checks are interleaved with the code that runs. There is
no single moment at which the whole original image exists in memory: pages are decrypted when needed and
may be re-encrypted afterwards. Vendors of virtualising protectors document that virtualising the entry
point prevents manual unpacking, and the mechanical reason is that the original entry point stops being
machine code at all (`inferred`).

**The practical consequence.** With a compressor, unpacking is a step. With a protector, unpacking is a
project, and the honest question is whether the deliverable needs it.

## Recognising the layer from observable evidence

All of these come from the file itself, before any execution.

| Evidence | What it indicates | Strength |
|---|---|---|
| Section names that are not the usual compiler-emitted set, or a small odd set | A packer or protector wrote the table | `inferred` |
| One section with a raw size far smaller than its virtual size | The real code is created at run time; the section is a destination, not content | `inferred` |
| Entropy near maximum across an entire executable section on disk | Compressed or encrypted content | `inferred` |
| Entry point RVA outside the first executable section | The stub is not the program; the real entry point is computed later | `inferred` |
| Import directory present but resolving to one or two libraries | The real imports are resolved by the stub at run time | `inferred` |
| Import directory absent or pointing into a writable section | Import destruction, documented as a feature by more than one commercial protector | `observed` in this project's vendor-documentation pass |
| A writable and executable section, or a section that becomes executable after a protection change | Self-modifying stub, or a run-time code region | `inferred` |
| A thread-local-storage callback array pointing at code | Work is done before the entry point ever runs | `observed`: the PE specification documents the callback array as a null-terminated array of TLS callback functions, called with a process-attach reason when a new process has started |
| A relocatable image whose relocations are stripped | The image will only load at its preferred base, or the protector moved them | `inferred` |
| Size on disk far smaller than the sum of virtual sizes | Compression | `inferred` |

**Entropy is a heuristic, not a test.** A large embedded resource, a compressed installer payload, or a
JPEG in a resource section produces the same reading as encrypted code. Confirm with a second kind of
evidence, and record which evidence you used.

## Locating the original entry point

The original entry point (OEP) is the address the program's own startup code begins at. The route is
always the same shape: get control back after the stub has finished its work, and record where it jumps.

Approaches, in increasing cost:

1. **Follow the transfer of control statically.** The stub ends with an indirect jump or a return into a
   computed address. If the address is computed from a table you can read, you can compute the OEP without
   running anything.
2. **Stop after the first memory protection change that makes a region executable.** A stub that writes
   code has to make that code executable before it can run it. A breakpoint on the protection change is
   the classic single-shot approach, and it is usually the cheapest dynamic route.
3. **Let it run, then look at where execution actually is.** A trace, or a periodic sample of the
   instruction pointer, shows the transition out of the stub. Streaming a trace to a bounded summary is
   what makes this affordable; a raw trace of a full startup is not readable.
4. **Use the tail of the stub.** Stubs commonly push an address and return to it, or jump through a
   register loaded from the end of their own code. That is a small static problem worth solving before
   running anything.
5. **Accept that there is no OEP in machine code.** With a virtualised entry point, control transfers into
   an interpreter and never returns to native code belonging to the program. The substitute is the
   interpreter's dispatch loop, which is described in `virtualization-and-flattening.md`.

Record the OEP as an RVA, not as an address, and record the run in which you observed it. The same build
launched twice can produce two different addresses, because the image is relocated on every run.

## Dumping

A dump is the memory image of the process at a moment when the code you care about is decrypted.

| Method | When it works | What it costs |
|---|---|---|
| Break in a debugger after decryption, write the image to a file | The debugger can attach and no debugger check fires | Requires the anti-analysis question to be settled first, or the dump is taken from a corpse |
| Read the target's memory from a second process | The target is not attached, and the reader has sufficient access | The reader sees whatever state the target happens to be in |
| Read memory from a kernel-side view | The target detects user-mode instrumentation but not the kernel | Needs a kernel route, which is a different project with its own costs |
| Take a crash dump or a full process dump | The mechanism that kills the target also freezes it in a readable state | The dump may be taken after the code was re-encrypted |

**Freeze before you copy.** A protector that re-encrypts regions may have done so between your first and
last page read, which yields an image that is internally inconsistent and fails in a way that looks like
a bad dump rather than a race. Suspend the other threads, or read while the process is stopped, and state
in your notes which of the two you did.

## Repairing the dump

A raw memory image is not a loadable file. The repairs, in the order they must be done:

1. **Section layout.** In memory, sections occupy whole pages. On disk, the section table describes raw
   offsets and sizes. Write each section to a raw offset aligned to the file alignment, and set
   `PointerToRawData`, `SizeOfRawData`, `VirtualAddress` and `VirtualSize` consistently. A dump whose
   sections are misaligned normally fails at load with an error that names the file, not the layout.
2. **`SizeOfImage` and the headers.** Set the image size to the end of the last section rounded up to the
   section alignment. If the headers were wiped, restore them from a clean copy of the **same build**;
   headers from a different build produce a file that loads and then misbehaves in ways you will attribute
   to the protector.
3. **Entry point.** Point it at the OEP you recorded, or at a small stub of your own that then transfers
   control there. The second shape is easier to debug.
4. **Relocations.** If the image was loaded at a base other than its preferred base, every absolute
   address inside it is wrong relative to the file. Either rebase the file to the address it was dumped
   from, or apply the relocations in reverse. An image with relocations stripped (a common protector
   measure) cannot be rebased at all, so it must be mapped at the base it was dumped from.
5. **The load configuration.** If the image declares reserved structured exception handling, the PE
   specification states that a handler must appear in the load configuration's sorted handler table or
   the operating system terminates the application (`observed`). A repaired header that keeps the reserved
   flag without keeping the table produces an immediate death that has nothing to do with the protector.
6. **Read-only tables.** If the load configuration carries the guard flag documented as "module supports
   read only delay load IAT" (`observed`), the loader protects that table, so a repair step that writes to
   it faults. Re-check the guard flags before concluding that your rebuilder crashed.

## Rebuilding the import table

**Why a dump without it loads but does not run.** The PE specification states that the contents of the
import address table are identical to the import lookup table until the image is bound, and that during
binding the entries "are overwritten with the 32-bit (for PE32) or 64-bit (for PE32+) addresses of the
symbols that are being imported" (`observed`). A dump therefore contains **resolved addresses**, not
names. A loadable repaired image can often be produced by pointing every import slot at those addresses
directly, and that file will frequently load and then fail, because the addresses it hard-codes belong to
the process it was dumped from (`inferred`, and worth one control run to confirm on your sample).

There are two consumers, and they want different things:

- **The loader** wants a valid import directory so it can resolve against the current host.
- **The analysis tool wants names** so that a call site reads as a call to a named function instead of a
  number.

Rebuilding for one is not rebuilding for the other, and a stuck session is usually a session that solved
one and assumed the other.

**Rebuild procedure.** For every slot in the dump's import address table:

1. Read the resolved address.
2. Determine which loaded module owns it, by address range.
3. Look the address up in that module's export table, by address, to recover the name or the ordinal.
4. Emit a new import descriptor for that module, with a lookup table of names (or ordinals) and an address
   table parallel to it.
5. Write the repaired directory entry and size into the data directory.

**Hard cases, and what they mean.**

| Case | Consequence |
|---|---|
| An exported function that forwards to another module | The address belongs to a third module; resolve through the forwarder or record it as an ordinal |
| Imports by ordinal only | There is no name to recover; record the ordinal and the owning module |
| Delay-loaded imports | A separate directory with its own address table; the PE specification documents an unload-time copy that restores the preload state (`observed`), so a rebuilt delay-load table must match that shape |
| Imports resolved by the protector's own resolver, by hash | No name exists anywhere in the image. There is nothing to rebuild, and the honest output is a table of (address, hash) pairs you identified by hand |
| Statically linked runtime, no imports at all | Nothing to rebuild. Calls are inside the image, and this is an analysis problem, not a repair problem |

## Anti-dump measures

| Measure | Evidence you will see | What it does to a naive dump |
|---|---|---|
| Import destruction | Import directory empty, or pointing into a writable section | Produces a dump with no symbols, which is still useful; it makes the dump *look* broken |
| Header wiping | First page zeroed in the dump | Loader rejects the file; the headers must come from elsewhere |
| Section trimming | Section virtual sizes plausible, raw sizes tiny | A dumper that trusts the section table writes almost nothing |
| A guard page, or a page whose protection changes | A read faults in a region that the addresses say is readable. The documented behaviour of a guard page is that the first access raises `STATUS_GUARD_PAGE_VIOLATION` and clears the guard status, so the alarm is one-shot (`observed`) | The first read attempt fails; the second succeeds |
| A self-integrity check over the image | Death after any edit, with the death occurring at a delay rather than at the edit | Makes a repaired dump unusable, even a correct one |
| Re-encryption between reads | A dump where two halves disagree | Produces a file that is consistently wrong |

**Handling rule.** Every one of these is a *detection*, not a defeat. The question is the same as in
`anti-analysis.md`: whether the mechanism can be satisfied with a benign value, whether it can be avoided
by working outside the process, or whether the instrument has to move. In practice most dump-checks are
avoid-class, because the check fires on the act of reading, not on a value the target compares.

## When unpacking is not the right route

Unpacking is unbounded work, and the honest answer is sometimes that it is not needed. Check these before
committing:

- **The deliverable is a conclusion, not a binary.** If the request is "what does this check do", the
  protector only has to be understood, not removed.
- **The behaviour is in the readable part.** Protection is usually applied to a fraction of the image. The
  dialogue, the configuration, the update path and the licence UI are frequently outside it.
- **The decision is not local.** If the value that decides comes from a server, an unpacked client changes
  nothing.
- **A live patch or an observer is acceptable.** Modifying the running process needs the code located, not
  the file repaired.
- **You can name the cost ceiling.** If you cannot say what the unpacked artifact will buy you, you are
  buying it on principle.

## Mechanically true of packers generally, versus true of one build

| Mechanically true | True of one build only |
|---|---|
| A stub runs before the program's own code, and control reaches the program by a computed transfer | Which stub, and what it computes |
| Anything that hides code from a reader must restore it, and the restoration is observable | The exact instruction that performs the restoration |
| An import table that resolves to nothing must be rebuilt at run time, and the rebuild is observable | The structure the rebuild produces |
| A self-integrity check has a scope, and only the code inside that scope is protected | The exact region covered |
| Entropy is high over compressed or encrypted data | Whether a given section is compressed, encrypted, or a resource |
| A protection change to executable is needed before newly written code runs | Where that change is made |

State which column a conclusion belongs to when you write it down. "The stub decrypts into a section that
is initially not executable" is a mechanism. "This protector uses a two-stage stub with an encrypted
lookup table" is a build-level claim that needs its own evidence, and it does not generalise to the next
version of the same product.

## What this file does not contain

- No claims about the strength of any protection product, because none was tested for this document.
  Vendor material on protection strength is marketing, and the one honest thing it says is that a
  protector runs with ordinary application privileges, so it can be supervised from outside the process
  (`observed` in this project's vendor-documentation pass).
- No commands. The mechanics above are route decisions, and the instruments are in the debugging,
  patching, dump and tracing references.
- No entropy thresholds. A threshold picked without a measurement is the most common invented number in
  this domain; if you need one, measure it on this sample's known-good sections first.
