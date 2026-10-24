# Process Memory and Dumps as Evidence

Goal: know what a captured address space tells you, what it cannot, and what has to be done to an
image recovered from memory before it is a file you can load and study.

## When to load this

Load this when a live debugging session is not available or not repeatable, when a target's code in
memory differs from its code on disk (packed, decrypted, or self-modified), or when the symptom index
sent you here from "the image you dumped will not load — sections are misaligned or headers are gone".
Also load it when you are about to describe a value you read out of a dump as a fact about the
program's logic.

## A file image and a live image are not the same object

The file on disk holds sections at file-aligned offsets. The loader turns that into an address space
in which each section sits at a page-aligned virtual address, and it changes bytes while doing so.
The differences all have concrete causes:

| Difference | Cause |
|---|---|
| Addresses inside the image are not the ones in the file | The image may not load at its preferred base, so image-base-dependent fields are patched according to the relocation table — the mechanism exists precisely because the loader is not required to honour the preferred base (`observed`, the PE format's definition of an RVA versus a virtual address) |
| The import table's address entries hold real resolved addresses | The loader resolves each import and writes the result into the image's import address entries, leaving the by-name table intact for reference (`observed`, the PE format defines the import address table separately from the import name table, and the same split for delay-load imports) |
| A section's in-memory tail is not in the file | Where the raw size is smaller than the virtual size, the remainder is zero padding and need not be stored in the file (`observed`, the PE format's section-data rules) |
| A section's offset in the file differs from its offset in memory by something that is not a constant | File offsets are aligned per the header's file alignment; virtual addresses are aligned per the section alignment, and the alignment values need not be equal (`observed`, the optional header's alignment fields and the requirement that the image size be a multiple of the section alignment) |
| Pages that were never written may be shared rather than private | Image-backed pages are shared mappings until something writes them; a written page becomes private to the process while still being reported as image-backed (`observed`, the memory query documentation's note that a copy-on-write page continues to be reported as image rather than private) |
| The bytes userspace sees may have been rewritten after loading | Unpacking, decryption and anti-analysis all rewrite the mapped image, so a live read can differ from the file for reasons that have nothing to do with the loader |

The conversion you need repeatedly is the inverse of that table. Given a virtual address in the live
image, subtract the module's base to get an RVA, then find the section whose virtual address range
covers it, and read the file at `PointerToRawData + (rva - VirtualAddress)`. If the RVA falls beyond
that section's raw size, the byte is not in the file at all — it is the zero-filled tail or something
the program produced at run time (`observed`, field names and arithmetic per the PE format's section
data section). A tool that reports an RVA as if it were a file offset produces a screenshot that looks
right and points into the wrong bytes; the PE reader in this skill's script directory
(`scripts/peutil.py`, run as `python scripts/peutil.py <sample> --sections`) is the cheap way to get
the section table before doing that arithmetic by hand.

## What a dump contains, and what it does not

A user-mode minidump is a structured file, not a raw memory image. What it carries depends entirely on
the flags chosen at capture time, and the flags are a list of independent inclusions rather than
quality levels (`observed`, the dump-type enumeration and its per-flag descriptions):

- Which modules were loaded, with each one's base address, size, name and the image's own build
  identifiers.
- The threads that existed, and — with the right flags — their stacks, which is what makes a crash
  analysable.
- The memory regions the writer chose to include, each recorded as an address, a size and an offset
  into the file.
- The exception record, when the dump was produced by a fault.
- Optionally: handle information, token information, thread state, memory region information (the map
  of which ranges were present and how they were protected), full auxiliary state, and processor trace
  data, each only if requested.

What it does not contain, regardless of flags: anything the writer could not read (regions that are
not accessible are simply absent unless the writer was told to ignore the failures and continue); the
history that led to the state, which no memory image ever holds; kernel objects themselves, as opposed
to a list of handles; and any meaning — a dump records a value, never that the value is a licence
flag. The last point is the one that misfires: a dumped snapshot is a state, and identical states
arrive by different paths, so an explanation of *why* a value is what it is must come from code
(`inferred`).

## Minidump or full: which one answers which question

| The question | The capture that can answer it |
|---|---|
| Where did it fault, and what was the call stack | The smallest dump is enough: the default type exists to capture the information needed for stack traces of existing threads (`observed`) |
| What is the value of this field at that moment | The region holding the field must be included; a default stack-focused dump will not have it |
| What do the decrypted code bytes look like | A full-memory capture — all accessible memory, appended after the file's own structures so the header structures map directly (`observed`) — or, cheaper, a capture restricted to private read/write pages |
| Which pages were executable, private, or image-backed | The region-information inclusion, which records the memory region list rather than the bytes (`observed`) |
| The handle table, or the caller's token | The handle and token inclusions (`observed`) |
| Per-thread state beyond the register context | The thread-information inclusion (`observed`) |
| A capture that fails because some pages cannot be read | The "ignore inaccessible memory" flag, which makes the writer continue past read failures and omit those regions rather than fail (`observed`) |

Two practical costs. A full-memory capture is documented as potentially very large, so available disk
is a real constraint and an unbounded capture can fill the working volume; check the space before
choosing. And a capture with memory filtering enabled strips stack and backing-store memory down to
what is needed for a stack walk, which is exactly the wrong choice when the stack value itself is the
evidence (`observed`, the filter flag's description). A crash-focused capture and an
extraction-focused capture are different requests; deciding the flag set after the process is gone is
not an option.

The platform can also collect dumps at crash time from a registry configuration rather than from a
running tool: the dump type is an integer where 0 selects a custom flag set, 1 a mini dump and 2 a full
dump, and this collection is configured independently of crash reporting, so it still works when
reporting is off (`observed`, the local dump collection documentation, including the per-application
override key). That is the route to take when the behaviour to capture is a crash that happens only
without an analyst present.

## Dumping a process you own versus one you do not

Owning the process is not a permission concept; it is a question of what handle rights you can obtain.

- **A process you launched.** You can capture from inside it, but the documented advice is to call the
  dump writer from a *separate* process, or failing that from a dedicated thread, because calling it
  from inside an unstable process risks a loader deadlock and a stack that is already exhausted
  (`observed`, the dump writer's remarks).
- **A process you did not launch.** You need a process handle carrying query-information and
  virtual-memory-read, plus the ability to obtain full access to its threads; handle collection adds
  the duplicate-handle right (`observed`, the dump writer's documented access requirements).
- **A read-only pass, without any dump.** Enumerating and reading memory needs only the query right on
  the process and the read right on the address space; changing a region's protection or writing to it
  needs the operation and write rights (`observed`, the memory query, protection-change and
  cross-process write documentation). Making that distinction explicit is how a session stays honest:
  everything this file describes as discovery is achievable with the read-only set.
- **The case that is not answerable from here.** Whether a handle can be obtained at all for a
  protected or otherwise restricted process is a property of that process and that host, and a failure
  to open it is `unknown`, not proof that the memory is unreadable by every means. Report which call
  failed and with which error, and stop there rather than asserting a boundary you did not measure.

## Recovering a loadable image from a dump

The task is to rebuild a file that the loader will accept, from bytes that were captured in the form
the loader produced. In order:

1. **Locate the image in the dump.** Take the module's base and size from the dump's module list, then
   confirm those addresses have captured content in the dump's memory regions. If the module's range is
   not present, the capture type was wrong; re-capture rather than approximating.
2. **Get a header.** The header is the only thing that says where every other byte belongs, so if the
   in-memory header was wiped by a protector, a header of the same build must be supplied from
   somewhere — the same file on disk if its build identifiers match, or another copy of the image.
   Without a self-consistent header there is no reconstruction, only a guess about section layout
   (`inferred`). A missing header is not a gap to fill with reasoning: it is a hard prerequisite.
3. **Rebuild the file layout from the memory layout.** For each section, read the bytes at the
   image base plus the section's virtual address, and write them at the section's raw-data file offset
   for the section's raw size. It is the header's file-offset and raw-size fields that decide these
   positions, not a computed stride, and the tail between the raw size and the virtual size is zero in
   the file (`observed`, the PE format's section data rules). Getting this step right matters more than
   any other, because every directory in the optional header — imports, exports, resources, debug,
   relocations — is an RVA, and an RVA resolves correctly only if the layout is the layout the header
   describes.
4. **Restore the fields the loader or the program may have modified.** Decide, per field, whether the
   file should hold the original on-disk value or the live value, and write down which you chose.
   Anything you cannot determine honestly becomes a stated limitation of the rebuilt artifact.
5. **Rebuild what the loader did, or bind the result to it.**
   - *Import address entries.* In the dump they hold the addresses resolved in that session. Left
     as-is, they bind the file to a session that no longer exists, and the first indirect call in a new
     session lands somewhere invalid. The cleaner repair is to re-point them at the by-name table so a
     new loader resolves them, which requires the import name table to still be present and the
     directory entries to be consistent with it.
   - *Relocations.* Either write the image base as the base it was captured at and accept that the
     file is bound to that address, or reverse the applied relocations so the image is position-
     independent again — which needs the relocation section, and therefore fails when a protector
     removed it.
   - *The entry point.* The address the process was executing is not automatically the image's entry
     point; the entry point is a header field, and it must be restored from a source rather than
     inferred from where the target happened to be.
6. **Repairing means, concretely:** a header that parses and whose directory RVAs and sizes agree with
   the laid-out sections; a section table whose raw offsets and sizes match the bytes actually written;
   an import situation that is either resolvable at load time or explicitly static with the binding
   recorded; a relocation state consistent with the base you chose; an entry point that points at real
   code; and an image size that covers every section. When all of those hold the file loads — which is
   a statement about loading, not about behaving. A repaired image frequently still differs from the
   original program because run-time self-modification, decrypted regions and constructors that ran
   from the loader are now baked into it. That difference is the finding, and it should be reported as
   such instead of being described as "the unpacked binary".

The reason dumps so often fail to load before repair is that each of the above is a separate
requirement and the failure mode of every one of them is a load error rather than a diagnostic. The
most common single cause is a layout mismatch: memory is page-granular and the file is not, so a
verbatim memory copy produces a file whose section table and whose bytes disagree.

## Finding code in memory when a full dump is not an option

Enumerate first, read selectively, and treat the enumeration as the primary evidence:

1. Walk the address space with the query interface to get, per region, its base, size, state
   (committed, reserved, free), type (image, mapped, private) and protection (`observed`: these are
   the documented members and value sets, including the note that a written page stays reported as
   image rather than becoming private).
2. Filter to what the question needs. A search for live code keeps committed regions with execute
   protection; distinguishing a live image from dead leftovers uses the type — an image-backed region
   belongs to a mapped module, a private executable region does not.
3. Read each candidate region in bounded chunks and match your pattern — a distinctive byte sequence, a
   string, an instruction shape. Report each hit as an address, its module attribution (module plus
   offset when the hit falls inside a known module's range, otherwise explicitly "private region, no
   module"), and the region's protection.
4. Treat a failed read as information. A region that cannot be read is not the same finding as a region
   that is absent, and mixing the two is how a pattern search reports "not found" when it means "not
   looked at" (`unknown`, per the labelling rule: name the search that ran and the region it could not
   cover).

The same discipline applies to the result: hits into a private executable region are the interesting
ones — they are code that is not accounted for by any module — but they are also the region a protector
uses for its own runtime, so a hit there says "code lives here", not "this is the target's own code".

## What memory alone cannot establish

- **Causation.** A dump shows a state. Two byte-identical snapshots can have been produced by opposite
  code paths, so "this value was computed by that routine" needs the routine, not the value.
- **Which of two similar regions is live.** Two regions can hold identical code, one as the current
  mapping and one as a leftover from a reload or a protector's decoy. The evidence that separates them
  is attribution and use: which module claims the range, what references it, which pages are currently
  executable — and when those disagree or are missing, the honest answer is `unknown`, with the reason.
- **Time.** There is no before and after in a single capture. Anything sequential needs either two
  captures at known points or a trace.
- **Semantics.** Which field is a licence flag, what a structure's layout is, and whether a comparison
  is the decision or a diagnostic copy of it are all properties of code and callers.
- **The absence of a thing.** Not seeing a string, a module or a pattern in the captured regions is a
  statement about the regions you captured.

## Budget discipline while doing any of this

A dump is a producer that can emit an unbounded result, and a memory scan is the same. Both are run
under the rule this skill applies to every large producer: **print a bounded summary and write the
complete record to a path the summary reports.** Work from the summary, and open the full record only
for the specific question the summary left open. Do not re-run a capture or a scan in order to obtain
a smaller answer — the second run costs the same as the first and returns no less.

Applied to this file: choose the dump type from the question rather than capturing maximally "in case",
state the disk and time cost before the capture as a consequence of the type you chose, and when a
pattern search is the goal, bound the total bytes read and keep the full hit list in a file while the
summary carries counts and the top hits. An unbounded capture or scan turns a stall into "still
working", which is why the bound is calibrated from one measured run rather than assumed.

## Related material in this skill

For capturing a live observation instead of a state, and for choosing an instrument that does not
modify the target, load `references/dynamic-debugging.md`. For code you place in a process rather than
a capture of it, load `references/injection-and-hooking.md`. Before planning any capture, run
`python scripts/hwprobe.py`: which dump writers, debuggers and tracing tools exist on this machine is a
measured property of the machine, and a capability you never probed for is not a capability you lack.
