# Injection, Hooking, and the Discipline of Noticing You Modified the Target

Goal: put your own code where the target will run it, and keep straight which observations still
describe the target and which describe the instrument you just installed.

## When to load this

Load this when a breakpoint is not enough because the observation must persist across a call you
cannot stop at, when a memory patch must be applied to a running process rather than to a file, or
when the target defeats software breakpoints and the alternative is your own code inside it. Also load
it when you are about to conclude something about the target from a run in which a hook was installed:
this file is where the reason that conclusion needs a caveat lives.

## The asymmetry to hold on to

Observation and modification are not two settings of the same instrument; they are two instruments
with one shared failure. Code you place inside a target is a modification, and a modification changes
what the target is (`observed` as a mechanism: every technique below writes to the target process's
address space, its thread list, or its callback tables). The routes that do not write anything — an
out-of-process debugger reading memory, a processor-level trace, a log the target writes anyway — are
weaker at answering *why* and are the only ones whose answer does not need that caveat. Choose the
weaker instrument when the question tolerates it, and say which one you used.

## Getting code in: remote thread creation

The mechanism is three steps, each with its own access right:

1. Reserve and commit memory in the target, with the protection the payload needs. A region must be
   explicitly requested with the executable protection; a plain read/write allocation will fault the
   moment the target executes it. The handle needs the process's virtual-memory operation right
   (`observed` as the documented access requirement for cross-process allocation and protection
   changes).
2. Write the payload into that region. The entire area must be writable or the call fails, and the
   handle needs the write and operation rights (`observed`, cross-process write documentation).
3. Cause execution at that address: create a thread in the target whose start address is the payload.
   The documented access set for this is the widest of the three — create-thread, query-information,
   virtual-memory operation, write and read (`observed`, thread-creation documentation).

What that costs, in the platform's own words, is worth quoting because it is the whole argument
against using this as a default: the created thread "converts single-threaded applications into
multithreaded applications", "changes the timing and memory layout of the process", and "results in a
call to the entry point of each DLL in the process" (`observed`, the same documentation). Any target
that enumerates its own threads, watches its own memory layout, or detects a new module initialising
will notice all three. A further trap is documented and worth internalising: the thread-creation call
can **succeed** even when the start address is invalid, because the address is only dereferenced when
the new thread is first scheduled — so "the call returned success" is not evidence that anything ran.

Two consequences for the analysis. First, the payload must be position-independent and must resolve
whatever it needs at run time rather than relying on the target's loader. Second, the new thread is a
foreign object: if it takes a lock the target's own threads hold, the target deadlocks, and the
symptom will look like a hang in unrelated code (`observed`, the documentation names lock ownership as
a deadlock cause).

## Loading through the loader versus mapping manually

A dynamic library loaded through the platform's own loader is registered as a module: it appears in
the module list a snapshot enumerates, name lookup finds it, its imports are resolved, its
per-image initialisers run, and its TLS callback array is walked by the loader. That registration is
the point and the price: everything that enumerates modules sees it.

Manual mapping — building the image in memory yourself — bypasses all of it, and the bypass is exactly
what you inherit as work:

| Loader-provided step | What you must do instead after a manual map |
|---|---|
| Locate each section in memory and copy it from the file | Reimplement the section mapping: each section's raw data goes to the image base plus its virtual address, with alignment taken from the image's section alignment, and the tail beyond the raw size zero-filled. The first section's raw data normally starts after the rounded-up headers (`observed`, the PE format's section-data rules) |
| Apply base relocations when the image did not load at its preferred base | Apply the block relocations yourself, or force the mapping at a base where they are unnecessary |
| Resolve the import and delay-import tables | Walk the import descriptors and patch every entry with the resolved address; nothing else will do it for you |
| Call the entry point, and the per-image initialisers of dependencies | Decide whether to call it, and accept that skipping it leaves initialised globals wrong |
| Walk the TLS callback array | Call them yourself, in array order, if the target's behaviour depends on them (`observed`, PE format: the callback array is null-terminated and each callback is called in the order its address appears in the array) |
| Register the module so name lookup and module enumeration find it | Nothing — this is precisely the property you wanted removed, and it is also the reason a manual map is visible under a different check: a private, executable region that begins with an image header is not a mapped module |

The last row is the honest statement of the tradeoff. A manual map does not make the code invisible;
it moves the visible evidence from a bookmarkable list to a memory scan. Deciding between the two is
deciding which evidence the target examines (`inferred`).

## Where a hook can live

Hooks differ in how much code they intercept, how much they perturb, and what they leave behind. Pick
the highest row that still answers the question.

| Hook location | Intercepts | Survives | Breaks or reveals |
|---|---|---|---|
| A callback registered with the system | Whatever events you registered for, delivered through the system's own mechanism | Code-hash and integrity checks, because no code byte changes | Nothing, structurally — but a cross-process callback needs code loaded in the target, and a desktop-wide one needs a library whose bitness matches the target (`observed`, the window-hook documentation states the 32/64 mismatch rule and that global hooks are a shared resource affecting every application on the desktop) |
| An imported function's address in a module's import table | Every call that goes through that table entry | Code hashes, because only a pointer changed | Calls that do not use the table: statically linked copies, direct calls to the real target, delay-loaded entries not yet resolved. And every module has its own table, so a single edit covers only the caller you edited; modules loaded later bring their own copy. The table is usually read-only at run time, so the page protection must be changed first |
| An exported function, in the export table or at its head | Callers that resolve the name | Both, depending on which of the two you edit | Name resolution performed from a cached address, ordinal imports, and any caller that already resolved the function before you edited |
| A function's prologue, in place | Every call to that address, whatever its caller | Nothing that hashes the code | The instruction-length problem (below), and any target that verifies its own code bytes |
| A system-call stub or a dispatch table inside the platform's own library | All callers of that call, process-wide | Nothing that verifies the platform library's code | Highly visible: platform code is hashed by integrity mechanisms, and the region may be shared between processes, so a write shows up in a mapping you did not intend to own (`inferred` from the shared-mapping behaviour of image sections) |

The pattern to read off that table: **the further down you go, the broader the interception and the
larger the footprint.** A callback that the system invokes for you is the only row that modifies no
code and no table the target owns.

## Detours and trampolines, and the instruction-length problem

An in-place hook replaces the first bytes of the target function with a jump to your code. Your code
does its work, then needs to reach the *rest* of the original function — which is why a trampoline
exists: a small region holding the instructions you overwrote, followed by a jump back to the first
byte after them.

The problem is that a jump needs a fixed number of bytes (a relative jump over the whole address space
needs five on the common encodings) and a function head is not guaranteed to offer that many bytes as
whole instructions. Concretely:

1. You must decode instructions forward from the entry until the accumulated length is at least the
   size of your jump. You cannot simply overwrite a fixed count of bytes, because that splits an
   instruction and the split tail is executed as garbage.
2. Instructions you relocate may be position-dependent. A relative jump or a RIP-relative memory
   reference inside the moved bytes now computes from a different base and must be rewritten, which
   requires the decoder to have identified it in the first place.
3. If the function is shorter than the overwrite, or its head cannot be cut at an instruction
   boundary that gives you enough room, this hook location is not available. Fall back to a table-level
   hook, or hook a call site inside the function instead of its head.
4. Some compilers leave padding before a function to make this easier. Its presence is a per-build
   property you must check, never assume.
5. The write itself races the target's other threads. A multi-byte overwrite is not atomic while a
   thread is executing in that region, so the region must be made non-executable or the threads must
   be suspended while you write (`inferred`; the failure it produces is a crash inside the target that
   disappears under a debugger).

## Building the stub: where it lives, how it reaches, and what it clobbers

The trampoline above is the reading problem. This is the authoring problem, and it has four
independent decisions: where the bytes live, which jump encoding can reach them, what the stub must
preserve, and in what order the writes land.

**Placement.**

| Where | Reached by | Cost |
|---|---|---|
| a run of padding inside an executable section — a "cave" | a relative jump, if the distance is in range | no structural change; the cave may sit in a page the target hashes |
| a new section | a relative jump, because the RVA is chosen with it | structural: section table, alignment and size fields all change, and the file grows (`references/patching.md`) |
| memory allocated in the target | the jump is written into the target's code and points at the allocation | memory patch only; the allocation must be made executable, and a private executable region is visible to a memory scan |
| an existing routine that is close enough | a routine-pointer or call-site edit | no stub at all — the smallest edit, when such a routine exists |

**Reach.** The jump has to encode the distance, and on x64 the distance is the problem: a relative
displacement is 32-bit, so it covers ±2 GB, while an image and a separately allocated region are
commonly farther apart than that (`inferred` from the encoding width).

| Encoding | Bytes | Range | Notes |
|---|---|---|---|
| `EB rel8` | 2 | ±127 | cheapest and the most fragile; a rebuild moves the target |
| `E9 rel32` | 5 | ±2 GB | the default hook; needs five bytes of whole instructions at the site |
| `FF 25 00000000` + an 8-byte address | 14 | the full 64-bit space | reads the address out of the instruction stream; needs 14 bytes at the site, which a function head rarely has |
| `mov rax, imm64; jmp rax` | 12 | the full 64-bit space | clobbers RAX, which the callee may be about to use |
| a relay: the 14-byte form parked in a cave, reached by `E9 rel32` | 5 at the site | ±2 GB to the cave | the usual answer when the stub is far away and the head is short |

**What the stub must preserve.** The non-volatile registers it touches, and the flags if it branches
before restoring them (`pushfq`/`popfq`). A stub that calls anything needs the x64 frame — shadow
space and 16-byte alignment — described in `references/assembly-idioms.md`. Position independence is
not optional: the image base moves between runs, so the stub resolves what it needs at run time,
either from data placed beside it or through the export tables.

**Order of writes.** The stub body goes in first and the hook bytes last, so the site never points at
a half-written routine. A five-byte write is not atomic against a thread executing there: suspend the
other threads, or make the site's page non-executable for the duration. Where the site is 8-byte
aligned, one aligned 64-bit store installs the five-byte jump plus three filler bytes as a single
atomic write, which is why that alignment is worth checking before the site is chosen.

**Producing the bytes.** Assemble the stub to an object, take the `.text` raw bytes, and disassemble
those bytes back before using them: an assembler that emitted a relocation, or a section extracted at
the wrong file offset, still produces something that assembles. Then give the hex to the patcher's
`--bytes` on the file route, or write it into the allocation on the memory route.

## Managed methods are a different target

A managed method's code may not exist yet when you want to hook it: it is produced at run time, can be
re-compiled, and the call you identified may have been inlined into its caller and no longer exist as
a separate entry. Patching the JIT output of a method is therefore a race against the runtime, and
patching the method's bytes on disk in the assembly is a different activity with its own rules.

The layer that exists for this is the runtime's own recompilation interface. As a concrete instance of
the pattern: the profiling interface exposes a request to recompile all instances of specified
functions, it requires an event-mask flag to be set at initialisation, and its documented scope is
explicit that it "does not affect currently executing functions, only future function invocations"
(`observed`, the recompilation method's documentation). That last sentence is the whole design
constraint: a managed hook is a statement about the target's *future* calls, so verifying it means
making the target call the method again after the hook, not finding the method already running.

Decide native versus managed before choosing any instrument: a process whose module list contains the
runtime's modules, or whose image carries a CLR data directory, is the managed case and the hex-editing
route does not apply to it.

## Instrumentation frameworks versus a hand-written hook

A framework buys you the parts that are tedious and easy to get wrong: the injection step, an
instruction-length decoder, trampoline construction, argument marshalling, and a scripting layer that
lets you iterate without rebuilding. It charges for them in visibility: the framework's own runtime,
its agent library, its threads and its hook stubs are all present in the target, are nameable, and
look identical in every target they are used against (`inferred`). It also imposes its ABI at the
script boundary, which is where wrong-looking argument values usually come from.

A hand-written hook is chosen for the opposite reason: to change as little as possible — one import
pointer, or one callback registration — and to leave no framework signature behind. It costs you the
decoder, the relocation fix-ups and the concurrency problem above, and it is not a good vehicle for
exploration.

The selection order that avoids both mistakes: first ask whether a callback or an out-of-process
observation answers the question with no code in the target at all; if not, take the smallest
footprint that reaches the decision point; only then consider a framework, and accept that a
framework-observed target is a target with a framework in it.

## Telling your hook apart from the target

Four checks, in this order, whenever a hook is installed:

1. **The control.** The unmodified build, same input, same host. If the behaviour you are explaining
   exists in the control too, the hook is not the cause.
2. **The uninstall test.** Remove the hook and re-run. A symptom that survives removal was never the
   hook's.
3. **The transparency prediction.** Write down, before installing, what a transparent hook should and
   should not change. If the target's output, timing class, or memory layout changes in a way your
   prediction did not include, the hook is not transparent — suspect a split instruction, a clobbered
   register the caller expected to be preserved, a changed stack alignment, or a calling-convention
   mismatch.
4. **Count and log rather than redirect.** A hook that records the call and then forwards it lets you
   state "this routine ran 3 times with these arguments" — a quantitative claim — instead of "the
   feature came from here", which a redirect cannot prove.

**A hook on a hot shared routine changes the target's behaviour class, not just its speed.** A routine
called on every frame, every packet or every field access, once hooked, turns each call into a callback
across a process or language boundary. Targets that measure elapsed time, run watchdog timeouts, or
choose between two code paths on the basis of a deadline will take the other path under that load.
Locate the decision point and hook that, or hook a cold path such as initialisation, or move to an
observer outside the process.

The rule that follows from all of this, and that is worth stating plainly because it is the one that
gets violated when a session is going well: **a hook is a modification, therefore it changes the
observation.** A statement of the form "the target does not detect this" made from inside a hooked run
is a statement about the hooked build. If the claim matters, it needs a run with nothing installed.

## Where hooking is the wrong instrument

- **You only need to know whether a region was read or written, or whether a routine was reached.**
  Hardware breakpoints answer that without writing to the target at all, on the architectures that
  have them, and they leave the code bytes untouched.
- **You need a call graph, timings, or a sequence over time.** Platform tracing and sampling already
  collect that out of process, with no code in the target.
- **The target verifies its own code or its module list.** Every hook above except a pure callback
  registration is visible to such a check, and the detection will be attributed to you and not to the
  feature you were investigating.
- **The interesting code is in the kernel.** User-mode hooking stops at the boundary; a different
  route owns that layer.
- **The code is not yet decrypted or unflattened.** A hook needs a location; the location must be
  recovered first, and hooking an unpacking stub produces observations about the stub.
- **The question is what the target should have done.** A hook shows you the path taken with the hook
  present; a static read of the routine shows you the path's condition. The second is often the
  cheaper way to answer it.

## Related material in this skill

For the in-process observation instruments this file's hooks compete with, and the failure modes all of
them share, load `references/dynamic-debugging.md`. For capturing the address space without leaving
code in it, load `references/memory-and-dumps.md`. For whether the machine you are on can host the
out-of-process alternatives at all, run `python scripts/hwprobe.py` first: it reports the tool
inventory and the hardware capabilities, and a capability you never probed for is not a capability you
lack.
