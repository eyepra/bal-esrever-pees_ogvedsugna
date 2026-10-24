# Assembly-level reading: the ABI, the frame, and the idiom

Goal: turn a listing into three facts you can act on — which convention moves the arguments, which
producer shaped the frame, and which library routine an instruction sequence is standing in for —
before deciding where to patch and what the patch must preserve.

## When to load this

Load this when a routine's parameters or return value do not line up with the convention the
toolchain implies; when a detour, stub or code cave must keep its callee working; when a prologue does
not match the compiler the headers named; when a body is dense with string instructions or
floating-point stack operations; when a virtual call has no direct target; and when a 32-bit target's
file or registry access does not land where the documentation says it should.

Grades: the conventions and encodings are documented architecture, and applying one to a listing is
`inferred`. Any statement about what a particular build emits is `unverified` until it is checked
against that build. No sample was disassembled to write this file, so every row is a shape to look
for, not a measurement.

## The calling convention is the first thing the listing tells you

**32-bit.** The convention decides where the parameters are, who removes them, and therefore how many
the callee expects. `ret` with an immediate is the cheapest parameter count in the whole file: the
number is the byte count of the arguments the callee pops.

| Convention | Arguments | Stack cleaned by | Return | Where it turns up |
|---|---|---|---|---|
| `cdecl` | right to left, all on the stack | caller, `add esp, N` after the call | EAX | C and C++ default; every variadic function |
| `stdcall` | right to left, all on the stack | callee, `ret N` | EAX | the Win32 API; most exported callbacks |
| `fastcall` | ECX, EDX, then the stack | callee, `ret N` | EAX | `__fastcall`, some optimised exports |
| `thiscall` | ECX is `this`, the rest on the stack | callee, `ret N` | EAX | Microsoft C++ member functions |
| register convention | EAX, EDX, ECX in order | callee | EAX | Borland-family C++ and Delphi builds — `unverified` until a known sample confirms it |

A caller that cleans the stack is also the caller that must know the argument count statically, which
is why a variadic `cdecl` call is recognisable from the `add esp` after it rather than from the callee.

**64-bit.** Four integer arguments in RCX, RDX, R8, R9 and four floating-point arguments in
XMM0-XMM3; the rest at `[rsp+0x20]`, `[rsp+0x28]`, … — the first 32 bytes above the return address
belong to the callee as **shadow space** for exactly those four registers. The caller allocates and
frees it, and RSP is 16-byte aligned at the `call`, so a callee enters with `rsp % 16 == 8`. RAX
returns the integer result and XMM0 the floating-point one. Volatile: RAX, RCX, RDX, R8-R11 and
XMM0-XMM5. Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15 and XMM6-XMM15.

Five consequences, and the first three are where hand-written patches break:

- **A cave that calls needs a frame.** `sub rsp, 0x28` before the call and `add rsp, 0x28` after it is
  the minimum shape: 32 bytes of shadow space plus alignment. A cave that calls with RSP untouched
  gives the callee an unaligned stack, and the failure surfaces inside the callee's first aligned
  SSE store, not at the call.
- **The home space is live.** A callee may spill RCX-R9 into `[rsp+8]`..`[rsp+0x20]` as its first
  act. A trampoline that overwrites those slots before running the original prologue destroys the
  arguments it was supposed to forward.
- **The fifth argument is at `[rsp+0x28]`, not `[rsp+0x20]`.** The four slots of the shadow area
  hold the register arguments, and the stack arguments begin after them; measuring from the return
  address is what shifts the first one by eight bytes.
- **Non-volatile means what it says.** A stub that uses RBX, RDI, RSI or R12-R15 must save and restore
  them. A stub that uses only RAX, RCX, RDX, R8-R11 may not.
- **Read the count from the accesses, not from the convention.** The register count bounds the
  parameters; it does not prove the function uses all four, and a decompiler that fills the unused
  slots with plausible types is guessing.

**Varargs on 64-bit** duplicate a floating-point argument in both its XMM register and its integer
register, so a `printf`-style call shows the same value moved twice. That is not a bug in the listing
and not a second argument.

## Frames: what the prologue says about the producer

The frame is the most reliable statement of provenance in a listing, because a compiler emits the same
shape for every function it builds and an assembler author emits a different one every time.

| Shape in the listing | Producer | What it changes |
|---|---|---|
| `push ebp; mov ebp, esp; sub esp, N` | 32-bit build with the frame pointer kept — debug, or a function that needs a stable frame | locals at `[ebp-N]`, arguments at `[ebp+8]` upward; the frame can be reconstructed with confidence |
| `sub esp, N` with no EBP use at all | 32-bit release build with frame-pointer omission | locals are at `[esp+N]`, and any comment naming `[ebp-x]` comes from a different build |
| `push ebx`/`esi`/`edi`, then a mirrored pop set and `mov esp, ebp; pop ebp; ret` | ordinary compiler epilogue | the epilogue is the only place the frame is unwound; a patch that jumps past it unbalances the caller's stack |
| `lea edi, [ebp-N]; mov ecx, N/4; mov eax, 0CCCCCCCCh; rep stosd` | Microsoft debug build | 0xCC is `int3` fill: a run of `int3` inside a function body is uninitialised stack, not code and not a trap |
| `enter N, 0` … `leave` | hand-written assembler, or a build asked for it explicitly | no mainstream compiler emits `enter`; treat the routine as assembled and read its author's intent, not a compiler's |
| `ret 4`, `ret 8`, `ret 0Ch` | 32-bit `stdcall` or `thiscall` callee | parameter byte count on the spot; this encoding does not exist in 64-bit mode, so seeing it dates the image to 32-bit |
| no prologue, body under five bytes, plain `ret` | leaf function, or a stub | nothing to preserve — and too short for a five-byte jump, which is a hooking constraint, not a reading one |
| `mov [rsp+8], rcx` near the entry (64-bit) | debug build, or a function that must keep its arguments in memory | the home-space spill is the frame; RBP being untouched does not mean the frame is absent |
| `push rbp; mov rbp, rsp; sub rsp, N` (64-bit) | frame pointer forced — debug, or a function with unwinding requirements | the same reconstruction rules as 32-bit, with the frame sized so that RSP stays 16-byte aligned |
| a push/pop set larger and more symmetric than the callee-saved set | hand-written routine | the author preserved registers by habit; check the epilogue mirrors it exactly |

Two conventions of the assembler itself are worth knowing when the artifact *is* assembly rather
than a compilation: `USES` generates the push/pop pair for the registers it names, and `LOCAL`
generates the `sub esp` for its variables, so a routine whose frame looks minimal in source still has
a full one in the listing. A routine whose only frame is what a macro produced is still a frame you
must respect when patching.

**What a frame tells you about patching.** A five-byte jump over a prologue also jumps over the
`sub esp` and the pushes, and the callee's epilogue will undo work that never happened. Hook the
first instruction of the function, not the first instruction after the frame, or run the displaced
bytes in a trampoline and jump back past them. The instruction-length problem itself belongs to
`references/injection-and-hooking.md`; the frame is why the length is not the only thing that must
match.

## String instructions: a library routine written out in one instruction

| Instruction | Stands in for | Registers | Tell |
|---|---|---|---|
| `rep movsb` / `rep movsd` | forward `memcpy` | RCX count, RSI source, RDI destination | the copy loop is absent; one instruction does the whole transfer |
| `rep stosb` / `rep stosd` | `memset`, including zero-fill | AL/EAX value, RCX count, RDI destination | a buffer is cleared without a loop and without a `VirtualAlloc`-zeroing call |
| `repne scasb` | `strlen` | AL = 0, RDI string, RCX = -1 as the bound | the length is found by scanning, and RCX ends negated |
| `repe cmpsb` | `memcmp` / `strncmp` | RSI and RDI, count in RCX | equality is decided by the string unit, ZF read after the prefix |
| `std` before `rep movs`, `cld` after | a backward or overlap-aware copy | DF = 1 | a compiler almost never emits this; a hand-written routine doing it might |

Consequences that change a measurement:

- **The same routine may be an SSE/AVX loop instead.** A compiler is free to inline `memcpy` as wide
  loads and stores, and a modern C runtime is free to use `rep movsb` because the processor implements
  it efficiently. Presence of a string instruction says "this is a library-shaped routine", not "this
  build is old" — the dating claim needs a compiler fingerprint, not an instruction.
- **One instruction, many iterations.** A trace, a single-step or a breakpoint at a `rep` address sees
  one event for a whole buffer. Counting executions there undercounts the work, and a hook that
  instruments per iteration sees nothing per iteration at all. The repeated-instruction hazard for
  memory hooks is described in `skills/exe-reverse/evidence/tool-sources.md`.
- **A zero count is a legal no-op.** `rep movs` with RCX = 0 copies nothing and does not fault. "The
  copy instruction is present" is not "the data was copied"; read RCX before believing either.
- **Direction flag.** The ABI requires DF clear on entry and exit. A hand-written stub that sets it
  and does not clear it corrupts the next library call, and the crash appears in unrelated code,
  which is the classic shape of an unattributable failure.

## x87: the floating-point stack, and what its presence means

x87 is a stack of eight extended-precision registers, ST(0) through ST(7), with ST(0) on top.
Loads push, stores pop, and arithmetic consumes its operands and pushes a result. That is why a
listing shows `faddp` and `fmulp` with no operands.

| Instruction | What it does |
|---|---|
| `fld dword ptr [x]` / `fld qword ptr [x]` | push a float or a double |
| `fild dword ptr [n]` | push an integer, converted to extended precision |
| `faddp`, `fmulp`, `fsubp`, `fdivp` | pop two, push the result |
| `fstp dword ptr [x]` | pop into memory |
| `fcomip st, st(1)`, `fucomip` | compare, pop, and set EFLAGS so an ordinary `jcc` follows |
| `fldz`, `fld1`, `fldpi` | push a constant — there is no immediate form |
| `fchs`, `fabs` | sign manipulation, usually around a threshold test |
| `fsin`, `fcos`, `fpatan`, `fsqrt` | transcendental and root operations — angle and distance math |

What the presence means:

- **x87 in a 64-bit image is not compiler output.** The 64-bit Microsoft toolchain uses SSE2 as its
  baseline and does not emit x87 for C or C++ floating-point work, and it does not support inline
  assembly at all. x87 there points at a hand-written routine, an embedded library built elsewhere,
  or a toolchain outside that family — an inference worth checking against the imports before acting.
- **x87 in a 32-bit image is ordinary**, and it is a weak dating signal at best.
- **A float comparison is patchable like an integer one.** `fcomip` plus `jcc` is the same branch
  shape as `cmp` plus `jcc`, so the site choice is unchanged. The *constant*, though, lives in a data
  section; a byte patch on it changes the threshold everywhere it is read.
- **Operand order is the usual decompiler error.** `fsubp` and `fsubrp` reverse which operand is
  subtracted from which, and a decompiler that renders a subtraction from a stack it did not fully
  model can invert it. Read the two pushes that precede the operation before trusting the sign.

## Virtual calls, object layout, and the three places a patch can go

In a Microsoft C++ build the object begins with a pointer to its class's **virtual function table**;
the table holds the virtual functions in declaration order, one pointer per slot. The call is an
indirect transfer, so it has no static target:

    mov rax, qword ptr [rcx]        ; the vptr, RCX is this
    call qword ptr [rax+8]          ; slot 1

The displacement divided by the pointer width is the slot index. When RTTI is enabled, the slot
before the vptr (`vptr[-1]`) points at the class's type information, which gives a class name
without symbols — a static-analysis gain that costs one pointer read.

| Site to patch | What changes | Cost |
|---|---|---|
| the function body | every caller, virtual and direct | a routine with many callers is a helper, not a gate (`references/patching.md`) |
| the vtable slot | this class, and every derived class that does not override the slot | the table is usually in a read-only section, so the write needs a protection change, and a file patch has to change the section's characteristics |
| the call site | one call, leaving every other user intact | only viable when the site is unique, and it breaks when the object's dynamic type changes |

Two reading cautions. A virtual call is an indirect transfer, so the listing has no successors until
you read the table, and the table is data (`references/static-analysis.md`). And teaching examples
that model the vtable pointer as a named first field, or place it before the object, model the
mechanism rather than the ABI: in a real Microsoft build the vptr is at offset 0 and the first data
member follows it, which is what the decompiler will show.

## WOW64: the two views a 32-bit target actually uses

A 32-bit process on a 64-bit Windows runs under WOW64, and its file and registry paths are redirected
so that both bitnesses can coexist. The redirection is silent: the call succeeds, the path looks
right, and the bytes are somewhere else.

| The target asks for | A 32-bit process gets | A 64-bit process gets |
|---|---|---|
| `%SystemRoot%\System32\foo` | `%SystemRoot%\SysWOW64\foo` | the real `System32` |
| `%SystemRoot%\Sysnative\foo` | the real `System32` — a virtual path that exists only for 32-bit callers | not a directory |
| `HKLM\SOFTWARE\Vendor` | `HKLM\SOFTWARE\Wow6432Node\Vendor` | `HKLM\SOFTWARE\Vendor` |
| `HKCR\CLSID\{…}` | the 32-bit COM registration view under the same node | the native view |

What this changes during analysis:

- **"The key is not there" is a statement about the view.** Both views exist on the same machine, and
  a native-view search that returns nothing has excluded one view, not the configuration. Open the
  32-bit registry editor, or query the `Wow6432Node` path, before concluding that the target keeps
  no local state — that conclusion otherwise redirects the whole investigation to a server.
- **The file twin matters for anything the target loads.** A 32-bit target loads the `SysWOW64` copy
  of a system library even when an installer wrote the other one, so a replaced file can be present
  and unused, and a missing file can be present under the other name.
- **Bitness decides the debugger, not the file header.** A 32-bit target needs a 32-bit debugger or a
  WOW64-aware one, and its register set and PEB are the 32-bit ones. Query the process architecture
  (`IsWow64Process2`) rather than inferring it from the image, because a managed AnyCPU image and an
  emulated host both defeat the header.
- **Elevation adds a second redirect.** A 32-bit process without a manifest that writes under
  `HKLM\SOFTWARE` or `Program Files` is also subject to UAC virtualisation, which lands the write in
  a per-user store. A setting that "was written successfully" and cannot be found afterwards can be
  in either of two places; check both before calling the write a failure.

## Idioms worth recognising on sight

| Listing | Means |
|---|---|
| `xor eax, eax` | zero a register, or return success — shorter than a move and extremely common in a check that passed |
| `test eax, eax` or `or eax, eax` | compare with zero through SF and ZF; a literal `cmp eax, 0` is the rarer form |
| `lea eax, [eax+eax*2]` | multiply by three: `lea` is arithmetic, not only address formation |
| `lea rax, [rip+disp]` | the address of a global or a literal — the 64-bit cross-reference |
| `call qword ptr [rip+disp]` | an imported API or a function pointer slot, which is the import table in one instruction |
| `mov rax, gs:[60h]`, `mov eax, fs:[30h]` | the process environment block: the shape of an anti-debug read or a manual API resolution walk |
| `movzx` / `movsx` | the value is narrower than the register, and the extension tells you how it is treated: zero-extended is unsigned or a table index, sign-extended feeds signed arithmetic and negative bounds |
| `setne al` / `cmovne` | a boolean materialised without a branch — a one-byte patch changes its polarity |
| `int 3` (0xCC) | padding, a debug build's uninitialised stack fill, or a breakpoint: three meanings, one byte |
| `ud2` | the compiler's marker for unreachable code, or a deliberate trap |
| `jmp rax` after a table load | a dispatch whose target set is data, not code |
| a push/pop pair around a single call | a volatile register saved across the call — compiler output, not a frame |

## What this file does not do

- **An idiom is not an identity.** Recognising that a shape is a copy, a comparison or a dispatch does
  not say which routine owns the decision. That is `references/static-analysis.md`, and the owner is
  confirmed by observation, not by reading (`references/dynamic-debugging.md`).
- **No disassembler is shipped here.** The reading is done with whatever the host provides, and
  `scripts/hwprobe.py` reports whether that is anything at all.
- **An idiom is not a guarantee.** The same bytes can mean two instructions and the same instruction
  can leave an undefined result, so a behaviour that differs between processor implementations is not
  an idiom — it is `references/cpu-vendor-divergence.md`.
- **A reconstructed frame is a hypothesis.** The listing gives the shape a compiler intended; the
  unwinder gives the one the processor used. Where they disagree, the run is authoritative.
- **Conventions describe calls the compiler emitted.** A stub written by hand, a callback invoked by
  the system, and an exported function called from another language each need their convention
  confirmed from the call site, not assumed from the language the target is written in.
