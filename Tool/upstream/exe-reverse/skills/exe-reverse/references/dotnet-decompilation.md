# Reading a .NET assembly: decompilers, CIL, and the logic underneath

Goal: produce a defensible account of what a managed program does -- its inputs, its decisions and
its effects -- using a decompiler for the shape and CIL for the truth.

**What this answers:** which of `de4dot`, `ildasm`/`ilasm`, ILSpy/`ilspycmd` and dnSpyEx to reach
for; how to run each; how to read a CIL listing; what the compiler-generated names mean; and the
sequence that turns a method body into a statement about business logic.

**When to load this:** after `managed-dotnet.md` has classified the artifact as an ordinary managed
assembly and the task is to *understand* it -- a licence check to locate, a feature gate to explain,
an algorithm to recover, or decompiler output that is unreadable, renamed, or does not add up.

**Not this file:** classification, bundles, ReadyToRun and Native AOT (`managed-dotnet.md`); the
structural rules for a managed edit and its verification (`managed-dotnet.md`, `patching.md`);
native code (`static-analysis.md`); a live debugging session (`dynamic-debugging.md`).

## The order of work

**R1 -- Decompile for the map, disassemble for the fact.** A decompiler turns a stack machine into
C#-shaped text by guessing types and expressions. That guess is what makes a 300-method assembly
navigable. It is also where the wrong answer comes from. Read C# to form a hypothesis, read the IL
around the decisive branch to test it, and go back.

**R2 -- Start at a surface, never at a random method.** A surface is something observable: a menu
item, an error string, a command-line flag, a file the program writes, a request it sends. Walk
inward from it. Reading the assembly alphabetically has no stopping rule.

**R3 -- One question per load.** "What does this method return?" and "who calls it?" are different
reads of the same file. Answer the one you asked before opening the next tool.

**R4 -- Write the hypothesis down, then try to kill it.** A reconstruction that exists only in the
transcript cannot be checked by the next reader, including you after a context change.

**R5 -- The cleaned assembly is not the shipped assembly.** A deobfuscated file has different
tokens, different names and possibly different types. Analysis may use it; a patch, a hash or a
version comparison must go back to the original.

**R6 -- Every line of the logic map carries a grade.** `observed` (a tool printed it, or a run
showed it), `inferred` (the step is reasoned), `unverified` (assumed). A map whose rows are all
`inferred` is a reading list, not a finding.

## Tool roles

| Question | Reach for | What it gives | What it costs |
|---|---|---|---|
| What is in this assembly, and what does it reference? | `ilspycmd -l c`, `ildasm /text`, or the tree pane of either GUI | types, members, dependencies, resources -- the map | minutes, and no truth about behaviour |
| What does this method do, in C#? | ILSpy (GUI) or `ilspycmd` | readable reconstruction, fast | it is a reconstruction; P22 |
| Is this instruction sequence what I think it is? | `ildasm /text /tokens`, `ilspycmd -il`, dnSpyEx IL view | the actual body, tokens, exception clauses | slow to read; no types or names |
| Where does this value come from at run time? | dnSpyEx debugger | breakpoints, locals, call stack, values | interactive; one session at a time |
| What did the obfuscator do, and can it be undone? | `de4dot -d`, then `de4dot` | a classifier and, for supported protectors, a cleaned assembly | the output is a new artifact with new tokens |
| Change one method and run it now | dnSpyEx IL editor, or `ildasm` -> edit `.il` -> `ilasm` | an executable experiment | the change lives in memory (dnSpyEx) or in a rebuilt file (ilasm); neither is the deliverable until verified |
| Read a .NET assembly where no Windows tooling exists | `ilspycmd` (cross-platform), `monodis` | C# or IL on Linux/macOS | older or fewer framework references resolved |

The four GUI decompilers overlap and are not interchangeable in practice.

| Tool | What it is | Best at | Limits that change the plan |
|---|---|---|---|
| ILSpy / `ilspycmd` | ILSpy's own decompiler; GUI on Windows, Linux and macOS, plus a CLI | reading and navigating current assemblies; the CLI makes the same engine scriptable | the GUI is a human tool; the output is still a reconstruction |
| dnSpyEx | a debugger first, with an assembly editor and an IL editor | breakpoints in decompiled code, locals, editing IL, in-memory images | Windows-only, GUI-only; not a tool an unattended run can drive |
| dotPeek | JetBrains' free decompiler, built on ReSharper's engine | navigation and search, the compiler-generated-code toggle, Process Explorer, exporting a `.csproj`, acting as a symbol server for a Visual Studio debug session | Windows-only, GUI-only, no documented command line |
| JustDecompile | Telerik/Progress decompiler | legacy assemblies, project export | **retired**: no new downloads and no support since 2024-04-02 (`observed`: the vendor page is now a discontinuation notice); use it only where it is already installed |

dotPeek is the one to reach for when the question is *navigation* rather than a single method.
`observed`: JetBrains' feature page lists ReSharper-style *Find Usages* and *Go to Everything*,
opening `.dll`/`.exe`/`.winmd`, archives and folders, a Process Explorer that lists a running
process's modules and decompiles the managed ones, a *show compiler-generated code* toggle, an IL
view synchronized with the C# view, project export, and a symbol-server mode that supplies a
Visual Studio debugger with sources. It is free of charge.

JustDecompile is worth knowing about because it is still installed on some analysis machines, not
because it is a route to plan. A retired tool receives no fixes for newer metadata, so a failure to
open an assembly is the tool's age first and the target second.

None of the four is a substitute for reading the IL of the branch you care about.

## Setup, and the reference problem

`ilspycmd` installs as a .NET global tool:

```
dotnet tool install --global ilspycmd
ilspycmd --help
```

`observed`: the ILSpyCmd README at version 11.0.0 states that the pointer package needs .NET SDK
10.0.100 or newer, and that on Windows x64 and Linux x64 the tool is published as a Native AOT
build. Pin a version for an older SDK; do not assume the newest package installs.

`observed`: `ildasm` and `ilasm` are documented as installed with Visual Studio, not with the
runtime alone (Microsoft Learn, "Ildasm.exe" and "Ilasm.exe"). The .NET Core line distributes them
separately from the SDK's default path, so "the SDK is installed" does not imply "ildasm is on
PATH" -- check before writing it into a plan.

A missing reference is the most common reason decompiled output lies. When an assembly's dependency
cannot be resolved, the decompiler renders the unknown type as `object`, drops members, or emits
code that would not compile; the IL is unaffected. So:

- If the C# contains `object` where a domain type belongs, or members that "do not exist", read IL
  until the reference is supplied, or supply it.
- ILSpy and dnSpyEx resolve dependencies from the target's directory and the GAC/runtime; a sample
  copied out of its install directory loses that context. Work on a copy of the *directory*.
- Target framework matters for tool choice: an ILSpy old enough to predate a metadata feature
  cannot open the file, and `de4dot`'s dnlib predates the .NET Core era entirely (`inferred`:
  from the 2015 copyright range in its source and its obfuscator table; `unverified` per file).

## de4dot: the pre-pass, and its limits

`de4dot` is a deobfuscator and unpacker for the obfuscators it knows. `observed`: its README
states GPLv3, no support, and a feature list that includes inlining, string and constant
decryption, proxy-call removal, control-flow deobfuscation, resource and embedded-assembly
decryption, tamper-detection and anti-debug removal, symbol renaming, and conversion of a wrapped
Win32 PE back to a .NET PE.

Detect first. Detection is cheap, non-destructive, and tells you whether the rest is worth doing:

```
de4dot -d sample.dll
de4dot -d -r C:\samples -ru
```

`observed`: the README documents `-d` as detect-only, prints "Unknown obfuscator" for an
unsupported or unobfuscated file, and combines with `-r` (recursive) and `-ru` (ignore unknown
files). Then deobfuscate into a separate directory, which is the shape the README recommends --
copy the input tree to the output tree first, so unprocessed files survive:

```
de4dot -r C:\samples -ru -ro C:\samples-cleaned
```

`observed`: `-r`, `-ru` and `-ro` are the README's recursive form. For a single file the tool
writes a new assembly rather than editing in place; in the builds in circulation the output name is
the input's with a `-cleaned` suffix (`unverified`: not reproduced here, and the flag set of a
2015-era tool is not stable across forks). List the directory after the run instead of assuming a
name, and never point a later step at the input by habit.

What it cannot do, and what that means for the plan:

- **Names do not come back.** `observed`: the README says symbol renaming is impossible to restore
  because the original names are not in the assembly. A cleaned file gives readable *generated*
  names, not the vendor's. Every name in your notes is either original or yours; keep the
  distinction (see "Recovering names from evidence").
- **Only the protectors in its table.** A protector newer than the tool, or a custom one, is
  "Unknown", and `-p un` handles it by preserving tokens and removing nothing (`observed`:
  README). That is a safe pass-through, not a deobfuscation.
- **It is old.** The source's copyright range ends in 2015. Newer metadata, newer runtime
  features, and newer protector versions are outside what it was written against. A crash or a
  malformed output is the tool's age; it is not evidence that the target implements a defence.
- **Dynamic decryption executes target code.** `observed`: the feature list includes decrypting
  strings and methods "statically or dynamically". Treat any dynamic mode as running the sample:
  isolate the host first (`environment.md`).
- **The output is a new artifact.** Entry point, type list and tokens can change. Hash it, keep the
  original, and re-run classification rather than assuming the shape survived.

`observed`: the README also documents `--preserve-tokens`, `--keep-types` and
`--dont-create-params` for the cases where a later step depends on token identity. Reach for them
when you intend to patch, not when you intend to read.

## Reading the artifact before decompiling

The metadata is the map, and it costs one command.

```
ilspycmd -l c sample.dll                 # entity kinds: c, i, s, d, e (class, interface, struct, delegate, enum)
ilspycmd --list-resources sample.dll      # embedded resources, .resources entries listed inside
ilspycmd --dump-table TypeDef sample.dll  # RID, token, names, heap offsets, coded indexes
ilspycmd --dump-pdb sample.dll            # debug information, if any
ildasm /text /tokens sample.dll            # whole assembly as IL, with metadata tokens
ildasm sample.dll /out=sample.il          # same, to a file
```

`observed`: the option names and their wording are the `ilspycmd --help` text shipped with
ILSpyCmd 11.0.0 (`-l`, `--list-resources`, `--dump-table`, `--dump-pdb`), and the
`ildasm` switches are the Microsoft Learn parameter table (`/text`, `/tokens`, `/out=`,
`/bytes`, `/raweh`, `/source`, `/linenum`, `/pubonly`, `/visibility:`).

Read in this order, and write down one line per answer:

1. **`.assembly extern`** -- what it depends on. A vendor licensing assembly, `System.Management`
   (WMI), `Microsoft.Win32.Registry`, `System.Net.Http`, a database client, a crypto library:
   each narrows the mechanism before a single method is read.
2. **The type table** -- is there a `Licence`, `License`, `Activation`, `Trial`, `Auth`,
   `Settings`, `Config`, `ApiClient`? Names that survived are the cheapest evidence there is.
3. **Custom attributes** -- `[DllImport]` names a native call, `[STAThread]` says WinForms,
   `[Route]`/`[HttpGet]` says ASP.NET, `[JsonPropertyName]`/`[DataMember]` names the wire
   fields, `[CommandLine]` names the flags. Attributes are strings that survived renaming more
   often than method names did.
4. **String literals** -- a listing's `ldstr` operands are the domain vocabulary: error text,
   registry paths, URLs, SQL, file names, product names. Search them before reading control flow.
5. **The entry point** -- `.entrypoint` in the IL, or the `Main` the manifest names. A library
   has none, which is itself the answer: the host owns the entry.

## How to read a CIL listing

### The shape of a method body

A body opens with a header (tiny or fat) that states the code size, the maximum stack depth, and
whether locals and exception clauses follow. In text form:

```
.method private hidebysig instance bool Check(string key) cil managed
{
  // Code size 42 (0x2a)
  .maxstack 2
  .locals init (string V_0, bool V_1)
  ...
} // end of method App::Check
```

- `.maxstack` and `.locals` are facts about the body, not about the source: the C# compiler's
  local count is not recoverable from them.
- Exception handling is **not** in the linear instruction stream. `.try` blocks and their
  `catch`/`finally`/`fault`/`filter` handlers carry clause offsets; a `leave` that jumps out
  of a protected region is the tell that you are inside one.
- An empty body, or a body that is only `ldnull; throw`, is a stub: the real code is elsewhere
  (a protector, a P/Invoke, a generated method).

### Instruction crib sheet

| CIL | C# it usually came from | What it buys you |
|---|---|---|
| `ldarg.0` then `ldfld` | `this.field` | instance state; the field name is a domain word |
| `call` / `callvirt` | non-virtual call / virtual or interface dispatch | `callvirt` also carries the null check C# emits for `x.M()`; a `call` to an instance method is a base call or a compiler-chosen non-virtual call |
| `newobj` / `initobj` | `new X(...)` / `default(T)` | allocation site; `initobj` on a local is struct zeroing |
| `ldstr` | string literal | business vocabulary, error text, keys, URLs |
| `ldc.i4.*`, `ldc.i8`, `ldc.r8` | numeric literal | thresholds, timeouts, retry counts |
| `ldtoken` + `Type.GetTypeFromHandle` | `typeof(T)` | reflection, serialisation, DI registration |
| `box` / `unbox.any` / `constrained.` | boxing, cast, generic call on a struct | interface dispatch through a type parameter |
| `isinst` / `castclass` | `is`, `as`, `(T)` | type tests, pattern matching |
| `switch` | dense integer `switch` | the jump table is in the instruction; a sparse switch becomes a comparison chain |
| `brtrue`/`brfalse`, `beq`/`bne.un`, `bgt`/`blt`/`bge`/`ble` | `if`, `while`, `&&`, `\|\|`, comparisons | a gate is a branch whose two arms have different effects |
| `leave`, `.try`, `catch`, `finally`, `fault`, `filter` | `try`/`catch`/`finally`, `using`, `lock`, `foreach` | the clause table, not the listing, holds the structure |
| `dup` | a value used twice: object initialiser, null-conditional, assignment-as-expression | explains a stack dance a decompiler hid |
| `ldftn` + `newobj ...::.ctor(object, native int)` | delegate creation: method group, lambda, event handler | the wiring from a surface to the logic |
| `add_`/`remove_` + a delegate | `+=`/`-=` | event subscription, the usual path from a button to a gate |
| `call ... GetEnumerator/MoveNext/get_Current` | `foreach` | iteration order matters for "last one wins" logic |
| `Monitor.Enter`/`Exit` | `lock` | concurrency, and where a second instance is refused |
| `callvirt ... Dispose` in a `finally` | `using` | resource lifetime |
| `string::Concat`, `string::Format`, `AppendLiteral`+`AppendFormatted` | `+`, `string.Format`, interpolation | C# 10+ uses an interpolated-string handler, so interpolation looks like a builder, not a concat |
| `Nullable<T>` `get_HasValue`, `GetValueOrDefault` | `T?`, `??`, `!= null` | optional configuration values |
| `newarr`, `ldlen`, `ldelem`, `stelem` | array creation, `.Length`, indexing | table-driven logic |
| `conv.i4`, `conv.u8`, `conv.r8` | numeric conversion | width and sign are where algorithm work actually breaks |
| `throw` / `rethrow` | `throw;` | the message string names the failure and often the gate |
| `ldsfld` / `stsfld` | static field | configuration, caches, singletons, global state |
| `nop` | nothing | debug builds, and padding left by an obfuscator |

Two cautions on the crib sheet. First, the mapping is one direction only: `brtrue` is a branch,
not necessarily an `if` -- it is equally a loop condition, a `&&` short-circuit, or a compiler
null check. Second, CIL is a stack machine; the expression nesting the decompiler shows is its
inference, and the instruction order is the fact.

### A decision, read in IL

The following is a constructed illustration, not a sample (`inferred`):

```
IL_0000: call       class App.Config App.Settings::get_Current()
IL_0005: ldfld      string App.Config::LicenseKey
IL_000a: call       bool [System.Runtime]System.String::IsNullOrEmpty(string)
IL_000f: brtrue.s   IL_0024
...
IL_0024: ldstr      "No licence key found."
IL_0029: call       void [System.Windows.Forms]System.Windows.Forms.MessageBox::Show(string)
```

That reads as `if (string.IsNullOrEmpty(Settings.Current.LicenseKey)) { MessageBox.Show("No licence
key found."); ... }`. Four different kinds of claim came out of six instructions, and they must
not be graded together:

- **Observed in the listing:** a static property `Settings.Current` is read, its `LicenseKey`
  field is tested for null-or-empty, and the true branch shows a message.
- **Inferred:** the message is the refusal path for the licence feature, and this method is part of
  the gate.
- **Unknown:** that the key is validated here rather than later; that `Settings.Current` reads a
  file, the registry, or a server response; that no second check exists (P22's neighbour: a
  decompiler showing one check is not a search for the others).

### What CIL does not tell you

- **Names.** Locals, parameters and often types are unnamed without a PDB; the decompiler's
  `num`, `text`, `flag` are its own.
- **Inlining and dead code.** The JIT decides what runs, and the compiler already removed what
  could not run at compile time. A method present in metadata may never be called.
- **Reflection and DI.** `Activator.CreateInstance`, `Type.GetType(string)`,
  `Assembly.Load`, `MethodInfo.Invoke`, and container registrations are calls that do not
  appear in the call graph. "No caller" is not "dead" in a framework application.
- **The executed copy.** ReadyToRun and tiered compilation mean the bytes that ran may not be the
  CIL you read (`managed-dotnet.md`). When the loaded assembly is not the file on disk -- a
  single-file bundle's extracted copy, an assembly decrypted at start-up -- open the module from
  the running process rather than from the path: dotPeek's Process Explorer and dnSpyEx's modules
  window both do this (`observed`: dotPeek features page; dnSpyEx README).

## Compiler-generated names, and what they were

Roslyn leaves a consistent signature on the constructs it lowers. Recognising the name saves the
minutes spent wondering why a method has a state machine in it.

| Shape | Origin | How to read it |
|---|---|---|
| `<M>d__3` as a struct, `IAsyncStateMachine` | `async` method | `MoveNext` is the body, split at each `await`; `<>1__state` selects the segment |
| `<M>d__3` as a class, `IEnumerable`/`IEnumerator` | iterator | `MoveNext`/`Current`; each `yield` is a suspension point |
| `<>c` | cached non-capturing lambda holder | the `b__N_M` methods are the lambdas |
| `<>c__DisplayClassN_M` | closure | its fields are the captured variables; `b__N_M` is the lambda |
| `<M>g__Local\|N_M` | local function | a helper the source declared inside a method |
| `<>f__AnonymousType0` | anonymous type | the projection shape of a LINQ query |
| `<PrivateImplementationDetails>` | array/struct initialiser blobs; string-switch hashing | `ComputeStringHash` means a `switch` on a string |
| `<Module>` | module initialiser | runs before `Main`; a favourite place for a check |
| `get_`/`set_`, `add_`/`remove_` | property and event accessors | |
| `IFace.Method` | explicit interface implementation | |
| `Program.<Main>$` | top-level statements | the real entry point |
| `<Clone>$`, `PrintMembers`, `EqualityContract` | `record` | generated value semantics |

`inferred`: in Roslyn's async machines `<>1__state` starts at `-1` and `-2` marks completion,
while an iterator's initial state is `-2`; each `await` or `yield` is a non-negative state. The
convention is stable across compilers in practice but is not part of the language specification, so
read the `switch` rather than trusting the numbers. Newer C# adds shapes (collection expressions,
list patterns) that an older decompiler will render as raw IL; a construct that looks like a
state machine but is not should be read as "this decompiler does not know this lowering yet".

dotPeek exposes the same information as a view instead of as a listing: its *show compiler-generated
code* option renders lambdas, closures and auto-properties in their lowered form (`observed`:
dotPeek features page). That is faster than reading IL when the question is "what did this lambda
capture", and it is still a rendering -- the IL remains the authority.

## From method to business logic

A "logic map" is the deliverable, not a decompiled file. Build it in this order.

1. **Pin one observable behaviour** as a sentence someone else could test: "Importing a CSV with
   120 rows produces 120 records" or "A second copy of the app exits with a message". One
   behaviour at a time; a map of the whole program is a rewrite of the program.
2. **Find the boundary that receives it.** The entry shape decides where to look:

   | Shape | The hook to find |
   |---|---|
   | Console, service | `Main(string[])`, `ServiceBase.Run`, a top-level `Program.<Main>$` |
   | WinForms | `Application.Run(new F())`; the designer's `InitializeComponent` wires `Click +=` to a handler |
   | WPF / Avalonia | generated `App.Main`; `Click=`, `Command=`, and bindings; `INotifyPropertyChanged` names the state |
   | ASP.NET Core | `Program.Main` -> builder; controllers or `MapGet`; attributes carry the routes |
   | Unity | no `Main`; `MonoBehaviour` subclasses, `Awake/Start/Update`, code in `Assembly-CSharp.dll` |
   | Plugin host | types implementing a host interface, discovered by reflection: no static caller |

3. **Walk inward one hop at a time**, and at each hop write down the data the method receives. A
   hop that adds no data is a wrapper; skip it by following the only call it makes.
4. **Stop at the first decision whose arms differ in effect.** Two arms that both call the same
   logger are not a business decision. A branch to a message, an exit, a different request, or a
   different file is.
5. **Recover the data contract.** For each input the decision reads: where does it come from --
   argument, config file, registry, licence file, embedded resource, server response, clock? This
   is the part that turns "there is a check" into "the trial flag is a local file, and deleting it
   restores the trial".
6. **Model the refusal path.** Denial is frequently not a crash: a message box, an exit code, a
   feature silently absent, a retry, a time bomb. Each is a different deliverable.
7. **Write the rows.** One row per branch, with the condition in C# form and the evidence that
   produced it:

   | # | Trigger | Input (source) | Condition | Effect | Evidence | Grade |
   |---|---|---|---|---|---|---|
   | 1 | app start | `LicenseKey` (config file) | `string.IsNullOrEmpty` | message, then exit | IL 0x06000012, IL_000f | observed |
   | 2 | "Export" clicked | `Rows` (grid) | `Rows.Count > 0` | writes CSV | handler token, string "/export" | inferred |

8. **Try to falsify row 1 and only row 1.** Re-read the branch in IL, set a breakpoint on it in
   dnSpyEx, and observe both arms with the original and a modified input. A map that has never had
   one row tested is a hypothesis with good formatting.

The seams where business logic hides, in the order they pay:

- **Strings.** Error text, config keys, registry paths, URLs, SQL, format strings. They survive
  renaming and they name the feature.
- **Enums and constants.** A `Tier`, `Plan`, `Feature` enum with three values tells you the
  product's own model; `const int MaxFreeRows = 50` is a limit expressed as a number.
- **Serialisation attributes.** `[JsonPropertyName]`, `[XmlElement]`, `[DataMember]` give the
  wire contract, which is the server's vocabulary and often the real model.
- **Interfaces and base classes.** What a class implements says what role it plays even when the
  class is named `a`.
- **Reflection and registration.** `AddSingleton<X>`, `services.AddTransient<...>`,
  `Assembly.GetTypes()` -- the composition root that names the participants.

## Recovering names from evidence

When the renamer won, names come from evidence, in this order of cost:

1. **A PDB.** Separate, embedded portable PDB, or a source-link reference. `ilspycmd --dump-pdb`
   shows what is there; `-usepdb` uses its local names. A mismatched PDB is worse than none: it
   produces confident wrong names.
2. **Surviving metadata names.** Public API, interface members, explicit implementations, and
   attributes often keep their names even when private members do not.
3. **Attribute arguments.** A `DllImport` target, a JSON property name, a route template, a
   command-line option: strings with meaning.
4. **String literals and exception messages.** The domain vocabulary, verbatim.
5. **Base types and interfaces.** Behaviour follows the role, not the name.
6. **Shape.** Parameter and return types, arity, call sites, position between an input and an
   effect. A `bool`-returning method with one string parameter called immediately before a
   message box is a validator until proven otherwise.
7. **Run time.** dnSpyEx locals and return values.

Rule: a name you assign is marked as yours, in the notes and in the logic map. Presenting a
recovered name as the vendor's destroys the reader's ability to tell what came from the file.

## Verifying a reconstruction

A decompiled method is a hypothesis (P22). Verification is cheapest in this order, and each step
can fail:

1. **Two renderings of the same body.** C# and IL. If they disagree, IL wins; if two decompilers
   disagree, neither has won -- the disagreement is the signal that the construct is being lowered
   in a way one of them does not model.
2. **Round-trip.** `ildasm /out=x.il sample.dll`, `ilasm /dll x.il`, then run both. A difference
   in behaviour locates what you misread: header flags, assembly references, resources, attributes.
   `observed`: Microsoft Learn documents `/out=` for ildasm and `/dll` for ilasm.
3. **One observed arm.** A breakpoint on the decision in dnSpyEx, with the operands watched, and
   the unmodified original run under the same conditions. A clean log is not an arm.
4. **The claim's grade, restated.** "The IL contains a comparison against an empty string"
   (observed) is not "the licence is refused for an empty key" (inferred until an arm is seen) and
   is certainly not "this is the only check" (unknown).

For a deliverable that is a patch rather than an account, the authority is the original file and
the verification is the one in `verification.md`: identity of what ran, which layer executed, and
the feature observed directly.

## Where this hands over

| The reading reaches | Go to |
|---|---|
| Mixed-mode image, or a `DllImport` whose comparison matters | `static-analysis.md`, then `patching.md`; classify the layer first with `managed-dotnet.md` |
| A single-file bundle whose payload is not on disk | `managed-dotnet.md`: extract, then re-triage what came out |
| ReadyToRun output: IL present, native copy executing | `managed-dotnet.md`; do not patch CIL and assume it ran |
| Native AOT output: no CIL to find | the native routes in `static-analysis.md` |
| Obfuscated control flow, a dispatcher, a VM | `virtualization-and-flattening.md` |
| The question is what the licence mechanism *is* | `license-mechanisms.md` |
| The question is a live value, not a static one | `dynamic-debugging.md` (native) or dnSpyEx (managed) |

## What this file does not cover

`unknown`, and it is worth stating precisely: **no .NET tool was installed on the host that wrote
this file**, so every command above is quoted from its project's or vendor's documentation and
none was executed here. `observed` in this file therefore means "the named document says so",
not "a run reproduced it". The versions behind the claims are the ILSpyCmd command-line help, the
Microsoft Learn pages for `ildasm` and `ilasm`, the de4dot README at the 2015-era source range,
and the dnSpyEx README, read on 2026-10-24; the exact revision of each is recorded with its
source in `skills/exe-reverse/evidence/tool-sources.md`.

Also not covered:

- BAML/XAML semantics beyond extracting the resource (`--resource` decompiles BAML to XAML;
  reading the result as a UI specification is a separate exercise).
- ReadyToRun IL editing and Native AOT symbol recovery.
- Assembly resolution for a sample whose dependencies are absent, and multi-module assemblies.
- Whether a given de4dot build reads a given modern assembly. That is a per-file measurement:
  run `-d`, then open the file, and record which of the two failed.
- Whether dotPeek opens a given runtime build. That is a per-version fact; JustDecompile's support
  is frozen at its 2024 retirement, which is why it is not in the capability registry.
- Any claim that a protector's output can be cleaned. "Unsupported obfuscator" is a statement
  about the tool's table, not about the target's strength.
