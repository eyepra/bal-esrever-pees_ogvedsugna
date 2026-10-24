#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capability registry: the one place that decides what this host can actually do.

WHY THIS EXISTS
---------------
An earlier version of this file answered the capability question from a hand-written list of
21 rows whose `needs` column was prose, and delegating every probe to one other script. That
is a description of a route, not a measurement of one: "needs a debugger" cannot tell you
whether the debugger is installed, whether it can be driven without a human, or whether the
host's virtualisation layer will intercept the mechanism you plan to use.

So the question is answered here, once, from probed facts:

  * a capability has a **closure** -- the atoms it needs, plus the capabilities it depends on,
    expanded recursively (`depends_on`), so `hardware_breakpoint` cannot be ok while the
    debugger it needs is blocked, and `dump_repair` cannot be ok while `dump_capture` is;
  * an atom is either probed on this host (an executable on PATH or under `EXEREV_TOOLS`, an
    importable module, a file this skill ships, a processor feature, a privilege, an operator
    supplied artifact) or it is an external **artifact** the host cannot install -- those are
    reported as missing, never silently assumed;
  * a missing atom carries a **next action that can be executed**: the exact directory to
    expose, environment variable to set, or package to install, with the command written out;
  * a cost estimate is attached only where this repository measured one, and is labelled
    `unverified` where it did not. A guess presented as a measurement is the failure this
    module exists to remove;
  * an alternative route is expressed as `any_of`, so "use one of these" is resolved by
    probing rather than by a preference nobody checked.

WHAT IT DOES NOT DO
-------------------
It never installs anything, never imports a probed module (probing uses
`importlib.util.find_spec`, so a module is never executed), never runs a debugger, and never
touches a target.

CAPABILITY DECLARATION
----------------------
A script may declare its capability as the first line of its own docstring, written as

    capability: <capability_id>[, <capability_id>]

directly under the opening quotes, before the prose. `doctor.py` reads that declaration when
it is present. Scripts without one are resolved through `SCRIPT_CAPABILITIES` below, which is
an explicit, auditable mapping; a script present in neither is reported as `unknown` and
**counted**, never skipped.

Usage
-----
    python capabilities.py                    # every capability, one line each
    python capabilities.py --verbose          # + missing atoms and the next action
    python capabilities.py --list             # ids and names only
    python capabilities.py <capability_id>    # one capability, verbosely
    python capabilities.py --json             # machine-readable, all
    python capabilities.py --json byte_patch  # machine-readable, one

Exit codes: 0 = every capability ok, 3 = at least one blocked, 2 = usage error,
4 = internal error. The last line is `RESULT=<token>`.
"""

import argparse
import ast
import importlib.util
import json
import os
import re
import shutil
import sys

# A real declaration is `capability: id` or `capability: id, id2` and nothing else. See
# `declared_capability` for why the pattern must not accept a template.
_DECLARATION_RE = re.compile(r'(?i)^capability:\s*([a-z_][a-z0-9_]*(?:\s*,\s*[a-z_][a-z0-9_]*)*)$')

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(SKILL_DIR))

# ---------------------------------------------------------------- exit codes
# 0 success / 1 negative finding / 2 usage / 3 environment short of a capability
# 4 internal error. Shared by every script in this kit; keep the numbers stable.
EXIT_OK = 0
EXIT_USE = 2
EXIT_ENV = 3
EXIT_INTERNAL = 4

TOKENS = {
    'ok': 'capabilities_ok',
    'partial': 'capabilities_partial',
    'blocked': 'capabilities_blocked',
    'use': 'usage_error',
    'internal': 'internal_error',
}

# Cost estimates. `basis` is the strength label of the *measurement*:
#   observed   -- timed in this repository, the figure and its source recorded
#   unverified -- nobody here has timed it; the number is a planning aid only
ATOMS = {
    # --- the interpreter ------------------------------------------------------
    'python310': {
        'name': 'Python 3.10+',
        'kind': 'python',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'Every script here is standard-library only. A bare interpreter is a working '
                'install, which is why no other Python atom is required by anything.',
    },

    # --- Python modules -------------------------------------------------------
    'module:pefile': {
        'name': 'pefile (third-party PE reader)',
        'kind': 'module',
        'module': 'pefile',
        'install': 'python -m pip install pefile',
        'est_minutes': 2,
        'basis': 'observed',
        'note': 'Not needed: scripts/peutil.py reads PE images without it. Listed because its '
                'answers are worth cross-checking against a second implementation.',
    },
    'module:capstone': {
        'name': 'capstone (disassembly backend)',
        'kind': 'module',
        'module': 'capstone',
        'install': 'python -m pip install capstone',
        'est_minutes': 2,
        'basis': 'observed',
        'note': 'The route from a byte range to instructions when no full disassembler is '
                'installed. Version drift changes which instructions decode, so record it.',
    },
    'module:keystone': {
        'name': 'keystone (assembler backend)',
        'kind': 'module',
        'module': 'keystone',
        'install': 'python -m pip install keystone-engine',
        'est_minutes': 3,
        'basis': 'unverified',
        'note': 'Assembling a replacement for a code range. The mirror of capstone; needed only '
                'when a patch must be written rather than picked from existing bytes.',
    },
    'module:unicorn': {
        'name': 'unicorn (CPU emulation)',
        'kind': 'module',
        'module': 'unicorn',
        'install': 'python -m pip install unicorn',
        'est_minutes': 3,
        'basis': 'observed',
        'note': 'Emulating a bounded routine so it can be called without its program. The cost '
                'is never the CPU model, it is stubbing everything the routine calls.',
    },
    'module:lief': {
        'name': 'lief (binary rewriting)',
        'kind': 'module',
        'module': 'lief',
        'install': 'python -m pip install lief',
        'est_minutes': 3,
        'basis': 'observed',
        'note': 'Rewriting structures rather than editing bytes in place. Useful when a change '
                'cannot be equal-length, which is exactly when this skill says to stop and think.',
    },
    'module:frida': {
        'name': 'frida (host package)',
        'kind': 'module',
        'module': 'frida',
        'install': 'python -m pip install frida  (host version must match the agent that runs '
                   'inside the target)',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'The host half. Where it is an old release, a target on a recent runtime can be '
                'refused before any hook is placed.',
    },
    'module:triton': {
        'name': 'triton (dynamic binary analysis, tainting and symbolic expressions)',
        'kind': 'module',
        'module': 'triton',
        'install': 'python -m pip install triton-library  (the import name is `triton`; confirm '
                   'the distribution name for your interpreter before trusting this line)',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'The route for reducing a trace rather than reading it: symbolise the inputs, '
                'taint them through the instructions, and hand the resulting expression to a '
                'solver. Requires a build toolchain on some interpreters.',
    },
    'module:z3': {
        'name': 'z3-solver (SMT solver)',
        'kind': 'module',
        'module': 'z3',
        'install': 'python -m pip install z3-solver',
        'est_minutes': 2,
        'basis': 'observed',
        'note': 'The reduction step: an expression becomes a small equivalent one, or a '
                'condition becomes a witness. A model returned is not the same as an answer '
                'validated against the target.',
    },
    'module:angr': {
        'name': 'angr (symbolic execution and path exploration)',
        'kind': 'module',
        'module': 'angr',
        'install': 'python -m pip install angr',
        'est_minutes': 15,
        'basis': 'unverified',
        'note': 'Explores paths rather than executing one. The cost is the environment model: a '
                'routine that calls into the platform needs those calls stubbed before a run '
                'reaches the condition you care about.',
    },

    # --- static analysis ------------------------------------------------------
    'tool:ghidra': {
        'name': 'Ghidra (headless capable)',
        'kind': 'tool',
        'tool': 'analyzeHeadless',
        'alternatives': ['analyzeHeadless.bat', 'ghidraRun'],
        'install': 'unpack the Ghidra release and put its support/ directory on EXEREV_TOOLS, '
                   'or call analyzeHeadless with an absolute path',
        'est_minutes': 10,
        'basis': 'observed',
        'note': 'The one decompiler route that is free and scriptable. Its headless launcher '
                'does the work unattended; the GUI is not required and should not be scripted.',
    },
    'tool:ida': {
        'name': 'IDA Pro / IDA Free',
        'kind': 'tool',
        'tool': 'ida64',
        'alternatives': ['ida', 'idat64', 'idat'],
        'install': 'install IDA and put its directory on EXEREV_TOOLS',
        'est_minutes': 20,
        'basis': 'unverified',
        'note': 'Autonomous runs need the dialog-suppressing switch together with a script '
                'switch; the two are separate and only one of them runs your code.',
    },
    'tool:binaryninja': {
        'name': 'Binary Ninja',
        'kind': 'tool',
        'tool': 'binaryninja',
        'install': 'install Binary Ninja; the Python API is imported as `binaryninja`',
        'est_minutes': 15,
        'basis': 'unverified',
        'note': 'Headless use is gated on the licence rather than on the API: an edition that '
                'does not include headless access refuses the operation. Confirm before planning.',
    },
    'tool:radare2': {
        'name': 'radare2',
        'kind': 'tool',
        'tool': 'r2',
        'alternatives': ['radare2'],
        'install': 'install radare2 and put its bin/ on EXEREV_TOOLS',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'The lightest scriptable disassembler here: a command string in, text or JSON '
                'out, no licence and no GUI.',
    },
    'tool:rizin': {
        'name': 'rizin (radare2 fork)',
        'kind': 'tool',
        'tool': 'rz-bin',
        'install': 'install rizin; its tools are named rz-* and its flags differ from radare2',
        'est_minutes': 5,
        'basis': 'unverified',
        'note': 'A fork, not an alias. A command copied from a radare2 page can mean something '
                'different here, which is worth knowing before following a tutorial.',
    },
    'tool:cutter': {
        'name': 'Cutter',
        'kind': 'tool',
        'tool': 'Cutter',
        'install': 'install Cutter (a graphical front end over rizin)',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'Graphical. Useful for a human reading a control-flow graph, not for an '
                'unattended run.',
    },
    'tool:diec': {
        'name': 'Detect It Easy, console form',
        'kind': 'tool',
        'tool': 'diec',
        'alternatives': ['die', 'diel'],
        'install': 'download the release and put its directory on EXEREV_TOOLS; `diec` is the '
                   'console binary, `die` the GUI, `diel` the scanner alone',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'Names a packer or protector from structure. An identification is a starting '
                'point, not a route: the same file can be named differently by two tools.',
    },
    'tool:dumpbin': {
        'name': 'dumpbin (MSVC toolchain)',
        'kind': 'tool',
        'tool': 'dumpbin',
        'install': 'install the Visual Studio build tools and put the directory containing '
                   'dumpbin on EXEREV_TOOLS, or run it from a developer command prompt',
        'est_minutes': 25,
        'basis': 'observed',
        'note': 'Header and import inspection from Microsoft. scripts/peutil.py answers the same '
                'questions offline, which is why this is optional here.',
    },
    'tool:innoextract': {
        'name': 'innoextract (Inno Setup extractor)',
        'kind': 'tool',
        'tool': 'innoextract',
        'install': 'winget install --id dscharrer.innoextract   (or download the release archive '
                   'and put its directory on EXEREV_TOOLS)',
        'est_minutes': 2,
        'basis': 'observed',
        'note': 'Unpacks an Inno Setup installer without running it. Measured here: it listed and '
                'extracted a 6.1.0-format installer although its own banner declares support to '
                '6.0.5, so treat the banner as a signal about the tool rather than a verdict on '
                'your file -- try it before routing around it.',
    },
    'tool:7z': {
        'name': '7-Zip',
        'kind': 'tool',
        'tool': '7z',
        'alternatives': ['7za', '7zz'],
        'install': 'install 7-Zip and put its directory on EXEREV_TOOLS',
        'est_minutes': 3,
        'basis': 'observed',
        'note': 'Unpacks many container formats, and notably NOT Inno Setup. Useful for package '
                'and self-extracting-archive payloads and for nested archives.',
    },
    'tool:strings': {
        'name': 'strings',
        'kind': 'tool',
        'tool': 'strings',
        'install': 'ships with a GNU toolchain (MinGW, MSYS2, Git for Windows)',
        'est_minutes': 3,
        'basis': 'observed',
        'note': 'Minimum-length and encoding defaults differ between implementations, so the '
                'same file gives different lists. Record the invocation with the result.',
    },
    'tool:objdump': {
        'name': 'objdump',
        'kind': 'tool',
        'tool': 'objdump',
        'install': 'ships with a GNU toolchain; a MinGW build reads PE files as well as ELF',
        'est_minutes': 3,
        'basis': 'observed',
        'note': 'Section dump and disassembly without a licence. Its output is large, so fold it '
                'before it reaches anything with a context limit.',
    },

    # --- debuggers ------------------------------------------------------------
    'tool:x64dbg': {
        'name': 'x64dbg',
        'kind': 'tool',
        'tool': 'x64dbg',
        'alternatives': ['x32dbg'],
        'install': 'download the snapshot archive and put its release/ directory on EXEREV_TOOLS',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'Graphical, and the command line it accepts is a startup form (a file, an '
                'argument, an optional command string) rather than a scripting interface. Treat '
                'its scripting as a thing a human drives.',
    },
    'tool:windbg': {
        'name': 'WinDbg (and its command-line engine)',
        'kind': 'tool',
        'tool': 'windbg',
        'alternatives': ['WinDbgX', 'dbgeng'],
        'install': 'install WinDbg from the Store or the SDK; the modern package is a separate '
                   'binary from the classic one',
        'est_minutes': 15,
        'basis': 'observed',
        'note': 'The only route to a recorded replay of a user-mode session, and the only '
                'supported kernel debugger. Both of those are capabilities of this tool alone.',
    },
    'tool:cdb': {
        'name': 'cdb (command-line debugger engine)',
        'kind': 'tool',
        'tool': 'cdb',
        'install': 'install the Debugging Tools for Windows component of the SDK',
        'est_minutes': 15,
        'basis': 'unverified',
        'note': 'The unattended form: a process or a dump plus a quoted command list, output to '
                'stdout. This is the debugger an agent should prefer over driving a GUI.',
    },
    'tool:gdb': {
        'name': 'gdb',
        'kind': 'tool',
        'tool': 'gdb',
        'install': 'ships with MinGW-w64 or MSYS2',
        'est_minutes': 10,
        'basis': 'observed',
        'note': 'Works on PE images with a matching build, and its PE support is narrower than '
                'its ELF support. Fine for a locally compiled helper, not the first choice for '
                'a hardened target.',
    },
    'tool:ttd': {
        'name': 'Time Travel Debugging recorder',
        'kind': 'tool',
        'tool': 'ttd',
        'alternatives': ['TTD.exe'],
        'install': 'ships with the modern WinDbg package',
        'est_minutes': 15,
        'basis': 'observed',
        'note': 'Records a user-mode session for replay. Elevated, user-mode only, and the '
                'recording is large; replay is read-only.',
    },

    # --- instrumentation ------------------------------------------------------
    'tool:frida': {
        'name': 'frida (command-line tools)',
        'kind': 'tool',
        'tool': 'frida',
        'alternatives': ['frida-trace', 'frida-ps'],
        'install': 'python -m pip install frida-tools',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'The command-line front ends over the host module. Useful without writing an '
                'agent; a hook is a modification, so it changes the observation.',
    },
    'tool:procdump': {
        'name': 'ProcDump',
        'kind': 'tool',
        'tool': 'procdump',
        'alternatives': ['procdump64'],
        'install': 'download the Sysinternals package and put its directory on EXEREV_TOOLS',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'Capture triggered by a condition (a fault, a threshold, a delay). Note its own '
                'licence terms before distributing anything captured with it.',
    },
    'tool:scylla': {
        'name': 'Scylla (import table reconstruction)',
        'kind': 'tool',
        'tool': 'Scylla',
        'install': 'download the standalone release, or use the plugin shipped inside x64dbg',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'Turns a dump whose imports were destroyed back into something that can be '
                'analysed. Its own documentation records cases where a fully correct rebuild is '
                'not achievable, which is worth reading before promising one.',
    },

    # --- tracing --------------------------------------------------------------
    'tool:wpr': {
        'name': 'Windows Performance Recorder',
        'kind': 'tool',
        'tool': 'wpr',
        'install': 'included in Windows; kernel providers need an elevated session',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'The supported way to record a system-wide trace. Start and stop are commands, '
                'so a session can be driven unattended.',
    },
    'tool:xperf': {
        'name': 'xperf',
        'kind': 'tool',
        'tool': 'xperf',
        'install': 'install the Windows Performance Toolkit',
        'est_minutes': 20,
        'basis': 'unverified',
        'note': 'Older than the recorder and still the tool some guides name. Its flag set is '
                'not the recorder\'s, so a copied command may be read as something else.',
    },
    'tool:logman': {
        'name': 'logman / tracerpt',
        'kind': 'tool',
        'tool': 'logman',
        'alternatives': ['tracerpt'],
        'install': 'included in Windows',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'Session control and trace-to-text conversion. tracerpt is how a recorded trace '
                'becomes something readable without a GUI.',
    },
    'tool:tshark': {
        'name': 'tshark',
        'kind': 'tool',
        'tool': 'tshark',
        'alternatives': ['dumpcap'],
        'install': 'install Wireshark and put its directory on EXEREV_TOOLS',
        'est_minutes': 10,
        'basis': 'observed',
        'note': 'Reading a capture rather than taking one. Where a capture must be taken, the '
                'question is usually which boundary it was taken at.',
    },

    # --- managed code ---------------------------------------------------------
    'tool:dotnet': {
        'name': '.NET runtime and SDK',
        'kind': 'tool',
        'tool': 'dotnet',
        'install': 'install the .NET SDK',
        'est_minutes': 15,
        'basis': 'observed',
        'note': 'Answers which runtimes exist, and runs managed tooling distributed as a '
                'package.',
    },
    'tool:ildasm': {
        'name': 'ildasm',
        'kind': 'tool',
        'tool': 'ildasm',
        'install': 'ships with a Visual Studio install (the SDK), not with the runtime alone',
        'est_minutes': 25,
        'basis': 'unverified',
        'note': 'Disassembles CIL to text. The reverse direction is what matters for a managed '
                'patch: text back to an assembly.',
    },
    'tool:ilasm': {
        'name': 'ilasm',
        'kind': 'tool',
        'tool': 'ilasm',
        'install': 'ships with the .NET Framework and with Visual Studio',
        'est_minutes': 25,
        'basis': 'unverified',
        'note': 'Assembles CIL text back into an assembly, which is how a managed edit is made '
                'without a hex editor touching metadata.',
    },
    'tool:de4dot': {
        'name': 'de4dot',
        'kind': 'tool',
        'tool': 'de4dot',
        'install': 'download a de4dot build and put its directory on EXEREV_TOOLS',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'Reports which supported protector it recognises with -d, and cleans the ones it '
                'knows. The output is a new assembly with new tokens, so it is for reading, not '
                'for patching the shipped file.',
    },
    'tool:ilspycmd': {
        'name': 'ilspycmd (ILSpy command line)',
        'kind': 'tool',
        'tool': 'ilspycmd',
        'install': 'dotnet tool install --global ilspycmd',
        'est_minutes': 5,
        'basis': 'unverified',
        'note': 'Decompiles to C# and prints IL with -il, so the map and the fact can come from '
                'one install; -l and --dump-table read the metadata without decompiling.',
    },
    'tool:dnspy': {
        'name': 'dnSpyEx',
        'kind': 'tool',
        'tool': 'dnSpy',
        'install': 'download a dnSpyEx release and put its directory on EXEREV_TOOLS',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'The managed debugger: breakpoints in decompiled code, locals, an IL editor, and '
                'the in-memory image for an assembly that decrypts itself. GUI only, so it is '
                'for a human at the keyboard rather than an unattended run.',
    },
    'tool:dotpeek': {
        'name': 'dotPeek',
        'kind': 'tool',
        'tool': 'dotPeek64',
        'alternatives': ['dotPeek32'],
        'install': 'download dotPeek from JetBrains and put its directory on EXEREV_TOOLS',
        'est_minutes': 10,
        'basis': 'unverified',
        'note': 'Free Windows decompiler on ReSharper\'s engine. Its advantages over a plain reader '
                'are navigation, the compiler-generated-code toggle, a Process Explorer that '
                'opens a loaded module, and exporting a .csproj. GUI only, no command line.',
    },

    # --- language toolchains (for reading their output) -----------------------
    'tool:go': {
        'name': 'Go toolchain',
        'kind': 'tool',
        'tool': 'go',
        'install': 'install the Go distribution',
        'est_minutes': 10,
        'basis': 'observed',
        'note': 'Its own commands read a Go binary\'s build information and disassemble it with '
                'symbols, which is far cheaper than reconstructing them.',
    },
    'tool:rustc': {
        'name': 'Rust toolchain',
        'kind': 'tool',
        'tool': 'rustc',
        'alternatives': ['cargo'],
        'install': 'install rustup',
        'est_minutes': 20,
        'basis': 'observed',
        'note': 'Mostly for building a helper. Reading a Rust binary benefits from symbol '
                'knowledge rather than from the toolchain being installed.',
    },
    'tool:gcc': {
        'name': 'gcc (or another C compiler)',
        'kind': 'tool',
        'tool': 'gcc',
        'install': 'install MinGW-w64 or MSYS2',
        'est_minutes': 15,
        'basis': 'observed',
        'note': 'Builds a small helper, a probe, or a fixture. A toolchain that is present but '
                'cannot compile anything is not an installed toolchain: make it produce output '
                'once before relying on it.',
    },
    'tool:nasm': {
        'name': 'nasm',
        'kind': 'tool',
        'tool': 'nasm',
        'install': 'install nasm',
        'est_minutes': 5,
        'basis': 'observed',
        'note': 'Assembling a small stub without a C toolchain.',
    },
    'tool:signtool': {
        'name': 'signtool',
        'kind': 'tool',
        'tool': 'signtool',
        'install': 'ships with the Windows SDK',
        'est_minutes': 25,
        'basis': 'unverified',
        'note': 'Inspects and applies signatures. Editing a signed image invalidates the '
                'signature over it, so this is for reading the state, not for restoring it.',
    },

    # --- files this skill ships ----------------------------------------------
    'file:peutil.py': {'name': 'scripts/peutil.py (PE reader)', 'kind': 'file',
                       'script': 'peutil.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:pe_triage.py': {'name': 'scripts/pe_triage.py (triage)', 'kind': 'file',
                          'script': 'pe_triage.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:pepatch.py': {'name': 'scripts/pepatch.py (patch engine)', 'kind': 'file',
                        'script': 'pepatch.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:aob_scan.py': {'name': 'scripts/aob_scan.py (pattern locator)', 'kind': 'file',
                         'script': 'aob_scan.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:pe_diff.py': {'name': 'scripts/pe_diff.py (build differ)', 'kind': 'file',
                        'script': 'pe_diff.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:hwprobe.py': {'name': 'scripts/hwprobe.py (host probe)', 'kind': 'file',
                        'script': 'hwprobe.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:make_fixture_pe.py': {'name': 'scripts/make_fixture_pe.py (fixture builder)',
                                'kind': 'file', 'script': 'make_fixture_pe.py',
                                'est_minutes': 0, 'basis': 'observed'},
    'file:scan_leaks.py': {'name': 'scripts/scan_leaks.py (identity scanner)', 'kind': 'file',
                           'script': 'scan_leaks.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:fold.py': {'name': 'scripts/fold.py (record folder)', 'kind': 'file',
                     'script': 'fold.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:doctor.py': {'name': 'scripts/doctor.py (environment doctor)', 'kind': 'file',
                       'script': 'doctor.py', 'est_minutes': 0, 'basis': 'observed'},
    'file:dart_snapshot_strings.py': {'name': 'scripts/dart_snapshot_strings.py (Dart snapshot '
                                              'literals)', 'kind': 'file',
                                      'script': 'dart_snapshot_strings.py',
                                      'est_minutes': 0, 'basis': 'observed'},

    # --- host capabilities, probed rather than assumed ------------------------
    'host:elevated': {
        'name': 'an elevated session',
        'kind': 'host',
        'probe': 'elevation',
        'install': 'run the shell as administrator; several routes below are unavailable '
                   'without it and cannot be raised from inside a script',
        'est_minutes': 1,
        'basis': 'observed',
        'note': 'Kernel providers, driver loading and the replay recorder all need this.',
    },
    'host:hypervisor_free': {
        'name': 'a host with no hypervisor under it',
        'kind': 'host',
        'probe': 'hypervisor',
        'install': 'not installable: this is a property of the machine. Move the analysis to a '
                   'host whose processor feature report does not set the hypervisor bit, or '
                   'accept that the intercepted routes are intercepted',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'A virtualisation layer can consume the debug exception, which turns a working '
                'mechanism into one that never fires and looks like a tool fault.',
    },
    'host:debug_registers': {
        'name': 'hardware breakpoints usable on this host',
        'kind': 'host',
        'probe': 'breakpoints',
        'install': 'not installable: the architecture provides a small fixed number, and a '
                   'hypervisor decides whether they reach your handler',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'They do not modify the bytes they watch, which is why this route is reached '
                'for when a code check would notice a software breakpoint.',
    },
    'host:intel_pt_cpu': {
        'name': 'a processor that reports the trace feature',
        'kind': 'host',
        'probe': 'intel_pt',
        'install': 'not installable: a hardware capability',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'Reports capability only. A trace unit also needs a way to reach its output, '
                'and on this platform that path is not documented for user mode.',
    },
    'host:test_signing': {
        'name': 'boot configuration that accepts test-signed code',
        'kind': 'host',
        'probe': 'test_signing',
        'install': 'bcdedit /set testsigning on  (then reboot; a security feature may still '
                   'refuse the load)',
        'est_minutes': 10,
        'basis': 'observed',
        'note': 'Prerequisite for loading your own driver. A reboot, and on some configurations '
                'a policy that refuses regardless.',
    },
    'host:etw': {
        'name': 'OS-level event tracing available',
        'kind': 'host',
        'probe': 'etw',
        'install': 'included in Windows; kernel providers need the elevated atom',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'User-mode providers work without elevation; kernel events do not.',
    },

    # --- artifacts the host cannot install ------------------------------------
    'artifact:sample': {
        'name': 'the target binary (operator supplied)',
        'kind': 'artifact',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'This repository ships no sample. Every target-behaviour claim is therefore '
                'unverified until someone runs a route against one.',
    },
    'artifact:two_builds': {
        'name': 'two builds of the same program',
        'kind': 'artifact',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'Required by the build-diff route, and by signature migration across versions.',
    },
    'artifact:pdb': {
        'name': 'a matching symbol file (PDB)',
        'kind': 'artifact',
        'est_minutes': 0,
        'basis': 'unverified',
        'note': 'Not generated by this repository. Where the vendor publishes one, it is the '
                'cheapest route from an address to a name.',
    },
    'artifact:dumped_image': {
        'name': 'a captured image of a running process',
        'kind': 'artifact',
        'est_minutes': 0,
        'basis': 'observed',
        'note': 'Produced by a capture route, not by this repository. A capture is bytes, not '
                'the loader\'s work: repairing it is arithmetic over the section table.',
    },
}

# ---------------------------------------------------------------------------
# Capabilities: what a task needs, expressed as atoms plus the capabilities it
# depends on. `any_of` lists alternatives where one of them will do; the closure
# is satisfied when a required alternative is present.
# ---------------------------------------------------------------------------
CAPABILITIES = {
    'pe_structure_read': {
        'name': 'Read a PE image\'s structure',
        'required': ['python310', 'file:peutil.py'],
        'scripts': ['peutil.py'],
        'note': 'Headers, sections, directories, imports, exports, resources, TLS, relocations '
                'and the checksum, offline and dependency-free.',
    },
    'pe_triage': {
        'name': 'Triage an unknown image into signals',
        'required': ['python310', 'file:pe_triage.py'],
        'depends_on': ['pe_structure_read'],
        'scripts': ['pe_triage.py'],
        'note': 'Identity, build evidence, protective signals with their measurements, and a '
                'next-action list. Signals, never verdicts.',
    },
    'equal_length_patch': {
        'name': 'Apply a verified equal-length byte patch',
        'required': ['python310', 'file:pepatch.py'],
        'depends_on': ['pe_structure_read'],
        'scripts': ['pepatch.py'],
        'note': 'Read-only input, a new output file, an ambiguity guard, checksum recomputation, '
                'and every patched byte re-read from the written file.',
    },
    'aob_locate': {
        'name': 'Locate a byte pattern and judge the pattern',
        'required': ['python310', 'file:aob_scan.py'],
        'depends_on': ['pe_structure_read'],
        'scripts': ['aob_scan.py'],
        'note': 'Reports the hit count and a verdict, so a pattern that is a coin flip is '
                'visible before it is used as a locator.',
    },
    'build_compare': {
        'name': 'Compare two builds of the same program',
        'required': ['python310', 'file:pe_diff.py', 'artifact:two_builds'],
        'depends_on': ['pe_structure_read'],
        'scripts': ['pe_diff.py'],
        'note': 'Content-hash comparison with the volatile header fields normalised, so a '
                'same-size replacement is caught and a rebuild is not reported as a change.',
    },
    'fixture_generation': {
        'name': 'Build a synthetic PE fixture offline',
        'required': ['python310', 'file:make_fixture_pe.py'],
        'scripts': ['make_fixture_pe.py'],
        'note': 'Deterministic, byte-reproducible images carrying the awkward cases on purpose. '
                'No third-party sample is needed to exercise any parser here.',
    },
    'identity_scan': {
        'name': 'Scan a tree for target identity before publishing',
        'required': ['python310', 'file:scan_leaks.py'],
        'scripts': ['scan_leaks.py'],
        'note': 'Rules with their exemptions, findings with their context, and an exit code that '
                'can gate a commit.',
    },
    'host_capability_probe': {
        'name': 'Report what this host can actually support',
        'required': ['python310', 'file:hwprobe.py'],
        'scripts': ['hwprobe.py'],
        'note': 'Processor features read from the processor, OS and policy facts, the tool '
                'inventory, and a per-route verdict in three states.',
    },
    'record_folding': {
        'name': 'Fold a large record into a bounded summary',
        'required': ['python310', 'file:fold.py'],
        'scripts': ['fold.py'],
        'note': 'The mechanism behind the bounded-summary rule: one pass, a shape decided from '
                'the bytes rather than the name, every list capped and every cap admitted, and '
                'the record itself left untouched for the question that needs all of it.',
    },

    # --- static analysis beyond what this kit ships ---------------------------
    'static_disassembly': {
        'name': 'Disassemble or decompile with a full engine',
        'required': ['python310'],
        'any_of': ['tool:ghidra', 'tool:ida', 'tool:binaryninja', 'tool:radare2', 'tool:rizin',
                   'tool:objdump'],
        'note': 'One of these is enough. The GUI-only ones are for a human; the ones with a '
                'documented non-interactive entry point are what an unattended run should use.',
    },
    'managed_inspect': {
        'name': 'Inspect or change a managed assembly',
        'required': ['python310'],
        'any_of': ['tool:ildasm', 'tool:ilasm', 'tool:dotnet', 'tool:de4dot', 'tool:ilspycmd',
                   'tool:dnspy', 'tool:dotpeek'],
        'note': 'A managed assembly is a different artifact: the logic is CIL and metadata, and '
                'editing bytes without updating the tables produces something that loads and '
                'does the wrong thing. Reading the logic needs a decompiler or a disassembler; '
                'changing it needs an assembler.',
    },
    'installer_inspect': {
        'name': 'Get at an installer\'s payload without running it',
        'required': ['python310'],
        'any_of': ['tool:innoextract', 'tool:7z', 'tool:strings', 'tool:radare2'],
        'note': 'The container type decides the route, and the interesting binary may not exist on '
                'disk until a particular step of the install runs. Extract first, then re-triage '
                'what came out: it is a new unknown, not the same target.',
    },
    'flutter_static': {
        'name': 'Read a Flutter application\'s compiled Dart',
        'required': ['python310', 'file:dart_snapshot_strings.py'],
        'note': 'Literals are recoverable from the snapshot with nothing installed, which is '
                'usually enough to name the feature and the tier vocabulary. Locating the code that '
                'uses a literal needs the object pool parsed, and that needs version-matched '
                'tooling this repository does not ship.',
    },

    # --- dynamic routes -------------------------------------------------------
    'interactive_debug': {
        'name': 'Debug interactively',
        'required': ['artifact:sample'],
        'any_of': ['tool:x64dbg', 'tool:windbg'],
        'note': 'A human at the keyboard. Useful and not scriptable; ask for it rather than '
                'substituting a weaker method.',
    },
    'commandline_debug': {
        'name': 'Debug unattended, or read a dump, from a command',
        'required': ['artifact:sample'],
        'any_of': ['tool:cdb', 'tool:windbg', 'tool:gdb'],
        'note': 'A process or a dump plus a command string, output to stdout. This is the shape '
                'an agent can drive.',
    },
    'runtime_instrumentation': {
        'name': 'Instrument a live process',
        'required': ['module:frida', 'artifact:sample'],
        'any_of': ['tool:frida', 'module:frida'],
        'note': 'A hook is a modification, so it changes what is being observed. Count the calls '
                'an effect produces rather than only redirecting them.',
    },
    'hardware_breakpoint': {
        'name': 'Stop or watch without modifying the bytes',
        'required': ['host:debug_registers', 'artifact:sample'],
        'depends_on': ['commandline_debug'],
        'note': 'The point of this route is that it leaves no byte changed, so a code check does '
                'not notice it. Data watches are width-limited and must be aligned, and there is '
                'no read-only data watch.',
    },
    'intel_pt_capture': {
        'name': 'Record an instruction trace with hardware assistance',
        'required': ['host:intel_pt_cpu'],
        'note': 'The processor reports the feature; reaching the trace output needs a driver or '
                'an undocumented interface, which is the actual constraint. Treat capture, not '
                'decoding, as the open question.',
    },
    'ttd_record': {
        'name': 'Record a user-mode session for replay',
        'required': ['tool:ttd', 'host:elevated', 'artifact:sample'],
        'note': 'The only documented single-machine instruction-level route here. User-mode only, '
                'the recording is large, and replay is read-only.',
    },
    'dump_capture': {
        'name': 'Capture a process\'s memory',
        'required': ['artifact:sample'],
        'any_of': ['tool:procdump', 'tool:cdb', 'tool:windbg', 'tool:gdb'],
        'note': 'Needs the rights to read the process. A minidump and a full dump answer '
                'different questions, and the largest minidump is not the smallest full one.',
    },
    'dump_repair': {
        'name': 'Turn a capture back into something loadable',
        'required': ['artifact:dumped_image'],
        'depends_on': ['pe_structure_read'],
        'any_of': ['tool:scylla', 'file:peutil.py'],
        'note': 'Mapping each section back to a file offset, restoring a wiped header, and '
                'rebuilding what the loader did. A dump that reads fine can still refuse to load.',
    },

    # --- system and kernel ----------------------------------------------------
    'etw_capture': {
        'name': 'Record OS-level events',
        'required': ['host:etw'],
        'any_of': ['tool:wpr', 'tool:logman', 'tool:xperf'],
        'note': 'Kernel providers need the elevated atom. The documented problem is loss '
                'accounting and a single active session, not raw overhead.',
    },
    'kernel_debug': {
        'name': 'Debug a kernel component',
        'required': ['host:test_signing', 'host:elevated'],
        'any_of': ['tool:windbg', 'tool:cdb'],
        'note': 'On a current host this means a second machine, or a boot configuration change. '
                'Local-only debugging cannot stop the target.',
    },
    'kernel_driver_load': {
        'name': 'Load instrumentation of your own into the kernel',
        'required': ['host:test_signing', 'host:elevated', 'host:hypervisor_free'],
        'depends_on': ['kernel_debug'],
        'note': 'Every one of these gates is real, and the last one is not installable: a '
                'security feature may refuse an unsigned driver regardless of the boot setting.',
    },
    'hypervisor_observe': {
        'name': 'Observe from below the operating system',
        'required': [],
        'depends_on': ['kernel_driver_load'],
        'note': 'What an ordinary observer cannot see, and also what can intercept an ordinary '
                'observer. This repository documents the route and ships no hypervisor.',
    },

    # --- algorithmic reduction ------------------------------------------------
    'symbolic_reduce': {
        'name': 'Reduce a trace or a condition with a solver',
        'required': ['module:z3', 'artifact:sample'],
        'any_of': ['module:triton', 'module:angr', 'module:unicorn'],
        'note': 'The reduction step is cheap; the environment model is not. A model returned is '
                'not the same as an answer validated against the target\'s own outputs.',
    },
    'licence_classification': {
        'name': 'Classify a licence mechanism before touching it',
        'required': ['python310'],
        'note': 'No tool is needed for the classification itself, which is why it is a capability '
                'of the written material rather than of an install.',
    },
    'algorithm_recovery': {
        'name': 'Recover a key, hash or licence algorithm',
        'required': ['artifact:sample'],
        'depends_on': ['static_disassembly'],
        'note': 'Identify from constants and tables before reversing instruction by instruction; '
                'validate the candidate against the target\'s own outputs.',
    },
}


def _all_atoms():
    """Every atom id a capability refers to, in a stable order.

    Only `required` and `any_of` are read, because those name **atoms**. `depends_on` names
    *capabilities*, and folding the two together produced a list of identifiers drawn from two
    different vocabularies -- which is exactly how a capability id ended up in an atom slot, where
    the probe reports `atom is not defined` and the branch can never be satisfied.
    """
    seen = []
    for cap in CAPABILITIES.values():
        for key in ('required', 'any_of'):
            for atom in cap.get(key, []):
                if atom not in seen:
                    seen.append(atom)
    return seen


def extra_tool_dirs():
    """Directories to search in addition to PATH.

    Written this way because a tool that is installed off PATH is not a missing tool: SDKs,
    versioned installs and unpacked archives all live somewhere nothing adds to the search
    path. The variable is read on every call so a caller can set it before constructing a
    probe.
    """
    dirs = []
    for var in ('EXEREV_TOOLS', 'EXE_REVERSE_TOOLS'):
        raw = os.environ.get(var)
        if raw:
            dirs.extend(p for p in raw.split(os.pathsep) if p)
    return dirs


class Probe(object):
    """Answers "is this atom present" by measuring, never by importing or executing.

    Every probe is cached, because a capability closure asks the same question repeatedly and
    a probe that spawns a process should answer once.
    """

    def __init__(self, tool_dirs=None):
        self.tool_dirs = list(tool_dirs) if tool_dirs is not None else extra_tool_dirs()
        self._cache = {}
        self._host = None

    # --- primitives -------------------------------------------------------
    def which(self, name):
        """Resolve an executable, then a file of that name under the extra directories."""
        key = ('which', name)
        if key in self._cache:
            return self._cache[key]
        found = shutil.which(name)
        via = 'PATH' if found else None
        if not found:
            for d in self.tool_dirs:
                for ext in ('', '.exe', '.cmd', '.bat', '.py'):
                    cand = os.path.join(d, name + ext)
                    if os.path.isfile(cand):
                        found, via = cand, 'EXEREV_TOOLS'
                        break
                if found:
                    break
        self._cache[key] = (found, via)
        return found, via

    def have_module(self, name):
        key = ('module', name)
        if key not in self._cache:
            try:
                self._cache[key] = importlib.util.find_spec(name) is not None
            except (ImportError, ValueError):
                self._cache[key] = False
        return self._cache[key]

    def host(self):
        """Host facts, taken from the probe this kit already ships.

        Imported lazily and never executed as a subprocess: the probe is a module, and its
        CPUID reader is the same code path `hwprobe.py` uses when run directly.
        """
        if self._host is None:
            try:
                if HERE not in sys.path:
                    sys.path.insert(0, HERE)
                import hwprobe
                with hwprobe.Cpuid() as cpuid:
                    rows, _raw = hwprobe.probe_cpu(cpuid)
                os_rows = hwprobe.probe_os()
                priv_rows = hwprobe.probe_privilege()
                self._host = {'cpu': rows, 'os': os_rows, 'privilege': priv_rows}
            except Exception as exc:                      # pragma: no cover - host dependent
                self._host = {'error': str(exc)}
        return self._host

    def _host_flag(self, kind):
        """One of the probed host facts, as a tri-state: True / False / None (unknown)."""
        h = self.host()
        if 'error' in h:
            return None

        def row_value(rows, needle):
            for r in rows:
                if needle.lower() in (r.get('note') or '').lower():
                    return r.get('value')
            return None

        if kind == 'elevation':
            return row_value(h['privilege'], 'TokenElevation')
        if kind == 'hypervisor':
            v = row_value(h['cpu'], 'ECX[31]')
            return None if v is None else (not v)
        if kind == 'intel_pt':
            return row_value(h['cpu'], 'EBX[25]')
        if kind == 'breakpoints':
            # The architecture provides the registers; whether they reach your handler on a
            # machine with a hypervisor under it is the open question, so the atom is true
            # only when no virtualisation layer reports itself.
            hyp = row_value(h['cpu'], 'ECX[31]')
            return None if hyp is None else (not hyp)
        if kind == 'test_signing':
            v = row_value(h['os'], 'SystemStartOptions')
            if v is None:
                return None
            return 'testsigning' in v if isinstance(v, list) else False
        if kind == 'etw':
            return bool(self.which('wpr')[0] or self.which('logman')[0])
        return None

    # --- per-atom ---------------------------------------------------------
    def atom(self, atom_id):
        if atom_id in self._cache:
            return self._cache[atom_id]
        spec = ATOMS.get(atom_id)
        if spec is None:
            self._cache[atom_id] = {'ok': False, 'detail': 'atom is not defined'}
            return self._cache[atom_id]

        kind = spec.get('kind')
        result = {'ok': False, 'detail': ''}

        if kind == 'python':
            v = sys.version_info
            result = {'ok': v >= (3, 10), 'detail': 'python %d.%d.%d' % v[:3]}
        elif kind == 'module':
            ok = self.have_module(spec['module'])
            result = {'ok': ok, 'detail': spec['module'] + (' importable' if ok
                                                            else ' not importable')}
        elif kind == 'tool':
            names = [spec['tool']] + list(spec.get('alternatives', []))
            for n in names:
                path, via = self.which(n)
                if path:
                    result = {'ok': True, 'detail': '%s (%s)' % (path, via)}
                    break
            else:
                result = {'ok': False, 'detail': 'none of: ' + ', '.join(names)}
        elif kind == 'file':
            path = os.path.join(HERE, spec['script'])
            result = {'ok': os.path.isfile(path), 'detail': path}
        elif kind == 'host':
            v = self._host_flag(spec.get('probe'))
            if v is None:
                result = {'ok': False, 'detail': 'unknown (the probe could not answer)'}
            else:
                result = {'ok': bool(v),
                          'detail': 'measured' if v else 'not available on this host'}
        elif kind == 'artifact':
            result = {'ok': False, 'detail': 'operator supplied; not detectable from here'}

        self._cache[atom_id] = result
        return result


def closure(capability_id):
    """The capability plus everything it transitively depends on, de-duplicated, ordered."""
    out, stack = [], [capability_id]
    while stack:
        cid = stack.pop(0)
        if cid in out:
            continue
        out.append(cid)
        for dep in CAPABILITIES.get(cid, {}).get('depends_on', []):
            if dep not in out:
                stack.append(dep)
    return out


def resolve(capability_id, probe=None):
    """Resolve one capability: its own atoms, its alternatives, and its dependencies."""
    probe = probe or Probe()
    spec = CAPABILITIES.get(capability_id)
    if spec is None:
        return None
    chain = closure(capability_id)

    missing_atoms = []
    for atom in spec.get('required', []):
        r = probe.atom(atom)
        if not r['ok']:
            missing_atoms.append((atom, r['detail']))

    alternatives = spec.get('any_of', [])
    alt_state = None
    if alternatives:
        present = [a for a in alternatives if probe.atom(a)['ok']]
        alt_state = present
        if not present:
            missing_atoms.append(('any_of(' + ','.join(alternatives) + ')',
                                  'none present: ' + ', '.join(
                                      '%s [%s]' % (a, probe.atom(a)['detail'])
                                      for a in alternatives)))

    blocked_deps = []
    for dep in spec.get('depends_on', []):
        sub = resolve(dep, probe)
        if sub and sub['state'] != 'ok':
            blocked_deps.append((dep, sub['state']))

    ok = not missing_atoms and not blocked_deps
    state = 'ok' if ok else ('blocked' if (missing_atoms or blocked_deps) else 'ok')
    return {
        'id': capability_id,
        'name': spec.get('name', capability_id),
        'state': state,
        'required': spec.get('required', []),
        'any_of': alternatives,
        'alternatives_present': alt_state,
        'depends_on': spec.get('depends_on', []),
        'blocked_deps': blocked_deps,
        'missing': missing_atoms,
        'closure': chain,
        'scripts': spec.get('scripts', []),
        'note': spec.get('note', ''),
    }


def resolve_all(probe=None):
    probe = probe or Probe()
    return [resolve(cid, probe) for cid in CAPABILITIES]


def verdict(results):
    blocked = [r for r in results if r['state'] != 'ok']
    if not blocked:
        return 'ok', 0
    return 'blocked', EXIT_ENV


# ---------------------------------------------------------------------------
# Which capability does a script serve? Declared in the script where possible,
# mapped here otherwise, and counted as unknown when neither applies.
# ---------------------------------------------------------------------------
SCRIPT_CAPABILITIES = {
    'peutil.py': ['pe_structure_read'],
    'pe_triage.py': ['pe_triage'],
    'pepatch.py': ['equal_length_patch'],
    'aob_scan.py': ['aob_locate'],
    'pe_diff.py': ['build_compare'],
    'hwprobe.py': ['host_capability_probe'],
    'make_fixture_pe.py': ['fixture_generation'],
    'scan_leaks.py': ['identity_scan'],
    'fold.py': ['record_folding'],
    'capabilities.py': ['host_capability_probe'],
    'doctor.py': ['host_capability_probe'],
    # Not a Python script, but it belongs to a capability all the same: it instruments a live
    # process to decide whether a located branch is the branch that decides. Left out of the table,
    # the doctor counts it in the denominator and reports it unclassified -- which is the check
    # working, and it is cheaper to answer than to silence.
    'gate_probe.js': ['runtime_instrumentation'],
}


def declared_capability(path):
    """Read a `capability: <id>[, <id>]` line from the first line of a script's docstring.

    Static, so a script never has to run to be classified. Returns [] when there is no
    declaration, which is not the same as declaring none.

    The match is deliberately strict -- plain identifiers only. A looser one accepted the
    documentation of this convention, which lives in *this* file's own docstring, and reported
    the registry as declaring `capability: <capability_id>[, <capability_id>]`. A declaration
    that is a template is not a declaration.
    """
    try:
        with open(path, encoding='utf-8') as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError):
        return []
    doc = ast.get_docstring(tree) or ''
    for line in doc.splitlines():
        m = _DECLARATION_RE.match(line.strip())
        if m:
            return [c.strip() for c in m.group(1).split(',') if c.strip()]
    return []


def capabilities_for_script(name, path=None):
    """(ids, source) where source is 'declared', 'mapped' or 'unknown'."""
    path = path or os.path.join(HERE, name)
    declared = declared_capability(path)
    if declared:
        return declared, 'declared'
    mapped = SCRIPT_CAPABILITIES.get(name)
    if mapped:
        return mapped, 'mapped'
    return [], 'unknown'


def human_report(results, verbose=False):
    lines = []
    width = max(len(r['name']) for r in results) if results else 10
    for r in results:
        mark = 'ok ' if r['state'] == 'ok' else 'BLK'
        lines.append('  %s %-*s  %s' % (mark, width, r['name'], r['id']))
        if verbose and r['state'] != 'ok':
            for atom, detail in r['missing']:
                spec = ATOMS.get(atom, {})
                lines.append('        missing atom : %s' % atom)
                lines.append('        detail       : %s' % detail)
                if spec.get('install'):
                    lines.append('        next action  : %s' % spec['install'])
                if spec.get('est_minutes') is not None:
                    lines.append('        est. minutes : %s (basis: %s)'
                                 % (spec['est_minutes'], spec.get('basis', 'unverified')))
            for dep, state in r['blocked_deps']:
                lines.append('        blocked by   : %s (%s)' % (dep, state))
                # Say where to look next. A row blocked by another capability has no missing atom of
                # its own, so without this the verbose report names the obstacle and stops -- which
                # reads as "there is nothing you can do" when the answer is one query away.
                lines.append('        see          : capabilities.py %s --verbose' % dep)
    return lines


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write('error: %s\n' % message)
        sys.exit(EXIT_USE)


def main(argv=None):
    ap = _Parser(description='Capability registry: what this host can actually do, and what '
                             'to do about what it cannot.')
    ap.add_argument('capability', nargs='?', help='one capability id')
    ap.add_argument('--verbose', action='store_true', help='detail on what is missing')
    ap.add_argument('--list', action='store_true', help='ids and names only')
    ap.add_argument('--json', action='store_true', help='machine-readable')
    ap.add_argument('--tools-dir', action='append', default=[],
                    help='extra directory to search for tools (repeatable)')
    args = ap.parse_args(argv)

    probe = Probe(tool_dirs=(args.tools_dir or None))

    if args.list:
        for cid, spec in CAPABILITIES.items():
            print('  %-26s %s' % (cid, spec.get('name', '')))
        print('\n%d capabilities.' % len(CAPABILITIES))
        # `--list` prints identifiers, so the verdict beside them has to be a real one. It used to
        # print the ok token and exit 0 unconditionally, which reported a healthy registry on a host
        # where most of it is blocked -- the same registry that `--json` reports as blocked. Two
        # views of one table disagreeing is worse than either view alone.
        results = resolve_all(probe)
        v, rc = verdict(results)
        ok = sum(1 for r in results if r['state'] == 'ok')
        print('%d ok, %d blocked' % (ok, len(results) - ok))
        print('RESULT=%s' % TOKENS[v])
        return rc

    if args.capability:
        if args.capability not in CAPABILITIES:
            sys.stderr.write('error: no such capability: %s\n' % args.capability)
            print('RESULT=%s' % TOKENS['use'])
            return EXIT_USE
        results = [resolve(args.capability, probe)]
        if args.json:
            print(json.dumps(results[0], indent=2))
            print('RESULT=%s' % TOKENS[verdict(results)[0]])
            return verdict(results)[1]
        print('capability: %s' % results[0]['name'])
        print('scripts   : %s' % (', '.join(results[0]['scripts']) or '-'))
        print('requires  : %s' % ', '.join(results[0]['required']))
        if results[0]['any_of']:
            print('any of    : %s' % ', '.join(results[0]['any_of']))
            print('present   : %s' % (', '.join(results[0]['alternatives_present']) or 'none'))
        if results[0]['depends_on']:
            print('depends on: %s' % ', '.join(results[0]['depends_on']))
        print('state     : %s' % results[0]['state'])
        for line in human_report(results, verbose=True):
            print(line)
        if results[0]['note']:
            print('note      : %s' % results[0]['note'])
        v, rc = verdict(results)
        print('RESULT=%s' % TOKENS[v])
        return rc

    results = resolve_all(probe)
    if args.json:
        print(json.dumps(results, indent=2))
        v, rc = verdict(results)
        print('RESULT=%s' % TOKENS[v])
        return rc
    print('capability registry -- %d capabilities' % len(results))
    for line in human_report(results, verbose=args.verbose):
        print(line)
    ok = sum(1 for r in results if r['state'] == 'ok')
    print('\n%d ok, %d blocked' % (ok, len(results) - ok))
    v, rc = verdict(results)
    print('RESULT=%s' % TOKENS[v])
    return rc


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(EXIT_INTERNAL)
