# Installers, self-extractors, and application packages

Goal: get the payload out of the container, and prove which payload the installer actually
executed, instead of analysing a file that was never the one that ran.

## When to load this

Load this when the sample is a `.msi`, an `.exe` that unpacks before it does anything, a
`.msix`/`.appx`, a setup wrapper around other files, or any case where the interesting binary
is nowhere on disk after the install finished. Load it **before** running the installer, not
after: the first run is also the run that changes the machine, and it may be the run that
downloads the real payload from a server you did not intend to touch.

## Identify the container from the file

Names lie. Identify by structure, and record what you saw.

| Container | How to identify it from the file | What it means |
|---|---|---|
| Windows Installer package (`.msi`) | Starts with the OLE compound-file signature `D0 CF 11 E0 A1 B1 1A E1` (`observed` on three cached packages under `C:\Windows\Installer` on this host, each 150 KB and 384 KB in size). Its content is read through the installer's database interface, not as a flat archive | A database plus a payload. Tables describe what to install, where, and which custom actions to run; the payload may be inside the container or in companion cabinets |
| Self-extracting archive | A native executable whose sections or overlay hold another file, often a cabinet, sometimes a vendor-specific archive. Behaviourally: run it with a help switch and it prints a switch list | A wrapper. The wrapper executes first; the payload executes second, and may come out to a temporary directory, to a chosen directory, or over the network |
| Cabinet (`.cab`) | Documented compressed container; `expand -d <source>.cab` lists its contents without extracting, and `expand <source>.cab -f:<files> <destination>` extracts a subset (`observed`: Microsoft's `expand` documentation) | The payload layer of many installers. Extracting here avoids running any installer logic |
| Application package (`.msix`, `.appx`) | A zip-shaped container with footprint files: `AppxManifest.xml` (identity, dependencies, capabilities, extension points), `AppxBlockMap.xml` (each file plus cryptographic hashes per 64 KB block), `AppxSignature.p7x` (the signature) (`observed`: Microsoft's MSIX overview) | Every package must be signed before installation. The payload is present as ordinary files, so extraction is a container operation, not a reverse-engineering problem |
| Vendor-specific setup builder output | No documented structure. Identify from embedded markers, an overlay appended to a valid PE, resource strings that name the setup framework, and the switch list the binary prints for `/?`, `/h`, `/help` | Treat as an unknown wrapper: enumerate before executing, and never assume another product's extractor works on it |

`observed`: Microsoft's Self-Extractor documentation describes a self-extracting package as a
self-extracting executable and documents the switch set, including `/?`, `/h` and `/help` to
list what the package supports, with the caveat that "not all switches may be available in all
packages". That caveat is the honest state of the whole category: the switch surface is a
property of the individual package, and the only reliable way to learn it is to ask the binary.

## What installing actually does

An install is a sequence of actions, not a file copy. The interesting cases all come from that.

- **Extraction and placement.** Files are copied from the container (or from cabinets, or from
  a URL) into their final locations. Until the relevant action runs, the binary does not exist
  on disk. An installer that defers extraction to a custom action, or downloads the payload,
  leaves you with a machine state that cannot be reconstructed by reading the original file
  alone.
- **Custom actions.** `observed`: Microsoft's custom actions documentation describes them as
  the escape hatch for launching an executable during installation, calling functions in a
  dynamic-link library, running script text, and deferring execution until the installation
  script runs. A custom action is arbitrary code with the installer's privileges: it can
  unpack, decrypt, download, patch, write licence data and decide whether the install should
  succeed at all. When the install behaves differently from the package it claims to be, the
  custom action is the first place to look.
- **Component registration.** The package records what it installed so it can repair and
  remove it: file records, registry records, shortcuts, services, and for COM-adjacent
  payloads the self-registration entry points. Registration is why an install can be undone
  and why a repair can overwrite what you changed.
- **Registry writes.** Windows Installer's registry table carries a root key per record, and
  the installer's own documentation states the default is context-dependent: writing under
  `HKEY_CURRENT_USER` for a per-user install and under `HKEY_LOCAL_MACHINE` for a per-machine
  install, with the per-machine case identified by setting the all-users property to 1
  (`observed`: Microsoft's registry table documentation). The same page documents the write
  actions (`WriteRegistryValues`, `RemoveRegistryValues`) and the value prefixes that choose
  registry data types.
- **Environment and machine state.** Services, drivers, firewall rules, scheduled tasks and
  environment variables are all common installation effects, and any of them can be the thing
  that actually gates the feature you are chasing.
- **A transform or a patch.** A package can be extended by a transform applied at install time
  and superseded by later patch files. Two machines with the same nominal product can be
  running different effective payloads.

## Extract the payload without running the installer

Ordered by how much of the installer you have to trust.

1. **Read the container directly.** For a compound-file package, read the streams as a
   compound file; for a package format, unzip; for a cabinet, `expand -d` to list and
   `expand -f:` to extract. This executes nothing. `unknown`: the stream layout of the `.msi`
   files observed on this host was not enumerated, so the specific stream names are not
   claimed here; the documented interface is the installer's database API and the tables it
   exposes.
2. **Ask the binary for its switches, then use the extract switch.** `observed`: the
   Self-Extractor switch list includes `/extract:[path]`, described as extracting the content
   of the package to the path folder. Running the wrapper to extract is not the same as
   installing, but it is still running vendor code: it is a deliberate step with a recorded
   hash and a snapshot, not a casual one.
3. **Administrative installation.** `observed`: `msiexec /a` is documented as the
   administrative installation option, `TARGETDIR` during an administrative installation
   "specifies the location to copy the installation package", and the installer creates a
   source image of all features except those marked level 0. This is the documented way to get
   a full payload tree in a chosen directory. Two warnings come straight from the same
   documentation and both matter: the administrative path runs its own action sequence (so it
   is not a no-op, and a custom action can still run), and transforms applied while creating
   the image have no effect, so a transform must be applied afterwards to see its behaviour.
4. **Install for real.** Sometimes the only honest answer, because the payload exists only
   after a custom action or a download. Do it on a copy of the machine, with the network
   posture chosen deliberately, and record what the installer contacted.

Useful knobs from the same documented option set: `/i` to install, `/x` to uninstall, `/f`
with its letter flags to repair (the `a` letter forces all files to be reinstalled, which will
undo a patch to an installed file), `/q` for user-interface level, `/l` with its flags to log,
`/t` for a transform, `/p` for a patch, and `/y`/`/z` to call a module's self-registration
entry points. Only public properties can be set on the command line, and they are matched
case-insensitively while their values keep their case.

For a self-extracting wrapper, the equivalent logging switch from the documented set is
`/log:[path to log file]`, and the package's own quiet switches (`/quiet`, `/passive`,
`/norestart`, `/forcerestart`) change how much of the install you will see happen.

### A worked extraction, measured end to end

An Inno Setup installer does not declare itself in a header the way a package format does, but its
shape is unmistakable in the triage report, and every signal below is a field the report already
prints. `observed`, on one 31,059,248-byte installer:

| Signal | Observed | Why it identifies this builder |
|---|---|---|
| Exported module | `SetupLdr.exe` | the setup loader's own name, exported from a program that should not export anything |
| A section named | `.itext` | not a name a C or C++ toolchain emits |
| Entry point | inside `.itext`, not the first code section | stubs run before the program proper |
| Toolchain | linker 2.25, **no Rich Header** | not an MSVC build, consistent with a stripped non-MSVC toolchain |
| Strings | `Inno Setup`, `SetupLdr`, `rDlPtS`, `zlb`, `LZMA1` | the product name, the loader, the data identifier, and two compression markers |

Extraction, with a purpose-built extractor rather than by running the installer:

```
winget install --id dscharrer.innoextract
innoextract --info    installer.exe                  # names the product and the setup data version
innoextract --list    installer.exe                  # payload inventory; nothing is written
innoextract --extract --output-dir OUT installer.exe
```

Measured on that target: `--info` reported the product name and `setup data version 6.1.0
(unicode)`; `--list` returned 158 entries; the extract finished in 9.2 s and produced 155 files
(87.6 MB), including a 26.8 MB `app/data/app.so`. `observed`.

**A version banner is a signal about the tool, not a verdict on your file.** This extractor's own
banner declares support up to setup data 6.0.5, and it listed and extracted a 6.1.0 image without
complaint. The honest sequence is to run the extraction and read the result, rather than to rule a
tool out from its documentation — and equally, not to promise a target will work because the banner
covers it.

Two consequences that generalise past this one product:

- **The download is not the program.** What came out was a launcher plus a Flutter payload, and the
  behaviour of interest was in neither the launcher nor any of the DLLs beside it. Re-triage the
  extracted tree as a new unknown: it is not the same target you started with.
- **The payload can be a different file format from the container.** A Windows installer delivered an
  **ELF** shared object. A workflow that assumes "extracted means PE" stops at that point; see
  `flutter-and-dart-aot.md` for the shape it actually was.

## Where configuration and licence data end up

Three destinations, and the distinction decides whether a patch survives later maintenance.

- **A file.** Beside the installed binaries, under a shared application-data directory, or in
  the user's profile. A file the installer writes at install time and never rewrites is a
  workbench you can edit; one it regenerates on every launch is not.
- **The registry.** Per the registry table above, the hive depends on the install context, so
  the same product installed per-user and per-machine reads different data. Enumerate both;
  the licence key you cannot find in one hive may be in the other.
- **A redirected view.** `observed`: Microsoft's MSIX description states that packaged apps
  run in a lightweight container with a virtual file system and registry, with certain file
  system and registry writes virtualized or redirected. A per-user redirected write is
  invisible to a naive registry or file search from outside the package. Search the redirected
  locations before concluding that the data does not exist.

How this changes a reinstall:

- A **repair** re-writes the records the package tracks. With the `a` letter it reinstalls every
  file, so any byte patch to an installed binary is gone. A patch that must survive maintenance
  has to live somewhere maintenance does not reach, or the deliverable has to be re-applied.
- An **uninstall** removes tracked components, including tracked registry values. Data the
  application wrote outside the installer's records is not tracked, and its survival is a
  property of that application rather than of the installer (`inferred`).
- An **update** is a new package with its own records; the old package's decisions about where
  configuration lives do not bind it. Durability of a client-side change across an update is a
  separate question, answered by looking at what the update replaces.
- A **transform or patch** changes the effective payload without changing the container you
  first extracted, so the artifact you analysed and the artifact that exists afterwards can
  differ in content while sharing a product identity.

## Verification specific to this shape

This container has one extra failure mode that other samples do not: **the file you analysed
may never have been executed, and the file that was executed may not exist any more.**

Prove the chain explicitly.

1. **What was extracted** (or downloaded): path plus hash. If the payload came from a URL,
   record the URL and the hash of the response, not the name of the file.
2. **What was installed**: path plus hash, after the install, read from disk. Compare it with
   the extracted payload. A difference is a finding: a custom action transformed it, or a
   different payload was used.
3. **What executed**: the identity of the process image that ran, taken from the running
   process or from the installer's own log (`/l*v` for the installer, `/log:` for a
   self-extractor), not inferred from the install directory.
4. **Whether the machine state matches the container**: services, drivers, registry values,
   and the tracked records. An installer can succeed and leave the interesting component
   disabled, and an installer can fail and still have placed the payload.
5. **The unmodified control**: the same install from the same container on a clean baseline,
   with the same answers to any prompts, so that a difference is attributable to your change
   rather than to install-time variability.

Success reported by an installer describes the request it accepted. It is not evidence about
what is on disk, and it is not evidence about what ran.

## Failure modes this shape produces

- **Analysing the wrapper.** Hours spent on the setup executable's own code, which exists to
  unpack and call other things. Extract first, then triage what came out.
- **A first run that mutates the machine.** The installer writes registry state, installs
  services and sometimes reboots. Take the baseline before the first run, on a copy.
- **A payload that only exists after a step.** A custom action that downloads or generates the
  binary means the container is not the artifact; the machine after the install is.
- **A patch defeated by repair.** Documented behaviour of the `a` repair letter is to reinstall
  all files. If durability matters, state it as a limitation of the deliverable.
- **A licence file regenerated on launch.** The edit is real and the effect resets. Time to
  reset is the measurement to take.
- **Two machines, one product name.** A transform or a patch makes the effective payload
  differ. Compare hashes, not version strings.
- **Trusting the container's signature as a statement about the payload.** A signed installer
  is evidence about the installer. What it extracts, downloads or writes is a separate chain.

## What this file does not cover

`unknown`: the `.msi` payload layout was not enumerated beyond its container signature, no
installer was executed while writing this file, and no download-and-install path was measured.
Not covered here, and each needs its own source or its own measurement: the metadata table
names and stream layout of Windows Installer packages (read them from the installer's database
documentation); the archive format of any particular vendor's setup builder (there is no
documented structure, so identify it from the binary); the behaviour of any specific
application package's redirected registry and file views on this build (measure it on the
package); and the contents of any licence file, registry value or downloaded artifact produced
by a real install, which are target-derived data and must be reported as such.
