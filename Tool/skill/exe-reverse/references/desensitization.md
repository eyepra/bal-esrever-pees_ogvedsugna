# Desensitization: publishing the finding without publishing the target

A reverse-engineering artefact is the worst possible thing to publish casually: the material that teaches is real work, and the identity of the target leaks into it one field at a time, through files that no structural check looks at.

## When to load this

Load this before publishing anything derived from real work, including a reference document, a case
note, a script, a transcript, a capture, a screenshot, a report, and the names of any of those files.
Load it again when a scan reports a hit, and load it once more on the file you are about to publish,
because the scan you ran earlier ran on a different file. It applies to material you are writing now
and to material you are copying from a private note into a public document.

## Strength labels used here

- **observed**: reproduced here, with the artefact named (a tool's output, a field read from a file,
  a command and its result).
- **inferred**: follows from observations by a stated step.
- **unverified**: asserted from documentation or expectation, not reproduced here.

Claim strength in this file describes how well the desensitization statement itself was checked, not
how confident the writing sounds. Missing coverage is `unknown`, never absence: "the scan found
nothing" and "the identity is not present" are different statements, and only the first one was
measured.

Most of this file is procedure and policy rather than claim. An imperative line ("replace the name",
"scan the file you are about to publish") is a rule, not a statement about the world, and carries no
label. Every line that asserts how a tool, a file format or a host behaves carries one.

## The two failure directions

Under-redaction publishes target identity: a product name, a licence key, an internal hostname, a
build number, a customer name, a path with the account in it. The leak is usually a single field in
the middle of a long line, in a document that otherwise reads as generic, and it is invisible to
every check that looks at structure rather than content.

Over-redaction destroys the reusable part. A pass that removes the tool names, the file formats, the
API names and the public protector names leaves a document that cannot teach anything, and it fails
at the same job from the other side. Both directions are fixed by one artefact: an explicit list of
what is exempt, written down, so a reader can argue with it.

The test that separates the two lists: **does removing this string make the sentence less able to
teach?** If yes, keep it and remove the identity somewhere else. If it costs the reader nothing, it
was identity and it goes.

## Must be removed

| Class | Typical shapes | Why |
|---|---|---|
| Product identity | The product name, its version, its vendor, its edition string | The triple of name, version and vendor identifies one commercial artefact, and two of the three usually identify it already (inferred from how product identity is indexed) |
| The version resource | The version-info strings embedded in the image: product name, company name, file description, legal copyright, original file name | Observed: a PE carries these as resources, and they are printed by any header-dumping tool without warning |
| Licence and activation material | Licence keys, serial numbers, activation codes, request or response blobs from an activation exchange, key files | These are usable secrets, not explanations |
| Real endpoints | Hostnames, IP addresses, URLs, tenant or account identifiers, cloud resource names, internal service names | They point at infrastructure that belongs to someone else |
| Customer and organisation identifiers | Support or registration identifiers, embedded customer names, the organisation string in a licence file, a certificate subject, an account name inside a log | They identify a person or a company, often not the vendor |
| Personal and machine identifiers | Paths containing the account name, user or group SIDs, machine names, e-mail addresses, MAC addresses | These identify the analyst, the customer, or the machine that produced the evidence |
| Target-derived filenames | Original file names, internal project names, the names the installer uses | The file name often carries the product and version in a field a body-text scan never reaches |
| Target-derived hashes, when they are lookup keys | A published sample hash, where the document does not need it for verification | A hash is an index into public sample corpora (inferred), so if the document's job does not require it, it is identity |
| Timestamps that pin one build | The linker timestamp of a specific sample, file system timestamps copied out of a capture | A precise timestamp narrows a sample to one build of one product (inferred) |
| Raw host output | Capability reports, environment dumps, process listings, capture summaries | Observed: the capability probe in this skill prints a token SID and absolute paths containing the account name, by design; the tool is right and the report is the leak |

Two judgement calls worth naming rather than pretending are mechanical. Hashes: an internal record
needs them, and a published document needs them only where verification is the point, so publish the
hash of a synthetic fixture and keep the real hash out. Version numbers of tools: a tool version is
not target identity and belongs in the report, because a measurement without its pins is not
reusable; a target's version is identity and does not.

## Must not be removed

Every row here is a real category of over-redaction, and removing any of them costs knowledge.

| Class | Examples of the shape | Why it stays |
|---|---|---|
| Tool names | The debugger, disassembler, patcher, script interpreter, trace tool actually used | The tool is half the method; the name is public and identical for every reader |
| Library and module names | A runtime library, a compression library, a UI toolkit, a language runtime | Recognising the runtime is a finding, and the name is public |
| File and container formats | The executable format and its structures, resource formats, debug information formats, archive formats | Format vocabulary is what makes a description portable, and it names no target |
| CWE identifiers | CWE numbers and their names | Public classification identifiers; redacting them removes the reference |
| Public packer and protector names | A publicly sold or publicly documented protector, its own tooling and its documented markers | The protector's name describes a class of target, which is exactly what a reader needs to recognise |
| Public challenge material | Published crackmes, published CTF binaries and their names, published exercise documentation | Deliberately published fixtures; their names are part of the published exercise |
| Generic API and system names | Documented function names, registry paths that belong to the OS, documented structure names, documented CPU features | API vocabulary, not identity; a large fraction of the technique is exactly these names |
| Architecture and instruction vocabulary | The architecture, section names, calling conventions, register names | Required to describe anything |
| Placeholder tokens | `<image>`, `<sha256>`, `<host>`, `<account>`, `<build>`, `<offset>` | The redaction mechanism itself; a scan that reports these is unusable |

Two boundary cases that genuinely are boundary cases. A protector or licence-product name that
appears because the target uses that product is technique vocabulary and stays; the same name
appearing as the vendor identity of the artefact being analysed is target identity and goes. And a
symbol exported by a third-party library stays, while a symbol that encodes the customer's own naming
convention is a company identifier and should be replaced by a descriptive placeholder.

## The scanning checklist

Work in this order. Each step has a different blind spot, which is why the order matters less than
doing all of them.

1. **Freeze the surface.** List every file that will be published or copied to a public location:
   documents, scripts, capture files, images, the names of all of those, and any metadata attached to
   them. Files that are easy to forget are the capture file, the image file name, the directory name
   and the commit message.
2. **Text pass over the bodies.** Read for the identity shapes rather than a word list: a version
   triple, a licence or activation field, a company or customer string, an endpoint, a path segment
   under the user profile directory, a support identifier. This is slower than a pattern scan and it
   finds the things a pattern scan is not looking for.
3. **Binary and header pass on anything you publish that is executable or a dump of one.** Read the
   version resource fields, the debug directory path, the linker timestamp, exported names, the
   certificate subject if signed, and any strings table. Header dumps are identity-heavy and are
   published as "just the facts" more often than any other artefact.
4. **Image pass on the pixels, not the text.** Look at each screenshot and each frame: window titles,
   licence dialogs, user names in a title bar or a recent-files list, tray icons, file paths in an
   open or save dialog, product banners, the taskbar, and a second window behind the one you meant to
   capture.
5. **Metadata and name pass.** Read the file names and any embedded metadata of the files in step 4,
   and rename them. A screenshot named after the product, the version and the screen it shows is a
   full identity disclosure in a field that no text scan of the body will ever read.
6. **Capture pass.** Read the names in a name-resolution log including the failures, the endpoints of
   connection attempts, the server names in handshakes, certificate subjects, cloud or tenant
   identifiers, internal hostnames, and the address and interface of your own capture host.
7. **Transcript and command-line pass.** Read shell history, absolute paths, environment variables,
   tokens, session cookies, proxy credentials, and every command line you are about to quote. A single
   command line can carry a path, a key and a hostname at once.
8. **Re-derivation pass.** After replacing identity with a placeholder, search for the placeholder's
   own definition and for any value that appears next to it. A placeholder defined beside its value is
   not redacted, and a mapping table left in a public file reverses the whole pass.
9. **Publish-time scan on the artefact itself.** Run the check on the file you are about to ship, not
   on the file you started from. A report written about the findings is a copy of the findings, and a
   document that quotes a hit in order to be concrete is the leak it was written to document.
10. **Record the decision, not the values.** Keep a short table of what was removed and why, with the
    category and the rule, and keep it out of the published tree.

## The entry-point surface, which is the trap

A published skill or repository is not only read by people and by tools skimming for content. Its
entry-point files are read as instructions before anything else decides how to treat it (unverified:
documented behaviour of the host that loads them, not reproduced here): the main skill document, a
readme, the front matter of a reference, the file names in a directory listing, a case note that
becomes documentation later, and a screenshot's file name.

Consequences, each of which is a real and repeated mistake:

- The redaction must not be reversible by reading the file. A placeholder defined next to its value, a
  sample transcript that still carries the field in a comment, or a mapping table in an appendix all
  restore the identity while looking redacted.
- Identity in a name or a heading is in an instruction position, so it is worse than identity in a
  body paragraph, not equivalent to it (inferred from where such files are consumed).
- The document written during the work is the one that leaks. It is produced while the target is in
  front of you, so it is where the real name is first written down, and it is the file most likely to
  be reused later as the public write-up (inferred). Write it with placeholders from the first line;
  you are the only reader who needs the mapping, and the mapping belongs in a private note.
- Pasted evidence carries identity in a place nobody reads twice: a tool's own JSON output, a header
  dump, a log excerpt. Observed: the capability report this skill produces contains a token SID and
  paths containing the account name, and the header reader prints the absolute path of the file it
  read. Both are correct behaviour for a local tool and both need the pass before publication.
- A contributed file is read before it is linked, and material reproduced from elsewhere is summarised
  with its source named rather than quoted into an instruction position.

## Failure modes

| Symptom | Mechanism | What to do |
|---|---|---|
| A scan reports many hits, none of them a leak | Shape-only rules against a document full of legitimate identifiers: versions, offsets, symbol names, hashes | Do not widen the exemption list one hit at a time. Group the hits by reason and fix the rule; a context-free pattern is the bug |
| A scan reports nothing and you believe it | The scan ran on the wrong tree, on a file with an extension the walker skips, or on a body while the identity sits in a name or a header | Read the scan's own header line: root and file count. Then point it at the single directory you care about and check the count is plausible |
| A real leak was suppressed | An exemption matched a substring, or a benign-prefix rule is too broad and swallowed a target that shares its first two name segments | Print the exempted hits with the reason per suppression. A vague reason is the defect, not the exemption |
| The published report contains the leak it documents | The report quotes the value to be concrete, and the report is the published artefact | Never quote a hit value in a published document. Keep the rule, the category, the strength and the count, and describe the value by shape |
| The tree is clean and the archive is not | The archive was built from a work directory, or from a branch that was never scanned | Scan the directory the archive is built from, with the same exclusions the build uses |
| The body is clean and the file name is not | The name was written before the pass, or generated from the product name automatically | Treat names and metadata as part of the surface, and rename at the same time as the body is edited |
| A `<placeholder>`-style token is reported as a finding | The placeholder uses a bracket style or a spelling the rules do not know | Extend the placeholder rule. This is the one exemption class that should grow freely, because a placeholder cannot leak |

## What a scan cannot decide

A scan decides whether a shape is present and whether a known-benign pattern explains it. It does not
decide whether the surrounding text is identity-bearing, and it cannot see identity that is described
rather than quoted: "a mid-size licensed backup product, build from the second half of last year"
survives every pattern pass and still identifies the target to anyone who knows the market. It also
cannot see a value that a human deliberately masked, which is why the mask has to be documented and
the document has to be read by a person at least once.

So the pass ends with a reader, not with a green scan. The scan's job is to make the reader's once
through the material cheap, and to keep the list of exemptions arguable by putting the reasons next to
the rules.

## Anti-patterns

- Replacing the target's name and leaving its version and vendor in the next clause.
- Publishing a header dump as "just structure" while the version resource, the debug path and the
  certificate subject are all still in it.
- Leaving the account name in an absolute path inside a pasted command line.
- Publishing a capture, or a capture summary, without reading the endpoint names it contains.
- Renaming the body text and shipping a screenshot still named after the product.
- Defining a placeholder next to the value it replaces.
- Scanning the working tree and shipping an archive built from somewhere else.
- Quoting a hit in the published report about the hits.
- Deleting the tool names, the file formats and the API names, and calling the result sanitised.
- Keeping a mapping table of placeholders to real values inside the published repository.
