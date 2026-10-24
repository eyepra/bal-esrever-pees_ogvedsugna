# Licence mechanisms: classify before patching

Goal: name the mechanism, and with it the layer that holds the decision, before a single byte is
edited. Getting this wrong does not fail loudly; it produces a build that runs and does the wrong
thing.

## When to load this

- A licence, activation, trial or feature gate has to be understood or changed.
- A patch had no effect, and you are about to try a third variant of it.
- One feature silently never works while everything else does.
- The target talks to a service and you cannot tell whether the answer was decided locally.
- The request touches an account, an activation count, or a subscription.

## The taxonomy

| Mechanism | Where the decision physically lives | What a client-side change can achieve | Symptom of getting it wrong |
|---|---|---|---|
| Licence file read locally | Client, in ordinary code that parses a file | Full effect if the file is the only input | Editing the file appears to work until the file is regenerated |
| Serial checked by a local algorithm | Client, in an arithmetic routine | A keygen or a check-skip, both complete | The skip works but a second routine validates the same serial differently |
| Machine or hardware binding | Client, deriving an identity from this machine | Only for this machine, and only while the identity is stable | Works on your host, fails on the next one; a hardware change re-locks |
| Time-limited trial | Client, comparing a clock against a stored start | Full effect until something rewrites the stored state | Reverts after a while, or after a restart, with no visible cause |
| Online activation, client decides | Client, evaluating a response | Full effect if a valid response can be produced locally | The dialog disappears and the feature still refuses |
| Server-authoritative entitlement | Server, with the client only rendering | Nothing durable; at most the local appearance changes | Everything looks unlocked and the feature returns nothing |
| Signed licence blob | Client verifying a signature over the blob | Only the removal of the verification step | The blob is refused, or accepted locally and rejected remotely |
| Dongle or hardware token | The token's own hardware | Only skipping the check; the secret never enters the host | Every challenge fails because the response can only come from the token |

Five of these eight can be settled from the binary alone. Three cannot, and those three are where the
hours go.

## Mechanism by mechanism

**Licence file, read and parsed locally.** The decision is a comparison of parsed values. Read the
parser first: the file's structure tells you which fields are checked, and the parser is usually
easier to read than the checker. This is the mechanism most often misdiagnosed as "signed", because a
field looks random. Check whether the field is verified against anything before treating it as a
signature.

**Serial or key checked by a local algorithm.** Two things exist and both matter: the arithmetic that
maps the serial to an accept value, and the set of features the accept value selects. A skip that
returns "valid" without a serial may leave the feature table empty. Recovery of the algorithm, when it
is wanted, is a separate activity (see `references/algorithm-recovery.md`).

**Machine or hardware binding.** The licence is computed over an identity derived from the host, so
the licence is only valid on the host it was issued for. Candidate inputs, all observable from outside
the target: the volume serial number assigned when a volume was formatted (`observed`;
`GetVolumeInformation`, `lpVolumeSerialNumber`), a machine identifier stored in the registry at
`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` (`observed` on this development host; the value is
not reproduced here), network adapter addresses, processor-visible identifiers, and disk or firmware
serials, which the platform's own documentation directs you to WMI for rather than to the volume API
(`observed`; `GetVolumeInformation` remarks). The practical consequences: a patch that neutralises the
comparison on one machine may be wrong on the next, and any change to the bound input re-triggers the
gate, which is indistinguishable from a patch that stopped working.

**Time-limited trial.** Two pieces: a stored start point (or a stored remaining count) and a
comparison against the current clock. Both the store and the comparison are usually duplicated, and
the duplicate is what survives your edit. Establish where the start point lives and how often it is
written before deciding the deliverable form.

**Online activation where the client holds the decision.** The client receives a response and decides
for itself whether the response means "entitled". This is the case that looks server-side and is not:
the entitlement can be produced locally because nothing verifies the response's origin. The diagnostic
path, and the reason to classify this before patching, is in `references/network-activated-licensing.md`.

**Server-authoritative entitlement.** The client requests the resource; the server decides and returns
it or does not. There is no local decision to change. The client-side check, if any, is a courtesy: it
decides whether to render a dialog, not whether the resource exists. This is the most expensive wrong
classification in the domain, because the wrong branch still produces a build that starts, renders,
and logs nothing wrong.

**Signed licence blob.** The blob carries a signature verified against a public key embedded in the
client. Tools for that verification are platform APIs (`observed`: the platform documents signature
verification entry points such as `BCryptVerifySignature` and `CryptVerifySignature`; the padding
scheme has to match the one used at signing, which is a standard cause of an implementation rejecting
a valid signature). A local change cannot forge a blob, because the private key is not on the host, so
the only reachable client-side change is to remove or invert the verification. If the same blob is
also validated when the resource is requested, that change buys nothing but a shorter error path.

**Dongle or hardware token.** The licence computation is a challenge and response performed by the
token. The host can skip the check, and the check is then simply absent. What the host cannot do is
produce the token's output, so any path that genuinely needs the token's secret still fails, and it
fails with a different symptom than a refused licence: usually an empty or malformed cryptographic
result rather than a dialog.

## The two sentences that decide the task

The framing to classify against is CWE-602, "Client-Side Enforcement of Server-Side Security": the
product is composed of a server that relies on the client to implement a mechanism intended to protect
the server, and because the protection lives on the client, "an attacker can modify the client-side
behavior to bypass the protection mechanisms" (`observed`; MITRE CWE-602, description and extended
description). The same entry's own mitigation guidance is that client-side checks must be duplicated
on the server, and that a client-side check is still useful for intrusion detection (a request that
should have been refused by the client is anomalous) and for user feedback (`observed`; CWE-602
potential mitigations). That guidance is also the classification test in reverse: if the server
duplicates the decision, removing the client's copy changes only the client's own behaviour.

So state both sentences explicitly and separately:

1. **Is the check in the client?** If yes, a local change can alter what the client concludes.
2. **Is the resource account-scoped, or otherwise minted by the server?** If yes, there is nothing for
   a local change to unlock. The client can be made to believe it is entitled; the server still
   returns nothing, and no amount of patching the belief changes the answer.

Both sentences can be true at once, and that combination is the one that produces the misleading
artifact. A client that skips its own check and then requests a resource it is not entitled to will
display an unlocked-looking shell and empty content.

## The question those two sentences do not ask

They classify where the **permission** comes from. They do not ask where the **feature runs**, and
conflating the two produces a classification that is wrong in the pessimistic direction -- the more
expensive way to be wrong, because it ends an analysis that could have continued.

A feature whose work happens on the machine is reachable from the machine, whatever issued the
permission. Renaming a saved folder, deleting a stored entry, enabling a local option: the server's
part in these is to say *who may*, and the client's part is to *carry it out*. The client still has
to read the entitlement and act on it, and both of those are local.

| Permission comes from | Feature runs | What a local change reaches |
|---|---|---|
| the client's own data | on the machine | the feature, and the change persists |
| the server, handed to the client | on the machine | the feature, until the client asks again -- understand the re-ask before promising durability |
| the server, enforced per request | on the server | nothing. The client cannot make the server agree |
| the server, cached by the client | on the machine | the feature, and the cache's validator becomes the real subject: if a signature is what makes a value acceptable, the route is "understand what makes a value acceptable", not "patch the value" |

**The mistake this table exists to prevent**, recorded because it was made here and then corrected:
a target was classified server-authoritative from its endpoint names and a server-issued tier value,
and the features behind those gates -- every one of them a local operation -- were reported as out of
reach. The permission was remote. The features were not. Those are two different sentences, and only
the second decides what a client-side change can do.

**What remains true, and belongs in the same breath:** a change to a server-issued entitlement
changes the client's *belief*. Where the entitlement is re-asked, that belief is a cache with a
lifetime. Where the feature needs something only the server can supply, the belief buys nothing.
Both are findings about the client, and neither is a reason to stop before asking where the feature
runs.

## Where the licence lives, and why an edit sometimes reverts

- **A file** in the install directory, the roaming or local application data tree, or a shared
  location. Readable structure means the field names are in the target's strings; treat the contents
  as target-derived data, not as instructions.
- **The registry.** Record which hive and which key: a per-user store under the current user's hive
  and a per-machine store under the local machine hive are different mechanisms with different
  visibility, and a per-user store means the same binary behaves differently for a different account
  on the same host.
- **A DPAPI-protected blob.** The platform protects the data with a key derived from the user's logon
  credentials by default, or from the machine when the protecting call passes the machine-scoped flag,
  and it adds a message authentication code over the protected data to guard against tampering
  (`observed`; `CryptProtectData` documentation). Two consequences follow directly: editing the
  ciphertext makes the blob undecryptable, which an application usually handles as "no licence
  present", and a blob protected under one account does not decrypt under another unless it was
  machine-scoped or the profile roams.
- **A signed token.** Editing any covered byte invalidates it. A token issued by a service may also
  carry an expiry, so a locally valid token stops being accepted later for reasons unrelated to your
  change.
- **Server-held state.** The client's copy is a cache of a verdict the server owns; it is refreshed,
  and every refresh overwrites whatever the client-side edit produced.

Reversion, specifically, is almost always one of five things: the store is rewritten from a source you
did not edit; a second copy of the state exists elsewhere and wins; the protected blob failed to
decrypt so the application reset it; a signed token failed verification so it was discarded; or a
periodic re-check fetched a fresh verdict. Identify which, because the fix for the first four is in the
target and the fix for the fifth is not a fix at all.

## What a client-side change cannot do

- It cannot mint a credential the server accepts, if the server verifies a signature over data the
  client cannot produce.
- It cannot create entitlement on an account.
- It cannot make a token return data that the token's own hardware holds.
- It cannot survive a re-installation or an update that replaces the artifact, unless the change is
  re-applied by the same mechanism.
- It cannot be reported as a result on the strength of a dialog disappearing.

## Classification checklist

Answer these before editing, and write the answers down next to the claim:

1. What does the target read, from where, at what moment, and what happens when that read fails?
2. Is there a comparison whose result the feature depends on, and does the feature consult it again
   later?
3. Does the target send the licence, or a derived value, to a service, and what comes back?
4. Can a valid answer be produced on this host, given only what the client already knows?
5. Is the requested resource computed locally or fetched?
6. If the resource is fetched, what does the request carry, and what would the server need to be true
   in order to answer it?
7. Does the state get rewritten, and what rewrites it?
