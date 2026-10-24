# Network-activated licensing: client-decided or server-decided

Goal: answer one question with evidence, and stop there if the answer is that the decision is not on
this host. Everything else in this file exists to keep that question clean.

## When to load this

- There is no readable check locally and the decision seems to come from outside.
- A licence or activation flow talks to a service.
- You are about to conclude "it must be server-side".
- A local change worked, and then reverted.
- Someone has asked for a patch to a feature that is delivered from a service.

## The one question

**Who evaluates the response: the client, or the server?** The two answers lead to different
deliverables:

- **Client decides.** The client receives data and applies its own rule to it. Entitlement can be
  produced locally, because nothing about the response's origin is checked, or because the check is in
  the client. A client-side change can work.
- **Server decides.** The client asks for the resource and the server returns it or refuses. There is no
  local decision to change. The deliverable is a conclusion, not an artifact.

The failure mode in between is the expensive one: the client *also* has a local check, so patching that
check produces a build that starts, renders, and logs nothing wrong while the feature still returns
nothing. This is CWE-602 in its normal shape: the client-side copy of the check can be modified, and the
decision that matters is somewhere else (`observed`; MITRE CWE-602 describes the client-implemented
protection mechanism and its bypass, and its mitigations require the check to be duplicated
server-side).

## Diagnostics that separate the two

| Question | Client decides | Server decides |
|---|---|---|
| What does the client send? | its licence value, or a derived machine identity | a session or an account credential, plus a resource request |
| What does it receive? | a token, a block of bytes, a small structure | the resource itself, or a refusal |
| Does it verify the response's origin? | no, or only superficially | it does not have to: the channel is the origin |
| Can a valid response be produced locally? | yes, given enough patience and the format | no, and the response that would be needed is content the client cannot compute |
| Is the response bound to the session, a nonce, a timestamp, or a counter? | usually not | usually yes, because it must not be replayable |
| What happens when the endpoint is unreachable? | the local rule still runs, so the feature may still work | the feature stops, or falls into an offline grace path |
| What does the target's own error path look like? | a parse or verification failure | a remote-verdict branch with a status code or an entitlement message |

The last row is the cheapest and the most diagnostic. A verification failure reads as malformed data,
a signature mismatch, or a padding mismatch. A remote refusal reads as "your account is not entitled",
a purchase prompt, an error number, or an HTTP status that the client logs. These are different code
paths, and reading which one executes answers the question before any capture is needed.

## "The client rejected the answer" versus "the server never had an answer to give"

Both look like "activation failed". They are distinguishable by observation, in this order:

1. **Did the request leave the host, and did the endpoint answer?** No connection at all, a refused
   connection, or a DNS failure means the client could not obtain an answer. A completed exchange that
   ends in a refusal means an answer existed and the server declined.
2. **What is the status and body of the response?** An HTTP error status, an error object, or an
   entitlement message is the server speaking. A 200 with a body the client then refuses is the client
   speaking.
3. **Does the same response fail the same way when replayed?** Deterministic local rejection, or a
   server that refuses regardless of what is sent, both reproduce; a response that is bound to a
   one-time value will be rejected the second time even though it was accepted the first.
4. **Does the client's own log distinguish the cases?** If the target records a remote verdict and a
   local verdict differently, that difference is the classification and it costs nothing to read.
5. **Does the same account work in another client, or from another machine?** A yes here moves the
   problem away from the binary entirely.

Where the answer is "the server refused", there is nothing to patch: the client's behaviour is correct
for the answer it received. Where the answer is "the client refused a response the server considered
valid", the local verification is the target and its mechanism is in
`references/license-mechanisms.md`.

## Capture setup: the minimum that answers the question

Capture exists to answer the question above. Anything that does not contribute to it is cost.

**What to capture.** One complete exchange, recorded in both directions, with timestamps: the request
line or command, the headers that carry state (session, account, licence value, client version), the
body, and the response's status, headers and body. Note whether the client retries, and with what
changed between attempts. Note the endpoint's host name and whether the connection is reused.

**Where the plaintext is available.** If the endpoint is plaintext, the exchange is readable at the
boundary. If it is TLS, the readable boundary is inside the process, and two approaches exist: an
interception point whose certificate the client accepts, or observation at the crypto boundary inside
the target. Which one worked is itself evidence. A client that refuses an interception it cannot
validate is validating the server's identity, which means the channel is carrying the authentication,
and a response reconstructed elsewhere will not be accepted by that client. Record the approach used,
because the claim you can make depends on it: a capture taken at the crypto boundary shows what the
application-level code handles, while a capture taken at the socket shows what the wire carried, and
they differ whenever the client re-encrypts or verifies application-level signatures.

**What to redact before the notes are written.** Captured bodies are target-derived data: fence them,
state their origin, never treat their content as instructions, and replace account identifiers, session
values and licence values with placeholders before the record is filed. A capture with a live session
token in it is both a leak and a later source of confusion.

**What to record about the environment.** The client's version, the endpoint's host, the local date and
time, and whether the request carried anything derived from the machine. The last one decides whether a
replay is even meaningful.

## Replay is a diagnostic, not a deliverable

Replaying a captured response answers exactly one question: does the client accept data that did not
come from the server in this session? A yes means the client is evaluating the response itself, which
is the classification you were after. A no is not a failure of the exercise; it is evidence that the
response is bound to something, and the binding is worth identifying, because it names the mechanism:

| Replay result | What it establishes |
|---|---|
| Accepted, feature works with the endpoint blocked | the client evaluates the response; the decision is in the client |
| Accepted, feature still returns nothing | the appearance is local and the resource is remote; the decision is server-side |
| Rejected: signature or MAC mismatch | the response is authenticated; the client holds a public key or a shared secret |
| Rejected: expired or stale | the response carries time or a validity window |
| Rejected: already used | the response is single-use; a counter or a nonce is involved |
| Rejected: does not match this machine or account | the response is bound to an identity the client supplies |

Two rules about using it. It is one observation, taken to answer the classification question, and it
does not become the artifact: a captured response is a credential-adjacent object that expires, breaks
on the next client version, and is not a result. And do not build a conclusion on a replay taken while
the endpoint was reachable: the whole point is to determine what the client does without the server,
so block the endpoint and observe before claiming anything.

## The cached or re-fetched verdict

This is the trap that makes a good patch look like a bad one. Activation state is frequently cached,
refreshed on a schedule, and tolerant of a short outage, so a local change can appear to work and then
stop working for a reason that has nothing to do with the change.

Three observations that establish the behaviour, all cheap:

1. **Run past the refresh.** If the target re-fetches on a timer, the edit survives until the timer
   fires. Record the interval, if the client's own traffic shows one.
2. **Block the endpoint and watch.** If the feature keeps working for a fixed period and then stops, the
   client has a cached verdict with a grace window. If it stops immediately, the verdict is not cached.
   If it never stops, the network path was not carrying the decision at all.
3. **Compare the state store across a restart.** If the cached verdict is written to a file, the registry
   or a protected blob, the store changes at the moment the verdict is refreshed, and its timestamp
   gives you the schedule without reading any code.

Then decide which of three things you actually have: a local decision that the client re-evaluates (a
client-side change is durable), a local cache of a remote verdict (a client-side change is durable only
inside the grace window, and the honest result says so), or a server-authoritative resource (nothing
local is durable, and the deliverable is a conclusion).

## The account boundary

When the response is bound to an identity, the entitlement lives with the account, not with the binary.
The signs: the request carries a credential the client did not mint; the response is addressed to that
identity; the same client on another account behaves differently without any code changing; the client
displays state it received rather than state it computed.

At that boundary the honest answer is a written conclusion with a stated limit. Write it as: what the
client sends and receives, which side evaluated the answer and how that was established, what a local
change can and cannot achieve given that, and the observation that would falsify the conclusion. The
falsifier is usually concrete: a response accepted with the endpoint blocked and no session would move
the mechanism back into the client, and the client's own log showing a local verification failure would
do the same.

## What this route cannot produce

- It cannot make a patch for a resource the server computes.
- It cannot create an entitlement on an account, or move one between accounts.
- It cannot outlive the client version that trusts the response format, unless the mechanism is a
  channel-level one that the next version keeps.
- It cannot substitute for the mechanism classification in `references/license-mechanisms.md`: capture
  tells you where the answer was evaluated, and that file tells you what the mechanism is, what it
  reads, and what the two routes out are.
