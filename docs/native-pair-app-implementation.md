# Native Pair App implementation checkpoint

[Frozen-source validation](native-pair-app-validation-20261017.md) records the
actual checks, development artifact and unrun acceptance lanes for this change.

This document describes the App consumer of
[the Native Pair contract](hub-native-pair-contract.md). It does not establish
Hub Guard, Store, real Codex Runtime, Windows desktop or deployment acceptance.
The earlier delivered login executable does not contain this implementation.
The A2 Hub preparation checkpoint keeps its public capability unavailable;
this App therefore sends no new Owner proof against that checkpoint. Positive
App actor tests exercise the frozen full contract, not an available deployment.

## App interactions

The existing native controller exposes eight closed local actions: prepare and
confirm two empty slots, read their state, review both actual joined candidates,
approve one exact slot, reject one exact slot, explicitly revoke the pair, and
recover an uncertain operation. Each maps to its dedicated shared wire DTO.
There is no generic management API, protocol change, model invocation or
automatic native-session creation in this App change.

Bootstrap preview starts with the locally confirmed N3 Node binding. The App
does not invent Store credential commitments or control-binding versions.
The shared target validator checks those values in the authenticated Hub
challenge before the App displays or signs its complete bootstrap target.
Consent review checks the retained bootstrap proof, exact Node, both slot
tuples, candidate attestations and key manifests using the shared validators.

The bilingual UI requires separate explicit consent for bootstrap, slot A,
slot B and revocation. Slot review shows both session identities, full candidate
fingerprint/key ID and the binding, generation, revision and lease metadata
covered by the target digest. The controller independently rechecks the current
review ID and exact target before signing. First consent remains waiting;
ACTIVE after the second consent accepts only the plan's two projected membership
revisions, with the remaining slot fields unchanged. A status observation never
turns the App into a generic authorized Manager.

Each click creates a fresh Owner consent intent. Its separate Group key proof
uses the reviewed manifest's exact issue and expiry times; waiting between
review and either click cannot replace that lifetime with the click time.

Pair status reads are explicit. Idle rendering does not poll Pair routes.
Changing the review or account context resets local consent controls. Account
expiry/logout hides private Pair metadata and administrative actions while
preserving the pair's independent peer lifetime. It never sends an implicit
revocation. Expired reviews cannot enable signing; restarted observations are
historical until a fresh authenticated operation confirms current eligibility.

## Local identity and independent Node pin

The original Owner/device keys stay in the existing local vault. An explicit
native Save dialog exports only `owner.Public()` as the existing three-field
`e2ee.PublicIdentity` JSON. It contains no private identity, session or grant.
The App preserves existing files by creating a new file exclusively.

After current account authentication the App displays the full local Owner key
ID and the fingerprint compatible with `nodekeys.PeerKeyFingerprint` alongside
Owner ID. A small pure crypto helper implements the same validated public-key
hash, with compatibility tests against that Node API, so the production App
does not link the Node's SQLite implementation. This is the Node peer
pin fingerprint (`sha256:` plus 64 hexadecimal characters), independently
computed from the local vault keys; it is distinct from the N2 Owner fingerprint.
It is compatible with the existing Node `machine trust-owner-key` public-key
input. Establishing the gpu1 Node pin and any service maintenance remain an
explicit user/operator action outside this App implementation.

## Durable requests and recovery

Six bounded encrypted vault namespaces separate original request, ordinary
response, diagnostic request, diagnostic response, compact state and retained
review. The existing per-namespace 1 MiB and total vault limits are unchanged.
The App never stores a giant reconcile response together with another decoded
copy of its nested receipt in the same record.

The controller seals and CAS-persists the original DTO, packet and immutable
identity/Node target before POST. It authenticates replies against that exact
original and pinned Hub, then persists the raw reply before applying any result.
CAS failure prevents memory-only continuation. Crash recovery applies saved
receipts idempotently and does not restore live administrative permission.

After a lost response, manual recovery first retries the exact original bytes.
Unsigned HTTP errors and malformed responses retain the original. A detached
reconcile uses the same original packet/target, independently of live session,
Root or Node availability. Only an authenticated matching receipt or permanent
no-effect fence settles a mutation. An expired diagnostic may get a fresh
diagnostic request ID, nonce and timestamp; the business original is unchanged,
and a late response to the superseded diagnostic cannot complete its replacement.
There is no unbounded retry loop and no ABSENT-as-success path.
Known-pair rejection uses the shared dedicated fence and original DTO/packet
target validator. A generic result cannot replace its no-effect proof, and an
outer reconcile outcome cannot contradict its nested authenticated fence.

## Independent Node-local checkpoint

The earlier `a451b9b` Node-local checkpoint is separate from the App consumer
above. It extended `internal/nodekeys` crypto-state schema 5 to 6 and added
unwired Node helpers. The consumer wiring below builds on those primitives.
Neither checkpoint changes the public protocol or replaces Join/Relay.

The local policy commits the original bootstrap proof, pinned Hub identity,
required-policy marker and first credential/control-binding versions together.
The Owner key must already have independent local trust; a Hub response cannot
install it. Missing evidence for a required Group, changed scope and revoked
local Owner trust reject fresh work. Ordinary Groups retain their existing path.

Candidate publication retains the original public key and exact signed
attestation before POST. A missing original private-key file cannot silently
create a replacement once its marker exists. The retained candidate version
stays zero until the caller has checked the actual matching acknowledgement.
Join-selection helpers accept only Pair ID and slot from tool arguments; the
original SID/workspace must come from the checked native context. At that
checkpoint these helpers were not connected to production MCP dispatch.

Durable reservations enforce four root ASKs, four replies, eight messages, one
outstanding root ASK, 8 KiB per plaintext and 64 KiB total plaintext, 128 KiB per
ciphertext and 1 MiB total ciphertext, and eight native submissions. UNKNOWN,
restart and cancellation do not refund their message or byte charges. Only a
matching authenticated admission or cancellation/expiry outcome may settle the
corresponding request. A reserved reply alone does not close its ASK.

An `existing=true` reservation is historical lookup/recovery metadata, never a
new send or queue permission. Production callers still need current peer
evidence, the independent Owner pin and all routed scope checks, including a
recheck after acquiring the original writer. An existing submission must use
its retained writer ledger and must not enqueue another invocation. Actual
production send/injection callers remain outside this checkpoint.

Reopening an accepted local policy after the ten-minute Join window preserves
its original proof and one-hour peer deadline; a previously unknown policy
cannot first enter after that window. This is not proof of a live native or
Network-access lease. Existing MCP Group heartbeats run every 30 seconds;
restart checks the cached original binding through whoami and heartbeat and
does not silently rejoin. Ordinary Network renewal rotates the access epoch,
so it cannot stand in for renewal of a Pair's already signed access identity.
Five-minute native/access lease continuity and its peer-deadline ceiling need
their own Hub integration evidence.

At that checkpoint the public Current carrier and production Join receipt
application remained unwired. Historical accepted Join recovery must precede a new Describe/Join,
without replacing the original SID, binding or key. The legacy peer-key view
may omit the receiver SID; current SID checks must use actual Current metadata,
not fill missing live data from the signed plan. Public Join/ASK tool results
must remain small; full bootstrap/Owner proofs, internal peer evidence and
tokens must not appear in model results.

## Node and MCP consumer wiring

The subsequent consumer uses the existing `cicada_join` tool with exactly
`pair_id` and `slot` (`A` or `B`). Native SID, workspace, Node identity and API
origin come from the checked native record and configured MCP connection. The
private local socket checks that record and origin again. No new tool, Runtime,
transport adapter or session is created. The public result contains the existing
small Join view; full Owner proofs, Node RPC receipts and session tokens remain
in private local state.

The original approved Node-Control key and state must already exist. Describe
is authenticated through that original binding. Its Owner proof must match an
independent active local Owner pin, the original Node/Hub keys and approval,
actual credential commitment and retained versions. Availability permits only
the attempt to use these guarded operations. An unavailable capability prevents
a new Describe/Join, while recovery of an already pending or accepted original
precedes discovery.

The existing bounded 8 MiB private Node-Control state gains original Pair
request metadata, authenticated receipts and detached diagnostic state. It
persists the exact business packet before POST and the raw response before
applying it or clearing pending state, including startup recovery. Reconcile
uses the original business sequence with a separate diagnostic operation ID,
nonce and timestamp. Both the outer diagnostic and nested original receipt
must authenticate for their exact routes and target. An unsigned HTTP error
cannot retire the original Join. A terminal Join refusal needs its dedicated
authenticated fence; expiry of a Describe result is only read expiry. Pair
RPC response readers enforce the existing 128 KiB receipt and 384 KiB diagnostic
bounds without changing other Node RPC limits.

A matching Join fence is reported and durably marked as reported before that
invocation returns. A later independent explicit Join may create a new intent
and read the current slot generation. Recovery in the same invocation cannot
do that, and failure to persist the report cannot advance it. The old request
and authenticated fence remain permanent, including late replay after an
Owner rejects a different SID and reserves the next slot generation.

An accepted Join is recovered before any new Describe. Its original SID,
workspace, Endpoint, binding, epoch and key survive loss or reopen. A cached
initial lease expiry does not force another Join: current whoami and the
existing Group heartbeat inspect and renew the same binding, bounded by the
original peer deadline. This does not use the epoch-rotating Network renewal.
Candidate publication reuses the exact durable attestation and original private
key, and records its version only after a matching acknowledgement.

The persisted routed Group selects whether Pair evidence is mandatory. Both
independent evidence and actual Current must be present for that Group, and
the original Owner pin must still be active. Old Endpoint/principal/key/grant
fields match the signed plan and projected Group membership; actual SID,
generation, attempt, Network access identity/epoch/revisions and lease fields
are checked through Current. A redacted legacy receiver SID stays empty. The
carrier measures the complete HTTP bytes against 320 KiB, with independent
256 KiB evidence and 4 KiB Current bounds. Ordinary Group carriers keep their
existing behavior when both extensions are absent.

Existing sealed Relay callers reserve the finite ASK/REPLY and byte budgets
before business POST; an exact retry preserves its ciphertext and charge.
Required Groups reject SEND, broadcast, causal children and legacy local
fallback. Matching admission, reply or cancellation observations settle only
the corresponding retained request. Uncertain traffic is not refunded.

Receiver admission rechecks current authorization and local trust after taking
the original physical writer. The original writer outcome is authoritative:
ACCEPTED, UNCERTAIN or INJECTING cannot authorize another queue command or be
rewritten as unexecuted because current HTTP authorization or an independent
Owner pin now fails. Early rejection also checks that exact operation under
the writer lock before changing the inbox. The implementation retains the
existing inbox, writer and `codex queue --thread --message` command.

The subsequent disposable TCP gate uses the committed Hub producer, real
N2/N3 and Owner proofs, two original Node Join receipts, actual compatible
dual consent, production MCP/socket/sealed Relay/inbox/writer paths and synthetic
queue subprocesses. Its Hub database and Node state use an owned host bind.
Current corruption, independent local Owner revocation, INJECTING plus process
termination, and slot-generation recovery have their own effective caller
assertions. Normal and race results retain their exact source/binary evidence.

Public Pair capability remains unavailable. The actual TCP fixture explicitly
uses the reviewed development probe to obtain the original Join receipts;
the real MCP entry then recovers those receipts. A fresh MCP Join against
capability=false sends no Describe/Join. A scripted actor separately exercises
fresh positive dispatch. Neither result establishes a fresh public SDK/App
workflow, real Codex consumption, Windows or public deployment acceptance.
This work does not alter the delivered Windows executable or App UI.

## Verification scope

App-local tests use real shared PQ envelopes, Owner proofs and encrypted vault
CAS with a scripted HTTP actor. They separately test original persistence before
POST, explicit per-slot consent, projected activation, rejection, invalid target
revisions, lost-response recovery without duplicate consent, capability absence,
reopen/CAS boundaries, late diagnostics and public-only key export.

These tests do not establish actual Store/Guard authorization, two real Codex
threads, Runtime/tool delivery, Windows Save-dialog/DPAPI/ACL operation, visual
legibility, public HTTPS or physical acceptance. Those results must retain their
own tested source and artifact provenance. Cross-compilation is a build check;
the known user-reported Windows text-rendering issue remains a separate result.
