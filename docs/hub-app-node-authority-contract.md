# Finite App authority for one INITIAL Node

Reviewed contract `app-node-authority-v1`, 2026-10-17, phase
**STORE_ONLY — reviewed types, shared proof/framing helpers and Store state
machine; no N3 HTTP service or App behavior is enabled by this checkpoint.** Root approved this
contract before implementation. The normative types are
`internal/e2ee/owner_app_node_claims.go` and
`internal/hubaccountwire/app_node_authority*.go`; metadata is
`internal/hubaccountwire/app-node-contract.json`. Run
`python3 scripts/app-node-authority-contract.py check` for metadata consistency.
This check is not an implementation or deployment acceptance result.

## Scope and compatibility

This slice lets the **same ACTIVE Owner and same enrolled App device** explicitly
authorize one exact INITIAL Node after N2 expiry, and explicitly reauthorize only
status for that unchanged confirmed Node later. It preserves
the account, Owner, all existing public/private identities, device ID and epochs.
No installer code, first-Root ceremony, identity export, new signer or replacement
device is involved. A successful password/device login alone grants no Node
preview, confirmation or management authority.

This first slice requires the exact completed N2 enrollment and immutable N2
lease history for this same Owner/App identity and matching security epochs.
Expiry is allowed; missing history or a legacy device that never completed N2
is refused before prepare. There is no N3 opt-in for ordinary legacy Clients in
this slice. Consequently every N3-capable device already has the permanent N2
restriction row: untagged requests in **every** serve mode remain subject to it
and cannot obtain broad rights through the old no-lease-row compatibility path.
Clients that never opted into N2/N3 keep their existing behavior. A future legacy
N3 adoption would require its own durable restriction/migration contract.

N2 establishes the App Client key/session at epoch 1. Its old account activation
binding has no Client-epoch field; this slice therefore also requires the
retained Client key version and session epoch to remain 1 for first N3 admission.
A later Client-epoch reset is a security change and cannot be silently adopted
through the old N2 history. No counter or identity is reset to satisfy this gate.

`owner-activation-v1` and its immutable, nonrenewable 15-minute lease remain
unchanged. `OwnerDeviceGrant` v1 remains an enrollment proof, never a runtime
lease. Frozen `client-hub-v1.6.5`, encrypted wire 1, 55 catalog operations, old
account operations and old Owner-bootstrap vectors remain byte-compatible.
Software version, proposed next schema migration, Git revision and artifact
digest are recorded separately. Schema 63 implements the private Store state
machine and extends restore inventory/floor rules; it does not enable an HTTP
service by itself.

The INITIAL Client RPC operations are the exact ordered list
`["nodes.confirm"]`. The initial confirmation budget is
**one**. No `nodes.revoke`, broad `nodes.list`, `status.snapshot`, UPGRADE,
Worker, Goal, Manager intent, Group or Runtime permission is included. After a
successful confirmation, the budget is zero and confirmation is no longer
available; the finite Node-only observation remains available until expiry.
The separately signed `read_node_status:true` permission authorizes the exact
Node-only read on the N3-owned `owner.app_node.status` HTTP operation. It is
not a Client catalog entry or an implicit consequence of a Client capability.
`READ_EXISTING` has an empty Client RPC allowlist, zero confirmations and the
same explicit exact-Node HTTP read permission. RPC capability replies list
catalog RPC operations only; new HTTP operations are advertised separately.
This slice never grants or calls `session.capabilities`; its counter-consuming
Client request is unnecessary. Public N3 discovery and authenticated N3 status
provide feature/context metadata without an extra RPC conversation.
Cancelling App authority does not revoke a previously approved Node. A separate
explicit Node-revocation UI/contract slice is needed for that operation.

## New operations and encrypted framing

All paths are POST and independent of the frozen Client catalog:

| Operation | Path | Request | Response |
| --- | --- | --- | --- |
| `owner.app_node.prepare` | `/v2/owner/app-node/prepare` | `AppNodePrepare` | `AppNodeChallenge` |
| `owner.app_node.complete` | `/v2/owner/app-node/complete` | `AppNodeComplete` | `AppNodeResult` |
| `owner.app_node.status` | `/v2/owner/app-node/status` | `AppNodeStatusRequest` | `AppNodeResult` |
| `owner.app_node.cancel` | `/v2/owner/app-node/cancel` | `AppNodeCancel` | `AppNodeResult` |
| `owner.app_node.reconcile` | `/v2/owner/app-node/reconcile` | `AppNodeReconcileRequest` | `AppNodeReconcileResult` |

Before its **first N3 POST**, including bootstrap status carrying a session token,
and before creating any first N3 pending packet, the upgraded App queries the new
public **GET `/v2/owner/app-node/capabilities`**, bounded to 8 KiB, and strictly
decodes `AppNodeCapabilities`. It must recognize the exact contract, enabled
`--hub-nodes-only` mode, five HTTP operations, profiles and limits. A 404 or
unsupported mode keeps N3 unavailable: **zero N3 secret POSTs and zero new N3
pending packets**, including status. Transport
failure likewise grants nothing. This availability metadata is not authority or
an identity pin; current account/grant guards still apply. Deployment can change
after discovery: a subsequent unauthenticated error still retains pending bytes
until authenticated recovery is possible. Neither `/healthz` nor
`/v2/client/identity` gets extra fields; existing strict N2 decoders stay valid.

Requests use the existing `cicada.owner-account-packet.v1` envelope, the same
enrolled App key, and Client Wire v1 ML-KEM-768 / ML-DSA-65 / AES-256-GCM. Every
new account envelope has **HandshakeEpoch=1, PacketSequence=1**, its own random
128-bit request ID and 256-bit client nonce. There is no new global account
sequence. Account/device epochs in the protected context are checked against
Store, not trusted from the route. Fresh first deliveries have the existing
60-second request window and at most 30 seconds future clock tolerance.

The exact canonical origin and full Hub pin are the saved App profile's existing
Client-Control public identity. Responses are signed by that **same
Client-Control identity and key version** and encrypted to the enrolled App.
Neither the Peer identity nor the Node-Control identity substitutes this pin.
No secret-bearing POST precedes independent full-pin verification.

Canonical JSON follows the existing typed `encoding/json` framing: bounded
decode, unknown fields and trailing data rejected, and byte equality with typed
re-encoding required. Each original and receipt is bounded to 128 KiB. Every
accepted prepare/complete/cancel packet and N3-tagged Client confirmation packet
is capped at 128 KiB even where a legacy parser allows more, so every accepted
mutation fits `reconcile`. Oversize originals fail before admission; reconcile
itself is never an eligible original target. The new
extension body is bounded to 192 KiB. **Reviewed transport-budget erratum after
types checkpoint `a545988`: only the five N3 operations use a 384 KiB inner cap;
the outer cap remains 384 KiB.** Ordinary Client/N2 inner caps remain 256 KiB.
The bounded outer parser recognizes an exact N3 operation before selecting its
larger inner bound; unknown/default ingress never gains it. Explicit clientwire
packet-limit helpers preserve old defaults, fields, AAD and version. The retained
real-PQ RED proved that a legal 128 KiB nested carrier fits the JSON body but
exceeds the old inner cap after double base64; full outer-frame GREEN and default
rejection are required. Owner proofs are at most 32 KiB. Compact reconciliation
responses do not repeat large full-key scopes alongside a nested base64 receipt.
Legal receipts above 96 KiB must round-trip; limits never expand old operations.

## Preview without knowing the Node ID

The user normally has a short pairing code. It is an **untrusted selector**,
not proof of identity, ownership or approval. Normalize exactly like the current
Node flow: uppercase, remove ASCII spaces/hyphens, then require 12 characters
from `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`. The selector digest reuses
SHA256(`"cicada-node-device-code-v1\0" + hub_id + "\0" + normalized_code`).
It must not be confused with the Node credential's case-sensitive base64url
digest. Only the code digest is retained in authority state; raw code, session
token and complete sensitive request payloads are excluded from evidence/logs.

1. A fresh authenticated `status` with an empty grant ID supplies only this
   App's authority context: the exact existing Owner/App public identities,
   current key versions/epochs, published head, exact current account-session ID
   and expiry, and Client-counter observation. No version is guessed to be one.
   It supplies no candidate directory, Node list or liveness without authority.
   On first Client adoption only, an authenticated live counter snapshot can
   initialize a profile that has no Client counters and **no pending Client
   packet**. A resumed profile verifies its saved epoch/counters and settles its
   original pending request; metadata never skips, resets or silently adopts a
   different Client conversation. Missing/expired login allows only saved own
   diagnostics, not a new intent context or fresh Node data.
2. Entering a code and requesting preview signs an
   `APP_NODE_INITIAL_PREVIEW` intent with the existing local Owner. Its scope
   includes canonical origin/full Hub pin, existing account/Owner/App IDs and
   public identities, Owner-key version, account/device/Client-session epochs,
   expected head version, transport policy, new grant/request IDs, code digest,
   client nonce and a maximum **60-second** window. The request contains the
   same context, code, Owner intent and a current account session token.
   `AppNodePrepare.target` is exactly one discriminated selector:
   `INITIAL_CODE` (code nonempty, previous grant empty) or `PREVIOUS_GRANT`
   (previous grant ID nonempty, code empty). Unknown or mixed selectors fail.
3. In one writer transaction, Hub independently validates the session, active
   human/Root/account device/Client device and exact identities, Owner signature,
   nonce and expected head. It uniquely resolves one unexpired **PENDING INITIAL**
   candidate. Zero/multiple candidates, a digest collision/conflicting persisted
   tuple, UPGRADE or an established binding are refused. It recomputes the old
   candidate digest from the original stored basis and credential digest.
4. Prepare proposes generation `g+1` from expected published head `g`, persists the
   complete immutable candidate and a server nonce, and caches the exact sealed
   challenge atomically. At most one pending authority exists for an App.
   It neither publishes the proposed head nor changes a previous ACTIVE grant.
   `PREPARED` grants **no business capability**. Pending uniqueness chooses one
   prepare winner. Its `ExpectedHeadVersion=g` and proposed signed scope
   `HeadVersion=g+1` differ from status `CurrentHeadVersion=g`. Only complete
   publishes the new head by CAS after explicit consent. Empty-grant status
   always supplies the actual published head for a new intent.

`OwnerAppNodeCandidate` includes the old request ID/version/digest, INITIAL and
PENDING state, Hub/Node IDs, name, code digest, Node key epoch, both complete
Node and Hub Node-Control public identities, both full Node-Control-domain
fingerprints, Hub Node-Control key version and candidate expiry. Hub checks that
its current Node-Control key matches this stored candidate. The App authenticates
these values through the pinned Client-Control challenge, validates their full
fingerprints, and compares the public Node/Hub fingerprints with the Node's local
display. Names and the code never replace those checks.

## Explicit approval and finite state

The UI displays the exact authenticated candidate, the one-confirmation scope
and expiry. Only a separate explicit approval signs
`APP_NODE_INITIAL_CONFIRM` using the **same Owner in the local vault**. Signing
uses existing Pure ML-DSA-65 with empty context over the dedicated domain plus
canonical typed claims. Preview and grant domains are
`cicada/owner/app-node-preview/v1\0` and
`cicada/owner/app-node-grant/v1\0`; neither is the old Root-bootstrap or device
enrollment purpose. Active Root already has the earlier KEM/signature possession
proof; this operation changes no Root and requires no repeated first-Root ceremony.

The grant signs every scope/candidate field, expected and proposed head, grant ID, exact
prepare request/packet digest, exact preview-proof digest, server nonce, ordered
allowlist, confirmation limit and all deadlines. Complete must match the original
persisted challenge byte-for-byte. Its proof deadline is at most five minutes
from prepare and no later than the Node candidate's expiry. Its runtime deadline
is **exactly prepare time + 15 minutes**. Delayed complete, retry, restart and
re-login cannot move that deadline.

| Transition | Required authority and durable result |
| --- | --- |
| no pending proposal → PREPARED | Current login + enrolled App proof + exact Owner preview intent; one pending winner; published head and any ACTIVE grant unchanged |
| PREPARED → ACTIVE | Same login/App/Owner and epochs + exact grant proof/server nonce/target; compare published head `g`, publish new grant `g+1` and revoke any prior ACTIVE grant atomically with receipt |
| PREPARED → CANCELLED | Same enrolled App/current login/exact proposal and expected published head; published head and prior ACTIVE grant unchanged |
| ACTIVE → CANCELLED | Same enrolled App/current login/exact active grant and published head; advance head by one and cancel pending proposals based on the old head atomically with receipt |
| PREPARED → EXPIRED | Proof/candidate deadline reached; cannot complete later |
| ACTIVE → EXPIRED | Fixed lease deadline reached; no new business read or action |
| pending/active → REVOKED | Root/device/human revocation, changed account/device/Client epoch, or restore fence; no revival from old receipts |

Terminal history and immutable deadlines are retained. A new authorization uses a
new explicit preview/approval, grant ID and monotonic head; it cannot update the
old grant or N2 row. The server enforces one confirmation; competing confirms
cannot approve two bindings. The App must distinguish **permission granted**
from **Node confirmed**. Complete alone does not confirm the Node.

If INITIAL authority becomes ACTIVE but never produces successful confirmation
provenance, a consumed/expired candidate must not strand that App. A new explicit
INITIAL preview from a new code is permitted only after the prior proposal or
grant has an authenticated terminal result, every pending original packet has
been reconciled, and neither the App's retained history nor the Hub has a
successful confirmation provenance. It uses the current head CAS and a new
grant instance, preserving all old history. ACTIVE unconfirmed authority must
first be explicitly cancelled or become expired/session-ended. Security
revocation or changed identities/keys/epochs cannot use this path. Once any
successful provenance exists, the only subsequent profile is READ_EXISTING for
that exact unchanged binding; a new code cannot substitute another Node.

### Explicit status reauthorization after expiry or login replacement

The user is not stranded after the one-use INITIAL code is consumed. The
`PREVIOUS_GRANT` branch is an explicitly signed **new** `READ_EXISTING` grant for
the same previously confirmed Node. It never re-pairs, consumes a new code,
resets a binding, rotates a key or extends a previous lease in place.

The parent must be the latest published grant, with durable exact confirmation
provenance (or a later status-only grant retaining that provenance). Its finite
lease may have expired, its bound account session may have ended, or the same
App may have explicitly SELF_CANCELLED it. Self-cancel reduces current App
access, not the unchanged Node binding. A cancelled PREPARED proposal has no
confirmation provenance and cannot use this path. Security-REVOKED authority
cannot use this path. The new current login may
have a different session ID/expiry, but the account/device/Client epochs,
Owner/App identities and Owner-key version must match the parent's. Hub checks
the original unchanged ACTIVE owner binding, credential version, Node key,
Node-Control key/epoch and approved candidate tuple. Changed keys, epochs or
binding fail closed rather than being adopted as the old Node.

An ACTIVE parent in the same still-current bound login cannot roll into an
early READ_EXISTING lease. Prepare requires expiry, bound-session end or
SELF_CANCEL; an ACTIVE parent is eligible only when the explicitly authenticated
current login is a different session. This is explicit reauthorization after a
lifecycle boundary, never periodic early refresh.

Published head metadata keeps `LatestGrantID` after expiry/self-cancel and a
`ConfirmationProvenanceID` naming the immutable exact successful confirmation
record. A READ_EXISTING chain retains this same provenance. Cancelling ACTIVE
advances `CurrentHeadVersion` but retains those pointers; cancelling PREPARED
does not publish that proposal or change either pointer. Bootstrap status returns
the current head and these own pointers without adopting authority. The new
intent uses the **current** published version, not the old signed grant's version;
the new Owner signature also fixes the parent and confirmation provenance IDs.

The Owner signs `APP_NODE_STATUS_PREVIEW` naming that exact previous grant,
current login/context and expected head. Prepare returns a mutually exclusive
`OwnerAppNodeBinding` full-key tuple instead of a new candidate, and grants no
liveness read yet. The user explicitly approves it; complete verifies
`APP_NODE_STATUS_READ`, profile `READ_EXISTING`, `read_node_status:true`,
an empty Client RPC list and **confirmation_limit=0**. Its new grant ID, head
CAS and prepare+15-minute deadline use the same receipt/fence machinery. It
cannot execute `nodes.confirm`, even with an old valid code or replayed packet.
The user action is “authorize status again”; it is never an automatic refresh.

### Account-session binding

Every intent/challenge/grant binds the exact authenticated account-session ID
and expiry, not merely an account/device epoch. Complete uses the same active
session as its prepared scope; re-login during review requires a new explicit
intent. Its proof deadline is also capped by that session's expiry. New confirm,
and Node-only status recheck **that stored session**, its credential
version, state and deadline inside the authorization transaction. Logout or
session expiry stops new operations; another session for the same device cannot
substitute through an “any active login” query. Status requests carrying a token
must match the grant's session for fresh Node data. Client RPC uses its exact
grant ID to select the bound session; it does not infer one from Client epoch.

The effective deadline is the earlier of bound session expiry and fixed grant
expiry. Fresh login does not renew or silently adopt the old N3 grant; it can
start the explicit status-only consent above. Diagnostic reconciliation remains
available to settle historical packets. Historical COMMITTED/COMPLETED receipts
do not establish current session or Node-read authority.
Own status reports SESSION_ENDED when the bound session has ended, distinguishing
it from security REVOKED. Expired/self-cancelled/session-ended authority has no
fresh Node projection or new business operations until explicit reauthorization.

## Existing Node confirmation and Guard

After complete, use the old `nodes.confirm` body and response shape with exactly
the approved code/digest/version. Client RPC retains its independent monotonic
session epoch, request sequence and reserved response sequence. Its authenticated
`operation_id` is `n3.<grant_id32hex>.<nonce32hex>` (68 characters, within old
limits). The existing Client AAD authenticates it. Every new N3 business packet,
names the exact grant instance. A delayed
packet cannot borrow a later grant, even when the same Node is approved again.

Guard intersects current authenticated App, human/Owner key, account and device
epochs, a current account login, exact grant/head/Client-session epoch, scope,
fixed deadline, confirmation budget and the existing Node candidate/binding
Guard. It runs at admission and **inside the effect transaction**. A protected
N2/N3 device never falls back to ordinary broad Client rights when a lease is
expired, revoked, absent or malformed. Legacy registration cannot remove either
history. Missing scoped authority means deny; public capabilities are metadata.

Extract the existing Store confirmation into a shared transaction helper. For an
N3-tagged confirm, one writer transaction must authenticate the exact original
Client packet metadata, recheck all current guards, consume the confirmation
budget, confirm the old exact candidate/credential/key binding, reserve the
response sequence, seal and persist the **original Client response**, then commit
the effect and receipt together. Existing response framing/fields stay unchanged.
No network/client/user wait occurs inside the transaction. Seal failure rolls
back the binding, budget, sequence reservation and receipt. Any preliminary
PROCESSING request left by old admission is never itself proof of confirmation.

All ingress paths must use that atomic N3 transaction or reject the packet.
This slice exposes N3 only in `--hub-nodes-only`. Full `serve`, `--hub-only` and
`--fabric-only` reject N3-tagged packets and new endpoints; they cannot route
them through legacy non-atomic dispatch. Old untagged behavior remains separate.

## Exact retry, reconciliation and counters

Before **every POST**, App vault persistence records the original ciphertext,
operation/request ID, nonce, complete grant/candidate tuple, digest and relevant
Client counters. Persistence failure sends nothing. An unsigned 403/429/5xx,
timeout, truncated/corrupt response or process death retains the pending bytes.
Retry never reseals, re-signs, changes identities or creates a substitute ID.

Prepare, complete and cancel effects/nonce consumption and exact sealed receipts
are atomic. Same ID and exact packet returns the original receipt; a changed
digest/body/nonce is rejected for these primary mutations. Status is a cached
historical observation on exact retry while its bounded read-cache entry exists;
a **new** status request is required to observe current authority.
`ABSENT` never settles pending work. Cached success does not establish current
authority and never dispatches again after expiry or revocation.

`reconcile` is a diagnostic channel authenticated by the retained exact App key.
Its `OriginalKind` is `APP_NODE_AUTHORITY` for prepare/complete/cancel/status, or
`CLIENT_CONTROL` for exactly N3-tagged `nodes.confirm`. It carries the complete
original packet, not a caller-asserted ID/digest. Hub authenticates that original
against the same saved identities and extracts the target and grant instance.
No arbitrary RPC, account operation or other device's target is accepted.

Status consumes no Client request/response sequence and cannot mutate a grant,
binding or budget. A lost, unadmitted or no-longer-cached status can therefore be
settled by authenticated `READ_EXPIRED` naming the exact original read digest.
Reconcile returns its cached observation when present, otherwise READ_EXPIRED;
it does not execute a fresh Node read. Replaying an uncached status beyond its
60-second request window likewise returns a sealed READ_EXPIRED, never just an
unsigned rejection that strands the App. The App durably closes **only that
read**, ignores its late responses by request ID, then uses a new status ID for
current data. No durable mutation fence is needed for a side-effect-free read;
READ_EXPIRED is never valid settlement for prepare/complete/cancel/confirm.

Under the same writer serialization as the original action, reconciliation:

- returns `COMPLETED` with the exact original receipt when the committed packet
  digest and effect/receipt record match; or
- persists `REJECTED_FENCED` for that original operation/digest and returns its
  authenticated rejection, guaranteeing a late original can never execute.

Those two durable outcomes govern mutations. The status-only READ_EXPIRED rule
above is separate and cannot clear an uncertain mutation. Reconcile itself is
not an eligible original target: retrying even an aged diagnostic request may
reconstruct an authenticated answer from the permanent **target** receipt/fence
after its optional outer-response cache expires. It never replays a target effect
or requires a new grant/session just to recover that outcome.

For N3 confirm, authoritative binding proof must include the exact sponsoring
Client request ID/digest, grant/head, approved candidate request/version/digest,
Owner/App, Node-Control and credential versions. “A Node with this name/ID is
bound” is insufficient. An unexplained historical PROCESSING/UNCERTAIN record
without that proof remains unresolved and fails closed; it is never fabricated
as success or silently resubmitted.

The fence for an unadmitted Client request can consume its slot only if the
original epoch and sequence are exactly current/next. Fence, request slot,
reserved response sequence and original-route rejection packet commit together.
An accepted slot is settled through its existing reservation. Conflicting,
future/gapped or changed-epoch slots return `COUNTER_CONFLICT` and preserve the
App's uncertainty. No diagnostic hint resets or skips Client counters. Historical
epoch receipts can be inspected without mutating the new epoch's counters.

Reconcile itself never executes a business action or grants a login/lease. It
works after the original session/lease expires or Root/device authority is
revoked, using retained diagnostic keys. The response separates original outcome
from current grant/epoch diagnostics. Restored state revokes all N3 pending/active
authority through the existing account-epoch fence; no Owner/App identity is
regenerated and no Client replay counter is zeroed. App restores must settle
pending packets before initializing a new business conversation.

Read-only metadata/status/reconcile response caching retains at most 128 entries
per device in a rolling five-minute cache; oldest read entries may expire/evict.
Ordinary Node polling and metadata refresh have **no epoch-lifetime quota**.
Diagnostic reconcile work has a renewable rate bound of 128 new requests per
minute per device; exact cached retries do not consume another token. Temporary
backpressure expires with that window and cannot permanently brick an account.
Primary mutation receipts, confirmation provenance, replay nonces and rejection
fences are never subject to this cache's eviction or rate-accounting deletion.
Restore inventory and floor
protection must cover all new head, authority, nonce and effect/receipt rows.

## Node-only observation

With a current login and live exact grant, fresh `status` returns only its selected
Node's binding/key state and heartbeat observation. Without those conditions,
`Node` is null; only this App's authority/counter/receipt diagnostics are returned.
No full status snapshot or other Node, Worker, Goal, Thread or provider profile
is fetched as a substitute. A confirmed binding can exist with unknown liveness.

`AppNodeObservation` identifies the exact binding and credential versions,
Node key/epoch, authorization, `last_heartbeat_at`, server `observed_at`,
`fresh_until`, source `store.machines.last_seen`, and known/stale flags.
Freshness uses the server-recorded accepted bound relay heartbeat plus 120
seconds, independently of Worker availability. INITIAL starts with no heartbeat;
an empty/malformed time, missing machine, heartbeat before exact binding approval
or implausible future time means UNKNOWN/stale. A valid heartbeat means CONNECTED
before `fresh_until`, otherwise STALE. Relay-only sends an empty heartbeat body:
its persisted Worker `machines.status` can remain `offline` while relay is live.
That flag is not a Node-liveness oracle and is never changed to worker-available
to make the view green. V1 has no separate authenticated relay-shutdown marker,
so it does not emit OFFLINE or infer physical disconnection from stale data.
Unavailable/revoked current binding is not shown as an authorized online Node.
No local `control-local` or
`worker-local` shortcut is allowed. CONNECTED means a recent heartbeat, **not**
proof of an open SSE connection, Runtime readiness, model consumption or work.

## Explicit Hub composition and first Node

`serve --hub-nodes-only` is a new explicit, mutually exclusive mode. It composes
one existing Store and the retained Hub identities with hubowner, hubauth,
Fabric and a narrow Node service/Client transport interface. It reuses existing
Store pairing, Node proof, confirmation, heartbeat, SSE and Client/Node wire
helpers. It never calls `Control.New`, `Control.Start`, `registerLocalMachines`,
intent recovery, Worker launch, planner, scheduler or Runtime. It neither creates
a replacement key nor deletes historical local-machine rows. Public discovery
advertises only this composition's availability; authenticated scope is checked
again for every call.

The only Node-Control business RPC is existing `node.binding.status`; other
management/Worker routes are unavailable. Account and Owner operations retain
their existing services. Existing `--hub-only` behavior stays unchanged. Add a
bounded interface/transaction extraction, not a second implementation of all
Control behavior or a broad compatibility retirement.

First physical target is Ubuntu **24.04.3 x86_64**, ordinary `zyf` uid 1000,
Codex CLI **0.163.0**. A reviewed matching linux/amd64 artifact and script can run
with explicit binary/state paths and `--mode relay`; the Node needs no Go build
or Hub private state. Keep its identity and private state across retries/restarts.
It opens no inbound port and uses trusted outbound HTTPS. Installing, authorizing,
confirmed binding, recent heartbeat and a real Runtime task are distinct states;
this slice stops at the first four and performs no paid/model work.

`HTTPS_APPLICATION_PQ` means standard verified HTTPS transport plus the existing
application PQ proofs; it is **not strict PQTLS**. The adopted specification's
outbound-HTTPS path and current optional transport allow this bounded mode. A
configured strict-PQ policy may not downgrade to it. Production CA setup,
PQTLS changes and ARM64 are outside this slice; no synthetic key initializes a
deployment. The current ACTIVE Hub is upgraded by separately reviewed rollout,
retaining a consistent backup, exact identities and state. Earlier wipe permission
does not authorize replacing it. This contract authorizes no deployment.

## Errors, ownership and executable acceptance

Authenticated terminal errors use `INVALID_REQUEST`, `SESSION_REQUIRED`,
`ROOT_UNAVAILABLE`, `DEVICE_UNAVAILABLE`, `SCOPE_MISMATCH`,
`CANDIDATE_UNAVAILABLE`, `CANDIDATE_CHANGED`, `AUTHORITY_CONFLICT`,
`PROOF_EXPIRED`, `AUTHORITY_EXPIRED`, `AUTHORITY_REVOKED`, `CONFIRMATION_USED`,
`REPLAY_CONFLICT`, `COUNTER_CONFLICT` and `DIAGNOSTICS_FULL`.
`READ_EXPIRED` is the additional authenticated terminal result for status only.
A terminal mutation result may clear pending bytes only when it names their
exact digest and has a durable receipt/fence; the side-effect-free read exception
is defined above. Unauthenticated transport errors never do so. Unknown errors fail
closed. Error payloads exclude codes, passwords, tokens, private keys and complete
sensitive packets.

Hub owns these public types/contracts/checks, e2ee proof wrappers, hubauth,
Store/migration/restore coverage, Server, the narrow Hub composition and Node
CLI/install/build helpers. App owns vault/controller/UI consumption after Root
review. QA owns independent N3 process/fault tests and native plan/validation;
Root owns integrated N2 regression, standard disposable interop and matched final
builds. No dependencies or frozen identifiers change for coordination.

The reviewed-types checkpoint's focused structural normal/race checks each
passed 15 events (four top-level and eleven subtests), zero failures/skips.
New metadata, the unchanged N2 metadata and formatting checks passed. Exact
dirty source manifests and logs are retained under workspace-local
`.local/evidence/n3-hub/contract-draft/`, attributed to `f8b5e58` plus these seven
new paths, not HEAD alone. Earlier cache-permission and non-executable-tmpfs
attempts failed before test execution and remain recorded. These data-only tests
use visibly synthetic identities and non-signature placeholders; they do not
establish cryptographic proof verification, N3 HTTP/Store support or a deployed
feature. The source below lists implementation acceptance still required.

Required implementation checks (not yet run by this types-only checkpoint):

- Focused Hub normal/race guards: same Owner/App after natural N2 expiry;
  account/password without Owner signature; code substitution/collision,
  UPGRADE/second Node, grant scope/nonce/deadline/epoch/head tampering; concurrent
  prepare/complete/confirm/cancel; one budget; transactional rollback; same-packet
  retry, changed ciphertext, expired/revoked historical receipts and restore.
- Every ingress either reaches the atomic N3 path or refuses it; all N2/N3
  expired/missing grant paths deny broad Client operations. Mode tests prove
  zero Control constructor/scheduler/local Worker registration and only
  Node-only status. No model, shared Hub or real keys are test fixtures.
- Independent TCP process gate: persist before POST; loss before admission,
  after each effect/receipt commit, 403/truncation/PQ tamper; kill/reopen Hub and
  App; original late delivery versus durable fence; exact binding proof;
  counter/epoch conflicts; >96 KiB nested receipt; wrong Hub/scope sends no secrets.
- Root's N2 regression and standard disposable Docker interop remain required.
  Matching Node/App builds, real Windows custody/UI, Ubuntu physical Node
  installation/approval/heartbeat, public HTTPS, Runtime tasks and strict PQTLS
  each have separate evidence and NOT_RUN until actually executed.
