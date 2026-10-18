# N3 bounded native Thread pair: contract proposal

**SERVER PREPARATION — guarded setup/recovery only; public availability remains false until the Node and peer Guards close.**
Baseline: `0fbd09105e73e1e6e2488dafcb0b7b14e8264faa`, 2026-10-17.
Proposed separate contract identifier: `native-pair-v1`. Names and limits below
become implementation requirements only after review. This is the proposed
public boundary, not another task/implementation-status ledger.
Scoped preparation evidence is appended to the existing [A1/A2 validation record](hub-native-pair-a1-validation.md#a2-storehttp-preparation-available-false).

## Result and fixed scope

One already ACTIVE Owner uses the existing Windows App vault to prepare two
zero-permission Join slots on one existing Hub/Node binding. Native SIDs need
not be known during preparation. Two real Threads explicitly Join the new
private, Network-bound Group and publish their own Node-held Endpoint candidates.
Only then does the Owner review and authorize both actual SIDs and candidates.
Preparation is not permission to communicate.
Then A uses `cicada_ask`, B consumes the request in its original context and uses
`cicada_reply`, and A receives B's answer in its original context. The App
authorizes setup; it is not in the peer-message path.

New same-Node messages use the existing sealed Hub Relay. Generic native direct
remains `UNSUPPORTED`. Same Group needs no CommunicationLink. Cross-Group,
cross-Owner, second Node, Worker/Goal creation, generic Manager RPC, arbitrary
command execution, workspace enumeration, transcript reads and automatic cold
wake are outside this contract.

The account, Owner, App device, Node ID, three retained Hub keys, Node private
keys, credentials and epochs are preserved. No other Owner/device is enrolled to
escape N2 restrictions. No real private key is exported from the Windows vault.

## Authority and clocks

The existing `owner-activation-v1` and `app-node-authority-v1` grants retain their
exact scopes and immutable deadlines. Neither account login nor Node status
permission authorizes this flow. A separate, explicit Owner proof is required.
Existing Client wire 1/catalog 55 and peer ciphertext formats remain unchanged.

Administration requires the current exact account session, App key, ACTIVE
Root/human/Owner key, matching account/device/Client epochs, and the current full
Node binding/credential/Node-Control tuple. All checks occur after acquiring the
Store writer and transaction, using one trusted server time. The requesting App
is the existing N2-enrolled device with its completed N2 history; N2 need not
still have an active runtime lease.

Only the explicit Hub Nodes composition may advertise this new capability.
The old N3 capabilities response remains byte/schema compatible: its five
operations and profiles do not gain pair authority. Standard/full/Hub-only and
Fabric-only modes do not silently acquire this new App bootstrap surface.

Proposed fixed limits: one pair per bootstrap request, two initially empty slots,
exactly two distinct Codex native SIDs before final consent, one new private
Network and one new Group, at most two current slot consents. A bootstrap preview
expires after five minutes; both Joins must finish within ten minutes of
bootstrap preview. At most one nonterminal pair may exist per Owner/Hub/Node,
and each slot may have at most sixteen total generations before
this pair must be explicitly revoked/replaced. This is a per-pair bound, not an
epoch-lifetime polling or enrollment quota. A consent plan expires after five
minutes, capped by its administration session and the pair's peer deadline.
Owner preview intent freshness is at most sixty seconds. Request freshness is
sixty seconds. Retry/restart never recomputes a deadline.

The proposed peer deadline is exactly bootstrap preview + one hour, displayed
and signed before creation. Network/Group membership and Endpoint key grants
are capped at that absolute deadline. This one-hour policy is a review decision,
not a change to N2/N3's fifteen-minute policies. No automatic renewal is included.

The account session bounds creation/consent/revoke administration. After ACTIVE,
App logout, App shutdown and expiry of its Node-status grant do not rewrite
peer memberships or key grants. Current Owner/Node/Group/member/key revocations,
native leases and the peer deadline remain authoritative. No existing Guard is
bypassed because a pair was once approved. A replacement login may administer
the same retained pair only with fresh explicit intent; it cannot reuse a pending
old-session consent. Historical recovery is separate from new authority.

## Proposed typed HTTP and Node methods

Paths under `/v2/owner/native-pairs/` use the registered App's authenticated PQ
envelope, typed strict JSON and the pinned origin/Hub key. No generic RPC or
caller-supplied SQL/action list is accepted. Public discovery is availability,
not authority; unsupported discovery means zero secret POSTs/new pending state.

| Method/path suffix | Typed operation and effect |
| --- | --- |
| GET `capabilities` | Available mode, this contract revision, exact operations, limits and `SEALED_RELAY`; no identities, candidates or credentials |
| POST `bootstrap/prepare` | Verify Owner preview intent for the exact existing Node and two zero-permission slots; reserve immutable pair/Network/Group IDs; return a review challenge; no Network/Group/peer rights yet; no SID scan |
| POST `bootstrap/complete` | Verify exact vault Owner bootstrap proof; atomically create the ACTIVE private Network, mapped ACTIVE Group, two empty slots and exact response receipt; no SID or peer permission is inferred |
| POST `slots/reject` | Before ACTIVE only: Owner rejects one exact occupied zero-permission attempt; fence it, retain its history and open a new slot generation; invalidate unpublished consents; never replace a SID under an old proof |
| POST `consent/prepare` | After both zero-permission slots and candidates exist, freeze one activation plan containing both exact candidates and projected final membership/key manifests; no rights change |
| POST `consent/complete` | Record one slot's explicit Owner consent and existing Group Endpoint key-grant proof; only the second compatible consent may atomically activate both slots as described below |
| POST `status` | Only this pair's setup/slot/consent/receipt metadata and current administrative eligibility; no peer bodies, native history or owner-wide topology |
| POST `revoke` | CAS-revoke the entire pair and both peer memberships; invalidate its key grants and unstarted deliveries; retain all provenance/receipts |
| POST `reconcile` | Authenticate the exact original request/digest; recover its receipt or commit a rejection fence for an unadmitted mutation; never execute a substitute action |

Node-Control `node.native_pair.describe` first returns the bounded signed
bootstrap and current slot generations for this pair. The Node verifies it
against its independent original Owner public pin and current exact Node tuple,
then durably marks this Group/pair **pair-policy-required before Join**. This
marker survives restart and cannot be cleared by a later Hub response.

New Node-Control operation `node.native_pair.join` uses the existing Node PQ
route, sequence/outbox and exact current binding. It names only pair ID, slot
`A`/`B`, expected slot generation and actual native SID plus bounded display
metadata. Its trusted local bridge
derives SID/workspace from the actual Codex process and verifies the local
session record before sending. Model arguments cannot override those values.
The Hub checks the Owner-signed empty-slot policy, actual Node and slot CAS,
then records the actual SID for this attempt. It returns the existing
Group Join shape inside the Node envelope, keeping session credentials out of
MCP output. The same slot/generation/SID retry cannot create another Endpoint.
A third SID, duplicate SID across slots or competing caller for an occupied
slot is rejected without replacing the winner. Occupancy grants no peer right.

This narrow operation composes actual zero-grant Network enrollment,
zero-permission Group admission and native binding atomically under the explicit
Owner empty-slot proof. Existing `OwnerNetworkJoinGrant` requires a known SID;
it must not be fabricated or treated as a wildcard for this new preparation
flow. Extract validated enrollment row/Guard builders behind the new typed
actor, retaining current Network/Node/Owner and native-binding checks; do not
relax the old Network-Join proof validator. It does not call a local-operator API,
fabricate a legacy accepted Client request or expose generic `topology.apply`.
For this first checkpoint a SID already bound to an unrelated Cicada scope is
rejected explicitly; it is not rekeyed or silently moved. Reopening an admitted
SID restores its retained scope and session without changing identity, epoch,
budgets or peer deadline. Expired/revoked old scopes remain recorded. This first
version does not support moving that SID to a new pair or migrating an unrelated
scope; return a typed conflict instead of creating a replacement SID or rekeying.

The sole MCP selector is additive `cicada_join(pair_id, slot)`, with both
parameters required together and `slot` exactly `A` or `B`. Explicit `group_id`
is mutually exclusive; the pair branch ignores a legacy default
`CICADA_GROUP_ID`. Native SID, Node and workspace still come from trusted local
context. Node authenticates describe, verifies/persists the required policy
marker and original tuple, then durably sends exact Join. An uncertain Join
cannot refresh generation through another describe. Node persists the returned
zero-Join session and original Endpoint private key before automatically
publishing the existing self-attested candidate. Intermediate output is
`JOINED_ZERO`/`CANDIDATE_PUBLICATION_PENDING`; only actual Hub acceptance plus
local durable application yields `CANDIDATE_READY`. Neither implies peer rights.

All three Node methods use POST `/v2/node/control/rpc`, existing `CicadaNode`
authentication and `nodewire` v1 PQ. Describe returns its existing typed
`NativePairNodeDescription` as the normal RPC `result`; Join returns the existing
`fabric.JoinResult` inside that envelope, retaining credentials only on Node.
Detached reconcile binds the original Node route/operation ID/sequence/digest,
not App authentication, and does not consume the blocked business sequence.

CredentialCommitment is lowercase hex encoding of the same 32-byte SHA-256
represented by the existing raw-base64url Node credential digest. Hub strictly
decodes that stored digest and Node hashes its actual trimmed credential; there
is no second hash. The first Store-only Node-Control binding version comes from
the independently Owner-pinned bootstrap and is durably pinned, not claimed as a
value locally derivable before that first proof. Subsequent tuple changes cannot
be silently adopted. Existing binding.status JSON is unchanged.

Original Owner public-key transfer uses only flat `e2ee.PublicIdentity` JSON
(`id`, `kem_public`, `signing_public`; byte arrays are base64), at most 32768 bytes.
App displays the retained Owner ID, full key ID and the existing
`nodekeys.PeerKeyFingerprint`: `sha256:` plus lowercase hex SHA-256 of
`cicada/nodekeys/peer-key-fingerprint/v1` plus NUL, then KEM bytes, then signing
bytes, with no other separator. This differs from the Hub/Node-Control and N2
display fingerprints. The user independently compares those values before
`machine trust-owner-key` on the original Node/state/WriterRoot. Its existing
regular-file/no-symlink checks and maintenance locks remain authoritative;
the user normally stops and restarts the original Node service around pinning.
No private key, session credential or replacement identity is transferred.

## Minimum DTOs and signed statements

The authoritative Go/JSON DTOs are `internal/hubaccountwire/native_pair_types.go`
and `internal/e2ee/owner_native_pair_claims.go`; canonical validators and digest
helpers sit beside them. A1 was `WIRE_ONLY`. The Store/HTTP preparation checkpoint implements guarded
setup and recovery but advertises `available=false` while Node Join, dual
consent and Relay Guards are incomplete; supported Apps send zero new secret
POSTs on this discovery response. Explicit synthetic protocol tests can exercise
the guarded development routes without representing a supported user flow. Required fields cannot be inferred from display labels.

| DTO | Required contents |
| --- | --- |
| `NativePairRequestContext` | contract/version, operation, origin, Hub/account/Owner/App device IDs, current account-session ID, account/device/Client epochs, request ID, nonce, issued time |
| `e2ee.OwnerNativePairScope` | context identity tuple; full original Owner/App public identities; full current Owner Node-binding ID/version, credential version, Node public key/version/epoch, Hub Node-Control key/version; Node ID; runtime allowlist exactly `codex` |
| `e2ee.NativePairBootstrapClaims` preview | PairScope, proposed private Group label, two initially empty slots, no-peer/no-directory/no-history policy, fixed eventual per-slot peer allowlist/budget and absolute bounds, intent nonce/deadline; no SID required |
| `NativePairBootstrapChallenge` | exact intent and original-packet digests, reserved pair/Network/Group IDs, two empty slot IDs/generations, bootstrap nonce/deadline, Join deadline, peer deadline, server observed time |
| `e2ee.OwnerNativePairProof` commit | vault Owner signature over the complete challenge and original Node scope; expressly permits only two zero-permission local metadata Joins before actual SID/key review |
| `NativePairSlot` | slot/generation/attempt ID/actual SID, authoritative Endpoint/Principal/Node IDs, Network access binding/epoch, Group native binding/epoch, membership/join revisions, candidate version/full public key/fingerprint/attestation/digests; no private key, transcript or session token |
| `NativePairConsentPlan` | pair/control revision, plan ID/digest, both complete PairSlots, current snapshot revisions, projected final membership revisions, exact final per-slot permission lists, budgets and deadline, both projected existing GroupEndpointKeyGrantManifest values, plan deadline |
| `e2ee.NativePairConsentClaims` | slot/generation/attempt ID, plan digest, both actual SIDs and both-slot target digest, explicit activate-when-both-approved statement, Owner proof for this slot's exact projected state, existing OwnerLinkKeyGrant proof for the corresponding Group key manifest |
| `e2ee.NativePairRejectClaims` | pair/control revision, slot/generation/attempt ID and complete rejected tuple digest, explicit Owner rejection proof; no substitution SID or generic mutation list |
| `NativePairResult` | original request ID/digest, pair/slot state, immutable IDs/deadlines, current control revision and diagnostic epochs, observed time, bounded error code and exact historical receipt reference |

PairScope also binds the pinned Hub Client-Control key fingerprint/version and
a Store-derived digest of the stable authority Node tuple, including the
credential commitment without disclosing its raw bearer. Node labels, heartbeat
and observation timestamps are not authority. Normal lease renewal preserves
lease identity, binding and epoch and never extends the absolute peer ceiling;
it must not invalidate consent solely because the next heartbeat is newer. Group labels are bounded
to 128 UTF-8 bytes; SID/ID selectors are canonical, bounded to 128 bytes, and
cannot be paths, aliases or caller-selected native-process arguments. Origin is at most 512 bytes and Node display name is at most 128 UTF-8 bytes. Each
MCP Join's SID must be confirmed by the trusted existing native-record check.

The six Owner proof purpose/domain pairs are fixed below. Domains end in an
actual NUL byte; JSON uses Go struct field order and must round-trip byte-for-byte
with no unknown/duplicate fields. ML-DSA-65 signing reuses the retained Owner key.
A proof for one purpose cannot be accepted for another purpose or an old N2/N3
operation. Request ID, nonce, issued/expiry times and exact scope are signed.

| Purpose | Domain before final NUL |
| --- | --- |
| `NATIVE_PAIR_BOOTSTRAP_PREVIEW` | `cicada/owner/native-pair/v1/bootstrap-preview` |
| `NATIVE_PAIR_BOOTSTRAP_COMMIT` | `cicada/owner/native-pair/v1/bootstrap-commit` |
| `NATIVE_PAIR_CONSENT_PREVIEW` | `cicada/owner/native-pair/v1/consent-preview` |
| `NATIVE_PAIR_SLOT_CONSENT` | `cicada/owner/native-pair/v1/slot-consent` |
| `NATIVE_PAIR_SLOT_REJECT` | `cicada/owner/native-pair/v1/slot-reject` |
| `NATIVE_PAIR_REVOKE` | `cicada/owner/native-pair/v1/revoke` |

Existing Network-Join and Group key signatures retain their frozen purposes and
encodings. New unknown-SID bootstrap cannot satisfy the old known-SID grant.
Canonical Slot and Plan digests bind the complete public DTOs; final consent
also names both actual SIDs, generation and attempt explicitly. A bootstrap
preview requires empty reserved IDs/deadlines; commit binds the server-assigned
IDs, prepare packet digest and nonce. Preview never pre-approves an actual SID.

Both final Group memberships have exactly `directory.read`, `message.ask`,
`message.receive`, `message.reply`. Either original Thread may ask the other;
the pair-wide limits below apply across both directions together. No
`message.send`, broadcast, artifact, history, Network directory/direct,
invite/admin, topology or Runtime permission is granted. Group directory has
only these two admitted Endpoints. Network enrollment grants remain empty.

The signed fixed budget is **four independent root ASK and four correlated
Reply, eight business messages total per pair**, with at most one Reply per ASK
and one outstanding ASK. No child/causal ASK, third party or automatic loop is
allowed. Limits are 8 KiB plaintext/message, 64 KiB total plaintext,
128 KiB ciphertext/message, 1 MiB total accepted ciphertext and eight distinct
receiver native submissions. Both Hub and Node enforce this signed policy;
Node checks plaintext after opening, Hub counts actual ciphertext bytes.
The Hub also bounds authenticated inner AEAD ciphertext length minus the fixed
16-byte AES-GCM tag, without decrypting content; padding consumes the same
plaintext budget. Its total is derived from the immutable admitted ciphertexts,
so cancellation, expiry, UNKNOWN and restart do not refund it.
These ceilings do not instruct the gate to exhaust all four exchanges.

Hub charges admission and its exact receipt atomically. Same pair/message ID/
ciphertext digest reuses the recorded outcome before charging; changed bytes
conflict. On the same Node, sender/receiver handling counts that message once,
not once for each role. Native delivery charges once per receiver identity plus
pair/message/digest. UNKNOWN durably occupies a reservation and never permits
blind re-injection, refund or restart reset. Node's conservative local reservation
ledger and Hub's admitted counters may differ; this is not a distributed atomic
counter. Status must distinguish them. These are business-message/submission
limits, not provider HTTP call, model turn, token or cost limits.

## Zero-permission Join and atomic activation

1. `PREPARED`: metadata-only bootstrap challenge. Abandonment has no domain or
   permission effect.
2. `WAITING_JOIN`: bootstrap completion creates an actual ACTIVE Network and an
   ACTIVE Group whose `network_id` names it. It reserves two initially empty
   slots without knowing their SIDs. It never activates global Network migration
   mode or uses an
   unmapped/`PREPARING` migration exception.
3. Each slot transitions `RESERVED -> JOINED_ZERO -> CANDIDATE_READY`. Actual
   Network enrollment records the actual SID under the signed empty-slot
   policy, with no Network grants and no discoverability. Group
   membership is ACTIVE `member`, `grants:[]`, with no inherited peer grants.
   This permits only the existing self `whoami`, heartbeat and self-attested
   candidate publication/read. It cannot resolve/enumerate peers or ASK/Reply.
   Controlled Pair Join records the existing
   `local_peer_delivery: "sealed_v1"` Endpoint capability in that same transaction;
   its Join/WhoAmI/resolve cards project the same value. This describes the
   implemented transport, supplies no grants, and cannot bypass double consent
   or any current Guard. Ordinary Join defaults remain unchanged.
   The Node keeps Endpoint private keys; the Hub sees public candidates only.
4. With both candidates ready, `consent/prepare` freezes one plan. A candidate,
   binding, key, Node tuple, lease identity, Network/Group or membership revision change
   makes that plan stale; no changed tuple is adopted. Both slots remain zero.
5. The Windows App verifies both attestations/full keys and shows the exact two
   SIDs, scopes, permissions and deadlines. The Owner explicitly approves each
   slot, binding both actual SIDs and candidate tuples. The first
   `consent/complete` stores `CONSENT_RECORDED`, not an effective
   key grant or any peer right. Both consents sign the same activation plan.
6. The second compatible consent atomically CAS-updates both zero memberships
   to their fixed per-slot allowlists, accepts both existing Owner Group Endpoint key grants,
   publishes `ACTIVE` and the exact response receipt. Any failure leaves no
   effective partial membership/key grant. Consent-collection writes do not
   change the immutable plan/control revision; activation advances that revision.

Existing key manifests bind membership revisions. Signing manifests at revision
1 and then changing membership to revision 2 would immediately stale them.
Plan preparation and consent collection retain the reviewed control revision;
PlanID selects the exact immutable prepared target. Explicitly replacing a
prepared plan invalidates its old consents without changing either Thread.

Consequently the preview must derive the exact projected final manifests under
Store Guard; activation first checks the unchanged source revisions and then
rebuilds/verifies those manifests against the final transaction rows. No external
request can observe partially upgraded membership. This requires shared Tx
helper extraction; calling the existing public Store methods in separate
transactions is not an acceptable implementation.

The pair, slot-attempt history and plan state are durable. An occupied attempt
cannot be claimed by another SID/Node; it is never overwritten. A lost Join
response recovers the exact winner. A conflict response leaves that winner
intact; Owner `slots/reject` is the only replacement path before ACTIVE, creating
a monotonic slot generation and fencing old Join/consent packets. Rejection
retains the Thread and history but revokes that attempt's zero memberships and
pair access credentials. The other slot's identity is retained, while a new
activation plan must review both actual tuples again. An ACTIVE slot cannot use
this replacement operation. A stale/expired
unpublished plan may be explicitly replaced under fresh Owner intent while
preserving the same existing identities and zero slots. Old consent packets
cannot activate a replacement plan. ACTIVE is not automatically refreshed.

`REVOKED` and `EXPIRED` stop subsequent peer authority and never return to ACTIVE.
Revoke is pair-wide in this minimum contract. The server preserves the original
Network/Group/Endpoint records; it does not delete them or the native Threads.
Replacing an expired/revoked pair is a new explicitly reviewed authorization,
not silent restoration of the old plan.

## Existing peer data path and Runtime evidence

After activation, existing native MCP `cicada_ask`, `cicada_reply`,
`cicada_request_status` and caller-scoped cancel use current Group session proof.
The Node validates current candidates, Owner key grants, peer pins and exact
source/receiver bindings. ASK/reply request IDs, immutable ciphertext and causal
ancestry follow the existing same-Group Relay implementation.

The bounded Hub composition needs only these existing peer route shapes, with
their existing methods and Guards, in addition to the new typed setup surface:

- `/v2/fabric/whoami` GET; `/heartbeat` POST; `/endpoint-keys` POST for self
  candidate publication; `/resolve` POST after activation.
- `/v2/relay/nodes/{node}/group/sealed/peer-key` GET;
  `ask`, `reply`, `claim` POST; `requests/{request}` GET;
  `requests/{request}/cancel` POST;
  `deliveries/{message}/authorization` GET with the existing exact attempt.
- Existing Node heartbeat, events, receipts and required empty queue polls.

The pair-aware admission guard must constrain these existing Relay methods to
this pair's two Endpoints, either exact direction between the two endpoints, current activation and remaining
budgets. Merely opening routes and relying on legacy membership grants would
omit these new bounds. No general Fabric/Relay prefix is enabled. The new reserved-slot Join replaces
the need to expose unrestricted `node/join` in this composition. Old local
ledger recovery is retained independently; it does not enable new direct work.

The Node needs an independently verified public pin of this same Owner before
accepting peer-key grants. Reuse `machine trust-owner-key` with the public
identity, expected key ID and fingerprint confirmed from the App; a Hub-provided
authorization bundle is not its own trust root. This never exports a private key.

For a pair-policy-required Group the peer-key and current delivery-authorization
response must carry `NativePairPeerEvidence`: complete canonical Plan, bootstrap
Owner proof, both slot Owner consents and both existing Group key proofs. Node
verifies original Owner pin, all signed identities/digests, actual candidate keys,
projected final memberships, policy and absolute peer expiry independently.
Existing GroupKeyManifest alone does not bind pair ID or budgets. Missing,
swapped, oversized or invalid evidence fails closed even if legacy Group grants
would allow the message. Ciphertext format is unchanged. Evidence JSON is bounded
to 256 KiB and the complete new authorization carrier to 320 KiB.

Before the second consent can publish ACTIVE, its writer transaction preflights
both directions of the complete peer-key and delivery-authorization types. It
uses the real endpoint/key/proof/current tuples and reserves only unknown future
route/attempt fields: the unchanged 256-byte Relay token bound with maximum JSON
escaping, a 64-character hexadecimal digest, and a maximum 30-byte RFC3339Nano
observation. Both ASK and Reply shapes are checked; the fixed depth-zero policy
keeps parent request empty and excludes Task/SEND additions. These size-only
values are internal and are never published as actual authorization evidence.
The two Pair-specific HTTP responses write exactly the complete `json.Marshal`
bytes measured by Store, with no extra Encoder newline. Thus the 320 KiB bound
also holds for the actual HTTP body consumed by Node. Legacy Group responses
retain their existing JSON Encoder behavior.
A peer-key fitting by itself is insufficient. Overflow rolls the second consent
back to zero effective peer grants. Message admission repeats the complete check
with the actual route; claim and final authorization encode the exact actual
attempt/route before their writer commits. Overflow rolls back, without partial
message/attempt publication, truncation, or a spurious terminal delivery failure.

The two existing typed carriers, `SameGroupSealedV1PeerKey` and
`SameGroupSealedV1DeliveryAuthorization`, carry separate optional top-level
`native_pair_evidence` and `native_pair_current` fields. Legacy Groups omit both;
a persisted pair-policy-required Group must have both. Evidence appears once.
`NativePairPeerCurrent` is bounded to 4 KiB and has exactly `state=CURRENT`,
`control_revision`, `observed_at`, `sender`, and `receiver`. Each
`NativePairCurrentSlot` has exactly `slot`, `generation`, `attempt_id`,
`native_session_id`, `network_access_binding_id`, `network_access_epoch`,
`network_membership_revision`, `endpoint_network_revision`, `lease_owner`, and
`lease_ceiling`. These coordinates come from actual slot, Network and native
binding rows in the same authorization transaction; the signed Plan cannot be
copied into a purported current observation. Original native and Network access
leases must both be live and at or below the signed ceiling. The old carrier's
Sender/Receiver fields independently match the Plan's identities, candidate keys,
binding and projected membership revisions. In particular, the old peer-key
receiver native-session field remains redacted; its current SID comes from the
separate current object. `VerifyNativePairPeerAuthorization` verifies the
independently pinned Owner evidence and the directional current coordinates;
callers also retain the old carrier checks and final exact-attempt delivery Guard.
CURRENT describes the observation time and does not replace that final Guard.
JSON expansion counts toward the complete 320 KiB limit; a larger carrier fails
closed without increasing legacy bounds or omitting evidence.
Before enabling pair permissions, the authorization writer must preflight the
exact complete peer-key/delivery carrier encoding before committing effects or
admission. An oversized encoding rejects and rolls back, without truncation or
partial publication. The preparation checkpoint adds the shared DTOs, validators
and actual-carrier measurements; production peer activation/preflight remains
unavailable with public capabilities false.

The existing Group heartbeat is also the same-identity pair lease renewal path.
Its writer transaction rechecks the current pair/slot, original Node tuple,
native binding and Network access binding, and extends both still-live leases
together without changing their IDs, epochs, credentials or lease owner. Both
remain bounded by the Owner's absolute peer ceiling. It never calls
`network_renew`, whose directory credential rotation changes its epoch. After
both slots were accepted before `JoinUntil` and entered `WAITING_CONSENT` or
`ACTIVE`, their existing sessions may heartbeat past that Join deadline. An
incomplete `WAITING_JOIN` pair loses self/heartbeat authority at `JoinUntil`, even
if both of its original lease deadlines are still later. Historical Join receipt recovery never renews or
resurrects an expired lease, reoccupies a slot or creates a replacement key.

The existing native writer ledger, inbox/outbox, provider admission and queue
uncertainty rules remain authoritative. `codex queue --thread SID` acceptance is
`CONSUMPTION_UNCONFIRMED`, not model consumption. Automatic loaded/cold wake and
user-controlled continuation are separate acceptance lanes. A controlled resume
may target only the original SID and must be reported explicitly; it must not
copy the peer body/answer, change the SID or impersonate unattended wake.

Revocation/expiry before a final current delivery Guard blocks injection. Work
already begun/consumed cannot be undone by a revoke receipt. No global instant
revocation or Runtime cancellation is promised. Uncertain queue/process outcomes
remain uncertain and are not blindly re-injected after retry/restart.

## Exact recovery, bounds and compatibility

Before every App or Node mutation POST, preserve the original ciphertext and
exact request/route/digest in the existing private durable outbox. Response
verification precedes durable application. A timeout, unsigned HTTP error,
truncation, corrupt signature or crash never permits a replacement operation.

Bootstrap creation, slot Join, consent recording/activation and revoke commit
their effects, nonce/slot consumption, CAS and exact sealed receipt together.
Same ID/packet recovers that receipt; same ID with different bytes, reused nonce,
other SID/slot or another plan is rejected. Reconcile names the full original;
an authenticated ABSENT is insufficient. A permanent rejection fence must precede
replacement of an unadmitted mutation. Historical receipt recovery never supplies
current permission. Revoked Node callers cannot obtain fresh Join credentials;
their unconfirmed originals remain retained and App pair diagnostics can report
the durable slot outcome.

Recovery authentication is independent of fresh admission:

| Surface | Required authentication after expiry/revoke | Effect |
| --- | --- | --- |
| App exact original retry / `reconcile` | Original registered device PQ identity, exact original packet/digest and retained account/Owner/device provenance; no live login, Root or Node permission required | Return original sealed receipt or permanent rejection fence only; never execute an expired old proof |
| App `status` diagnostic | Retained authenticated device and pair provenance | Bounded historical metadata; `administrative_permission=false` without current authority |
| Node exact retry / `node.native_pair.reconcile` | Retained original Node public identity and exact original route/digest, even if current binding is revoked | Recover receipt/fence only; no fresh Join/session credential |
| Fresh prepare/consent/reject/revoke | Current session, Root, device/epochs, exact Node tuple and fresh purpose-specific Owner proof | Current guarded mutation only |

If bootstrap.prepare loses its response, App does not yet know the assigned
PairID. Only reconciliation of that exact original may omit PairID. Completed
history returns the original challenge and its actual assigned ID; an unadmitted
prepare ends only with an authenticated durable `NativePairBootstrapFence`
(`REJECTED_FENCED`, `no_effect=true`, no scope/IDs/admin/budget/domain effect).
Bare `ABSENT` never settles a mutation. All other originals require exact PairID.
The nested receipt must be opened against the original route and its pair ID
checked against the outer diagnostic result before closing pending.

For a known-pair mutation whose target row is unavailable,
`NativePairRejectionFence` binds the verified original operation/request ID,
packet digest and mandatory Owner-proof PairID. Its only outcome is
`REJECTED_FENCED`, `no_effect=true`; it carries no fabricated domain state,
authority or budget. `ValidateNativePairRejectionTarget(fence, originalDTO,
originalPacket)` verifies that exact target after the nested Hub receipt is
opened. Only bootstrap-complete, consent-prepare/complete, slot-reject and revoke
can use it. Unknown-ID bootstrap-prepare retains its distinct BootstrapFence.
The permanent fence must commit before returning; ABSENT cannot close pending.

An aged/lost reconcile query may receive a new diagnostic ID/nonce/time with the
same exact business original bytes/route/digest/PairID. App durably replaces only
its current diagnostic query and rejects late replies for older query IDs.
It does not replace/re-sign the business original or execute a new business
intent. The read cache remains five minutes; fresh diagnostics are bounded to
128/minute, without an implicit retry loop.

Node reconcile is detached diagnostic authentication and must not consume the
blocked business sequence. Recovery cannot require a replacement login while
pending blocks that login. Receipt recovery never refreshes proofs, deadlines,
counters or peer permissions. Old unadmitted consent is fenced, never executed
once its authority or deadline has expired.

Status/manifest observations use bounded read-cache semantics: exact retries are
historical; new data requires a new read ID. An unadmitted/evicted/aged pure read
can close as target-bound `READ_EXPIRED`, never as a mutation settlement. Late
responses cannot update a closed request or another pair/scope.

Proposed limits: at most one unpublished consent plan per pair, one outstanding
App operation per existing vault conversation, one outstanding Node operation per
existing Node channel; 128 KiB original request, 256 KiB response/receipt,
32 KiB new proof, 16 KiB each existing Group key proof, 128 KiB Plan and 256 KiB
PeerEvidence. Ordinary pair typed plaintext stays 192 KiB, inner 384 KiB.
Only `owner.native_pair.reconcile` uses typed plaintext 352 KiB and inner/outer
640 KiB, through explicit operation-specific crypto/decode entries. No other
operation can use these entries. The default `DecodePacket` remains 384 KiB;
ordinary new requests are 128 KiB and responses 256 KiB, checked by direction. Consent requests carry
one slot; activation references retained proofs instead of wrapping both original
packets. No old packet limit or global parser default changes. Read caches are
five minutes/max 128 entries per device; diagnostic reconcile admission is
128 new requests/minute. Primary receipt/fence/nonce/provenance rows are retained.
Restore inventories/floors cover these rows; restored or changed epochs cannot
revive a consumed slot, rejected generation, stale plan or terminal pair.
No status/read consumes a Client business sequence or peer execution budget.

Network invitation/session credentials and raw proof payloads never appear in
public logs, MCP output, evidence or capabilities. Public discovery/schema checks
must precede secret use. Old servers/modes return unavailable; upgraded clients
must not silently fall back to broad Client rights or direct transport.

## Frozen A1 call sequence and size correction

Public discovery fixes `serve_mode="--hub-nodes-only"`,
`peer_transport="SEALED_RELAY"`, and the existing HTTPS application-PQ policy
(or explicit loopback-test policy). `DecodeNativePairCapabilities` requires
canonical JSON up to 8 KiB, available=true, exact format/revision/fixed budget,
and closed ordered HTTP/Node lists from `NativePairHTTPOperations` and
`NativePairNodeOperations`. Unavailable preparation metadata cannot authorize
an App request or create pending state.

App keeps the original typed DTO and sealed packet together in its existing
private outbox. After `OpenClientResponse`, it must call
`ValidateNativePairBootstrapTarget(originalDTO, originalPacket, challenge, hub, now)`
before displaying/signing bootstrap completion. This verifies full original
known Actor/Node equality, completed server tuple/digest, original packet digest,
exact label/policy, server IDs and 5/10/60 minute
bounds. Generate a new completion request ID and nonce; never sign the prepare
request ID as completion. `ValidateNativePairBootstrapChallenge` is the
standalone structural/pinned-Hub check; it does not replace this local target
comparison or human approval.

For final review, call
`ValidateNativePairPlanTarget(originalDTO, originalPacket, challenge, retainedBootstrapProof, hub, now)`.
It validates the complete Plan and both attestations/projected manifests, exact
signed local pair/revision/Node/slot digests and original chosen Network/Group/
peer deadline. Only then obtain explicit per-slot approval and sign the selected
`OwnerNativePairClaims` with `e2ee.SignOwnerNativePair`, plus the existing
`SignOwnerLinkKeyGrant` for that slot's projected manifest. Each signed consent
must pass `ValidateNativePairConsentTarget`. Signatures and these helpers do not
establish current Store authority; production guards recheck it atomically.

Generic account `SealClientRequest`, `OpenRequestAt`, `SealResponse` and
`OpenClientResponse` dispatch only the exact new operation allowlist. The large
`DecodeNativePairPacket` rejects all old/unknown operations and enforces request/
response direction limits. Four fixed `clientwire.*NativePairReconcile*` entries
require the exact trusted reconcile route; generic WithLimits ceilings stay
unchanged. Call `ValidateNativePairCarrierSize` on the entire peer authorization
response before sealing; evidence verification is a separate required check.

The earlier 192 KiB evidence and 128 KiB receipt proposal failed real PQ
measurement and is superseded by the limits above. A maximal accepted fixture
uses 128-byte selectors/labels, 512-byte escaped origin, escaped Node label,
maximum positive revisions, sixteen slot generations, nanosecond timestamps,
full ML-KEM-768/ML-DSA-65 identities, three real Owner signatures, two real Group
grant signatures and all candidate attestations. Measured bytes: bootstrap proof
30237, each slot proof 29320, each Group proof 5021, Plan 99182, evidence 231263,
carrier with actual base64 encoding of 32 KiB metadata 275003, encrypted Plan
response 193401. Maximum 256 KiB nested receipt produces a 638714-byte encrypted
reconcile packet, below its 655360-byte limit. Initial failed design probes stay
failed evidence; they are not counted as acceptance passes.

The carrier measurement uses a synthetic metadata wrapper. A2 must measure the
actual `SameGroupSealedV1PeerKey` and delivery-authorization DTOs with complete
evidence before accepting the production carrier bound. A1 does not establish
service availability. The historical A1 helper gaps are documented in
[the A1 validation record](hub-native-pair-a1-validation.md). The following A2
wire correction closes those gaps before server availability is implemented.

Only `NATIVE_PAIR_BOOTSTRAP_PREVIEW` requires `NodeControlBindingVersion=0`,
`CredentialCommitment=""`, `NodeTupleDigest=""`. All three must be empty together;
full or mixed partial server fields are rejected for that purpose. The original
complete Actor and N3 Node binding still remain signed and validated. The
purpose-specific `ValidateNativePairBootstrapPreviewScope` accepts only this
shape; there is no caller-selected allow-partial flag. Commit, consent preview,
slot consent, reject, revoke and peer evidence always require complete scope.

Prepare derives the three fields after current Store Guard. App authenticates
the pinned Hub response, checks the original complete Actor/Node field equality,
then recomputes NodeTupleDigest over the supplied full tuple before Owner reviews
and signs commit. App cannot derive CredentialCommitment without the raw Node
credential and must not guess it. Before describe/Join policy acceptance, Node
independently checks the signed full tuple against its actual local credential
and control binding.

Plan target and peer evidence share full stable bootstrap/Plan scope equality;
only Actor account-session ID and expiry may differ for a new explicit login.
Origin, account, Owner/App public keys, epochs and both Node/control key tuples
cannot drift under that exception.

Revoke uses `NativePairRevokeTargetDigest(scope, pairID, expectedRevision)` with
`cicada/native-pair/revoke-target/v1` plus NUL. Canonical JSON field order is
`scope`, `pair_id`, `expected_revision`. Dynamic budget, observation and heartbeat
fields are absent. `ValidateNativePairRevokeTarget` and request transport reject
an arbitrary target digest, even with an otherwise valid Owner signature. A new
login uses its fresh complete scope, request ID, nonce and explicit Owner proof;
it cannot execute old consent or borrow its target. These helpers do not replace
current Store authorization.

## Reuse and file ownership

| Responsibility | Existing implementation to reuse; necessary bounded extraction |
| --- | --- |
| Hub public contract/wire/auth | This document; `internal/hubaccountwire`, `internal/hubauth`, retained N2 actor/history and N3 exact receipt/fence patterns; new purposes cannot expand old profiles |
| Hub domain transaction | `Store.CreateNetwork`, `IssueNetworkInvitation`, `AcceptNetworkJoin`; `CreateClientTopologyGroupAtomic`; `PreviewClientTopologyEndpointAdmissionForClientRequest` / `AdmitClientTopologyEndpointForClientRequest` zero-grant semantics; `UpdateClientTopologyMembershipAuthorizationForClientRequest`; extract shared Tx builders behind a new exact Owner-pair actor, never synthesize a legacy accepted Client row |
| Hub candidate/Owner consent | `GetNativeSelfForActor`, `RegisterEndpointKeyCandidateForActor`; `PreviewGroupEndpointKeyGrant`, `AcceptGroupEndpointKeyGrant`, `VerifyCurrentGroupEndpointKeyGrant`; `Identity.SignOwnerLinkKeyGrant` / `VerifyOwnerLinkKeyGrant` keep their frozen Group proof use |
| Hub composition/data plane | `internal/hubnodes`, `internal/server/hub_nodes.go`; reuse Fabric same-Group sealed methods and current Node/native/Network Guards without `Control.New/Start`, planner or Manager API |
| Node | `cmd/cicada/local_join_bridge.go`, `local_network_join_bridge.go`, `local_join_keys.go`, `cross_node_group_bridge.go`, `machine_fabric.go`, existing Node PQ outbox and native writer/inbox; add only reserved-slot Join plumbing and exact route discovery |
| App | App writer owns typed bootstrap/slot review/consent/revoke and original vault signing, durable pending/reconcile and minimal UI in `internal/appcore`, `appvault`, `appui`; no secret export or peer-body forwarding |
| QA | Independent `acceptance/n3` / actual Runtime gate and scoped validation; current native plan/acceptance ownership stays with QA; no producer-only PASS promotion |
| Root | Contract review, Git windows/integration and later explicit user-approved artifact/deployment changes |

The raw operator CLI `network ... --db` and disposable Store fixture shortcuts
are not the production Owner authorization path. `clientoperator` currently has
profile/session/node helpers, not a ready Group authorization SDK. Only its exact
packet/pin/persistence techniques are reusable without new authority.

## Minimum executable acceptance

1. Disposable synthetic Owner/App vault and one logical Node run the production
   Hub composition and signed typed setup routes. No direct DB grant injection.
   Demonstrate zero-permission Join/self publication while peer resolve/ASK/Reply
   remain denied; first consent also leaves both peers denied.
2. Second consent activates both exact slots atomically. Test wrong Owner/App,
   Node/binding/credential/key/epoch/SID/slot/Group/Network, stale projected
   membership/candidate and competing consent/revoke. Rejected cases leave no
   partial peer rights, receipts or consumed new-plan budget.
3. Drop before admission/after commit, kill/reopen Hub/App/Node, retry identical
   packets, deliver old originals late, and reconcile. Assert stable identities,
   one slot/consent/activation effect, preserved nonces/counters and no replay of
   uncertain queue work. App logout/lease expiry does not revoke already ACTIVE
   peer authority; the signed peer deadline and actual peer Guards do.
4. Real Runtime acceptance belongs to the user: on the same gpu1 Node the user
   selects two owned real Threads, retains their original SIDs and distinct
   private context, explicitly Joins both and approves their actual candidates
   through the original App vault. The user initiates A's MCP ASK and B's MCP
   Reply and confirms that original A receives the B-only answer with its own
   context intact. Root/QA/scripts do not create/seed SIDs, start model turns,
   arm delivery or call a real native queue for this acceptance. They may supply
   reviewed builds, exact supported steps and read-only diagnostics. They never
   transfer the peer body/answer. Synthetic isolated fixtures remain a separate
   lane and cannot stand in for this user-operated conversation.
5. Record queue acceptance, actual consumption, loaded/unattended wake, user
   continuation of the same SID, revoke-before-delivery and reopen continuity separately.
   Missing consumption is not a conversation PASS. Hub storage/HTTP traces must
   exclude private peer plaintext; actual cost/provider use is bounded and
   attributed to that test's stated execution plan.

This contract-only checkpoint runs no models. The authorized isolated verification
does not authorize updating the resident Hub, installing Node code or copying
credentials. The user path needs the
reviewed Hub/Node composition plus App vault consent support before a separately
approved rollout; the currently deployed status-only composition cannot be made
to work merely by updating the App.
