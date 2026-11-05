# Thread Network, classification and Group protocol locks

Status: **REVIEWED_CONTRACT / LIVE_PROFILE_GATED**, 2026-11-05.
The shared checkpoint is `a00b639`; the gated Store/Owner HTTP/Node RPC producer
checkpoint is recorded in [implementation evidence](#gated-backend-checkpoint).
Proposed additive revision: `thread-network-group-locks-v1`. Compilable shared DTOs, pure codecs and client interfaces are in
[`thread_collaboration_types.go`](../cicada-go/internal/hubaccountwire/thread_collaboration_types.go)
and [`thread_collaboration.go`](../cicada-go/internal/hubaccountwire/thread_collaboration.go). These install no handler, Store mutation or live profile. This draft defines
the confirmed user rules and reviewable interfaces. It is not an availability,
runtime acceptance or compatibility claim. Existing wire versions, public
identifiers and historical validation remain attributed to their original source.

## Authority and confirmed rules

One real native Thread belongs to at most one `(HubID, NetworkID)` authority.
Hub, Node, server installation, App and Principal may cover several Networks
through different Threads. A Network still has one authoritative Hub. Changing
the selected App connection, alias, Endpoint ID, local connection epoch, native
binding or key does not select another Network for an existing Thread.

Owner classifies each stable registered Thread within that Network as exactly
one of `worker`, `advisor`, `manager`. A worker has at most one active
Endpoint–Group relation, counting all effective sources. Advisor and manager
have no product rule limiting their Group count; normal finite storage/safety
bounds still apply. A second contribution to the same effective relation is
not a second Group. This classification is per registered native Thread, not
per Principal: two Threads sharing a Principal do not share one Group quota.
Mixed tags cannot exempt a worker. The user's “control” label is the manager
classification; Hub Control remains a service, not a new privileged user role.

Classification changes no Group membership, key grant, business capability or
Owner authority. A manager classification is not an authorization grant.
Advisor/manager → worker with several effective Groups refuses until Owner
explicitly removes the excess original relations. There is no automatic eviction.

Each Group has exactly eight general protocol slots numbered **1–8**. Members
decide their meaning. Slots have no ResourceID, GPU, Workspace, Task, execution,
queue, scheduling or purpose binding. They coordinate protocol participants;
they do not stop a process or provide filesystem/runtime isolation.

## Reused authority and limits

The Node reuses `nodeinbox.NativeContextRegistry` under the existing shared
WriterRoot. It does not open a Hub-private copy or introduce a parallel Thread
Network database/service. The existing identity digest is derived from harness
and native session ID; account digest is separate retained metadata. Preserve
those existing keys and history. A new account field or path must not create
an empty alternate history for the same Thread. The current `uid:N` writer scope
is conservative local serialization, not proof of a Codex account.

Real Thread coordinates come from the existing verified Host/native-session
record and current Node context, not a caller's title, alias, arbitrary native ID
or self-declared workspace. Local digests remain private; no new global Thread
identifier is exposed to other Hubs. Coverage remains `CICADA_KNOWN_ONLY`: this
does not claim to detect unobserved external Runtime activity or malicious
privileged processes bypassing the supported Node.

Hub role/slot mutations reuse current authenticated Node/App carriers, exact
Owner purposes, transactional Store writers, replay/original-operation journals
and server Guard. They do not call Control inference. The task-bound physical
`ResourceLease` API and its executor/stop semantics are not this protocol.
The protocol must work in `serve --hub-nodes-only` with Control/inference off;
it cannot require `control.AcquireResourceLease`, a Control management bearer
or a second daemon. Existing Node work/recovery loops perform bounded protocol
maintenance without creating business work or a scheduling service.

## Thread Network admission before external effects

The following are proposed methods on the existing common registry/service
boundary, not implemented functions or additional public user commands:

```go
InspectThreadScope(ctx, verifiedNativeSource) (ThreadScopeView, error)
ReserveThreadNetwork(ctx, verifiedNativeSource, requestedScope, original) (ThreadNetworkReservation, error)
SettleThreadNetwork(ctx, reservation, authenticatedOriginalResult) (ThreadScopeView, error)
CheckThreadScope(ctx, verifiedNativeSource, currentScope) error
```

`verifiedNativeSource` is built by the original Host/Node verifier. `requestedScope`
is the pinned Hub identity and explicit Network ID. `original` contains the
original operation ID, digest, expected registry revision and private packet
reference; it is not a newly generated identity or placeholder Endpoint/binding.

| Phase | Required behavior |
|---|---|
| Inspect | Read all known history for the original identity, including other Hub contexts. Return one scope, unassigned, unresolved, or conflict; never choose the first row. |
| Reserve | Obtain the serialized SQLite writer **before** checking history. Atomically reserve the exact Network/original request before Join, registration or any Network-linked external mutation. Competing Networks cannot both reserve. |
| Retry | Same operation ID/digest/scope returns the same reservation. Reusing the ID with changed bytes/scope refuses. |
| Settle accepted | Bind the authenticated result to that reservation, then record the real Endpoint/native binding metadata in the same existing history domain. No fabricated BindingID is used before admission. |
| Settle no effect | Only an authenticated exact original result proving no external admission can retire an uncommitted reservation. Retain its history/receipt. |
| Timeout/crash/unknown | Keep the reservation unresolved. Reopen/resume its original request; no competing Network may proceed because a response was lost. |
| Consume/deliver | Recheck the current Network reservation/history, native binding, classification/Group cardinality and existing final native admission fence. A successful earlier lookup is not later authority. |

Zero-authority local directory reads do not enroll a Network. Any registration
which will establish or activate a Network/Group identity must use the admission
gate before its external effect. The same check applies to CLI Join, default
LocalDomain admission, manual registration, renew/recovery, restore and direct
common-call entry points; hiding a button is insufficient.

Leave stops access and revokes its precise current authority; it does not erase
native context history or make that same Thread eligible for another Network.
V1 adds no implicit cross-Network transfer. Any future explicit migration must
have a separately reviewed contract preserving original history and uncertainty.

## Common read models and Owner classification

Native CLI/MCP obtains these bounded DTOs through the verified local Node.
Windows App obtains Owner observations through its independent authorized
Owner HTTPS client below. Neither lane reads registry files, infers Hub from
a nickname or replaces live pins; Owner observations never borrow a Thread identity.

| DTO | Closed proposed fields |
|---|---|
| `ThreadScopeView` | `format, hub_id, network_id, node_id, endpoint_id, source, registration_digest, scope_revision, state, classification, classification_revision, relations_revision, active_group_ids, active_group_count, groups_cursor, history_coverage, reservation_id?, conflict?` |
| `ThreadNetworkReservation` | private `reservation_id, operation_id, request_digest, hub_id, network_id, expected_revision, revision, state` |
| `ThreadRoleChange` | `network_id, node_id, endpoint_id, source, classification, expected_classification_revision, expected_relations_revision, registration_digest`; outer original request/Owner proof bind the operation |
| `GroupCoordinationPolicy` | `format, hub_id, network_id, group_id, policy_id, revision, state, slot_count, rights, owner_consent_digest` |

Scope states are `UNASSIGNED`, `RESERVED`, `CURRENT`, `UNRESOLVED`,
`NETWORK_CONFLICT`, `CLASSIFICATION_REQUIRED`, `GROUP_CONFLICT`. Classification
is empty only when unclassified; otherwise the three lowercase values above.
Read status does not imply that the caller may perform Group business. Active
Group IDs are a bounded page, with total `active_group_count` and continuation
cursor; page size is not an Advisor/manager product quota.

The shape is closed by phase. UNASSIGNED has no Network/Endpoint/source and no
reservation or classification. RESERVED/UNRESOLVED carries the real target
Hub/Network, original `reservation_id` and scope revision, with **no** Endpoint,
registration source, classification or Group rows; pre-registration never invents
those IDs. CURRENT and registered classification/Group-conflict observations
require their real immutable registration source. NETWORK_CONFLICT carries
**no selected Hub/Network/Endpoint**, only `conflict{kind,known_network_count}`;
kind is `MULTIPLE_NETWORKS` or `UNRESOLVED_HISTORY`. The outer Owner query scope
is not a winning historical scope. Both codecs and consumers preserve this
phase distinction.

Owner role change follows the existing finite prepare/review/apply/status/
reconcile model, with a new purpose binding the exact Thread registration,
Network, target classification and both expected revisions. It requires current
Owner/device authority and the original Node binding; login, old signatures,
Node visibility and classification names cannot substitute for that proof.
Exact original result recovery precedes creating another change request.

The mutation transaction must recompute the original request digest from the authenticated caller/source and the complete typed body, operation ID and idempotency key. The JSON digest is only an assertion to compare; it is not authority. Changed ID, key, note, scope, CAS or source cannot reuse an old digest.

Server transaction checks must cover every activation source: Owner Add/Apply,
default/manual source materialization, self Join/restore, role changes,
membership authorization changes/restoration and lease/recovery projections.
Count the effective Endpoint–Group relation set for this stable registration,
not `memberships.role` alone, its first `roles[]` element or all rows belonging
to the Principal. Current Actor Guard rechecks the constraint at use time.
Source contribution overlap must not reset the count; a fresh Endpoint/key for
the same original Thread must not reset its Network/classification history.

## Group slot API

### Closed profile, HTTP and RPC inventory

The public availability route is GET `/v2/thread-collaboration/capabilities`,
format `cicada.thread-collaboration-capabilities.v1`. Profiles are
`THREAD_SCOPE_ROLE_V1` and `GROUP_LOCKS_V1`, with independent
`thread_scope_role_available` / `group_locks_available` flags. The confirmed
`disconnect_policy=FINITE_LEASE` advertises default/min/max TTL seconds 300/1/3600.
Factories remain unavailable until the complete configured service activates them.
Availability authorizes no caller; missing/unsupported profiles have no legacy
ResourceLease or guessed Group fallback.

| Owner HTTP POST | Encrypted Owner operation |
|---|---|
| `/v2/owner/thread-collaboration/read` | `owner.thread_collaboration.read` |
| `/v2/owner/thread-collaboration/prepare` | `owner.thread_collaboration.prepare` |
| `/v2/owner/thread-collaboration/apply` | `owner.thread_collaboration.apply` |
| `/v2/owner/thread-collaboration/status` | `owner.thread_collaboration.status` |
| `/v2/owner/thread-collaboration/reconcile` | `owner.thread_collaboration.reconcile` |

The Owner request format is `cicada.owner-thread-collaboration.v1`; the concrete
`ThreadCollaborationOwnerRead/Prepare/Apply/Status/ReconcileRequest` aliases carry
existing `AppNodeRequestContext`, session token, exact Owner proof and their
closed typed bodies. The prepare tagged union allows exactly one of `role`,
`policy`, `clear`, with actions `SET_CLASSIFICATION`, `CREATE_GROUP_WITH_POLICY`,
`ENABLE_GROUP_POLICY`, `REVOKE_GROUP_POLICY`, `CLEAR_ONE_SLOT`. This is additive;
existing Owner EndpointGroups packet fields and purpose identifiers do not change.

Windows App uses the concrete `ThreadCollaborationOwnerClient` interface:
`Read`, `Prepare`, `Apply`, `Status`, `Reconcile`, each with its corresponding
request/result type. Owner `Read` views are `THREADS` (bounded list),
`THREAD_SCOPE` (one Node/Endpoint), `GROUP_LOCKS` (one Group). These are authorized
Owner/device HTTPS reads; no remote Node Host/native-session proof, borrowed
Thread credential or native writer is required. Current Owner/Network/Group
visibility is checked independently for every request. App cannot inspect a
foreign Hub's raw local registry or choose a historical Network winner.

Only a CLI/MCP child with the original verified Host/native source consumes
`ThreadCollaborationNativeClient`: `ReadScope(ctx)`, `ReadLocks(ctx, GroupLockScope)`,
`Acquire(ctx, GroupLockAcquireRequest)`, `Renew(ctx, GroupLockRenewRequest)`,
`Release(ctx, GroupLockReleaseRequest)`.
Its closed Node-Control RPC operations are `thread_scope.read`, `group_locks.read`,
`group_locks.acquire`, `group_locks.renew`, `group_locks.release` through the existing authenticated
Node-Control carrier. These request DTOs are claims, not Host proof: the bound
Node bridge supplies/authenticates the actual caller and exact Group source.
The Owner lane cannot impersonate this native caller; native callers cannot
call the Owner HTTP lane to clear another holder.

App consumes the typed Owner/common surface and current observations; it does
not decide slot ownership or reconstruct a live caller context from retained
storage metadata. The compiled interfaces are the seam; there are no generic
untyped service signatures for consumers to infer. Runtime implementations,
Node/Store enforcement and MCP presentation remain separate checkpoints. Owner
constructors and the actual existing PQC carrier are wired in this checkpoint.

| Message | Closed proposed body |
|---|---|
| Native read | `GroupLockScope{hub_id, network_id, group_id}` |
| Acquire | `scope, slot, expected_version, original{operation_id,idempotency_key,request_digest}, note, ttl_seconds?` |
| Renew | `scope, slot, expected_version, generation, original{operation_id,idempotency_key,request_digest}, ttl_seconds?` |
| Release | `scope, slot, expected_version, generation, original{operation_id,idempotency_key,request_digest}` |
| Owner clear | `scope, slot, expected_version, generation, expected_holder`; outer exact Owner review/digest/CAS/proof, no replacement holder |
| Slot | `slot, state, version, generation, holder{node_id,endpoint_id,principal_id,source}, holder_name?, holder_name_state?, note?, expires_at?` |
| Group view | `format, scope, observed_at, policy_revision, policy_state, slots` (exactly eight ordered slots after explicit initialization) |
| Mutation receipt | `format, scope, operation_id, request_digest, slot, applied_version, generation, outcome, observed_at, expires_at?` |

`slot` is an integer 1–8. Versions are integers `1 <= version < 2^63`; generation
starts at zero, is below 2^63 and increments on successful acquisition, never resets/wraps.
Only `FREE`/`HELD` are normal slot states. Initial slots are FREE/version1/
generation0 with no holder/note. `note` is optional, at most 1024 UTF-8 bytes,
and is Group-visible lock metadata; the server neither interprets nor executes
it. It is not a Task/resource key or a secret peer-message transport. Holder
identity comes from current authenticated scope, never request JSON. No native
session ID, workspace, account digest, bearer or private key is in the slot DTO.

`ThreadRegistrationSource{registration_id,source_epoch}` is an opaque Hub/Network
scoped immutable source, not a native ID or a native lease epoch. It survives
normal original Thread cold recovery and credential/native-binding renewal.
A different real Thread taking the same Endpoint/Principal must obtain a new
registration source ID or source epoch. The Hub verifies this from the existing
Node/Host registration chain; caller-supplied source fields cannot establish it.
Normal Release and exact original recovery require the holder's same source in
addition to current authorization and the slot's exact version/generation.
Another Thread reusing an Endpoint cannot borrow an old hold or old receipt.

Read/list may perform only idempotent expiry normalization of existing expired
leases. It cannot create a row, acquire, renew, change policy/role, reserve a
Network or write last-seen state. A normalized expiry preserves generation,
increments version exactly once and retains original receipts. Existing transport replay
accounting remains separate. Exactly eight rows are created in the explicit
Group+policy/first-enable transaction, never by viewing a Group. Re-enable cannot
reset existing versions/generations. Absent policy returns absent policy/slots
in the Owner view (or `GROUP_LOCK_POLICY_REQUIRED` for native use), not fabricated
FREE rows. `observed_at` and `policy_revision` describe an observation; an old
FREE snapshot never proves acquisition or current ownership.


All operations require exact `(HubID, NetworkID, GroupID)` and current native
Host/Endpoint/Group source. A **single Owner-approved Group coordination policy**
authorizes `group_locks.read/acquire/renew/release` for that Group's currently effective
members. The policy has `slot_count=8`, those four exact rights, and state
`ENABLED`, `DISABLED` or `REVOKED`. This additive profile is separate from the
old five communication rights: neither an old membership grant/proof nor role
classification silently grants lock actions. Membership/source revisions and
this policy are checked on every use; membership alone remains insufficient.

New Group creation may include this policy in **one explicit original Owner
confirmation**, binding the prepared Group identity and policy body in a new
purpose. An existing Group needs one explicit policy enable, not a new Owner
review for each slot or each member action. The original create/enable result
is recoverable without re-approving or spending the consent twice. App access
credentials authorize that configuration call; their later expiry is not the
expiry of the already approved policy.

Role classification, Group policy, slot ownership, versions and original
receipts are persistent Hub state. App exit/uninstall/logout, its account/session
or 15-minute status-access expiry, UI polling loss and Control shutdown do not
remove that state or invalidate Node collaboration. Node callers still need
their own current authorization; this does not revive a revoked Owner root,
Group, policy, member, Node binding or native endpoint. Explicit current
revocation denies later use without pretending the old slot was released.
Public capabilities describe support/availability only. Owner clear separately
checks current Owner authority for the Group and confirmed slot snapshot.

## Atomic state and original operations

Acquire obtains the Hub Store writer transaction, then checks current Group
authorization, Thread scope/classification, slot version and FREE state. It
sets the authenticated holder, note, generation+1 and version+1 atomically.
There is no implicit “any free slot”, wait ticket, FIFO, scheduler or business
automation. Busy is an immediate bounded result; the Group decides what to do.

Normal Release requires the exact authenticated holder Endpoint/Principal,
current authorization, generation and expected version. It clears holder/note,
preserves generation and increments version. Owner clear uses the same CAS but
only its independently confirmed Owner purpose, retaining an audit receipt.
Neither operation frees another generation or transfers ownership. A new acquire
after either successful release advances generation again.

The operation ledger records original scope, authenticated actor, request digest,
CAS inputs and result in the same transaction as the slot change. Same key/bytes
after lost response or restart returns the original receipt without reapplying.
Same key with changed bytes/target conflicts. An old release/clear retry cannot
clear a successor. Receipts identify an applied historical version; they do not
claim that the slot is still FREE/HELD now. Refresh the view for current state.
Every replay still checks current caller/Owner authorization.

Reuse bounded original packet/outbox recovery. No unresolved original or live
holder record is silently evicted; exhaustion refuses new operations before
mutation. Restart does not clear slots, reset versions, mint replacement requests
or discard uncertain packets. The reviewed bounded recovery rule below governs receipt maintenance; it never
resets slot versions/generations or makes an expired original executable.

Error classes are `UNSUPPORTED_PROFILE`, `AUTHORIZATION_REQUIRED`,
`THREAD_NETWORK_CONFLICT`, `THREAD_NETWORK_UNRESOLVED`,
`THREAD_CLASSIFICATION_REQUIRED`, `WORKER_GROUP_LIMIT`, `GROUP_LOCK_POLICY_REQUIRED`, `SLOT_INVALID`,
`SLOT_BUSY`, `VERSION_CONFLICT`, `HOLDER_MISMATCH`, `GENERATION_STALE`,
`ORIGINAL_REQUEST_CONFLICT`, `ORIGINAL_OUTCOME_UNCERTAIN`, `STATE_AT_LIMIT`.
Authorization failures reveal no other Group's holders or private registry paths.
All new objects reject unknown/duplicate fields, invalid bounds and scope
substitution before mutation. Existing encrypted-carrier size/proof limits apply;
the current closed shape/digest tests are codec evidence only, not carrier/Guard acceptance. Node bodies are at most 8 KiB, notes 1024 UTF-8 bytes, slot views 32 KiB; Owner pages have at most 64 rows / 128 KiB. Owner body/packet budgets reuse 192/384 KiB, original packet 256 KiB and reconcile 640/896 KiB. Existing Node-Control plaintext/encrypted-packet limits are unchanged; there is no arbitrary payload or resource/Task ID extension.

## Retained-state migration and finite lease policy

Existing identities, registrations, context history, keys and original packets
stay in place. Preflight enumerates every known scope/source for the real Thread.
One known Network can be retained; different Networks or unresolved legacy
scope yield a visible conflict, not a chosen first row. Historical multi-Network
Threads retain every row and are fenced. Owner may stop/revoke their access,
but cannot select a winner, relabel/delete history or approve a migration which
pretends that old cross-Network context never existed. V1 provides no historical
washing override. Unknown historical Network IDs may be resolved only from exact
original authoritative evidence; Owner classification alone cannot invent them.
A new real Thread is distinct; changing an Endpoint for the old Thread is not.
Absence is not a fresh start.

An old anonymous `member` registration is `CLASSIFICATION_REQUIRED`, not
silently worker or unlimited advisor. Owner explicitly classifies it against
the complete current relation snapshot. Multi-Group → worker refuses until
Owner precisely resolves excess sources; it does not delete data or reset IDs.
Conflicted/unclassified records cannot create/restore additional participation
or gain new lock business. Only bounded inspection, independently authorized
cleanup and original-operation reconciliation remain available while resolution
is required; retained remote ACL rows are not proof that a new native action is
admitted. The exact migration gate is part of Root review before activation.

**Confirmed finite lease.** Acquire and explicit AI Renew accept optional
`ttl_seconds`: omitted means 300; explicit integer 1..3600 is required otherwise.
Explicit 0, negative, fractional, string, overflow and null are rejected. Expiry
is the original server `observed_at + ttl`, including Renew; it never adds to
an old expiry or shifts on exact retry. Only AI explicitly requests Renew; the
Node daemon never renews in the background. AI should explicitly Release when
finished. Cicada records coordination, does not decide actual usage, force a
resource/process or provide a queue. Members contact the visible holder to
negotiate; a hidden name is `NOT_DISCLOSED`, never an invented ID-as-name.

At `expires_at <= server_now`, bounded normalization clears holder/name/note/
expiry, preserves generation, advances version once, keeps original receipts
and allows a new holder to atomically acquire. Expired Renew is rejected; old
release/renew/generation cannot affect a live successor. Normalization runs in
the same Store writer transaction as a read/write, and never fabricates FREE
rows from absence. App offline or its 15-minute status access expiry does not
revoke a still-live lease (a 3600-second lease can outlive 900 seconds). Explicit
current authority revocations still deny use. Persistent classification/policy
are independent of lease expiration.

This is a contract-only checkpoint from base `381842d848fd52b9cee005406ca1342215fa17ce`.
Shared Go DTOs, closed inventories, pure canonical codecs/digest helpers and typed client interfaces are provided. No live handler, Store state machine, Node admission enforcement, App consumer, database migration, daemon or real Runtime/deployment is implemented by this draft. Codec tests do not count as actual admission or ownership enforcement. Required
later evidence includes cross-process/cross-Hub pre-reservation races, every
role activation source, stale/foreign holder/Owner CAS, exact retry after lost
responses/restart, retained legacy conflicts, actual `--hub-nodes-only` operation
with Control absent, App exit/status-access expiry with persistent policy/slot/
classification still intact, explicit current revocation denial and separate
actual interoperability.

## Earlier pre-TTL contract/codec qualification (historical)

The earlier pre-TTL draft added only the three shared `hubaccountwire/thread_collaboration*`
Go contract files and these two documents. Original unpublished draft
`ff0e9185124ec2ff6e9a439029550226e85a2516` remains mapped in the private receipt;
no published history or earlier validation is rewritten. The codec input is base
`381842d848fd52b9cee005406ca1342215fa17ce` plus those exact dirty Go files,
not an implementation claim for either clean historical HEAD.

With the existing Go 1.27.3 image and offline cached modules, the selector
`go test ./internal/hubaccountwire -run '^TestThreadCollaborationContract' -count=1 -timeout=2m -json`
passed 6 top-level / 14 leaf tests (16 passing events), zero FAIL/SKIP, exit 0,
14.100 seconds including compile. The same selector with `-race` passed the
same counts, exit 0, 24.981 seconds. `go vet ./internal/hubaccountwire` passed,
exit 0, 1.776 seconds. Coverage is pure shape/inventory/digest validation:
independent Owner reads, closed action/profile lanes, phase-specific pre-admission
and conflict shapes, worker/current versus paged Advisor views, eight ordered
slot observations, original stable holder source, stale generation refusal,
server digest recomputation, duplicate/unknown/oversized JSON refusal. The tests
do not establish cryptographic caller authorization or perform Store mutations.

Raw output, commands, tested source hashes and the final old→new draft mapping
are under
`/home/zyf/Cicada/.local/evidence/v01-thread-network-locks-contract-20261105-02/`.
Store/Node enforcement, Owner HTTP/native RPC carriers, App integration, Docker,
real Runtime/device/public/resident acceptance remain **NOT_RUN**. No second
daemon, physical resource protocol or business scheduler was introduced.

## Final shared consumer checkpoint

The final TTL contract extends the typed inventory with Renew, finite lease bounds,
server observation/expiry and scoped holder display fields. `ThreadScopeView` also
exposes the retained `registration_digest` for explicit Owner role CAS. Owner
`GROUP_LOCKS` read includes `group{group_id,network_id,name,group_version}` even
when policy/slots are absent, so enabling a policy never guesses a version.

Owner consumers use `NewThreadCollaborationOwnerRead`, `Prepare`, `Apply`,
`Status`, `Reconcile` (each prefixed `NewThreadCollaborationOwner`), then the
existing `SealClientRequest`. Open through `OpenThreadCollaborationOwnerResponse`
and correlate with `VerifyThreadCollaborationOwnerResult`; approval additionally
uses `ValidateThreadCollaborationOwnerReview`. Apply effects are checked against
the retained approved review using `VerifyThreadCollaborationOwnerOperation`;
new-Group review freezes `target_group_id` before approval. The result envelope binds format,
contract revision, Hub/Owner/device, request ID/digest, observation, original
operation ID/digest and a closed state/payload. `ORIGINAL_RECEIPT` carries the
exact retained encrypted original response, to be opened against that original
request; uncertainty never becomes success. These new exact Owner purposes reuse
`OwnerAppNodeScope` and the existing ML-DSA/ML-KEM service. Legacy purposes and
packet ceilings are unchanged. Only the independent new reconcile operation
admits the named 640/896 KiB recovery budget.

`ThreadScopeNodeRead`, `GroupLocksNodeRead/Acquire/Renew/Release` are the typed
Node-Control bodies. The original verified native CLI/MCP binding provides the
Endpoint and the server checks its current registration/source; JSON fields are
not caller authority. The private local socket bridge and business handlers are
the next implementation checkpoint. No public profile is activated by DTOs.

Final shared qualification: all three related packages (`hubaccountwire`,
`clientwire`, `e2ee`) passed normal and race tests, 194 passing top-level tests /
671 passing events per run; elapsed 19.053 / 86.627 seconds. Each run separately
skipped the pre-existing opt-in `TestExternalOwnerOpenSSLRealSignatureInterop`
because `CICADA_TEST_OWNER_OPENSSL` was not set to an independently verified
OpenSSL 3.5.9 executable. That external interop was **NOT_RUN**, not a pass.
Three-package vet passed in 1.908 seconds. The added production Node-decoder
nested-TTL test then passed normal/race, 17 passing events and zero skips each,
in 13.945 / 23.964 seconds. All production Go hashes match the full-package
qualification snapshot; only the supplemental test file was added afterward.
Evidence and exact original→amended draft mapping are in
`/home/zyf/Cicada/.local/evidence/v01-thread-network-locks-contract-20261105-03/`.
PQC codec round trips are demonstrated; Store/Guard/current authority, live
HTTP/Node handlers, Native local Host RPC, Docker, App, real Runtime/device/public
and resident acceptance are not established by this shared checkpoint.

## Bounded original recovery

Root approved a 24-hour recovery window for new lock semantic originals.
`NewGroupLockOriginal(at)` creates `operation_id` and `idempotency_key`, each
16-byte lowercase hex: the first 48 bits are the same UTC millisecond timestamp,
the remaining 80 bits are independently random. `request_digest` starts at 64
zero hex characters and is filled by `GroupLockRequestDigest` from the trusted
caller/body before the Node packet is sealed. Existing Owner request IDs and
existing protocol-family identifiers are unchanged.

The server checks both the prefix binding and creation window on every new use
and replay: future skew at most 30 seconds, age strictly less than 24 hours.
Outside that window it returns `ORIGINAL_RECEIPT_UNAVAILABLE` and executes no
lock action, even if the old ID is given a new body, CAS or authenticated carrier.
Within the window, ID/key/body changes conflict; exact retries return the original
receipt and never shift expiry. A receipt reports a historical result, never
current occupancy. Refresh the current Group view.

Bounded maintenance in the existing Store transaction reclaims expired original
receipts in batches of at most 256, retaining current successful CAS effects
until the slot version advances and retaining unknown/corrupt originals.
Rejected originals with no effects may be reclaimed after their ID window;
they cannot execute later. Node wrapper receipts/inbox rows retain their shared
sequence highwater; old sequence packets are refused after reclamation. Owner
read/status/reconcile and expired-prepare caches follow the existing five-minute
proof window (plus skew); applied or unknown Owner mutation receipts remain
retained. Capacity exhaustion refuses before mutation. This is bounded recovery,
not indefinite retention of every read or a lifetime lock-operation quota.

Hub classifications use the real harness/native-session identity scoped to the
Hub, excluding account, Endpoint, Principal, key and workspace. The original
registration revision supplies the stable source epoch. Supported paths retain
the original Endpoint; another registration for the same real Thread is refused.
Pre-existing multiple registrations are retained and reported/fenced, never
chosen as a new winning identity. Local cross-Hub history remains the separate
existing shared NativeContextRegistry responsibility.

## Gated backend checkpoint

This records implementation evidence separately from the adopted specification.
The earlier sections define the contract.
The shared contract/Owner PQC checkpoint is `a00b6391ede9d773773c268af0c277c823fe75fa`.
The backend checkpoint uses base `b6fa465e80dac2e9ff351d5c61ab5474563a58a0`
plus its exact recorded Go hashes. It is not attributed to that clean base alone.

## Gated backend scope

Schema 72 adds persistent classifications, independently approved Group policies,
eight numbered finite leases, bounded original receipts and finite Owner reviews.
No Owner/account/public key/epoch is regenerated. Existing Owner/account signing,
PQC envelopes, Node bindings, shared sequence counters and transactional Guard
services are reused. The new Hub Nodes handlers import no Control inference or
old task-bound ResourceLease service. Public capability flags remain false until
the complete admission/Guard/native-consumer checkpoint is reviewed.

Owner read/prepare/apply/status/reconcile run through the actual encrypted HTTP
lane. Read/list requires current independent Owner authority and no remote Host
ticket. Login alone supplies no Root. Explicit classification checks original
source and classification/relation revisions; worker downgrade refuses multiple
effective Groups. Policy enable creates eight rows once, never on a read.
Create+policy uses one review with a prepared Group ID. Apply consumes one finite
review, records its exact sealed response atomically and status/reconcile recover
that response. Reconcile closes an authenticated unseen original with a no-effect
fence; it never replays old business.

Node RPC checks current Node/registration, classification, exact Group source and
independently enabled policy before both first use and original recovery. Every
slot action compares scope, stable holder source, generation and version. Reads
normalize only existing expired leases. AI explicitly renews/releases; no daemon
renews. Exact retry preserves original expiry. Expiry increments version once,
preserves generation and permits a new atomic holder. Old release/renew cannot
change a successor. Holder names are read only through current same-Group source
authorization, with an explicit NOT_DISCLOSED marker otherwise.

The 24-hour time-prefixed semantic-original window permits bounded receipt
maintenance. Daily reads and lock actions do not consume an irreversible lifetime
quota. Maintenance retains unknown/current originals, reclaims expired completed
receipts under the existing writer and refuses late execution by ID time or the
shared Node sequence floor. Owner mutation receipts remain retained and bounded.

## Validation scope

The real isolated TCP fixture uses actual Owner/device/Node keys, account and
Owner enrollment, Node registration, Group membership/key completion and PQC
envelopes. The composed handler has Control absent. It exercises classification,
pre-policy Group metadata without fake FREE slots, policy enable, original Apply
response recovery, eight slots, held nickname/expiry, acquire/renew exact retry,
expiry, successor generation, stale release refusal, Owner clear, holder release
and policy-revoked old-packet refusal. Production codecs also reject nested
invalid TTLs and expired/future semantic originals.

Separate deterministic Store mechanics use synthetic rows without claiming
caller authorization: two independent SQLite writers compete for one slot, then
reopen the database, recover the exact receipt, normalize expiry once and reclaim
a 25-hour original. Reusing that expired ID with a new body/CAS is refused.

The historical v68/v69 fixture builder removes later 72/71/70 objects before
claiming an old schema. Production restore coverage remains reviewed through
schema 67; schema 72 restore is not newly authorized. A development broader
selector first exposed that stale historical fixture and failed; its corrected
focused restore checks are recorded separately, not called a first-run pass.

Final raw logs, commands, tested hashes and commit receipt are under
`/home/zyf/Cicada/.local/evidence/v01-thread-network-locks-backend-20261105-01/`,
`...-02/` and `...-03/`, with exact source hashes for each run.

## Remaining work

The local NativeContextRegistry reservation producer is assigned separately to
QA. The Node must consume it before every external Join/registration effect,
preserve timeout/unknown reservations and settle only an authenticated exact
original result. Full activation and current-use classification/count guards
across legacy/default/manual paths and the private verified native CLI/MCP
consumer are subsequent work. These are required before enabling capability
flags. The backend checkpoint does not establish cross-Hub native admission.

App integration, disposable Docker interop, real native Runtime, physical device,
public HTTPS and resident deployment validation remain NOT_RUN here. The producer
has not pushed, deployed, merged into dev or changed resident state.

### Backend qualification and retained failures

The 01 selector passed 15 top-level tests / 54 PASS events, zero skips, normal
exit 0 in 31.435 seconds. Its race run passed the 14 non-TCP top-level tests /
53 PASS events; the TCP case failed because the test's one-second initial lease
expired during real PQC processing under instrumentation. This was a correct
LEASE_EXPIRED refusal, not a race pass. The test now acquires 30 seconds and
explicitly renews for one second, then observes expiry. No production TTL bound
was increased. The unchanged production sources passed the corrected TCP case
normal/race in 02, 12.233/62.398 seconds, and five-package vet in 4.768 seconds.

The final 03 checkpoint adds exact unseen-Apply reconciliation: closing the
original also consumes its one-use review, a late exact packet remains fenced,
a newly signed request cannot borrow that review, and a consumed review with a
missing receipt remains uncertain. It records the fence at the actual server
time. Expired reclaimed diagnostic absence reports receipt unavailable instead
of asserting that its old read was never performed. The final real TCP case
passed normal/race, exit 0, zero skips, 13.444/83.276 seconds; vet across Store,
Server, hubaccountwire, hubauth and hubnodes passed in 12.469 seconds. Only the
Owner reconciliation producer and its TCP test changed after 02; the unchanged
Store/common/restore tests retain their exact 01 source attribution.

Development failures remain separately recorded. A preliminary broader selector
failed the old synthetic v68 reconstruction because it retained later objects;
the fixture now removes them before claiming a historical schema, with production
restore coverage still 67. An intermediate late-original test re-sealed a logical
request with fresh PQC randomness and correctly received packet conflict; it now
resends the retained exact packet. Neither diagnostic is promoted to acceptance.

The final commit receipt hashes every committed changed file and maps the base,
normal/race/vet artifacts and these limits. This checkpoint is the gated backend
producer, not the complete native Thread admission/CLI/MCP acceptance.

### Final review corrections

The 04 Owner-PQC qualification passes two top-level tests / six PASS events in
normal/race, zero skips, 14.012/25.664 seconds. The review observation lower bound
is client issued time minus 30 seconds and upper bound client now plus 30 seconds;
exact packet/body and proof expiry remain bound. Server observation offsets of
±100 milliseconds pass; ±31 seconds refuse. This handles real clock skew in UTC.

For a saved Node operation, a current policy/member/registration denial cannot
be sealed as a new ordinary original no-effect rejection. Its original receipt
remains unchanged and recovery reports transport outcome unavailable. This
profile's dedicated error maps to HTTP 503; other Node error routes are unchanged.
The private consumer must retain UNKNOWN, not infer a terminal result from any
transport authorization denial. Re-enabling the policy allows byte-identical
recovery of the old success, without reapplying it or claiming a current hold.

The 05 development test first received the old generic HTTP 403 mapping; that
was unsigned transport denial, not an authenticated original rejection. The
scoped error now has the explicit retained-original 503 mapping. Final 06 TCP
normal/race both passed, zero skips, 13.851/89.781 seconds, and five-package vet
passed in 12.899 seconds. All changed Go hashes are in the 06 snapshot; earlier
01–05 evidence remains source-bound and is not overwritten. The unpublished
`abd5a3b58628ecdab91b2e1f135082274f662af1` draft is mapped to the final amended
checkpoint in the 06 commit receipt; published `a00b639`/`b6fa465` are untouched.

The next private bridge contract is frozen with the consumer: request embeds the
existing `localEndpointGroupsRequest` Host provenance and optional real
`endpointGroupsOperatorContextProof`, then exactly one Scope/Acquire/Renew/Release
payload (scope-read has none). `requestMachineAgentThreadCollaboration(ctx,
socketPath, request)` returns a typed result with exactly one Scope/Locks/Receipt
and optional `localThreadCollaborationOriginalEvidence`: Operation, final typed
Original, RequestPacketDigest, ResponsePacketDigest, Outcome and ErrorCode.
Outcome is APPLIED, REJECTED_FENCED or UNKNOWN. Only verified exact PQC semantic
original evidence may settle a mutation; string errors or Retryable flags cannot.
This seam still requires its actual producer and complete current Guards before
activation. Local recover metadata remains in exact Host/Operator arguments,
while the original immutable wire body/digest excludes that control flag.

## Zero-member bootstrap and private state seams

A real TCP probe confirms JoinZero → candidate attestation → explicit
EndpointGroups Describe → original anchor → Owner classification → Group key
completion. Bare active join rows with `grants=[]` count as zero effective Groups.
The probe first exposed a real cycle: the ordinary key snapshot requires ACTIVE
source authority once a registration exists, although the first Group key is
not completed yet. The internal LocalDomain projected-manifest path now uses
an exact verified ZERO member/policy/registration admission plus current
classification and projected Group count. Ordinary snapshot/business Guard is
unchanged, and there is no wire bypass flag. Ordinary snapshot and lock access
still refuse after classification but before actual key completion.

The bounded existing Node state adds typed ThreadCollaboration originals with
exact caller/source, immutable body and retained request/response packets.
Rollback cloning preserves independent packet bytes. Generic Node recovery and
generic calls fence all five new operations/pending packets as uncertain; only
the dedicated original-aware producer may consume them. No old loop may clear
their pending slot or infer completion. Constructor/load validation, the socket
producer and real original-aware execution remain assigned to the following
private-producer integration. The new public
`ThreadCollaborationNodeEvidence{operation,original,request_packet_digest,outcome,error_code?}`
is reserved for verified Node envelopes; the next server implementation must
prove a semantic durable fence before REJECTED_FENCED. Declaring this type does
not activate or manufacture that evidence.

Qualification at base `43c071cd0d114d742bf8acffe99bff744e9bae5b` plus exact Go
hashes: 01 normal/race pass three top-level tests / eight events, zero skips,
21.316/74.091 seconds; Store/Server/hubaccountwire/cmd vet passes 15.735 seconds.
After also fencing generic call entry, the changed cmd tests pass normal/race
seven events, zero skips, 22.103/33.023 seconds; cmd vet passes 2.741 seconds.
The server/bootstrap sources are unchanged from 01. Raw evidence is under
`/home/zyf/Cicada/.local/evidence/v01-thread-network-locks-bootstrap-seams-20261105-01/`
and `...-02/`. The initial probe's key_prepare rejection is retained as the
identified cycle, not relabeled a pass. Full activation/use guards, Registry
pre-effect consumer, private Host/Operator execution, App, Docker, Runtime,
device/public/resident acceptance remain pending; capability flags stay false.

## Node semantic evidence and socket integration

The Hub now emits `original_evidence` inside the exact PQC Node response for
lock mutations. APPLIED and REJECTED_FENCED require the exact operation, IDs,
digest, canonical body and trusted caller to match a durable semantic original
row in the same transaction as the sealed reply. A transport or current Guard
denial without that row emits UNKNOWN. Previously saved successful packets
retain their dedicated current-denial HTTP 503 behavior and immutable recovery.
The real TCP test checks exact request-packet digest and distinguishes expired
originals from durable semantic rejection; reads never mint mutation evidence.

The shared private socket now dispatches only the closed five operation names
and returns the typed ThreadCollaboration result. Its private producer is a
separate QA checkpoint; socket Retryable/error strings are not terminal evidence.
At base `66ff79d` plus the exact source hashes recorded in local evidence
`v01-thread-network-locks-node-evidence-20261105-01`, real TCP normal/race pass
one top-level test each, zero failures/skips (5.491/53.097 seconds). Three-package
Store/hubnodes/Server vet passes. Root's independent combined-producer overlay
checks remain attributed to that overlay, not this isolated backend test.
Registry pre-effect and zero-stage Node bootstrap remain in progress, and both
new public capability flags remain false. No Docker, real Runtime, physical
device, public HTTPS or resident deployment acceptance is claimed here.
