# Native local domain contract

Status: **HUB/NODE RPC, CRYPTO, REPORT, NATIVE ISSUER, JOIN AND PEER ADAPTERS
IMPLEMENTED; REAL HOST COMMUNICATION AND LOGIN-EXPIRY ACCEPTANCE INCOMPLETE**. Root approved
the trust boundary, lifecycle and operations on 2026-10-22. The shared contract
checkpoint remains attributed to its original source. The subsequent backend
checkpoint implements the Hub service and Node report/cryptographic components.
The later Node checkpoint below passes scoped synthetic integration/race gates
and actual original-daemon A/B registration. Host failures below retain their
tested sources; complete communication and login-expiry acceptance remain
incomplete. Public capability describes server
availability, not complete Native acceptance or caller authorization. Hub schema migration 66 and Node crypto
schema 7 retain existing identities, public keys, epochs and historical Pair data.
This does not change `native-pair-v1`,
the frozen Client wire identifiers, or the installation-registration profile.

## Authority and trust boundary

One Owner explicitly delegates collaboration for one exact Hub, Node and local
OS-user scope in one Network and one dedicated Group. That Node's private local
IPC authenticates the local user; a Thread is an exact native address and context,
not a security principal isolated from other processes of the same OS user.
Only an explicit current-Thread registration can enter the policy. No history
scan, implicit enrollment, cross-Node peer, other Network, Group administration,
Owner power, historical-message access or arbitrary native operation is granted.

The local user scope is the existing Node writer scope (`uid:<decimal>` on Unix),
bound to the approved Node-Control identity and its current binding/key epochs.
Equal numeric UIDs on different Nodes do not identify the same subject. The Hub
trusts the approved Node to report/enforce its OS-user scope; it cannot remotely
attest a Unix UID. A private Node key or IPC accessible to another UID violates
this boundary and remains a hard refusal.

The App never guesses the remote user or takes it from its own OS. A new
Node-signed `LocalDomainUserReport` binds Hub/Node/Owner-binding/key-epoch,
actual user scope, nonce and at most five minutes validity. The prepare target
may leave `LocalUserScope` empty to resolve this authenticated report, or require
an exact nonempty match. The complete preview includes the report; App verifies
its Node signature, binding and time independently, displays the derived scope,
then signs the persistent policy. Without a fresh report, preparation refuses
with a bounded upgrade/start-Node result. The report is needed only to prepare
and activate, never to keep an active policy alive, read/revoke it or recover an
exact old receipt.

The report's `OwnerID` is an optional hint because the original approved Node
state does not contain an Owner ID. A nonempty hint must match exactly. An
empty hint does not assert or grant Owner authority: the Hub derives Owner from
the unique current authenticated binding; the App verifies the unchanged signed
report against its authenticated Owner/Node binding. Hub ID, Node ID,
Owner-binding ID and Node-key epoch remain mandatory exact signed coordinates.
No local first-Owner guess or new discovery operation supplies an identity.

Owner delegation is necessary for Endpoint encryption-key authenticity as well
as membership. An approved Node signs each exact current Endpoint candidate and
route under the delegation. Receivers independently verify the pinned Owner
root, the complete Owner delegation, the delegated Node signature, the Endpoint
self-attestation, and fresh current-policy/route evidence. A Node signature is
never accepted as an Owner signature in existing grant verification.

## Proposed profile and types

New independent revision `native-local-domain-v1`, format
`cicada.native-local-domain.v1`. Existing encrypted App account envelopes and
Node-Control RPC are reused; no Control inference, new daemon or dependency.

Only this new profile uses a 224 KiB encrypted Node receipt limit and a 560 KiB
encrypted reconciliation-response limit. An original Node request stays within
64 KiB; the exact `node.local_domain.reconcile` plaintext body alone may use
128 KiB to embed that original. The existing generic 256 KiB request-packet,
64 KiB other-request plaintext and 2 MiB response-plaintext limits remain.
Strict typed DTOs reject unknown padding. The complete signed Owner/Node and
member proofs, including worst-case legal native fields and JSON escaping,
must fit these bounds through actual PQ encryption and nested exact recovery.
Legacy Pair bounds and its verifier are unchanged.

`LocalDomainPolicy` contains these immutable authority coordinates:

* `policy_id`, `policy_version` (= 1), monotonically allocated `policy_epoch`;
* exact Hub ID/origin and Hub Control identity fingerprints;
* Owner ID, Owner approval-key ID/version/fingerprint;
* Node ID, Owner-Node binding ID/version, Node binding epoch, Node-Control key
  epoch, public identity and fingerprint;
* `local_user_scope`, `network_id`, `group_id`;
* fixed rights: explicitly register/admit current native Threads, directory
  visibility among current policy members, and existing same-Group sealed
  SEND/ASK/REPLY with the existing bounded native queue and binding Guard;
* `issued_at`, Owner-selected `expires_at`, preparation request/digest and nonce.

Policy expiry is independent of login and read leases. The default empty
`expires_at` means until explicit revocation; an Owner can select a fixed expiry.
The selected lifetime is shown before approval. Traffic, read, registration,
renewal and retry cannot extend a fixed expiry. Format `version=1`, immutable
authority `epoch` and mutable state `revision` are distinct.

Owner signing uses one purpose-specific canonical claim via existing ML-DSA
identity primitives, not a reused Pair consent purpose. `LocalDomainPolicyProof`
authenticates the entire immutable policy. A separate short
`OwnerLocalDomainRequestProof` authorizes activation; its expiry never expires
the persistent policy proof. Scope expansion requires a new Owner
decision and a new epoch; no in-place widening or resurrection.

`LocalDomainMember` contains policy ID/version/epoch, native harness/SID/cwd,
Endpoint/principal ID, SessionBinding ID/epoch, Network access binding, current
membership/Endpoint-Group revisions, candidate key version/fingerprint/proof
digest, state and exact join operation digest. It contains no Owner private key.

`LocalDomainEndpointKeyGrant` contains the existing complete
`GroupEndpointKeyGrantManifest`, policy proof, delegated Node public identity,
Node-signed grant and delegation reference. It is a distinct evidence variant,
not an `OwnerGroupEndpointKeyGrant` with forged Owner attribution. The delegated
signature reuses existing ML-DSA signing/verification primitives with a distinct
typed purpose `local-domain-endpoint-key-grant:v1`; policy and member binding
digests are signed together. `LocalDomainEndpointKeyClaims.MemberDigest` is
mandatory and equals the lowercase SHA-256 of UTF-8
`cicada/local-domain/member/v1\0` followed by the canonical complete typed
`LocalDomainMember` JSON (Go DTO field order, normal JSON escaping, no whitespace).
It binds SID, canonical cwd, user, access ID/epoch, membership revisions and
LeaseOwner in addition to the generic manifest's key/binding coordinates.
Preparation computes it from the projected member; the Node must compare the
complete original local member before signing; completion and receivers
recompute it. Missing or substituted coordinates refuse. This addition belongs
to the subsequent backend source, not the original shared-contract validation.
Its optional expiry equals the policy expiry; the
short key-completion challenge is separate. Empty manifest expiry is accepted
only by this new delegation verifier, never by legacy Owner or Pair verifiers.

`LocalDomainCurrent` binds policy ID/version/epoch, current authority revision,
sender and receiver member/Endpoint/binding/candidate coordinates, operation,
request/delivery attempt, issue time and a maximum 30-second validity interval.
It is authenticated by the existing Hub response route and required again at
queue admission, claim and final native delivery. A cached policy proof alone
never authorizes an offline new send or native injection.

## Proposed operations and state machines

Public capabilities at `/v2/owner/local-domains/capabilities` advertise profile
availability only. Purpose-specific Owner requests use existing App encryption,
current authenticated account/device authority and independent Owner proof:

* `owner.local_domain.prepare`: authenticated read/preview plus current Owner
  proof, exact Node/user/Network target and expiry. Reserve policy and a fresh
  dedicated Group; optionally reserve a new explicitly named Network when the
  request selects creation. No membership or communication rights yet.
* `owner.local_domain.activate`: Owner signs the exact server-derived preview;
  atomic activation and Network/Group creation through existing Store helpers.
* `owner.local_domain.status`: private authenticated Owner read, not a data-plane
  lease. Exact policy-ID reads and exact Node-ID paginated history reads are
  available. A Node page has at most 64 policies in ascending policy-ID order;
  `NextCursor` is the last returned ID when more exist. Empty history is a valid
  completed read. This restores Hub-held policies after a new App installation
  without original App cache, a current Node report or the Node being online.
* `owner.local_domain.revoke`: exact Owner-signed policy/epoch/revision CAS.
* `owner.local_domain.reconcile`: original authenticated encrypted packet,
  returning its durable exact receipt or a permanent no-effect fence.

HTTP paths use `/v2/owner/local-domains/{prepare,activate,status,revoke,reconcile}`.
Preparation expires at the earliest of five minutes, the original prepare
Owner-request proof expiry, the authenticated account session expiry and the
Node user-report expiry. A later server observation/report never extends the
original Owner intent window. Owner request proofs have at
most five minutes validity. Accepted proofs/nonces are consumed atomically with
the result. The complete policy lifetime is separate from these short requests.

Node operations use `/v2/node/control/rpc` with current original Node credential,
key/epoch, sequence and replay ledger:

* `node.local_domain.available`: publishes an independently Node-signed
  `LocalDomainUserReport` and reads current exact Node/user policies, with no
  account session token or policy for other Nodes/users. Its exact report/read
  receipt has a bounded five-minute cache; a retry in that window returns the
  original observation. An expired original sequence returns signed
  `READ_EXPIRED` without republishing the report or refreshing the read. On
  startup and periodically, the existing
  Node agent publishes a fresh actual-writer report when the Hub advertises this
  profile, even before any Thread joins. Refresh is at most once per two minutes,
  with a persisted 2/4/8/16-minute failure backoff; old Hub 404/unavailable leaves
  the normal shared counter/outbox and daemon intact. There is no per-tool,
  whoami or heartbeat report. No legacy heartbeat schema is changed.
* `node.local_domain.join`: explicitly selected policy plus exact current native
  registration; returns original Endpoint/SessionBinding/network session and
  member with runtime/SID/canonical workspace. This is zero peer rights until the
  key grant completes. Existing zero-right registration is reused, never renamed.
* After this binding allocation, the Node publishes its existing Endpoint key
  candidate/self-attestation through the existing candidate service.
  `node.local_domain.key_prepare` proposes the complete current manifest and
  projected next member revision under an exact current-revision CAS. It has its
  own immutable Node sequence/receipt. Exact retry returns the original challenge;
  an expired challenge needs a new operation, preserving Endpoint/key identity.
* `node.local_domain.key_complete`: exact challenge and Node-signed manifest;
  verify candidate self-attestation and current policy atomically, then activate
  Network membership/Group join/key evidence. No App or Owner key is needed.
* `node.local_domain.describe` and `node.local_domain.reconcile`: current scope
  and exact operation recovery. Existing native lease renewal retains policy
  authority checks and never renews policy expiry.

Owner status/reconcile and Node available/describe/reconcile use five-minute
read caches of at most 128 entries per authenticated actor/epoch and at most
128 fresh reads per minute. Node reads share the existing sequence highwater;
deleting an expired read cache never makes an old sequence executable again.
Only one latest signed user report is upserted per Node-binding/key epoch.
Prepare/activate/revoke, join and key prepare/complete retain permanent exact
mutation receipts and no-effect fences. Report polling does not append a full
policy response to permanent history every two minutes.

Policy: `PREPARED -> ACTIVE -> REVOKED | EXPIRED`. No backward transition.
v1 admits at most one nonterminal policy per exact Node/user. Creating another
Network/scope conflicts until the old policy is revoked or expires; it is never
chosen by first/latest policy. `cicada join NAME` explicitly registers the current
Thread and admits it when exactly one current policy applies. With no domain,
it retains zero-right registration and reports that the Owner can enable a domain
in the App. Ambiguous/stale scopes refuse; an old Pair is never a fallback.
Preparation timeout creates an expired durable outcome, not a new scope.
Member: `REGISTERED_ZERO -> JOINED_ZERO -> ACTIVE -> LEFT | REVOKED | EXPIRED`.
A failed or expired key challenge remains zero-right; refresh can issue a new
challenge under the same current member, without resetting its identity or
epochs. An already-left member cannot be revived by retry. A fresh explicit
Attempt can reuse the stable native SID, cwd, Endpoint and principal after Leave
or under a newly approved policy. It allocates a new member and SessionBinding
with a strictly newer binding epoch; only current members participate in SID and
Endpoint uniqueness. The established Network table keeps one AccessID per
Network/Endpoint, so same-Network rejoin preserves that ID and CAS-increments its
access epoch. Historical members retain their original `(AccessID, epoch)` and
remain terminal; exact old packets return the original receipt without revival.
A new policy
does not automatically adopt terminal members, old Pair slots or prior history.

The key challenge contains `ExpectedRevision` (current), a projected `Member`
and Node claims with `MemberRevision = ExpectedRevision + 1`. Completion checks
the original current revision, then atomically installs the projected member and
key evidence. Pure `describe` never creates a challenge or changes membership.

The transaction serializes the policy epoch and current authority, exact native
SID/cwd registration, unique member and accepted nonce. Concurrent claims cannot
allocate two identities. Exact packet retry returns the original receipt and
original session material; a changed packet using the same operation ID fails.
Receipt recovery authenticates retained original keys but does not restore
permission. New work always checks current authority after historical recovery.
Database restart preserves policy, member, receipt, fence and epoch history;
Node restart preserves existing candidate/private-key state and operation outbox.

## Current authority, revocation and compatibility

Every new admission, peer-key read, send, queue/claim and native delivery checks
active Owner root, current Owner-Node binding and Node key epochs, policy
version/epoch/state/expiry, member state, Network/Group membership, candidate and
SessionBinding epoch. The policy's creator App/device/session are audit context,
not continuing authorization dependencies. App close, ordinary logout, a
15-minute account expiry or an Owner-directory read expiry do not revoke it.
Explicit policy revoke, Owner-root revoke, Node-binding/key revoke/rotation,
Network/Group/member revoke or policy expiry immediately prevents new work.
Queued work fails current Guard; accepted historical receipts remain recoverable.

The Hub serializes send, claim and final authorization with revocation under
SQLite's writer transaction. Committing final authorization for an exact native
attempt is the in-flight boundary. Revocation before that commit denies it;
revocation afterward may leave that already authorized attempt in flight only
within its original deadline (at most 30 seconds and the current short leases).
A Node fetches final authorization afresh before each actual attempt, including
after a writer wait or restart; it cannot reuse the observation for another
operation/attempt. Queued/claimed rows without such authorization fail after
revoke. This is no claim of an atomic Hub/remote-OS operation, rollback of native
side effects or two-phase commit. Complete peer/delivery carriers are bounded
to 320 KiB including both distinct delegated grants and current evidence.

The dedicated domain Group cannot be an existing Pair Group. Legacy admission,
topology or key-grant mutations cannot insert unrelated members into that Group.
The policy permits only peers under the exact same active policy, Node and local
user. All original Pair proofs, limits, deadlines and strict native-context
checks remain authoritative for existing Pair scopes. No Pair proof is converted
into a domain policy, and no old per-SID Owner join grant is weakened.
The independently installed original Owner public pin remains required. A public
key delivered by the Hub cannot replace that trust root in this profile.

Hub Nodes mode exposes the existing exact `GET /v2/fabric/members` and
`GET /v2/fabric/list` directory aliases through the same native self boundary.
Both authenticate the current Group session, require current native
collaboration self membership, and call the existing `Fabric.List`, including
its current `directory.read` authorization and directory-card redaction. Query
filters and the `endpoints` response are unchanged. Zero-rights admission,
an unjoined or incorrect Group scope and revoked authority cannot enumerate peers. These two
paths do not enable a general Fabric prefix or change Pair consent semantics.

## Real Codex record permissions

For this explicitly selected domain profile, a trustworthy private Node IPC and
current Node/user policy are the authority; record group/world-write mode is
diagnostic provenance, not Owner consent. A separate domain verifier retains the
configured root, containment, no-symlink chain, local UID ownership, regular file,
same inode across open, native source, exact SID and canonical cwd checks. It can
accept an old Codex daemon's umask-002 records without per-record chmod, changing
daemon ACLs or restarting it. A diagnostic reports writable native-record
provenance. Root must freeze this profile before that code is enabled.

Root approved the private issuer's exact operator event forms after reviewing
the pinned Codex 0.163 evidence. Only `codex.operator.endpoint_register`,
`codex.operator.endpoint_leave`, `codex.operator.endpoint_directory`,
`codex.operator.native_pair_available` and
`codex.operator.native_pair_join_named` may carry a valid original TurnID with
an empty ToolUseID, as real UserPromptSubmit does. Their existing double-empty
and valid double-present forms remain compatible. Tool-only and malformed IDs
refuse. The missing-ID exceptions do not apply to unknown operator purposes or
MCP tool events. The real
TurnID remains in the HMAC-bound context and exact consumer comparison; no
replacement ToolUseID is generated. This changes no public DTO, frozen protocol
identifier or authorization right. Existing Pair verification stays strict.

This deliberately grants the approved local user its scoped domain authority;
it does not claim isolation between that user's Threads. Another UID able to
modify the native Runtime/history can corrupt SID/cwd provenance, so this path
requires a trusted host/native Runtime and is not cross-UID tamper attestation.
Private Node keys, state and IPC must remain protected. A compromised same-UID
process already belongs to the trusted subject and can act within its policy.

Context tickets bind the selected verification profile and exact policy
ID/version/epoch in addition to their existing HMAC fields. A domain ticket
cannot authorize Pair or another policy. A missing/ambiguous/stale policy refuses
domain admission; an unselected legacy call retains strict mode-022 refusal.

## Implementation ownership and proposed entry points

Hub owns new `internal/e2ee/owner_local_domain*.go`,
`internal/hubaccountwire/local_domain*.go` and machine-readable profile inventory;
Store schema/policy/member/receipt/current-Guard files; `hubauth/local_domain.go`,
`hubnodes/local_domain.go`, Server route/profile advertisement and Hub CLI.
Node owns distinct `nodekeys/local_domain*.go`, shared sealed-evidence verifier
selection and native local bridge/admission/lease integration in `cmd/cicada`.
Existing same-Group services gain an explicit authority variant with strict
Pair/legacy branches. No App implementation or QA-script writes by Hub.

The exact shared Go APIs are:

```go
NewLocalDomainPrepare(AppNodeSession, e2ee.OwnerAppNodeScope, e2ee.LocalDomainTarget, *e2ee.Identity, time.Time) (LocalDomainPrepare, error)
NewLocalDomainActivate(AppNodeSession, e2ee.OwnerAppNodeScope, LocalDomainPrepare, []byte, LocalDomainChallenge, *e2ee.Identity, time.Time) (LocalDomainActivate, error)
NewLocalDomainStatus(AppNodeSession, e2ee.OwnerAppNodeScope, string, *e2ee.Identity, time.Time) (LocalDomainStatusRequest, error)
NewLocalDomainStatusForNode(AppNodeSession, e2ee.OwnerAppNodeScope, string, string, *e2ee.Identity, time.Time) (LocalDomainStatusRequest, error)
NewLocalDomainRevoke(AppNodeSession, e2ee.OwnerAppNodeScope, LocalDomainDescription, *e2ee.Identity, time.Time) (LocalDomainRevoke, error)
NewLocalDomainReconcile(AppNodeSession, []byte, time.Time) (LocalDomainReconcileRequest, error)
SealClientRequest(*e2ee.Identity, HubIdentity, any) ([]byte, error)
OpenLocalDomainResponse(*e2ee.Identity, HubIdentity, []byte, []byte, any) error
```

After opening a result, App consumers call `ValidateLocalDomainResultTarget`
with the retained exact request/packet to check the policy/Node selector and
independently pinned Owner key on every restored policy. `BuildLocalDomainStatusPage`
enforces at most 64 rows **and** 128 KiB for the entire canonical result, including
proofs and cursor. A byte-limited page can contain fewer than 64 rows. An
oversized first row refuses instead of skipping a policy; continuation is the
last returned policy ID. Reconcile uses the new operation's exact 640/896 KiB
body/packet budgets; generic and Pair ceilings are unchanged.

Signing APIs are `e2ee.Sign/VerifyOwnerLocalDomainPolicy`,
`Sign/VerifyOwnerLocalDomainRequest`, `Sign/VerifyLocalDomainUserReport` and
`Sign/VerifyLocalDomainEndpointKey`. Nodes use
`CanonicalLocalDomainNodeRequest`, `DecodeLocalDomainNodeRequest`,
`DecodeLocalDomainNodePacket`, `DecodeLocalDomainNodeAvailable` and
`LocalDomainSelectionForPolicy`. Typed DTOs are defined in
`internal/hubaccountwire/local_domain_types.go`. Hub service/Store entry points,
Node cryptographic state and the bounded Node report worker are implemented in
the backend checkpoint recorded below. The later Node checkpoint implements the
Native issuer and explicit Join/peer/delivery adapters with the acceptance limits
recorded separately. `ValidateLocalDomainEndpointKeyProjection` validates the
complete policy/member/candidate/manifest before the local Node signs; it does
not authenticate an absent Node proof or assert current authority.
`VerifyLocalDomainEndpointKeyGrant` additionally verifies that exact Node proof
and complete MemberDigest. The following shared-contract
validation retains its original, earlier implementation boundary.

Separately approved local diagnostic API is
`LocalCodexContextError{Stage string}` with `Unwrap() -> errLocalCodexContext`;
nine fixed stages ROOT/PATH/OWNERSHIP/PERMISSION/INODE/METADATA/SOURCE/SESSION/
WORKSPACE. This adds no IPC free-text diagnostics or authorization.

## Shared contract validation, 2026-10-22

This checkpoint supplies shared canonical DTOs, constructors, purpose-separated
Owner policy/request and Node report/key signatures, bounded PQ packet codecs,
result-to-local-target/Owner-pin checks, byte-bounded history pagination and a
machine-readable inventory checked against compiled constants. Public service
availability stays absent/false. Store/Server/Node-agent/local-domain admission,
current authority checks and domain context-ticket behavior are **NOT IMPLEMENTED
by this checkpoint**. Real App/Node consumption, Hub/Node disposable interop,
real Codex Runtime, other-UID domain-context signing, Windows, Android, physical
devices and public HTTPS remain **NOT_RUN** for this new profile.

The final test source was a dirty tree based on
`18c54a6b3f5d4a595a8185774163efb3e2f764d3`, with full source manifest SHA-256
`f90beb8bb4eaf82e5a1bb28e9ebbdd38a4b26ebf3d458c68176861b43deb2a23`.
This validation section is a subsequent documentation-only overlay. Do not
attribute the tested dirty source solely to its base commit. Every file in each
test manifest remained unchanged through its gate, verified by post-run hashes.

All commands ran under `cicada-go` in disposable, network-disabled Docker
containers as UID 1000, with Go 1.27.3, source/module-cache mounts read-only and
image pinned to
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`.
Only synthetic identities and payloads were used; no credential/key contents
were emitted into evidence.

| Gate | Result | External evidence directory |
| --- | --- | --- |
| `go test -json -count=1 ./internal/clientwire ./internal/e2ee ./internal/hubaccountwire` | 532 pass, 0 fail, 1 skip; 139 top-level pass | `local-domain-shared-final-full-20261022-20261022T180220Z` |
| Same packages with `-race -count=1` | 532 pass, 0 fail, 1 skip; 139 top-level pass | `local-domain-shared-final-race-20261022-20261022T180220Z` |
| `go vet ./internal/clientwire ./internal/e2ee ./internal/hubaccountwire` | Exit 0 | `local-domain-shared-final-vet-20261022-20261022T180220Z` |

After these full gates, the prepare-fence test added two assertions refusing
activate/revoke purpose substitution, with no production-source change. A
focused race gate passed 1/0/0 on source manifest
`47163a2d9e80aff20f46fbb4be8322a835322aa275fa0d6431062af7c4b54bdd`
in `local-domain-prepare-fence-purpose-20261022-20261022T180455Z`, with post-run
source hashes unchanged. The final checkpoint includes that test-only addition
and this documentation-only overlay. The helper accepts only an authenticated,
exact-packet, no-effect prepare rejection with no invented policy scope; a
successful prepare still requires the full challenge validation.

The skipped `TestExternalOwnerOpenSSLRealSignatureInterop` requires
`CICADA_TEST_OWNER_OPENSSL` to select an independently verified OpenSSL 3.5.9
executable. That selector was not set in these isolated gates; it is **NOT_RUN**,
not counted as a pass. In-process real ML-DSA/ML-KEM signing, verification and
PQ envelope round trips ran, including existing Pair regression tests.

The maximum-field real-PQ fixture produced a two-row 111,385-byte canonical
history page, a 214,681-byte sealed page, a 125,734-byte activation packet, a
178,083-byte reconcile request and a 526,980-byte reconcile response. Tests open
the actual nested packets, exercise a byte-limited continuation below 64 rows,
refuse a first row exceeding the supplied budget, preserve the next unreturned
policy, and verify original packet/receipt identity. They also reject a genuine
Hub-signed preview that extends only the original Owner intent expiry while
remaining within a later valid Node-report/session expiry. Short requests and
reports expire; an explicitly persistent delegation and delegated key proof
still verify years later, subject to independent current authority at use time.

Earlier iterations are retained separately: the first focused gate had 12 pass
and one failure from using the legacy generic frame ceiling for new recovery;
the second had 81 pass and one failure from a maximum-field fixture retaining
its old App session tuple. The new operation-specific recovery entry and fixture
tuple correction were validated by the subsequent 82-pass focused gate and the
final full/race gates. These earlier failures are not rewritten as passes.

All evidence is under
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`, retaining source
manifests, exact receipts, post-source checks and command output. The final
candidate manifest lists exact checkpoint file hashes and receipt hashes.

## Hub backend and Node crypto/report validation, 2026-10-22

This checkpoint implements Hub schema 66, encrypted Owner prepare/activate /
status/revoke/reconcile, Node report/available/zero-Join/key-prepare/key-complete /
describe/reconcile, dedicated-Group guards, lease recovery and existing sealed
Relay SEND/ASK/REPLY admission. Node crypto schema 7 requires the independent
original Owner public pin, verifies complete delegated member/key chains and
rechecks that pin under the peer-pin writer. The existing Node worker publishes
the actual OS-user report before Thread enrollment only after binding approval;
low-level discovery startup stays read-only. No Control inference is used.

The final tested dirty source is based on
`e423be32b070cc2cefacf9974dd0d3e957ecabcb`, with full source manifest SHA-256
`289a6ec7a9b5f0d31eca58086b6121c28be450571f43d5942777ed62ed2f8c14`.
All final gates kept every source byte and base commit unchanged, checked after
completion. This validation record and the preceding entry-point clarification
are a subsequent documentation-only overlay. Do not attribute this dirty build
solely to HEAD. Commands used the same pinned Go 1.27.3 Docker image, UID 1000,
network-disabled container and read-only source/module mounts described above.
Only disposable SQLite/TCP fixtures and visibly synthetic identities were used.

| Gate | Result | External evidence directory |
| --- | --- | --- |
| Full normal: e2ee, clientwire, hubaccountwire, nodewire, nodekeys, nodebackup, hubauth, hubnodes | Exit 0; 817 pass, 0 fail, 1 skip; 272 top-level pass | `local-domain-crypto-rpc-normal-20261022-20261022T204318Z` |
| Scoped normal: Store, Server and CLI | Exit 0; 289 pass, 0 fail, 1 skip; 124 top-level pass | `local-domain-backend-normal-final-20261022-20261022T204623Z` |
| Focused race: local domain, crypto migrations, concurrent Hub migration and existing Node request/response ceilings | Exit 0; 103 pass, 0 fail, 0 skip; 40 top-level pass | `local-domain-focused-race-final-20261022-20261022T210403Z` |
| Vet: the above packages plus fabric | Exit 0 | `local-domain-backend-vet-final-20261022-20261022T204635Z` |
| Wider compatibility race attempt | **NOT_ACCEPTED**, exit 1; Store package reached its 20-minute timeout after 1263.287 seconds overall | `local-domain-all-race-final-20261022-20261022T204623Z` |

The full normal lightweight-package gate used earlier source manifest
`addc30a13435541f92ce335adf7739e9fa2395e9a0a5921f7a1e2976e6ef737f`;
its tested package sources are unchanged in the final source. The later changes
fixed the Store's external reconciliation digest and strengthened its concurrent
Join / persistent-reopen test. Exact commands, package lists, selectors,
per-test events, receipt hashes and post-source checks remain in each evidence
directory. Counts are per gate and include subtests; they are not additive.

The scoped normal selector covers local domain, legacy Native Pair, same-Group
sealed carriers, native self, relevant migration/restore, Node discovery and
Owner topology tests. The focused race selector is exactly
`^Test(LocalDomain|CryptoStateV[123]|V2MigrationsConcurrentOpenSerializesLedger|NodeControlUsesRequestAndResponseBodyCeilings)`
over e2ee, hubaccountwire, nodewire, nodekeys, nodebackup, Store, Server and CLI.
The broad race attempt recorded 342 completed pass events and no explicit test
assertion failure before its package timeout; this is **not** an overall pass.
Its last active test, `TestV2MigrationFailureRollsBackSchemaAndResumes`, had run
six seconds; the retained stack was compiling SQLite integrity-check work in
`verifySQLiteIntegrity` / `Store.New`. Prior test completions kept advancing.
This evidence alone does not establish absence of a product deadlock. Unfinished
wide-race tests are **NOT_RUN**; compatibility claims use the completed normal
scope and completed focused race, without retrying the enormous broad group.

The two separate skip reasons are unchanged external prerequisites: the full
lightweight normal gate did not select an independently verified OpenSSL 3.5.9
executable, and the scoped normal restore gate did not supply two disposable
physical bind mounts. Neither is a pass. The focused race has no skips.

Real Hub-Nodes-only TCP tests perform existing N2/N3 enrollment, preserve original
Owner/Node keys and epochs, activate a policy, recover the exact activation
receipt, zero-Join two synthetic native SIDs, publish original Endpoint
candidates, complete the real PQ Owner-to-Node-to-Endpoint chain, SEND/claim /
final-authorize and revoke. Maximum legal native fields produced 214,186-byte
Node completion receipts and 520,695-byte nested reconciliation responses.
A 55,248-byte authenticated original with a deliberately invalid inner signature
produced a durable no-effect refusal, recovered byte-for-byte through a
73,831-byte reconciliation body / 143,353-byte request packet. Unknown DTO
padding, oversized profile frames, operation substitution and inherited old
Pair/generic enlarged limits are refused.

Store tests cover four concurrent identical Joins returning one exact
identity/token receipt, close/reopen recovery of that original receipt, Leave
followed by explicit same-SID/cwd rejoin with greater binding and Access epochs,
non-revival of old members, cold lease recovery after App/session/device loss,
bounded report reads and expired-original fencing, current full-chain peer
guards, and final authorization serialized before/after revocation. Restore
tests reject policy/proof/receipt/challenge/member replacement and epoch
rollback, distinguish disposable caches from permanent sequence floors, and
accept only exact higher-epoch stable-coordinate Access credential advancement.
Node offline inspection remains read-only and refuses missing trust/key tables
or future crypto schemas.

Earlier failures are retained, not relabeled: the initial broad normal attempt
recorded 3018 pass / 30 fail / 22 skip and a Store timeout. It exposed stale
migration/version fixtures, missing schema-66 / crypto-7 restore coverage,
implicit report startup in low-level discovery fixtures and a pre-existing
Owner-directory expectation. The latter was independently reproduced on clean
`914250b6` by Root; only that test expectation changed, with no product directory
query change. Subsequent boundary fixtures corrected base64 size calculations;
the real TCP test also caught the external Node reconciliation digest using the
internal ledger SHA-256 instead of the shared domain-separated packet digest.
The internal ledger algorithm remains unchanged. Final scoped gates above cover
these corrections; no full Store/Server/CLI-suite pass is claimed.

**Remaining acceptance boundary:** Native context issuer/profile selection,
explicit local-domain Join/candidate publication/managed lease adapters, actual
native delivery, integrated Hook/MCP consumption, the supervising App-to-Hub
domain gate, real Codex Runtime, Windows, Android, physical devices, public HTTPS
and production restore/deployment are **NOT_RUN / NOT_ACCEPTED by this backend
checkpoint**. Synthetic SIDs in TCP fixtures were never sent to a real Runtime.
No deployment, real identity/key replacement, push or merge is performed here.

## Node issuer and admission checkpoint, 2026-10-22

This checkpoint connects the selected domain to the existing private Node IPC,
explicit current-Thread admission, original Endpoint key publication, shared
managed-lease worker and same-Group sealed transport. The Node selects the
verification profile from the current approved policy and independent original
Owner pin. Caller input cannot select the relaxed record-permission profile.
The retained exact transcript path is bounded private metadata; fresh domain
admission and outbound verification do not scan native history. An explicit
registration can reuse the latest original signed report for one current-policy
read, so activation need not wait for the next periodic report. This creates no
new report signature, expiry extension or per-tool report publisher.

Admission retains zero-Join, candidate attestation, key-prepare and exact signed
key-complete originals. The scope decision precedes key-complete. Before signing,
the Node compares the complete projected member, candidate and manifest with its
original native tuple and public key. Missing/corrupt retained Endpoint keys
refuse replacement. A separate bounded managed-domain map shares the existing
worker/capacity budget with Pair leases; the token remains only in the original
encrypted zero-Join receipt. Warm renewal uses ordinary heartbeat without a
per-tick permanent mutation receipt. Cold recovery uses the original AttemptID,
member and epochs, never an explicit replacement admission or an App session.

Hub Join checks a retained AttemptID's original terminal/member coordinates
before the current-SID shortcut. A stale worker cannot renew a later admission.
Leave retains its original lease-ID snapshot before dispatch; exact receipt
recovery stops those IDs rather than a subsequent same-SID admission. Existing
Pair stop reason `EXPLICIT_LEAVE` is retained. Candidate admission checks both
effective-at and expiry against one precise real instant through the existing
time functions; it neither truncates the clock nor backdates a real rejoin.

Unknown originals settle before fresh policy/native checks. Historical complete
results reverify the original full chain and own prepare/complete proof at its
original issue time; returning that history does not restore current rights.
Only a separate current check may permit renewed use. No-effect fencing refuses
unknown key-complete outcomes. Actual ACK-loss/restart tests cover zero-Join,
candidate, prepare and complete, as well as lost Leave followed by fresh rejoin.

Peer transport retains distinct legacy and delegated grant variants. Both domain
chains, original local key and fresh current operation/attempt are verified.
Existing carrier locator redaction is preserved: peer-key hides the receiver
locator and delivery hides the sender locator; every nonempty locator must match
the signed member, and the actual delivery receiver SID is mandatory exact.
REPLY reverses the complete domain current snapshot with the original ASK route.
Native delivery refreshes final authorization after acquiring the physical
writer, checks local trust again, and carries the current deadline through local
admission and the executable. No atomic Hub/remote-OS guarantee is added.

### Source-specific deterministic and disposable integration evidence

Artifacts below are under
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`. Tests use the pinned
Go 1.27.3 Docker image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network disabled, read-only source/module mounts and synthetic disposable keys.
Each completed gate has `receipt.json`, `source-manifest.json` and a successful
full `source-after-check.json`. Dirty source is not attributed solely to HEAD.

| Tested source | Gate | Result / artifact prefix |
|---|---|---|
| Dirty `a52cf563204f658a31876bcf54832150db6db531`, manifest `030fa5a6ff5707c7674e1b5151bf52a4a4dd4aa476dc535c308c30af10369a25` | Normal Hook/private IPC/v2 cache/shared contextual MCP/Hub/Relay/crypto/inbox/physical writer ASK and REPLY, plus direct Node diagnostic | 2 pass, 0 fail, 0 skip; `local-domain-hook-peer-reverse-current-20261022-20261022T223047Z` |
| Same source | Scoped normal: cmd/cicada, Store, nodekeys, hubaccountwire; domain, context, managed Pair, existing consumer/Leave/key checks | **NOT_ACCEPTED**, 187 pass, 2 fail, 0 skip (83 top-level pass, 1 top-level fail); `local-domain-node-focused-normal-20261022-20261022T223156Z` |
| Same source | Focused domain/context/fractional-time race across those four packages | Exit 0, 108 pass, 0 fail, 0 skip (44 top-level); `local-domain-node-focused-race-20261022-20261022T223156Z` |
| Same source | Vet: cmd/cicada, hubaccountwire, nodekeys, Store, fabric | Exit 0; `local-domain-node-focused-vet-20261022-20261022T223156Z` |
| Dirty `a52cf563…`, manifest `aab475adad8958af8ff2b03b9f608035f0c6ee387d5fff0b60945b4e8e29aea4` | Restore only Pair stop reason `LEFT` to original `EXPLICIT_LEAVE`; exact failed test and related Leave guards, normal and race | Each 11 pass, 0 fail, 0 skip (3 top-level); `local-domain-pair-leave-code-{normal,race}-20261022-20261022T224218Z` |
| Dirty `0da74df97453667c1f52ff3790dc5c34d2b1a076`, manifest `fd87f665aa9ed92a21945c1ff9e17dd8165021b86d67168fc97b90d0f08c0f1a` | Exact operator ID forms/negative purposes/HMAC, context guards and real-shape synthetic Hook/MCP ASK/REPLY, normal and race | Each 69 pass, 0 fail, 0 skip (9 top-level); `local-domain-user-prompt-shape-{normal,race}-20261022-20261022T225725Z`; vet cmd/cicada exit 0 in the matching `vet` artifact |

The first scoped normal failure is the existing
`TestManagedPairLeaseDelayedReplyUsesCurrentClockAndLeaveCAS/leave_before_reply`
stop-reason assertion, after its STOPPED-state assertion passed. Its later exact
normal/race gates cover that one-word compatibility correction and related
Leave guards; they do not relabel the earlier whole gate as passing. Their
selector is
`^Test(ManagedPairLeaseDelayedReplyUsesCurrentClockAndLeaveCAS|ManagedPairLeaseLeaveAndCurrentAuthorityStopWithoutResurrection|LocalEndpointLeaveExactRecoveryDoesNotRefreshDigest)$`.
The final event-shape selector is
`^Test(LocalDomainContext|LocalDomainHookMCPRelayAndNativeCallbackRealTCP|LocalCodexContext)`.

Frozen candidate `local-domain-node-prompt-shape-candidate-20261022.json` has
SHA-256 `a41ac230b9eef44d1c2c8ac015646a3119f446aaa8e7693d007bf863257057a9`.
Relative to Root's prior freeze it changes only the issuer ID-form check and
two tests. This documentation is a later overlay; production files retain that
candidate's exact hashes. Earlier failures are retained, including the readonly
crypto handle used for candidate writes, real-time rejoin denial, the temporary
overstrict redacted-SID check, consumer outbox projection loss and missing
reverse domain current. Subsequent accepted gates cover their final corrections;
no full Store/CLI regression-suite pass or real Runtime pass is inferred.

### Actual Runtime evidence and remaining boundary

QA alone ran the actual pinned original-daemon lane with normal Hook trust and
`CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY=1`. The following results remain
under `/home/zyf/Cicada/.local/evidence/native-pair-acceptance/`:

| Run / source | Actual result | `result.json` SHA-256 |
|---|---|---|
| `run-20261022T223355Z-WhxOtu`, dirty `a52cf563…` / original freeze `329af9…` | **FAIL** at `LITERAL_AB/A_JOIN/ASSERTION`; private exception removed by fixture cleanup, cause unproven | `a3b6cdd7e662728d5e19d24027e57c3529cada1a7332a6fd344ee776214123f5` |
| `run-20261022T225021Z-nghDUR`, dirty `0da74df…` / Root freeze `bb1436…` | **FAIL**, `ACTUAL_TUI_LITERAL_RESULT_NOT_VISIBLE`, Hook `context_refused`, provider POST 0 | `40b216ada516ed60a41f3cc26dcf88a5ea04e1b91d7cc9e10a05a8bcff9efbc5` |
| `run-20261022T230207Z-3NUe5A`, dirty `0da74df…` / final freeze `a41ac230…` above | A/B literal admission, original SID/cwd/UID/inode, zero literal POST, MCP readiness and actual App Close passed; **FAIL** at `HOST_APP_CLOSED/A_WHOAMI/ASSERTION`, fixed code `UNCLASSIFIED`, static-provider POST 2 | `6219be1790282693cda1dc07477f903152580a8b73a07718e7c5e494c2db4f67` |

Historical raw events from the same pinned Codex 0.163 binary establish the
UserPromptSubmit TurnID-only shape; they are not this failed run's raw input.
The App review receipt is
`/home/zyf/.cicada/acceptance/codex-context-checks/codex-0163-prompt-event-review-20261022T225756Z/result.json`,
SHA-256 `796d8ad292fe75062ae816bec4bcb16817aa7c9421cc93aefdd4255bd30c32d2`.
The successful later actual A/B registration supports that compatibility fix.
The first Host failure remains undiagnosed at this checkpoint; static schema
agreement is not evidence of a successful live whoami or a proven product cause.

**NOT_ACCEPTED / NOT_RUN:** complete actual Host whoami/ASK/REPLY/receive,
real login-expiry waiting and subsequent C admission, actual post-revoke Host
refusal, automatic native queue/model consumption, Windows physical Runtime,
Android, physical devices, public HTTPS and production restore/deployment.
Synthetic native queue subprocesses remain separate from actual Runtime
consumption. No existing daemon/record permissions or real identity were changed
to bypass proof, and no push, merge or deployment is performed by this task.

## Hub Nodes directory routing follow-up, 2026-10-22

The Nodes-only route allowlist omitted the existing members/list aliases even
though MCP already exposed `cicada_members` and `cicada_list`. This follow-up adds
only those two exact GET paths to the native self handler. It calls the existing
`Fabric.List` after current Group authentication and
`RequireNativeCollaborationSelf`; `List` retains its `directory.read` check,
filters and `directoryCard` projection. No wildcard Fabric route, new grant,
caller-selected identity, DTO revision or Pair consent change is introduced.
Other HTTP methods refuse and suffix routes remain unavailable.

The tested source is dirty
`c4cb7b965481377ecface335e693095e3b7df76e`, full manifest SHA-256
`7f385dd774c6de02a7f97fbd3334f3af2152e44eb54b3fe41ee229665c4b3401`.
The tests use the same pinned isolated Docker environment documented above.
All three gates have successful full source/base postchecks; this validation
record and the scope-wording clarification are later documentation-only overlays.
Production and test files remain exactly as tested. Artifacts are under
`/home/zyf/Cicada/.local/evidence/node-endpoint-registration/`:

| Gate | Result | Artifact directory |
|---|---|---|
| Scoped normal, `internal/server`: ordinary domain TCP, legacy Pair TCP and existing directory privacy HTTP | Exit 0; 25 pass, 0 fail, 0 skip; 3 top-level; 14.163 seconds | `hub-nodes-directory-normal-20261022-20261022T234739Z` |
| Focused race, `internal/server`: ordinary domain and legacy Pair TCP | Exit 0; 7 pass, 0 fail, 0 skip; 2 top-level; 106.137 seconds | `hub-nodes-directory-race-20261022-20261022T234739Z` |
| `go vet ./internal/server ./internal/fabric` | Exit 0 | `hub-nodes-directory-vet-20261022-20261022T234739Z` |

Both directory aliases are checked over the actual Nodes-only TCP handler with
real synthetic N2/N3/Owner/Node signatures and durable Store state. Active domain
A/B and fully consented legacy Pair entries retain their own names/cwds while
Native SIDs and credentials remain absent. Zero-grant admission, absent/wrong
credential type, unjoined Group header and current revocation refuse. Node,
harness and limit filters retain the original behavior; POST and extra path
segments cannot enable a general Fabric API. The existing foreign-Owner directory
privacy assertions also pass. No SQL membership or grant bypass sets up the
Nodes-only positive cases.

These scoped HTTP results do not establish complete actual Native Host
communication, real fifteen-minute login expiry, Windows, Android, public HTTPS
or production deployment. QA owns the separate full Native/login-expiry gate;
its historical driver-framing and tool-name corrections retain their own sources.
