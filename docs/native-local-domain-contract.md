# Native local domain contract

Status: **SHARED CONTRACT; SERVICE NOT IMPLEMENTED**. Root approved
the trust boundary, lifecycle and operations on 2026-10-22. The shared Go types,
constructors and crypto/codec tests are the reviewable contract checkpoint.
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
Node-signed `LocalDomainUserReport` binds Hub/Owner/Node/Owner-binding/key-epoch,
actual user scope, nonce and at most five minutes validity. The prepare target
may leave `LocalUserScope` empty to resolve this authenticated report, or require
an exact nonempty match. The complete preview includes the report; App verifies
its Node signature, binding and time independently, displays the derived scope,
then signs the persistent policy. Without a fresh report, preparation refuses
with a bounded upgrade/start-Node result. The report is needed only to prepare
and activate, never to keep an active policy alive, read/revoke it or recover an
exact old receipt.

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
digests are signed together. Its optional expiry equals the policy expiry; the
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
  account session token or policy for other Nodes/users. This is a mutation with
  an immutable exact replay receipt; retry returns the original report/read
  outcome, not a new observation. On startup and periodically, the existing
  Node agent publishes a fresh actual-writer report when the Hub advertises this
  profile, even before any Thread joins. No legacy heartbeat schema is changed.
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
epochs. An already-left registration cannot be revived by retry. A new policy
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

The dedicated domain Group cannot be an existing Pair Group. Legacy admission,
topology or key-grant mutations cannot insert unrelated members into that Group.
The policy permits only peers under the exact same active policy, Node and local
user. All original Pair proofs, limits, deadlines and strict native-context
checks remain authoritative for existing Pair scopes. No Pair proof is converted
into a domain policy, and no old per-SID Owner join grant is weakened.
The independently installed original Owner public pin remains required. A public
key delivered by the Hub cannot replace that trust root in this profile.

## Real Codex record permissions

For this explicitly selected domain profile, a trustworthy private Node IPC and
current Node/user policy are the authority; record group/world-write mode is
diagnostic provenance, not Owner consent. A separate domain verifier retains the
configured root, containment, no-symlink chain, local UID ownership, regular file,
same inode across open, native source, exact SID and canonical cwd checks. It can
accept an old Codex daemon's umask-002 records without per-record chmod, changing
daemon ACLs or restarting it. A diagnostic reports writable native-record
provenance. Root must freeze this profile before that code is enabled.

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
`internal/hubaccountwire/local_domain_types.go`. Service/Store/CLI entry points
above remain implementation work, not exposed availability in this checkpoint.

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
