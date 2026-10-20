# Controlled installation registration v1

**CONTRACT_CANDIDATE / C0. Public availability is false.** The Go DTOs, pure
cryptographic helpers, canonical vectors and checker are reviewable code. No
registration HTTP handler, Store migration, ingress authorization change or
three-component integration is enabled by this checkpoint. Implementation and
validation results belong to the existing native App validation/plan records;
this document defines the boundary, not a second acceptance ledger.

The separate identifier is `installation-registration-v1`; its format is
`cicada.installation-registration.v1`. Existing Owner/account identities, public
keys, credentials, epochs, receipts and authorization histories remain intact.
Wire 1, catalog 55 / `client-hub-v1.6.5`, `owner-activation-v1`,
`app-node-authority-v1` and `native-pair-v1` retain their exact formats and
purposes. The new purpose-specific envelope reuses existing Go ML-KEM-768,
ML-DSA-65 and AES-256-GCM; it is not a generic RPC or role framework.

## Installation, subject and authority

A physical host may run any combination of Hub, Node and App. A Host/device
inventory grouping is metadata, not a credential or hardware attestation.
`installation_id` is opaque, stable and scoped to one Hub and controlled local
installation/OS security context. It is not NodeID, App DeviceID, hostname, IP,
OS UID or a globally correlatable hardware ID. A retained admission identity
authenticates only installation registration/self operations. It never replaces
an existing Hub, Node, App or Owner key.

Each attempt names one exact `NODE_CONTROL` or `APP_DEVICE` subject and proves
both its keypairs. Components `APP`, `HUB`, `NODE` are a sorted inventory list,
not grants. A Hub component refers to an existing Hub; first Hub/Owner bootstrap
still requires the existing operator-scoped activation and true original Owner
private-key proof. A device code cannot activate Root or repair a lost signer.

Installation and subject/attempt states are separate. An initial attempt moves
`PENDING -> OWNER_APPROVED -> REGISTERED`, or closes expired/revoked/fenced.
`OWNER_APPROVED` means Hub durably accepted the exact Owner approval and capsule;
local trust acknowledgement has not completed. The first accept creates the
REGISTERED parent and subject. A registered parent stays REGISTERED while an
additional subject has its own PENDING/OWNER_APPROVED attempt. Failed additions
do not recreate, downgrade or strip existing Node bindings/grants.

REGISTERED permits only authentication, its own state and heartbeat. It grants
no Network/Group/peer, Worker/Manager, workspace, Runtime or administration
authority. Business permissions are independent 0..N grants. H1 must persist
server-assigned `NEW_REGISTERED_ONLY` versus `VERIFIED_LEGACY_ADOPTED` provenance
and check new subjects before every relevant legacy/no-N2/no-lease fallback.
In particular, absence of `hub_app_leases_v1` cannot imply broad Client rights.
Do not manufacture a legacy `CLIENT_CONTROL` enrollment or N2 history for App2.
C0 does not claim that this production guard work has been implemented.

## Exact bytes without circular digests

`J(x)` is UTF-8 `encoding/json.Marshal` of the named, fixed-order Go struct,
without maps, whitespace, trailing LF or unknown/duplicate fields. Decoding must
round-trip to identical bytes. Times are canonical RFC3339Nano UTC. `H` is
SHA-256, each domain is its exact Go ASCII constant followed by one NUL byte,
and `L` is a four-byte unsigned big-endian length. Digest/nonce concatenations
below use decoded fixed 32-byte values, not variable-length hex text.

Every participant supplies its actual trusted UTC clock, synchronized by its
operating system; time zones affect display only. Remote issuance lower bounds
have at most **30 seconds** of tolerance: `now >= issued_at - 30s` (or
`prepared_at - 30s`). Fresh request age remains at most 60 seconds. Challenge
issuance and approval preparation may precede B's local issuance by at most the
same 30 seconds when the Hub clock is behind. All expiry/session/accept deadlines
remain immutable and strict `now < expires_at` / `now < accept_before`, with
**no expiry grace**. Larger clock errors require correcting the local clock;
neither an original packet nor its times may be rewritten. No protocol time
service or Hub-selected historical clock substitutes for this premise.

1. `B = J(InstallationCandidateBase)`. B includes the full Hub/subject/admission
   public tuple, trust discriminator, local `issued_at` and `expires_at`. It
   contains no candidate/OOB/capsule/ACK/proof-derived fields. Its local expiry
   is immutable and at most issued + 10 minutes. A fresh start requires trusted
   now >= issued - 30s, now < expiry and age <= 60 seconds; a future issuance
   beyond 30 seconds is rejected without changing the original.
   `C = H(D_candidate || L(B) || B)`.
2. In FIRST_OOB only, the local installation persists independent random
   `S[32]`; `O = H(D_oob || C || S)`. Existing-pin mode has empty O and no S.
3. After both key PoPs, `T = J(InstallationApprovalBase)` includes C/O, exact
   verified possession receipt digest, existing complete Owner/App scope,
   subject digest, revision, prepare/preview digests, nonce and immutable times.
   T contains no capsule/ACK/final-proof derived fields.
   `t = H(D_approval_base || L(T) || T)`.
4. Owner App chooses independent random `X[32]` (not S or a Hub challenge).
   `P = J(InstallationTrustCapsule{format,T,OwnerPublic,S,X})`; in existing-pin
   mode S is strictly JSON null. `E = e2ee.Seal(Owner,AdmissionPublic,P,
   D_capsule_aad || t,1)`. E means the exact returned raw ciphertext bytes before
   transport JSON/base64. `e = H(D_capsule_digest || L(E) || E)` and
   `a = H(D_ack || t || X)`.
5. Finally Owner signs the canonical `{version,purpose=OWNER_INSTALLATION_REGISTER,
   approval:T,capsule_digest:e,ack_commitment:a}` under the separate Owner
   registration signature domain. Capsule P never contains this final proof,
   e or a; T never contains E/e/a. Thus B -> C/O -> PoP -> T -> E -> e/a -> proof
   has no cycle.

The source constants and machine manifest specify every exact domain, including
subject, original-packet, read-query, intent and finite-read-grant domains.
Purpose-specific proofs cannot be accepted as old OwnerDeviceGrant, Pair
consent/key grant, generic management or Runtime authorization.

## Independent Owner trust and key possession

`FIRST_OOB` uses a local secret ticket, delivered from the actual trusted
installation UI/terminal to the original Owner App through a trusted local/OOB
channel. Hub sees only O and encrypted E. Its short device code is a selector,
not a trust root. Hub-known request/credential/nonce values and a self-signed
Owner-public bundle cannot replace S. App independently matches its already
pinned Hub and recomputes the candidate before approval. The local receiver
checks E, the signature, T and its retained S before installing Owner trust.

`EXISTING_LOCAL_PIN` is a strict independent-local-input branch. Owner App does
not need another S or manual key-file transfer when adding a component. Its
existing trust source is exactly one of:

| Source | Required independent local facts | Parent effect |
| --- | --- | --- |
| `REGISTERED_PARENT` | Actual ACTIVE Owner pin/version, REGISTERED parent, retained admission private key, exact parent ID/epoch and current admission credential version | Keep parent and existing subjects/grants; add one approved subject |
| `LEGACY_NODE` | Actual ACTIVE original Owner pin and ACTIVE original Node identity/key, binding, epoch, credential and approved-request tuple; original Node key and bearer possession | First parent may be created, while original Node binding/keys/credentials/leases/grants/replay state remain unchanged |

LEGACY_NODE is only NODE_CONTROL + ADOPT_EXISTING, with no fabricated registered
parent/epoch/admission history. It never reuses an expired device code or requires
reinstallation. A Hub-supplied descriptor cannot substitute for the independent
`InstallationLocalPin` input. Missing/conflicting/revoked pins cannot fall back
to a weaker branch. Any already known Hub pin must still match. Original Node
Control pins and exact original Node coordinates remain mandatory.

For every mode, both admission and subject signatures **and KEM private-key
possession** are required. Start has the admission-signed encrypted request and
a subject-signed encrypted binding of its context/C/O; there is no self-containing
start-packet digest. Hub then draws distinct 32-byte admission/subject KEM
challenges and seals them separately to those exact public keys. Headers bind
purpose, C/O, Hub/installation/attempt, exact start packet digest, challenge ID,
recipient key, issued time and expiry (<= 2 minutes and original attempt expiry).
Public headers have null nonce. `prove` is an explicit durable mutation; subject
returns its decrypted challenge, admission returns its own challenge plus the
exact subject receipt digest. The verified receipt precedes Owner prepare.
Poll remains a read; it never implicitly completes PoP.

Node starts carry the actual original/new `NodeCredential` only inside the
Hub-addressed encrypted Start body. It is absent from B, tickets, Owner
challenges and diagnostics. Public commitment equality is not possession.
For adoption, Hub must compare the actual token's existing
`fabric.HashSessionCredential` digest, current credential version, original key,
binding/epoch and Owner record inside its writer. Rotation/revocation after
start invalidates a fresh accept. Do not persist plaintext bearers; retain the
original protected ciphertext and clear transient decrypted fields. An old key
with a stale bearer cannot adopt the current binding.

After local trust is durably saved, accept returns capsule-only X inside PQ
encryption, together with the original subject's signed/PQ acknowledgement of
C/t/e/Owner-proof digest/X/accept request/current tuple. Hub checks signed a,
both key PoPs, current original coordinates and revision CAS. Reporting public
digests alone cannot prove capsule decryption. S is never echoed to Hub.

## Short ticket and time rules

The single secret item is `cicada-ir1.<unpadded-base64url(J(array))>`, with exact
array `[1,origin,hub_id,full_CC_pin,full_NC_pin_or_empty,installation_id,
attempt_id,C_hex,S_base64url,expires_at]`. No PQ public key/signature is in it.
Origin is at most 256 bytes; HubID at most 96; the complete token is at most
1024 ASCII bytes on encode **and** decode. Origins use ASCII DNS names or
literal IPs with canonical ports; arbitrary URI reg-names/HTML metacharacters,
Unicode hostnames, userinfo, paths, fragments, queries including a bare `?`, and
noncanonical ports are rejected by this new protocol. Existing v1 validators
are unchanged. HTTP is restricted to explicit literal-loopback test policy.
App fetches full candidate data only from its exact pinned Hub, then recomputes
C/O and matches every ticket field. No truncation, short fingerprint or hidden
multipart fallback is permitted. Existing-pin additions do not issue a ticket.

`accept_before = proof_expires_at = min(prepared_at+5min, B.expires_at,
approving administration expiry)`. T's attempt expiry equals B's exact local
expiry. First local trust validation and a fresh Hub accept both require actual
trusted now < accept_before; no Hub statement that a proof was valid earlier can
authorize a first pin. Exact recorded local validation/accepted-original recovery
is historical, never a fresh admission. If local pin was saved but Hub accept
expired, preserve the independent trust fact without claiming REGISTERED or
business rights. Closing the approving App does not delete a committed bounded
approval; current key/device/epoch revocation still applies.

## Closed operations and shared-object reads

All operations below are separate typed POSTs. Only GET capabilities is public.
The explicit Hub Nodes composition is the intended future carrier; no Control
inference instance, Worker API, broad snapshot or arbitrary RPC is attached.

| Path suffix | Operation | Caller/effect |
| --- | --- | --- |
| `/v2/installations/start` | `installation.register.start` | Admission/subject proofs; reserve immutable candidate and KEM challenges |
| `/v2/installations/prove` | `installation.register.prove` | Exact independent KEM receipts; publish possession receipt only |
| `/v2/installations/poll` | `installation.register.poll` | Same admission; bounded historical/current attempt observation |
| `/v2/installations/accept` | `installation.register.accept` | Private ACK and subject proof; atomically close zero-business registration |
| `/v2/installations/self` | `installation.self.status` | This registered installation/recipient only, including its own grant refs |
| `/v2/installations/heartbeat` | `installation.self.heartbeat` | Only own liveness; no permission/lease renewal |
| `/v2/installations/reconcile` | `installation.reconcile` | Same admission or account device as original; receipt/fence only |
| `/v2/owner/installations/prepare` | `owner.installation.prepare` | Current Owner App + fresh exact preview intent |
| `/v2/owner/installations/complete` | `owner.installation.complete` | Current Owner App + original Owner registration proof |
| `/v2/owner/installations/revoke` | `owner.installation.revoke` | Exact Owner target/revision proof |
| `/v2/owner/app-access/prepare` | `owner.app_access.prepare` | Exact recipient/profile/target/revision Owner preview |
| `/v2/owner/app-access/complete` | `owner.app_access.complete` | Original Owner's finite fixed read-grant proof |
| `/v2/owner/app-access/revoke` | `owner.app_access.revoke` | Exact Owner grant/revision proof |
| `/v2/owner/connections/read` | `owner.connections.read` | Explicit disjoint read authorization described below |

The first independent-App profiles are exactly `N3_NODE_STATUS_READ` (one exact
current Node binding) and `N3_PAIR_STATUS_READ` (one exact Pair and original Node
binding), with fixed 15-minute absolute expiry. They reuse bounded N3/Pair
observations. They cannot Join, consent, revoke a Pair, sign Group key grants,
launch native work, read transcripts or mint other grants. All original
Owner-signed writes stay genuinely Owner-signed. Existing N3 and fixed Pair
permissions retain their original contracts and may be projected as tagged
references, never copied to another App.

`connections/read.authorization` is exactly one branch:

- `OWNER_READ_PROOF`: fresh original Owner signature under
  `OWNER_INSTALLATION_READ`, <= 60 seconds, over complete current scope and the
  exact query/request/nonce/target/page/cursor digest. The query digest excludes
  this proof and the containing packet digest. Login, Root ACTIVE and old N2
  history alone are insufficient, including after N2 lease expiry.
- `RECIPIENT_GRANTS`: current registered App/account session and only its own
  effective fixed read grants. Empty grant IDs means discover that recipient's
  effective grants, never Owner-wide inventory. No own grants returns only own
  state/empty shared objects, or GRANT_REQUIRED for a requested forbidden target.

Own authenticated state discovers grant refs automatically; users need not copy
grant IDs. The limit of 16 counts concurrently effective grants; expired/revoked
history does not exhaust a permanent quota. Grant effects/deadlines are independent
and retain immutable proof/receipt history. Each page rechecks current epochs,
grant state and exact targets. Hub owns shared registered objects and permissions;
another App never receives an old App's private keys, session, counters or outbox.
Uninstalling an App must not delete Hub/Node state or revoke existing rights.
Deleting the only Owner signing key still has no automatic password-only recovery.

## Recovery, bounds and paging

Before each mutation, preserve its exact ciphertext/request ID/nonce/digest in
the existing protected outbox. In the same Store writer transaction as effects,
persist the exact response, nonce consumption and target/revision provenance.
Concurrent claims/approvals/accepts have one CAS winner. Changed bytes under the
same ID conflict; no key/identity replacement, epoch reset or deadline extension.
Lost accept response retries/reconciles the same original; timeout remains UNKNOWN.

`OpenInstallationRequest` is a fresh entry and requires trusted current time.
`AuthenticateInstallationOriginal` is separate: it verifies canonical packet,
route/header/key/AEAD and typed body without a fake historical now, returning
`InstallationHistoricalOriginal`. It is only input to exact receipt recovery or
permanent fencing after matching a currently authenticated reconciliation actor.
It cannot authorize a new effect or first pin. A retained committed receipt is
returned byte-for-byte; an unadmitted mutation receives a durable exact-original
`REJECTED_FENCED` no-effect settlement. That settlement concerns only its original
mutation, not all current attempt/parent effects. READ_EXPIRED is only for pure
reads; malformed/unauthenticated HTTP failures never settle an uncertain write.
Restore cannot clear quarantine, revive revoked trust or reset replay floors.

| Bound | Bytes/count |
| --- | ---: |
| Ticket | 1,024 |
| Ordinary request plaintext / packet / original | 98,304 / 131,072 / 131,072 |
| Ordinary complete response packet | 262,144 |
| Reconcile plaintext / complete packet | 360,448 / 655,360 |
| One Owner proof | 65,536 |
| Shared page count ceiling / concurrently effective grants | 50 / 16 |

Both plaintext and complete encoded packets must fit; every nested JSON/base64
and PQ envelope expansion counts. Old decoder limits are unchanged. `page_size`
is only a count ceiling: full Pair observations include public keys and bounded
attestations, so a page must also stop at the complete response byte budget,
returning fewer rows plus NextCursor/Truncated. A legal single item must fit.
H2 encodes each row once, accumulates JSON bytes/commas and reserves actual or
worst-case encoded cursor bytes; it uses the deterministic
`InstallationResponsePlaintextBudget`/`InstallationResponseEncodedSize` model
and performs PQ Seal once for the final page, rather than repeatedly sealing
each trial item. The model is checked against actual production Seal bytes.
An oversize mutation rejects before admission; it is never partially published.

Heartbeat becomes STALE after 120 seconds but does not unregister, revoke,
rotate keys, renew grants or revive native leases. Polling is confined to the
bounded pending ceremony/explicit refresh; no additional daemon, coordination
service, dependency or automatic authorization renewal is introduced.

## Implementation checkpoints

C0 freezes contract/DTOs, exact proof framing, pure crypto/codecs, visibly
synthetic public vectors, bounds and checker, with availability false. H1 must
implement persisted zero-right admission/adoption, current ingress guards,
credential/Owner proofs, exact receipts/fences/reopen. H2 must implement the
independent fixed read grants and byte-bounded grant-filtered shared recovery.
Node local material/pin/ack and App independent registration/read-sync are
consumer-owned integration work. Root reviews C0 hashes before H1; availability
stays false until the complete three-component actual-carrier gate closes.

Synthetic crypto/codec/size checks do not establish Store/TCP, Windows DPAPI/GUI,
physical devices, public HTTPS, strict PQTLS or native Runtime conversation
acceptance. No real keys, providers, queues or resident deployments are operated
by this contract checkpoint.
