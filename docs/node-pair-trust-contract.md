# Node device pairing and independent Owner trust

Contract revision **node-pair-trust-v1**, format `cicada.node-pair-trust.v1`,
packet format `cicada.node-pair-trust-packet.v1`. The Node qualification
checkpoint enables this additive family (`available=true`) for the complete
App/Node qualification gate. Availability describes the implemented carrier,
not caller authorization or a claim that final physical acceptance has passed.
Shared and Hub checkpoint records below retain their historical availability
and tested-source attribution. C0 installation registration stays disabled. Frozen Client wire 1,
client-hub-v1.6.5/catalog 55, N2, app-node-authority-v1, native-pair-v1 and
installation-registration-v1.1 retain their existing identifiers and purposes.
In particular, this change enables no C0 registration carrier, admission key,
parent registration, App2 or generic role framework.

## User flow and independent trust

The default intended command is `cicada machine agent --hub-address IP:port`
with the existing Node ID/state/user-root options. The address is one canonical
numeric IPv4:port or [IPv6]:port; it is not the logical application origin.
The Node discovers only candidate public Hub/TLS information, requests its
actual Node-Control candidate, then displays one secret pairing code. The
already logged-in original Owner App accepts that code, shows the actual Node,
and requests one explicit approval. Hub retains and delivers the signed binding;
the Node proves receipt before joining. Later permissions remain independent
Owner-panel actions. No Owner public-key upload, descriptor SCP, reverse-order
setup or new daemon is a default prerequisite.

Only a genuinely pristine unpinned installation may discover a candidate.
Existing Hub/Owner IDs, keys, original credentials, epochs, binding and pending
packets remain authoritative and cannot be regenerated to bypass proof. An
existing binding with missing independent Owner trust takes the separate
`EXISTING_BINDING` trust-only branch. It never starts INITIAL or changes the
binding, old approval history, credential or key epoch. An existing ACTIVE or
REVOKED local Owner record under any different key ID conflicts; checking only
the newly returned key ID's absent row is insufficient. Rotation is outside
this contract. Revocation tombstones cannot be reopened.

The only manual transfer is **Node to App**, once. A Hub-generated short code
alone is an untrusted selector. The Node generates and durably retains independent
random **S[32]** before sending the original attempt. Hub never receives S in
plaintext or any Hub-decryptable request field. The App returns S only inside
the original Owner-to-Node PQ-encrypted trust capsule E. A false Hub with an
invented self-signed Owner cannot construct an E containing that retained S.
This assumes the user transfers the code from the actual trusted Node terminal
to the intended already trusted App. Theft of that secret code defeats this
independent channel; public lookup metadata does not replace it.

The code prefix is `cicada-npt1.` followed by canonical unpadded base64url of
the compact JSON array:

`[1,origin,hub_id,full_CC_fingerprint,full_NC_fingerprint,attempt_id,context_digest,selector,S_base64url,expires_at]`

The whole ASCII text is at most **1024 bytes**, on encode and decode. The
combined encoding bound also applies when individual fields reach their own
limits; no truncation or multipart fallback exists. Original selector is the
normalized existing 12-character Node device code for INITIAL, empty for
trust-only. The App decodes the entire code locally, preserving base64 case.
Only the decoded selector reaches `NormalizeAppNodeCode` and the old preview.
Passing the complete code into `user_code`, telemetry or an error log is forbidden.
The typed local code/capsule/secret request diagnostics are redacted.

The daemon must not print this secret into systemd/service logs. Intended
foreground display requires a real TTY. The companion local command is
`cicada machine pairing-code --id NODE_ID --state-dir DIR`, reading the same
protected state and requiring an interactive TTY rather than redirected output.
Background logs contain only sanitized state. The Node qualification checkpoint
implements these CLI names; earlier shared validation did not test a consumer. The existing explicit
`--hub-connection-file` / `--hub-dial-address` path remains an advanced trusted
installation path and cannot silently override an existing pin.

## Public discovery on one TLS socket

`hubtransport.DiscoverCandidate(ctx, numericAddress)` returns only
`DiscoveryCandidate{Descriptor, DescriptorText, DialAddress}`. It exposes no
HTTP client, Doer or trusted flag. The Hub's existing native TLS leaf chain now
also includes its already retained public root DER. No key/profile/descriptor
is regenerated, no system CA is installed, and the existing verified
`NewTransport` remains unchanged.

The first TLS 1.3 connection uses an empty RootCAs pool, numeric ServerName and
`InsecureSkipVerify=false`; it deliberately fails verification. Go's
`tls.CertificateVerificationError.UnverifiedCertificates` supplies only public
candidate chain data. Exactly one leaf and one bounded self-signed root are
required. There is no HTTP write on this connection.

A second private connection uses that candidate root, the leaf's sole SAN and
the same numeric socket, normal current-time x509 verification and exact live
SPKI. It sends exactly `GET /v2/hub/transport`, without Authorization, cookies,
body, query, proxy or redirects. Shared timeout is eight seconds, connect and
handshake/header waits at most three seconds each; header bound is 8 KiB,
descriptor text its existing 43715-byte bound. The response is exactly canonical
descriptor text, without LF. Live root, SAN, SPKI, descriptor signature and full
public identities must agree. Wrong/missing chain or certificate expiry rejects.

These checks establish public self-consistency only. They do not establish a
trusted Hub or Owner. Candidate state can send only the typed zero-right pairing
requests below, never an old bearer, password, App session or business packet.
App independently matches its retained exact logical origin, complete CC/NC
identities and exact saved descriptor digest (including CA/SPKI/epoch) before
sealing S. No network-discovered code/context may change its trusted profile.
The ordinary standard transport is constructed after candidate validation for
the bounded ceremony; promotion to normal business use waits for independent
S/E validation and authenticated ACKED outcome. Known-pin failure never falls
back to discovery, another address, plaintext or a weaker transport.

## Exact context, proofs and private ACK

All JSON is compact `encoding/json.Marshal` of the named fixed-order struct.
Unknown/duplicate fields, alternate order/whitespace, trailing LF and alternate
base64 spellings reject by exact canonical round-trip. `H` is SHA-256; each
domain ends in NUL. Framed hashes use `domain || uint32be(len(bytes)) || bytes`.
Nonce commitments use `domain || decoded_digest[32] || nonce[32]`.
The machine inventory is
`cicada-go/internal/hubaccountwire/node-pair-trust-contract.json`.

`NodePairTrustContext` fixes format, Node-generated attempt ID, complete Hub CC
identity, exact origin/descriptor digest, Node nonce, one discriminated original
INITIAL candidate or ACTIVE existing binding, and immutable issued/expiry times.
INITIAL retains the actual existing request ID/version, Node key/epoch, NC key,
selector digest and candidate digest. START responses recompute the **original**
candidate hash with the locally retained credential digest and complete tuple.
`nodewire.PairingCandidateBasis/PairingCandidateDigest` are the original Store
algorithm moved without byte/domain changes; Store aliases/delegates to it.
The returned Node public key must equal the actual original sender key.

Let C be the framed Context digest. `O=H(D_oob || C || S)` is committed once by
the same Node key. O, exact Context and original START bytes are durable before
the code is displayed. START is deduplicated by attempt, sender and exact packet;
its original sealed response retains the same Hub selector across lost replies.
Different bytes under the same request/attempt conflict rather than issuing a
replacement code, S or candidate.

An authenticated Owner/App lookup sends only selector, attempt, C, current
account token/scope and fresh request metadata. It returns exact stored Context
and O. App never reconstructs Hub times or a side-record Context from old preview
fields. `MatchNodePairTrustCode` requires the separately retained Hub, NC,
origin and descriptor digest; the returned O must equal its computed O.

App reuses its original N3 INITIAL preview, Owner finite grant and exact sealed
`nodes.confirm` packet. `NodePairTrustApproval` T binds C/O, actual current
Owner/account/App scope and epochs, original grant/proof digest, original
confirmation-packet digest, prepare request/digest, immutable server nonce and
deadline. Trust-only has empty grant and confirm digests; no fake INITIAL grant
is manufactured. After the explicit approval, Owner independently draws X[32],
distinct from S. E is existing `e2ee.Seal(Owner, originalNodeControlPublic,
{format,T,OwnerPublic,S,X}, D_capsule_aad || digest(T), sequence=1)`.

The final purpose `OWNER_NODE_PAIR_TRUST` signs T plus the raw E digest and
`a=H(D_ack || digest(T) || X)`. The existing ML-DSA signer signs a fixed 32-byte
claims commitment under `cicada/owner/node-pair-trust/v1\0`; it is a thin
purpose-specific adapter, not a new cryptographic primitive. No circular
commitment exists: Context -> C/O -> T -> E -> E_digest/a -> Owner proof.

The Node opens E with its original private key and checks retained C/O/S, Owner
signature, complete T and X commitment. Signature self-consistency alone cannot
install trust. First validation requires the actual nonzero local clock and
strictly precedes accept_before. It durably saves exact proof/E, verified trust
facts and original ACK before sending X with a Node-signed PQ ACK. S is never
echoed to Hub. ACK additionally binds exact original poll packet/receipt,
Owner proof and capsule digests; Hub retains that original delivery receipt
until the attempt/accept/reconciliation window closes.

Context lifetime is at most ten minutes, a fresh request age at most 60 seconds,
and issuance skew at most 30 seconds. T's accept_before is no later than
prepared+5min, Context expiry, current approving session and original INITIAL
proof/lease expiry. There is no expiry grace or permission renewal. Exact local
validation recorded earlier remains a historical trust fact if Hub acceptance
expires; it grants no binding/business readiness. First pin cannot be installed
late using Hub's claim about past validity.

## Closed HTTP operations and public API

Only GET descriptor and GET `/v2/node/pair-trust/capabilities` are public.
`NodePairTrustContractCapabilities()` currently returns available=false.
All following paths are purpose-specific POSTs carrying the new packet format:

| Path suffix | Operation | Typed request |
| --- | --- | --- |
| `/v2/node/pair-trust/start` | `node.pair-trust.start` | NodePairTrustStart |
| `/v2/node/pair-trust/existing` | `node.pair-trust.existing` | NodePairTrustExistingStart |
| `/v2/node/pair-trust/commit` | `node.pair-trust.commit` | NodePairTrustCommit |
| `/v2/node/pair-trust/poll` | `node.pair-trust.poll` | NodePairTrustPoll |
| `/v2/node/pair-trust/ack` | `node.pair-trust.ack` | NodePairTrustACK |
| `/v2/node/pair-trust/cancel` | `node.pair-trust.cancel` | NodePairTrustCancel |
| `/v2/node/pair-trust/reconcile` | `node.pair-trust.reconcile` | NodePairTrustReconcile |
| `/v2/owner/node-pair-trust/lookup` | `owner.node-pair-trust.lookup` | NodePairTrustOwnerLookup |
| `/v2/owner/node-pair-trust/prepare` | `owner.node-pair-trust.prepare` | NodePairTrustOwnerPrepare |
| `/v2/owner/node-pair-trust/complete` | `owner.node-pair-trust.complete` | NodePairTrustOwnerComplete |
| `/v2/owner/node-pair-trust/status` | `owner.node-pair-trust.status` | NodePairTrustOwnerStatus |
| `/v2/owner/node-pair-trust/cancel` | `owner.node-pair-trust.cancel` | NodePairTrustOwnerCancel |

Packet headers fix operation, request/attempt IDs and actual sender public key.
Existing PQ Seal authenticates/encrypts the body to Hub CC, binding canonical
header, complete Hub identity and REQUEST purpose in AAD. Responses use the
opposite direction and exact original packet digest. Only the original Node
key can poll/ACK; no original bearer is sent before proof. **The old
pollMachineNodeControlPairingStatus path sends a bearer and must never run in
this pending ceremony.** App requests separately authenticate its actual current
account/device/Owner source; a body-supplied scope or public capability is not
authorization. The original Hub Identity/Authorization services are reused;
Control inference is not part of authentication.

Shared entry points in `hubaccountwire` are `Encode/DecodeNodePairTrustCode`,
`MatchNodePairTrustCode`, `NodePairTrustContextDigest`, `NodePairTrustOOBCommitment`,
`ValidateNodePairTrustContext/Approval/InitialAuthorization/Accepted`,
`SealNodePairTrustApproval`, `VerifyNodePairTrustOwnerProof`,
`OpenNodePairTrustCapsule`, `VerifyNodePairTrustACK`,
`Seal/OpenNodePairTrustRequest`, `Seal/OpenNodePairTrustResponse`,
`AuthenticateNodePairTrustOriginal`, `OpenNodePairTrustRecoveredResponse` and
the purpose-specific digest helpers. `OpenNodePairTrustResponse` receives the
retained typed request as well as its original raw packet, preventing guessed
Context/O/selector or initial tuple replacement. The caller must compare O and
perform current service Guard; cryptographic opening alone does not authorize.

## Durable state machine and confirmation slot

The carrier must implement `PENDING -> OWNER_APPROVED -> ACKED`, with EXPIRED,
CANCELLED, REVOKED and FENCED terminal outcomes. An immutable per-candidate
RequireACK flag is written atomically with new candidate creation. All original
confirmation writers, including compatibility Control paths, Client RPC and
App exact retry/recovery, must honor it. A client-supplied bypass boolean is not
an authority input. No binding/credential is activated by OWNER_APPROVED.

Owner prepare/complete durably reserve the exact original Client confirmation
packet, counter and response slot. Other App business writes cannot advance or
overwrite that slot while pending. Ordinary `nodes.confirm` retries return the
ACK-required outcome without performing its effect. ACK rechecks actual current
Owner/App/device/key, account/session epochs, N3 head, finite grant, candidate,
deadline and expected revisions. In one writer transaction it reuses the
existing `appNodeClient` / `confirmNodeControlKeyRequestTx`, consumes exactly
one confirmation, activates the existing binding type, writes its original
Client receipt at the reserved sequence and seals Node ACK receipt. App status
then returns that exact original Client confirmation response. No resealing,
counter reset or duplicated consumption is permitted.

Closing App does not cancel the stored approval or require it online for ACK.
Logout, expired session or explicit revocation still constrain acceptance.
Node-local OwnerKeyTrust installation after verified S is exact/idempotent,
rejects other/revoked keys for that Owner, and does not grant a route. A stored
pin while ACK is unconfirmed is only a trust fact/pending admission; no Relay,
Join, peer, Network, Group, Runtime or execution authority becomes ready.
After ACKED, all existing business Guards and original packet/replay rules stay.

## Original recovery and bounds

Requests are saved once and retried byte-for-byte. Reconcile carries the exact
old packet and digest under the same original sender/attempt. Nested reconcile
is forbidden. A `RECOVERED` result contains only original_packet_digest and the
exact sealed original_receipt; no current Context/binding/business projection
may substitute for it. `OpenNodePairTrustRecoveredResponse` authenticates the
outer response, then opens that original receipt with the old raw packet and
retained typed body, checking operation/request/attempt/digest/recipient again.
It returns historical result plus exact bytes, never fresh first-pin authority.
An unrecorded original must be durably fenced with no effect in the writer
before returning FENCED. It must not be dispatched or inferred from current
ACKED state. Response caches contain encrypted originals, not plaintext S/token.

| Item | Byte ceiling |
| --- | --- |
| Pairing code | 1024 ASCII bytes |
| Owner proof / capsule plaintext | 64 KiB |
| Raw encrypted capsule | 128 KiB |
| Ordinary request body / packet | 256 / 512 KiB |
| Ordinary response body / packet | 512 / 1024 KiB |
| Reconcile original request | 512 KiB |
| Reconcile request body / packet | 896 / 2048 KiB |
| Recovered raw original receipt | 1024 KiB |
| Reconcile response body / packet | 1536 / 3072 KiB |

Complete encoding must fit its whole-message ceiling even if every individual
field reaches a separate maximum. Reconcile's larger response bounds cover
the original receipt's JSON/base64 and PQ envelope expansion; they do not expand
ordinary routes. Oversize is rejected before mutation. Service integration,
concurrency/crash/fault recovery, App/Node actual process gate, Windows security,
physical devices, public-IP/IPv6 and native Runtime remain separate validation.

## Shared checkpoint producer validation — 2026-10-24

`node-pair-shared-20261024T070538Z` tested dirty parent
`cfe33e0a735ea838f14eda7d3f283f5603cac36f`, not merely that HEAD. Go input
manifest SHA-256 is
`ea3df6516dd1786d9e41fe2c69867fa2ab7ac677be0faa4319d81edaa7f27290`;
full source manifest is
`b2ddea19af32e81d23f3e90f5de463e0b2e2a3d2b5048f0e263cd13a08ae1afa`.
Before/after inventories match. Evidence, exact argv and raw output are outside
Git at `/home/zyf/Cicada/.local/evidence/hub-native-tls/` under that run name.
Aggregate receipt SHA-256:
`e93fd9cf8c7b2403b1f751d1bf0bd5261942f41bc48527229d18f568ded51eb7`.

Normal checks passed exit 0: **168** test/subtest outcomes, **59** top-level,
no failures/skips, across hubaccountwire, hubtransport and Store. The selector
includes NodePair and original NodeControl, Profile, NativeTLS, AppNode and
Installation regressions. New NodePair crypto/socket race checks passed exit 0:
**50** outcomes, **13** top-level, no failures/skips. Vet passed for e2ee,
nodewire, hubaccountwire, hubtransport and Store. Go is 1.27.3, modules are
offline/read-only, private fixtures use umask 0077. No shared Hub, real keys,
model, system CA, public listener or resident deployment was used.

Actual synthetic TLS sockets cover public candidate discovery, no-root/wrong-
root/expired chains, wrong SAN/SPKI, foreign/tampered/oversized descriptors,
redirect refusal, numeric-only addressing and cancellation. Persisted native
profiles publish their retained public root and preserve exact descriptor/keys.
The original standard transport still refuses another pin after discovery.
The HTTP handler is a bounded synthetic fixture, not the future production
public-discovery handler or a complete Node pairing.

Crypto/wire tests cover independent S, self-consistent false-Owner rejection,
retained origin/transport digest checks, exact lookup, complete START
credential/candidate tuple, explicit trust-only, fresh time, private X ACK,
closed typed operations and double-authenticated original receipt recovery.
The full **1-MiB opaque** original slot is exercised through actual PQ Seal/Open
and its dedicated response budget; double opening still rejects invalid inner
bytes. A separate genuine authenticated poll receipt recovers byte-for-byte.
The opaque size fixture does not prove a valid decrypted capsule, completed
ACK or maximal production history. Initial smoke found base64 LF acceptance;
exact text round-trip now rejects it before these formal results.

QA then requested two bounded recovery hardenings: terminal reconcile accepts
only the explicit no-effect `FENCED` error; the recovered-result helper itself
rejects recursive original operations. These affect only the new shared helper
and its focused tests. Their later delta results remain separately attributed;
the preceding formal run is not relabelled as that later source.

The delta run `node-pair-shared-delta-20261024T070917Z` passed its focused
normal and race checks, each **14** outcomes / **1** top-level, no failures or
skips, and hubaccountwire vet exit 0. Its unchanged before/after Go manifest is
`27c1063dce930fcfa4ed12923340c2f2789f2f6d04f05bbf3f3c52f042da855c`,
full manifest `9761dcd693c22ea79ef8565f239e565248409004de4cef801974c8dd77528961`,
and aggregate receipt SHA-256
`8048c0c0c48174be483e0a3a9adcfbfeb56312a4dfd7670894568c77cba4f847`.
Only this final prose was appended afterward; tested Go inputs remain exact.

Public availability remains false. Root explicitly deferred shared-only Docker
to QA's disposable full-carrier gate, so Docker here is **NOT_RUN**, not PASS.
Actual Store transitions, reserved original counters/slots, all RequireACK
writers, same-Owner cross-key rejection, App-close ACK and original-process
recovery remain required carrier gates. Windows security, physical/public IP,
Android and native Runtime are also **NOT_RUN** for this shared checkpoint.


## Hub service and transactional carrier

The `--hub-nodes-only` composition serves the fixed public GET and twelve typed
POST routes through HubAuth's existing bounded workers/rate admission. It requires
the retained native TLS descriptor and exact original CC/NC identities. It creates
no Control inference service. Cookie/Authorization headers are rejected before
reading pairing POST bodies; public GET also rejects query, body and chunked
encoding. Ordinary and reconcile packet ceilings remain distinct. Failures are
sanitized; waiting old `nodes.confirm`/reconcile returns HTTP 409 ACK_REQUIRED
without sealing a new Client response or advancing its counters. Capacity is 503.
Public availability stays false until the missing consumers and full gate land.

Schema 68 adds the side attempt and an independent, monotone
`require_pair_trust_ack` marker to the actual original candidate in the same
transaction. Every original confirmation writer checks that marker centrally.
A marked candidate with missing side state fails closed. No boolean supplied by
a caller can bypass the gate. Existing confirmed Nodes use the authenticated
trust-only path, preserving their complete binding, credential and all epochs.

Owner prepare fixes the original encrypted Client confirm packet, reqSeq,
respSeq, operation ID/digest, Owner/device/session epoch in a RESERVED side slot.
It does not insert an original PROCESSING row or advance either counter. A SQL
trigger blocks all competing counter updates within that session epoch. Security
revocation and epoch advancement remain possible. Complete stores the exact
Owner signature and encrypted E without confirming the Node. Node ACK proves X
and the exact authenticated OWNER_APPROVED poll packet/receipt. Only its single
transaction enters internal ACKING, checks current retained Owner/App authority,
executes the original `appNodeClient` once, writes the original Client receipt,
marks the slot DONE and saves the ACKED Node response. ACKING is never committed
as intermediate state. A failure to seal either response rolls everything back.
Closing the App connection requires no online callback and is not logout.

Fresh Node poll, Owner status and either cancel may carry a structurally valid
expired Context so they can observe the real terminal result. Each newly issued
request still has the original one-minute freshness bound and all current caller
Guards; this never renews proof/acceptance deadlines. Cancel returns the actual
immutable terminal state if one already exists: CANCELLED, EXPIRED, REVOKED,
FENCED or ACKED. INITIAL OwnerCancel ACKED, like OwnerStatus ACKED, **must** carry
the exact original ConfirmationResponse. App must authenticate it using its
retained original Client packet/response slot and settle once before displaying
admission. Trust-only OwnerCancel and NodeCancel never carry that App receipt.

Expiration/cancellation/revocation releases only the side reservation. The
candidate marker stays permanent and raw old confirm cannot activate it. Only
the authenticated old app-node reconcile of the exact original Client packet
can create/return an original negative response and settle that counter once.
An old epoch never settles into a replacement epoch. NPT reconcile fences only
one exact original packet; FENCED does **not** imply that the whole attempt is
terminal. Consumers query current status or explicitly cancel the attempt before
settling it. A missing original is shape checked at its original issued time,
which cannot be later than the current writer time plus 30 seconds, so a short
recovery fence cannot expire before a far-future request becomes admissible.

Anonymous attempt metadata is capped at 512 rows/16 MiB. Ephemeral encrypted
read cache is separately capped at 4096 rows/16 MiB, 64 per attempt, and 60 new
reads per sender/attempt/minute. Ordinary reads live two minutes; start/commit
originals retain the immutable attempt expiry plus ten minutes. Indexed GC
reclaims at most 256 expired reads/rates and unapproved attempts per transaction,
including their unapproved original candidates. It preserves Owner-prepared
history, all authorized receipts and marked missing-side candidates. Singleton
statistics and SQL triggers enforce byte/row budgets without global receipt
scans. Owner prepare reserves 12 MiB in a separate 256-MiB authorized budget;
OWNER_APPROVED polls are at most 64/10 MiB per attempt, leaving ACK capacity
independent of anonymous read exhaustion. Consumers must back off polling to
respect these bounded observation windows; five-second polling is suitable for
one Node plus one App. Limits reject rather than silently evict approved history.

Hub restore retains its fully reviewed schema pin at **67**. Schema 68 permits
only the previous capabilities when all six NPT tables exist, all five state/
receipt/cache/slot tables are empty, the budget singleton is exactly zero and
every original candidate RequireACK marker is zero. Both read-only inspection
and coverage comparison enforce this. Any missing table, NPT state, nonzero
budget or marker is UNSUPPORTED (`ErrHubRestoreCoverage`). Recovery of NPT
reservations, capsules and receipts requires a separate forward/UNKNOWN review.
Normal non-restore startup/reopen remains supported and retains those records.

## Hub carrier producer validation — 2026-10-24

This checkpoint tests dirty parent
`a9b1f43a38bbea896ba9eda1ff4667d2b97e3902`; it does not attribute a dirty build
solely to that Git revision. Fixed-source evidence is under
`/home/zyf/Cicada/.local/evidence/hub-native-tls/`:

| Run | Exact result |
| --- | --- |
| `node-pair-server-20261024T080505Z` | Normal exit **1**: 362 PASS, 1 FAIL, 2 SKIP, 164 completed top-level outcomes. Original failed receipt remains unchanged. |
| `node-pair-server-resume-20261024T080915Z` | Fixture-only normal delta exit 0: 19 PASS, 0 FAIL/SKIP, 9 top-level. Race exit **1**: 55 completed outcomes PASS, then Store's 240-second package timeout. |
| `node-pair-server-race-tail-20261024T081528Z` | Only the two unfinished race top-level tests resumed separately: each exit 0, 1 PASS, no FAIL/SKIP. Vet seven packages exit 0. |

The normal failure was an obsolete pre-v61 synthetic migration fixture: it
removed every later ledger row but left schema 67's native TLS table, causing a
real re-open failure before schema 68 could apply. The fix removes only synthetic
67/68 objects and the 68 column and also updates the existing historical Network
fixture helper. The resumed run covers that failed case plus affected historical
Network/V2 migration fixtures. A manifest comparison proves these **two test
files** are the only changes between the normal and resumed sources; production
blobs are identical. The original successful normal cases are carried forward,
not rerun or relabelled as a clean original package pass.

Race slowdown exceeded the original package budget; no data-race diagnostic or
individual failing test preceded timeout. The original package failure is not
changed to PASS. The exact unfinished trust-only and expired-observation tests
were resumed once each. Together with the prior 55 completed outcomes, all
**20** declared NPT top-level tests are accounted for. Original normal skips are
`TestHubBoundedCapacityDocker` (isolated Docker fixture absent) and
`TestHubForwardPrepareRejectsPhysicalBindCapsuleBeforeFence` (two disposable bind
mounts absent), each retained as NOT_RUN rather than PASS.

Every run has matching before/after full source inventories. The final tested Go
input manifest is
`4505fedfda4d49c4214b0c5a728f519d3939c1698e54becfdf2902038ccaeeab`;
its full tested source manifest is
`950bc5b274d8099a0f3cbe267515fae2fc86613385c23e535f6a35a48040d6bb`.
Only this validation prose was appended afterward. Aggregate evidence file
`node-pair-server-checkpoint-evidence.json` has SHA-256
`3b6ee3e896a45236b917945a1e2c712f17a8c9d5afd9612d4939e8a169742394`.
It preserves original receipt hashes, exact argv and source comparisons. Go is
1.27.3; modules are offline/read-only, GOMAXPROCS=2 and synthetic private
fixtures use umask 0077. Vet covers e2ee, nodewire, hubaccountwire, hubtransport,
hubauth, server and Store.

Actual production HubAuth/Server on a private synthetic TLS socket covers public
discovery, original N2 activation/login, actual NPT candidate/lookup, wrong App
and wrong Hub rejection, old finite grant plus original Client confirm, HTTP
409 before ACK, App connection closure without logout, S/E verification, private
Node ACK, original Client response/counter opening, exact START/ACK retry and
late OwnerCancel ACKED returning the same original receipt. It found and fixed
the old Client route's missing ACK_REQUIRED HTTP mapping. Test HTTP retries only
the existing bounded service's explicit transient busy response.

Store tests cover reopen and rollback before ACK response sealing; central old
direct/N3 confirm/reconcile gates; concurrent prepare's single winner and eight
concurrent ACKs recovering one receipt/counter; timeout/cancel/logout/Owner
revocation/App epoch change rejecting an otherwise valid retained ACK; missing
side state under a marked candidate; bounded anonymous GC and a completely full
read cache leaving reserved ACK capacity; original-only no-effect reconciliation;
trust-only preserving the existing binding/candidate/counter; and fresh expired
observations without original Client settlement. Existing restore positive tests
remain executable; an empty NPT schema 68 retains legacy restore, while any NPT
state/marker is explicitly unsupported.

This is a Hub carrier checkpoint, not full user acceptance. Availability remains
false. Node default-address/TTY/sealed-secret consumers, same-Owner cross-key
receiver enforcement, integrated App consumer and actual Node/App process gates
remain subsequent work. Docker full-carrier, physical bind mounts, Windows,
physical devices, public HTTPS/IP/IPv6, Android and real native Runtime are
**NOT_RUN** here. No shared Hub, real credential, model change, system CA,
public listener or resident deployment was used.

A final bounded resource delta was reviewed before the same carrier commit:
no-effect FENCED originals and existing-terminal cancel observations must use
the TTL cache rather than the permanent authorized budget. Only the first real
CANCELLED transition retains one critical cancellation receipt, using an indexed
existence check in the same transaction. Successful prepare/complete/ACK receipts
remain immutable. This prevents one formerly approved Node from repeatedly
burning global permanent capacity with newly signed historical no-effect packets.

`node-pair-server-budget-delta-20261024T082246Z` freezes that final source:
normal **9/0/0**, four top-level tests, exit 0; race **2/0/0**, two top-level,
exit 0; Store vet exit 0. It covers permanent receipt accounting for a real first
cancel, bounded repeat cancel/ACKED observation, post-ACK garbage original fences,
and a formerly valid original poll being rejected after its short fence expires.
The terminal suite and real TLS late OwnerCancel receipt also pass on the delta.
Compared with the prior frozen source, exactly the budget implementation, its
Store test file and the preceding validation prose changed; no other production
blob changed. The source inventories match before/after.

Final tested Go input SHA-256:
`651cf3c9fb0dd2dde8dfae3d2e74892b9ffb56ec93126f39782c6bef0751a803`;
full tested source manifest:
`f64531a82059335981820c91c4459fef5d118345fadfe8a60a94e9d0a27d18d9`;
final delta receipt:
`2aab382919ace5371ebd666021fce1a4c85da17beb1404c8bce0a6a969c3be04`.
The prior combined evidence remains immutable. Final combined evidence is
`node-pair-server-final-evidence.json` (same external evidence root); its hash is
recorded in the checkpoint delivery. The source inventory and completed-test
union account for all **21** final NPT top-level tests. The original normal
failure/skips and race timeout remain visible in their own receipts. Only this
addendum follows the final frozen run; final Go blobs remain exact. No Docker
or physical result is promoted to PASS.

## Retained original binding subset

The next Node consumer uses the existing `node.pair-trust.existing` route when
its trusted native transport and original key/credential are already readable,
but its historical local state lacks the full public binding. ExistingStart
adds optional `retained_binding` with exactly the fourteen fields in the machine
manifest. Full Context.Binding and RetainedBinding are strictly exclusive;
Candidate is always absent. Only this request envelope may omit Binding.

The subset carries every original locally saved Node/binding/NC key and epoch,
original approved-request coordinates and the original credential **digest**.
It carries no bearer and invents no Owner/device/credential version. Hub verifies
the original Node signature/full key, loads the actual ACTIVE binding by exact
digest/Node ID, compares every retained coordinate and fills only Binding in the
returned Context. All other Context fields must match exactly. The completed
Context remains subject to the same S/O/E/ACK ceremony and unchanged binding.
Full-binding ExistingStart remains supported. This path cannot discover a new
transport for a partially populated legacy state or repair a missing key,
credential, native descriptor or revoked/conflicting Owner pin.

A reconcile query is a bounded observation about its immutable target original.
If that outer read ages beyond the request freshness window after response loss,
a consumer may persist a new fresh reconcile request ID/issued time, retaining
exactly the same OriginalPacket/OriginalPacketDigest/attempt/sender. It never
replaces the original mutation, nests reconcile or renews S, T, E, proof, confirm,
ACK intent or acceptance deadline. A returned FENCED result still fences only
the targeted original, so the consumer reads current attempt state afterward.


## Node consumer qualification

`machine agent --hub-address IP:port` performs the ceremony while holding the
existing Agent and WriterRoot locks, before ordinary transport activation,
local business discovery, bearer probes or heartbeat. Only a pristine Node may
perform candidate discovery. A retained pending attempt reuses its exact
original descriptor, address, Node key, credential, S, nonce, proofs and packets.
Existing bound Nodes require their original readable trusted native transport
and use RetainedBinding; a legacy/incomplete state cannot fall back to INITIAL.
The original advanced descriptor/dial flags remain separate and cannot bypass
a pending Node pairing marker.

`node-pair-trust.sealed.json` lives in the existing Node state subtree. Its outer
public coordinates are AAD; the entire secret journal is sealed Node-to-itself
using the original Node-Control key and existing e2ee primitives. State/file
paths reject symlinks, require same-user ownership and 0700/0600 permissions.
S and derived full code never enter public describe/ordinary Node state. The
ordinary state adds only the attempt ID as a fail-closed admission marker.
Missing original key, credential, routing or sealed state never generates a
replacement. Existing restore quarantine and process locks remain authoritative.
The new secret-storage ownership guard is verified on Linux; Windows/other
unavailable ownership mechanisms fail closed pending their own validation.

Original requests are durably sealed before network I/O. Exact retries retain
operation/request/attempt IDs and all bytes. An aged request uses fresh reconcile
observations of its unchanged original. An original FENCE is retained with its
authenticated receipt in bounded sealed history and does not close an attempt.
START/commit may create a new request only after known no effect, retaining the
same S, nonce/proof, Context and original deadline (START may refresh only its
request issued time before that deadline). ACK may create a new intent only
when its prior intent is explicitly fenced and a fresh poll still reports
OWNER_APPROVED, the real deadline is live and the current Owner pin recheck
succeeds. S/O/T/E/proof/X/original confirm stay unchanged; the new ACK binds the
new actual poll/receipt. Old ACK bytes stay archived. ACKED poll projection
requires recovery of an already saved, unfenced original ACK receipt; it cannot
install a binding by itself.

First trust calls OpenNodePairTrustCapsule on the live clock and verifies S
before opening the local Owner trust writer. The conditional Owner-wide SQLite
write rejects any existing other key ID, ACTIVE or REVOKED, and any same-key
tombstone/public-key conflict. Independent handles cannot race in two first
keys. Once a verified local trust fact has been saved, historical capsule
reopening requires that same current ACTIVE local pin and the protected accepted
time; it cannot install a missing pin late. Pin saved/ACK uncertain remains
pending admission. The sanitized local error
`NODE_PAIR_INDEPENDENT_TRUST_REJECTED` means the actual capsule trust check was
reached and rejected, without printing S or a payload.

A real original ACKED receipt is retained and checked before populating the
original Node-Control binding/routing fields. Existing binding, sequence,
credential, Node key and epochs are preserved. Repeated ordinary startup checks
this exact saved receipt and current local Owner trust under the original locks.
A second Agent cannot overwrite live state before acquiring its singleton lock.
Account login, public capability metadata and Control inference do not supply
this authority. Later Network/Group/Worker rights still need their own Guards.

`--retry-pairing` is an explicit modifier to `machine agent --hub-address`.
Without it, termination never automatically replaces S. It first obtains a
fresh authenticated current EXPIRED/CANCELLED/REVOKED observation, preserves the
old sealed journal and receipts in an attempt-named archive, and creates a new
attempt/code using the original descriptor/key/credential and the original
INITIAL-versus-EXISTING mode. Unknown or ACKED outcomes prohibit a new S. Existing
local trust facts must still pass the current Owner-wide check. A logout-induced
old REVOKED attempt can be followed by a fresh explicit consent after login;
a revoked local pin or inactive original binding/credential cannot be bypassed.
The old attempt/deadlines remain immutable. PreviousAttemptID plus the exact
archive digest recovers a crash between new sealed-state and public-marker
writes, without generating yet another secret.

If no Context ever arrived, explicit retry first reconciles the retained START.
RECOVERED restores its actual Context, then observes actual terminal state. If
all actually sent START originals have authenticated no-effect fences, the
original deadline has truly passed and no Context/O-commit/code/ACK fact exists,
the local intent may be archived as RETIRED_NO_EFFECT. This does not label the
whole remote attempt terminal. An uncommitted O may be observed only by its
original signed Node after the actual side attempt is terminal: State and
ErrorCode match, the payload is empty and O is never echoed or committed. Live
uncommitted observations remain refused; there is no Owner/business bypass.

Terminal side transitions retire the actual marked original candidate in the
same writer transaction. Its RequireACK marker remains permanently 1 and its
version advances. Explicit new attempts retain existing rate limits, including
the five-second reissue cooldown. An expired approval with a still-live original
candidate therefore cannot leave a false pending blocker. Old original Client
counters still settle only by the existing negative reconcile, once.

The qualification source enables only Node pairing availability. It does not
claim Docker full-carrier, actual App/Node 12-case, physical, public HTTPS/IP,
Windows, Android or real native Runtime acceptance. Those results belong to
QA's independently recorded gates after this checkpoint.

## Node producer record — 2026-10-24

Frozen dirty parent is `26cdacc996faf0ed3dc1b8cebb5b0ab770b17cc9`.
Evidence root: `/home/zyf/Cicada/.local/evidence/hub-native-tls/`.
`node-pair-node-20261024T095229Z`: normal exit **1**, 161 PASS / 1 FAIL / 0 SKIP;
receipt SHA `c057dbd2d8154791b7696cae4b2623f8f0d3640a103a2fe3efb86e4fccdbead7`.
The failure was the old shared test's false-availability assertion. Only that
assertion changed before `node-pair-node-resume-20261024T095531Z`: normal delta
1/0/0, four race lanes 7/0/0, 46/0/0, 4/0/0, 9/0/0, nine-package vet exit 0;
receipt SHA `152be2265179f8e53f26c01a19f3eca1dd21baa76e97fb0866b39dde577182b1`.
The 161 prior successes retain their original attribution; their production
blobs did not change. The original FAIL is preserved.

A final routing-only delta preserves a later verified current locator under the
same descriptor rather than restoring an ACK's historical locator. Only a first
binding with all three routing/binding fields empty installs the sealed address;
partial/missing bound routing fails closed. `node-pair-node-routing-delta-20261024T101427Z`
passed normal 1/0/0, race 1/0/0 and cmd vet exit 0; receipt SHA
`0b636d0801429c5cf1ecb5077c9d41dfa152cc935e8ad1dab2d19581ef5d7f27`.
Exactly the receiver and its focused test changed from the preceding frozen Go
source. Final Go input manifest is
`ba29da7c93d68c7c68b3be47e5f7b94d296bf99f4ee941703e419cf903310fb7`;
full tested manifest is
`21835a09df08228a74202a12406a7f06a337a2e5deea782d0eaccc587bb8271c`.
All run inventories match before/after; only this prose follows the last freeze.
Go 1.27.3, offline/read-only modules, GOMAXPROCS=2 and umask 0077 were used.
Actual Node START/commit/cancel/retry TLS, PTY code output, protected storage,
retained tuple and Owner conditional write are producer scope. Full actual
Owner/App/Node acceptance, ACK-loss/malicious-Hub process cases and physical
acceptance remain QA scope; they are NOT_RUN here. Root's old-wire Docker gate
passed on `1bba176` separately and is not attributed to this later Node source.
