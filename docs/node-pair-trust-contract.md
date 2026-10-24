# Node device pairing and independent Owner trust

Contract revision **node-pair-trust-v1**, format `cicada.node-pair-trust.v1`,
packet format `cicada.node-pair-trust-packet.v1`. This shared-code checkpoint
keeps public availability **false**. It defines codecs, proof primitives and
public TLS discovery; production HTTP handlers, transactional ACK gates, Node
consumers and App integration are the next checkpoint. Frozen Client wire 1,
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
Background logs record attempt and state only. This checkpoint defines these
CLI names; it does not implement them yet. The existing explicit
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
