# Node-scoped independent pairing trust

Contract **`node-pair-trust-node-scoped-v1`** accompanies
[Node-scoped finite App authority](hub-app-node-scoped-authority-contract.md).
The normal Hub Nodes composition advertises **`available=true`** and enables
scoped pairing POSTs when its independently bound native TLS descriptor is
available. A missing or invalid descriptor still fails discovery closed. The
existing [NPT v1](node-pair-trust-contract.md) identifiers, packets,
EXISTING_BINDING semantics and installed identities remain unchanged. Codec,
carrier and consumer qualification retain their own source in the
[validation ledger](hub-app-node-scoped-authority-validation.md).

## Closed formats and version chain

| Item | Exact value |
|---|---|
| Context/DTO format | `cicada.node-pair-trust-scoped.v1` |
| Encrypted packet format | `cicada.node-pair-trust-scoped-packet.v1` |
| Packet wire Version | 1 |
| Context ScopeVersion | 2 (`scope_version`) |
| Context exact Node | required `authority_node_id`, equal to actual Candidate.NodeID or Binding.NodeID |
| Approval Scope | independent `e2ee.OwnerAppNodeScopedScope`, Version 2, same AuthorityNodeID |
| Owner claims Version/Purpose | 2 / `OWNER_NODE_PAIR_TRUST_SCOPED` |
| Owner signature domain | `cicada/owner/node-pair-trust-scoped/v1\x00` |
| Local code prefix | `cicada-npts1.` |
| Code compact schema version | 2 |
| Public discovery | GET `/v2/node/pair-trust-scoped/capabilities` |

New DTOs are `NodePairTrustScoped{Context,Approval,OwnerClaims,OwnerProof,Capsule,
Packet,Start,ExistingStart,Commit,Poll,ACK,Cancel,Reconcile,OwnerLookup,
OwnerPrepare,OwnerComplete,OwnerStatus,OwnerCancel,Result,Code,Capabilities}`.
Only immutable existing candidate/binding and retained-binding leaves are shared.
Start explicitly includes `scope_version=2` and its actual NodeID; subsequent
Context carries that same Node ID and version throughout. No Scope2 is placed
inside an old NPT approval or decoded by trying the old parser.

The compact secret code is base64url of canonical JSON array:
`[2,origin,hub_id,hub_fingerprint,node_control_fingerprint,attempt_id,
context_digest,selector,base64url(S),expires_at,authority_node_id]`.
Its new bound is 1536 bytes, covering the added Node ID at the old worst-case
origin/Hub bounds; the old code's 1024-byte bound is unchanged. S and independent
ACK nonce X remain 32 random bytes. S is transferred privately between the
actual Node and App and never enters a request DTO or evidence. The code gives
the App a Node ID before its scoped owner lookup; the signed/pinned context and
full independent Hub/Node-Control identity must still match it.

Every context/approval/capsule/proof/packet/ACK/OOB/descriptor digest or AAD uses
the existing algorithm with the independent prefix
`cicada/node-pair-trust-scoped/` and the corresponding old suffix, including
`context/v1\x00`, `approval/v1\x00`, `capsule/v1\x00`, `proof/v1\x00`,
`packet/v1\x00`, `ack/v1\x00`, `oob/v1\x00`, `descriptor/v1\x00`,
`owner-claims/v1\x00`, `capsule-aad/v1\x00`, `packet-aad/v1\x00`.
The same ML-DSA/PQ envelope services are reused. Scope and Node tampering,
old-domain signatures, missing S and cross-family originals are rejected.

## Operations and consumer API

Each suffix below maps to POST under the exact route prefix. Operations use
the exact operation prefix shown, followed by a period and suffix.

| Actor | Route prefix | Operation prefix | Suffixes |
|---|---|---|---|
| Original Node | `/v2/node/pair-trust-scoped/` | `node.pair-trust-scoped` | `start`, `existing`, `commit`, `poll`, `ack`, `cancel` |
| Original sender, Node or App | `/v2/node/pair-trust-scoped/` | `node.pair-trust-scoped` | `reconcile` |
| Existing App | `/v2/owner/node-pair-trust-scoped/` | `owner.node-pair-trust-scoped` | `lookup`, `prepare`, `complete`, `status`, `cancel` |

The App also uses `node.pair-trust-scoped.reconcile` at
`/v2/node/pair-trust-scoped/reconcile` to recover its own exact Owner request.
Reconcile requires the same original SenderPublic, AttemptID and complete
original-packet digest. It only authenticates historical result recovery or a
permanent no-effect fence; it cannot query another sender, create fresh business
authority, change Client sequences, spend another confirmation or replace the
pending original with a newly sealed write. Node and App use the same closed
reconcile DTO and recovery codec.

Capability format is `cicada.node-pair-trust-scoped.v1`, revision above,
`scope_kind="NODE_V1"`, `scope_version=2`, `available=true`, exact 12 operations,
modes `INITIAL_CANDIDATE` and `EXISTING_BINDING`, prefix and bound above.
`DecodeNodePairTrustScopedCapabilities` requires an available exact document;
it does not authorize a caller. Do not create pending state or send secret
scoped POSTs on false/unknown/old discovery.

| API | Exact typed input/output role |
|---|---|
| `EncodeNodePairTrustScopedCode` / `DecodeNodePairTrustScopedCode` | actual scoped Context + selector + local S / local code + current time |
| `MatchNodePairTrustScopedCode` | local code + authenticated Context + independent trusted Hub/Node-Control/origin/descriptor digest; returns OOB commitment |
| `NewNodePairTrustScopedRequestBody` | closed operation to pointer DTO; unknown operation returns nil |
| `SealNodePairTrustScopedRequest` | existing sender identity, pinned Hub, `NodePairTrustScopedPacket{Operation,RequestID,AttemptID}`, exact operation DTO, current time |
| `OpenNodePairTrustScopedRequest` | existing Hub identity, exact operation and typed decode target; verifies scope version/Node chain |
| `ValidateNodePairTrustScopedInitialAuthorization` | exact Context/Approval, retained scoped grant proof and `n3s.` confirmation packet |
| `SealNodePairTrustScopedApproval` | existing Owner signer, exact Context/OOB/Approval, local S, independent X, current time; returns proof and capsule |
| `OpenNodePairTrustScopedCapsule` | actual original Node private key, retained Context/OOB, exact proof/capsule, retained local S and current time |
| `VerifyNodePairTrustScopedACK` | exact Context/OOB/proof/capsule and actual Node ACK; Store must also check original poll receipt and current Guard |
| `SealNodePairTrustScopedResponse` / `OpenNodePairTrustScopedResponse` | original exact request and typed original body; authenticated result |
| `OpenNodePairTrustScopedRecoveredResponse` | exact reconcile and retained original body; returns authenticated original result plus identical receipt bytes |
| `ValidateNodePairTrustScopedAccepted` | locally S-verified Approval and authenticated ACKED exact Binding; historical result does not authorize first trust late |

There are no implicit owner-DTO constructors: initialize the explicit scoped
DTO with its Format, current SessionToken, scoped Scope, exact Context/OOB and
IssuedAt, then use the closed sealer above. OwnerLookup uses locally decoded
Selector/ContextDigest and Scope.AuthorityNodeID from the protected local code.
OwnerPrepare additionally carries the exact scoped GrantProof and retained
ConfirmationPacket for INITIAL. OwnerComplete carries exact OwnerProof and
TrustCapsule. OwnerStatus/Cancel retain the original Context/OOB. No caller
guesses aliases or re-signs an uncertain original.

## Carrier requirements

The current original-Node trust protocol remains the behavioral baseline:
PENDING → OWNER_APPROVED → ACKED with explicit terminal expiry/cancel/revoke/fence
and exact recovery. Owner complete does not install a binding. The original
Node must verify local S, exact approval, current time and capsule before its
private ACK. No App can ACK on the Node's behalf. Binding installation and its
original App confirmation response are atomic at the ACK writer transaction.

For scoped INITIAL, Store selects only the explicit Scope2 head for that same
Node, exact grant/proof/confirmation digest and one confirmation budget. It does
not try legacy authority after a scoped failure. It shares the whole-App Client
session/counters and single RESERVED slot with legacy NPT; no second Node may
skip an unresolved first-Node original. ACK atomically rechecks Root, account,
App, Node/candidate, epochs/head, nonce/deadline, both packet identities,
confirmation budget, original poll delivery and existing Node Guard, then commits
binding/provenance/budget/counters plus both exact encrypted responses. Response
loss or restart recovers those originals without changing identity or sequences.

EXISTING_BINDING retains its no-new-candidate/no-new-confirmation behavior. Its
new typed envelope binds Scope2 and the same actual binding/Node; no grant proof
or confirmation packet may be supplied. Retained historical Node-Control tuples
must resolve to that exact actual binding, never invented versions or keys.

Legacy/new cross-namespace INITIAL reuse, per-Node head CAS, original-response
loss/restart, revocation and restoration require carrier tests before enabling
availability. The codec tests do not establish actual Node CLI, App, Android,
native Runtime, physical Windows or public HTTPS acceptance.
