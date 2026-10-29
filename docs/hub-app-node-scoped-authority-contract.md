# Finite App authority scoped to an exact Node

Contract: **`app-node-authority-node-scoped-v1`**. This checkpoint freezes
shared proof/packet codecs and advertises **`available=false`**. It does not
implement or enable the scoped Store/Hub carrier. Its transactional requirements
below are implementation obligations, not passing acceptance claims.

The existing [App Node v1 contract](hub-app-node-authority-contract.md) and its
original packets, signatures, heads, provenance, READ behavior and recovery stay
unchanged. Account login does not confer Root. Existing Owner, account, App,
Node public keys and epochs remain authoritative. No identity regeneration,
Control inference, installation-registration or new Client catalog entry is
part of this family. Software remains unreleased 0.0.5, Client wire 1/catalog 55;
Scope version 2 is a separate value.

## Discovery and exact APIs

GET `/v2/owner/app-node-scoped/capabilities` returns
`AppNodeScopedCapabilities`, format `cicada.app-node-scoped-capabilities.v1`,
contract revision above, `scope_kind="NODE_V1"`, `scope_version=2`,
`serve_mode="--hub-nodes-only"`, `available=false`. It lists exactly the five
operations below, profiles `INITIAL_CONFIRM` and `READ_EXISTING`, the existing
900-second finite lease and 128 KiB original limit. The consumer must first
authenticate the independently retained Hub and strictly decode an available
capability before creating a scoped pending operation or sending a secret POST.
Unavailable, unknown, malformed and old-Hub responses grant no fallback write.

| Operation | POST path | Request | Success response |
|---|---|---|---|
| `owner.app_node_scoped.prepare` | `/v2/owner/app-node-scoped/prepare` | `AppNodeScopedPrepare` | `AppNodeScopedChallenge` |
| `owner.app_node_scoped.complete` | `/v2/owner/app-node-scoped/complete` | `AppNodeScopedComplete` | `AppNodeScopedResult` |
| `owner.app_node_scoped.status` | `/v2/owner/app-node-scoped/status` | `AppNodeScopedStatus` | `AppNodeScopedResult` |
| `owner.app_node_scoped.cancel` | `/v2/owner/app-node-scoped/cancel` | `AppNodeScopedCancel` | `AppNodeScopedResult` |
| `owner.app_node_scoped.reconcile` | `/v2/owner/app-node-scoped/reconcile` | `AppNodeScopedReconcile` | `AppNodeScopedReconciled` |

Formats are respectively `cicada.app-node-scoped-{prepare,challenge,complete,
status,cancel,result,reconcile,reconciled}.v1`. A rejected prepare uses the
authenticated common result, never an HTTP-status-based pending clear. The
existing account packet wrapper, fixed handshake route, PQ cryptography and
identity leaf `AppNodeRequestContext`/constructor input `AppNodeSession` are
reused. The operation, entire original packet, new scope and proof domains are
explicitly distinct. No scoped POST handler is enabled at this checkpoint.

`e2ee.OwnerAppNodeScopedScope` is an independent strict DTO: every existing
identity/session/epoch/transport coordinate plus mandatory `version=2` and
`authority_node_id`. The Node ID must be a real product Node identifier and must
equal the exact signed candidate or binding Node ID. HeadVersion denotes only
this Node's head. The old `OwnerAppNodeScope` remains version 1 and rejects the
new field, including an empty field. No parser tries both authority versions.

The separate `OwnerAppNodeScoped{PreviewClaims,Preview,GrantClaims,Grant}` use:

| Proof | Purpose | Signature domain |
|---|---|---|
| Initial preview | `APP_NODE_SCOPED_INITIAL_PREVIEW` | `cicada/owner/app-node-scoped-preview/v1\x00` |
| Status preview | `APP_NODE_SCOPED_STATUS_PREVIEW` | same preview domain |
| Initial grant | `APP_NODE_SCOPED_INITIAL_CONFIRM` | `cicada/owner/app-node-scoped-grant/v1\x00` |
| Status grant | `APP_NODE_SCOPED_STATUS_READ` | same grant domain |

Every field is signed. The existing finite bounds remain: intent 60 seconds,
proof 300 seconds, lease 900 seconds, one confirmation for INITIAL and zero for
READ_EXISTING. No lease renewal or general business permission is introduced.
Candidate/binding public leaf DTOs are reused without modifying their meaning.

Status requires a strict XOR `AppNodeScopedStatusTarget{NodeID,CandidateCode}`:
`node_id` selects one exact Node; `candidate_code` is the canonical existing
12-character code and requires the current authenticated account token and an
empty grant ID. The latter is a rate-limited, secret-protected, read-only
candidate resolution before the App knows the Node ID. It returns the exact
Node scope/head; it cannot publish a grant, spend a confirmation or list other
Nodes. Prepare signs that resolved Node ID and the original normalized code
digest. Store must resolve the code again and require the same actual candidate.
An old or substituted selection cannot redirect approval.

Cancel and reconcile carry mandatory `authority_node_id` as well as the grant
and exact original where applicable. Reconcile results repeat that Node ID.
Caller validation must compare it with its retained Node, original kind,
operation, request ID and digest. An authority original uses kind
`APP_NODE_SCOPED_AUTHORITY`; a Client original retains `CLIENT_CONTROL`.
`nodes.confirm` retains its frozen operation/body, but its authenticated
OperationID is `n3s.<grant-id>.<nonce>`; the legacy `n3.` parser rejects it.
Packet/claims digests use `cicada/app-node-scoped-authority/{packet,claims}/v1\x00`.

## Store state and namespace invariants

The carrier must add a fresh migration after the current schema baseline;
historical migration 63, old heads and historical provenance are immutable.
The following invariants must hold in the same writer transaction as effects
and exact response persistence:

- New heads are keyed by `(owner_id, device_id, authority_node_id)`. Grants retain
  immutable namespace kind and Node ID; legacy rows default to `LEGACY_V1` with
  no synthetic Node-scoped backfill. Nonempty provenance is irreversible.
- ACTIVE uniqueness is per namespace and exact Node. PREPARED uniqueness remains
  across the whole App, including legacy and scoped families. A new Node does
  not bypass an unresolved prepare, original or RESERVED confirmation slot.
- Prepare compares published Node head g and proposes g+1 without publishing it.
  Complete CASes exactly that Node's g, activates g+1, replaces only that scope's
  prior ACTIVE grant and commits its exact encrypted response atomically. Same
  Node concurrent completion has one winner. Cancel of a proposal does not
  change another Node's head, grant, budget or provenance.
- Before INITIAL, both namespaces must search the actual Node's full history,
  including confirmed provenance and irreversible revocation/tombstones.
  Legacy-first Node A may coexist with scoped Node B. Changing namespace cannot
  revive a confirmed or revoked Node, clear its provenance or reset its budget.
  This does not permanently lock an unconfirmed Node after its first failed
  attempt: the original same-namespace v1 continuation after authenticated
  EXPIRED or SELF_CANCEL, with no confirmation provenance, retains its existing
  candidate/actor/fence checks. It is not a namespace-switch recovery shortcut.
  Any unresolved whole-App pending original or RESERVED slot still blocks a
  fresh operation. Carrier tests must distinguish confirmed/revoked history,
  legitimate same-namespace pre-provenance continuation and unresolved retry.
- Owner/account/App revocation and epoch fences apply to every scope. A grant
  for A cannot authorize B or lend B a confirmation. Only current Root, exact
  account session, App identity, signed Node, epoch/head and existing Guard can
  authorize the one original confirmation.
- The existing Client session epoch, request sequence and response sequence are
  **global for the App**. They are never copied/reset per Node. The single NPT
  RESERVED slot remains global. An unresolved A packet blocks a fresh B write;
  recovery must retain A's original bytes, operation ID and sequences first.
- Exact retries select the stored operation plus complete packet digest and
  authority namespace. Same ID with a different Node, version, proof or packet
  conflicts; original replay returns the identical retained response. A lost
  response, process restart, expiry or revocation cannot turn retry into a fresh
  confirmation. Reconcile authenticates the historical original and returns its
  retained receipt or explicit permanent fence, never unadmitted new effects.
- Restore must inventory new heads/grants/provenance and include their replay
  floors and pending slot. Unknown/incomplete snapshots remain UNSUPPORTED;
  merely incrementing a supported-schema constant is insufficient.

READ_EXISTING requires the exact original Node confirmation provenance and
binding; no new confirmation, Node key, Owner key or epoch is created. The old
READ/provenance response bytes keep their original attribution.

## Shared constructor and Owner-operation entry points

Authoritative implementations live in `internal/e2ee/owner_app_node_scoped_*`
and `internal/hubaccountwire/app_node_scoped_*` under `cicada-go`.

| Entry | Required inputs |
|---|---|
| `NewAppNodeScopedPrepare` | existing `AppNodeSession`, exact Scoped scope, `AppNodeScopedPrepareTarget` (`INITIAL_CODE` or `PREVIOUS_GRANT`), existing Owner signer, current time |
| `NewAppNodeScopedComplete` | same session, retained prepare + its exact packet, authenticated challenge, existing Owner signer, current time |
| `NewAppNodeScopedStatus` | same session, XOR status target, optional exact grant ID, current time |
| `NewAppNodeScopedCancel` | same session, Node ID, grant ID, expected Node head, current time |
| `NewAppNodeScopedReconcile` | same identity/session leaf, Node ID, kind, grant ID, exact original packet, current time |
| `SealClientRequest` / `OpenAppNodeScopedResponse` | existing App private identity, pinned Hub, typed request / retained original and response |
| `SealAppNodeScopedConfirmation` | exact grant, canonical code, the next **global** Client request sequence, current time |
| `ValidateAppNodeScopedLiveResult` | exact retained grant, pinned Hub and current time; historical success alone is insufficient |
| `ValidateAppNodeScopedReconcileTarget` | result, retained Node ID, kind and exact original |
| `AppNodeScopedOwnerActor(scoped, hub)` | full validated identity coordinates from the currently authenticated scoped context |

`AppNodeScopedOwnerActor` explicitly produces the existing v1 **Owner actor**
with head=0 for newly signed LocalDomain/OwnerEndpointGroups requests. It is not
a grant/proof conversion. Those independent purpose families require head=0 and
recheck live Root/session on the server. App must first match every identity,
session and epoch against its current independently authenticated session; use
the selected Node's exact successful NPT ACK binding; and sign that Binding/Node
as the operation target. No legacy grant or confirmation is borrowed.

An existing Network selector may use only the App's authenticated, settled
Node/LocalDomain records. It fills exact NetworkID and clears NewNetworkName.
Hub revalidates current Owner, Hub and active Network at prepare; stale,
foreign-Owner, foreign-Hub or revoked selections fail closed. Existing Group
membership already permits Nodes of the same Owner in that same Network; this
change adds no Group right or public directory.

The [scoped NPT contract](node-pair-trust-scoped-contract.md) defines the new
device request, Owner approval and original Node ACK. App vault entries for v1
stay untouched; new records are per Node and retain the one global pending gate.
Actual second-Node enrollment, existing-Network selection, same-Group exchange,
response-loss/restart, revocation and restore gates remain NOT_RUN at this
codec-only checkpoint. A same-Node fixture is not second-Node acceptance.
