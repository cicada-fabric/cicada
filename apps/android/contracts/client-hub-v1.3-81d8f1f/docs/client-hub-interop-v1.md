# Android ↔ Hub minimal interop v1

Status: **server-side partial contract**. This is an implementation guide for the separate Android repository, not a claim that independent Android interop has passed. Read [the detailed wire contract](client-hub-wire-v1.md) and [OpenAPI](client-hub-v1.openapi.yaml). The Hub advertises `android-hub-v1-draft`; `GET /v2/client/identity` has `contract=android-hub-v1`. They are distinct endpoint labels.

Use the [joint workflow](client-hub-development.md) and exported protocol bundle
to pin the tested source/image and `contract_revision`/`catalog_sha256`. Run
`scripts/test-client-hub-interop.sh` for a disposable, real-TCP Hub protocol check.
That check uses a Go protocol client, not Android or a native Codex Runtime.

## 1. Negotiate, then pin the Hub

```http
GET /v2/client/capabilities
```

When Control is available, require `status="partial"`. `available_rpc_operations` lists the resident manager's operations; `external_rpc_operations` is the limited outside-owner list. After enrollment, call encrypted `session.capabilities` to learn this device's actual scope. `status_events` and routable `external_thread_links` are always `false`; `external_link_invites=true` means only one-use proposal invitations are implemented. In Fabric-only mode, `status="not_ready"` and both RPC lists are empty. A `true` flag reports a Hub implementation, not Android readiness.

```http
GET /v2/client/identity
```

The response has `hub_id`, `control_public_identity: {id, kem_public, signing_public}`, `control_key_version: 1`, `suite: "ML-KEM-768+ML-DSA-65+AES-256-GCM"`, and `contract: "android-hub-v1"`. Pin the Hub ID and complete public identity through an independent trusted channel. Do not trust an identity fetched only from the URL being verified.

## 2. Enroll one Android device

Generate an independent device ML-KEM-768/ML-DSA-65 identity. The owner approval key must already be trusted by this Hub through local operator bootstrap; there is no legacy bearer or phone-only login shortcut. The owner signs an exact `OwnerDeviceGrant` for the Hub, owner, device ID, device public-key ID and fingerprint, purpose `CLIENT_CONTROL`, validity window, and one-use nonce. Send the canonical grant JSON bytes as standard padded base64:

```http
POST /v2/client/devices/enroll
Content-Type: application/json
```

```json
{
  "owner_id": "<owner-principal-id>",
  "owner_key_id": "<owner-ml-dsa-key-id>",
  "device_id": "android-phone-1",
  "device_public_identity": {
    "id": "<pq1-derived-id>",
    "kem_public": "<standard-base64-ml-kem-public-key>",
    "signing_public": "<standard-base64-ml-dsa-public-key>"
  },
  "owner_device_grant": "<standard-base64-of-canonical-grant-json>"
}
```

`201` returns `{owner_id, device_id, session_epoch, device_key_version, state:"ACTIVE"}`. If this response is lost, repeat the exact original enrollment request bytes; the active binding returns the same epoch/version. A malformed body returns `400`; a changed grant, invalid key/owner scope, or revoked binding returns `403`. Store the returned epoch and key version with the device key. Enrollment does not create a Group or join a Thread.

## 3. Send the first encrypted operation

For `status.snapshot`, the decrypted request body is `{}`. Encode it in a Client-Control v1 envelope using the exact byte rules and field order in [Client wire v1](client-hub-wire-v1.md#encrypted-rpc-packet), then post the outer packet:

```http
POST /v2/client/rpc
Content-Type: application/json
```

```json
{
  "route": {
    "version": 1,
    "direction": "REQUEST",
    "hub_id": "<pinned-hub-id>",
    "owner_id": "<enrolled-owner-id>",
    "device_id": "android-phone-1",
    "session_epoch": 1,
    "sequence": 1,
    "operation_id": "<new-stable-operation-id>",
    "operation": "status.snapshot",
    "sender_key_id": "<android-device-key-id>",
    "sender_key_version": 1,
    "receiver_key_id": "<pinned-control-key-id>",
    "receiver_key_version": 1
  },
  "envelope": "<standard-base64-of-serialized-encrypted-envelope>"
}
```

The signed route's compact JSON bytes are AAD with the `cicada/client-control/packet/v1\u0000` prefix. The envelope encrypts the operation JSON to the pinned Control identity and signs it with the device ML-DSA key. Do not use generic map serialization for signed bytes. HTTP `200` returns a `RESPONSE` packet; after verifying and decrypting it, read `{request_id, operation_id, ok, result}`. If `ok` is false, `error` replaces `result`; today that value is free text, with no stable RPC error code.

Persist the exact sealed request before sending. Start request sequence at 1 and increment by one per session epoch. Reusing the exact packet returns the cached exact response when one exists. A changed packet with an accepted sequence/operation ID, a processing retry, or an uncertain request can return HTTP `409`. Retry a pending request only with its exact original packet; do not create another operation to repeat its side effects. If the response is missing or the request is uncertain, post the exact saved packet to `POST /v2/client/rpc/recover`. The Hub returns the cached response, `409 STILL_PROCESSING`, `409 RECOVERY_UNAVAILABLE` for pre-v29 uncertain rows, or a signed `OUTCOME_UNCERTAIN` notice with the expected response sequence. Android must verify and persist the notice, retire only its transport pending slot, and leave the business outcome visibly uncertain until checked against authoritative state. This Client-side implementation is pending in the separate repository. Never reset counters to clear uncertainty. `400` means malformed/empty/oversized packet; `403` means inactive device or failed authentication/binding; `503` means Control is unavailable. See OpenAPI for method and internal-error statuses.

Examples of operation selector and the corresponding decrypted JSON body:

| `route.operation` | Decrypted JSON body |
|---|---|
| `status.changes` | `{"limit":100}` |
| `goal.lifecycle` | `{"goal_id":"goal_...","action":"pause","expected_version":1}` |
| `goal.result` | `{"intent_id":"intent_..."}` |
| `nodes.preview` | `{"user_code":"ABCD-EFGH-JKLM"}` |
| `intent.submit` | `{"text":"Create a benchmark plan","kind":"idea"}` |

`status.changes` is a durable but partial snapshot-delta poll, not push; it includes only metadata for owner-attributed Approval and Client Intent changes, so fetch details through their dedicated operations when allowed. An outside owner can read its own attributed `status.snapshot/changes` and Group/Endpoint topology, but never the resident manager's legacy ownerless state. `goal.lifecycle` pauses or resumes only unclaimed remote Node work and is currently a resident-manager operation; take `expected_version` from the Goal item in `status.snapshot` or a current Goal delta and refresh after a conflict. A running Worker is never reported as paused by this operation. `intent.submit` returns a durable pending Intent; `DONE` from `intent.status` means dispatch finished, while the nested Intent carries the management outcome. Intent submission and Approval decisions are resident-manager operations. Full request and result fields are in [the wire operation table](client-hub-wire-v1.md#available-operations).

For a Client-created Goal, use `goal.result` with the accepted `intent_id` after `intent.status` resolves. It returns the owner-scoped Goal state, Worker summaries and opaque Artifact metadata; no local filesystem path or Artifact body. This read does not itself prove native Codex execution or Android integration.

## 4. Bind a Node, then use its outbound Relay channel

The Node generates and keeps its `cicada_node_...` bearer locally. It posts only its node ID/name and `SHA-256(token)` as unpadded base64url `credential_digest` to public `POST /v2/nodes/device-code`. The Hub returns a 12-symbol `user_code` formatted `XXXX-XXXX-XXXX` and `verification_uri:"/client/device"`; this repository does not host that UI. The Android Client must first have its pinned, enrolled encrypted session, then call `nodes.preview` for review and `nodes.confirm` as a separate approval.

After confirmation the Node makes outbound HTTPS requests with `Authorization: CicadaNode <node-bearer>`:

1. `GET /v2/relay/nodes/{node_id}/events` holds an SSE connection. Hub events are body-free wake hints (`ready` or `wake`, data `claim`).
2. On a hint, the Node `POST`s `{consumer_id, limit}` to `/claim` and receives durable delivery assignments.
3. The Node stores each delivery in its local inbox/journal, delivers it to the exact bound native session, and posts progress to `/receipts`.
4. `POST /heartbeat` with `{}` records liveness and returns `204`.

The wake stream does not contain or consume messages. This Hub→Node peer delivery path is separate from Client→Control RPC and from Control's Worker planning. A bound Node can also call `POST /v2/fabric/node/join` with its Node bearer; the Hub derives owner and Node from that credential, while the Node Agent must independently verify the live native Codex session before supplying its ID. Older Sessions without sealed-delivery capability cannot start new peer SEND/ASK/REPLY; their historical receive and durable rows remain available for migration. Sealed-capable same-owner, same-Group peers use the Node-local ledger or Node-only sealed Hub Relay and never silently downgrade. Their bounded real-native validation and remaining limits are recorded in the [status matrix](architecture-v2-status.md).

The separate, Node-only `POST /v2/relay/nodes/{node_id}/sealed/send|ask|reply` routes accept only bounded ciphertext, exact Link/request correlation fields and an authenticated Node credential; sender/receiver, owner, Group and binding are derived from the current bilateral Link and original request. `ciphertext` is standard base64 for the complete signed Endpoint envelope; requests cannot assert a sender, target or approval. Durable acceptance returns `202`. `POST /v2/relay/nodes/{node_id}/sealed/claim` returns bounded opaque deliveries for the bound Node only after a current Link and Grant check; sealed request status/cancel are also Node-only. These are Hub/Node transport endpoints, not Android Client calls. The Node runtime verifies exact-attempt authorization and local Owner trust, saves a durable crypto inbox, decrypts, and queues the bound native Codex Thread. SEND/ASK/REPLY have passed two-logical-Node/fake-Codex tests, not real cross-user native or two-physical-machine acceptance. `external_thread_links=false` remains authoritative for the complete Android conversation feature until native, Client and broadcast acceptance is finished.

For new Goals accepted from an encrypted Client session, the same confirmed Node bearer also accesses its own management work without a global Control token:

1. `POST /v2/relay/nodes/{node_id}/heartbeat` with `{"status":"available","capabilities":{...}}` reports Node liveness and Worker capabilities. An empty `{}` only refreshes liveness. Pairing alone does not assert that a Node is online.
2. `GET /v2/relay/nodes/{node_id}/jobs` returns only queued work for Goals attributed to that bearer’s current owner and machine. `POST /jobs/{worker_id}/claim` with `{}` atomically claims one attempt.
3. A claimed Workspace job uses `GET /jobs/{worker_id}/snapshot/{digest}` to restore the current archive and `POST /jobs/{worker_id}/snapshot` to attach the new archive. Both requests include `X-Cicada-Worker-Attempt` and `X-Cicada-Workspace-ID`; upload also includes `X-Cicada-Snapshot-Digest` (lowercase SHA-256). The Hub checks the current bearer, owner, Worker attempt and Workspace relation again when attaching. Archives are bounded to 256 MiB.
4. `POST /jobs/{worker_id}/result` reports `attempt`, `status` (`completed` or `failed`) and bounded summary/thread/error/revision fields. The snapshot digest is committed by the snapshot route, not supplied in the result body. A stale attempt cannot finish a newer Worker. The Client then reads `intent.status` and `status.snapshot` or `status.changes` through its encrypted RPC.

These Node routes use `Authorization: CicadaNode <node-bearer>` and cannot be called with the legacy Control bearer. Old ownerless Goals remain in the database but are not claimable through this owner-scoped API. The independent Android repository does not need to call any Node route or hold a Node credential.

For current bilateral Link trust evidence, a bound Node can separately call `GET /v2/relay/nodes/{node_id}/links/{link_id}/authorization` with the same Node bearer. `200` returns `{manifest, source_grant, target_grant, link_state}` only if the Node/owner binding is one side of the current Link and both owner key-bound grants are valid. Each grant includes the owner public identity and signed proof. Node must verify both against owner keys it already trusts and the current manifest; values fetched from the Hub do not bootstrap that trust. Missing or stale evidence is masked as `404`. This read-only evidence does not activate the Link or authorize delivery.

## 5. Cross-user Thread Link boundary

`topology.apply` can create or revoke a **same-owner** Link proposal. For two owners on one Hub, the source encrypted Client calls `link.invite_create` for its currently joined, leased Endpoint/Group and gets a one-use token. It transfers that token to the intended other owner through a separately trusted channel. The target's encrypted Client calls `link.invite_preview`, checks the source label, Hub, allowed actions/data scopes and expiry, then calls `link.invite_accept` with one of its own currently joined Endpoint/Group pairs. The Hub atomically creates only a `PROPOSED` Link and consumes the token. Both sides can recover the accepted Link ID and terms through owner-scoped, paged `link.list`; the target also receives the ID on accept. `link.key_manifest`, `link.key_grants`, and `link.key_grant` then let each owner inspect and sign the exact current key-bound contract. `external_thread_links=false` remains authoritative for general product routing: Node-only sealed SEND/ASK/REPLY has two-logical-Node/fake-Codex evidence, while real guest native Join and cross-user native-session continuity remain unverified. Retired plaintext `/v2/fabric/send|ask|reply` routes return 410 and cannot be used for a Link.
