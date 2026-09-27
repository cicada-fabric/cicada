# Android ↔ Hub minimal interop v1

Status: **server-side partial contract**. This is an implementation guide for the separate Android repository, not a claim that independent Android interop has passed. Read [the detailed wire contract](client-hub-wire-v1.md) and [OpenAPI](client-hub-v1.openapi.yaml). The Hub advertises `android-hub-v1-draft`; `GET /v2/client/identity` has `contract=android-hub-v1`. They are distinct endpoint labels.

## 1. Negotiate, then pin the Hub

```http
GET /v2/client/capabilities
```

When Control is available, require `status="partial"` and gate each operation on `available_rpc_operations`. `status_events` and `external_thread_links` are always `false`. In Fabric-only mode, `status="not_ready"` and the RPC list is empty. A `true` flag reports a Hub implementation, not Android readiness.

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

`201` returns `{owner_id, device_id, session_epoch, device_key_version, state:"ACTIVE"}`. A malformed body returns `400`; an invalid grant, key, owner scope, or reused device binding returns the generic `403` error. Store the returned epoch and key version with the device key. Enrollment does not create a Group or join a Thread.

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

Persist the exact sealed request before sending. Start request sequence at 1 and increment by one per session epoch. Reusing the exact packet returns the cached exact response. A changed packet with an accepted sequence/operation ID, a processing retry, or an uncertain request can return HTTP `409`; reconcile with a new read operation before taking another action. `400` means malformed/empty/oversized packet; `403` means inactive device or failed authentication/binding; `503` means Control is unavailable. These outer failures use `{"error":"..."}` and are not encrypted. See OpenAPI for method and internal-error statuses.

Examples of operation selector and the corresponding decrypted JSON body:

| `route.operation` | Decrypted JSON body |
|---|---|
| `status.changes` | `{"limit":100}` |
| `nodes.preview` | `{"user_code":"ABCD-EFGH-JKLM"}` |
| `intent.submit` | `{"text":"Create a benchmark plan","kind":"idea"}` |

`status.changes` is a durable but partial snapshot-delta poll, not push. `intent.submit` returns a durable pending Intent; `DONE` from `intent.status` means dispatch finished, while the nested Intent carries the management outcome. Full request and result fields for all advertised operations are in [the wire operation table](client-hub-wire-v1.md#available-operations).

## 4. Bind a Node, then use its outbound Relay channel

The Node generates and keeps its `cicada_node_...` bearer locally. It posts only its node ID/name and `SHA-256(token)` as unpadded base64url `credential_digest` to public `POST /v2/nodes/device-code`. The Hub returns a 12-symbol `user_code` formatted `XXXX-XXXX-XXXX` and `verification_uri:"/client/device"`; this repository does not host that UI. The Android Client must first have its pinned, enrolled encrypted session, then call `nodes.preview` for review and `nodes.confirm` as a separate approval.

After confirmation the Node makes outbound HTTPS requests with `Authorization: CicadaNode <node-bearer>`:

1. `GET /v2/relay/nodes/{node_id}/events` holds an SSE connection. Hub events are body-free wake hints (`ready` or `wake`, data `claim`).
2. On a hint, the Node `POST`s `{consumer_id, limit}` to `/claim` and receives durable delivery assignments.
3. The Node stores each delivery in its local inbox/journal, delivers it to the exact bound native session, and posts progress to `/receipts`.
4. `POST /heartbeat` with `{}` records liveness and returns `204`.

The wake stream does not contain or consume messages. This Hub→Node delivery path is separate from Client→Control RPC and from the Control Worker-job APIs. **Current Fabric delivery bodies are plaintext**: the Node accepts an empty or `PLAINTEXT` payload mode and persists `body` before injecting it into the native session. This does not provide Hub-blind Endpoint E2EE. A full machine agent may separately call Control machine/worker APIs with its configured Control bearer; the Node Relay credential does not grant that API access.

For current bilateral Link trust evidence, a bound Node can separately call `GET /v2/relay/nodes/{node_id}/links/{link_id}/authorization` with the same Node bearer. `200` returns `{manifest, source_grant, target_grant, link_state}` only if the Node/owner binding is one side of the current Link and both owner key-bound grants are valid. Each grant includes the owner public identity and signed proof. Node must verify both against owner keys it already trusts and the current manifest; values fetched from the Hub do not bootstrap that trust. Missing or stale evidence is masked as `404`. This read-only evidence does not activate the Link or authorize delivery.

## 5. Cross-user Thread Link boundary

`topology.apply` can create or revoke a **same-owner** Link proposal. The `link.key_manifest`, `link.key_grants`, and `link.key_grant` operations inspect Endpoint key candidates and record owner key-bound consent for that current Link. They do not provide an external invitation flow, two independent User approvals, cross-user Link activation, or routable cross-user Thread traffic. `external_thread_links=false` is authoritative. The Node authorization-evidence route above is separate from Client management and does not activate routing or change this Client capability. Endpoint-to-Endpoint sealed delivery is not yet implemented, and current peer traffic remains plaintext.
