# Client task: integrate Monitor broadcast consent (Hub v1.3 candidate)

这份任务书交给独立的 `CICADA_CLIENT` 仓库执行：Android 实现和测试只改
Client 仓库。Hub 权威协议与服务端代码属于 `CICADA`，不要在 Client 端改写 Hub
行为，也不要在当前候选 artifact 冻结前假设接口已部署。

**Status, 2026-09-27:** this is an implementation task outline, not an immutable
release pin. Before importing the candidate, obtain from the Hub owner the clean
CICADA source commit, complete exported protocol bundle and manifest/hash, exact
Hub image ID/digest, and confirmation that public HTTP plus disposable Docker
interop gates passed. Do not invent or substitute a commit, bundle, image, APK, or
test-result hash. Do not use the shared development Hub as a disposable fixture.

The current shared-tree candidate identifies as `client-hub-v1.3`, wire v1, with
33 catalog operations. Its catalog SHA-256 is
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`, but that
digest alone is not a frozen protocol bundle or Hub image. Use the exact bundle
received from the Hub owner, run its `client-contract.py verify` check, and treat
the [wire contract](client-hub-wire-v1.md), [OpenAPI](client-hub-v1.openapi.yaml)
and [Android contract](android-client-hub-contract.md) in that bundle as the
field-level authority.

Build a Client flow in which an authenticated owner explicitly approves one
Monitor Endpoint to broadcast exact text to a reviewed, fixed same-owner Group
recipient roster. The Client keeps the plaintext locally until it creates the
Monitor envelope; the Hub stores the consent evidence and ciphertext. The Hub
operation catalog advertises availability only. The encrypted device session and
server Guard authorize every request.

Expose the Group's `message.broadcast` permission as an explicit owner-controlled
membership setting, using the versioned topology operation in the contract.
Display its current state from `topology.snapshot` so a lost toggle response can
be reconciled. Granting the `monitor` role does not grant `message.broadcast`.
Changing the permission or roster invalidates outstanding preview evidence.

Implement these four catalog operations:

- `monitor.broadcast_prepare`: send the selected Group, Monitor Endpoint and
  lowercase SHA-256 of the exact UTF-8 body. Do not send plaintext. Independently
  validate the complete Endpoint attestation and owner-signed Group Endpoint key
  grant against trust anchors already held by the Client. A Hub-returned key ID,
  public key or digest is not a trust anchor. Show the consent scope, current
  revisions, Monitor identity and ordered recipient cards before confirmation;
  a roster hash alone is not meaningful user consent.
- `monitor.broadcast_confirm`: after an explicit user action, seal the exact body
  to the verified Monitor key and sign Monitor envelope v2 with the authenticated
  Client device key. Bind it to the preview, exact body digest, consent/snapshot,
  device epoch/key, Monitor binding, expiry and accepted confirm request sequence.
  Persist the exact sealed envelope and outer encrypted RPC packet before sending.
- `monitor.broadcast_status`: show the bounded approval and per-recipient outcome
  state. `NODE_REPORTED` and `RELAY_PERSISTED` describe persistence evidence only;
  neither means a native Runtime consumed the message or a model completed work.
- `monitor.broadcast_recover`: after an uncertain Prepare response, use the
  original Prepare `operation_id` for a read-only lookup. Do not issue a new
  Prepare because a response was lost. For transport recovery of a persisted RPC,
  follow the existing `/v2/client/rpc/recover` rules and retry only the exact
  original packet; after an uncertain Confirm, check Status instead of creating a
  second approval.

Keep the existing identity and recovery boundaries: the caller does not supply an
owner ID, role, sender or approval decision; never fall back to a management bearer
or legacy `/v1` endpoint. Do not log bodies, private keys or sealed plaintext to
analytics/crash reports. Preview/result DTOs must not expose Node-private paths or
native Session IDs.

The limits are part of the interaction contract. The exact body is at most 16 KiB
UTF-8; a recipient snapshot is at most 32 recipients and dispatch remains batched
by at most 8. A prepared approval expires after five minutes. Hub admission allows
at most 16 unexpired PREPARED/APPROVED/DISPATCH_AUTHORIZED previews per
owner-device and 64 per owner. Revocation does not immediately free a slot for an
unexpired row; an exact Prepare retry does not consume another slot. The server
returns one generic backpressure error for either full limit. Show a neutral
temporary-capacity message and do not spin, create a fresh Prepare, or silently
retry under a new operation ID. Node notice lists are bounded pages; server-side
periodic reconciliation is required for backlog and is not an immediate-delivery
promise.

Add Client tests for complete Endpoint-attestation and owner-grant verification,
consent-scope rendering, exact UTF-8 body digest, ordered recipients, disabled
permission and foreign/stale/expired preview rejection, and same-packet recovery
after response loss. Verify that an `OUTCOME_UNCERTAIN` response does not lead to a
second Prepare or Confirm. Include backpressure and expiry behavior, and assert
that status text never represents transport persistence as model consumption.
Use only the public synthetic vectors from the verified bundle; they are test
fixtures, not deployment keys.

After the pinned Hub artifact is provided, run Kotlin/vector tests and the isolated
Android emulator flow against that exact image, then record the Client commit,
verified bundle manifest/hash, Hub image ID/digest, APK hash, test commands and
result paths. Keep Android physical-device, real native Monitor, dual-physical
Node and public HTTPS results separate. Until each is run, report it as
**NOT_RUN**. The earlier v1.2.1 Android PASS remains historical evidence for its
own fixed source and image, not for this candidate.
