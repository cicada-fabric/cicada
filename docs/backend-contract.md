# Client ↔ Hub contract: `client-hub-v1.4`

**Current checkpoint:** 2026-09-30, branch `dev/react-native`, clean Hub `f30892fcd79a27bfe5604575deaecebe52c5ec50`, protocol `client-hub-v1.4`, catalog `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`. The [current validation record](client-hub-v1.4-f30892f-validation.md) provides complete pins, commands, APK hashes and outcome boundaries.

Current work adds isolated Hub profiles and explicit ACTIVE Network selection, topology v2, `group.create(network_id)`, and dedicated `network.key_manifest/key_grant/key_status`. No operation is authorized by a local profile or a public capability alone. A captured profile and selection generation fences every native call. Device identity and pending enrollment/RPC bytes remain in their original profile; deleting unresolved profiles is refused. A pinned profile cannot be reassigned to a different Hub ID.

Network proof verification uses the exact v1.4 domains, full ML-KEM/ML-DSA public identity, canonical raw self-attestation, native Session commitment, complete manifest digest, current identity/revisions, externally signed Owner proof and explicit confirmation. Signed claims end with `"signature":null`. Manifest digest claims omit the Owner-only `native_session_id` and include `"digest":""`. Group bindings do not substitute for Network direct bindings. Fresh encrypted capabilities, topology and manifest are checked before sealing a grant. The fixed source lacks an external Network signing CLI, so the real positive Network grant remains BLOCKED; its published incomplete vector is tested for its precise bytes and is never accepted as a complete production preview.

Completed bounded gates: final APK build, 45 Kotlin tests, 23 JavaScript checks, offline connection UI, and fresh-device disposable fixed-image enrollment, encrypted capabilities, ACTIVE topology/selection and Network-scoped Group creation. An independent durable Network grant uncertainty fence rejects replacement writes and identity resets until dedicated reconciliation is implemented. Next gates: accept a separately pinned Core signer delivery and complete native fixture; then validate real Network consent, dedicated status correlation and rejection/recovery states. Native Node/Monitor delivery, physical devices, public HTTPS and additional platforms retain their own test status. Do not use historical PASS results or unpublished Core changes for the current target.

## Historical checkpoints

**Last updated:** 2026-09-27

This document follows the imported protocol bundle at [`contracts/client-hub-v1.3-be0269e`](../contracts/client-hub-v1.3-be0269e/manifest.json). The current fixed target is:

| Item | Value |
|---|---|
| Hub source revision | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` |
| Contract revision | `client-hub-v1.3` |
| Protocol archive SHA-256 | `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Full Docker image ID | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |

The Client independently checks the archive and manifest, clean source and full
image provenance. Encrypted `session.capabilities` must report this exact
revision and catalog before operations are enabled. See the [fixed-image
validation record](client-hub-v1.3-be0269e-validation.md) for the current test
status. Prior v1.2.1 results apply only to their recorded source and APKs.

## Trust and authorization

The current wire protocol provides `GET /v2/client/identity`, `GET /v2/client/capabilities`, `POST /v2/client/devices/enroll`, `POST /v2/client/rpc`, and `POST /v2/client/rpc/recover`. The public capabilities response describes Hub implementation support. It does not authenticate a device or grant access.

Before enrollment, the user independently verifies and pins the full Hub ID and Control public identity. The device generates its own ML-KEM-768 and ML-DSA-65 key pair. An independently trusted owner signs a one-time `OwnerDeviceGrant` bound to the Hub, owner, device public identity, purpose, nonce, and expiry. The Client persists the exact enrollment bytes before the first POST. If the 201 response is lost, only the same bytes may be replayed. The Client does not self-approve enrollment or use a legacy bearer shortcut.

After enrollment, the first encrypted operation is `session.capabilities`. It supplies the authenticated owner, role, contract revision, catalog digest, recovery support, and operation allowlist. The Client requires both this encrypted authorization and local support for an operation. Server guards remain authoritative; no role, owner, or approval field supplied by the Client grants permission.

## Encrypted RPC and recovery

Every operation uses the Client-Control v1 wire framing and its exact route/AAD rules with ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. The device persists the request sequence, expected response sequence, operation ID, and exact signed ciphertext before sending. The server derives owner/device/epoch from the registered device and fences replayed or altered packets.

The encrypted RPC catalog includes session capabilities; status snapshots and partial changes; Intent submission, lookup, and status; Goal results and lifecycle; topology; device, Node, and Approval management; Link proposals and key evidence; and Group Endpoint key operations. Actual access depends on the authenticated role and encrypted allowlist. Catalog presence alone does not make a Client UI action available.

For a missing response, the Client submits the original request packet to `/v2/client/rpc/recover`. Recovery never dispatches the business operation again:

| Recovery result | Client behavior |
|---|---|
| Completed request | Accept the original cached encrypted response. |
| `STILL_PROCESSING` (HTTP 409) | Preserve the exact pending packet, operation ID, and sequence. Do not create another operation. |
| Signed encrypted `OUTCOME_UNCERTAIN` | Verify the signature, original operation ID, and reserved response sequence. Retire only the transport pending slot; retain the uncertain business outcome and reconcile authoritative state. |
| `RECOVERY_UNAVAILABLE` (HTTP 409) | Preserve the unresolved business evidence. Do not guess a response sequence or replay the operation. |
| `RECOVERY_REJECTED` | Permit retry only as an explicit user choice and only with the original packet. |

HTTP success does not imply business success. A business rejection is an authenticated encrypted result. Transport failure, Intent dispatch, Goal state, Worker execution, and model consumption remain separate states in the UI.

Historical v1.2.1 fixed-image Android validation passed all three deterministic recovery cases on a disposable `/tmp` Hub with an independent Android session. The exact commands and limits are in the [validation report](client-hub-v1.2.1-967dbd-validation.md#recovery-faults-on-the-disposable-fixed-image). This evidence does not authorize direct Hub database access or a production fault switch.

## Status, Intent, and management operations

| Operation family | Contract behavior and Client boundary |
|---|---|
| `status.snapshot`, `status.changes` | Authenticated authoritative snapshot plus partial, cursor-based changes. Reconcile periodically with snapshots; this is not a complete push event feed. Display source, age, and stale state. |
| `intent.submit`, `intent.list/get/status` | Submit user-confirmed text or a reviewed local transcript. A completed Intent dispatch is not proof a Worker consumed input or a Goal completed. Read history and detail only on demand; responses may contain sensitive text and do not belong in durable Client caches or logs. |
| `goal.result`, `goal.lifecycle` | Results are owner-scoped and bounded. Lifecycle changes require an authorized role, current expected version, and fresh authoritative state. A queued Goal state is not a claim about a running native Worker. |
| `topology.snapshot/apply` | Versioned same-owner Group, Endpoint membership, role, and Link-proposal operations. A failed write or 409 requires a fresh authoritative read; parent Group permissions do not propagate to child Groups. |
| `nodes.preview/confirm/list/revoke` | Node generates and keeps its Node credential. Client displays a short code, previews it, then asks the user to confirm through encrypted RPC. Confirmation does not give the Client the Node credential. |
| `approvals.list/decide` | The authorized user decides a real pending approval. A Monitor cannot approve for a User. The approval body is Hub-visible management data; do not describe this path as peer-message blind encryption. |
| `devices.list/revoke` | Versioned owner-device management. The current Client must not offer self-revocation when the accepted response could no longer be delivered. |
| `link.*` | Owner-scoped invitations and key-consent records are proposals. The fixed contract advertises `external_thread_links=false`; these operations do not enable cross-user message routing. |
| `group.key_manifest/grant/status` | Fixed v1.2.1 returns a complete Endpoint attestation and owner grant fields. Android independently verifies the proof and binding, accepts an externally signed `signed_proof`, requires explicit confirmation, and reads the current Hub status through a dedicated encrypted method. A disposable fixed-image run with a real native Codex Endpoint reached `CURRENT`, then `STALE` after lease expiry and `PROOF_EXPIRED` after proof expiry. The Owner private key stayed outside the APK. See the [Group key acceptance report](client-group-key-v1.2.1-disposable-validation.md). |

The fixed wire contract keeps `status_events=false` and routable `external_thread_links=false`. Client status pages use partial changes and periodic snapshot reconciliation. Cross-user invitations must be described as proposals, never as a connected Thread or permission to send messages.

## Monitor consent and envelope v2

All four operations require authenticated allowlist entries. The dedicated native
bridge prevents generic RPC calls from bypassing proof verification or confirmation.
Manager and external roles may have these entries; a role name alone grants nothing.

| Operation | Client boundary |
|---|---|
| `monitor.broadcast_prepare` | Send Group, Monitor Endpoint and SHA-256 of the exact UTF-8 body. Persist the original operation ID. Verify complete Endpoint attestation, Owner-signed Group grant, consent cards, ordered recipient snapshot, revisions, binding and expiry against existing trust anchors. |
| `monitor.broadcast_confirm` | Require explicit review of exact text, Group, Monitor and every recipient. Refresh the same preview, seal to its independently verified Monitor key, and sign envelope v2 with the device identity. Persist the exact inner envelope and outer encrypted request atomically before sending. |
| `monitor.broadcast_status` | Read only the reviewed preview. Display approval state and individual `PENDING`, `FAILED`, `UNKNOWN` or `ACCEPTED` outcomes. `NODE_REPORTED` and `RELAY_PERSISTED` mean persistence evidence; neither establishes native consumption or task success. |
| `monitor.broadcast_recover` | Read-only lookup using the original Prepare operation ID after transport reconciliation. An uncertain Confirm requires Status for the same preview; never create a second approval. |

Text remains in memory. The Client neither trims nor normalizes it; malformed
UTF-16 is rejected before UTF-8 hashing. Only the digest goes to Prepare. The
Monitor envelope binds exact text, consent, snapshot, preview, device epoch/key,
Monitor binding, expiry and the accepted Confirm request sequence. The Hub stores
ciphertext and consent metadata. This specific flow does not establish blind
routing for other message APIs.

`membership.set_broadcast_permission` changes the explicit Group membership
`message.broadcast` permission using the expected membership version. The
`monitor` role does not grant this permission. Permission, membership or binding
changes invalidate prior previews and may require fresh Group key grants.

Limits are 16 KiB of UTF-8 text, 32 ordered recipients, dispatch batches of eight,
a five-minute preview and 16 unexpired previews per device / 64 per Owner.
Backpressure is a temporary-capacity error. Revocation does not immediately free
an unexpired slot. The Client does not automatically retry Prepare under a new ID.

The preview and Owner Group grant have independent validity windows. A current
grant may expire before the five-minute preview. Confirmation stops at the earlier
deadline; the original `expires_at` remains unchanged in the signed envelope.
The Client allows at most five seconds of local clock skew above the Hub's
five-minute preview duration, without extending either expiry. This is a local
validation bound, not a different wire TTL. Historical ledger recovery verifies
the complete proof and remains nonconfirmable after expiry, including after a
local clock rollback.

Before the first seal, the native session reads `topology.snapshot` and the source
Monitor's `group.key_status` using the same serialized session state. It checks
current identity, binding, membership, role and explicit broadcast permission,
then independently verifies the current Owner grant and Endpoint proof against
the original consent. Topology management CAS versions are distinct from signed
Group and membership revisions. These two read permissions are prerequisites
for the feature. The reads advance RPC counters before the final Confirm sequence
is allocated. Exact recovery of an already sent Confirm never repeats this
preflight or creates another sealed payload. The Hub's final guard handles changes
that occur after the reads; a rejection does not trigger automatic resubmission.

`PREPARED` and `APPROVED` may have an empty or partial recipient outcome ledger.
The Client validates every reported ordinal and identity; it requires the complete
roster only at `DISPATCH_AUTHORIZED`. An empty ledger is displayed as absent
delivery evidence, without inventing recipient results.

## Endpoint attestation and historical evidence

The v1.2.1 correction remains part of v1.3: ordered compact unsigned
`EndpointKeyAttestation` v1 retains the final `"signature":null` field. Its domain
is `cicada/fabric/endpoint-key-attestation/v1\0`. Independent Kotlin verification
checks raw proof SHA-256, full ML-DSA-65 public key and signature, Endpoint /
Principal / Node / SessionBinding identity and epoch, membership / Group
revisions, candidate binding and manifest digests, and validity times. A
self-attestation proves key possession, not Owner consent.

The current Monitor vector exposes public identities, canonical consent and
signature/AAD bytes. It contains no private Monitor key; its verification must
not be reported as successful decryption of the published ciphertext. Generated
local-key round trips are a separate test.

Historical v1.2.1 results are retained in the [fixed-image record](client-hub-v1.2.1-967dbd-validation.md)
and [native Group acceptance](client-group-key-v1.2.1-disposable-validation.md).
They do not establish v1.3 behavior. Physical-device security, native Monitor
execution, dual physical Nodes and public HTTPS each require their own evidence.
