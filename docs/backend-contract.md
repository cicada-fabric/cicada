# Client ↔ Hub contract: `client-hub-v1.6`

**Provenance supplement:** independent retrospective reconstruction now reproduces the immutable v4 fingerprint from all 773 pinned inputs, exit 0. Original build-time per-file mode capture remains **NOT_PROVIDED**. The earlier BLOCKED record is preserved; current live acceptance stays unrun. See the [separate supplement](client-hub-v1.6.1-fe565b4-provenance-supplement.md).

**Prior checkpoint provenance gate: BLOCKED.** At milestone `d580975`, the archive and pinned Git blobs matched, but the raw-permission fingerprint was not yet independently reproducible. That original result remains preserved; the supplement above records the later retrospective match. No live Hub or native-runtime acceptance is claimed; see the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md).


## Active checkpoint — Client-Control v1.6.1

The final corrected checkpoint passed the pinned offline build, 59 JavaScript tests, TypeScript, ESLint (22 warnings, no errors), 74 Kotlin tests across 14 selectors, and five offline UI checks; every gate exited 0. App/test APK SHA-256 values are `6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816` and `abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec`; compiled source FP is `0b89a85d5c332faffb980851501c474942f28c1b047562e0daa547f27a32d7f0` over 112 files. The owned emulator was removed and six resident containers were unchanged. These are local checks, not live Hub or native Monitor acceptance. The full Client commit is recorded in `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/client-delivery.redacted.json` after the milestone commit.

The deterministic integration target is clean Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, protocol `client-hub-v1.6.1`, wire 1, catalog `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` and immutable Hub image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. See the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md) for archive/source pins, exact DTO verification, commands, artifacts and individual acceptance states. Earlier evidence below is historical and does not establish this checkpoint.

No new Hub, Node or model runtime is started in this checkpoint. Current encrypted runtime capabilities, native Endpoint/Monitor acceptance, physical Android and public HTTPS remain unaccepted. The 38-operation local policy and 17 closed operations are retained; no advertisement or synthetic proof authorizes a closed operation. Terminal regroup `OUTCOME_UNCERTAIN` retains its exact ciphertext/counters and dedicated fence.

## Current v1.6 — Contract implementation and authorization

**Target:** clean Hub successor `4fb241b5e824eb752ceb85586089f44c408e1e7e`, `client-hub-v1.6`, wire 1, 55 catalog operations. The current imported bundle, catalog, source fingerprint and image pins are in the [4fb241b management validation record](client-hub-v1.6-4fb241b-management-validation.md). The prior [f4e4725 v1.6 validation](client-hub-v1.6-f4e4725-validation.md) is historical and remains attributed to its own bundle, source and images. The local Hub and interop IDs are immutable Docker image IDs, not published registry releases.

The current Client allowlist contains 38 of the 55 catalog operations; 17 remain closed. `network.directory` and `topology.endpoint_admission_preview` are bounded metadata reads. The prior app/test pair `9a6a…`/`3cbe…` passed encrypted `network.directory` with a session-epoch assertion and a read-only saved-fixture selector verifying the enrolled Owner against `topology.snapshot` and two unique ACTIVE Groups at version 1 in the selected ACTIVE Network. These connected results do not transfer to the final guarded pair `93d490…`/`041f6a…` (source FP `e75862…`, 110 files), whose 71-test/13-selector Kotlin matrix and five offline UI checks pass. The old Group evidence does not assert each Group's Owner or a Monitor Membership. Android Group creation remains tied to an intermediate app/test pair. The native Endpoint admission-preview selector has not run because the current native Endpoint fixture is missing. The existing regroup proposal, delegation issue and delegation revoke methods have a local proposal-ID review flow with explicit one-use issue and delegation-version-CAS revoke. The current local validator requires unique ACTIVE positive-version Membership projections in both Groups and the Monitor role on source Membership; this does not establish live proposal/mutation interoperability. Core's transactional Guard requires explicit current Monitor Membership in the target Group and its revision; ACTIVE Group records alone do not establish it. A catalog entry or public capability never substitutes for encrypted `session.capabilities`, current authority, local implementation, and the server Guard.

| New v1.6 operation | Catalog boundary | Client treatment |
|---|---|---|
| `network.directory` | Current Network Owner, opted-in directory cards | Display-only read. A bounded card does not reveal Owner, Node/native locator, Group, key, or workspace, and does not authorize joining or messaging. |
| `topology.endpoint_admission_preview` | Same-Owner current Network Endpoint admission preview | Display-only read. It returns current revisions for a possible later CAS; it does not change membership or grant keys/history. |
| `space.foreign_endpoint_preview` | Exact admission reviewed by the foreign Endpoint Owner | Closed. A preview is not Endpoint Join, admission approval, or history access. |
| `network.collaboration_key_manifest` | Current Network Owner and purpose-bound Endpoint manifest | Closed. Requires a verified current Endpoint key candidate and binding, plus separate `TASK` or `BROADCAST` purpose review. |
| `network.collaboration_key_grant` | Owner proof for exact current manifest and purpose | Closed. Requires independent Owner proof, exact current authority, explicit consent and server Guard. A key grant does not authorize `task.offer.*`, `broadcast.*`, or `direct.*`. |
| `network.collaboration_key_status` | Authenticated Owner's exact purpose grant | Closed pending a complete current-authority and dedicated status/reconciliation path. `active`, `stale`, and `revoked` are distinct from task or broadcast execution. |
| `link.review_policy_preview` | Current Link side policy preview | Closed. The preview digest, Link version, policy version and reviewers must be reviewed before proof creation. |
| `link.review_policy_grant` | One Owner proof for exact candidate Link policy | Closed. Each Link Owner must independently sign the same policy digest and version; one proof cannot stand for both sides. |
| `link.review_policy_status` | Current metadata-only policy and signed sides | Closed until the complete current Link/policy authority and dual-side result are independently checked. It reveals no Link message content. |

The seven closed v1.6-specific operations are `space.foreign_endpoint_preview`, the three `network.collaboration_key_*` methods, and the three `link.review_policy_*` methods. Of the earlier 13 gates, the three topology regroup/delegation operations now have a local flow; the seven cross-Owner Space consent/admission operations and three Link-key operations remain closed. Together those groups account for the current 17 closed operations. Do not open them based on catalog or Hub advertisement alone; require the applicable implemented Client flow, independent proof or consent, current authority, encrypted capability, and server Guard.

### Regroup and one-use delegation flow

The panel reads one `topology.regroup_proposal` by caller-supplied proposal ID; no proposal-list API is available. It binds the strict proposal DTO to the selected Hub, authenticated Human Owner, ACTIVE Network, Monitor Endpoint/Principal/Node binding, and current source/target Group records. `principal_id` is the Monitor actor identity and must remain distinct from the Human Owner. `SET_PARENT` requires distinct source and target Group IDs; `CREATE_CHILD` permits the same Group ID in both positions.

Issue is offered only for a current `PROPOSED` proposal with matching ACTIVE source/target Group versions and the Monitor's explicit current target-Group Membership and revision. Core's Guard requires this Membership separately; Group records and proposal preview do not create or imply it. Issue requires explicit confirmation by the enrolled Owner device over encrypted Client-Control RPC, a one-use `max_uses=1` delegation, and expiry in the future no later than proposal expiry or 24 hours. No separate offline Owner signature is specified for this authenticated Owner-device operation. Revoke requires a reviewed ACTIVE delegation and explicit confirmation with the exact delegation ID and expected version CAS. A Group version change does not by itself prevent revoking the current delegation; Hub/Owner/Network scope and the server's current delegation guard remain required.

For a lost response while the original RPC packet remains pending, recover that exact packet before any new RPC; a validated original cached/recovered `COMPLETED` response can clear the pending operation and its regroup context. If recovery instead returns a terminal authenticated `OUTCOME_UNCERTAIN`, retain the original ciphertext/counters and keep the dedicated regroup fence indefinitely. This Core contract does not promise a later correlated `COMPLETED` result or any automatic/manual clearing route after that terminal response. `status.snapshot` and proposal metadata cannot clear the fence or permit a replacement write. The fence remains blocked until a separately authorized Core reconciliation contract defines such a path. Live Core regroup acceptance remains pending.

### Candidate-bound Node pairing UI and remaining Core result-shape gap

The v1.6 wire contract's `nodes.preview` returns the pending `NodeControlKeyCandidate`, including Node and Hub Node-Control key fingerprints plus `candidate_digest` and `candidate_version`. `nodes.confirm` requires `{user_code,candidate_digest,candidate_version}` and fails closed when candidate fields are omitted or stale. The scope-bound pairing panel/parser, session-epoch binding, five focused tests, TypeScript, focused lint and current build pass. The current app passed the emulator UI flow against fresh same-Hub attach-3 public pins (SHA-256 `98c8dc0fe6e498b14d224f0ae368c3cbed251587313c2c18ab0554f6c418b333`; candidate version 1, expiry `2026-10-01T19:54:32Z`): it checked all candidate metadata against the independent pins, requested both trust confirmations, sent the preview-bound confirmation through the native Alert, then refreshed `nodes.list` and verified the same authorized Node with a positive binding version. `nodes.confirm` returned only an acknowledgment; the binding object came from the subsequent list read. The redacted receipt is `/gpu1-share/data/cicada-client/v16-deterministic-offline-management-20261001-final/android/node-pairing-ui.redacted.json`, SHA-256 `b9b26faea3d2ecdfc7469898892a684097717be8a662ec70641956fd16a35815`; its 143 steps all exited `0`, and it records no RPC injection, short-code persistence or UI-dump persistence. The command wrapper receipt is `node-pairing-ui-command.redacted.json`, SHA-256 `261de4b594ac5f457a8b28f1a40cbfcc8211fc1d9d21fbc5a4b4fe13c2267c09`, exit `0`; it records the exact public pin file hash and APK pair. The candidate has since expired; refresh before another attempt. This confirms the Client pairing UI and Hub binding, not native Thread Join. Core's redacted result/classification receipts show its native-tool Join attempt failed with HTTP 404 because an existing Endpoint was absent for a Group with non-empty `NetworkID`; Network enrollment is separate. The tool failed despite all 13 recorded subprocess phases exiting `0`, and the witnessed controller terminal exit was `1`; exact controller argv was not retained. This is a fixture/setup failure, not a pairing UI failure or accepted native Join. The wire result table labels confirmation/list/revoke records `NodeDeviceBinding`, while the Core implementation path reports `NodeControlKeyBinding`; resolve this DTO mismatch before result-shape acceptance. The pairing evidence combines the authenticated Owner role oracle and declared `nodes.list` authorization result; it does not export a per-Node Owner field.

### Public vectors and authority boundary

The v1.6 bundle carries three public synthetic proof vectors. `owner-link-review-policy-proof-v1.json` (SHA-256 `aab0a7074fb32523f75bb89f9a61f4725d9f462c2d83eec33d23f79609fc5907`) signs eleven ordered Policy claims with no `signature` field. `network-collaboration-broadcast-consent-v1.json` (SHA-256 `c18b237047a6963b95844a1a32307794e6b353150313b77ab2ce84393b0ab8ea`) signs twelve ordered `BROADCAST` claims including final `"signature":null`. The separate TASK vector (SHA-256 `ad073291703a01513c27fc729439a6bfa8502a8df8f8138a7ed1c3863a4d0c64`) has its own purpose and twelve-claim shape. Endpoint attestation v1 signs the ordered DTO including final `"signature":null`; OwnerLinkKeyGrant v2 signs exactly ten claims without a signature field. Keep all four encodings distinct.

All three vectors use synthetic public keys and signatures. They verify byte formats and cryptographic consistency only; they do not establish a trusted Owner key, current Endpoint or Link authority, admission, native Join, or a live Network binding. In the BROADCAST vector the candidate `attestation` decodes to an opaque placeholder, and its `fingerprint` is synthetic. Neither is a complete Endpoint attestation or a current-authority proof. An independently trusted current Owner key and authenticated current context must be supplied separately.

The remaining Core fixture must bind a complete candidate Endpoint to an actual current authority view: full canonical Endpoint attestation v1 and its ML-DSA verification under the candidate public identity; Endpoint, Principal, Owner and Node identities; native Session identifier/digest; current binding identifier/epoch; Network membership revision and Endpoint enrollment revision; and the trusted Owner public key and exact purpose grant. The current collaboration vectors contain the identity and revision-shaped fields but only synthetic session/binding values and opaque attestation bytes. Core must provide a disposable current native Endpoint fixture showing those fields belong to the same joined Endpoint before Android can claim native current-authority acceptance. Core's native Join attempt returned HTTP 404 because no existing Endpoint was present for the Group with non-empty `NetworkID`; Network enrollment is a separate prerequisite, not a direct Group bootstrap route. The exact Core result and classification receipts are in the current validation report; the Join tool failed, and the witnessed controller terminal exit was `1` (exact argv not retained). For foreign admission, a separate fixture must also show the Endpoint Owner's exact admission review, Group Owner admission, fresh Node Join and resulting current membership; each Owner approves only its own side.

The durable direct-Network grant uncertainty fence remains separate from outer RPC recovery. A generic `status.snapshot` can reconcile an outer RPC outcome but cannot release an uncertain direct `network.key_grant`; it must retain the original signed proof, packet, and counters until dedicated `network.key_status` correlation completes. Profile changes or reset must not replace unresolved proof evidence. Regroup follows the same no-replacement rule: recover a still-pending original packet; if authenticated recovery terminates as `OUTCOME_UNCERTAIN`, the current Core contract has no correlated later result or clearing route, so preserve the original evidence and leave the dedicated fence blocked indefinitely pending a separately authorized reconciliation contract. The optional proposal delegation projection is not operation correlation. The new collaboration-key grant methods remain closed and require their own purpose-specific status evidence.

### v1.6 evidence status

The exact 4fb241b contract import and Core image provenance passed. The final guarded app/test pair is `93d490…`/`041f6a…`, compiled from source fingerprint `e758625224b056a32a0ddb0d498606a6a49522f623a6c0173704a4896641cffb` over 110 files. Docker build, 56 JavaScript tests, TypeScript, lint (22 warnings, no errors), 71 Kotlin tests across 13 selectors, and five offline UI checks passed. The Client verifies explicit current source/target Memberships and Endpoint association before issue, including the source Monitor role; it rechecks the scope before confirmation and in the native write path. Membership DTO `version` does not expose the Core database revision.

Earlier pair `9a6…`/`3cbe…` alone owns the connected Directory, saved-fixture Group-scope, external-role intersection, original-byte enrollment/RPC response-loss recovery, and Node pairing UI PASS receipts. Those results do not transfer to the final guarded pair; its live Hub checks are **NOT_RUN**. Core's separate native Join failed with HTTP 404, controller exit 1, because required Endpoint/Network bootstrap was absent. Native admission preview and live regroup remain **BLOCKED**. The Node result DTO mismatch and terminal regroup `OUTCOME_UNCERTAIN` reconciliation remain open. All Client-owned disposable environments were removed, six resident containers were unchanged, and evidence remains outside Git. Physical Android, public HTTPS and additional platforms are **NOT_RUN**. See the [validation report](client-hub-v1.6-4fb241b-management-validation.md) for complete pins, artifact attribution, commands, exits and receipts; earlier Hub-version results remain historical.

## Historical v1.5 checkpoint

**Target:** clean Hub `bd79ff93c90ecafc28a2471dd9523444903b39e6`, `client-hub-v1.5`, wire 1, 46 catalog operations. The complete archive, catalog and immutable image pins are in [the validation record](client-hub-v1.5-bd79ff9-validation.md). Only that image is accepted for this checkpoint; older results and current dirty Core work remain separately attributed.

The Client retains its 33 implemented RPC operations and explicitly rejects the seven new `space.*` consent/admission operations and three `topology.*` delegation/proposal operations. Native rejection precedes persisted-state access, device-key creation, pending replacement, and counter mutation. The UI also filters them even when the authenticated Hub advertises permission. Link key consent remains disabled. Cross-user messages, shared-history grants and silent delegated approval are unavailable.

Existing profile isolation, independent Hub pins, encrypted capabilities, original-packet recovery, Monitor ledger and the durable Network grant uncertainty fence remain in place. A generic snapshot cannot authorize a replacement Network Grant. Full dual-Owner v2 consent requires authoritative proof-side semantics, complete signed synthetic vectors, independent Kotlin verification, exact scope/version/expiry review and explicit phone confirmation before implementation can be enabled. A proposal remains separate from User Approval.

Fresh acceptance is recorded per layer: imported contract and image provenance; Kotlin public vectors and local guards; actual Android UI; disposable fixed-image Hub permission and response recovery. Physical Android, public HTTPS, full native Network consent, v1.5 Node/Monitor delivery, iOS and native HarmonyOS require separate evidence. v0.2 Dot/Live is documentation only.

## Historical v1.4 checkpoint

**Historical checkpoint:** 2026-09-30, branch `dev/react-native`, clean Hub `f30892fcd79a27bfe5604575deaecebe52c5ec50`, protocol `client-hub-v1.4`, catalog `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`. The [v1.4 validation record](client-hub-v1.4-f30892f-validation.md) provides complete pins, commands, APK hashes and outcome boundaries.

That checkpoint added isolated Hub profiles and explicit ACTIVE Network selection, topology v2, `group.create(network_id)`, and dedicated `network.key_manifest/key_grant/key_status`. No operation is authorized by a local profile or a public capability alone. A captured profile and selection generation fences every native call. Device identity and pending enrollment/RPC bytes remain in their original profile; deleting unresolved profiles is refused. A pinned profile cannot be reassigned to a different Hub ID.

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
