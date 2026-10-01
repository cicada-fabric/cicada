# CICADA Client development and validation plan

**Provenance gate: BLOCKED.** The v1.6.1 public archive and pinned Git blobs match, but the independent raw-permission build fingerprint is not yet reproducible. No complete import, live Hub or native-runtime acceptance is claimed; see the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md).


## Active checkpoint — Client-Control v1.6.1

The final corrected checkpoint passed the pinned offline build, 59 JavaScript tests, TypeScript, ESLint (22 warnings, no errors), 74 Kotlin tests across 14 selectors, and five offline UI checks; every gate exited 0. App/test APK SHA-256 values are `6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816` and `abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec`; compiled source FP is `0b89a85d5c332faffb980851501c474942f28c1b047562e0daa547f27a32d7f0` over 112 files. The owned emulator was removed and six resident containers were unchanged. These are local checks, not live Hub or native Monitor acceptance. The full Client commit is recorded in `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/client-delivery.redacted.json` after the milestone commit.

The deterministic integration target is clean Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, protocol `client-hub-v1.6.1`, wire 1, catalog `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` and immutable Hub image `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589`. See the [v1.6.1 validation record](client-hub-v1.6.1-fe565b4-validation.md) for archive/source pins, exact DTO verification, commands, artifacts and individual acceptance states. Earlier evidence below is historical and does not establish this checkpoint.

No new Hub, Node or model runtime is started in this checkpoint. Current encrypted runtime capabilities, native Endpoint/Monitor acceptance, physical Android and public HTTPS remain unaccepted. The 38-operation local policy and 17 closed operations are retained; no advertisement or synthetic proof authorizes a closed operation. Terminal regroup `OUTCOME_UNCERTAIN` retains its exact ciphertext/counters and dedicated fence.

## Historical v1.6 checkpoint

**Target:** clean Hub `4fb241b5e824eb752ceb85586089f44c408e1e7e`, `client-hub-v1.6`, wire 1, 55 catalog operations. The [validation report](client-hub-v1.6-4fb241b-management-validation.md) records the fixed archive, catalog, source and immutable image pins. No successor or dirty Core source is accepted implicitly.

The Client locally implements 38 operations and keeps 17 closed. Current Directory/admission controls are bounded metadata reads. Regroup provides one named proposal review, explicit one-use issue and version-CAS revoke. Issue requires unique explicit ACTIVE source/target Principal Memberships with positive projected versions, Endpoint association with both Groups, and the source Monitor role. Fresh topology and lifecycle checks fence stale consent. A projected Membership version is not the Core database revision. Terminal authenticated regroup `OUTCOME_UNCERTAIN` preserves original ciphertext/counters and keeps the write fence blocked; snapshots cannot clear it.

| Gate | Status | Evidence and remaining work |
|---|---|---|
| Imported contract / immutable Hub image | **PASS** | Exact 4fb241b provenance in the validation report |
| Final guarded build | **PASS**, exit 0 | App `93d490…`, test `041f6a…`, compiled source `e758625224b056a32a0ddb0d498606a6a49522f623a6c0173704a4896641cffb` (110 files) |
| JavaScript / TypeScript / lint | **PASS**, exits 0 | 56 tests, TypeScript; lint 22 warnings, no errors |
| Final Kotlin matrix | **PASS**, exit 0 | 71 tests/13 selectors, including 8 regroup checks and valid roles-only Monitor |
| Final offline UI and owned cleanup | **PASS**, exits 0 | Five checks; fresh network-isolated emulator removed; six residents unchanged |
| Earlier connected capabilities, Directory, Group-scope, 201/200 recovery and Node pairing UI | **PASS on earlier `9a6…`/`3cbe…` only** | Exact receipts retained; none transfers to final guarded artifacts |
| Final guarded APK live Hub checks | **NOT_RUN** | Repeat only with a fresh approved complete fixed-image fixture |
| Core native Join attempt | **FAIL**, controller 1, tool HTTP 404 | Required Endpoint/Network bootstrap was absent; exact argv not retained |
| Current native Endpoint admission preview / Monitor regroup | **BLOCKED / NOT_RUN** | Requires a real native Network Join, current binding, explicit target Membership and Monitor proposal |
| Candidate guarded APK `533142…` | **FAIL**, driver 1 / ADB 0 | Valid roles-only case rejected; fixed in final APK; candidate UI not run |
| Physical Android / public HTTPS / iOS / native HarmonyOS | **NOT_RUN** | Separate environment acceptance |

## Next ordered gates

1. Preserve all earlier artifact and failure receipts; the final Client commit is recorded in `/gpu1-share/data/cicada-client/v16-4fb241b-20261001/provenance/client-delivery.redacted.json`.
2. Obtain a supported native Network/Endpoint bootstrap and explicit Owner Group admission fixture. If it requires a new Core contract, independently verify its complete clean delivery before changing pins.
3. On that complete fixture, rerun final-APK encrypted capabilities/recovery, Node pairing, Endpoint preview and explicit Monitor delegation. Verify stale CAS, expiry, revoke, one-use application and replay refusal without synthetic Threads.
4. Keep all 17 unsupported consent/proof operations closed. Implement each only after its independent Owner proof, current authority, explicit confirmation and recovery semantics are complete; see the [readiness audit](client-hub-v1.6-operation-readiness.md).
5. Run physical-device key boundaries and public HTTPS independently. No emulator or historical native result substitutes for either.

## Historical v1.5 — Development checkpoint

**Target:** clean Hub `bd79ff93c90ecafc28a2471dd9523444903b39e6`, `client-hub-v1.5`, wire 1, 46 catalog operations. The complete archive, catalog and immutable image pins are in [the validation record](client-hub-v1.5-bd79ff9-validation.md). Only that image is accepted for this checkpoint; older results and current dirty Core work remain separately attributed.

The Client retains its 33 implemented RPC operations and explicitly rejects the seven new `space.*` consent/admission operations and three `topology.*` delegation/proposal operations. Native rejection precedes persisted-state access, device-key creation, pending replacement, and counter mutation. The UI also filters them even when the authenticated Hub advertises permission. Link key consent remains disabled. Cross-user messages, shared-history grants and silent delegated approval are unavailable.

Existing profile isolation, independent Hub pins, encrypted capabilities, original-packet recovery, Monitor ledger and the durable Network grant uncertainty fence remain in place. A generic snapshot cannot authorize a replacement Network Grant. Full dual-Owner v2 consent requires authoritative proof-side semantics, complete signed synthetic vectors, independent Kotlin verification, exact scope/version/expiry review and explicit phone confirmation before implementation can be enabled. A proposal remains separate from User Approval.

Fresh acceptance is recorded per layer: imported contract and image provenance; Kotlin public vectors and local guards; actual Android UI; disposable fixed-image Hub permission and response recovery. Physical Android, public HTTPS, full native Network consent, v1.5 Node/Monitor delivery, iOS and native HarmonyOS require separate evidence. v0.2 Dot/Live is documentation only.

Completed in this checkpoint: 54 Kotlin and 29 JavaScript tests; independent exact external-role operation checks across four Android sessions; fixed-Hub scoped Group creation and foreign-Owner denial; exact enrollment/RPC response-loss recovery; all three isolated outer-ledger recovery faults; offline UI and bounded connected management observation. Test commands and artifact attribution are in the current validation record. Next development gates are a separately pinned complete dual-Owner v2 proof/authority delivery, positive native Network consent with dedicated uncertain-outcome reconciliation, and fresh native Worker, physical-device and public HTTPS acceptance. Historical native results cannot satisfy these gates.

Subsequent [shared-space v2 framework work](shared-space-v2-framework.md) adds a collapsed, scope-bound local review panel and independent candidate-only complete-status proof verifier. The public Core vector is WIP; it is separate from the fixed protocol snapshot. All ten v2 operations and three Link key operations stay disabled. A local reading marker cannot become approval. The next integration must validate per-Owner external signatures and explicit confirmation separately from native Join and final dual-proof status. Proposal/delegation UI currently explains the blocked lifecycle rather than fetching or applying a proposal.

The bounded [Release packaging checkpoint](release-packaging-validation.md) selects the existing ABIs explicitly, enables managed-code/resource optimization and retains the native crypto/STT dependencies. It records actual unsigned artifacts separately from disposable signed test copies. Local package size and emulator inference do not replace a clean future Hub contract, native consent acceptance, physical-device measurements or public HTTPS validation; the protocol gates remain unchanged.

The subsequent [Release policy test correction](release-policy-public-validation.md) passes all four policy tests through public session behavior and synthetic authenticated responses against the unchanged optimized product. Only instrumentation was rebuilt; the original reflection failure remains separately recorded. This local test does not advance live Hub, native consent, physical-device or public HTTPS gates.

## Historical v1.4 checkpoint

**Historical checkpoint:** 2026-09-30, branch `dev/react-native`, clean Hub `f30892fcd79a27bfe5604575deaecebe52c5ec50`, protocol `client-hub-v1.4`, catalog `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54`. The [v1.4 validation record](client-hub-v1.4-f30892f-validation.md) provides complete pins, commands, APK hashes and outcome boundaries.

That checkpoint added isolated Hub profiles and explicit ACTIVE Network selection, topology v2, `group.create(network_id)`, and dedicated `network.key_manifest/key_grant/key_status`. No operation is authorized by a local profile or a public capability alone. A captured profile and selection generation fences every native call. Device identity and pending enrollment/RPC bytes remain in their original profile; deleting unresolved profiles is refused. A pinned profile cannot be reassigned to a different Hub ID.

Network proof verification uses the exact v1.4 domains, full ML-KEM/ML-DSA public identity, canonical raw self-attestation, native Session commitment, complete manifest digest, current identity/revisions, externally signed Owner proof and explicit confirmation. Signed claims end with `"signature":null`. Manifest digest claims omit the Owner-only `native_session_id` and include `"digest":""`. Group bindings do not substitute for Network direct bindings. Fresh encrypted capabilities, topology and manifest are checked before sealing a grant. The fixed source lacks an external Network signing CLI, so the real positive Network grant remains BLOCKED; its published incomplete vector is tested for its precise bytes and is never accepted as a complete production preview.

Completed bounded gates: final APK build, 45 Kotlin tests, 23 JavaScript checks, offline connection UI, and fresh-device disposable fixed-image enrollment, encrypted capabilities, ACTIVE topology/selection and Network-scoped Group creation. An independent durable Network grant uncertainty fence rejects replacement writes and identity resets until dedicated reconciliation is implemented. Next gates: accept a separately pinned Core signer delivery and complete native fixture; then validate real Network consent, dedicated status correlation and rejection/recovery states. Native Node/Monitor delivery, physical devices, public HTTPS and additional platforms retain their own test status. Do not use historical PASS results or unpublished Core changes for the current target.

## Historical checkpoints

**Last updated:** 2026-09-27

This repository develops the mobile Client only. Android is the current target. The completed historical integration baseline was Hub commit `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`, contract `client-hub-v1.2.1`, protocol archive SHA-256 `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a`, catalog SHA-256 `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`, and full local image ID `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`. The [backend contract](backend-contract.md) describes the wire behavior; the [v1.2.1 validation report](client-hub-v1.2.1-967dbd-validation.md) records runtime evidence. Results for the earlier `41beaf0` image are historical only.

## Completed v1.3 Client emulator slice

The fixed target is clean Hub `be0269e80c41e94881d131bd4f4b233e80b6ffe6`,
contract `client-hub-v1.3`, catalog
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`,
archive `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9`,
image `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`.
The [dedicated plan and validation record](client-hub-v1.3-be0269e-validation.md)
tracks the ordered implementation and independent acceptance gates. The user flow
is exact local text → verified Monitor/recipient review → explicit confirmation
→ consent-bound sealing → bounded authoritative outcomes. Lost responses must
retain original request bytes and reconcile the same operation.

Implementation `9568b2ff6d4e156b70484c10b7fd5195405004b0` passed the scoped
emulator acceptance: 21 Kotlin checks, 13 JavaScript checks, independently
verified Group grants, actual product consent/status UI, genuine HTTP 200
response-loss recovery, bounded capacity, changed-text rejection and current
permission revocation before sealing. The runtime used synthetic authorization
Endpoints; native Monitor delivery and model consumption remain **NOT_RUN**.
The report records each APK and keeps earlier failures separate. The disposable
Hub/Node/proxy/emulator and private fixture material have been removed.

The v1.2.1 status below is historical; none of its Android or native PASS entries
certifies the new v1.3 target.

## Historical v1.2.1 status

| Area | State |
|---|---|
| Protocol package, manifest, image labels | **PASS** for the fixed target. The imported bundle records the exact commit, `source_dirty=false`, and catalog digest. |
| Android encrypted session | **PASS**. An independent Android session verified encrypted `session.capabilities` against the fixed Hub. |
| Android app/test build | **PASS** for the corrected artifacts listed in the validation report. TypeScript, lint, contract, and whitespace checks also exited 0. |
| Lost enrollment and RPC responses | **PASS**. Android retried the exact saved Owner Grant and recovered the exact RPC response on the fixed image. |
| Three recovery faults | **PASS** on a disposable `/tmp` Hub: `STILL_PROCESSING`, Hub restart after `FAULT_READY` yielding `OUTCOME_UNCERTAIN`, and `RECOVERY_UNAVAILABLE`. Android retained the original packet and did not create a second operation. |
| Endpoint attestation, synthetic manifest, and owner proof | **PASS** on corrected APK `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76`; `EndpointAttestationVectorTest` returned `OK (4 tests)`, ADB exit 0. The earlier `70423555…` candidate failed the valid four-digit RFC3339Nano timestamp case; commit `af3ad451e29d0c43142b3fc792272bbd6df75c84` fixes it. |
| Native Group preview/grant/status implementation | Implemented with external signed-proof import, explicit Android confirmation and a dedicated encrypted status read. The APK does not import the owner private key; it verifies against the owner public approval key saved from authenticated enrollment. The fixed-image live acceptance passed. |
| Positive Group grant against the fixed Hub | **PASS** on a disposable fixed-image Hub with a real native Codex Endpoint, external Owner signing, explicit Android confirmation, and encrypted `group.key_status=CURRENT`. The same grant became `STALE` after the native lease expired, then `PROOF_EXPIRED` after proof expiry. Exact artifacts and limits are in the [Group key acceptance report](client-group-key-v1.2.1-disposable-validation.md). |
| Real Node/Codex approval | **PASS** on the fixed image with E2E candidate APK `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197`: one original Codex turn was approved on the same native Thread/Worker attempt 1, Worker and Goal completed, Intent resolved, and `goal.result` matched 30 bytes. This does not validate Group grant or production TLS. |
| Physical Android device and public HTTPS | **NOT_RUN**. |

The full command and evidence record is in [the v1.2.1 validation report](client-hub-v1.2.1-967dbd-validation.md). An initial recovery-fixture attempt failed with HTTP 502 because the fixture was not run from `/tmp`; the corrected disposable-Hub runs passed and both results are recorded separately. The four-digit RFC3339Nano compatibility issue found in one candidate was fixed, rebuilt, and retested successfully.

## Product and model work

The app retains the five-page Android UI, a clear voice entry point, editable transcripts, and a text composer that works without a speech model. The model centre offers only models with a real format/runtime/device validation record. Model weights are optional, verified before installation, and kept in app-private storage. See [model selection](model-selection.md) and [speech validation](stt-validation.md) for model sources, licenses, command results, timings, and limitations. Host inference does not count as physical Android testing; microphone, memory, battery, and background-resume measurements on a physical device remain **NOT_RUN**.

State views distinguish Node connectivity, native session binding, Worker execution, Goal lifecycle, Intent dispatch, and Artifact references. They show authority, observation time, and stale state. Large lists load on demand. When the app is disconnected or unauthorized, it must not show development fixtures or claim that a message was sent, an approval was granted, a Goal completed, or a Thread connected.

## Remaining gates

1. Resolve the original native Session lease failure documented in the [joint Monitor attempt](client-monitor-v13-native-acceptance.md) before repeating Android-to-native delivery acceptance. No Group grant, positive Prepare or Confirm was submitted in that failed attempt. The separate [Prepare RPC recovery fault run](client-monitor-v13-recovery-faults.md) passed all three ledger-level recovery states; Confirm recovery faults and recovery after actual Monitor business execution remain untested. Preserve the completed v1.2.1 native Group trace and separate [two-Owner authorization acceptance](client-two-owner-v1.2.1-967dbd-validation.md); the latter used synthetic Endpoints and does not establish native messaging.
2. Preserve the completed fixed-image Node/Codex trace in the validation record. Any new Hub image or Client protocol change needs its own run; do not transfer results from historical `41beaf0` or the separate Group verifier artifact.
3. Test on a physical Android device: enrollment and Keystore boundary, foreground/background recovery, microphone capture, supported model download and inference, latency, memory, and battery. Mark each item `NOT_RUN` until measured.
4. Validate production-style public HTTPS, certificate checks, device network behavior, and recovery after network changes. Do not infer this from emulator-to-host HTTP.
5. Keep full status push, cross-user Thread routing, equipment migration/recovery, iOS, and native HarmonyOS as separate future gates. Native HarmonyOS requires an ArkUI/ArkTS app; the React Native TSX UI is not a native Ark application.

## Development and safety rules

- Develop, build, and test in Docker. Verify Docker data root `/gpu1-share/data/docker-root`; keep project cache, model downloads, APKs, test identities, and temporary Hub state under `/gpu1-share/data/cicada-client`. Do not alter `/gpu1-share/data/cicada` data or global Docker configuration.
- Work only in this Client repository. Treat the adjacent CICADA core as read-only. Use one-time disposable Hub state for integration tests; never inspect or edit its database from Android.
- Fixed dependencies use lock files. Do not put real API keys, long-lived bearer credentials, private keys, complete sensitive messages, audio recordings, or model-test personal audio in Git, APKs, snapshots, persistent caches, logs, or analytics.
- All user content and management operations use independently pinned Client-Control PQ encryption and encrypted `session.capabilities`. No old `/v1` bearer fallback. Every write uses server guards, expected versions, idempotency, and authoritative rereads after conflict or uncertain network outcome.
- A protocol package, public capability flag, Hub image tag, HTTP 200, or test fixture is not runtime proof. Record exact package, complete image ID, app artifact, command, exit code, outcome, and limits for each validation.
- Do not push, merge, publish, deploy production, rotate keys, or change global CLI/Docker configuration automatically.
