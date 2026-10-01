# CICADA Client

CICADA Client is the mobile entry point for a CICADA environment. It lets an authorized user inspect Hub state, submit confirmed text or locally transcribed speech to Control, and perform supported management actions. Control and authoritative management state usually run on a Hub; native Threads and their Workers run on Nodes. The Client does not inject input directly into a native Worker session.

The shared application is written in TypeScript and React Native. **Android is the only implemented and validated mobile platform.** Android security and device integrations use Kotlin. iOS remains a future platform. A future native HarmonyOS application will need an ArkUI/ArkTS interface; this React Native UI is not a native HarmonyOS application. See the [stack decision](docs/stack-decision.md).

## Product capabilities

- **Status and work:** Read authenticated snapshots and partial changes for authorized Nodes, Endpoints, Workers, Goals, Groups, and Tasks. Submit user-confirmed text or reviewed speech transcripts to Control, inspect Intent dispatch, and read bounded Goal results when the session permits it. Intent, Goal, Worker, and Artifact states remain distinct.
- **Local speech:** Supported Vosk, Paraformer, and SenseVoice models are optional downloads. The model centre verifies, installs, selects, and removes supported models in the app's private storage. Users can always enter text without a model. Audio is not uploaded in the first phase. See [model selection](docs/model-selection.md) and [speech validation](docs/stt-validation.md).
- **Independent connections:** Each Hub profile keeps its own verified pin, device keys, enrollment, encrypted session, counters, pending requests and Monitor ledger. Hub and Network selection is explicit. Switching clears transient drafts and consent previews; late callbacks remain bound to their original selection.
- **Network consent:** The existing direct Network flow supports ACTIVE Network selection, scoped Group creation and independent verification of Endpoint self-attestation and external Owner key consent. The v1.6 collaboration-key grants remain gated. See the [current v1.6 successor validation](docs/client-hub-v1.6-4fb241b-management-validation.md) and the [historical v1.5 record](docs/client-hub-v1.5-bd79ff9-validation.md) for their separate scope.
- **Hub management:** Authorized operations use the Hub's versioned guards and encrypted Client-Control RPC. Feature visibility requires both a locally implemented operation and permission in encrypted `session.capabilities`. The current policy locally implements 38 of 55 operations, including bounded Directory/admission metadata reads and an explicitly confirmed one-use Monitor regroup delegation flow. Seventeen operations remain closed; the Hub remains authoritative for every write.
- **Monitor consent:** Review an exact message and ordered recipient roster before authorizing a same-owner Group broadcast. The Client verifies the Monitor's Endpoint and Owner proofs, checks current source authorization before sealing, and reports approval separately from delivery or model consumption. See the [historical v1.3 validation](docs/client-monitor-v13-25013b5-native-validation.md) for its tested scope; that result does not establish v1.6 native delivery.
- **Recovery:** The Client persists the exact enrollment Grant request and each signed encrypted RPC packet before sending. It recovers a lost response with the original packet through `/v2/client/rpc/recover`. A still-pending regroup operation may finish through a validated cached response; terminal authenticated `OUTCOME_UNCERTAIN` retains its original ciphertext and dedicated fence indefinitely under the current Core contract, with no later clearing route. See the [successor validation report](docs/client-hub-v1.6-4fb241b-management-validation.md).

## Security boundary

Client-to-Control business RPC uses the Client-Control v1 post-quantum protocol: ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. Users must verify and pin the full Hub identity through an independent trusted channel. Device enrollment requires an independently signed, one-time `OwnerDeviceGrant`. Android wraps its private keys with Android Keystore. Release builds require HTTPS; local debug HTTP is restricted to emulator-to-host development addresses.

The Client does not use legacy `/v1` management bearer APIs, store Hub or Node bearer credentials, or read the Hub database. This encrypted channel terminates at Control so Control can process the request. It does not prove that ordinary peer messages are unreadable to the Hub. Cross-user Thread messaging remains unavailable while the server advertises `external_thread_links=false`.

The Endpoint attestation v1 signature input includes the final `"signature":null` field. The Android verifier handles canonical Go RFC3339Nano timestamps. Historical v1.2.1 acceptance covers a real native Codex Endpoint, independent external Owner signing, explicit Android confirmation, and encrypted `group.key_manifest → group.key_grant → group.key_status` with `CURRENT`, then `STALE` after binding expiry and `PROOF_EXPIRED` after proof expiry. See the [Group key acceptance report](docs/client-group-key-v1.2.1-disposable-validation.md) for its exact APKs and rejection tests. Those results do not certify the current v1.6 target. Physical Android and public HTTPS remain untested.

## Current Hub integration target: v1.6

The current contract snapshot is the clean Core successor `4fb241b5e824eb752ceb85586089f44c408e1e7e`, `client-hub-v1.6`, wire 1. Its 55-operation catalog is unchanged from f4e4725; the imported archive and Core source/image pins are recorded in the [current management validation report](docs/client-hub-v1.6-4fb241b-management-validation.md). The earlier [f4e4725 validation report](docs/client-hub-v1.6-f4e4725-validation.md) remains historical evidence for its own source and image; its PASS results do not transfer to this successor.

| Item | Fixed value |
|---|---|
| Hub source revision | `4fb241b5e824eb752ceb85586089f44c408e1e7e` |
| Protocol / wire | `client-hub-v1.6` / `1` |
| Protocol archive SHA-256 | `9ada56ced408e90fbdf2a224897cf43fee2d325e6963f8f1714b0ef888f4f689` |
| Catalog SHA-256 | `1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c` |
| Clean Core source fingerprint | `31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2` |
| Local Hub Docker image ID | `sha256:a48ce4b096f4d003ed6f8586674f4c175ce8616005dc65e7cbf9e9edaededf65` |
| Local interop image ID | `sha256:e2268a08ef1b27619ff6dc7039e8f883518130c5292384967d973cb759b3b810` |

The [imported snapshot](contracts/client-hub-v1.6-4fb241b/manifest.json) contains the verified 55-operation catalog. The current local policy implements 38 operations and keeps 17 closed. `network.directory` and `topology.endpoint_admission_preview` are bounded metadata reads. The regroup panel reviews one named proposal at a time and provides explicit one-use issue and version-CAS revoke actions; those local controls do not assert live Core acceptance. The other 17 operations retain their independent proof, consent, current-authority, and recovery gates. Public capabilities, synthetic vectors, and local implementation never replace encrypted `session.capabilities` or the server Guard.

The final guarded app/test APKs are `93d490…`/`041f6a…`, built from source fingerprint `e75862…` over 110 files. The guarded build, 71 Kotlin tests across 13 selectors, and five offline UI checks pass. JavaScript (56 tests), TypeScript, and focused lint pass. These are local build/test results only: the prior app/test pair `9a6a…`/`3cbe…` owns the earlier connected Directory, saved-fixture Group-scope, external-role, four enrollment/RPC 201/200 recovery, and candidate-bound Node UI passes. None transfers to the guarded pair. That prior Group-scope receipt does not assert each Group's Owner field or explicit Monitor target-Group Membership; the earlier Android-created two-Group result remains intermediate. The prior Node candidate expired. Current native Endpoint admission preview and live regroup proposal/issue/revoke remain unaccepted. Core's native Join tool separately failed HTTP 404 because a Group with non-empty `NetworkID` had no existing Endpoint; Network enrollment is a separate prerequisite. All 13 subprocess phases exited `0`, while the witnessed controller terminal exit was `1`; its exact argv was not retained. The wire/Core Node result DTO naming mismatch remains open. The external OwnerGrant signer used the Owner private key for signing outside the Client; Android did not read or import it. Physical Android and public HTTPS remain unaccepted. See the [current report](docs/client-hub-v1.6-4fb241b-management-validation.md) for pins, hashes, receipts and limits.

## Historical acceptance

The [v1.5 validation](docs/client-hub-v1.5-bd79ff9-validation.md),
[shared-space framework](docs/shared-space-v2-framework.md), and
[Release packaging report](docs/release-packaging-validation.md) retain their
original source, APK, image, commands and limitations. Earlier native Group,
Monitor and Worker results remain version-specific; they do not certify v1.6.

## Build and local development

Build and test in Docker. Verify the Docker data root before development; this environment expects `/gpu1-share/data/docker-root`. Keep build caches, model downloads, test identities, and temporary Hub state under `/gpu1-share/data/cicada-client`, outside Git. Do not change global Docker configuration or data belonging to the adjacent CICADA core project.

```bash
python3 scripts/check-client-contract.py
./scripts/docker-build.sh
./scripts/docker-build-android-test.sh
```

The contract checker defaults to the current imported `4fb241b` v1.6 snapshot. Verify its archive SHA-256 against the external receipt before relying on the result. The checker is an offline contract check; it does not replace fixed-image provenance or encrypted runtime `session.capabilities` verification.

```bash
python3 scripts/check-client-contract.py
```

Run its public-fixture regressions in the Docker development image with `python3 scripts/test_check_client_contract.py`.

`docker-build.sh` copies its APK to `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`. `docker-build-android-test.sh` writes the current debug and test APKs to `android/app/build/outputs/apk/debug/app-debug.apk` and `android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`. Hash the artifacts used in each test run; the exported copy is not refreshed by the test-build script. A successful host or emulator build does not establish physical-device, iOS, or public HTTPS validation.

For local unsigned per-ABI Release APKs, use `scripts/docker-build-release.sh` with a complete immutable build-image ID; `--android-test` additionally builds Release instrumentation. The helper runs offline with a cached image, enables R8/resource shrinking and preserves the existing default Debug output. Actual artifact sizes, SHA-256 values, native-library inventories and the bounded Release runtime checks are recorded in [Release packaging validation](docs/release-packaging-validation.md). These artifacts are not a published or production-signed release.

## Project documentation

- [Git milestones and validation provenance](docs/git-history.md)
- [Product behavior](docs/product.md), [development plan](docs/development-plan.md), and [model selection](docs/model-selection.md)
- [Backend contract](docs/backend-contract.md), [Hub interface requests and completed items](docs/hub-interface-requests-v12.md), and [core team handoff](docs/cicada-core-handoff.md)
- [Current v1.6 successor management validation](docs/client-hub-v1.6-4fb241b-management-validation.md), [historical f4e4725 v1.6 acceptance](docs/client-hub-v1.6-f4e4725-validation.md), [historical v1.5 validation](docs/client-hub-v1.5-bd79ff9-validation.md), and [historical v1.4 acceptance](docs/client-hub-v1.4-f30892f-validation.md)
- [Historical v1.3 candidate validation](docs/client-monitor-v13-25013b5-native-validation.md), [historical native attempt](docs/client-monitor-v13-81d8f1f-native-validation.md), [historical recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md), and [historical Set H acceptance](docs/client-hub-v1.3-be0269e-validation.md)
- [Historical v1.2.1 validation](docs/client-hub-v1.2.1-967dbd-validation.md) and [historical v1.2 validation against `41beaf0`](docs/client-hub-v1.2-41beaf0-validation.md)
- [Disposable Group Endpoint key acceptance](docs/client-group-key-v1.2.1-disposable-validation.md)
- [Two-Owner encrypted authorization acceptance](docs/client-two-owner-v1.2.1-967dbd-validation.md) — own-Group controls, cross-Owner rejection, Hub signature rejection and device revocation using explicitly synthetic Endpoints

The historical fixed v1.2.1 image passed the emulator-based real Node/Codex approval and result flow; see the validation report for the exact APK and run evidence. Physical Android devices and public HTTPS have not been tested. Do not transfer those results to the current v1.6 target.
