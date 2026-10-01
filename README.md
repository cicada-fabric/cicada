# CICADA Client

**Provenance gate: BLOCKED.** The v1.6.1 public archive and pinned Git blobs match, but the independent raw-permission build fingerprint is not yet reproducible. No complete import, live Hub or native-runtime acceptance is claimed; see the [v1.6.1 validation record](docs/client-hub-v1.6.1-fe565b4-validation.md).


CICADA Client is the mobile entry point for a CICADA environment. It lets an authorized user inspect Hub state, submit confirmed text or locally transcribed speech to Control, and perform supported management actions. Control and authoritative management state usually run on a Hub; native Threads and their Workers run on Nodes. The Client does not inject input directly into a native Worker session.

The shared application is written in TypeScript and React Native. **Android is the only implemented and validated mobile platform.** Android security and device integrations use Kotlin. iOS remains a future platform. A future native HarmonyOS application will need an ArkUI/ArkTS interface; this React Native UI is not a native HarmonyOS application. See the [stack decision](docs/stack-decision.md).

## Product capabilities

- **Status and work:** Read authenticated snapshots and partial changes for authorized Nodes, Endpoints, Workers, Goals, Groups, and Tasks. Submit user-confirmed text or reviewed speech transcripts to Control, inspect Intent dispatch, and read bounded Goal results when the session permits it. Intent, Goal, Worker, and Artifact states remain distinct.
- **Local speech:** Supported Vosk, Paraformer, and SenseVoice models are optional downloads. The model centre verifies, installs, selects, and removes supported models in the app's private storage. Users can always enter text without a model. Audio is not uploaded in the first phase. See [model selection](docs/model-selection.md) and [speech validation](docs/stt-validation.md).
- **Independent connections:** Each Hub profile keeps its own verified pin, device keys, enrollment, encrypted session, counters, pending requests and Monitor ledger. Hub and Network selection is explicit. Switching clears transient drafts and consent previews; late callbacks remain bound to their original selection.
- **Network consent:** The existing direct Network flow supports ACTIVE Network selection, scoped Group creation and independent verification of Endpoint self-attestation and external Owner key consent. The v1.6 collaboration-key grants remain gated. See the [historical v1.6 successor validation](docs/client-hub-v1.6-4fb241b-management-validation.md) and the [historical v1.5 record](docs/client-hub-v1.5-bd79ff9-validation.md) for their separate scope.
- **Hub management:** Authorized operations use the Hub's versioned guards and encrypted Client-Control RPC. Feature visibility requires both a locally implemented operation and permission in encrypted `session.capabilities`. The current policy locally implements 38 of 55 operations, including bounded Directory/admission metadata reads and an explicitly confirmed one-use Monitor regroup delegation flow. Seventeen operations remain closed; the Hub remains authoritative for every write.
- **Monitor consent:** Review an exact message and ordered recipient roster before authorizing a same-owner Group broadcast. The Client verifies the Monitor's Endpoint and Owner proofs, checks current source authorization before sealing, and reports approval separately from delivery or model consumption. See the [historical v1.3 validation](docs/client-monitor-v13-25013b5-native-validation.md) for its tested scope; that result does not establish v1.6 native delivery.
- **Recovery:** The Client persists the exact enrollment Grant request and each signed encrypted RPC packet before sending. It recovers a lost response with the original packet through `/v2/client/rpc/recover`. A still-pending regroup operation may finish through a validated cached response; terminal authenticated `OUTCOME_UNCERTAIN` retains its original ciphertext and dedicated fence indefinitely under the current Core contract, with no later clearing route. See the [historical successor validation report](docs/client-hub-v1.6-4fb241b-management-validation.md).

## Security boundary

Client-to-Control business RPC uses the Client-Control v1 post-quantum protocol: ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. Users must verify and pin the full Hub identity through an independent trusted channel. Device enrollment requires an independently signed, one-time `OwnerDeviceGrant`. Android wraps its private keys with Android Keystore. Release builds require HTTPS; local debug HTTP is restricted to emulator-to-host development addresses.

The Client does not use legacy `/v1` management bearer APIs, store Hub or Node bearer credentials, or read the Hub database. This encrypted channel terminates at Control so Control can process the request. It does not prove that ordinary peer messages are unreadable to the Hub. Cross-user Thread messaging remains unavailable while the server advertises `external_thread_links=false`.

The Endpoint attestation v1 signature input includes the final `"signature":null` field. The Android verifier handles canonical Go RFC3339Nano timestamps. Historical v1.2.1 acceptance covers a real native Codex Endpoint, independent external Owner signing, explicit Android confirmation, and encrypted `group.key_manifest → group.key_grant → group.key_status` with `CURRENT`, then `STALE` after binding expiry and `PROOF_EXPIRED` after proof expiry. See the [Group key acceptance report](docs/client-group-key-v1.2.1-disposable-validation.md) for its exact APKs and rejection tests. Those results do not certify the current v1.6 target. Physical Android and public HTTPS remain untested.

## Current Hub integration target: v1.6.1

The deterministic integration target is clean Core `fe565b41bb1aa86d400a0ec98c528c856d0b9579`, Client-Control v1.6.1, wire 1. The verified public snapshot and exact artifact-level results are recorded in the [v1.6.1 validation report](docs/client-hub-v1.6.1-fe565b4-validation.md). Its 55-operation catalog preserves the local 38-operation policy and 17 closed operations.

| Item | Fixed value |
|---|---|
| Hub source revision | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` |
| Protocol / wire | `client-hub-v1.6.1` / `1` |
| Protocol archive SHA-256 | `b5757b055bc871ef5f19fcc5ffe425813c6dea2ccc8cc64b4e74e1f1dcd8db55` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Declared Core source fingerprint | `6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be` |
| Local Hub Docker image ID | `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589` |
| Local interop image ID | `sha256:a6a88de73b1c8c00b38fafb4e9236c404b52b06165527a0b4e097c0f17f3a6be` |

The final offline checkpoint passed the Docker build, 59 JavaScript tests, TypeScript, ESLint, 74 Kotlin tests and five UI checks. The owned emulator was cleaned; six resident containers were unchanged.

Node confirmation now validates the complete `NodeControlKeyBinding` public keys and exact approval scope, then correlates the separate `NodeDeviceBinding` list projection. These checks preserve independent pin review and explicit user confirmation. Core image tests are a separate layer from Android acceptance. Current live Hub, native runtime, physical Android and public HTTPS results remain unaccepted; older APK or Hub-version results do not transfer. The [4fb241b management report](docs/client-hub-v1.6-4fb241b-management-validation.md) remains historical evidence.

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

The contract checker defaults to the imported `fe565b4` v1.6.1 snapshot. Verify its archive SHA-256 against the external receipt before relying on the result. The checker is an offline contract check; it does not replace fixed-image provenance or encrypted runtime `session.capabilities` verification.

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
- [Current v1.6.1 validation](docs/client-hub-v1.6.1-fe565b4-validation.md), [historical v1.6 successor management validation](docs/client-hub-v1.6-4fb241b-management-validation.md), [historical f4e4725 v1.6 acceptance](docs/client-hub-v1.6-f4e4725-validation.md), [historical v1.5 validation](docs/client-hub-v1.5-bd79ff9-validation.md), and [historical v1.4 acceptance](docs/client-hub-v1.4-f30892f-validation.md)
- [Historical v1.3 candidate validation](docs/client-monitor-v13-25013b5-native-validation.md), [historical native attempt](docs/client-monitor-v13-81d8f1f-native-validation.md), [historical recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md), and [historical Set H acceptance](docs/client-hub-v1.3-be0269e-validation.md)
- [Historical v1.2.1 validation](docs/client-hub-v1.2.1-967dbd-validation.md) and [historical v1.2 validation against `41beaf0`](docs/client-hub-v1.2-41beaf0-validation.md)
- [Disposable Group Endpoint key acceptance](docs/client-group-key-v1.2.1-disposable-validation.md)
- [Two-Owner encrypted authorization acceptance](docs/client-two-owner-v1.2.1-967dbd-validation.md) — own-Group controls, cross-Owner rejection, Hub signature rejection and device revocation using explicitly synthetic Endpoints

The historical fixed v1.2.1 image passed the emulator-based real Node/Codex approval and result flow; see the validation report for the exact APK and run evidence. Physical Android devices and public HTTPS have not been tested. Do not transfer those results to the current v1.6 target.
