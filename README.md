# CICADA Client

CICADA Client is the mobile entry point for a CICADA environment. It lets an authorized user inspect Hub state, submit confirmed text or locally transcribed speech to Control, and perform supported management actions. Control and authoritative management state usually run on a Hub; native Threads and their Workers run on Nodes. The Client does not inject input directly into a native Worker session.

The shared application is written in TypeScript and React Native. **Android is the only implemented and validated mobile platform.** Android security and device integrations use Kotlin. iOS remains a future platform. A future native HarmonyOS application will need an ArkUI/ArkTS interface; this React Native UI is not a native HarmonyOS application. See the [stack decision](docs/stack-decision.md).

## Product capabilities

- **Status and work:** Read authenticated snapshots and partial changes for authorized Nodes, Endpoints, Workers, Goals, Groups, and Tasks. Submit user-confirmed text or reviewed speech transcripts to Control, inspect Intent dispatch, and read bounded Goal results when the session permits it. Intent, Goal, Worker, and Artifact states remain distinct.
- **Local speech:** Supported Vosk, Paraformer, and SenseVoice models are optional downloads. The model centre verifies, installs, selects, and removes supported models in the app's private storage. Users can always enter text without a model. Audio is not uploaded in the first phase. See [model selection](docs/model-selection.md) and [speech validation](docs/stt-validation.md).
- **Independent connections:** Each Hub profile keeps its own verified pin, device keys, enrollment, encrypted session, counters, pending requests and Monitor ledger. Hub and Network selection is explicit. Switching clears transient drafts and consent previews; late callbacks remain bound to their original selection.
- **Network consent:** The existing direct Network flow supports ACTIVE Network selection, scoped Group creation and independent verification of Endpoint self-attestation and external Owner key consent. The v1.6.4 Link consent candidate is a separate Native flow; its live acceptance is still pending below. See the [historical v1.6 successor validation](docs/client-hub-v1.6-4fb241b-management-validation.md) and the [historical v1.5 record](docs/client-hub-v1.5-bd79ff9-validation.md) for their separate scope.
- **Hub management:** Authorized operations use the Hub's versioned guards and encrypted Client-Control RPC. Feature visibility requires both a locally implemented operation and permission in encrypted `session.capabilities`. The v1.6.4 local candidate implements 44 of 55 operations, including bounded Directory/admission reads, explicit one-use Monitor regroup delegation, Link review-policy status metadata, and five dedicated Link consent operations. Eleven operations remain closed. The five Link consent operations are always rejected by generic `rpc` and use the dedicated Native flow only. The Hub remains authoritative for every write. The bounded native-fixture Link status run has its own [validation record](docs/client-link-status-native-fixture-144e079-validation.md); status metadata alone does not establish bilateral consent or enable messages.
- **Monitor consent:** Review an exact message and ordered recipient roster before authorizing a same-owner Group broadcast. The Client verifies the Monitor's Endpoint and Owner proofs, checks current source authorization before sealing, and reports approval separately from delivery or model consumption. See the [historical v1.3 validation](docs/client-monitor-v13-25013b5-native-validation.md) for its tested scope; that result does not establish v1.6 native delivery.
- **Recovery:** The Client persists the exact enrollment Grant request and each signed encrypted RPC packet before sending. It recovers a lost response with the original packet through `/v2/client/rpc/recover`. The current snapshot recovery test retains the retired packet after authenticated `OUTCOME_UNCERTAIN`, blocks writes until a fresh authoritative snapshot, and verifies session reconciliation. An uncertain regroup delegation has a separate durable fence: a generic snapshot cannot establish its outcome or clear that fence under the current Core contract. See the [current recovery validation](docs/client-hub-v1.6.1-144e079-validation.md) and [historical regroup validation](docs/client-hub-v1.6-4fb241b-management-validation.md).

## Security boundary

Client-to-Control business RPC uses the Client-Control v1 post-quantum protocol: ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. Users must verify and pin the full Hub identity through an independent trusted channel. Device enrollment requires an independently signed, one-time `OwnerDeviceGrant`. Android wraps its private keys with Android Keystore. Release builds require HTTPS; local debug HTTP is restricted to emulator-to-host development addresses.

The Client does not use legacy `/v1` management bearer APIs, store Hub or Node bearer credentials, or read the Hub database. This encrypted channel terminates at Control so Control can process the request. It does not prove that ordinary peer messages are unreadable to the Hub. Cross-user Thread messaging remains unavailable while the server advertises `external_thread_links=false`.

The Endpoint attestation v1 signature input includes the final `"signature":null` field. The Android verifier handles canonical Go RFC3339Nano timestamps. Historical v1.2.1 acceptance covers a real native Codex Endpoint, independent external Owner signing, explicit Android confirmation, and encrypted `group.key_manifest → group.key_grant → group.key_status` with `CURRENT`, then `STALE` after binding expiry and `PROOF_EXPIRED` after proof expiry. See the [Group key acceptance report](docs/client-group-key-v1.2.1-disposable-validation.md) for its exact APKs and rejection tests. Those results do not certify the current v1.6 target. Physical Android and public HTTPS remain untested.

## Accepted Android baseline: v1.6.1

The deterministic integration target is clean Core `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c`, Client-Control v1.6.1, wire 1. The independently verified public snapshot, fixed images, APKs and acceptance results are recorded in the [current v1.6.1 validation report](docs/client-hub-v1.6.1-144e079-validation.md). Its 55-operation catalog is unchanged. The current local policy implements 39 operations and keeps 16 closed; the new status-only implementation is recorded separately from the prior 38-operation APKs.

| Item | Fixed value |
|---|---|
| Hub source revision | `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c` |
| Protocol / wire | `client-hub-v1.6.1` / `1` |
| Protocol archive SHA-256 | `0835e10f229900e120b458211469e80d9bb0804bd40cb8d464ef1a196bd11dee` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Independently verified Core source fingerprint | `e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902` |
| Local Hub Docker image ID | `sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb` |
| Local interop image ID | `sha256:4ddf7bdc25c7da2fd59024a1a85006f7370e40e14f9546d65fcbea9f2ac957d3` |

The prior `d580975` offline checkpoint passed the Docker build, 59 JavaScript tests, TypeScript, ESLint, 74 Kotlin tests and five UI checks. The owned emulator was cleaned; six resident containers were unchanged.

Node confirmation now validates the complete `NodeControlKeyBinding` public keys and exact approval scope, then correlates the separate `NodeDeviceBinding` list projection. These checks preserve independent pin review and explicit user confirmation. Core image tests are a separate layer from Android acceptance. The current fixed-image Android gate has passed 81 Kotlin tests, UI smoke checks, encrypted enrollment, Directory authorization and exact recovery of lost enrollment and completed RPC responses. It also verified `STILL_PROCESSING` through an authorized synthetic ledger injection, encrypted `OUTCOME_UNCERTAIN` after restart, and `RECOVERY_UNAVAILABLE` at the Android protocol layer with separately corrected cleanup evidence. Original driver failures remain recorded. Native runtime, physical Android and public HTTPS remain unaccepted; older APK or Hub-version results do not transfer. The [4fb241b management report](docs/client-hub-v1.6-4fb241b-management-validation.md) remains historical evidence.

## Current integration candidate: v1.6.4

The candidate targets clean Core `0213538b62ccf2533eccf546c80fc848804ea8e0`.
Its archive, catalog and fixed image IDs are recorded in the
[F19 target record](docs/client-hub-v1.6.4-0213538-f19-validation.md). The
[F24–F28 report](docs/client-hub-v1.6.4-0213538-f28-validation.md) retains all
five bounded-run outcomes. The [F30 report](docs/client-hub-v1.6.4-0213538-f30-validation.md)
records the next clean Client checkpoint and actual Root-authorized run; F29's
plan failure is retained in the [Core handoff](docs/cicada-core-handoff.md).

F30 passed SOURCE KEY submit with partial fresh status and SOURCE `NONE` with
partial policy status. TARGET enrollment, capabilities, and independent pins
passed; a Target signing request and proof handoff were created. JUnit then
failed at `kt386` when the confirmation-control label could not be resolved
uniquely. The flow exited `1`; the positive confirmation Alert, Target KEY Hub
acceptance, Target `NONE`, and bilateral KEY/`NONE` were NOT_RUN. Its terminal
is `OUTCOME_UNKNOWN_PRESERVE_PENDING`; do not retry the original operation.
F28 and F29 remain their recorded failures and are not reclassified by F30.

The [F33 validation report](docs/client-hub-v1.6.4-0213538-f33-validation.md)
records the later Android run from Client `906c7b0d0434b569336060a33697ff96e9ec7948`,
using app/test SHA-256 `397029c61950133ba986e7cb0f108d73f7c727c27dcf619df323c9f1e1545cc3` /
`7a8a54806874791ff4a313995fd4a0a29a4682a5f5777b1dddc72d916ed689eb`.
Encrypted SOURCE and TARGET enrollment, capabilities and independent pins
passed. SOURCE KEY and `NONE` returned only partial statuses. TARGET preparation
reached `REVIEW_READY`, but JUnit failed with `CONTROL_MISSING` before the
confirmation button or native Alert was activated. Its terminal remains
`OUTCOME_UNKNOWN_PRESERVE_PENDING`; no retry was made. F31 and F32 did not run
the business flow and do not change this result.

The [F34 report](docs/client-hub-v1.6.4-0213538-f34-validation.md) records the
subsequent run from Client `8f2900c`. Its bounded proof editor and app-window
control lookup reached `CONFIRM_READY`; the full native Alert checks and
positive-button action returned. JUnit then failed waiting for the response
text. Callback entry, encrypted request outcome and Target KEY acceptance
remain **UNKNOWN**; the original operation must be preserved. SOURCE results
were partial, and Target `NONE` and bilateral consent were **NOT_RUN**.

The [F35 report](docs/client-hub-v1.6.4-0213538-f35-validation.md) records the
next run from Client `a80d1a9`. Its passive debug observer confirmed callback
entry, scope guard success, a resolved native response with `ok=true`, and
return to the UI. The response text was not visible and JUnit failed. This
does not establish a current Target grant or bilateral acceptance; the
original operation remains preserved with an unknown outcome.

The successor gives the response note a stable view ID and searches both page
directions within the original 20-second deadline. It requires actual visible
text and retains the complete Alert and bilateral checks. Pure Kotlin page
search regressions and affected static checks are recorded with the subsequent
build and delivery receipts at
`/gpu1-share/data/cicada-client/v164-f35-response-viewport-20261004`, binding
the exact clean commit and APK pair. Fresh live acceptance remains **NOT_RUN**.
Physical Android, public HTTPS, native Worker acceptance, Link recovery faults
and bilateral consent remain **NOT_RUN**. Ordinary cross-user messages remain
closed while `external_thread_links=false`.

## Imported clean v1.6.3 delivery

The clean Core `e8a029d79bbdddb75ea376afa76e62a5c8444f59` contract and immutable image identities have been independently verified and imported. The catalog remains at 55 operations. This is a separate [provenance and offline validation record](docs/client-hub-v1.6.3-e8a029d-validation.md). That earlier provenance-only milestone retained its then-current v1.6.1 runtime pins. The active candidate now targets v1.6.4; no v1.6.3 APK or runtime result transfers to it. Fresh encrypted `link.key_manifest` is the Hub's authoritative current scope; Owner keys still require independent trust. Core has confirmed a reviewer permission/binding guard defect in this fixed release, so policy authorization awaits a separately verified correction.

## Prepared Group directory permission extension

The branch prepares an explicit Owner review and enable/revoke flow for one Principal's Group `directory.read` permission through existing topology RPCs. The scope covers all that Principal's joined Endpoints in the named Group and grants discovery only. The production entry remains closed pending native integration and Android acceptance against the new clean delivery. Candidate implementation and offline results are recorded separately in [Group directory permission preparation](docs/group-directory-permission-candidate-validation.md); they do not replace the accepted v1.6.1 APK or runtime evidence.

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

The contract checker defaults to the imported `144e079` v1.6.1 snapshot. Verify its archive SHA-256 against the external receipt before relying on the result. The checker is an offline contract check; it does not replace fixed-image provenance or encrypted runtime `session.capabilities` verification.

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
- [Current v1.6.4 F24–F28 validation](docs/client-hub-v1.6.4-0213538-f28-validation.md), [historical F20–F23 validation](docs/client-hub-v1.6.4-0213538-f23-validation.md), [current v1.6.1 validation](docs/client-hub-v1.6.1-144e079-validation.md), [historical fe565b4 checkpoint](docs/client-hub-v1.6.1-fe565b4-validation.md), [historical v1.6 successor management validation](docs/client-hub-v1.6-4fb241b-management-validation.md), [historical f4e4725 v1.6 acceptance](docs/client-hub-v1.6-f4e4725-validation.md), [historical v1.5 validation](docs/client-hub-v1.5-bd79ff9-validation.md), and [historical v1.4 acceptance](docs/client-hub-v1.4-f30892f-validation.md)
- [Historical v1.3 candidate validation](docs/client-monitor-v13-25013b5-native-validation.md), [historical native attempt](docs/client-monitor-v13-81d8f1f-native-validation.md), [historical recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md), and [historical Set H acceptance](docs/client-hub-v1.3-be0269e-validation.md)
- [Historical v1.2.1 validation](docs/client-hub-v1.2.1-967dbd-validation.md) and [historical v1.2 validation against `41beaf0`](docs/client-hub-v1.2-41beaf0-validation.md)
- [Disposable Group Endpoint key acceptance](docs/client-group-key-v1.2.1-disposable-validation.md)
- [Two-Owner encrypted authorization acceptance](docs/client-two-owner-v1.2.1-967dbd-validation.md) — own-Group controls, cross-Owner rejection, Hub signature rejection and device revocation using explicitly synthetic Endpoints

The historical fixed v1.2.1 image passed the emulator-based real Node/Codex approval and result flow; see the validation report for the exact APK and run evidence. Physical Android devices and public HTTPS have not been tested. Do not transfer those results to the current v1.6 target.
