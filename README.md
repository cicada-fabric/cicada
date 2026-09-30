# CICADA Client

CICADA Client is the mobile entry point for a CICADA environment. It lets an authorized user inspect Hub state, submit confirmed text or locally transcribed speech to Control, and perform supported management actions. Control and authoritative management state usually run on a Hub; native Threads and their Workers run on Nodes. The Client does not inject input directly into a native Worker session.

The shared application is written in TypeScript and React Native. **Android is the only implemented and validated mobile platform.** Android security and device integrations use Kotlin. iOS remains a future platform. A future native HarmonyOS application will need an ArkUI/ArkTS interface; this React Native UI is not a native HarmonyOS application. See the [stack decision](docs/stack-decision.md).

## Product capabilities

- **Status and work:** Read authenticated snapshots and partial changes for authorized Nodes, Endpoints, Workers, Goals, Groups, and Tasks. Submit user-confirmed text or reviewed speech transcripts to Control, inspect Intent dispatch, and read bounded Goal results when the session permits it. Intent, Goal, Worker, and Artifact states remain distinct.
- **Local speech:** Supported Vosk, Paraformer, and SenseVoice models are optional downloads. The model centre verifies, installs, selects, and removes supported models in the app's private storage. Users can always enter text without a model. Audio is not uploaded in the first phase. See [model selection](docs/model-selection.md) and [speech validation](docs/stt-validation.md).
- **Independent connections:** Each Hub profile keeps its own verified pin, device keys, enrollment, encrypted session, counters, pending requests and Monitor ledger. Hub and Network selection is explicit. Switching clears transient drafts and consent previews; late callbacks remain bound to their original selection.
- **Network consent:** The v1.4 implementation supports ACTIVE Network selection, scoped Group creation and independent verification of Endpoint self-attestation and external Owner key consent. See the [v1.4 validation record](docs/client-hub-v1.4-f30892f-validation.md) for the tested scope and remaining integration requirements.
- **Hub management:** Authorized operations use the Hub's versioned guards and encrypted Client-Control RPC. Feature visibility requires both a locally implemented operation and permission in encrypted `session.capabilities`. The Hub remains authoritative for every write.
- **Monitor consent:** Review an exact message and ordered recipient roster before authorizing a same-owner Group broadcast. The Client verifies the Monitor's Endpoint and Owner proofs, checks current source authorization before sealing, and reports approval separately from delivery or model consumption. See the [historical v1.3 validation](docs/client-monitor-v13-25013b5-native-validation.md) for its tested scope; native delivery has not been rerun on v1.4.
- **Recovery:** The Client persists the exact enrollment Grant request and each signed encrypted RPC packet before sending. It can recover a lost response with the original packet through `/v2/client/rpc/recover`. An uncertain business outcome remains visible until reconciled with authoritative state.

## Security boundary

Client-to-Control business RPC uses the Client-Control v1 post-quantum protocol: ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. Users must verify and pin the full Hub identity through an independent trusted channel. Device enrollment requires an independently signed, one-time `OwnerDeviceGrant`. Android wraps its private keys with Android Keystore. Release builds require HTTPS; local debug HTTP is restricted to emulator-to-host development addresses.

The Client does not use legacy `/v1` management bearer APIs, store Hub or Node bearer credentials, or read the Hub database. This encrypted channel terminates at Control so Control can process the request. It does not prove that ordinary peer messages are unreadable to the Hub. Cross-user Thread messaging remains unavailable while the server advertises `external_thread_links=false`.

The Endpoint attestation v1 signature input includes the final `"signature":null` field. The Android verifier handles canonical Go RFC3339Nano timestamps. Historical v1.2.1 acceptance covers a real native Codex Endpoint, independent external Owner signing, explicit Android confirmation, and encrypted `group.key_manifest → group.key_grant → group.key_status` with `CURRENT`, then `STALE` after binding expiry and `PROOF_EXPIRED` after proof expiry. See the [Group key acceptance report](docs/client-group-key-v1.2.1-disposable-validation.md) for its exact APKs and rejection tests. Those results do not certify the current v1.4 target. Physical Android and public HTTPS remain untested.

## Fixed Hub integration target

The current implementation pins the clean v1.4 delivery below. Independent contract and image checks, Kotlin vectors, profile isolation, and emulator UI validation are recorded separately in the [current validation record](docs/client-hub-v1.4-f30892f-validation.md). Historical acceptance is not transferred to this target.

| Item | Fixed value |
|---|---|
| Hub source revision | `f30892fcd79a27bfe5604575deaecebe52c5ec50` |
| Protocol | `client-hub-v1.4` |
| Protocol archive SHA-256 | `445017efe9085303942892c1bd1eaa2812c708f78389dbc59f906af8f535c324` |
| Catalog SHA-256 | `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54` |
| Full local Docker image ID | `sha256:56956f8a3d50b7e0445eef4017ba7cecff0ced570694cf8d8c3bb964e060aef7` |

The [imported snapshot](contracts/client-hub-v1.4-f30892f/manifest.json) is immutable. Network consent requires the exact public operation catalog, encrypted `session.capabilities`, independently pinned Owner public key, complete Endpoint attestation, fresh manifest, external Owner signature and explicit phone confirmation. The fixed Core revision does not provide a Network key signing CLI. A separate candidate tool can sign device Grants, but the complete pinned native Endpoint/Owner-consent fixture has not been delivered; positive real-Hub Network grant acceptance remains **BLOCKED**. No v1.5 candidate is treated as this frozen v1.4 delivery.

### Historical v1.3 acceptance

The bounded run on the fixed v1.3 candidate below passed ten fresh Android integration selectors and the real native Monitor scenario. Three independently verified Endpoint grants reached `CURRENT`; the original Monitor previewed and dispatched the confirmed message once, and both original recipient Threads passed exact-body and context assertions. Android then read two ordered `ACCEPTED` outcomes. This used an emulator, two logical Nodes in one container and controlled native safe points. Full React Native screen-flow revalidation, physical Android and public HTTPS remain **NOT_RUN**.

| Item | Fixed value |
|---|---|
| Hub source revision | `25013b51915124fa1da25e5fd37088eadf0e3d2d` |
| Protocol | `client-hub-v1.3` |
| Protocol archive SHA-256 | `5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Full local Docker image ID | `sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c` |

The imported snapshot is in [`contracts/client-hub-v1.3-25013b5`](contracts/client-hub-v1.3-25013b5/manifest.json). Archive contents, clean source, catalog, exact running image and encrypted capabilities were independently checked. The [historical validation report](docs/client-monitor-v13-25013b5-native-validation.md) records the pinned artifacts, commands, exit codes and evidence. The [core handoff](docs/cicada-core-handoff.md) distinguishes transport acceptance from native model consumption and lists remaining work, including reopening an already reconciled Monitor operation in the product UI.

Two historical `81d8f1f` runs retain separate results: the [first attempt](docs/client-monitor-v13-81d8f1f-native-validation.md) failed a recipient recall assertion; the [fresh recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md) was blocked by native approval review before dispatch. Their passing Android checks and failed native outcomes are not transferred to the current run.

The earlier [Set H protocol and UI acceptance](docs/client-hub-v1.3-be0269e-validation.md) used synthetic authorization Endpoints on Hub `be0269e`. A separate [Prepare recovery fault run](docs/client-monitor-v13-recovery-faults.md) passed all three outer RPC recovery states on that older image; its ledger-only fixture does not establish Monitor business execution. These results retain their original image and APK identities.

The older [joint native Monitor attempt](docs/client-monitor-v13-native-acceptance.md) on `be0269e` stopped when the original native Session lease could not be renewed. Android setup and full-manifest verification passed, but no Group grant, positive Prepare or Confirm was submitted. The later `81d8f1f` results do not rewrite that failure.

The [v1.2.1 validation report](docs/client-hub-v1.2.1-967dbd-validation.md), Group report and two-Owner report retain their original images and APKs. Their PASS results are not transferred to v1.3.

## Build and local development

Build and test in Docker. Verify the Docker data root before development; this environment expects `/gpu1-share/data/docker-root`. Keep build caches, model downloads, test identities, and temporary Hub state under `/gpu1-share/data/cicada-client`, outside Git. Do not change global Docker configuration or data belonging to the adjacent CICADA core project.

```bash
python3 scripts/check-client-contract.py
./scripts/docker-build.sh
./scripts/docker-build-android-test.sh
```

The contract checker defaults to the approved `f30892f` v1.4 snapshot. For a separately delivered candidate, first verify its archive SHA-256 against the trusted handoff, then supply the extracted snapshot and independent expected pins explicitly:

```bash
python3 scripts/check-client-contract.py \
  --snapshot-dir "$VERIFIED_SNAPSHOT" \
  --source-revision "$EXPECTED_HUB_COMMIT" \
  --catalog-sha256 "$EXPECTED_CATALOG_SHA256" \
  --contract-revision "$EXPECTED_CONTRACT_REVISION"
```

Do not obtain the expected pins from the candidate manifest itself. This offline check does not replace fixed-image provenance or encrypted runtime `session.capabilities` verification. Run its public-fixture regressions in the Docker development image with `python3 scripts/test_check_client_contract.py`.

`docker-build.sh` copies its APK to `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`. `docker-build-android-test.sh` writes the current debug and test APKs to `android/app/build/outputs/apk/debug/app-debug.apk` and `android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`. Hash the artifacts used in each test run; the exported copy is not refreshed by the test-build script. A successful host or emulator build does not establish physical-device, iOS, or public HTTPS validation.

## Project documentation

- [Git milestones and validation provenance](docs/git-history.md)
- [Product behavior](docs/product.md), [development plan](docs/development-plan.md), and [model selection](docs/model-selection.md)
- [Backend contract](docs/backend-contract.md), [Hub interface requests and completed items](docs/hub-interface-requests-v12.md), and [core team handoff](docs/cicada-core-handoff.md)
- [Current v1.4 implementation and validation](docs/client-hub-v1.4-f30892f-validation.md)
- [Historical v1.3 candidate validation](docs/client-monitor-v13-25013b5-native-validation.md), [historical native attempt](docs/client-monitor-v13-81d8f1f-native-validation.md), [historical recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md), and [historical Set H acceptance](docs/client-hub-v1.3-be0269e-validation.md)
- [Historical v1.2.1 validation](docs/client-hub-v1.2.1-967dbd-validation.md) and [historical v1.2 validation against `41beaf0`](docs/client-hub-v1.2-41beaf0-validation.md)
- [Disposable Group Endpoint key acceptance](docs/client-group-key-v1.2.1-disposable-validation.md)
- [Two-Owner encrypted authorization acceptance](docs/client-two-owner-v1.2.1-967dbd-validation.md) — own-Group controls, cross-Owner rejection, Hub signature rejection and device revocation using explicitly synthetic Endpoints

The historical fixed v1.2.1 image passed the emulator-based real Node/Codex approval and result flow; see the validation report for the exact APK and run evidence. Physical Android devices and public HTTPS have not been tested. Do not transfer those results to the current v1.4 target.
