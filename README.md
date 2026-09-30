# CICADA Client

CICADA Client is the mobile entry point for a CICADA environment. It lets an authorized user inspect Hub state, submit confirmed text or locally transcribed speech to Control, and perform supported management actions. Control and authoritative management state usually run on a Hub; native Threads and their Workers run on Nodes. The Client does not inject input directly into a native Worker session.

The shared application is written in TypeScript and React Native. **Android is the only implemented and validated mobile platform.** Android security and device integrations use Kotlin. iOS remains a future platform. A future native HarmonyOS application will need an ArkUI/ArkTS interface; this React Native UI is not a native HarmonyOS application. See the [stack decision](docs/stack-decision.md).

## Product capabilities

- **Status and work:** Read authenticated snapshots and partial changes for authorized Nodes, Endpoints, Workers, Goals, Groups, and Tasks. Submit user-confirmed text or reviewed speech transcripts to Control, inspect Intent dispatch, and read bounded Goal results when the session permits it. Intent, Goal, Worker, and Artifact states remain distinct.
- **Local speech:** Supported Vosk, Paraformer, and SenseVoice models are optional downloads. The model centre verifies, installs, selects, and removes supported models in the app's private storage. Users can always enter text without a model. Audio is not uploaded in the first phase. See [model selection](docs/model-selection.md) and [speech validation](docs/stt-validation.md).
- **Independent connections:** Each Hub profile keeps its own verified pin, device keys, enrollment, encrypted session, counters, pending requests and Monitor ledger. Hub and Network selection is explicit. Switching clears transient drafts and consent previews; late callbacks remain bound to their original selection.
- **Network consent:** The implementation supports ACTIVE Network selection, scoped Group creation and independent verification of Endpoint self-attestation and external Owner key consent. See the [current validation record](docs/client-hub-v1.5-bd79ff9-validation.md) for the tested scope and remaining integration requirements.
- **Hub management:** Authorized operations use the Hub's versioned guards and encrypted Client-Control RPC. Feature visibility requires both a locally implemented operation and permission in encrypted `session.capabilities`. The Hub remains authoritative for every write.
- **Monitor consent:** Review an exact message and ordered recipient roster before authorizing a same-owner Group broadcast. The Client verifies the Monitor's Endpoint and Owner proofs, checks current source authorization before sealing, and reports approval separately from delivery or model consumption. See the [historical v1.3 validation](docs/client-monitor-v13-25013b5-native-validation.md) for its tested scope; native delivery has not been rerun on v1.5.
- **Recovery:** The Client persists the exact enrollment Grant request and each signed encrypted RPC packet before sending. It can recover a lost response with the original packet through `/v2/client/rpc/recover`. An uncertain business outcome remains visible until reconciled with authoritative state.

## Security boundary

Client-to-Control business RPC uses the Client-Control v1 post-quantum protocol: ML-KEM-768, ML-DSA-65, HKDF, and AES-256-GCM. Users must verify and pin the full Hub identity through an independent trusted channel. Device enrollment requires an independently signed, one-time `OwnerDeviceGrant`. Android wraps its private keys with Android Keystore. Release builds require HTTPS; local debug HTTP is restricted to emulator-to-host development addresses.

The Client does not use legacy `/v1` management bearer APIs, store Hub or Node bearer credentials, or read the Hub database. This encrypted channel terminates at Control so Control can process the request. It does not prove that ordinary peer messages are unreadable to the Hub. Cross-user Thread messaging remains unavailable while the server advertises `external_thread_links=false`.

The Endpoint attestation v1 signature input includes the final `"signature":null` field. The Android verifier handles canonical Go RFC3339Nano timestamps. Historical v1.2.1 acceptance covers a real native Codex Endpoint, independent external Owner signing, explicit Android confirmation, and encrypted `group.key_manifest → group.key_grant → group.key_status` with `CURRENT`, then `STALE` after binding expiry and `PROOF_EXPIRED` after proof expiry. See the [Group key acceptance report](docs/client-group-key-v1.2.1-disposable-validation.md) for its exact APKs and rejection tests. Those results do not certify the current v1.5 target. Physical Android and public HTTPS remain untested.

## Fixed Hub integration target

The Client pins the clean v1.5 delivery below. Contract, image, independent Kotlin tests, Android product checks, and disposable Hub interoperability have separate results in the [current validation record](docs/client-hub-v1.5-bd79ff9-validation.md). Historical acceptance is not transferred to this target.

| Item | Fixed value |
|---|---|
| Hub source revision | `bd79ff93c90ecafc28a2471dd9523444903b39e6` |
| Protocol / wire | `client-hub-v1.5` / `1` |
| Protocol archive SHA-256 | `98ce7f02d03dd8291ff7361e46e22ed893f493d242fcb238a948bf869a2a5d0b` |
| Catalog SHA-256 | `a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68` |
| Full local Docker image ID | `sha256:4c321cd8f91a1e19befabd1f5c8983be46e6aed811614c68bd6f62ad06584771` |
| Clean Hub source fingerprint | `586ca8adbbcf9ea18c83f03e59267ad848c10792452520f5d499ef08ae340f17` |

The [imported snapshot](contracts/client-hub-v1.5-bd79ff9/manifest.json) is immutable and contains the 46-operation catalog. The Client permits only 33 locally implemented operations, subject to current encrypted authorization and the server Guard. Ten new shared-space consent/admission and topology delegation/proposal operations are explicitly disabled at both application and native boundaries until independent proof verification and explicit consent flows are implemented. The three Link key operations remain disabled. A Hub advertisement or an Agent proposal does not grant User Approval, access to history, or permission to send a message.

Current emulator acceptance passed 54 Kotlin tests, 29 JavaScript tests, exact authenticated external-role permissions in four fresh sessions, scoped Group creation, foreign-Owner denial, and original-byte recovery after lost enrollment/RPC responses. Three isolated outer-RPC faults passed: `STILL_PROCESSING`, signed `OUTCOME_UNCERTAIN` after a confirmed fault and single Hub restart, and `RECOVERY_UNAVAILABLE`. These fault fixtures do not establish real Worker execution or business-level exactly-once delivery. Connected management UI checks cover the recorded bounded view; the created Group card was not observed there.

Network consent still requires independently pinned Owner public keys, full Endpoint attestation, a fresh manifest, an external Owner signature, and explicit phone confirmation. Complete native Network consent and its dedicated uncertain-outcome reconciliation remain unvalidated. A generic snapshot cannot clear the durable Network grant fence. Cross-user messaging remains unavailable while `external_thread_links=false`. OpenAI Dot/Live integration is planning only.

The [shared-space v2 framework](docs/shared-space-v2-framework.md) adds a gated review panel and candidate-proof verification without enabling shared-space, delegation or proposal RPCs. Its public synthetic vector is from ongoing Core development and has separate validation attribution. Each Owner must eventually confirm its own signature through its own Client; a local scope-reading marker grants no authority.

Historical [v1.4 acceptance](docs/client-hub-v1.4-f30892f-validation.md), native Monitor results, and older APKs retain their original sources, images, and scope. No current dirty Core source is substituted for this delivery.

## Build and local development

Build and test in Docker. Verify the Docker data root before development; this environment expects `/gpu1-share/data/docker-root`. Keep build caches, model downloads, test identities, and temporary Hub state under `/gpu1-share/data/cicada-client`, outside Git. Do not change global Docker configuration or data belonging to the adjacent CICADA core project.

```bash
python3 scripts/check-client-contract.py
./scripts/docker-build.sh
./scripts/docker-build-android-test.sh
```

The contract checker defaults to the approved `bd79ff9` v1.5 snapshot. For a separately delivered candidate, first verify its archive SHA-256 against the trusted handoff, then supply the extracted snapshot and independent expected pins explicitly:

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
- [Current v1.5 implementation and validation](docs/client-hub-v1.5-bd79ff9-validation.md) and [historical v1.4 acceptance](docs/client-hub-v1.4-f30892f-validation.md)
- [Historical v1.3 candidate validation](docs/client-monitor-v13-25013b5-native-validation.md), [historical native attempt](docs/client-monitor-v13-81d8f1f-native-validation.md), [historical recall attempt](docs/client-monitor-v13-81d8f1f-recall-validation.md), and [historical Set H acceptance](docs/client-hub-v1.3-be0269e-validation.md)
- [Historical v1.2.1 validation](docs/client-hub-v1.2.1-967dbd-validation.md) and [historical v1.2 validation against `41beaf0`](docs/client-hub-v1.2-41beaf0-validation.md)
- [Disposable Group Endpoint key acceptance](docs/client-group-key-v1.2.1-disposable-validation.md)
- [Two-Owner encrypted authorization acceptance](docs/client-two-owner-v1.2.1-967dbd-validation.md) — own-Group controls, cross-Owner rejection, Hub signature rejection and device revocation using explicitly synthetic Endpoints

The historical fixed v1.2.1 image passed the emulator-based real Node/Codex approval and result flow; see the validation report for the exact APK and run evidence. Physical Android devices and public HTTPS have not been tested. Do not transfer those results to the current v1.5 target.
