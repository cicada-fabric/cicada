# Client-Control v1.6.4 validation — Core `dd81575`

**Date:** 2026-10-02; F9 closure updated 2026-10-03
**Result:** **BUILT_AND_CONTRACT_VERIFIED** (limited to the independently reviewed delivery and frozen contract bundle).  
**Offline Android result:** **PASS_OFFLINE_ONLY_NOT_F6_HUB_ACCEPTANCE** for the frozen APK's 49-test emulator matrix and local UI smoke; the outer coordinator still exited `1` on its post-stop absence race, as recorded below.  
**F6 live result:** **BLOCKED_DEADLINE_BEFORE_ANDROID_BUSINESS**. The actual fixture, immutable Docker identity and fresh emulator bootstrap passed. No Android business selector, encrypted capabilities request or Owner signature ran before the fixed deadline.  
**F8 live result:** **BLOCKED_DEADLINE_BEFORE_ANDROID_BUSINESS**. The fresh public fixture, actual Docker identity, bootstrap binding and carrier startup passed; the first business subprocess never ran. Driver failures are retained below.
**F9 live result:** **FAIL_RUNTIME_RECEIPT_COMPATIBILITY** at the first staging command. Bootstrap, exact binding and carrier startup passed. Device enrollment, encrypted capabilities, Owner signing and Link business operations remain **NOT_RUN**. The fixed execution stop was enforced without retry or extension.
**Scope:** contract and source provenance, independent offline Android evidence, actual Main F6–F9 fixture/Docker verification, emulator bootstrap/cleanup, and the original F9 staging failure. These limited passes do not establish bilateral Link acceptance, physical-device acceptance, or production readiness.

## Fixed artifact identity

| Item | Independently recorded value |
|---|---|
| Core revision | `dd81575b160aa901b642137e54d7a60961e4bd68` |
| Core Git tree | `68e5875456455e11141d86699cc988e1521c911a` |
| Contract | `client-hub-v1.6.4`, wire version `1`, 55 operations |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Contract archive SHA-256 | `5a4e52b8e6df15e10870c568cdd745ac8246bf856ff45d39efac398b4a418ef1` |
| Contract archive size | 439,217 bytes |
| Contract manifest SHA-256 | `87fe7c003ea68d9a15a0d79bbc5361d0aa6f5fcc3118938edd624ecfc87628cd` |
| Core standard-input source fingerprint | `b874b7fbf3453e0a5faa3ba36c1eb89337d0c4920353ed225b314666e1c04556` over 891 standard inputs; **not** an image or package digest |
| Hub image ID | `sha256:ab189ee06372e4eaa248eac6e3699f7b4e2d9105505e87027f0081d118adc561` |
| Interop test image ID | `sha256:c926d0f3809572e541414cbb239efdc00ba82d07e16950318199df4c6d5e2679` |
| Reported Hub/Interop binary SHA-256 | `22a4ae014553c27ebc03569d426deeef0c569727f6f9fecf8db35ab7645dad80` (delivery receipt value; binary bytes were not separately re-extracted by the independent provenance audit) |
| Reported Hub image archive SHA-256 | `4ce96b1886bcf1e83a5f5e212763238c5baa0a411a1675f7c13fbcce15aac193` (delivery-receipt value; archive was not retained) |
| Client source checkpoint referenced by the frozen Android candidate | `508ca333c8ae90d27a8191ac828a7be16b71c7b3` |
| Client acceptance harness checkpoint | `6d01e4a82818c0bae9013d4c42ead2b99a9be9c0` |
| Frozen candidate app APK SHA-256 | `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` |
| Frozen candidate test APK SHA-256 | `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6` |

The app and test APK values are artifact-selection pins; their separate offline emulator run is documented below and does not constitute live F6 acceptance. The APK source checkpoint and harness are kept distinct from the Core source revision.

## Contract archive verification

The public archive is at `/home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/contracts/client-hub-5a4e52b8e6df15e10870c568cdd745ac8246bf856ff45d39efac398b4a418ef1.tar.gz`. Its manifest identifies the exact Core revision above, `source_dirty: false`, wire version 1, and the pinned catalog digest. The archive contains 25 regular-file members: one manifest and 24 payloads totaling 909,567 bytes. Every payload length and SHA-256 matches the manifest, paths are unique and relative, and all 24 payloads are byte-identical to the frozen Client bundle at `contracts/client-hub-v1.6.4-25bc586/`. The prior frozen manifest has identical payload records; its only differing top-level value is `source_revision`.

The protocol-critical comparison passed with no differences: the catalog, wire document, OpenAPI document, Client-Control vector, endpoint-attestation vector, Link proof vector, Link review-policy evidence vector, and Owner review-policy proof vector all match their pinned Client copies byte-for-byte. In particular, the public Link proof vector SHA-256 is `aa191b75c01dfe26ca916c12566dcd22bd26c6072a89640f63f4446ed2c4f41d`, and the Link review-policy evidence vector SHA-256 is `aeb0985056e305a2ea06616e39bebd2bd58957efe61d5e2be9511f6a52039bcd`.

The package verification receipt is `/gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/verification.redacted.json`, SHA-256 `a2e2e209364b867f3170da07f798e63a5ed51d700fe2c06314c77b24506c63a4`, result `PASS_WITH_DOCUMENTATION_CAVEAT`. Its extracted manifest is `/gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/manifest.json`, SHA-256 `87fe7c003ea68d9a15a0d79bbc5361d0aa6f5fcc3118938edd624ecfc87628cd`. The extraction used private directories mode `0700`, files mode `0600`, and contained no symlinks or special files. The reproducible read-only checker is `/gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/verify-archive.py`, mode `0600`, SHA-256 `0f9477e11dafa32d7661531cc0d5f93748262ad55b2e19a95235155cb23c416e`.

The archive's `docs/client-hub-development.md` has a stale candidate paragraph that still cites the older `c146d58` dirty tree and `4380e9…` fingerprint. Do not use that paragraph as dd81575 provenance. The manifest and independently checked Git inventory supply the revision and clean-state evidence. The archive also labels inner RPC shape coverage as `partial_prose_references`; archive integrity and protocol-vector equality do not convert that coverage caveat into runtime verification.

## Core provenance and schema

The independent provenance audit is `/gpu1-share/data/cicada-client/v164-dd81575-20261002/provenance-private/independent-provenance-audit.redacted.json`, SHA-256 `276f6eec0b6f0e3fe3aa99ffbb30750d50290d47ec36cd9fabff480b948acc4b`, result `PASS`. It independently reproduced the v4 source fingerprint from the 891 standard Hub build inputs, verifying the pinned Git blobs, Git modes, raw filesystem modes, and clean repository status. The producer's `full_source_count: 1069` is not independently verified by that inventory; this record makes no 1069-input claim.

The catalog was read from the pinned Git blob and confirms contract revision v1.6.4, wire version 1, and 55 operations. The store schema version is **57**, independently established from the pinned public Go source rather than delivery metadata: `cicada-go/internal/store/migrations_v2.go:24` declares `CurrentV2SchemaVersion = 57`. The declaration's source-file SHA-256 is `dbc767f805c6501b566a8c762060fbfb656938d5b08c3c737f80715bc8d71f2f`. The contract manifest has no schema-version field, and the build JSON schema name `cicada.hub-build.v1` is not the store schema version.

Read-only image inspection confirmed the Hub image ID and its revision, clean label, source fingerprint, catalog digest, and `hub` role. The interop image had the same revision/fingerprint/catalog and a clean label, but its role label was absent (`<no value>`). Those label checks do not constitute the interop image gate or execution of its test command; that gate remains **NOT_RUN**.

## Commands and exits

The archive and provenance receipts above retain the detailed checks. The commands below record the relevant actual argv and exit results.

| Check | Actual command / result |
|---|---|
| Archive bytes | `sha256sum /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/contracts/client-hub-5a4e52b8e6df15e10870c568cdd745ac8246bf856ff45d39efac398b4a418ef1.tar.gz` — exit `0`; SHA matched the pinned archive digest. |
| Archive members, manifest, payload digests, frozen payload equality | `python3 /gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/verify-archive.py /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/contracts/client-hub-5a4e52b8e6df15e10870c568cdd745ac8246bf856ff45d39efac398b4a418ef1.tar.gz /home/zyf/CICADA_CLIENT/contracts/client-hub-v1.6.4-25bc586` — exit `0`; output reported 25 members, 24 payloads, 909,567 payload bytes, all payloads byte-identical. |
| Archive/audit receipt file hashes | `sha256sum /gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/manifest.json /gpu1-share/data/cicada-client/v164-dd81575-20261002/package-private/verification.redacted.json /gpu1-share/data/cicada-client/v164-dd81575-20261002/provenance-private/independent-provenance-audit.redacted.json` — exit `0`; output hashes are recorded above. |
| Build-input inventory (`build.json`) | `python3 /home/zyf/CICADA_CLIENT/scripts/verify-hub-input-inventory.py --metadata /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/build.json --repository /home/zyf/CICADA --expected-revision dd81575b160aa901b642137e54d7a60961e4bd68 --expected-catalog-sha256 953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d --expected-source-fingerprint b874b7fbf3453e0a5faa3ba36c1eb89337d0c4920353ed225b314666e1c04556 --expected-helper-sha256 b9725970b70f073aaf35c3960842654973cb3d17deb9448eaee03bb30674e85a --verify-worktree` — exit `0`; stdout SHA-256 `5e6b0473eba8aa3d700c310e88b2335b7e212611007cc3d1339c5b67ee63d6c0`. |
| Source-info inventory (`source-info.json`) | Same verifier and pins, with `--metadata /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/source-info.json` — exit `0`; stdout SHA-256 `d8b256322b867f6eda09b1836bcf362f2796d14e243688c467e42e6fc96bdbe2`. |
| Hub image labels | `docker image inspect sha256:ab189ee06372e4eaa248eac6e3699f7b4e2d9105505e87027f0081d118adc561 --format '{{.Id}}|{{index .Config.Labels "org.opencontainers.image.revision"}}|{{index .Config.Labels "org.cicada.build.dirty"}}|{{index .Config.Labels "org.cicada.build.source-fingerprint"}}|{{index .Config.Labels "org.cicada.client-catalog.sha256"}}|{{index .Config.Labels "org.cicada.role"}}'` — exit `0`; stdout SHA-256 `cbf4fbf6740f4489cc2ecdce142b1f18745febe381657f7d83235c6d0844d7b0`. |
| Interop image labels | Same `docker image inspect` format with image `sha256:c926d0f3809572e541414cbb239efdc00ba82d07e16950318199df4c6d5e2679` — exit `0`; stdout SHA-256 `35fa0acac6cd33b0ccf25613cc1f28039701f0d4ab13b3138a1778bccdcb09c6`. |
| Pinned catalog | `git -C /home/zyf/CICADA show dd81575b160aa901b642137e54d7a60961e4bd68:cicada-go/internal/clientcontract/catalog.json` — exit `0`; stdout SHA-256 equals the catalog pin. |
| Store schema declaration | `git -C /home/zyf/CICADA grep -n -E 'CurrentV2SchemaVersion[[:space:]]*=[[:space:]]*57' dd81575b160aa901b642137e54d7a60961e4bd68 -- cicada-go/internal/store/migrations_v2.go` — exit `0`; matched line 24. |
| Pinned schema source bytes | `git -C /home/zyf/CICADA show dd81575b160aa901b642137e54d7a60961e4bd68:cicada-go/internal/store/migrations_v2.go | sha256sum` — exit `0`; SHA-256 `dbc767f805c6501b566a8c762060fbfb656938d5b08c3c737f80715bc8d71f2f`. |
| Core checkout HEAD | `git -C /home/zyf/CICADA rev-parse HEAD` — exit `0`; checked out revision was `dd81575b160aa901b642137e54d7a60961e4bd68`. |

The corrected delivery receipt records the build command `bash /home/zyf/CICADA/scripts/build-hub-image.sh --image cicada-clean-dd81575-20261002:hub --interop-test-image cicada-clean-dd81575-20261002:interop --metadata-file /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/build.json --transport standard` with exit `0`. This is a delivery-recorded build result, not a new build run for this validation. The independent acceptance receipt records export and contract verification exit codes `[0, 0, 0]`.

One superseded inventory-audit attempt exited `1` because its expected helper SHA contained a typo (`…3fb3d17…` instead of the pinned `…3cb3d17…`). Its actual argv was:

```bash
python3 /home/zyf/CICADA_CLIENT/scripts/verify-hub-input-inventory.py \
  --metadata /home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/build.json \
  --repository /home/zyf/CICADA \
  --expected-revision dd81575b160aa901b642137e54d7a60961e4bd68 \
  --expected-catalog-sha256 953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d \
  --expected-source-fingerprint b874b7fbf3453e0a5faa3ba36c1eb89337d0c4920353ed225b314666e1c04556 \
  --expected-helper-sha256 b9725970b70f073aaf35c3960842654973fb3d17deb9448eaee03bb30674e85a \
  --verify-worktree
```

It produced no stdout (empty SHA-256) and stderr SHA-256 `83916bde0383d9acedf914bfcd9cb02c810458f34af37f7bc3b0ea3d87624e49`. The corrected runs above used the verified helper SHA and both passed. This auditor-input failure is retained and is separate from the original producer failure below.

## Producer failure and corrected review status

The original producer record remains unchanged and **FAIL**: `/home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/std-producer.json`, outer exit `1`, SHA-256 `3de3948442b6bb9686858f6deaab34efa2cb209064fbdf0498e4cc782230c912`. A separate mount-order interpretation correction is `/home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/resident-order-correction.json`, SHA-256 `165c822f4905387c938cc04ce2f20e8f65168132a8f4f0e8c7851de916e4dc36`; it does not rewrite or erase the producer record.

The normalized delivery receipt `/home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/delivery-receipt.json` (SHA-256 `eb57b2743447c71e6a5a2a8d203cfe4bc17a00ee190ba166c0f9fa4747dcdc25`) is a separate corrected summary with status `READY_FOR_INDEPENDENT_REVIEW`. The independent acceptance receipt `/home/zyf/CICADA/.cicada-data/v164-clean-dd81575-20261002/independent-review-acceptance.json` (SHA-256 `e0a193e07c2ec4e64225c44f3ccc4b98eea020aa033af144b1ca7473e7fbd46b`) records **BUILT_AND_CONTRACT_VERIFIED** within the limited scope stated here. Neither receipt changes the original producer exit `1`; neither claims runtime acceptance.

## Offline Android matrix and local UI smoke

This separate lane is explicitly classified `OFFLINE_ONLY_NOT_F6_HUB_ACCEPTANCE`. It used the same frozen APK pair already listed above, not a rebuilt or relabeled APK. The emulator container used Docker `--network none`; it did not run a Hub, connect to a Hub, or perform owner enrollment, key pinning, signing, proof exchange, or model work.

| Evidence | Result / pin |
|---|---|
| Android app APK | `56684d33a9b111a7719416970915a22986ffd50b1620d5f109fbaeb01fb2bc67` |
| Android test APK | `caa8a1705e56359c0a2742ec0f18ea9437c9c136857603cfd47fd2189107d0c6` |
| Client checkout | HEAD `6d01e4a82818c0bae9013d4c42ead2b99a9be9c0`; observed 139-file fingerprint before and after `7fe06b0d5865eaf0a3719417cd78bf51b3566372c045ad2cfb5670baa87197fe` |
| Runtime properties | API level `35`; Android `15`; ABI `x86_64`; emulator flag `1` |
| Emulator image | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| Test matrix | **49/49 PASS**, 7 selectors, every adb and driver result exit `0` |
| Local UI smoke | **PASS** for unconnected bootstrap, create-without-activation, new profile unpinned/unenrolled, explicit profile-switch consent, and remaining unconnected after switching |
| Network | `none` |

The emulator was started with this recorded command (exit `0`; `emulator-start.json` SHA-256 `02ac15d8585f36f63fa556a11f60d5295fb43b918341cdc5abe1c29616b43ef9`):

```bash
docker run --rm -d --user root \
  --name cicada-v16-deterministic-v164-offline-preflight-20261002-1729 \
  --label org.cicada.client-v164-offline-preflight=v16-deterministic-v164-offline-preflight-20261002-1729 \
  --device /dev/kvm --network none \
  -e CICADA_TWO_OWNER_EMULATOR_PORT=5640 \
  -e ANDROID_ADB_SERVER_PORT=5070 \
  -e CICADA_EVIDENCE_OWNER=1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -v /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-emulator-preflight/run-v164-offline-20261002T1730Z:/out \
  -v /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-emulator-preflight/run-v164-offline-20261002T1730Z/installed-app.private.apk:/tmp/cicada-v15-app.apk:ro \
  -v /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-emulator-preflight/run-v164-offline-20261002T1730Z/installed-test.private.apk:/tmp/cicada-v15-test.apk:ro \
  sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f \
  bash /workspace/scripts/interop/two-owner-emulator.sh
```

The test classes and counts were:

| Instrumentation selector | Tests | Result / exits |
|---|---:|---|
| `ai.cicada.client.hub.ClientWirePublicVectorTest` | 5 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.EndpointAttestationVectorTest` | 4 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.LinkKeyManifestVerifierTest` | 7 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.LinkReviewPolicyConsentValidationTest` | 9 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.LinkReviewPolicyEvidenceV164Test` | 13 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.LinkConsentAuthorityFactoryTest` | 6 | PASS; adb 0, driver 0 |
| `ai.cicada.client.hub.LinkConsentLedgerTest` | 5 | PASS; adb 0, driver 0 |

Each test selector used this exact argv, substituting the selector from the table; the cited command index records every expanded command and its exit:

```bash
docker exec cicada-v16-deterministic-v164-offline-preflight-20261002-1729 \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 shell am instrument \
  -w -e class ai.cicada.client.hub.<SELECTOR> \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

The exact ADB prefix for installs, property reads, tests, and UI actions was `docker exec cicada-v16-deterministic-v164-offline-preflight-20261002-1729 /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640`. Both APK installs exited `0` with `install -r /tmp/cicada-v15-app.apk` and `install -r /tmp/cicada-v15-test.apk`. The four property-read argv values each exited `0` with `shell getprop ro.build.version.sdk`, `shell getprop ro.build.version.release`, `shell getprop ro.product.cpu.abi`, and `shell getprop ro.kernel.qemu`.

The exact launch argv was `docker exec cicada-v16-deterministic-v164-offline-preflight-20261002-1729 /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 shell am start -W -n ai.cicada.client/com.cicadaclient.MainActivity`; all UI commands and screen reads exited `0`. It used `shell uiautomator dump /sdcard/cicada-v15-layout.xml` followed by `exec-out cat /sdcard/cicada-v15-layout.xml` after each state transition. Input argv suffixes, following the exact ADB prefix above, were `shell input tap 160 109`, `shell input tap 160 461`, `shell input tap 160 411`, `shell input tap 79 436`, `shell input tap 160 109`, `shell input tap 260 384`, `shell input text OfflineQA`, and `shell input keyevent 4`. The explicit switch-consent action was an emulator automation event, not a human/physical-device approval. This local UI result does not exercise the separate Link-consent Alert or Hub protocol.

The run evidence is under `/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-emulator-preflight/run-v164-offline-20261002T1730Z/`:

| Artifact | SHA-256 / result |
|---|---|
| `offline-receipt.private.json` | `1d2067a1a09aac8dcd6d7045d3b020113d3409886a3be2edb261091003232a17`; 49-test matrix and local UI passed, classification `OFFLINE_ONLY_NOT_F6_HUB_ACCEPTANCE` |
| `deterministic-summary.redacted.json` | `de7f8c0c96eb6a7d35e726b69b35cfa56277028c3d5fd7251a5c43578d106a66` |
| `ui-smoke-summary.redacted.json` | `234d314471f4b98c81ec486f674a6976cbcf012ae80d148c3dd12e51d7543f35` |
| `android-runtime.redacted.json` | `519fc91ea80737fc4a1832b53f10f3b30575fcafb784bb72c75525204f89e471` |
| `offline-command-index.private.json` | `25904e462bad8a90f925337ea573cb796e820d8bec4db2383b55358d691fadea`; 37 recorded step argv/exits |
| `emulator-start.json` | `02ac15d8585f36f63fa556a11f60d5295fb43b918341cdc5abe1c29616b43ef9`; Docker start exit `0` |
| `emulator-stop.json` | `b5dbdb6ce4f4b28dd1170feb6e92afdd80bd2671c36d7c39f848cfd835e468cc`; Docker stop exit `0` |
| `offline-coordinator-invocations.private.json` | `f445e239bf398dc5b9eeda1de695cbac3b47ecb1a6c352858e3312b6cef25133` |
| `offline-cleanup-correction.private.json` | `8e94c177d2e953f85984745dc8b02241c89d6cb074ec96d604814baa81f9557a` |

The exact coordinator invocation was `python3 /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-emulator-preflight/offline-preflight-coordinator.private.py` from `/home/zyf/CICADA_CLIENT`. Invocation 1 exited `1` before Docker because the evidence directory was not empty while the coordinator was colocated there; its failure record is `offline-bootstrap-failure.private.json`, SHA-256 `1a9eebaa435a72cdbac87961c54aa1dfee12cf09c027ea437163b69218d66c26`. Invocation 2 also exited `1`: all 49 tests and local UI passed, but the immediate post-stop `docker inspect` exited `0`, leaving the original receipt's cleanup state `ABSENCE_UNCONFIRMED`. The exact `docker stop --time 10 cicada-v16-deterministic-v164-offline-preflight-20261002-1729` command exited `0`.

A separate correction-only addendum performed no test rerun and did not rewrite that original result. It ran the exact-name check `docker inspect cicada-v16-deterministic-v164-offline-preflight-20261002-1729 --format '{{.Id}}'`, which exited `1` with stderr SHA-256 `ca3dadd8ffd2edd3e78046430600d0bf079f7d88cbaeebe8ccaf7a9aa408f591`; the addendum classifies absence of that owned container as confirmed. The original outer coordinator exit `1` remains preserved.

An independent exact-ID check also confirmed removal of owned container
`21f9a983a428e1be8b833fc5af4c1dba769a09679c6da4809b2f3ea4d4f342d9`:
`docker inspect 21f9a983a428e1be8b833fc5af4c1dba769a09679c6da4809b2f3ea4d4f342d9 --format '{{.Id}}'`
exited `1` with the expected missing-object classification. Receipt
`independent-exact-id-absence.redacted.json` in the same directory has SHA-256
`13ea321cd3528b83d5f5243dc61e1b555162432b4df713941f677797b3c8f662`.
It retains an initial exit-1 audit-classifier attempt that expected uppercase
Docker error text; the corrected classification accepts the actual lowercase
missing-object text. This check ran no tests or container mutation.

The source identities for the offline runner are recorded in the receipt: [scripts/interop/v164-android-deterministic.py](../scripts/interop/v164-android-deterministic.py) SHA-256 `520f2bca0ce914c5b7529910be8d7cc78e638a90438ad2e1ca32bbf1d54dc78d`; [scripts/interop/v15-android-deterministic.py](../scripts/interop/v15-android-deterministic.py) SHA-256 `d80668cb132c1d6aec1d3a927d83fa312c2b43867ac4fbda19648d78055ff32a`; [scripts/interop/monitor-android.py](../scripts/interop/monitor-android.py) SHA-256 `e60b4ccdf6d5fc3cf0db42b127166ff421973efa04268b2297a48d67b832375f`; [scripts/interop/two-owner-emulator.sh](../scripts/interop/two-owner-emulator.sh) SHA-256 `9827a111708c18eda550174c6adaf5e8c653e28cb822d0244b3aeda9cb325fc8`; external private coordinator SHA-256 `9d5d4485e5aa0b24bb1bfeec8f508b84ae150a2f7942d691db7fa90bace8da30`. The shared `offline-command-index.private.json` has the precise argv and exit for each recorded step.

This evidence makes no formal five-pin delivery claim and does not record a fresh F6 `READY` or `GO`. Live F6 Hub RPC, owner enrollment/pinning/signing/proof exchange, actual Link-consent Alert acceptance, bilateral KEY/NONE operation, Hub runtime/recovery, interop execution gate, physical Android, public HTTPS, and model calls remain **NOT_RUN**. The earlier F5 failure is not carried over or reclassified.

## External signing and execution preparation

Core's public `signing-interface.md` v2 was read without executing its signer;
its SHA-256 is `a1c201d58fa4954f378a58e17a6e4d5d0c114828b7eadaac360924a3db6ae7ba`.
It accepts the existing flat Client request, exact selected expiry and actual
public device handoff. Root approval record IDs remain external; an unexported
Native review ID stays null. Core owns current-state checks and Owner private
keys. Client does not invoke that signer or read its database/private files.
This is **PASS** for static interface compatibility, with actual signatures
**NOT_RUN**.

The Client coordinator remains outside Git/APK under
`/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/coordinator-private/`.
Its `f6-coordinator.py` and final `README.md` SHA-256 values are
`d91a85bf235806b2232550e6d4855bcb96968bf67c84b8a30864523f42923e1d` and
`2ec764cd29870772a8ad5af1fa23a7d8132f1554b43eda0b37c29a57cf2bd720`;
files are mode 0600 and the directory is mode 0700. Static receipt
`coordinator-static-preflight.redacted.json`, SHA-256
`3248e1a0483e07e43f98acb229d10f91c510d118ab5bead1c1821dcbb3c3ccf8`,
records AST exit 0 and a superseded exit-1 check of an intermediate README
digest. The source script digest was unchanged. No live prepare/start/selector
or signer ran during this check.

The six planned external handoffs are Source DeviceGrant, KEY and NONE, then
Target DeviceGrant, actual RN KEY Alert and NONE. Raw request/proof hashes,
fresh delivery pins and full UI receipts are checked before recording a phase.
The Target UI process waits at most 180 seconds and respects the earlier
Source/Target KEY expiry. None of that preparation establishes a live result.

### Main F6 fixture format

The Core-owned Main fixture has a distinct READY layout. Its exact 17-field
receipt is `public/READY.json`, with ten Hub fields and nine public references.
Each reference binds its absolute path, relative path, raw SHA-256, byte count
and regular-file mode. The shared Client adapter resolves the owned manifest
from the same `evidence/attempt-NN/` directory as the Root-bound
`hub-ready-final.json` reference. It does not reuse the older F3/F5 receipt or
manifest locations. The carrier additionally validates the complete public
source, setup, binding and ACTIVE business-network relationships and actual
Docker ownership and image identity.

The inspected preparation draft, SHA-256
`633196e40218850e32a2f6e13b87ce9e6e40ffb1f1a11fe19927409a76ef7482`,
explicitly states `DRAFT_SCHEMA_ONLY_NOT_AUTHORIZED`. Attempt 05 was reported
cleaned without a usable READY. Its identities, state and pending digest
placeholders cannot authorize the future run. No draft value is used as an
actual Link, nonce, proof or delivery pin.

The fresh live run requires a separate actual READY, independently trusted
Root envelope and GO. Final coordination is bounded by the actual earliest
lease/Link expiry minus 15 seconds and the latest join plus 720 seconds; no
renewal or replacement proof is permitted within that run. The fresh emulator
will install the frozen pair and record four runtime properties. It will
reference the already completed offline 49-test/UI lane instead of repeating
that lane or rebuilding the APKs.

The shared pin/path gate passed **29 synthetic tests**, exit `0`, in the
cached builder image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`
with Docker `--network none` and a read-only Client mount. Its command was:

```bash
docker run --rm --network none --user 1000:1000 \
  -e PYTHONDONTWRITEBYTECODE=1 -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -w /workspace \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -m unittest discover -s scripts/interop \
  -p test_v164_link_fixture_pins.py -v
```

Receipt `/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-main-path-check/receipt.redacted.json`
has SHA-256 `eaa98dec396d9aa43e279ed75db19ad62b6db6ce41052474ca3df376e2fcac87`.
This gate covers independent metadata binding, Main READY hash/path resolution,
draft rejection and unsafe attempt references. It does not establish full
Main nested-field validation, live Hub facts or Android acceptance.

The full Main carrier structural gate subsequently passed **8 tests**, exit
`0`, with this actual command:

```bash
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -B -m unittest scripts.interop.test_v164_f6_ready -v
```

The final carrier SHA-256 is
`d49ede521d7f8410f96710960c4dfd7b6cc10a42797da13baa44526d46b144a4`;
the test SHA-256 is
`ac4eb382cf292014b32f7b6c748cd061c94b8ec0f71550bca3ba587610fa9510`.
Root independently checked both hashes and AST parsing, exit `0`, and
`git diff --check`, exit `0`. A separate read-only review found no material
gap in the Main dispatch, nine public references, source/build relationship,
helper provenance, Hub readiness, binding namespaces or raw Endpoint-proof
digest/scope handling. Endpoint signature verification remains the existing
independent Kotlin verifier; these Python tests make no signature claim.

The initial run of that command exited `1` (7 of 8 tests passed): the positive
fixture revealed that Link creation/update timestamps had been included in a
generic ID loop. The correction routes those fields to their existing strict
UTC-Z timestamp parser. Docker capture timestamps use a separate exact Python
UTC-offset parser. SessionBinding, NetworkAccess and native registration IDs
are validated in their own namespaces; no cross-namespace equality or
inequality is invented.

Evidence directory:
`/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/offline-f6-carrier-test-20261002/`.
Receipt `receipt.private.json` has SHA-256
`d07df0c62b19442c68ab8f5becdb9252a93d6f4241f4a5f1774e82fc4ad44745`;
`command-index.private.json` has SHA-256
`32413c9ea7356346c7d4460b52b964b96b9b4294a09a9cdfb06af88e135a63e0`.
The retained initial and final output transcripts have SHA-256 values
`c9d54f7e1ad658c7781fdd95fc142a9ef7f12c2747331fa4eebbce4bde015895`
and `fb0d73c005b27722f79ddbff78adfdb4df81aef445b72865b88296b750473ece`.
They are explicitly transcribed from direct tool output, not original
redirected stdout bytes. The initial source digest was not captured. These
records preserve the original failure; no tests were rerun to create them.

## Actual Main F6 attempt 06 — terminal record

Core Root delivered formal GO at `2026-10-02T18:48:21Z` for the actual Main
fixture `/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002`.
The fixed deadline was `2026-10-02T18:51:45Z`. Neither deadline nor nonce was
renewed. The previous draft and attempt 05 were not used.

| Actual delivery binding | SHA-256 |
|---|---|
| Root envelope, `public/root-client-pins.json` | `8d7c29812accaab849519dd76e4e4a04a5937028546f1063df04fe217dbb5327` |
| Independent Client delivery metadata, `v164-f6-preparation-20261002/delivery-dd81575.private.json` | `e889e4804de3407d5a07f37a027a6f9c1cba1984babe5e9f65dedb2cb41e61d3` |
| Actual `public/READY.json` | `ea6bbf53400066ef157e180e8cc2bb2439ce3ebd8bfb5e107c825f121cd8e09a` |
| Setup, Hub-ready, reference and owned-manifest hashes | `fa17c6ff39c01f00f0fa44949c3c531bdad7f734ca5f6200fdf7b5741e98b285`, `f8b7af494ba728f797f90c4e48f16291ded912eb8601460b329bba304b7fbe5c`, `6435aad8271665aa981d4b4cca2b2f089c536edc35c498ce919c69bc21dc2e35`, `44abf381d80b04adda2e0d5b83f58bc93e47dad4fe501bc67ec6856ac6adec04` |

The run ID was `v164-f6-dd81575-main-20261002`. Its private coordinator
directory is `/gpu1-share/data/cicada-client/v164-f6-preparation-20261002/coordinator-private/runs/v164-f6-dd81575-main-20261002/`.
The Android evidence directory is `/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-dd81575-main-20261002/android/`.
Directories are mode 0700 and receipts are mode 0600. Device keys were not
generated or exported. The two prepared public onboarding files were never
staged into Android; they are not device enrollment evidence.

| Step | Actual result / exit |
|---|---|
| Coordinator `prepare` with actual five delivery arguments | **PASS**, exit 0; plan only, no Hub mutation |
| Carrier `verify_hub` against actual nine public references and Docker objects | **PASS**, exit 0; complete image ID, source/build relationships, owned mounts/network, loopback exposure and reachability verified |
| Initial Android `start` | **FAIL**, exit 1 before Docker: required private evidence directory did not exist |
| Same Android `start` after mode-0700 directory creation | **PASS**, exit 0 |
| Fresh emulator boot, both frozen APK installs, four runtime-property reads | **PASS**; installs and each property read exited 0; API 35, Android 15, x86_64, qemu 1 |
| Carrier process, onboarding stage, Android business selector, encrypted capabilities | **NOT_RUN** |
| Source DeviceGrant / KEY / NONE; Target DeviceGrant / actual RN KEY / NONE | **NOT_RUN**, all six signing requests, Root approvals and Owner signatures were zero |
| Client-owned emulator stop and removal | **PASS**, stop exit 0; inspect initially 0 while stopping, then expected missing-object exit 1 |
| Core-owned Hub and bridge cleanup | **PASS**, Core watchdog removed both at deadline with exit 0; Client independently confirmed both exact IDs absent with expected inspect exit 1 |

The actual coordinator command was:

```bash
python3 /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/coordinator-private/f6-coordinator.py prepare \
  --link-run-id v164-f6-dd81575-main-20261002 \
  --android-run-id v16-deterministic-v164-f6-dd81575-main-20261002 \
  --evidence-root /gpu1-share/data/cicada-client/v16-deterministic-v164-f6-dd81575-main-20261002/android \
  --app-apk /gpu1-share/data/cicada-client/v164-25bc586-20261002/candidate-build-retry-6/binaries/app.private.apk \
  --test-apk /gpu1-share/data/cicada-client/v164-25bc586-20261002/candidate-build-retry-6/binaries/test.private.apk \
  --delivery-pins /home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002/public/root-client-pins.json \
  --delivery-pins-sha256 8d7c29812accaab849519dd76e4e4a04a5937028546f1063df04fe217dbb5327 \
  --delivery-metadata /gpu1-share/data/cicada-client/v164-f6-preparation-20261002/delivery-dd81575.private.json \
  --delivery-metadata-sha256 e889e4804de3407d5a07f37a027a6f9c1cba1984babe5e9f65dedb2cb41e61d3 \
  --fixture-root /home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002
```

The actual verification used an in-process Python import of the unchanged
carrier followed by `_configure(...)` with these same trusted delivery pins
and `verify_hub(None, None, native_topology=<actual READY>,
native_topology_sha256=<actual READY SHA>, fixture_sha256=<setup SHA>,
public_sha256=<actual READY SHA>, native_mounts=<owned manifest>,
native_mounts_sha256=<owned manifest SHA>)`. The direct tool command exited 0;
the result receipt is listed below. This was verification only; no HTTP
business call or carrier process was started.

The fresh bootstrap's exact Docker argv is retained in
`android/emulator-start.json`; it uses the cached immutable emulator image,
`--network none`, a read-only Client mount and the frozen APK pair. The ADB
prefix was `docker exec cicada-v16-deterministic-v164-f6-dd81575-main-20261002
/opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640`.
Install suffixes were `install -r /tmp/cicada-v15-app.apk` and
`install -r /tmp/cicada-v15-test.apk`; property suffixes were `shell getprop`
followed by `ro.build.version.sdk`, `ro.build.version.release`,
`ro.product.cpu.abi`, and `ro.kernel.qemu`. Every expanded command and exit is
in its named JSON receipt. The actual cleanup command was
`docker stop --time 10 cicada-v16-deterministic-v164-f6-dd81575-main-20261002`.

| Private evidence artifact | SHA-256 |
|---|---|
| Coordinator `plan.json` | `1423078eb7bea43909321291060d54275b82fdb918de5123c5401a7064b16ef8` |
| Coordinator `commands.txt` (planned commands, not proof of execution) | `04b2409ca9e7bed27eab9299d3a4271b47e9cc66c83eabaf3ccb2596fe343254` |
| `actual-fixture-verification.redacted.json` | `97db968887caca47d6da1cb23b1940e8f1acb6a20c396503e7200282c9b98305` |
| `f6-terminal.redacted.json` | `4d4f1c758c755c0a0b0618eece7a496823927721bf04f4499fc77c8bee2090fc` |
| Android `emulator-start.json` | `a92ea978a9aa1f5c52c0816b46186c417bc02f2cc97e4fdeeb19cd3be1fc87ae` |
| Android `install-app.json` / `install-test.json` | `6376e61d5530f290d4d98295ec3603e3469ce7260df538347c270a38e84d0f84` / `80cec92fe359ecb00c9aff5137521615b60a4d1934a66af845af255d57b468cf` |
| Android `android-runtime.redacted.json` | `519fc91ea80737fc4a1832b53f10f3b30575fcafb784bb72c75525204f89e471` |
| Android `android-teardown.redacted.json` | `1df0b57744dc8d34c4115d5b3ad6d393d8192531e946e7fe25ab0186a11669a0` |
| Android `emulator-stop.json` / `emulator-absence-check.redacted.json` | `1b7114c9c3bd30a114cfd30fe8a2fb7c7fb91aa74e87a1768c7b582faf87e607` / `31aad0617897558df9af190ee740de0c99e1392f695cc25a0fba04b48041a7a4` |
| Coordinator `core-cleanup-addendum.redacted.json` | `3d1b6dba75f01a17784f2cfd32969b1f0860a277e5e72be60db9ca47d4f495f0` |

Core's public cleanup records remain under
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-06-20261002/evidence/attempt-06/`:
`cleanup-1790967105923979569.json`, SHA-256
`fe7bfe28c74a640637bff254ece23c0d14d58013fa6eda4f669aca50f0e96866`,
and `terminal-cleanup-absence.json`, SHA-256
`4e34058a872d4e41feef94c23cce6fb05cc5ba60984352b7ce1c92df37172a7a`.
Core attests private fixture deletion. Client checked only public receipts
and exact Docker resource absence; it did not inspect private paths or a DB.
The cleanup addendum retains both actual exact-ID inspect argv/results.

The formal GO left 204 seconds. Plan preparation, actual fixture verification,
the missing-directory correction and fresh emulator boot/install consumed that
window. No first Android signing request reached Core Root. This is an
execution-coordination blocker, not evidence of a cryptographic failure. No
business packet, operation ID or sequence was created, and no pending business
request can be replayed. The original initial-start failure is retained.

## F7 boot-only preparation — closed without fresh business GO

Core Root subsequently authorized **BOOT ONLY** for a new owned emulator,
with at most 20 minutes of waiting. This did not authorize Client Hub calls.
The Core fixture location was separately fixed to
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-07-20261002`,
label `client-link-v164-07`, Root scope `fresh-F7`, with the existing family
schema retained. Attempt 06 and its evidence were not overwritten.

The new run was `v16-deterministic-v164-f6-f7-dd81575-main-20261002`.
The literal `f6` portion identifies the existing harness family, not a reused
F6 fixture. Evidence remains in
`/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f7-dd81575-main-20261002/android/`.
Its frozen APK pair booted successfully; both installs and all four actual
runtime-property commands exited 0. READY was observed at
`2026-10-02T19:08:50.174Z`. No instrumentation, UI, device export, Hub operation
or Owner signing ran.

Private adapter copies under
`/gpu1-share/data/cicada-client/v164-f7-preparation-20261002/adapters/`
change only the separately authorized exact fixture root, label, Root scope,
helper source mount, import locations and adoption of the one known owned
bootstrap. APK, product source, wire protocol and catalog remain unchanged.
The helper source mount is strictly
`/src/cmd/cicada-client-link-v164-fixture-07`; the old 06 helper is not treated
as a matching 07 build. No private adapter is installed in the APK or Git.

| F7 preparation gate | Result |
|---|---|
| Cached immutable emulator, frozen APK installation, four real properties | **PASS**, bootstrap only |
| Exact prebooted container identity/image/label/network, frozen APK bytes and recorded installs/properties, no prior trusted/business evidence | **PASS**, private adoption check exit 0 |
| One synthetic positive and eight requested pin-shape refusals | **PASS**, Docker exit 0; no actual READY read |
| Fresh Root five-pin delivery, Android artifact binding, carrier, encrypted capabilities and business operations | **NOT_RUN** |
| Six signing requests, Root approvals and Owner signatures | **NOT_RUN**, zero of each |
| Idle cutoff and exact owned-emulator cleanup | **PASS**, stop 0 and expected missing-object inspect 1; finished `2026-10-02T19:25:08Z` |
| Core-owned F7 Hub/bridge removal and Client exact-ID absence checks | **PASS**, Core removal exit 0; both independent missing-object queries exited 1 |
| Client execution of Core PRE/final Join/READY or Core resource cleanup | **NOT_RUN**; the Core maintainer must report its separately owned operations |

The eight synthetic refusals cover old 06 root, unrelated 08 root, relative
path, traversal, old 25bc586 Core, old 06 label, old `fresh-F6` scope and wrong
full Root-file SHA. Their success is a shape guard, not live authorization.
The private binder was frozen and syntax-checked but never executed.

An idle watcher bound the exact Docker ID, name, image, ownership label and
network at startup and cutoff. It used the existing ownership/stop helpers;
there was no file-based GO channel. Its hard deadline was
`2026-10-02T19:25:08Z`. Fresh READY, five delivery pins and business GO were not
received before that deadline, so it stopped only its owned emulator. An
independent exact-ID query subsequently confirmed absence. No late GO was
consumed, idle deadline extended, or emulator automatically restarted.

The actual startup Docker argv, two install argv and four getprop argv are
retained in their mode-0600 receipts. They use the same previously recorded
cached image, network-none and read-only Client mount, with the new run/name
and evidence path above. The stop command was
`docker stop --time 10 cicada-v16-deterministic-v164-f6-f7-dd81575-main-20261002`.
The exact-ID absence command and exit are in the terminal receipt.

| F7 evidence | SHA-256 |
|---|---|
| Android `bootstrap-only.redacted.json` | `f9117d82dd1e8a62941307b7eca2afa60a7ed45987fef9340b7e88c3ad834f52` |
| Android `emulator-start.json` | `0e285ee0a671be8a19f735a4113bb63b88297f60ca382be9639cee05e7e51d21` |
| Android `f7-idlewatcher-ready.redacted.json` | `615ab028277cbbc6b3f7b28f7bf3791821d60eeff97a63845459ee1e226a8bff` |
| Android `f7-idlewatcher-finished.redacted.json` | `be2213e0d8e383b40b57a1527253979f4e0ec2010d5839d6f15366b9d6214b03` |
| Android `android-teardown.redacted.json` | `e58f3c205d90499c8b57fae8062f0fcf0ebeacb35a2df83afffc9ced5115aff4` |
| Preparation `f7-pin-shape-check/receipt.private.json` | `7991615050ce09aac73d5e72dd903c5bc46ab760227827604ebf664a69f105e7` |
| Preparation `bootstrap-adoption-check.redacted.json` | `cc2880ac40fc6a772810e1333624832f9c2ff98effaa76d2df42bc82ea7417b0` |
| Preparation `adapter-source-index-ready.private.json` | `108adf657b1f66e26f17901d148f82264a31905e790bf499b7fa3a9e7eae8bfb` |
| Preparation `f7-bind-boot-artifacts.private.py` | `b2f986da531a40a68a501ae6e837a767aa03e6b1288a3e20a74943e45fb81d37`; syntax only, not executed |
| Preparation `f7-preparation-terminal.redacted.json` | `e919de2d3d4ff08afcaa7ccfe07598091adc5570278b4688f27bb11b44d789fe` |

The preparation root is
`/gpu1-share/data/cicada-client/v164-f7-preparation-20261002/`.
The initial pre-Docker absence-classifier error remains in the sibling Android
`preflight-attempt-01/` directory. The initial adoption check exited 1 because
the private adapter assumed the delegated driver's `driver_exit_code` field;
the actual direct-bootstrap receipts have `expected_exit_code`. That original
failure remains in `bootstrap-adoption-initial-failure.redacted.json`; the
corrected check requires the actual integer exit/expected-exit 0 and PASS.
Neither failure created a Hub operation. An incorrect prewritten carrier hash
in one coordination message was explicitly retracted; the frozen source index
binds the actual raw-byte hash `7b7d4c00f8a54b42b2dad13f670e283faf4356162aed5bc9a300d69c2e70fa2a`.

F7 preparation closed **BLOCKED_NO_FRESH_ROOT_GO_BEFORE_IDLE_CUTOFF**.
It has no pending business packet, operation or sequence. No Client result is
inferred from Core preparation/build activity. Physical Android, public HTTPS,
native Worker/model and bilateral acceptance remain **NOT_RUN**.
Core Root subsequently instructed termination of its PRE and reported that no
final Group Join, Link or READY had been produced. This is a coordination
report from Core, not Client execution or a database observation. Both sides
stopped this attempt; no further bootstrap or fixture is authorized in this
closure.

Core delivered its actual cleanup receipt
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-07-20261002/evidence/attempt-07/cleanup-1790969360004890525.json`,
SHA-256 `21833ed03d4bc1ef5dd7419a546f1afdfe2da2d70d52baf499c0fcca967b0b60`.
It records removal of the two owned Docker resources with exit 0. Client
independently queried their exact full IDs and confirmed container/network
absence, each with expected exit 1. Addendum
`/gpu1-share/data/cicada-client/v164-f7-preparation-20261002/core-cleanup-addendum.redacted.json`,
SHA-256 `8d53429501ee1aa946febfa0a5aa91f618c8d55dee9a7168443e9b930a5d288a`,
retains both actual commands and tool outputs. This confirms resource cleanup
only; Client did not inspect Core private paths or a database.
Core separately supplied
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-07-20261002/evidence/attempt-07/terminal-cleanup-absence.json`,
SHA-256 `1c158ed4ab25483406750ff54de2ab51ac4e2720fa9f6c85cdafe1b54cac20e0`,
and `public/f7-terminal-evidence-index.json` at the same fixture root,
SHA-256 `6f50ab36ae51d5cd44f4617be4864d5c61f5c7632c24e4e99ecc05d96f7de81f`.
Core reports its 80-entry inventory matches and eight private paths are absent.
Those are Core-attested results; Client's independent scope remains public
cleanup receipt integrity and exact Docker resource absence.

## F8 terminal record — 2026-10-03

F8 used the fixed artifact identities above, with no product or APK rebuild.
The Client checkout during execution was
`f31794abeafc0629003b8dd6240e356b5fd263c0`; it is distinct from the frozen
product checkpoint `508ca333c8ae90d27a8191ac828a7be16b71c7b3`.
The Core fixture was `client-link-v164-fixture-08-20261002`, label
`client-link-v164-08`. Current Core development changes were not used as Hub
image provenance.

| Gate | F8 result |
|---|---|
| PRE and final public receipts, nine references, fixed running Hub image and ownership | **PASS**, read-only verification |
| Initial emulator and separately authorized business emulator; frozen APK installs and four properties | **PASS**, bootstrap only |
| Exact current emulator/artifact binding | **PASS**, binding only |
| Opaque five-route carrier startup | **PASS**, startup only; zero transactions |
| Carrier outer invocation | **FAIL**, exit 1 while removing ADB reverse after emulator removal; child exit 137 |
| RootFlow invocation | **FAIL**, exit 1 at fixed-deadline guard before first stage; business acceptance **BLOCKED** |
| Device export, enrollment and encrypted `session.capabilities` | **NOT_RUN** |
| Source/Target KEY and `NONE`; Target real React Native Alert | **NOT_RUN** |
| Six external Owner requests/signatures; RPC packet/operation/sequence | **NOT_RUN**, all counts zero |
| Owned Client emulators, carrier processes, Core Hub/bridge cleanup | **PASS**, attribution and exact absence checks below |
| Link lost-response/409 recovery | **BLOCKED**, no approved isolated fault driver |
| Native Worker/model, physical Android, public HTTPS | **NOT_RUN** |

The initial emulator was ready at `00:00:16.449Z` and removed at its fixed idle
cutoff `00:25:09Z`. Coordinator prepare then exited 1 because that emulator no
longer existed. Core Root authorized one fresh business emulator on the same
F8 fixture; it became ready at `00:29:56.359Z`. Prepare exited 0. The binder
first rejected the Client preparation directory's mode 0755, then passed at
`00:31:52Z` after mode 0700 was restored. Carrier attempts also rejected the
remaining literal `cicada-cl164-06` name check before the private adapter was
corrected to the actual 08 fixture. These failures remain retained.

Original GO was approved at `00:29:13Z`. The corrected scope/GO, approved at
`00:33:38Z`, distinguished phone proof validity from the unchanged execution
stop `00:34:43Z`. Proof expiry may exceed that stop only within the phone's
original five-minute and current Link/preview limits; signing/submission
authority and cleanup were not extended. RootFlow reached its deadline guard
before its first stage subprocess. Its command index is exactly `[]`; only a
host-generated public setup DTO was created. No phone device key, Grant,
pending packet, operation, counter or signature was created. Original GO was
consumed by the bootstrap binder; corrected GO was read by RootFlow, not by a
second binder. The authoritative terminal record supersedes the source-limited
timeline addendum's earlier attribution.

### F8 commands and evidence

Client preparation root is
`/gpu1-share/data/cicada-client/v164-f8-preparation-20261002`.
Core public evidence root is
`/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-08-20261002`.
All Client evidence remains outside Git/APK, in private directories and files.

| Recorded command | Exit / evidence |
|---|---|
| `docker run --rm -d … sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f bash /workspace/scripts/interop/two-owner-emulator.sh` | Both starts 0; full expanded argv in each `emulator-start.json` |
| Exact emulator ADB `install -r` for both APKs, then four `shell getprop` reads | All 0 in both lanes; API 35, Android 15, x86_64, qemu 1 |
| `python3 <prep>/adapters/f8-coordinator.py prepare …` | Initial 1; business 0 |
| `python3 <prep>/f8-bind-boot-artifacts.private.py …` | Initial 1; corrected 0 |
| `python3 <prep>/adapters/v164-link-fixture-carrier.py …` | Initial validation failures 1; final startup READY, then outer 1, child 137, transactions 0 |
| `python3 <prep>/f8-root-flow.private.py …` | 1, deadline guard before first stage |
| `docker stop --time 10 <exact-owned-emulator>` | Both 0; generated stop receipts |
| Exact full-ID Docker container/network inspections | Expected 1 with explicit missing-object text; independent absence **PASS** |

The complete expanded command journal is
`<prep>/f8-command-index.redacted.json`, SHA-256
`7ce685082083c070e70940c16c476a02fb0e1c702623e1a7dd30515bcc1dab24`.
It distinguishes original generated command receipts from operator-curated
previous tool invocations; these commands were not replayed during closure.

| Artifact | SHA-256 |
|---|---|
| `<prep>/f8-terminal.redacted.json` | `82bb25b84bd8f1a50630a9b525fe54b0f08fe737f8a299d088e6ffb82fdc5a2d` |
| `<prep>/f8-bootstrap-binding.redacted.json` | `b6947c6c2333119de3c03c0bf5c22bac81b71be98c065d8695bf440a0e523a39` |
| Core `public/READY.json` | `6cdad9b95f66424fcaa4f714e8be4de1067eb7e5308eddd30e2d40aef0684b15` |
| Core `public/M5-SCOPE.json` / `public/Root-GO.json` | `3ba129e0090e5ddaea883fab216e4dc5941efe800358f545b0283a3c90544c68` / `c406757f1eca172ea7ff69f0f4759e081e3de18310565c37bb236c23f218c47e` |
| Core `public/M5-SCOPE-CORRECTED.json` / `public/Root-GO-CORRECTED.json` | `3e65a9848baf3bcb1cd87ca3060c28107af2316c8e217c4ff5aaea6f4cc36aec` / `4c6cb632b02bd501fc313b8e6fbe187d0411a351fa610286f530f29e349e470c` |
| Business `android-teardown.redacted.json` | `cb4ea950fa1c9429eb152c3422c8f498e99cdd03e6e30bbea708826b51080e47` |
| Business `stdio-carrier-f6-f8-business-dd81575-main-20261002-stopped.redacted.json` | `8f5ea709223fa5c8e00084bfd3bbbcbaf02dad5522d7dcbefde3b49b996dc8f6` |
| `<prep>/independent-cleanup-classification-addendum.redacted.json` | `c6a3ff39ed9de1d3dbd1ef6d0fc58dd81f29d11331492dc9969560d13552a6e3` |
| Core `evidence/attempt-08/cleanup-1790987684234114116.json` | `930509b60780ea96797decf94f0119d2594bfcf61584d6efc630eef76828716e` |
| Core `evidence/attempt-08/terminal-cleanup-absence.json` | `23a774e73bc2ffffd72e161fdb0b72404e4c67a2bb42222a654ac944ba401766` |
| Core `public/f8-terminal-evidence-index.json` | `2d7f034b1022563cde951163110e6f96dabc1e64caf547862377984b390eaaca` |

The business evidence directory is
`/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f8-business-dd81575-main-20261002/android`;
the initial lane uses the same path without `business-`. The terminal receipt
binds both lanes, actual container IDs, immutable images and the complete
receipt index. Core's original watchdog removed its Hub/bridge with exit 0;
private-path destruction is **Core-attested**, not a Client database/private
file observation. Client independently confirmed both emulators, the Hub,
bridge and carrier processes absent. The original cleanup classifier receipt
remains `PENDING`: it expected `No such object` for a network whose actual
explicit absence text was `not found`. The separate correction retains that
receipt and records the expected full-ID absence; it reruns no business test.
At F8 closure, F9 was an offline plan only. Its later live outcome is recorded separately below.

### F9 offline carrier correction

The Client carrier now validates bounded safe Docker resource names and the
exact independently supplied fixture label, while retaining the pinned
manifest, full container/network IDs, immutable image, ownership, mounts and
nine public references. Helper provenance requires the independently pinned
source-image mount; only the exact historical F6 label retains its original
06 fallback. A later runtime root does not imply a new helper build origin.
No product or cryptographic verifier changed.

The existing eight structural tests plus one test containing a positive 08
manifest, wrong-label rejection and wrong-CID rejection passed: **9 tests,
exit 0**, no live Hub, signing, model or emulator. The exact command was:

```bash
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro -w /workspace \
  -e PYTHONDONTWRITEBYTECODE=1 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 -B -m unittest scripts.interop.test_v164_f6_ready -v
```

This is a synthetic shape regression **PASS**, not F9 encrypted/runtime
acceptance. Carrier receipt
`/gpu1-share/data/cicada-client/v164-f9-preparation-20261003/carrier-offline-regression.redacted.json`
has SHA-256 `ac47e0267b7627ba3b107686421316d92ddc40ebf90c7508a6fded9848dc0a74`.
The complete private preparation then passed one bounded network-none Docker
run: 11 file AST checks, eight CLI parsers and two exact reused-helper
provenance checks, exit 0. Its receipt `bounded-offline-preflight.redacted.json`
in the same directory has SHA-256
`0e88bc4468da7b675dfac58a5f33ba0d9b3a73629c0e160812da1f5a5f0ff93f`;
it retains the exact outer Docker argv, every parser argv/exit and output
hashes. No Core mount, Hub, Android, Owner signing or model call was used.
Freeze `f9-offline-freeze.redacted.json` has SHA-256
`4825e38ebbed247232f3dbd47255a13929e66776cd071b3b53769a511b5b0ab2`.
These checks preceded the F9 live attempt below and establish only offline
preparation. `client-checkpoint.redacted.json` binds their original Client
checkpoint; the live outcome does not change those historical results.

## F9 terminal record — 2026-10-03

The actual Client source was `6b2c552197bb625e31e32d700d84d12685b8f81f`.
The frozen product source, APKs and all fixed delivery identities above remain
unchanged. Core development changes were not used as this Hub. Runtime fixture
09 reused the reviewed helper build from 08; it was not attributed to a new
build. The one approved business flow was attempted once and stopped on its
first failed subprocess.

| Gate | F9 result / actual exit |
|---|---|
| Network-none emulator bootstrap and two frozen APK installs | **PASS**, bootstrap `0`, 37.122 seconds; actual READY `01:06:29.807Z` |
| API 35 / Android 15 / x86_64 / emulator property receipts | **PASS**, four commands `0`; bootstrap only |
| Coordinator prepare | **PASS**, `0`; plan only |
| Bootstrap-to-delivery binding | Initial CLI **FAIL**, `2` for missing `--helper-source-image-mount`; corrected invocation **PASS**, `0`; no business operation in either invocation |
| Opaque carrier startup | **PASS**, actual `READY`; zero transactions |
| First `stage-source-setup-public.json` / flow | **FAIL**, subprocess `1` / outer `1`: `owned emulator runtime metadata is inconsistent` |
| Device export / enrollment / encrypted `session.capabilities` | **NOT_RUN** |
| Six external Owner claims and signatures | **NOT_RUN**, zero requests and signatures; Core actor exit `0` is Core-attested |
| Source and Target KEY / `NONE`; actual Target React Native Alert | **NOT_RUN** |
| Fresh bilateral encrypted status | **NOT_RUN** |
| Carrier shutdown | Outer **FAIL**, `1`; Docker child `137`, zero transactions; ADB reverse cleanup failed during deadline-driven emulator teardown (Docker exit `128`, driver `1`) |
| Owned Client emulator and process cleanup | **PASS**, watchdog stop `0`, exact absence inspection `1` |
| Core-owned Hub/network cleanup | Core reports removal `0/0`; independent exact-ID absence audit is recorded separately; Core private-path deletion is Core-attested |
| Native Worker/model, physical Android, public HTTPS | **NOT_RUN** |
| Link write recovery faults | **BLOCKED**, no approved isolated Link fault driver |

### Failure and timing

The bootstrap wrote `android-runtime.redacted.json` with schema
`cicada.client-v164-deterministic.v1`, `image_id` and four actual properties.
The staging consumer instead required the legacy producer's
`emulator_image_id` and `platform="Android emulator"` fields. Neither field
exists in the actual bootstrap receipt. The binder had verified the image and
four raw property receipts, but the staging consumer used a different format.
This is a Client fixture compatibility failure, not a Hub encryption result.
The original receipt and failed command are immutable evidence; they are not
patched to make this attempt pass.

Root approved the business Scope at `01:17:13.969997Z`, with a hard stop at
`01:23:47Z`. The binder completed at `01:19:10.584509Z`. The carrier startup
receipt file was written at `01:20:06.784143898Z`; this filesystem timestamp
is not a separately captured READY event timestamp. The Client did not poll
the yielded carrier session until `01:23:17Z`, following a context handover.
The stage receipt was written at `01:23:38.939667491Z`, likewise an observed
filesystem completion timestamp rather than an instrumented start time.
This host orchestration gap is retained independently of the metadata bug.
The original idle watcher was replaced only after a business watcher adopted
the same exact container with the earlier stop. No expiry or claim count was
extended. No operation, nonce, signature or flow was retried.

Core's sole watchdog cleanup receipt records `01:23:48.740840210Z`,
1.740840210 seconds after the fixed stop. This is cleanup timing, not an
extension of signing or submission authority. Carrier's stopped receipt says
`PASS` for its local payload-persistence check; it does not override its
actual outer exit `1`. The original reverse cleanup log reports an OCI
`setns` failure, Docker exit `128` / driver `1`. The reverse receipt was
written before the stop receipt; filesystem write times do not establish
which action completed first. The retrospective journal's “after removal”
wording is therefore classified as a teardown race, not proven action order.

### Commands and evidence

Set `B=/gpu1-share/data/cicada-client/v164-f9-preparation-20261003`,
`E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f9-dd81575-main-20261003/android`
and `F=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-09-20261002`.
These paths identify historical evidence and must not be reused for a new
live operation. Exact actual argv and exits are in the journal and referenced
original receipts; its retrospective capture is explicitly labelled.

| Evidence | SHA-256 / purpose |
|---|---|
| `$B/f9-command-journal.redacted.json` | `31ec5b09ffef5cdbb1d579592e499cbd42e6c88d4143f57718f6ef61557c3099`; bootstrap, flow, carrier, first stage and watcher commands/exits |
| `$B/f9-owned-cleanup-audit.redacted.json` | `dce895e20f04fc623dad35889b02a4516045a5719377d9046e2df1b161130b44`; independent exact-ID/fixture-label checks, captured `01:41:00.456196Z`; three inspect exits `1`, five empty-filter exits `0` |
| `$B/bootstrap-stage-result.redacted.json` | `b7614686d0efe12d8b3b9fb08cf5e9dd8d0cb1ce412844d935f87629a78a896f`; actual `python3 .../f9-bootstrap-only.private.py --execute --idle-deadline 2026-10-03T01:24:00Z`, exit `0` |
| `$E/f9-hot-ready.redacted.json` | `3661c0ff1ff5b9bb28cf741335f8e04231a8ceaafbdf31b617333571be997303` |
| `$B/f9-bootstrap-binding.redacted.json` | `ed652bc3ec33740ac4617dfb3a41693ce3c6727cd938bf712a09f0588a634084`; corrected binder exit `0` |
| `$B/actual-flow/01-stage-source-setup-public.json.private.json` | `418811111468937c9f2f84fd6d26f5bddf1345e9b2606ce30ce5f3b8fad99d37`; original exact staging argv, exit `1`, error |
| `$B/actual-flow/command-index.private.json` | `7ccefeb49c49ebd91b9ca3699077040d54ec8ea6bcfc0d2178cbf3bf0a50e684`; one failed subprocess |
| `$E/android-runtime.redacted.json` | `d5dd216d5d0d28805540433b269fe278e8c20bf2359db52c2e852400e6a344e5`; original metadata mismatch |
| `$E/business-deadline-watcher-terminal.redacted.json` | `8fe2e6b671f55a44505544ffdc50413ddf9a62cbc1c54902657bcf7eebb3ec2f`; stop `0`, exact absence |
| `$E/android-teardown.redacted.json` | `8e465a7e5d399f537b9d47eb7378f0897234ad5a1572f4820e682f9c70b39517` |
| `$F/public/f9-core-terminal-evidence-index.json` | `7d661854804af404a4ef150fe39427d256cbeab53d075df53c27debb74df33ea`; Core's 11 terminal references |
| `$F/evidence/attempt-08/cleanup-1790990628740840210.json` | `538887f53b952e8e83ee37225da9e143c1307ea8565a4a6e8e098f839f26b90d`; original Core watchdog `0/0` |

The actual independent Hub/Node identifiers stay in restricted evidence.
Public documentation carries artifact hashes and evidence paths, not device
codes, Owner keys, session contents or bearer credentials. Ordinary cross-user
messages remain disabled. No APK rebuild, native execution or production
change occurred in this attempt.

### Runtime validator correction — offline result

The corrected consumer accepts the exact two documented producer projections.
It requires the pinned emulator image and Android 15 / API 35 / x86_64 / qemu
properties, rejects contradictory aliases and unexpected fields, and verifies
F9's four raw `getprop` command/output/exit receipts. Boolean values cannot
stand in for integer exit codes. Existing APK, ownership, immutable delivery
and network checks remain in the staging path.

The new `bootstrap-preflight` command checks the same runtime validator,
actual owned image/label/network-none, READY marker and bound container ID
against read-only live Docker ID/status. It makes no Hub or Root delivery
claim. `preflight` additionally runs the existing artifact/delivery checks
without staging, exporting, running instrumentation or contacting the Hub.
They must run on a newly authorized live bootstrap; neither was run on the
expired, removed F9 emulator. Live corrected preflight and business acceptance
remain **NOT_RUN**.

The focused Docker regression passed **9 tests, exit `0`**. Cases cover both
producer formats, mismatched image/properties/network/aliases, incorrect raw
property commands, missing receipts, boolean exits, mismatched READY/live IDs
and a stopped container. This delegated test execution is independent of the
historical F9 live attempt. No APK or cryptographic matrix was rebuilt or
rerun. The actual command was:

```bash
docker run --rm --network none \
  --mount type=bind,src=/home/zyf/CICADA_CLIENT,dst=/workspace,readonly \
  --mount type=bind,src=/gpu1-share/data/cicada-client,dst=/gpu1-share/data/cicada-client,readonly \
  --workdir /workspace --entrypoint python3 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  scripts/interop/test_v164_runtime_preflight.py
```

Receipt `$B/f9-runtime-fix-regression.redacted.json` has SHA-256
`6e3d6aad3a519e08756084f6ee83d1276dc490add909dae7d9700e1efa7a794d`.
It records the actual delegated command/exit and root-checked source hashes;
the full test output remains in the delegated tool transcript, rather than
being invented in a local raw-output receipt. Consumer source SHA-256 is
`f4977a693a96836785f89e3deac222c7bcac72b7478ced6b2d88863e8bcbbf72`;
regression source SHA-256 is
`bb7b5a19c6621b98ebd1384e4169f03f838e043ed5a0c3bc09a9bd90d5f8801b`.
The original private F9 adapters are not modified. This is a host acceptance
tool correction; the fixed product checkpoint and app/test hashes remain
unchanged. A single bounded carrier-to-flow entry remains a prerequisite for
the next separately authorized attempt; it has not been certified here.
The final fix/document checkpoint is bound after commit in
`$B/f9-client-delivery-closure.redacted.json`. The unpublished milestone was
consolidated with the F8/F9 preparation checkpoint, while runtime source
`6b2c552` is retained under local recovery reference
`refs/cicada-client/acceptance-snapshots/f9-6b2c552`. No push or merge occurred.

## Remaining acceptance and next coordination

| Gate | Status |
|---|---|
| Fresh F6 fixture setup, independently pinned nine public references and immutable actual Docker identity | **PASS**, verification scope only |
| Fresh F6 emulator boot, frozen APK install and four properties | **PASS**, bootstrap scope only |
| Fresh formal F6 Android matrix/app/UI acceptance | **NOT_RUN** (separate offline-only matrix 49/49 and local UI smoke passed; see above) |
| Phone-owner physical confirmation | **NOT_RUN** |
| Bilateral Link key grant and `NONE` review-policy flow against a fresh Hub | **NOT_RUN** |
| Interop image execution gate and native runtime/recovery | **NOT_RUN** |
| Full Go suite | **NOT_RUN** |
| Physical Android device | **NOT_RUN** |
| Public HTTPS | **NOT_RUN** |
| Model calls | **NOT_RUN** (zero calls in this delivery record) |

The earlier F5 attempt remains historical. This F6 attempt used a real isolated
Hub for read-only identity verification but made no Android Hub RPC. All
encrypted runtime and bilateral acceptance items remain unverified. A further
attempt requires separate Core Root authorization and fresh delivery pins;
this expired nonce must not be reused.

For that separately authorized attempt, complete private-directory creation,
fresh emulator boot, frozen APK installation and four property reads **before**
final Join/READY starts the short coordination window. Keep the Client
coordinator and external signer ready before Root publishes GO. Reuse the
completed offline results without rebuilding or repeating them. Then execute
the six exact external handoffs, with first Target KEY through the actual
React Native one-use Alert, and record encrypted capabilities/current bilateral
status. A safe isolated Link fault driver is separately required for recovery
acceptance; the current `fault=none` carrier cannot establish it.

The final Client checkpoint is bound after commit in
`/gpu1-share/data/cicada-client/v164-dd81575-20261002/client-delivery-closure.redacted.json`.
The original `client-delivery.redacted.json` remains unchanged (SHA-256
`5e2689ee9a9d09da7906c9b0a353dc9a0debe21b2404774bd70255696cb0fabb`)
and binds the earlier `d93afaf4d76594720622d77c0b03773c69c4edf6` checkpoint.
That F7 preparation HEAD is preserved by local recovery reference
`refs/cicada-client/acceptance-snapshots/f6-d93afaf`; the unpublished milestone
was consolidated rather than adding a separate documentation-only commit.
That receipt keeps the running Client HEAD, frozen APK product checkpoint and
final documentation/harness commit distinct. No push or merge is performed.
