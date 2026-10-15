# Client-Control v1.4 validation — clean Hub `f30892f`

**Date:** 2026-09-30

**Branch:** `dev/react-native`

**Delivery:** the single local implementation and validation checkpoint containing this report; no push or merge.

## Scope and provenance

This checkpoint adds independent Hub connections, explicit ACTIVE Network selection, topology v2, Network-scoped Group creation, and independently verified Network key consent. It preserves the Android UI, optional local speech models, encrypted Client-Control transport, exact pending-request recovery, and Monitor consent implementation. Historical v1.2.1 and v1.3 runtime results retain their original source, image and APK attribution.

| Artifact | Independent expected value |
|---|---|
| Clean Hub commit | `f30892fcd79a27bfe5604575deaecebe52c5ec50` |
| Protocol / wire | `client-hub-v1.4` / `1` |
| Protocol archive SHA-256 | `445017efe9085303942892c1bd1eaa2812c708f78389dbc59f906af8f535c324` |
| Catalog SHA-256 | `7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54` |
| Full Hub image ID | `sha256:56956f8a3d50b7e0445eef4017ba7cecff0ced570694cf8d8c3bb964e060aef7` |
| Clean Hub source fingerprint | `76becd7a479dfd801427fc470c376517227f67b293392d4cd7e314f5fa5b6e7c` |
| Imported snapshot | `contracts/client-hub-v1.4-f30892f/` |
| Public Network vector SHA-256 | `198bc89dc6508acfc587f1c8dab21cf650c16d816e448857c00deb6d4fdb112a` |

The archive inventory contains 17 members: a manifest and 16 payloads. Every manifest size and digest matched; payload bytes matched the exact committed Core source. Manifest, complete image metadata and delivery metadata independently matched the clean source, schema 37, catalog and source fingerprint. The catalog contains 36 operations. No current Core working-tree change was imported as this fixed delivery. Core's earlier dirty-source acceptance is separate from the fresh Client checks recorded here.

The tested Client checkout was `b627e7051aaa738ed0736c27f07085e31f4be40a` **plus uncommitted implementation changes**. This report does not attribute the new APK to that clean baseline commit. The final checkpoint contains the tested source; its actual commit ID is recorded separately in the private `delivery-checkpoint.redacted.json` and the completion handoff. All commit identities use the server's global Git configuration directly: `DaiVernon <205618093@qq.com>`.

| Android/build artifact | Actual value |
|---|---|
| Product APK SHA-256 | `abbc2be65bccc1e4e3f2490288949ba587786b9890bbd1b5f2bb74b2feb5c760` |
| Instrumentation APK SHA-256 | `0d7feb3c886072a23da7e9d9a291a0a814ac9955a7445cf91a2c4f7326ece0a3` |
| Compiled source fingerprint | `5e7a72fa5a15c2077f03e1fe8b7bd578bcd8b8f549704522e3cd90b1a507b437` |
| Build image ID | `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` |
| Emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| Emulator | Android 15 / API 35 / x86_64 |
| Docker data root | `/gpu1-share/data/docker-root` |

The fingerprint covers 80 compiled source/configuration files, using sorted relative path, NUL, and the binary SHA-256 of each file. It was captured before the final build and matched the checkout observed at emulator start. Documentation and test-driver changes do not enter this compiled-source fingerprint. Installed APKs were copied into private evidence and checked against the expected hashes.

## Evidence and reproducible commands

Private evidence remains outside Git. Public reports contain hashes, bounded statuses and commands; grants, keys, identities, app data and complete UI dumps are not published.

```bash
D=/gpu1-share/data/cicada-client/v14-development-20260930/evidence
E=/gpu1-share/data/cicada-client/v14-deterministic-final-f30892f-20260930/evidence
B=sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358
C=cicada-v14-deterministic-final-f30892f-20260930
R=v14-f30892f-final-20260930
```

Recorded commands use the actual UID/GID `1000:1000`. Build caches, downloaded dependencies and Android state stay under `/gpu1-share/data/cicada-client`.

```bash
docker run --rm --user 1000:1000 \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v /home/zyf/CICADA_CLIENT:/workspace \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules \
  -v /gpu1-share/data/cicada-client/gradle-cache:/gradle-cache \
  -v /gpu1-share/data/cicada-client/android-home:/home/gradle/.android \
  "$B" gradle --offline --no-daemon --project-dir /workspace/android \
  :app:assembleDebug :app:assembleDebugAndroidTest
```

Final build: **PASS**, exit `0`; `$D/integrated-build-4.redacted.json`. An earlier build failed with exit `1` because an existing STT permission test omitted the new recording session identifier; `$D/integrated-build.redacted.json` preserves that failure. Candidate 2 compiled with exit `0`, but preceded the Hub ID reassignment guard and staged Hub tests; `$D/integrated-build-2.redacted.json` identifies its different APKs. Neither early candidate carries final runtime acceptance. Candidate 3 subsequently passed its own 45 Kotlin checks, offline UI, and three real-Hub stages, but lacked the independent durable Network recovery fence. Its app SHA-256 `953bc94f125b530d6201569fddde6fdf8daccd4c3e2198ff5a494ecbbb12af29`, test SHA-256 `c3dde72c34220d9c62e4dbc0a3517e2dec34b5cc472fc662d61eb51e4be61ff8`, and source fingerprint `773385bf266b6982d5002bad66be9e884d857ace3157af47054e21058edab736` remain separately attributed in `/gpu1-share/data/cicada-client/v14-deterministic-f30892f-20260930T110347Z/evidence/`. Its PASS results were not transferred to candidate 4.

The following checks ran in Docker with `-v /home/zyf/CICADA_CLIENT:/workspace` and, for JavaScript tooling, the same private `node_modules` mount:

| Check | Container command after `"$B"` | Exit / result | Evidence under `$D` |
|---|---|---|---|
| TypeScript | `/workspace/node_modules/.bin/tsc --noEmit` | `0` / **PASS** | `typescript-final.redacted.json` |
| ESLint | `/workspace/node_modules/.bin/eslint App.tsx src/platform/clientHub.ts src/platform/clientHubContract.ts src/platform/hubProfileScope.ts src/platform/networkTopology.ts src/platform/speech.ts src/components` | `0` / **PASS**, inherited warnings retained | `eslint-final.redacted.json` |
| JavaScript helpers | `node --test tests/hubProfileScope.test.mjs tests/networkTopology.test.mjs tests/monitorBroadcast.test.mjs` | `0` / **PASS**, 23 tests | `node-tests-final.redacted.json` |
| Independent contract pins | `python3 scripts/check-client-contract.py --snapshot-dir contracts/client-hub-v1.4-f30892f --source-revision f30892fcd79a27bfe5604575deaecebe52c5ec50 --catalog-sha256 7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54 --contract-revision client-hub-v1.4` | `0` / **PASS** | `contract-check.redacted.json` |
| Contract checker regressions | `python3 scripts/test_check_client_contract.py` | `0` / **PASS**, 9 cases | `contract-checker-regressions.redacted.json` |

Archive/source/image import: **PASS**, exit `0`, `$D/contract-import.redacted.json`. Running disposable Hub provenance is recorded separately in `$D/running-hub-provenance.redacted.json`; image inspection alone does not establish encrypted runtime compatibility.

### Independent Kotlin tests on the final APK

```bash
python3 scripts/interop/v14-android-deterministic.py "$E" start \
  --app-apk android/app/build/outputs/apk/debug/app-debug.apk \
  --app-sha256 abbc2be65bccc1e4e3f2490288949ba587786b9890bbd1b5f2bb74b2feb5c760 \
  --test-apk android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk \
  --test-sha256 0d7feb3c886072a23da7e9d9a291a0a814ac9955a7445cf91a2c4f7326ece0a3
python3 scripts/interop/v14-android-deterministic.py "$E" test
```

Driver exit: `0`. Each selector uses:

```bash
docker exec "$C" /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  shell am instrument -w -e class "ai.cicada.client.hub.<selector>" \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

| Selector | Tests | ADB / driver exit | Result | Evidence under `$E` |
|---|---:|---|---|---|
| `HubProfileStoreTest` | 10 | `0 / 0` | **PASS** | `hub-profiles.json` |
| `NetworkKeyConsentVectorTest` | 6 | `0 / 0` | **PASS** | `network-key-vectors.json` |
| `NetworkSessionGuardTest` | 8 | `0 / 0` | **PASS** | `network-session-guards.json` |
| `ClientWirePublicVectorTest` | 5 | `0 / 0` | **PASS** | `client-wire-vectors.json` |
| `EndpointAttestationVectorTest` | 4 | `0 / 0` | **PASS** | `endpoint-attestation-vectors.json` |
| `MonitorBroadcastVectorTest` | 6 | `0 / 0` | **PASS** | `monitor-broadcast-vectors.json` |
| `ClientHubRecoveryLockTest` | 6 | `0 / 0` | **PASS** | `recovery-locks.json` |

Total: **45 Kotlin tests**; `$E/deterministic-summary.redacted.json`. These checks ran with the emulator container disconnected from external networks. Profile and session guard tests use private synthetic fixtures and loopback protocol responses; they are not acceptance against a real Hub. Public vectors independently exercise decrypt/signature/AAD and tamper rejection, Endpoint claims, Monitor envelope claims and Network consent canonical bytes.

Network tests verify the published vector's exact 14 digest claims independently. Production preview requires the complete 15-field manifest, including the raw native Session locator and independently recomputed public-key fingerprint; the deliberately incomplete published vector is refused as production consent evidence. Both signed Network claim inputs end with `"signature":null` and use their real NUL-terminated domains. Manifest hashing omits the cleared `native_session_id` and retains `"digest":""`; this follows the fixed implementation and vector, despite incomplete wire prose.

Profile checks cover independent identity, trust/session/counter/pending/Monitor storage, legacy adoption, unresolved-profile deletion refusal, a different Hub ID refusal, and stale scope fencing, including A → B → A. No existing keys, ciphertext or Grant are copied into a new Hub profile. This is a local storage/isolation result, not a real two-Hub interoperability claim.

### Actual React Native connection UI

```bash
python3 scripts/interop/v14-android-deterministic.py "$E" ui-smoke
```

**PASS**, driver exit `0`. The fresh, offline product UI showed unconnected/unpinned state, created `OfflineQA` without selecting it, required explicit switch confirmation, and kept both profiles unpinned and unenrolled after selection. Late STT events are independently checked against their originating recording session. Recording, pending voice startup and permission handling fence Hub/Network switching.

Evidence: `$E/ui-smoke-summary.redacted.json` and its four private UI XML references. The flow did not claim a connected Hub, completed task, model inference or approved key grant. This checkpoint did not rerun physical microphone/model performance measurements.

## Disposable fixed-Hub Android interoperability

**PASS for the bounded Android-to-Hub scenario.** Core owns the new disposable Hub, its private Owner signing material and final teardown. The Client only receives authorized public Hub/Owner identities and the exact signed Grant for the Android-generated device. The Client has not read or modified the Hub database.

The Android device preparation selector passed with ADB/driver exit `0/0`:

```bash
docker exec "$C" /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  shell am instrument -w -e run_id "$R" \
  -e class ai.cicada.client.hub.NetworkHubInteropTest#prepareDevice \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

Evidence: `$E/network-prepare-device.json`. The exported private `device-public.json` contains public device keys only. Fixture staging is consumed before enrollment; native recovery retains the original signed attempt if transport fails. No fixture or device Grant is built into the APK.

The two subsequent selectors use the same command, replacing `prepareDevice` with the method below. All three returned `OK (1 test)`, ADB/driver `0/0`:

| Method | Actual checks | Evidence under `$E` |
|---|---|---|
| `prepareDevice` | Fresh profile, independent Android PQ identity, no inherited enrollment/pending | `network-prepare-device.json` |
| `enrollAndVerifyActiveTopology` | Original canonical signed Grant, HTTP 201, independent Hub/Owner pins, encrypted exact v1.4/catalog, authorized role/operation lists, topology v2 ACTIVE Network, explicit persisted selection and old-generation refusal | `network-enroll-topology.json`, `enroll-topology.redacted.json` |
| `createGroupWithinSelectedNetwork` | Fresh topology, encrypted `topology.apply` Group creation with exact Network, authoritative Group/Network association and reread | `network-create-group.json`, `create-group.redacted.json` |

Enrollment and selection finish at `nextSequence=4`; Group pre-read/write/post-read consume request sequences `4/5/6`, ending at `nextSequence=7`, `pending=false`. The complete commands, exits, redacted authority IDs and final APK/source attribution are in `$E/network-real-hub-summary.redacted.json`. Device 1's registration, Grant, keys and counters were preserved while device 2 established its separate session. Public profile IDs, logical device IDs and both full PQ public keys differ; `$E/device-isolation.redacted.json`. These are two devices against **one** Hub, not a real two-Hub test.

Candidate 4 used a fresh Android device/session on the same disposable fixed Hub previously used by candidate 3. The earlier Group remained present: the final run independently created a different Group, changing the authoritative count from `1` to `2`. This was not a reset-to-empty Hub run and did not reuse candidate 3's device Grant or RPC counters.

The new Hub stages use Android instrumentation and the production Kotlin session methods. Offline connection creation/switching exercised the actual React Native UI. Connected React Native Network-card selection, Group-entry screens and positive Owner key-consent dialogs were not separately revalidated; no full connected UI acceptance is inferred from the native selectors.

The external device-Grant signer is a **separate uncommitted Core candidate**, not the clean Hub executable. Its binary SHA-256 is `8a8a60c0306a82d3dcecf10e903c0ba6171a431ac12ca40a407233951206708f`; Core reported `f30892f` as baseline with dirty source, Go `1.27.1`, and no build-start source fingerprint. Its reported `owner_device_sign.go` and `owner_network_key.go` hashes are `d3d89c3f1c5304db08f1f0064fac7840cd79a7f11704cf39c1f9549a9c23f481` and `2437808adb3c2fd2b0fc763774a17dc3d10a39df80c8b3c599bc2c77e8267907`. The tool signs offline and never opens the fixed schema-37 Hub database. This provenance does not qualify it as a released Network signer.

## Current acceptance boundaries

| Requirement | Status | Limit / next gate |
|---|---|---|
| Package, clean source, catalog and full image metadata | **PASS** | Independent exact pins and bytes; not inherited Core acceptance. |
| Final APK build and independent Kotlin crypto tests | **PASS** | Emulator artifacts and source fingerprint above. |
| Independent profiles and captured Hub/Network scopes | **PASS** | Deterministic native/JS checks and actual offline connection UI. |
| Real fixed-Hub enrollment, encrypted capabilities, ACTIVE topology | **PASS** | Final APK, new device/session, ADB/driver `0/0`; original Grant bytes and explicit scope preserved. |
| Real fixed-Hub Network-scoped Group creation | **PASS** | Final APK, ADB/driver `0/0`; fresh authoritative Network association and pending-free sequence `7`. |
| Real complete Network manifest → external Owner proof → phone confirmation → grant/status | **BLOCKED** | No complete frozen native Endpoint/Owner-consent fixture; separate dirty signer provenance does not certify the full chain. |
| Durable Network uncertainty fence | **PASS** | Actual cryptographic synthetic responses and restart guards; no HTTP/Hub fault claim. |
| Automatic dedicated Network grant reconciliation | **BLOCKED** | Client must correlate original proof/scope with authoritative key status; current fence stays closed. |
| Real Network stale/expired/wrong-Owner/wrong-Endpoint/tamper rejection | **NOT_RUN** | Kotlin synthetic rejection checks passed; no real complete Network grant exists in this run. |
| Real response-loss and three recovery faults on this Hub image | **NOT_RUN** | Local packet/uncertainty guards passed; older fixed-image fault results remain historical. |
| Current-version real Node/Codex approvals and Goal result | **NOT_RUN** | No native Worker was started for this checkpoint. |
| Current-version native Monitor/Network peer delivery | **NOT_RUN** | Preserved Monitor implementation and vector tests do not establish new native delivery. |
| Physical Android / public HTTPS | **NOT_RUN / NOT_RUN** | No hardware or public deployment acceptance. |
| iOS / native HarmonyOS | **NOT_RUN / NOT_RUN** | No platform implementation or validation claim. |

The fixed contract advertises `external_thread_links=false` and `status_events=false`; ordinary cross-user message sending and unsupported push status remain disabled. Network key consent alone does not enable peer messaging. Group binding revisions cannot substitute for Network direct bindings. The phone holds only the independently pinned Owner public identity; Owner private signing remains external.

Every Network operation requires both public and encrypted operation allowlists, the exact v1.4 pins, native support, current profile/generation, selected Network and authenticated Owner. Preview, proof review and grant use dedicated native methods and require fresh ACTIVE topology and complete manifest; generic RPC cannot bypass verification. A fresh encrypted capability/topology/manifest preflight precedes sealing a grant. Status refreshes capability authorization and checks authenticated grant metadata without requiring the Endpoint to remain present in current topology, so stale grants can be read. Expired, mismatched or changed proof/digest rejects before grant submission.

Generic packet recovery is transport verification, not a verified Network consent preview. The final candidate adds an independent durable Network grant fence retaining the first original signed ciphertext, operation ID and sequences. A successful generic snapshot, another uncertain read, session reconstruction or profile switch cannot clear or overwrite it. Grant, identity replacement, re-enrollment, changed pin and profile deletion refuse before new I/O or counters. Read-only key status remains available. The extended Kotlin regression feeds actual cryptographic synthetic packets into production `finishResponse` by reflection, **without HTTP**; it verifies automatic lock creation, two snapshots, a later uncertain read, restart, byte preservation, migration and damaged-state rejection. This is not real Hub fault acceptance.

Automatic dedicated Network grant reconciliation is **not implemented**. Only a future independently verified correlation of the original Network/Endpoint/Owner/proof digest/nonce with authoritative `network.key_status` may release the lock; ordinary reads never do so today. Legacy surviving retired Network packets are conservatively fenced, including `AUTH_RESET`, and may remain locked even if no grant ran. A packet already overwritten by an older build cannot be reconstructed. Real Network recovery faults remain **NOT_RUN**.

## Teardown and next delivery

**PASS:** both Client-owned emulators, their transparent forwarders and ADB reverse mappings were removed; both private host fixture adapters were deleted. Reverse removal/check and container stop each exited `0`; final independent `docker inspect --format` returned `1` with the specific missing-object diagnostic for each owned container. See `$E/combined-owned-teardown.redacted.json` and the final Hub summary.

Two cleanup wrappers initially returned `1`: the first expected a differently capitalized missing-object message; the second checked Docker's asynchronous `--rm` removal too early. Both diagnostic failures remain in `owned-cleanup-wrapper-attempt1.redacted.json` and `owned-cleanup-wrapper-attempt2.redacted.json`. The driver now waits at most ten seconds only while inspection succeeds; unexpected inspection errors fail immediately. Neither failure repeated a Hub request, device registration or container stop. Final independent absence checks passed.

**PASS:** Core subsequently ran `scripts/client-network-fixture.sh cleanup /tmp/cn.5MHz3yiC`, exit `0`. Core's redacted record is `/home/zyf/CICADA/.cicada-data/client-f308-device2-20260930/cleanup.json`; the Client independently confirmed the owned Hub container, Docker network and fixture directory absent. `$D/core-cleanup.redacted.json` records those commands, expected missing-object exit `1`, operator and source evidence hash. Core removed its ephemeral private key, Grants and signer; the Client did not modify Core or its database. No resident Hub, production deployment or global Docker/Git configuration was modified.

Core should deliver a separately pinned external Network key signer, complete production-shape public vectors, corrected digest prose and safe ACTIVE Network/native Endpoint fixture. Then validate real consent, explicit phone approval, authoritative status and rejection/recovery states as a new bounded run. See [the Core handoff](cicada-core-handoff.md) for the review prompt. Do not use a fabricated native Thread, unsigned proof, guessed wire field, changed fixed contract or historical APK to satisfy these gates.
