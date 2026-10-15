# Release operation-policy public-interface validation

**Date:** 2026-09-30

**Baseline:** Client `329a65942a2e10e5d658cfe58472bb53bad2cb7d`, branch `dev/react-native`.

**Scope:** A bounded instrumentation-only correction and four synthetic policy tests against the existing optimized Release product. No Hub, native Worker, speech, physical-device or public HTTPS acceptance is added.

## Purpose and boundary

The [packaging checkpoint](release-packaging-validation.md) retained a genuine 3/4 policy result: `authenticatedV15CapabilitiesExposeOnlyImplementedOperations` reflected on private method names that R8 changed and failed before its capability assertions. That original APK, source fingerprint, failed command and raw log remain unchanged. This checkpoint replaces the test's private lookup with public session behavior and a synthetic authenticated response fixture. Production code, keep rules, dependencies, protocol pins and deferred operation gates remain unchanged.

The fixed integration context remains clean Hub `bd79ff93c90ecafc28a2471dd9523444903b39e6`, `client-hub-v1.5`, archive SHA-256 `98ce7f02d03dd8291ff7361e46e22ed893f493d242fcb238a948bf869a2a5d0b`, catalog SHA-256 `a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68`, and Hub image `sha256:4c321cd8f91a1e19befabd1f5c8983be46e6aed811614c68bd6f62ad06584771`. No live Hub is used in this checkpoint; current dirty Core is excluded.

## Synthetic fixture design

The positive case starts with an explicitly synthetic enrolled sandbox whose capabilities are not ready and whose allowed-operation list is empty. The device key is generated and wrapped by public `createDeviceIdentity()`; only its returned public identity is used by the test responder. Public `getStatus()` must remain closed before public `rpc("session.capabilities", ...)` receives an authenticated result.

A test-only HTTPS URL handler supplies an in-memory `HttpURLConnection` for the exact fixture URL `https://127.0.0.1:1/v2/client/rpc`. It does not open a socket, resolve DNS, install a TLS trust override or modify production transport. Every other HTTPS host/path is refused, and the fixture accepts only its expected POST while a scoped responder is active. Java's process-wide handler factory cannot be uninstalled; the active responder is cleared in `finally`, and the run is limited to this one test class in a disposable process and emulator.

The responder inspects the actual request route and verifies the device's ML-DSA envelope signature using test-side canonical serialization. Request plaintext decryption is not exposed through the public API and is not claimed by this fixture. A synthetic Control identity generated only in memory seals the response to the device public identity. The reserved response sequence is `10` in this controlled fixture, whose initial last-response sequence is `9`; the fixture does not infer a real Hub sequence.

The production public RPC path checks and decrypts the matching signed response, persists filtered capabilities and clears pending state. Assertions cover manager/external role results, the exact locally implemented operation intersection, request/response counters `12`/`10`, absence of pending and rejection of dedicated or unavailable flows without mutating state. The other three tests continue to check rejection before device/state access, original-pending preservation and rejection of historical capabilities. No private production method is invoked by the replacement positive test.

This is an authenticated synthetic-response policy check, not a Hub implementation test, real enrollment acceptance, TLS handshake test or authorization to use a deferred consent operation. No Owner private key, bearer, model credential or plaintext request content is written to APK assets or command logs.

## Status

| Check | Status |
|---|---|
| Instrumentation-only offline build | PASS; Docker/Gradle exit `0`, command duration 35.988 s |
| Original four unsigned product APK hashes unchanged | PASS; checked before and after the build |
| Four Release operation-policy tests | PASS; `OK (4 tests)`, zero failures, ADB/driver exits `0`, 0.764 s |
| Owned emulator and disposable signing cleanup | PASS; exact container absent, disposable private key/password removed |
| Crypto and STT reruns | NOT_RUN; intentionally outside this checkpoint |
| Live Hub, native Worker, physical Android, public HTTPS | NOT_RUN |
| iOS and native HarmonyOS | NOT_RUN |

## Reproduction and evidence

The immutable build image is `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`. Docker root is `/gpu1-share/data/docker-root`; caches and restricted command receipts are under `/gpu1-share/data/cicada-client`. Build evidence is `/gpu1-share/data/cicada-client/release-policy-public-20260930/evidence/`. Runtime evidence is `/gpu1-share/data/cicada-client/v15-deterministic-release-policy-public-20260930/evidence/`. These directories are restricted to mode `0700`; command receipts and logs use `0600`.

The Gradle invocation requests only `:app:assembleReleaseAndroidTest`, with `-PclientAbiSplits=true`, `-PclientTestBuildType=release`, `--offline` and `--no-daemon`. Its Docker container uses the immutable build image, `--pull=never` and `--network=none`. No product assemble task is requested. Each original product APK is checked against the prior archived SHA-256 before and after this command.

The actual build command is recorded in `instrumentation-only-build.redacted.json`:

```text
docker run --rm --pull=never --network=none --user 1000:1000 -e GRADLE_USER_HOME=/gradle-cache -v /home/zyf/CICADA_CLIENT:/workspace -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules -v /gpu1-share/data/cicada-client/gradle-cache:/gradle-cache -v /gpu1-share/data/cicada-client/android-home:/home/gradle/.android -w /workspace sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 gradle --no-daemon --offline --project-dir /workspace/android -PclientAbiSplits=true -PclientTestBuildType=release :app:assembleReleaseAndroidTest
```

Gradle reports `BUILD SUCCESSFUL in 34s`; the complete command takes 35.988 seconds. The target `:app:minifyReleaseWithR8` remains `UP-TO-DATE`. This is not a new product build or a changed optimization profile. All four original unsigned product hashes match the table in the packaging report.

The x86_64 unsigned product is reused from the prior archive, SHA-256 `78e3538522d54826d391b1e3873499dfecc0eeb2eac5499a0442cec7cec53940`. The previous disposable private signing key was intentionally removed at the packaging checkpoint. For this run, unchanged product payload and new instrumentation are signed with a fresh disposable test certificate; these installed APKs therefore have their own hashes. They are not production-signed artifacts. Signing verification and identical ZIP payloads outside signature metadata are independently checked. The disposable key and password are removed after signing.

The owned Android 15/API 35/x86_64 KVM emulator uses image `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f`, network `none`. The sole approved instrumentation command is:

```text
docker exec cicada-v15-deterministic-release-policy-public-20260930 /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 shell am instrument -w -e class ai.cicada.client.hub.ClientHubV15OperationPolicyTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

The runner checks actual JUnit counts and failures rather than relying on ADB exit alone. Teardown uses the existing ownership-checked `v15-android-deterministic.py` stop action, followed by an independent exact-container absence check. Crypto and STT selectors are not invoked.

## Actual artifacts and source attribution

| Artifact | SHA-256 |
|---|---|
| Unchanged unsigned x86_64 product | `78e3538522d54826d391b1e3873499dfecc0eeb2eac5499a0442cec7cec53940` |
| Installed disposable-signed product copy | `656f218133d74f6d3f95b3fd8aba64754dde4c7a62e02296e09a6b621e155cb5` |
| New instrumentation before this run's signing | `bcfd3fa676fa5cbb71ebc959d0b20b99bc68aad2286698ebdbc90f7d008239ca` |
| Installed disposable-signed instrumentation | `4270a762fe1c62da4917a8f0be2a0988e1ca78671eb8ec2e6d83b05ad1e3937b` |
| Frozen policy test source | `e0ba6b27722d48981b43f49164088b720ca9e28c2f9256cdc089b76cd378938b` |

The signed app copy is 62,955,114 bytes; the signed test APK is 619,972 bytes. Both `apksigner verify` commands exit `0`. ZIP payloads outside `META-INF/` remain identical to each respective original, so the product copy retains the previous optimized code and resources. The new test APK's original development signature is not described as an unsigned product.

The 92-file observed checkout fingerprint for the new instrumentation is `64409378c261e6a1ae6b7327f86a4118d6866e8564ac48cbff018aa50dbcd6da`, built from `329a659` plus the test correction. The reused product retains its original packaging fingerprint `38fb1820bff51f81048f74c50dcae26aa2ef85bd9013c8d51f62b511a95cb2eb`. An additional 60-file product-input fingerprint, excluding `androidTest`, is `25e905b0ef67df24cacdc16ddaf190e2e1edfaae9438ab69ca07041c80ef8e7f`; those committed checkout bytes are unchanged. The new full checkout fingerprint must not be represented as the source of a newly compiled product APK.

The private build/sign helper SHA-256 is `015365fcd066c2031c24b53d3dc69b8a6bac82a53a6e00b2873c6caa3f583451`. `runner-identity.redacted.json` identifies the separate single-selector runtime helper. The completion receipt `release-policy-public-20260930/evidence/delivery-checkpoint.redacted.json` records the eventual local Client commit and verifies its filtered checkout bytes against these source fingerprints. No clean-commit rebuild is claimed.

## Actual commands, results and cleanup

| Command or step | Exit/result | Evidence |
|---|---|---|
| `python3 /gpu1-share/data/cicada-client/release-policy-public-build-20260930.py` | `0`; test-only build, product hash continuity, disposable signing and cleanup pass | build/sign receipts in the build evidence directory |
| Offline Docker/Gradle command above | `0`; 35.988 s | `instrumentation-only-build.redacted.json` and private log |
| Keytool, app/test signing, app/test signature verification | Each `0` | `temporary-keytool.redacted.json`, `temporary-sign-{app,test}.redacted.json`, `signature-verify-{app,test}.redacted.json` |
| `python3 /gpu1-share/data/cicada-client/release-policy-public-runner-20260930.py` | `0`; one class, 4 tests, zero failures, cleanup pass | runtime summary and command receipts |
| Instrumentation selector above | ADB `0`, driver `0`; `OK (4 tests)`, 0.764 s | `release-public-policy.json`, private log and `release-public-policy-summary.redacted.json` |
| `python3 scripts/interop/v15-android-deterministic.py /gpu1-share/data/cicada-client/v15-deterministic-release-policy-public-20260930/evidence stop` | `0`; exact-owned stop/removal | `owned-stop-command.redacted.json` and teardown receipts |
| `docker inspect cicada-v15-deterministic-release-policy-public-20260930` after removal | `1`; expected missing object, absence PASS | `root-cleanup-audit.redacted.json` |

The fresh disposable signing secret was removed immediately after the two APKs were signed; `temporary-signing-cleanup.redacted.json` records its exact-owned scope. The owned emulator was removed after the sole policy selector, and its absence was independently verified. Original packaging artifacts, failed logs, public fixtures and unrelated services remain intact. No Hub fixture, database, resident container or credential file was used.

**Outcome:** the corrected public-interface Release policy test class passes 4/4 against the existing optimized product. The original 3/4 failure remains historical evidence and is not rewritten. This result establishes the bounded local capability and rejection behavior described above; it does not enable a deferred operation or expand live fixed-Hub, TLS, native-session or physical-device acceptance.
