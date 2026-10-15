# Android local Release packaging validation

**Date:** 2026-09-30

**Baseline:** Client `feb0cd2ffb5932cf5a009c55114bb6e7e03c0264`, branch `dev/react-native`.

**Scope:** Local unsigned APK packaging and bounded offline runtime verification. No store release or live Hub acceptance. The fixed v1.5 Hub delivery remains unchanged; current dirty Core work and an unfrozen v1.6 are excluded.

**Subsequent test-only correction:** [Release public-interface policy validation](release-policy-public-validation.md) replaces the private-reflection test and passes its four policy tests against this same optimized product payload. It has separately identified instrumentation, signing and source evidence. The original 3/4 result below remains unchanged; the later test result does not transfer to the original test APK or extend Hub acceptance.

## Configuration and provenance

The release helper requires a complete immutable Docker image ID and uses the existing locked dependencies. The tested toolchain image is `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`. Docker data remains under `/gpu1-share/data/docker-root`; caches and restricted evidence remain under `/gpu1-share/data/cicada-client`.

`scripts/docker-build-release.sh` selects `clientAbiSplits=true` and builds one standalone APK for each existing ABI: `arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64`. This opt-in profile emits no universal APK. Default debug builds retain their existing universal APK path. The split APKs keep the existing `0.1.0-dev` metadata; this profile does not implement store versioning or publishing. R8 and resource shrinking apply to Release; no release signing configuration or native ZIP-compression override is added. The `--android-test` option selects `clientTestBuildType=release` and builds instrumentation for that target.

The normal Android Gradle Plugin native stripping path is retained. JNA/Vosk dynamic registration names are kept. Sherpa's JNI wrapper and configuration namespace is kept because the imported AAR contains no consumer rules for that surface. React Native and Gson retain their supplied consumer rules; the Bouncy Castle PQC APIs are statically referenced. These choices follow the Android guidance for [ABI APK outputs](https://developer.android.com/build/configure-apk-splits) and [JNI/reflection keep rules](https://developer.android.com/topic/performance/app-optimization/keep-rule-examples).

The exact `androidx.tracing.Trace` facade is also kept: AndroidX Test references it as a shared target dependency, but Release R8 initially removed it. The actual crash and DEX class definitions establish this requirement. Finite Kotlin runtime names/members and exact application/Gson/Kotlin APIs used by the selected instrumentation bytecode are kept. Kotlin multifile-facade ancestor methods require explicit rules; thirteen finite Kotlin package names are preserved to keep package-private inheritance legal after obfuscation. These package-name rules do not retain all classes or members. No blanket `kotlin.**`, `com.google.gson.**` or `ai.cicada.client.**` class keep, optimizer bypass or dependency/version change is added.

The initial mapped-APK reference trace emitted 123 lines; its incomplete diagnostics are recorded without calling it whole-program validation. The final selected trace uses ten original pre-R8 class files: three selected test classes and seven compiler helpers. It emits 214 lines with 46 exact keep directives plus one scoped package-name directive. App bytecode, Gson 2.14.0 and Kotlin stdlib 2.2.10 are explicit targets. The existing AGP-bundled R8 tool exits `1` because Android framework, JUnit/AndroidX and Sherpa definitions are outside these targets; complete output/error logs and exact archive hashes are retained in `release-selected-trace-derivation.redacted.json`. This is a targeted derivation, not a passing complete-program check. The purpose and limitation of this approach are documented by [Keeper's maintainers](https://slackhq.github.io/keeper/); no Keeper plugin or new build dependency is installed.

The unsigned APKs are local development artifacts with the existing version metadata. Installed test copies use a disposable local test certificate; those copies and the instrumentation APK are separately identified. No production signing key, Hub/Node bearer or model credential is used. All ten deferred protocol operations and three Link key operations remain closed. This checkpoint does not change the pinned Hub contract or expand the previous live acceptance.

## Baseline measurement

The archived four-ABI Debug APK has SHA-256 `2ecb5d25f193b1b59c574b51c6383bf4d19617f028ce3b4a926a070113657758` and size **296,177,563 bytes**. Each ABI contains 17 native libraries, including the existing Sherpa, ONNX Runtime, Vosk, JNA and React Native dependencies. The libraries are stored without ZIP compression. Official NDK `llvm-readelf` inspection found no `.debug_*` sections or full `.symtab` in any of its 68 libraries; all retained dynamic symbol tables. Native stripping is therefore already present in this baseline and cannot be claimed as a new size saving.

| Baseline ABI | Uncompressed native bytes |
|---|---:|
| `arm64-v8a` | 74,455,872 |
| `armeabi-v7a` | 50,811,200 |
| `x86` | 80,270,156 |
| `x86_64` | 78,407,064 |

APK byte counts measure the file itself. Native and DEX byte counts describe ZIP payloads; none is an installed-footprint or model-storage measurement. Model weights remain optional external downloads and are absent from the product APK.

## Validation status

| Gate | Status |
|---|---|
| Baseline APK/ELF audit | PASS; Docker exit `0` |
| Four unsigned per-ABI Release APKs | PASS; offline Docker/Gradle exit `0` |
| Native-library retention and stripping audit | PASS; exact ABI mapping, required STT/RN libraries, stripped ELF and unsigned checks |
| Offline Kotlin public crypto vectors on final Release | PASS; 5/5, ADB/driver exits `0`, 0.900 seconds |
| Release operation-policy instrumentation | FAIL; 3/4 pass, one private-reflection lookup fails; ADB `0`, driver `1` |
| Supported x86_64 native/STT smoke | PASS after fixture-only correction on the same APK; 1/1, ADB/driver exits `0`, 3.210 seconds |
| Offline MainActivity startup | PASS before selectors and after STT; ActivityManager and process checks exit `0` |
| Disposable test key and owned-emulator cleanup | PASS; exact-owned container absent and disposable private signing files removed |
| ARM/x86 runtime and physical Android | NOT_RUN |
| Public HTTPS and live Hub | NOT_RUN |
| iOS and native HarmonyOS | NOT_RUN |

Evidence is under `/gpu1-share/data/cicada-client/release-packaging-20260930/evidence/`, with directory mode `0700` and records/logs mode `0600`. Exact build commands and exit codes are recorded individually. The first offline build failed because the matching AGP Lint artifact was absent from cache; its failed receipt is retained. A cache-prime attempt also failed because its temporary init script applied to an included Gradle plugin build without an `:app` project. The corrected prime explicitly checks that project before resolving dependencies. These preparation failures are distinct from a completed Release build or runtime result.

## Measured Release artifacts

The delivered packaging candidate used Client `feb0cd2` plus the complete compatibility and package-access fixes. Offline build `6` completed in 56 seconds with exit `0`, including R8, resource shrinking and normal Lint gates. Its 92-file compiled-source fingerprint was `38fb1820bff51f81048f74c50dcae26aa2ef85bd9013c8d51f62b511a95cb2eb` before and after the build. This identifies the tested checkout bytes, not a clean-commit build. The milestone commit is identified separately in the external completion receipt; the checked-in source must match this fingerprint.

| ABI | APK bytes | SHA-256 |
|---|---:|---|
| `armeabi-v7a` | 43,347,420 | `b1618f625e446800d93df00606c22f633eaf19ce5b65c38f9a555fb916d81da6` |
| `arm64-v8a` | 58,052,430 | `aa35dcecf44e7a84996dbc485e283e684cba8adb4e62c37503d679d570e71205` |
| `x86_64` | 62,915,835 | `78e3538522d54826d391b1e3873499dfecc0eeb2eac5499a0442cec7cec53940` |
| `x86` | 64,731,304 | `ce6ed80e6e2ff1d7f5f17ba847c6e95470692df6f378d5559b94f7ebee9da8ec` |

Each unsigned original contains exactly its declared ABI and 17 native libraries, with no `.debug_*` sections or full `.symtab`; dynamic symbol tables remain. The original model, test-vector and known environment filename checks pass. DEX payload totals are **3,045,088 bytes** per APK, compared with **21,627,668 bytes** in the archived four-ABI Debug APK. The comparison combines ABI selection, native Release variants and managed-code optimization; it is not an isolated R8-only saving or an installed-size measurement. The ARM64 APK is 80.40% smaller than that four-ABI Debug file.

The official `apksigner` rejects each original as unsigned; the audit also checks absent JAR signature entries and APK signing-block markers. Exact inventories and checks are `release-apk-audit-access-fixed.redacted.json`, `release-apk-audit-access-fixed-command.redacted.json` and `release-artifact-gates-access-fixed.redacted.json`. Output filenames are `android/app/build/outputs/apk/release/app-<abi>-release-unsigned.apk`. All five original outputs, including instrumentation, are archived under `access-fixed-release-artifacts/` with their own receipt.

The disposable signed app copy SHA-256 is `07d0e8bbe00c5e4488a3f19f65a20537091b3513a80a89dceef18dad49e0f41c` (62,955,114 bytes). The disposable signed test copy SHA-256 is `d46634bad52d9ddb2d977709a4607be886deb04f2c074249f1dc23cbb85f4e38` (615,876 bytes). Both pass signature verification with exit `0`, and every ZIP entry outside `META-INF/` has identical payload bytes before and after signing. The original four delivery APKs remain unsigned and untouched. The instrumentation original may carry AGP's development signature and is not represented as an unsigned product. Certificate and exact command evidence is `temporary-signed-artifacts-access-fixed.redacted.json` and `temporary-signing-commands-access-fixed.private.json`.

## Retained failed attempts

Each failed stage has its own command receipt and private log. It is not counted as a successful runtime check.

| Stage | Actual exit/result | Evidence |
|---|---|---|
| Initial offline build | `1`; missing cached AGP Lint dependency | `build-1.redacted.json` and private log |
| First dependency-cache prime | `1`; init script applied to a plugin build without `:app` | `dependency-cache-prime-1.redacted.json` |
| Corrected cache prime | `0`; resolves existing pinned Lint configuration only | `dependency-cache-prime-2.redacted.json` |
| Initial disposable signing | `2`; password-file reader reached EOF on the repeated key-password argument | `temporary-signing-commands.private.json` |
| Corrected disposable signing | `0`; PKCS12 keystore password supplies the key password | `temporary-signing-commands-2.private.json` |
| Initial runtime helper | `1` before selectors; missing host fixture arguments | initial runtime `release-runner-attempt-1.redacted.json` |
| Three initial instrumentation selectors | ADB `0`, driver `1`; runner crashed before discovery, no JUnit counts | initial runtime selector JSON/logs and `selector-execution-counts.redacted.json` |
| Corrected Release rebuild | `0`, 55 seconds; no compiled-source change during build | `build-3.redacted.json` and private log |

The initial runtime directory is `/gpu1-share/data/cicada-client/v15-deterministic-release-packaging-20260930/evidence/`. Its `instrumentation-crash-buffer.private.log` shows `NoClassDefFoundError: androidx.tracing.Trace` in `AndroidJUnitRunner.onCreate`. The instrumentation DEX refers to the facade but has no class definition; the target R8 usage and DEX confirm its removal. The exact facade keep fixes this concrete classpath requirement. Initial DEX payload totaled 2,767,460 bytes; after correction it totals 2,769,076 bytes. The per-ABI APK byte counts remained unchanged; APK totals also include packaging alignment.

The first corrected-Trace retry also failed before JUnit: `kotlin.LazyKt` was removed from the shared target runtime. Only the first five-test selector was attempted (ADB `0`, driver `1`, no JUnit report); the remaining four policy tests and one STT test were **NOT_RUN**. Its bounded crash log and command receipts are retained in `/gpu1-share/data/cicada-client/v15-deterministic-release-packaging-retry-20260930/evidence/`; its owned emulator was removed. The Trace-only APK hashes and R8 outputs are retained separately and will not be counted as the final runtime acceptance.

The original compiled-source fingerprint is `ff592e3df12f5118b51410882ea7b572ccb572bc7c517178d84067541d694cef`. Its unsigned x86_64 APK SHA-256 is `4760636acec25d6f4c1a90c2351838e799b71eb517bea196f6f3e71cfc40ec38`; its installed disposable copy SHA-256 is `4a39c9492dc89882de6641c59b02967055906d2583480b7d98335ce6d0d3a439`. These are the failed-run artifacts, not the corrected artifacts in the table. All five initial outputs were archived before the rebuild under `initial-release-artifacts/`; all five corrected original outputs are under `final-release-artifacts/`, each with a separate SHA receipt. The initial signed copies and runtime evidence remain separately identified. The initial emulator was removed and confirmed absent.

The next finite-Kotlin-ABI candidate (source `de6283341fb15554fec6a3fe8062a87529e1e3980f6864c8de12536605f93d3e`) successfully started JUnit. `ClientWirePublicVectorTest` actually ran five tests and failed five: four failed to resolve `com.google.gson.JsonParser`, and one failed to resolve Kotlin byte-array `joinToString$default`. The runner's success-only parser left its summary JUnit field empty; `final-selector-junit.redacted.json` records the actual failed-run counts from the raw log. The remaining four policy tests and one STT test were NOT_RUN. This failed candidate's separate runtime evidence is `/gpu1-share/data/cicada-client/v15-deterministic-release-packaging-final-20260930/evidence/`; the owned emulator was removed.

The selected-source candidate from build `5` (fingerprint `08bc0c2e0cecff27f2887f9b47ba5908c0bdf2b85be87cd156790eba4bbcc394`) failed before any selector. ActivityManager returned `Status: ok`, but the process check exited `1`. The bounded crash showed an `IllegalAccessError`: a repackaged class extended the package-private `kotlin.collections.CollectionsKt__IterablesKt`. This is a production startup failure, not an instrumentation PASS. Its runtime evidence is `/gpu1-share/data/cicada-client/v15-deterministic-release-packaging-verified-20260930/evidence/`; its APKs, R8 maps and cleanup receipts remain separate.

## Bounded speech verification

The single new `ReleaseSttNativeSmokeTest` requires a nondebuggable target. It validates externally staged Paraformer model/tokens and public audio against exact catalog size and SHA-256 pins, invokes a Vosk/JNA native binding through the target classloader, and performs real Sherpa Paraformer inference on 16 kHz mono PCM16 audio. It requires nonempty output containing the historical public-sample token `研究` and prints no transcript. The Vosk call verifies linkage only; it does not establish Vosk transcription.

The existing public sample B has no manually verified complete transcript. The Paraformer model card identifies ModelScope provenance but lacks license metadata; the model's source terms remain unresolved as recorded in [model selection](model-selection.md). This test uses the existing local external fixture and makes no redistribution or license claim. It does not validate microphone quality, thermal behavior, installation/download UI or other models.

On the final APK, the first STT attempt ran one test and failed before inference: its model and token files were beneath a shell-owned child directory with mode `2770`. The app-owned fixture root was accessible, but the app could not traverse that child. The authorized single retry placed the same hash-verified public model and tokens directly in the app-owned root. No APK, permission policy, model bytes or test assertion changed. The retry passed `OK (1 test)` in **3.210 seconds**, including real Paraformer inference and the Vosk native binding check. This is end-to-end test duration, including setup and model loading, not isolated inference latency.

| External fixture | Bytes | SHA-256 |
|---|---:|---|
| Paraformer INT8 model | 81,828,675 | `3ef6c19369b912f7caf3cef8e545c5ccd1a33d9d7ec792a46668dc41c4b229ec` |
| Paraformer tokens | 75,352 | `4b2d964e18b9cf139b473003b6698fb2ed9a2a5ec55b93daa677b28f578897aa` |
| Public Chinese sample B | 179,712 | `1a6bf94091d9c35e11aea5d494d05e3287b8f5c767f6de3bfd796d91b637500c` |

## Runtime commands and cleanup

The delivered candidate runtime uses a fresh owned Android 15 / API 35 / x86_64 KVM emulator, image `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f`. Its Docker network is `none`. The delivered candidate runtime evidence directory is `/gpu1-share/data/cicada-client/v15-deterministic-release-packaging-access-fixed-20260930/evidence/`. The retained private runner delegates ownership checks and teardown to `scripts/interop/v15-android-deterministic.py`; its recorded execution hash identifies the local fixture driver. There is no Hub fixture, model-service request or downloaded dependency during the run.

The selected instrumentation commands use this exact ADB prefix:

```text
docker exec cicada-v15-deterministic-release-packaging-access-fixed-20260930 /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640
```

The initial three selector commands were:

```text
shell am instrument -w -e class ai.cicada.client.hub.ClientWirePublicVectorTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
shell am instrument -w -e class ai.cicada.client.hub.ClientHubV15OperationPolicyTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
shell am instrument -w -e class ai.cicada.client.ReleaseSttNativeSmokeTest#paraformerRecognizesPinnedPublicSampleAndVoskNativeBindingIsAvailable -e stt_model_path paraformer-zh-small/model.int8.onnx -e stt_tokens_path paraformer-zh-small/tokens.txt -e stt_sample_path zh-0.wav ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

Only the public fixtures in the table are staged, after size/hash validation, beneath `/sdcard/Android/data/ai.cicada.client/files/packaging-fixture/`. The instrumentation APK contains no native `.so` entries, so successful JNI/JNA calls exercise the optimized product libraries. The two APKs must be signed with the same disposable certificate before installation; the original delivery APKs remain unsigned. ADB exit `0` is insufficient: the driver requires the exact JUnit count and rejects crashes, failures or unexpected selectors.

The one authorized STT-only retry used the same ADB prefix and installed APKs:

```text
shell am instrument -w -e class ai.cicada.client.ReleaseSttNativeSmokeTest#paraformerRecognizesPinnedPublicSampleAndVoskNativeBindingIsAvailable -e stt_model_path model.int8.onnx -e stt_tokens_path tokens.txt -e stt_sample_path zh-0.wav ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

| Final-APK command | Tests run / failures | ADB / driver exits | Duration | Evidence |
|---|---|---|---:|---|
| Public vector selector | 5 / 0 | `0` / `0` | 0.900 s | `client-wire-vectors.json` and private log |
| Operation-policy selector | 4 / 1 | `0` / `1` | 0.685 s | `v15-operation-policy.json`, private log and `access-fixed-junit-summary.redacted.json` |
| Initial STT selector | 1 / 1 | `0` / `1` | 0.536 s | `release-stt-native-smoke.json` and private log |
| STT root-directory retry | 1 / 0 | `0` / `0` | 3.210 s | `release-stt-native-smoke-root-retry.json` and `stt-root-retry-result.redacted.json` |
| Post-retry `shell am start -W -n ai.cicada.client/com.cicadaclient.MainActivity` | Not JUnit | `0` / `0` | 0.656 s | `offline-main-after-stt-root-retry-start.json` |
| Post-retry `shell pidof ai.cicada.client` | Not JUnit | `0` / `0` | 0.144 s | `offline-main-after-stt-root-retry-pid.json` |

The policy failure is `authenticatedV15CapabilitiesExposeOnlyImplementedOperations`: its helper looks up private production methods by their original names and fails with `NoSuchElementException` after minification. It does not reach its capability-acceptance assertions. The other three tests verify rejection before key/state access, preservation of original pending requests and rejection of historical capabilities through the public session API. No further keep rule or production test hook was added for this failure. The next policy-test change should exercise public behavior with a suitable fixture rather than depend on private method names. This checkpoint does **not** claim 4/4 policy acceptance or live encrypted capabilities verification for the Release APK.

The driver initially leaves failed-run JUnit summary fields empty; the preserved raw logs and `access-fixed-junit-summary.redacted.json` supply the actual counts. The private wrapper also compared the STT retry's singular `OK (1 test)` with plural `OK (1 tests)` and reported a wrapper mismatch. The raw JUnit output and driver record both show the retry passed with exit `0`; this discrepancy remains recorded separately. Across all four final-APK selectors, eleven tests ran with two failures; the successful STT retry does not erase the first failed attempt.

Fixture copy commands, exact ownership/modes and device SHA-256 results are retained in `stt-root-retry-fixture.redacted.json` and its referenced command logs. The private runner SHA-256 is `458f049cdddb81ad456a2685975f78e983013244964f9bea396d17dc4d5bfa1e`. Both APK hashes and the 92-file source fingerprint match the final build. No crypto selector was repeated for the fixture correction.

Owned teardown ran `docker stop --time 10 cicada-v15-deterministic-release-packaging-access-fixed-20260930` with exit `0`; the automatic-removal container was subsequently absent (`docker inspect` exit `1`, expected `No such object`). The agent and root independently verified absence. Root removed only the two exact-owned disposable signing files and their restricted directory; no production or global development key was removed. `access-fixed-cleanup-audit.redacted.json` in the runtime directory and `owned-cleanup-final.redacted.json` in the packaging directory record cleanup. Public fixtures, caches, unsigned APKs and every failed-run receipt remain available. No resident Hub or Core fixture was used.

## Reproduction

After preparing the documented development image and caches:

```bash
./scripts/docker-build-release.sh \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  --android-test
```

The helper uses network-disabled Docker and offline Gradle. Any missing fixed build dependency must be resolved into the development cache before rerunning; no lint or optimizer gate is disabled by the helper. Product artifact inspection uses `scripts/audit-android-apk.py` with the pinned Android `apksigner` and NDK `llvm-readelf`, recording actual APK size, SHA-256, ABI/library inventories, ELF sections and signature-tool output. A bounded filename check is not a universal proof of absence of secrets.
