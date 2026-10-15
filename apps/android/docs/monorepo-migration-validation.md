# Android App monorepo migration validation

The Android history from `dev/react-native` at
`d266c5eb1e5b5d95df1d8388dc133dedea8b424f` was imported without squashing into
`apps/android`. The subtree import commit is
`83cb76a735aeea3d26ab711fd3960df4211891f7`; its second parent is the original
Android source. The initial imported tree was byte-identical to that source.
The root migration inventory records recovery and historical refs separately.
The source repository was preserved.

Current product labels use App and Advisor. Android package/application ID
`ai.cicada.client`, React Native registration `CICADAClient`, Native modules,
`Client-Control`, `client-hub-*`, `monitor.*`, signature inputs, keys and
permission checks retain their existing compatibility identities. Display
labels do not grant permissions. Kotlin Android layout selectors were updated
with the changed Advisor labels; their on-device execution remains NOT_RUN.

The source root for reusable interop entrypoints is derived from this file
layout instead of the former sibling checkout. The pinned fixture-carrier
path allowlists, frozen signed preparation paths, contract snapshots and
historical reports retain their old identities. Such historical paths are
not fresh authorization or a claim that an old live fixture can run after
relocation. Reauthorizing a historical fixture requires a new reviewed tuple.

Build helpers continue to use existing external caches under
`/gpu1-share/data/cicada-client`; `CICADA_ANDROID_DATA_DIR` explicitly overrides
that root. New Debug exports default to
`apps/android/build/outputs/cicada-app-android-debug.apk` and
`CICADA_ANDROID_OUTPUT_DIR` can override their directory. The emulator helper
uses the same export selection. No dependency, wire, package ID or key change
is part of this checkpoint.

## Checks on 2026-10-15

Checks used the dirty migration worktree based on the import commit, not a
clean released revision. Docker root was verified as
`/gpu1-share/data/docker-root`. All Docker checks used immutable cached builder
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
`--pull=never --network=none`, the server UID/GID, the Android source mounted
at `/workspace`, and existing Node/Gradle/Android caches. No install, download,
emulator, live Hub or model call was performed.

Commands below run from `/workspace` inside that builder:

| Check | Command | Result |
| --- | --- | --- |
| Contract | `python3 -B scripts/check-client-contract.py` | PASS; v1.6.5, 24 files, catalog digest unchanged |
| Public fixture regressions | `python3 -B scripts/test_check_client_contract.py` | PASS; 11 tests |
| UI authorization and DTOs | `node --test tests/*.test.mjs` | PASS; 98 tests, no failures/skips |
| TypeScript | `./node_modules/.bin/tsc --noEmit` | PASS, exit 0 after correcting an accidental local-variable rename |
| UI lint | `./node_modules/.bin/eslint App.tsx src/components` | PASS, exit 0; 23 existing warnings, zero errors |
| Shell and moved Python syntax | `bash -n` on shell helpers; `ast.parse` on the three moved Python entrypoints | PASS |
| Debug package and instrumentation compile | `gradle --offline --no-daemon --project-dir /workspace/android -PreactNativeArchitectures=arm64-v8a :app:assembleDebug :app:compileDebugAndroidTestKotlin` | PASS; exit 0 |
| APK packaging audit | `python3 -B scripts/audit-android-apk.py build/outputs/cicada-app-android-debug.apk --single-abi --readelf <cached NDK llvm-readelf> --apksigner <cached Android apksigner> --output build/validation/apk-audit.NONAUTH.json` | PASS; exit 0 |
| JVM crypto and policy | Scoped `:app:testDebugUnitTest`, described below | PASS; 38 tests, zero failures/errors/skips |

The first TypeScript attempt failed because a product-label edit also renamed
`syncMonitor` at its declaration. The declaration was restored, and the full
TypeScript and changed-surface lint checks passed. This failed attempt is not
reported as a pass.

The JVM gate ran `gradle --offline --no-daemon --project-dir /workspace/android
-I /out/kotlin-host.init.gradle :app:testDebugUnitTest
-PreactNativeArchitectures=arm64-v8a`, selecting all methods of
`ClientWirePublicVectorTest`, `LinkReviewPolicySigningLifecycleCandidateTest`,
`LinkReviewPolicyEvidenceV164Test`, `LinkReviewPolicyHistoricalResultTest`,
and these three `EndpointAttestationVectorTest` methods:
`completePublishedProofUsesNullSignatureInV1SignedBytes`,
`productionProofVerifierAcceptsVectorAndRejectsChangedBindings`, and
`syntheticGroupManifestChecksRevisionsBindingAndManifestDigests`.
Generated host copies remove the Android runner and load synthetic public
assets from the JVM classpath; cryptographic assertions are unchanged.
One other Android-dependent Endpoint test was deliberately not selected;
its Android execution remains NOT_RUN. This bounded gate does not claim
full Android instrumentation acceptance. The local log is
`build/validation/kotlin.log`; JUnit XML is under
`android/app/build/test-results/testDebugUnitTest`.

The fresh migration Debug APK was copied to the new default export path. Its
SHA-256 is `78b9ddccab198f8d44b6bbe49b8d771cc96bd74cb07b13c45b9c03dd233635cc` (85681771 bytes).
It was built from the dirty migration source; the original import HEAD alone
is insufficient provenance. The local build log and non-authoritative record
are `build/validation/android-build.log` and
`build/validation/android-build.NONAUTH.json`. This APK has not been installed
or exercised against a Hub.

## Artifact and runtime boundaries

The old source's seven ignored APKs and four Gradle output metadata files
were copied as regular private files into the workspace's private artifact
archive. A SHA-256 inventory verifies each preserved APK against the original;
unknown source attribution is left unknown and no runtime result is reassigned.
The existing checksum-pinned Sherpa AAR was copied from the external cache
into ignored `android/app/libs`. Old Gradle/CMake intermediates were not copied.
The exact historical ARM64 trial APK, receipts and SHA-256 remain recorded in
[the original trial delivery](android-arm64-v1.6.5-trial-delivery.md).

Android emulator/device execution, actual native Runtime, physical Android,
public HTTPS, iOS, HarmonyOS, live consent/recovery and new account/canvas
integration are **NOT_RUN** in this migration checkpoint. JVM crypto tests,
TypeScript checks and packaging cannot transfer historical runtime acceptance
to the migrated source.
