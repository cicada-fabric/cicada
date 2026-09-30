# Shared-space v2 Client framework

**Date:** 2026-09-30
**Baseline:** Client `eb0db6f3d095b60b0f2f73bcfda0079ba33ad846`, branch `dev/react-native`.
**Scope:** Local review UI and independent proof verification. Positive v2 RPC operations remain disabled.

## Relationship to the fixed v1.5 delivery

The [fixed v1.5 validation](client-hub-v1.5-bd79ff9-validation.md) remains attributed to its original APKs, source fingerprint, clean Core `bd79ff93c90ecafc28a2471dd9523444903b39e6`, contract and immutable Hub image. This subsequent framework work does not extend those live results or replace that contract snapshot.

The public candidate vector at `CICADA/cicada-go/internal/e2ee/testdata/cross-owner-group-key-v2.json` is from ongoing Core development. Its observed SHA-256 is `0cc1f40baf754870f36da1ba0a28be9b60036186ef1c02ed2aa6de64d29d778c`. It contains synthetic public identities and proofs. It is test input, not an independently trusted Owner identity, a pinned contract release, a native-session fixture, or production authorization. The source observation is recorded in `/gpu1-share/data/cicada-client/v2-framework-20260930/evidence/candidate-source-observation.redacted.json`.

## Canonicalization is specific to each proof type

| Proof | Signed input |
|---|---|
| Endpoint self-attestation v1 | `cicada/fabric/endpoint-key-attestation/v1` plus NUL and the ordered public claims, including the final `"signature":null` field. |
| OwnerLinkKeyGrant v2 | `cicada/communication-link/owner-key-grant/v2` plus NUL and exactly ten ordered claims: `version,owner_id,link_id,contract_digest,key_binding_digest,expected_link_version,side,issued_at,expires_at,nonce`. There is no `signature` key in these signed claims. The carried proof separately contains its signature. |
| Cross-Owner binding v2 | The exact v2 binding DTO under `cicada/group/cross-owner-key-binding/v2` plus NUL. A v1 binding cannot substitute for it. |
| Cross-Owner manifest v2 | The exact complete v2 DTO under `cicada/group/cross-owner-key-manifest/v2` plus NUL, including `candidate_attestation` and the final empty `digest` value. This differs from the historical Group v1 digest. |

Endpoint Owner business role `ENDPOINT` corresponds to signed side `SOURCE`; Group Owner business role `GROUP` corresponds to `TARGET`. Both independent proofs must bind the same exact manifest and candidate binding. A self-signature proves Endpoint key possession; it does not grant User approval or prove current authority.

## Review and authority boundaries

The review framework uses the selected Hub profile, selection generation, Hub, authenticated Owner, device/session epoch and ACTIVE Network/version. Group version, Endpoint Owner/binding/epoch and topology observation time also bind each local review and callback token. Transient reviews are invalidated when that scope changes; stale callbacks cannot repopulate them. Only the current authenticated topology projection may supply displayed Group/Endpoint metadata. A missing foreign scope is unavailable, rather than synthesized from another Owner's data.

Group admission grants a restricted Membership. It does not join a native Endpoint. The Endpoint Owner separately acknowledges the exact shared-context risk, and the Node must perform a fresh trusted native Join and publish its candidate before the manifest/key proof stages. Neither step silently grants history. Each Owner later reviews and signs its own exact side and confirms through its own Client; requiring both proofs before the first Owner can submit would create a circular workflow. Complete dual-proof status is a later verification step. A Monitor proposal is a proposal; a time-limited, single-use delegation is a separate User decision bound to exact scope and versions.

The product panel is collapsed by default. Its optional reading marker means only that the user reviewed a local scope, never signature, approval, admission, Join or submission. Proposal/delegation UI currently provides a blocked semantic overview; there is no typed proposal review, fetch, issue or revoke path. No fixture is displayed in the product UI. Lists are explicitly bounded and cannot be treated as a complete directory.

Both full Owner public identities must come from independent trust established outside the candidate manifest. The verifier requires explicit expected identities, bindings, revisions, grants and validity periods, verifies full ML-DSA signatures and recomputes proof, binding and manifest digests. Candidate JSON, a Hub-supplied digest or a locally reviewed form cannot establish current authority by itself.

`CrossOwnerGroupKeyV2Verifier` checks a complete dual-proof status against an explicit authority context; it does not implement the first Owner's manifest preview or signing-confirmation flow. Its accepted lifetime is the minimum of manifest and both Owner-proof expiries. Parsing rejects malformed UTF-8, duplicate fields, non-RFC JSON, incorrect typed objects, noncanonical numbers/base64, excessive nesting/items and integer overflow. Context revisions currently use positive signed 64-bit values; larger wire values are refused rather than approximated. No verifier result is exposed as an RPC authorization token or connected to a production bridge.

A separate read-only security review found no concrete blocker in these checks. The tests construct the complete status wrapper from the public vector's components and use the explicit synthetic clock `2026-09-30T12:05:00Z`; they do not consume a live status or establish present-time Owner authority. The vector's canonical strings are ASCII, so HTML and non-ASCII escaping branches are not directly exercised by this vector.

No Owner private key, Node/Hub bearer, native device code or model credential belongs in the phone review model, test asset, Git, APK or logs. The candidate asset belongs to instrumentation tests only. The framework adds no Hub request or production signing path and does not change the existing exact-pending or durable Network reconciliation fences.

## Validation status

The local framework build, requested emulator checks and cleanup passed. No live v2 authority acceptance is claimed.

| Gate | Status |
|---|---|
| Independent candidate Kotlin proof tests | PASS, exact `OK (9 tests)`; ADB and driver exits `0` |
| Native v1.5 operation-policy gate | PASS, exact `OK (4 tests)`; ADB and driver exits `0` |
| Pure scope/review model and existing operation/profile/topology tests | PASS, 22 tests; Docker exit `0` |
| Full TypeScript compile | PASS, Docker exit `0` |
| ESLint for App and the new model/panel | PASS, exit `0`; 21 existing App warnings, no new-file warnings |
| Android debug and instrumentation build | PASS, Docker exit `0` |
| Actual gated product UI on an offline emulator | PASS, collapsed and expanded unavailable states; driver exit `0` |
| Connected Group/Endpoint scope selection in the new product panel | NOT_RUN; pure scope and callback tests are separate |
| Owned disposable emulator cleanup | PASS, stop exit `0`; subsequent exact-name inspection exits `1` because the container is absent |
| Positive v2 RPC, dual-Owner authorization and native authority fixture | BLOCKED pending a new clean pinned Core delivery |
| Physical Android and public HTTPS | NOT_RUN |

The JavaScript gate used the immutable Docker build image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` with `--network=none` and the existing locked dependencies. Its command was `node --experimental-strip-types --test tests/sharedSpaceConsent.test.mjs tests/clientHubOperationPolicy.test.mjs tests/hubProfileScope.test.mjs tests/networkTopology.test.mjs`. TypeScript ran `./node_modules/.bin/tsc --noEmit`; ESLint ran on `App.tsx`, `src/platform/sharedSpaceConsent.ts` and `src/components/SharedSpaceConsentPanel.tsx`. Exact Docker argv, restricted logs and exits are recorded as `js-regressions.{argv,log,exit}`, `typescript.{argv,log,exit}` and `eslint.{argv,log,exit}` under `/gpu1-share/data/cicada-client/v2-framework-20260930/evidence/`.

The final APKs were built from `eb0db6f3d095b60b0f2f73bcfda0079ba33ad846` plus framework changes. The 91-file compiled-source fingerprint was `3d99c7901e0710183f7489e8d0416057a39c5149ac45d116fe47bf7d1d614842` before and after the build and at emulator start. This is a dirty-source build, separately attributed from the fixed v1.5 acceptance APKs. The completion receipt identifies the subsequent local milestone commit and independently checks that its compiled-source bytes match this fingerprint; it does not convert the original build into a clean-commit build.

| Artifact | SHA-256 |
|---|---|
| Framework product APK | `2ecb5d25f193b1b59c574b51c6383bf4d19617f028ce3b4a926a070113657758` |
| Framework instrumentation APK | `0a42a512d54d7070d1d22285e4eff2c64ade0885700898962181cb6d20736e22` |

Build command: `gradle --no-daemon --offline --project-dir /workspace/android :app:assembleDebug :app:assembleDebugAndroidTest`, in the pinned Docker image above. Exact Docker invocation and exit `0` are in `android-build.{argv,log,exit}` under `/gpu1-share/data/cicada-client/v2-framework-retry-20260930/evidence/`; source/artifact metadata are in `build-source-baseline.private.json` and `android-apk-artifacts.private.json`. The bounded product APK entry-name check confirms bundled JavaScript and absence of the candidate test asset and known environment filenames (`product-apk-packaging.redacted.json`); the public test asset also contains no private field names. This is not a universal proof of absence of secrets.

### Android runtime and exact commands

The fresh Android 15/API 35 x86_64 emulator used immutable image `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` with no network. Runtime evidence is under `/gpu1-share/data/cicada-client/v15-deterministic-v2-framework-retry-20260930/evidence/`. Installed APKs, runtime metadata and individual command receipts identify the exact binaries above. No Hub, carrier, native Thread, model credential or ADB reverse mapping was used.

Both test commands used the prefix `docker exec cicada-v15-deterministic-v2-framework-retry-20260930 /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 shell am instrument -w -e class`, followed by the fully qualified class below and runner `ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner`.

| Class or command | Result and exit | Receipt |
|---|---|---|
| `ai.cicada.client.hub.CrossOwnerGroupKeyV2VerifierTest` | PASS, `OK (9 tests)`; ADB `0`, driver `0` | `cross-owner-group-key-v2-verifier.json` and `.private.log` |
| `ai.cicada.client.hub.ClientHubV15OperationPolicyTest` | PASS, `OK (4 tests)`; ADB `0`, driver `0` | `v15-operation-policy-only.json` and `.private.log` |
| `python3 /gpu1-share/data/cicada-client/v15-deterministic-v2-framework-retry-20260930/evidence/ui-shared-space-check.private.py /gpu1-share/data/cicada-client/v15-deterministic-v2-framework-retry-20260930/evidence` | PASS, driver `0` | `ui-shared-space-control.{argv,log,exit}` and `ui-shared-space-summary.redacted.json` |
| `python3 scripts/interop/v15-android-deterministic.py /gpu1-share/data/cicada-client/v15-deterministic-v2-framework-retry-20260930/evidence stop` | PASS, exit `0` | `emulator-stop-control.{argv,log,exit}` and `emulator-stop.json` |
| `docker inspect cicada-v15-deterministic-v2-framework-retry-20260930 --format '{{.Id}}'` | PASS for absence, exit `1` | `emulator-absence-check.redacted.json` and `android-teardown.redacted.json` |

The product UI check launched the real MainActivity, opened Management, and inspected the shared-space panel collapsed and expanded. It showed the unconnected/unpinned unavailable state and no Owner scope, fixture, success state or actionable consent control. Restricted XML and screenshots record this bounded observation; connected scope selection remains unobserved. Each command and exit is preserved, with aggregate metadata in `/gpu1-share/data/cicada-client/v2-framework-retry-20260930/evidence/runtime-validation-summary.private.json`.

### Corrected initial test failure

The first verifier run reported **FAIL**, `Tests run: 9, Failures: 1`; ADB exited `0`, while the driver correctly exited `1`. The resource-bound test expected the custom integer-overflow reason for a 10,000-digit JSON token. Gson's strict lexer rejects that token before the custom guard. A pinned offline Docker check confirmed this behavior. The test now checks the explicit overflow guard with a 64-digit integer and separately requires rejection of the 10,000-digit token. Production verification was unchanged. The corrected source was rebuilt and all nine tests passed on a new emulator.

The original failure remains at `/gpu1-share/data/cicada-client/v15-deterministic-v2-framework-20260930/evidence/cross-owner-group-key-v2-verifier.json` and `.private.log`, tied to its original source fingerprint and instrumentation APK. Both initial and final owned emulators were removed and independently confirmed absent. The corrected run's APK and evidence above are the final local acceptance attribution.

## Required next Core delivery

Supply a clean complete contract package and immutable image with the candidate proof types and full public canonical/signature vectors. Supply an isolated native authority fixture with independent Owner public-key trust, exact admission/Join/candidate revisions, safe expiry/revocation scenarios and the external signing process. The Client must independently reverify that delivery, implement the dedicated encrypted preview/confirmation path, and obtain separate Android positive and rejection evidence before enabling any of the ten deferred operations. Existing v1.5 or candidate-vector success cannot authorize that change.

The current local scope panel covers a Group Owner's own topology projection. An Endpoint Owner's pre-Join foreign admission review remains an interface dependency:

- **Request:** Identify or deliver an encrypted, read-only, exact-admission preview for the Endpoint Owner before `space.foreign_endpoint_join`.
- **Expected result:** Authenticated current Hub, Network, foreign Group/Group Owner, admitted Endpoint/Principal, restricted grants, expiry, revisions and the current native binding/context policy. This must support an informed shared-context decision without signing, joining or exposing another Owner's unrelated directory.
- **Reproduction:** Create an admission as the Group Owner; switch to the Endpoint Owner's independent Client session; attempt to inspect that exact foreign admission before acknowledging risk. The fixed 46-operation catalog lists no admission-preview operation; its topology read contains the caller's own Groups, while `space.key_manifest_v2` requires the later trusted Join. The Client has not guessed an alternative JSON field or route. Core must clarify the intended trusted read in the next delivery.

Core acknowledged this gap in the authorized supervisor thread and is preparing an exact Endpoint-Owner preview contract. That work requires a new clean pinned delivery; the current v1.5 package and Client gates remain unchanged.
