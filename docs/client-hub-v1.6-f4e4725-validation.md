# CICADA Client v1.6 Validation Report

**Date:** 2026-10-01

**Scope:** Client implementation, independent Android proof-vector verification, and bounded encrypted Hub interoperability.
**Result:** Contract provenance, offline checks, the final Android build, 63 Kotlin tests, offline UI, and bounded fixed-image encrypted Hub interoperability passed. Native current Endpoint consent and the wider fault matrix remain separately unaccepted. No earlier Hub or native result is transferred.

## Fixed Hub target and import provenance

| Item | Pinned value |
|---|---|
| Clean Hub source revision | `f4e4725c5d81c54b166f4291b9d450c70954e6df` |
| Source dirty | `false` |
| Source fingerprint | `c3d22f3d69ee668bb29215100ba78a33acf107fd1e03443a48e4651c70e44c4b` |
| Contract / wire | `client-hub-v1.6` / `1` |
| Catalog operations | `55` |
| Catalog SHA-256 | `1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c` |
| Bundle SHA-256 | `54234527064c5923f9b40d4ac2f602c702e6dbc47fe7b52185da823c97c10fbd` |
| Handoff metadata SHA-256 | `a4160b688fbc783a6fdb8f18a3e3d8d349219a24510e1891abe87e6180b55049` |
| Local Hub image ID | `sha256:6a7e0af78d3d14369f451760541b54d49a6e9505a1c813aa1124186176d4f5c9` |
| Local interop image ID | `sha256:565aeffa59cacc00d871c1e81a836a992fca4a04633ea2ce21d015af3523aad4` |

The immutable imported snapshot is [contracts/client-hub-v1.6-f4e4725/manifest.json](../contracts/client-hub-v1.6-f4e4725/manifest.json). The receipt at `/gpu1-share/data/cicada-client/v16-f4e4725-20261001/provenance/contract-import.redacted.json` reports **PASS**, 21 payload files, safe archive paths, byte-for-byte matches to the pinned Core commit, and matching labels on both complete image IDs. The Hub image ID is local; it is not a published registry manifest digest.

The bundle manifest records `android_interop=NOT_RUN`, `native_runtime=NOT_RUN`, and `inner_rpc_shapes=partial_prose_references`. Image provenance does not establish Client interoperability or native runtime behavior.

## Contract checker

The offline checker passed with exit code `0` in the pinned Docker development image, with networking disabled and the repository mounted read-only. Its receipt is `/gpu1-share/data/cicada-client/v16-f4e4725-20261001/checks/contract-check.json`; the log reports `PASS client-hub-v1.6` with the pinned catalog SHA and 21 files.

```text
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 scripts/check-client-contract.py
exit: 0
```

This check verifies the imported protocol package. It does not build the Android app, run the Kotlin vectors, validate encrypted `session.capabilities`, or exercise the Hub image.

## Client build and source identity

The final Docker build completed with exit code `0` for both the app and Android test APK. The receipt records Client base commit `9b17f8fb25bb8f3e66e03e0190b63a022e93a895`, with an unchanged 102-file source fingerprint before and after the build: `1fca907f2e4f727f2a29e626c2e1e754e54036055dcd74f4cea5d1a21779226f`.

```text
docker run --rm --pull=never --network=none --user 1000:1000 \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v /home/zyf/CICADA_CLIENT:/workspace \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules \
  -v /gpu1-share/data/cicada-client/gradle-cache:/gradle-cache \
  -v /gpu1-share/data/cicada-client/android-home:/home/gradle/.android \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  gradle --offline --no-daemon --project-dir /workspace/android \
  :app:assembleDebug :app:assembleDebugAndroidTest
exit: 0
```

| Artifact | SHA-256 | Size |
|---|---|---:|
| Android app debug APK | `b853346ecd185a4713b1f90838275e456972f85fdd1cbddd9b527dc761511c46` | 296,183,275 bytes |
| Android instrumentation APK | `4effb0bc069039865f028c75251b2aef9d99a19fefc20d159194bfa9bcb4072b` | 1,080,599 bytes |

The first retained build attempt used the preceding 101-file source fingerprint `56dbbe76d91486099a938db9729933069a25f0b7f7f9630fb97c5663fce034ef` and exited `1` on a Kotlin `Long`/`Int` type mismatch; it produced no APKs. The correction is included in the final 102-file source snapshot above, whose rebuild passed. The initial build receipt and log remain under `build/history/initial-*`.

The final JavaScript test command ran 34 tests and exited `0`:

```text
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  node --test tests/clientHubOperationPolicy.test.mjs \
  tests/networkTopology.test.mjs tests/sharedSpaceConsent.test.mjs \
  tests/monitorBroadcast.test.mjs
exit: 0 (34 tests)
```

The TypeScript and lint checks also exited `0`. Lint reported 21 warnings and no errors.

```text
docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  ./node_modules/.bin/tsc --noEmit
exit: 0

docker run --rm --pull=never --network=none --user 1000:1000 \
  -v /home/zyf/CICADA_CLIENT:/workspace:ro \
  -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  ./node_modules/.bin/eslint App.tsx src/
exit: 0 (21 warnings, 0 errors)
```

## Operation boundary

The Client locally implements 35 of the 55 catalog operations and keeps 20 closed. The two new operations have read adapters, without dedicated product UI controls. All seven other new v1.6 operations remain closed, and the prior 13 shared-space, topology delegation/proposal and Link-key gates are preserved. Local implementation and encrypted session authorization are both required; the server Guard remains authoritative.

| New v1.6 operation | Status | Scope and remaining gate |
|---|---|---|
| `network.directory` | Display-only read | Bounded cards for opted-in Endpoints in the authenticated Owner's active Network. No Owner, Node/native locator, Group, key, workspace, Join, or messaging authority. Requires the current encrypted capability and server authorization. |
| `topology.endpoint_admission_preview` | Display-only read | Same-Owner current Network/Endpoint preview with revisions for a possible later CAS. It does not change membership or grant key/history access. |
| `space.foreign_endpoint_preview` | Closed | Exact foreign Endpoint Owner admission review is not implemented as an authorized Client flow. Preview alone cannot approve admission, cause Node Join, or grant history. |
| `network.collaboration_key_manifest` | Closed | No accepted current native Endpoint authority fixture or verified purpose-scoped manifest flow. |
| `network.collaboration_key_grant` | Closed | Requires the exact current purpose manifest, independently trusted Owner key and signature, explicit user confirmation, current server Guard, and dedicated uncertainty handling. A key grant does not authorize `task.offer.*`, `broadcast.*`, or `direct.*`. |
| `network.collaboration_key_status` | Closed | Purpose-specific current status and correlation are not accepted by the Client. `active`, `stale`, and `revoked` must remain distinct from task/broadcast execution. |
| `link.review_policy_preview` | Closed | Current Link contract, side, policy digest/version and exact reviewers are not independently bound in a Client review flow. |
| `link.review_policy_grant` | Closed | One Owner proof is not approval for both Link sides. Each Owner must independently sign the exact current policy digest/version. |
| `link.review_policy_status` | Closed | Current dual-side policy status is not independently reconciled by the Client. It must remain metadata-only and expose no Link message content. |

The 13 preserved gates are the seven cross-Owner Space consent/admission methods, three topology delegation/proposal methods, and three Link key methods. Catalog presence or a public capability does not open any of these operations.

## Public vector attribution and limitations

The three vectors are synthetic public test data from the pinned bundle. Their hashes match the imported manifest:

| Vector | SHA-256 | Exact signed shape |
|---|---|---|
| `owner-link-review-policy-proof-v1.json` | `aab0a7074fb32523f75bb89f9a61f4725d9f462c2d83eec33d23f79609fc5907` | Policy has 11 ordered claims and no `signature` field in its signed JSON. |
| `network-collaboration-broadcast-consent-v1.json` | `c18b237047a6963b95844a1a32307794e6b353150313b77ab2ce84393b0ab8ea` | BROADCAST has 12 ordered claims, including final `"signature":null`; its purpose is distinct from TASK. |
| `network-collaboration-key-consent-v1.json` | `ad073291703a01513c27fc729439a6bfa8502a8df8f8138a7ed1c3863a4d0c64` | TASK has its own 12-claim `signature:null` input and purpose. |

The vectors check public-key encoding, canonical bytes, purpose separation, digests, and synthetic signatures. They do not establish independent Owner trust or current Endpoint/Network authority. The BROADCAST manifest's `candidate.attestation` is an opaque synthetic placeholder, and its candidate fingerprint is synthetic; neither is a complete Endpoint attestation or evidence of a current native binding. The Policy vector likewise does not provide a current Link or Owner authority view. No private keys are included.

The missing Core-owned Endpoint fixture must bind these pieces to the same current native Endpoint:

1. A complete canonical Endpoint attestation v1, verified under the candidate's full public identity, rather than opaque placeholder bytes.
2. The Endpoint, Principal, Owner and Node identities plus the native Session identifier/digest.
3. The current SessionBinding identifier/epoch, Network membership revision, and Endpoint enrollment revision for that joined Endpoint.
4. An independently trusted Owner public key tied to the Owner identity and a purpose-specific signature over the exact current manifest, with valid issue/expiry times.
5. For foreign admission, the Endpoint Owner's separate exact-scope review, Group Owner admission, fresh trusted Node Join, and a resulting current membership projection. One Owner cannot approve for the other.

The current public vectors contain synthetic identity/revision-shaped fields, but do not prove that these values belong to a real current Node, Thread or Endpoint. The separate synthetic Endpoint-attestation vector does not fill this current native-authority gap.

## Deterministic Android emulator selector results

The final selector matrix driver exited `0`:

```text
python3 scripts/interop/v16-android-deterministic.py \
  /gpu1-share/data/cicada-client/v16-deterministic-f4e4725-20261001-final/android \
  test
exit: 0
```

Each selector receipt records the individual instrumentation exit and driver exit as `0`, along with `PASS` and the JUnit count. Across these 12 selectors, 63 tests passed and none failed or skipped.

| Instrumentation selector | Tests | Result |
|---|---:|---|
| `ai.cicada.client.hub.HubProfileStoreTest` | 10 | PASS |
| `ai.cicada.client.hub.NetworkKeyConsentVectorTest` | 6 | PASS |
| `ai.cicada.client.hub.NetworkSessionGuardTest` | 8 | PASS |
| `ai.cicada.client.hub.ClientWirePublicVectorTest` | 5 | PASS |
| `ai.cicada.client.hub.EndpointAttestationVectorTest` | 4 | PASS |
| `ai.cicada.client.hub.MonitorBroadcastVectorTest` | 6 | PASS |
| `ai.cicada.client.hub.ClientHubRecoveryLockTest` | 6 | PASS |
| `ai.cicada.client.hub.ClientHubV16OperationPolicyTest` | 4 | PASS |
| `ai.cicada.client.hub.NetworkKeyProductionVectorTest` | 5 | PASS |
| `ai.cicada.client.hub.OwnerLinkReviewPolicyV1VectorTest` | 3 | PASS |
| `ai.cicada.client.hub.NetworkCollaborationBroadcastConsentV1VectorTest` | 3 | PASS |
| `ai.cicada.client.hub.NetworkCollaborationTaskV1VectorTest` | 3 | PASS |

The receipts used this command for each listed class (substitute the exact selector from the table); each command and its driver exited `0`:

```text
docker exec cicada-v16-deterministic-f4e4725-20261001-final \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  shell am instrument -w -e class <selector> \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

The offline product UI smoke driver also exited `0`:

```text
python3 scripts/interop/v16-android-deterministic.py \
  /gpu1-share/data/cicada-client/v16-deterministic-f4e4725-20261001-final/android \
  ui-smoke
exit: 0
```

## Android, Hub and platform validation status

| Gate | Status | Evidence boundary |
|---|---|---|
| 12-selector deterministic Android emulator matrix | **PASS: 63 tests, 0 failures** | Every selector's instrumentation command, selector, test count, APK hashes, and adb/driver exit codes is recorded in the final run receipts. Emulator is Android 15 / API 35 / x86_64; this is not physical-device acceptance. |
| Policy, BROADCAST and TASK Kotlin vector selectors | **PASS: 9 tests** | `OwnerLinkReviewPolicyV1VectorTest` 3/3, `NetworkCollaborationBroadcastConsentV1VectorTest` 3/3, and `NetworkCollaborationTaskV1VectorTest` 3/3. These remain public synthetic vectors and do not establish live Owner trust or native current authority. |
| Android app and instrumentation build | **PASS**, exit 0 | APK and 102-file source fingerprint hashes are recorded above. |
| Offline product UI smoke | **PASS**, exit 0 | Five checks: unconnected bootstrap; create does not activate; new profile remains unpinned/unenrolled; explicit profile-switch consent; switched profile stays unconnected. No Hub runtime was used. |
| JavaScript tests / TypeScript / lint | **PASS**, exits 0 | 34 JavaScript tests; `tsc --noEmit`; lint had 21 warnings and 0 errors. |
| Encrypted v1.6 session capabilities and current permissions | **PASS** | Fresh Android enrollment and exact encrypted revision/catalog. External role advertises 47 operations; its exact local intersection is 27. `directory.redacted.json`, `role-oracle.redacted.json`. |
| Enrollment HTTP 201 response loss | **PASS** | The same Grant and exact enrollment request are retained, replacement is refused, and the original request returns the same registration bytes. Two Android selectors, adb/driver exits 0/0. |
| RPC HTTP 200 response loss / `COMPLETED` | **PASS** | Original signed ciphertext goes to `/v2/client/rpc/recover`; operation ID and request/response counters are retained. Original response envelope SHA matches the cached recovered envelope. Two Android selectors, exits 0/0. |
| `network.directory` empty result and scope refusal | **PASS**, bounded | One ACTIVE Owner Network; zero opted-in cards. The unselected foreign Network is refused locally before dispatch. This does not claim an encrypted Hub denial, nonempty discovery, native authority or a directory UI entry. |
| Nonempty directory and positive Endpoint admission preview | **BLOCKED / NOT_RUN** | No joined Endpoint exists in this two-Owner Network fixture. Preview has no operable UI control. Current native proof/authority fixture remains required. |
| `STILL_PROCESSING`, `OUTCOME_UNCERTAIN`, `RECOVERY_UNAVAILABLE` | **NOT_RUN** | No separately delivered v1.6-owned ledger-fault fixture was used. The v1.6 carrier refuses historical recovery fixtures; older PASS is not transferred. |
| Real Hub replay rejection, device revocation and broader server guards | **NOT_RUN** | Response-loss idempotency does not certify revocation or every permission boundary. |
| Carrier / emulator / owned Hub cleanup | **PASS** | Coordinators and inner carriers exit 0; proxies receive requested SIGTERM (-15). Both reverse ports are removed, both owned VMs are absent, cleanup exits 0 and the temporary Hub/Network/Owner-key directory is removed. |
| Native Endpoint/Owner current authority, admission and Join | **BLOCKED / NOT_RUN** | Awaiting the complete Core fixture listed above and independent Client acceptance. |
| Direct Network key-grant uncertain-outcome reconciliation | **BLOCKED / NOT_RUN** | Preserve the durable business fence and original signed evidence. A generic `status.snapshot` can reconcile an outer RPC result but cannot release this fence; require dedicated `network.key_status` correlation. |
| Physical Android and public HTTPS | **NOT_RUN** | Emulator/host-local evidence cannot substitute for either. |
| iOS and native HarmonyOS | **NOT_RUN** | iOS has no validation claim. A native HarmonyOS app requires ArkUI/ArkTS; React Native TSX is not a native HarmonyOS app. |
| Physical-device speech-model acceptance | **NOT_RUN** | This v1.6 contract record contains no new model or microphone result. |

The deterministic Android test matrix and UI smoke ran in offline emulators with networking disabled. In the earlier run `v16-deterministic-f4e4725-20261001`, the Policy selector failed at the v1.5/v1.6 identity check; that VM was subsequently cleaned. The final `v16-deterministic-f4e4725-20261001-final` run passes the Policy selector 4/4, and the earlier failure is not counted in the final 63-test result. The emulator receipt identifies API 35, Android 15, x86_64 and image `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f`. These selector and offline UI phases did not use a Hub. The separate live phase below subsequently used the same final APK pair and the pinned Hub.

The existing platform-neutral UI, editable local speech transcript and text entry remain separate product work. This report does not change the existing STT evidence or transfer any historical Android, native, image, or model result to v1.6. See the [model selection](model-selection.md), [speech validation](stt-validation.md), and [historical v1.5 validation](client-hub-v1.5-bd79ff9-validation.md) records for their original scopes.

## Live encrypted fixture and response recovery

Core's read-only `scripts/client-network-fixture.sh setup --build-metadata` ran
against `client-v1.6-clean-handoff/hub-build.json`, exit `0`, creating only
`/tmp/cn.AUjl5XBG`. Its immutable Hub image, clean revision, source fingerprint
and catalog were independently checked against the fixed pins. The fixture
contains two synthetic Owners and ACTIVE Networks, with no Node or native Thread.
Core independently signed the exported Android PUBLIC device manifest. The Owner
private key stayed outside Client, Hub mounts, Git and APK; Client staged only
Base64 of the exact signed Grant file bytes through interactive ADB STDIN.

The opaque carrier leaves Android in Docker `network=none`. It allows only the
five Client identity/capability/enrollment/RPC/recovery routes, forwards to the
owned Hub's independently checked numeric bridge address, and records counts and
hashes without decrypting or persisting packet bodies. This is development
loopback transport; it does not certify public HTTPS.

Evidence root:
`/gpu1-share/data/cicada-client/v16-deterministic-f4e4725-20261001-final/android`.
The full command, selector, APK hashes and adb/driver exits `0/0` are in each
receipt listed below. Run IDs and scenario arguments refer to this same fresh
Owner device session; none of the tests dispatches a Worker or business write.

| Selector (`ai.cicada.client.hub.` prefix) | Arguments | Receipt | Result |
|---|---|---|---|
| `ClientHubV16ResponseLossTest#captureEnrollmentResponseLoss` | `run_id=v16-base-f4e4725`, `scenario=enrollment` | `capture-enrollment-loss.json` | PASS, 0/0, 1 test |
| `ClientHubV16ResponseLossTest#recoverExactEnrollment` | same | `recover-enrollment-loss.json` | PASS, 0/0, 1 test |
| `ClientHubV16InteropTest#verifyRecoveredEnrollmentDirectory` | same run ID | `directory-live.json` | PASS, 0/0, 1 test |
| `ClientHubV16ResponseLossTest#captureRpcResponseLoss` | same run ID, `scenario=completed` | `capture-rpc-loss.json` | PASS, 0/0, 1 test |
| `ClientHubV16ResponseLossTest#recoverCompleted` | same | `recover-rpc-loss.json` | PASS, 0/0, 1 test |

The carrier CLI is recorded in `carrier-enrollment.command.json` and
`carrier-rpc.command.json`: `python3 scripts/interop/v16-host-stdio-carrier.py`
with the final evidence root, fixed marker/public paths, exact app/test SHA-256,
and `--fault enrollment` or `--fault rpc`. All ciphertext is produced and
verified by Android's production session API and the real pinned Hub.

`response-loss-comparison.redacted.json` independently compares the proxy and
carrier records: each fault drops once, request SHA-256 is identical on recovery,
and registration bytes or the signed response envelope are identical. RPC
request sequence and expected response sequence are both `8`; next sequence
remains `9` throughout recovery. The operation ID is recorded only as SHA-256.
No replacement request is created. `role-oracle.redacted.json` reads Client's
own state only in memory and compares the full operation set against the pinned
catalog and independent implementation oracle; the state file is not saved.

Two staging mistakes preceded acceptance: an ADB invocation without interactive
STDIN produced an empty test adapter file; a later adapter supplied Grant JSON
where the contract requires Base64. Both failures occurred before enrollment
HTTP and are preserved in `history/capture-enrollment-loss.*`; no registration,
new nonce, or operation was created. Corrected staging used the same original
Grant and device identity. The added `v16-stage-fixture.py` encapsulates correct
interactive/Base64 staging and passed AST parsing; its standalone CLI was
**NOT_RUN**, because the accepted equivalent staging preceded owned cleanup.

Cleanup evidence: `stdio-carrier-*-stopped.redacted.json`,
`carrier-reverse-remove-40373.json`, `android-teardown.redacted.json`, and
`/gpu1-share/data/cicada-client/v16-f4e4725-20261001/fixture/cleanup.receipt.json`.
The first failed-matrix VM has its own teardown receipt. Fixture cleanup exits
`0`, removes the owned Hub/Network and `/tmp/cn.AUjl5XBG`, including synthetic
Owner private keys. No resident Hub, Core source or Hub database was read or
changed by Client code. The explicitly authorized Core fixture operator alone
provisioned its temporary state.

## Delivery identity and remaining gates

Build source is base Client `9b17f8fb25bb8f3e66e03e0190b63a022e93a895` plus the
102-file source fingerprint above. The delivery commit is the commit containing
this report; its full ID and the matching filtered-Git fingerprint are recorded
in `/gpu1-share/data/cicada-client/v16-f4e4725-20261001/delivery.redacted.json`.
The external receipt avoids a circular self-commit reference. No push or merge
is part of this checkpoint.

Native current Endpoint authority, positive key consent/admission, broader
replay/revocation/ledger faults, connected UI, physical Android, public HTTPS,
fresh speech-model execution, iOS and native HarmonyOS retain separate
BLOCKED/NOT_RUN status. The live receipt does not certify full Worker/Codex
execution or business-level exactly-once behavior.
