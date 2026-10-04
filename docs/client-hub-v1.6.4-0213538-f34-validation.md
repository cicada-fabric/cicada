# Client-Control v1.6.4: F34 validation and Target outcome diagnosis

## Fixed target and tested APK pair

F34 ran Client commit `8f2900c63f515033827d41d962acf7453513f370` against this
fixed Core target. Findings apply only to the APK pair below.

| Target field | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source state | `source_dirty=false` |
| Hub image | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| App APK SHA-256 | `3c7a4e5903edc8549773cc89e29fe058959fa68e8f56ffba45214eba6a4cf32d` |
| Test APK SHA-256 | `1110cbed39069a6c5f316426db821237f696856188fa9ddee3475426f32d0fbf` |
| Runtime | Android emulator, API 35, x86_64 |

Evidence roots outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f34-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f34-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f34-0213538-main-20261004/outbox`
- `R=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-34-clean021-20261004`

The artifact metadata marks the bootstrap as `bootstrap_only`; that annotation
does not negate the compiled Android tests' independently retained SOURCE RPC
receipts. It also does not prove a Target RPC occurred.

## Launcher commands and outcomes

The private journal is the command source. This table keeps only stage, script,
exit, elapsed time and timeout outcome; arguments are omitted. The flow exit is
the JUnit failure, not evidence of a Hub rejection.

| Stage / script | Exit | Elapsed | Result |
|---|---:|---:|---|
| Bootstrap — `v164-acceptance-boot.py` | 0 | 38.426 s | Completed |
| Bootstrap preflight — `v164-link-consent-android.py` | 0 | 0.233 s | Completed |
| Prepare — `f20-client-coordinator.private.py` | 0 | 1.165 s | Completed |
| Bind — `f20-bind-boot-artifacts.private.py` | 0 | 1.202 s | Completed |
| Hot preflight — `v164-acceptance-hot.py` | 0 | 0.602 s | Completed |
| Flow — `f20-root-flow.private.py` | 1 | 98.332 s | Failed; not timed out |
| Carrier — `v164-link-fixture-carrier.private.py` | 0 | 100.979 s | Completed |
| Emulator stop — `v164-android-deterministic.py` | 0 | 0.916 s | Completed |

## Android evidence

| Gate | F34 evidence |
|---|---|
| SOURCE enrollment and encrypted capabilities | **PASS**; v1.6.4/catalog verified; no private material exported |
| SOURCE independent Owner pins | **PASS**; the native confirmation argument is not phone UI approval |
| SOURCE KEY submit and fresh read | **PASS, partial**: SOURCE `ACCEPTED`, TARGET `MISSING`, bilateral false |
| SOURCE policy candidate and fresh policy read | **PASS, partial**: grant not current; grant SOURCE `VERIFIED`, TARGET `MISSING`; fresh policy version `0`, both fresh sides `MISSING`, bilateral false |
| TARGET enrollment and encrypted capabilities | **PASS**; exact v1.6.4/catalog verified; no private material exported |
| TARGET independent Owner pins | **PASS**; the native confirmation argument is not phone UI approval |
| TARGET UI preparation | **PASS** at `REVIEW_READY` |
| TARGET UI consent stage | **PASS** at `CONFIRM_READY`; one enabled control, not busy; test did not call native session methods |
| Target JUnit | **FAIL**: one test, one failure, 31.696 s, source line 597; instrumentation process exit `0` |
| Authoritative Target KEY response / fresh bilateral read | **UNKNOWN / NOT_RETAINED** |
| Target `NONE` consent and fresh policy read | **NOT_RUN** |
| Bilateral current KEY / `NONE` verification | **NOT_RUN** |
| Physical Android, native Worker/model, public HTTPS | **NOT_RUN** |

The Kotlin test's native Alert scope assertions completed, and its positive-click
operation at line 596 returned. The following wait for the success message at
line 597 (the wait helper at line 386) timed out. This does **not** establish
that the React Native callback entered, an RPC was dispatched, a native response
returned, or Hub acceptance occurred. No authoritative Target post-submit
receipt or fresh Target status read is saved. The native RPC pending state and
error code are also **UNKNOWN**; the UI `CONFIRM_READY` receipt is not a grant.

SOURCE status remains partial and independent of the Target attempt. The KEY
receipt reports `local/source=ACCEPTED`, `target=MISSING`, bilateral false and no
reconciliation requirement. The policy receipt reports the prior grant not
current, its TARGET side missing, and a fresh policy head at version zero with
both sides missing. These SOURCE reads do not establish bilateral consent.

## Terminal and cleanup

The canonical launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**
(SHA-256 below). No retry was made. The Target outcome remains **UNKNOWN**. No
new Target grant state or native error is inferred from the host-side
pending/terminal marker. Core's independent closure is
`CLOSED_CLIENT_FAIL_TARGET_RESPONSE_UNKNOWN`. Its receipt says Target KEY
acceptance is `UNKNOWN_NOT_PROVEN`, a bilateral read was `NOT_REACHED`, and no
authoritative Target response or safe native HTTP/RPC error code was retained.
Five Core signed records (SOURCE 3, TARGET 2) and six guard records are counts,
not proof of Hub acceptance; Target `NONE` was not signed.

The emulator teardown passed with an independent absence check. Core's actual
two-resource cleanup is `OWNED_CLEANED`, private fixture deletion true, and zero
model calls. Physical Android, native Worker execution and public HTTPS remain
**NOT_RUN**.

## Current source boundary

The F34 APK hashes above belong to the fixed `8f2900c` Client commit. The
development-only passive diagnostic observer is a later source candidate. It
emits only fixed, payload-free stages when native
`linkConsentDiagnosticsEnabled` (`BuildConfig.DEBUG`) is true and an
instrumentation observer is active. A recorded stage is **OBSERVED**
telemetry, not a test PASS or Hub acceptance. A JavaScript Promise resolving,
rejecting or timing out does not measure native encrypted-ciphertext pending
state.

The external post-commit cache is
`T=/gpu1-share/data/cicada-client/v164-f34-submit-observation-20261004`. At this
checkpoint the APK build is **NOT_RUN**. Any post-commit build, source and
delivery receipts in T must bind the new Client commit and exact app/test APK
pair; no build or delivery result is claimed here.

Docker offline checks for the current source candidate passed; these do not
change F34 Android status:

| Command | Exit / result | Receipt SHA-256 in T |
|---|---|---|
| `node --test tests/linkConsentFlow.test.mjs tests/linkConsentDiagnostics.test.mjs` | 0 / 14 JS tests PASS | `2632de790863190b3f669fcb5d05fda427888c332ecaaaee8945d98a67927f17` |
| `python3 scripts/interop/test_v164_phone_ui_outcome.py -v` | 0 / 16 Python tests PASS | `1ba90108f4a86955f86c018dd40f077817ba34cecc3d5dfcb33ea005280ff909` |
| `node node_modules/typescript/bin/tsc --noEmit` | 0 / PASS | `5655889ab0f6e18e0e308e6be1476f84d6b735c1b76376f20dd418f96cca68df` |
| `node node_modules/eslint/bin/eslint.js src/components/LinkConsentPanel.tsx src/platform/linkConsentFlow.ts src/platform/linkConsentDiagnostics.ts src/platform/linkConsentDiagnosticEvents.ts` | 0 / PASS | `bce60ea5655c324c280acd1c0eb727a0a65c15074f75d7f7888090a8b1c2cd7f` |

## Evidence index

| Evidence | Path | SHA-256 |
|---|---|---|
| Safe Android artifact metadata | `E/android-artifacts.json` | `636598f982438a4824e52f6bcc9506cfcf881e44e504d6459536f5ef9abdfd33` |
| SOURCE enrollment/capabilities | `E/link-v164/receipt-source-enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities-394e1dfabcba.private.json` | `394e1dfabcba149f2410465f29371a259128c5691b176d17b86857d0dd0d4db5` |
| SOURCE independent pins | `E/link-v164/receipt-source-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-31d742b72c4e.private.json` | `31d742b72c4ec55c441f6067f1f62604302949719448f436fbdd9f9d470639d4` |
| SOURCE KEY fresh status | `E/link-v164/receipt-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus-6d30e9496192.private.json` | `6d30e9496192dd12c95ee652a6749f3960e17c47e3628ca67f4f6f83f7cdb908` |
| SOURCE policy fresh status | `E/link-v164/receipt-source-submitsHostSignedPolicyProofAndRevalidatesFreshV164Status-32a3c28bcf64.private.json` | `32a3c28bcf645016376c45be8e859aae03434e44fd8e23583fb3a323e8267e9e` |
| TARGET enrollment/capabilities | `E/link-v164/receipt-target-enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities-5e5c3d4271a0.private.json` | `5e5c3d4271a072c2492d9873ea67b4ee76a8d0eb8a81201a264481eae4ddf916` |
| TARGET independent pins | `E/link-v164/receipt-target-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-8908bcfc841b.private.json` | `8908bcfc841bc2dc87545f7292f61222325d078ce45f5ed36348e3ce1d84aab2` |
| Command journal | `L/command-journal.private.jsonl` | `6c463c5093886aefa17a9f8702a0e761d6cd9a942e9ec09b124e7468333aeab9` |
| Canonical terminal | `L/terminal.private.json` | `2a42d5525596461816af7feab4b3167c1ea2d8a7bf9c8e8092abaca3b2fb8be8` |
| Target UI prepare | `O/target-key-rn.phone-ui-prepare.redacted.json` | `80617d8d9e9180c8a6b361439ebc2028784a0286afb76e47ab74acb648769fc4` |
| Target UI consent | `O/target-key-rn.phone-ui-consent.redacted.json` | `eeefa9c2d0700ed316c310503b0c99c90bbaf28a18c07150df101e3d08fd2d99` |
| Target UI result | `O/target-key-rn.result.redacted.json` | `e9d4d0529603b0dbbe9c5f21a8e41d72535a6d31bc75e7fdd892ec0ff8e8e65f` |
| Target JUnit log | `O/target-key-rn.instrumentation.private.log` | `19255dbcb38d17e7525a935ce60cf8ede0e76b47419a8686e20e8ba936126b67` |
| Emulator teardown | `E/android-teardown.redacted.json` | `886fa425f3b4efcdaa6b652fc5f649b35eff53c8735c2767e22ca4bd4cac4320` |
| Core independent closure (16,681 bytes) | `R/evidence/attempt-08/independent-core-closure.redacted.json` | `8176563c423d52d49d1469d469929b1dbedaf2f6f8a79b6f275a9b13160c21aa` |
| Core two-resource cleanup (406 bytes) | `R/evidence/attempt-08/cleanup-1791078176848193471.json` | `66c36163d8163f8811d4c3968a94a40b53e14ccc6d972fefff74230c4dca1275` |
| Offline JavaScript tests | `T/js-tests.receipt.redacted.json` | `2632de790863190b3f669fcb5d05fda427888c332ecaaaee8945d98a67927f17` |
| Offline Python tests | `T/python-tests.receipt.redacted.json` | `1ba90108f4a86955f86c018dd40f077817ba34cecc3d5dfcb33ea005280ff909` |
| Offline TypeScript check | `T/typescript.receipt.redacted.json` | `5655889ab0f6e18e0e308e6be1476f84d6b735c1b76376f20dd418f96cca68df` |
| Offline ESLint | `T/eslint.receipt.redacted.json` | `bce60ea5655c324c280acd1c0eb727a0a65c15074f75d7f7888090a8b1c2cd7f` |
