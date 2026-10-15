# Client-Control v1.6.4: F35 response viewport validation

## Fixed target and tested APK pair

F35 tested Client commit `a80d1a9efbfb2cb413b8356bb5ca764f751702f0` against
the frozen Core target below. Findings apply to this APK pair only.

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
| App APK SHA-256 | `7de03f0bcb7f60ccee4ab14ec94709fdaa17e7241b91aeea8235191a7ecc41a4` |
| Test APK SHA-256 | `c117545c1db3a2f45748b5749bd2922a5ed736093dacaffd108a92ac2fd26e08` |
| Runtime | Android 15 emulator, API 35, x86_64 |

Evidence roots outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f35-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f35-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f35-0213538-main-20261004/outbox`
- `R=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-35-clean021-20261004`

The bootstrap artifact is labeled bootstrap-only. Compiled Android selector
receipts independently retain SOURCE enrollment and status RPC results; the
Target UI progress receipt independently records its native submit and return.
The bootstrap label does not erase those stage receipts or prove a Target grant.

## Android evidence

| Gate | F35 result |
|---|---|
| SOURCE enrollment and encrypted capabilities | **PASS**; v1.6.4/catalog verified; private material not exported |
| SOURCE independent Owner pins | **PASS**; native confirmation argument true, phone UI confirmation false |
| SOURCE KEY submit and fresh read | **PASS, partial**: local/SOURCE `ACCEPTED`, TARGET `MISSING`, bilateral false |
| SOURCE policy candidate and fresh read | **PASS, partial**: grant not current; grant SOURCE `VERIFIED`, TARGET `MISSING`; fresh policy v0 has both sides `MISSING` |
| TARGET enrollment and encrypted capabilities | **PASS**; v1.6.4/catalog verified; private material not exported |
| TARGET independent Owner pins | **PASS**; native confirmation argument true, phone UI confirmation false |
| Target UI preparation | **PASS** at `REVIEW_READY` |
| Target UI consent stage | **PASS** at `CONFIRM_READY`; proof ready, one enabled control, not busy |
| Target Alert scope assertions / positive click | **PASS** in the instrumented UI test |
| Target KEY UI/native submit sequence | **OBSERVED** through native resolution and `UI_RESPONSE_RETURNED`; this is not a grant result |
| Target response message viewport | **NOT_VISIBLE** to the UI selector |
| Target JUnit | **FAIL**: one test, one failure, 31.791 s; failure at `kt638` after forward scroll step 421 |
| Authoritative Target KEY status / bilateral acceptance | **UNKNOWN / NOT_RETAINED** |
| Target `NONE` consent and fresh policy read | **NOT_RUN** |
| Physical Android, native Worker, public HTTPS | **NOT_RUN** |

The progress receipt records, in order: `RN_CONFIRM_CLICKED`, `CONFIRM_OPENED`,
`ALERT_VERIFIED`, `ALERT_POSITIVE_CLICKED`, `CALLBACK_ENTERED`,
`SCOPE_GUARD_PASSED`, `REVIEW_CONSUMED`, `UI_SUBMIT_DISPATCHED`,
`NATIVE_BRIDGE_ENTERED`, `NATIVE_CALL_STARTED`, `NATIVE_RESOLVED` with
`native_ok=true`, and `UI_RESPONSE_RETURNED`. There is no rejection or stuck
stage in this trace. The receipt reports `promise_in_flight=false`,
`native_packet_pending=UNKNOWN`, `reconciliation_required=null`, and
`viewport=NOT_VISIBLE`. A returned JavaScript Promise does not establish native
packet-pending state or authoritative Hub acceptance.

The Kotlin Alert scope assertions completed and its positive click returned.
The failure was the later wait for the response Text to become visible. The
confirmation review is removed when submission starts; the response Text is
rendered below the panel's read-status and request-recovery actions. The tested
wait path scrolled forward only. These are layout and selector observations;
the exact viewport offset and cause of invisibility are **UNKNOWN**. No
authoritative Target grant response or fresh Target status is retained, so the
observer's resolved event does not establish accepted or rejected grant state.

SOURCE receipts remain independent and partial: KEY reports SOURCE `ACCEPTED`
and TARGET `MISSING`; policy reports SOURCE `VERIFIED` and TARGET `MISSING` for
the prior grant, then both fresh sides `MISSING` at policy version zero. These
reads do not establish bilateral consent.

## Terminal, Core closure, and cleanup

The canonical launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**.
No retry was made. Core's independent closure reports
`CLOSED_CLIENT_FAIL_TARGET_VIEWPORT_NOT_VISIBLE_BUSINESS_UNKNOWN` and
Target KEY acceptance `UNKNOWN`; its five signed records (SOURCE 3, TARGET 2)
are counts, not proof of Hub acceptance. Target `NONE` was not signed. The
canonical terminal says `CORE_ACK_NOT_SENT`, while the independent closure's
selected controller event records an ACK exit of 0; this lifecycle discrepancy
does not change the unknown business outcome.

Core-owned two-resource cleanup is **PASS**: `OWNED_CLEANED`,
`TERMINAL_ACK`, zero model calls, and private fixture deletion true. Independent
checks report the owned container and network absent and eight private paths
absent. Android emulator teardown also reports **PASS**. This read-only review
made no live Hub call; the unknown Target outcome is not safe to retry.

## Current source boundary

The current UI source adds `testID="link-consent-message"` to the existing
conditional response Text. Its message wording, state handling, layout,
auto-scroll behavior, and consent semantics are unchanged. This source change
is not in the tested APK pair above.

The viewport candidate retains the 20-second deadline, searches backward then
forward with at most 12 actions per pass, excludes `EditText`, and requires the
actual visible app message ID and response text. Visibility is checked first.
An active debug observer delays scroll attempts until `UI_RESPONSE_RETURNED`,
preserving the action budget while the request is pending; a null observer
uses the normal bounded scan. Observation alone never satisfies the UI gate.
The complete Alert, expiry, Guard and bilateral checks are unchanged.

`U=/gpu1-share/data/cicada-client/v164-f35-response-viewport-20261004` contains
the following offline checks. All used Docker, `--pull=never --network=none`,
and build image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
The pure Kotlin harness uses seven cached compiler/runtime JARs, recorded by
SHA-256 in its inner receipt; it does not execute Android UI or a Hub.

| Check / command | Exit | Result |
|---|---:|---|
| `node --test tests/linkConsentFlow.test.mjs tests/linkConsentDiagnostics.test.mjs` | 0 | PASS, 14 tests |
| `python3 scripts/interop/test_v164_phone_ui_outcome.py -v` | 0 | PASS, 16 tests |
| `node node_modules/typescript/bin/tsc --noEmit`; targeted ESLint | 0 each | PASS; exact argv in receipts |
| `python3 /delivery/kotlin-regression.private.py` | 0 | PASS, six pure Kotlin cases; compile/run exits 0 |

The Kotlin cases cover targets above/below the current page, boundaries, strict
action caps, absent content and delayed response readiness. Post-commit build,
source and delivery receipts under U bind the new clean commit and exact APK
pair. APK build and fresh Android acceptance are **NOT_RUN** at this source
checkpoint; a later build receipt does not establish live acceptance.

## Evidence index

Only safe status fields, stage names, booleans, and evidence hashes are recorded
here; proof bodies, request payloads, and raw signer material are omitted.

| Evidence | Path | SHA-256 |
|---|---|---|
| Android artifact attribution | `E/android-artifacts.json` | `f02c9d7db12dc9a6954fbd5b1b92c41cea80328b3c32f438223d4f9d64963ab9` |
| SOURCE enrollment/capabilities | `E/link-v164/receipt-source-enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities-fd9b694408fb.private.json` | `fd9b694408fb0dfb1b61fc85b3ade985dc6cbea055c053db1f35300a8b543508` |
| SOURCE independent pins | `E/link-v164/receipt-source-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-8609f70b1022.private.json` | `8609f70b102204fdbe69b7ae219ab71d5f97d7a0bcf07b6e5d50c38bfe58d0fb` |
| SOURCE KEY fresh status | `E/link-v164/receipt-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus-291f140ebfe9.private.json` | `291f140ebfe94740bb5547b142cd03560938c25a9f033a911c9f66628b49da03` |
| SOURCE policy fresh status | `E/link-v164/receipt-source-submitsHostSignedPolicyProofAndRevalidatesFreshV164Status-61297d1f1945.private.json` | `61297d1f1945569708a47b7edc09af262b3e3cbe00955bf88705960f00b4288a` |
| TARGET enrollment/capabilities | `E/link-v164/receipt-target-enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities-9c52a3f24460.private.json` | `9c52a3f244607b2f0c6391d48f8614f6945c1e29f6546bd625183d1f5edf143c` |
| TARGET independent pins | `E/link-v164/receipt-target-confirmsIndependentOwnerPinsWithoutClaimingPhoneUiApproval-a95a01be1082.private.json` | `a95a01be1082a4f9c9df56b3d10c60f19349a0b53fdba3550ca0b9b74506bd75` |
| Target UI review | `O/target-key-rn.phone-ui-review.redacted.json` | `0c24436802706708c3559deab7640c0133a2530db6450974083d834074d7dec3` |
| Target UI prepare | `O/target-key-rn.phone-ui-prepare.redacted.json` | `16232693e3eac5033c14cf74a884741478c1ec742502a26ac5ec2046ce31a5f8` |
| Target UI consent | `O/target-key-rn.phone-ui-consent.redacted.json` | `0edb28a93d5d04ad2daec7e7e3e7c06b5924402b1998a16267a93d7a4ae54583` |
| Target submit progress | `O/target-key-rn.phone-ui-submit-progress.redacted.json` | `9f303fc1e7c9942490bad40bf6183a917fb221f3ad6e436f5807eb7d0793db3f` |
| Target UI result | `O/target-key-rn.result.redacted.json` | `a71e8d796b16f2671204166731940c62167dee5842840b93748835282db29d06` |
| Target JUnit log | `O/target-key-rn.instrumentation.private.log` | `024b193d12b8b3e04a4f7f96aef984376f6d311fe9be8d91568caac8ab6a3820` |
| Canonical launcher terminal | `L/terminal.private.json` | `06278f1cda23961762adf239a80d952afb84f27be03d12dee5a25018b8b11ec5` |
| Core independent closure (20,175 bytes) | `R/evidence/attempt-08/independent-core-closure.redacted.json` | `758742e9a95a75d98a20413f1664d857d2614c05722f01ad88aa99c46338f356` |
| Core two-resource cleanup (406 bytes) | `R/evidence/attempt-08/cleanup-1791083097337692886.json` | `b81e31083f6832bd5fdde22f7e8762d83134a15b53d9efa5d584e2cca3890222` |
| Android teardown | `E/android-teardown.redacted.json` | `3e53b257a2ce320b1926c26352e04ba1a9e918500b09dea3f8d109fd2b86f819` |
| Successor JavaScript tests | `U/js-tests.receipt.redacted.json` | `087d9dac16464ba757fbdaa2c2a2a6f0fb8ed49e60a51ebb2961dfa2b5bf86e8` |
| Successor Python tests | `U/python-tests.receipt.redacted.json` | `28177a6e2ce695cae8fc0f01ae0d8e55c9a137025f42934275f447bbd98f8f35` |
| Successor TypeScript check | `U/typescript.receipt.redacted.json` | `2331c62ba1e308361d4a828a074b32855a4da5b3eb877ffee982cb8e36fb817a` |
| Successor ESLint | `U/eslint.receipt.redacted.json` | `4307a7ef8a452d8f0c523c2c7d93abda14a0f84574f3546c1217ae8b4c821a3d` |
| Successor Kotlin Docker regression | `U/kotlin-regression.receipt.redacted.json` | `fefcc7d11b4a0a467c9be877d116b1dcb84a6b23ad94f1aaebab49175c73f139` |
