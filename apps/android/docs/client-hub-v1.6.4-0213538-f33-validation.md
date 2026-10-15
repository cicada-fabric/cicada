# Client-Control v1.6.4: F33 validation and consent-control correction

## Fixed target and tested artifacts

F33 exercised Client `906c7b0d0434b569336060a33697ff96e9ec7948` against the
following clean Core target. Its results apply only to that APK pair.

| Target | Fixed value |
|---|---|
| Core commit | `0213538b62ccf2533eccf546c80fc848804ea8e0` |
| Contract / wire / schema / operations | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source state | `source_dirty=false` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| App APK SHA-256 | `397029c61950133ba986e7cb0f108d73f7c727c27dcf619df323c9f1e1545cc3` |
| Test APK SHA-256 | `7a8a54806874791ff4a313995fd4a0a29a4682a5f5777b1dddc72d916ed689eb` |

The installed APK copies matched these hashes. The owned emulator ran Android
15, API 35, x86_64, with emulator property `1` and image
`sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f`.
The bootstrap began with Docker network `none`. Binding and encrypted runtime
capability checks are separate from bootstrap metadata.

Evidence roots, outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f33-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f33-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f33-0213538-main-20261004/outbox`
- `R=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-33-clean021-20261004`
- `D=/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/driver-inputs`
- `S=/gpu1-share/data/cicada-client/v164-f33-consent-control-viewport-20261004`

## Actual commands and exits

The immutable `L/command-journal.private.jsonl` contains the complete executed
argv, deadlines, elapsed times and output hashes. The table shows command
prefixes; omitted arguments remain in that journal, rather than being copied
into public documentation. These commands are historical evidence, not retry
instructions.

| Stage / command prefix | Exit | Outcome |
|---|---:|---|
| `python3 D/v164-acceptance-boot.py --run-id …` | 0 | PASS; launcher elapsed 37.441 seconds |
| `python3 D/v164-link-consent-android.py E bootstrap-preflight` | 0 | PASS |
| `python3 D/f20-client-coordinator.private.py prepare …` | 0 | PASS |
| `python3 D/f20-bind-boot-artifacts.private.py --run-id …` | 0 | PASS |
| `python3 D/v164-link-fixture-carrier.private.py --fixture-root R …` | 0 | Exited and waited during cleanup |
| `python3 …/v164-acceptance-hot.py --evidence-root E …` | 0 | PASS |
| `python3 D/f20-root-flow.private.py --delivery-pins …` | 1 | FAIL; 103.383 seconds; not timed out |
| `python3 D/v164-android-deterministic.py E stop` | 0 | PASS |

The Target UI instrumentation process exited `0`, but JUnit reported **one test,
one failure**, in 30.43 seconds. The strict classifier returned `JUNIT_FAILED`.
Process exit zero does not establish Android test success.

## Android gates

| Gate | F33 result |
|---|---|
| SOURCE enrollment and encrypted `session.capabilities` | **PASS**; exact v1.6.4 and catalog verified |
| SOURCE independent Owner pins | **PASS**; no phone confirmation claim |
| SOURCE KEY submit and fresh grants read | **PASS**, partial: SOURCE `ACCEPTED`, TARGET `MISSING`, bilateral false |
| SOURCE `NONE` submit and fresh policy read | **PASS**, partial: grant SOURCE `VERIFIED`, TARGET `MISSING`, current false; fresh policy head version 0 / `NONE`, both side statuses `MISSING`, bilateral false |
| TARGET enrollment, encrypted capabilities and independent pins | **PASS** |
| Real RN review preparation and external signer handoff | **PASS** at `REVIEW_READY`; request exported from actual UI |
| Current request hash, canonical proof binding and exact proof-field text | Passed before the failing control lookup; these checks do not establish consent |
| Target confirmation-control lookup | **FAIL**: `CONTROL_MISSING`; candidate/enabled counts 0; busy and proof readiness unknown |
| RN confirmation click, native Alert and Target KEY Hub grant | **NOT_RUN** |
| Target `NONE` and bilateral KEY / `NONE` | **NOT_RUN** |
| Native Worker/model consumption, physical Android and public HTTPS | **NOT_RUN** |

The actual compiled Android selector receipts and their `OK (1 test)` logs
establish the earlier encrypted gates. The inherited `bootstrap_only` annotation
in wrapper artifact metadata describes bootstrap; it does not negate these
independent RPC receipts. External signature counts do not establish Hub
acceptance or a phone confirmation.

## Failure and minimal correction

The failure was `Consent confirmation control did not become ready:
CONTROL_MISSING`, at `LinkConsentPhoneUiTest.kt:281`, called from line 495.
The test found no matching visible consent control during its 20-second wait.
The receipts contain no accessibility tree, so the underlying disappearance or
selector mismatch remains **UNKNOWN**. They do not prove a keyboard, proof
validation, DTO, lifecycle or Hub rejection defect.

The original proof handoff contained 6,520 Base64 characters. Its multiline
editor had no display-height bound, while the control wait only polled after
a substring-based label scroll. The successor limits that editor to 120 display
units, retaining its complete value and original 21,848-character limit. Its
instrumentation selects only the app window, accepts the literal or exact
package-qualified test ID, preserves disabled/nonclickable candidates, and
performs at most 12 app scroll actions within the original 20-second deadline.
It never scrolls the proof editor to substitute for the page scroll.

Only a unique, visible, enabled, clickable control with the exact ready hint
can be activated. The original nine-field receipt, complete request hash,
canonical proof bytes, independent pins, expiry, lifecycle, typed guards, native
Alert scope checks and subsequent bilateral-status checks remain required.
This correction has not yet passed live Android acceptance.

## Pending outcome and cleanup

The canonical terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`** at
`2026-10-04T00:52:10.330Z`. No retry was made. Preserve the historical host pending
marker; the actual native RPC pending state was not exported and remains
**UNKNOWN**. Do not create a replacement operation to repeat F33.

The emulator teardown and an independent exact-container inspect confirmed
absence (`docker inspect` exit `1`). Core's actual two-resource receipt records
container and network removal exits `0`, `OWNED_CLEANED`, private fixture deletion
and zero model calls. The separate empty cleanup receipt cannot replace it.
Core independently checked exact resource absence and all eight private path
classes. Its marker confirms nonce use and ACK before the original hard deadline.

The Core closure labels one frame, actor true-wait exit `-15` and one ACK exit
`0` as Main-thread attestations; they are not Core-parent-held process results.
Five Core signature records (SOURCE 3, TARGET 2) do not prove accepted Hub sides.
Target `NONE` was not signed. F31 and F32 business flows were **NOT_RUN**;
F32 stopped after a launcher-wrapper parse error before its idle deadline.
Their orchestration outcomes do not change F33 or certify the successor.

## Successor offline checks and artifact boundary

Docker root was independently checked as `/gpu1-share/data/docker-root`.
The following affected checks ran with `--pull=never --network=none`, pinned
build image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
and unchanged source hashes during each check.

| Inner command | Exit | Result / receipt under S |
|---|---:|---|
| `node --test tests/linkConsentFlow.test.mjs` | 0 | PASS, 11 tests; `js-tests.receipt.redacted.json` |
| `python3 scripts/interop/test_v164_phone_ui_outcome.py -v` | 0 | PASS, 11 tests; `python-tests.receipt.redacted.json` |
| `node node_modules/typescript/bin/tsc --noEmit` | 0 | PASS; `typescript.receipt.redacted.json` |
| Targeted ESLint | 0 | PASS; `eslint.receipt.redacted.json` contains exact argv |

The commit containing this report is the successor source checkpoint. At that
checkpoint its post-commit APK build is **NOT_RUN**. The subsequent
`S/apk-build.receipt.redacted.json`, `S/source-inputs.final.frozen.json` and
`S/delivery.receipt.redacted.json` bind the exact clean Client commit, one APK
pair, 26 frozen source references and six APK pin files. Fresh Android UI,
bilateral consent, recovery faults, physical-device and public HTTPS acceptance
remain **NOT_RUN** until a separately authorized Root run supplies actual results.
No production deployment, new dependency, Owner key import, push or merge is
part of this milestone. Ordinary cross-user messages remain closed while
`external_thread_links=false`.

## Evidence index

| Evidence | Path | SHA-256 |
|---|---|---|
| Actual command journal | `L/command-journal.private.jsonl` | `08b3bdddf3975c9c597871a67d886f0e30efc35e8dfc20253069c1ce791b5e51` |
| Canonical terminal | `L/terminal.private.json` | `397137840c8bf28443513245f1debd9f00f6c48a0b0fbee44dc2de9c49a786e8` |
| SOURCE encrypted enrollment/caps | `E/link-v164/receipt-source-enrollSourceOwnerDeviceGrantAndVerifyFreshCapabilities-53a28a796cf3.private.json` | `53a28a796cf3b4755654148964f3dec1fc010f1cd1ae6ce15f62260d0c985410` |
| SOURCE KEY fresh status | `E/link-v164/receipt-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus-ca430b75b8b3.private.json` | `ca430b75b8b30bd8ffaef45b8a7f684576570e69b3fd9bf0048a859aa18e8db9` |
| SOURCE NONE fresh status | `E/link-v164/receipt-source-submitsHostSignedPolicyProofAndRevalidatesFreshV164Status-8fe644b56371.private.json` | `8fe644b56371f78df0bbb97de80f6575580a9accf056124a8cfe2f0dc77216a0` |
| TARGET encrypted enrollment/caps | `E/link-v164/receipt-target-enrollTargetOwnerDeviceGrantAndVerifyFreshCapabilities-9bc50503959f.private.json` | `9bc50503959f24383dd243fcc8e6458b4a76923333a2fdf850dc466743cd12c7` |
| Target preparation | `O/target-key-rn.phone-ui-prepare.redacted.json` | `0a36dc0dc9b1fc7a1252f8189f075621cb8ee0ad85cf6fdbeb1128a1a07ae6c4` |
| Target actual UI request handoff | `O/target-key-rn.phone-ui-review.redacted.json` | `8f978be5877332f39f9f56107a1632bb2425a24b55fc573f4c5c59cbce7a0811` |
| Target control-stage receipt | `O/target-key-rn.phone-ui-consent.redacted.json` | `0d19cd169712790fa20d20214c752e1c837fe5d3d35332d96788af4acbcddb88` |
| Actual Target JUnit log | `O/target-key-rn.instrumentation.private.log` | `94001fa141e2cc020a401a3124868f712ccb23c44cd3fc335cfc4361585d4d3c` |
| Target strict result | `O/target-key-rn.result.redacted.json` | `a926c992bd1cbc70f235c85dcc2659b666421c41c360bdd280692272ffdc1110` |
| Emulator teardown | `E/android-teardown.redacted.json` | `b18f5aaba7a5646f39de39d8cc87890af354a944f45b6aa23655e8c9f1297446` |
| Core independent closure | `R/evidence/attempt-08/independent-core-closure.redacted.json` | `dc1db57562e33aa20ec3cdd665921e75351206899935039d9520ae871d547c6b` |
| Actual two-resource cleanup | `R/evidence/attempt-08/cleanup-1791075131286104564.json` | `ed7194a269105d6ba6c1d40043aa50e17fd410fbf9dcb34ad91bbe8edcf392fc` |
| Successor JavaScript checks | `S/js-tests.receipt.redacted.json` | `45ffe22042f3c6143415bd7742d13dd28ffb9aa8fe48f9ebe6ce96d346eab532` |
| Successor Python checks | `S/python-tests.receipt.redacted.json` | `f1d4c3ee4ef40c12d827edfcb312795eb4bf135ed3a00599bcda15e35ddd7cd9` |
| Successor TypeScript | `S/typescript.receipt.redacted.json` | `b340201a99f07085bbf4115f9cba0f87fcd8ffa2cbb230bece2aca4140f98efc` |
| Successor ESLint | `S/eslint.receipt.redacted.json` | `09ab44750fefecafc5d24aeaefad04d4fd7e5b937b341ac4592fa13f0e543ca0` |

## Core coordination prompt

```text
Preserve F33 FAIL / OUTCOME_UNKNOWN_PRESERVE_PENDING and all prior outcomes.
Do not retry its packet, invent a replacement operation or equate signature
handoff/control readiness with actual phone consent. Review the successor's
clean Client commit, exact app/test hashes, delivery receipt and 26-source
closure before scheduling a fresh Root-only bounded run against clean Core
0213538b62ccf2533eccf546c80fc848804ea8e0 / client-hub-v1.6.4. Reuse only the
corrected controller implementation, with new BOOT/READY, Scope/GO and current
pins; do not reuse any expired authorization, actor inbox, proof or deadline.
Require actual JUnit success, the full native Alert, Target KEY grant and fresh
bilateral status, then Target NONE with independently verified current policy.
Record every gate separately and perform stop/wait, one ACK and owned cleanup.
Physical Android, native Worker and public HTTPS remain separate NOT_RUN gates.
```
