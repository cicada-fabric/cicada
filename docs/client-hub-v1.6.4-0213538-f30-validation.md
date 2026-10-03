# Client-Control v1.6.4: F30 validation

## Target and artifact attribution

F30 used the fixed clean Core `0213538b62ccf2533eccf546c80fc848804ea8e0`
and the app/instrumentation APK pair built from Client commit
`b19e84b66cae3887c64cb9e576f11b3cf55f6eee`.

| Fixed target | Value |
|---|---|
| Contract revision | `client-hub-v1.6.4` |
| Contract archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Source state | `source_dirty=false`; wire `1`, schema `57`, operations `55` |

| Artifact | SHA-256 |
|---|---|
| App APK | `5f242041c85bb1a2b83c2a0af4f90d3be3abbc26e90a8483bc8703b9d9bc6749` |
| Instrumentation APK | `f236c816218026deea3941bb9a75899ae83d450ca875d4b21dc14bd4dc126d48` |
| APK build receipt | `P/apk-build.receipt.redacted.json`, SHA-256 `50319a996cec87600919a102e53f446e5c531ae7cf5b387b203d96e97d6c4cb0` |
| Delivery receipt | `P/delivery.receipt.redacted.json`, SHA-256 `63e8736faf111800f431d32ce503dbf5854943c934f16c1abfdfb94825f9c0fa` |

This run used an actual Root BOOT and GO. The indexed BOOT SHA-256 is
`03da4d87c3290e9ed5930b52d017b0f5ecee5d0534ece41a66328bbb29eb0c35`; the
Root GO SHA-256 is `05d390031ead87eaa31caaa31868dea624dfe752d21db14ea9ef5898344dbab4`,
bound to Scope SHA-256
`57e5e7330ea3799b50515f393bcd2f7dc39e36e153371c9ea27cacfbe5d93e4c`. The
live checker passed with `391.828` seconds remaining in the original budget at
the check. The business plan bound the three exact Root references; the
authorized Scope bound 27 fields and nine public references. One
Root business frame was delivered through the retained TTY. The review-only
proposal and pin bundle below are provenance inputs; neither alone is an
authorization.

| Review-only input | SHA-256 |
|---|---|
| `P/business.F30.NONAUTH.proposal.private.json` | `d3aa272e7dc46431f0e99c292cf35a565932def22f50e01e639224603837693f` |
| `P/root-delivery-pins.F30.NONAUTH.proposal.private.json` | `bae83d25955839d2b63bff90c44db947f4a42837b65e3c9ca224751b8316f68b` |

Evidence roots:

- `P=/gpu1-share/data/cicada-client/v164-f28-phone-ui-diagnostic-20261003`
- `L30=/gpu1-share/data/cicada-client/v164-f30-0213538-launcher-20261003`
- `E30=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f30-0213538-main-20261003/android`
- `N30=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f30-0213538-main-20261003`
- `R30=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-30-clean021-20261003`

The fixed Core archive, catalog, and image identities are listed in the
[F24–F28 report](client-hub-v1.6.4-0213538-f28-validation.md); F30 used that
same pinned Core target.

## Actual commands and outcome

The launcher journal records these exit codes. F30 ran from `16:27:09Z` to
`16:37:50Z`; the flow itself was not timed out.

| Stage | Exit | Recorded result |
|---|---:|---|
| Android bootstrap | `0` | PASS |
| Bootstrap preflight | `0` | PASS |
| Prepare | `0` | PASS |
| Bind | `0` | PASS |
| Carrier | `0` | PASS |
| Hot preflight | `0` | PASS |
| Android flow | `1` | Failed after `97.673` seconds; JUnit reported one failure. |
| Emulator stop | `0` | PASS |

Core scope, prepare, and finalize stages each exited `0`. Core indexed one Root
frame, five signature records, and zero retries. The terminal at
`2026-10-03T16:37:50.651170Z` records `FAIL` and
`OUTCOME_UNKNOWN_PRESERVE_PENDING`. The actual encrypted-operation outcome is
unknown; no retry occurred and the host pending marker remains preserved.

## Encrypted flow and phone confirmation

| Gate | F30 result |
|---|---|
| SOURCE enrollment, encrypted capabilities, and independent pins | **PASS**. |
| SOURCE KEY submit and fresh side status | **PASS**, partial: SOURCE accepted, TARGET missing, `bilateral=false`. |
| SOURCE `NONE` terminal result and fresh policy status | **PASS**, partial only: `grant_current=false`, SOURCE grant status verified, TARGET missing; policy SOURCE/TARGET both missing and `bilateral=false`. The receipt reports `phone_confirmation=false` and `native_confirmed=true`; neither establishes bilateral consent. |
| TARGET enrollment, encrypted capabilities, and independent pins | **PASS**. |
| Target KEY phone-UI preparation | **PASS** at `REVIEW_READY`. A Target signing request and proof handoff were produced. |
| Target explicit confirmation control | **FAIL** in JUnit test `kt386`: automation could not resolve a unique `核对并明确授权` control. Earlier proof input checks passed for canonical bytes, request binding/current request hash, `ACTION_SET_TEXT`, and exact field text. |
| Positive confirmation Alert and Hub acceptance of Target KEY | **NOT_RUN**. |
| Target `NONE` and bilateral KEY/`NONE` status | **NOT_RUN**. |

The failed selector step does not identify its underlying UI cause, which
remains **UNKNOWN**. Do not infer a missing versus duplicate control, or an API,
DTO, or lifecycle defect. The Target preparation receipt is not phone approval
and does not establish Hub acceptance.

The instrumentation report has one test and one failure. Flow exit `1` is a
test failure, not a timeout. The target signing request/proof handoff exists,
but the actual native RPC state is **UNKNOWN** because it was not exported.
The original host pending marker is preserved. No retry or new operation was
sent after the failed confirmation step.

## Terminal cleanup and acceptance boundary

The Client emulator stop exited `0`. Core stopped its actor with exit `0`; the
held process exited `143` after the authorized SIGTERM. The single terminal ACK
exited `0` before the original hard deadline `16:42:39Z`. Core's owned cleanup
receipts passed: both resource removals exited `0`, exact absence was checked,
and all eight indexed private path classes were absent. The fixture recorded
zero model calls. Cleanup applies only to F30-owned resources.

F30 does **not** establish Target phone confirmation, Target KEY Hub acceptance,
Target `NONE`, or bilateral consent. Physical Android, public HTTPS, and real
native Worker execution remain **NOT_RUN**. Ordinary cross-user messaging
remains unavailable while Core advertises `external_thread_links=false`.

## Checks and pending minimal-fix checkpoint

The 18 focused checks (7 Python and 11 JavaScript), TypeScript, targeted ESLint,
and the single APK build were attributed to commit `b19e84b66cae3887c64cb9e576f11b3cf55f6eee`
and the APK pair above. They do not validate a later UI correction.

A follow-up consent-control checkpoint implements a stable target test ID,
tooltip/View ID diagnostics, test-state restoration, and a bounded 20-second
wait for one enabled and clickable confirmation control. Its strict nine-field
receipt rejects payloads, wrong-run values, duplicates, invalid types, and
unsafe values. The checkpoint passed 22 focused tests (11 Python and 11
JavaScript), plus TypeScript and targeted ESLint checks. The Python suite passed
exit `0` at
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/python-tests.receipt.redacted.json`,
SHA-256 `7551858cd7a3f7ab135ddda1e1e1eb52889017815653bdbc56a082b8263ea5eb`.
JavaScript tests receipt:
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/js-tests.receipt.redacted.json`,
SHA-256 `1e978f18492a3554a358fae520eeaaaa931defba5e4603d686ef7f2f55064158`.
TypeScript receipt SHA-256 is
`497a870f2bdebae5e7c210ecf5573f54c0cfc8c807b465020b568c0380933e9e`; targeted
ESLint receipt SHA-256 is
`e8ef8e936ce6b601b127c43b7badfc7f189ffa7d5298e1d2c744541f3ba5e40f`.
The Python tests cover strict field bounds and reject payloads, wrong-run
values, duplicates, invalid types, and unsafe values. These checks apply only
to the bounded offline consent-control checkpoint; the earlier 18 focused
checks, static checks, and single APK build apply only to b19 and its F30 pair.
At this source checkpoint, post-commit APK assembly is **NOT_RUN**; its
subsequent receipt at
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/apk-build.receipt.redacted.json`
will bind the exact source and APKs. A fresh live run remains **NOT_RUN**.

## Evidence index

The following paths are outside Git. This record contains only allowlisted
statuses, test summaries, commands/exits, and hashes. It does not reproduce
credentials, signatures, private keys, raw identifiers, or message payloads.

| Evidence | Path | SHA-256 |
|---|---|---|
| F30 launcher command journal | `L30/command-journal.private.jsonl` | `934f2f5a1c22d0894890cbfa8dac8bcedc0cc500eb0f78d8343c629c6870eaef` |
| F30 terminal | `L30/terminal.private.json` | `94eb4c26ac10a57045efbfd4f3dea946893e372972036f24310fa26d07d0b3ab` |
| SOURCE KEY submit and fresh status | `E30/link-v164/receipt-source-submitsHostSignedCurrentKeyProofAndReadsFreshSideStatus-4b16ec9c28bc.private.json` | `4b16ec9c28bc6a5413074f483f714b7c547554230ffb4c37980300d09895c610` |
| SOURCE `NONE` submit and fresh status | `E30/link-v164/receipt-source-submitsHostSignedPolicyProofAndRevalidatesFreshV164Status-202cbe320e85.private.json` | `202cbe320e856659a496dbb986c785287d3ea3682a9febb714df95ead4c50ae9` |
| Target phone-UI preparation | `N30/outbox/target-key-rn.phone-ui-prepare.redacted.json` | `6b73fec2a9fe3339ca3c40616c2c14bb7c31d09e064b2aa246a43c7c87030f6b` |
| Target instrumentation failure log | `N30/outbox/target-key-rn.instrumentation.private.log` | `e6c243ff7101441e059af043f32f60c7f9de32c30793afa674b086b76ccb1099` |
| Core actor/terminal/owned-closure index | `R30/evidence/attempt-08/stage-actor-terminal-owned-closure-index.redacted.json` | `6971bb1d72fc4157e726fede7daa0b385e09ea3a36a010b1f1c2a4216e02e073` |
| Single terminal ACK | `R30/evidence/attempt-08/terminal-consumer-ack.redacted.json` | `50882eb109969cbf4383e9c0206e9bacc4ff7f7c11c59baefb34fc63b2fc41b5` |
| Owned cleanup | `R30/evidence/attempt-08/cleanup-1791045471968877810.json` | `a3fae659f78a11d419e038c77175e1ce86b98451ce21b7ddcc122d83de52a53a` |
| b19 APK build receipt | `P/apk-build.receipt.redacted.json` | `50319a996cec87600919a102e53f446e5c531ae7cf5b387b203d96e97d6c4cb0` |
| Prior b19 Python checks | `P/python-tests.receipt.redacted.json` | `69807ab64acca5d8d1ea98f2381fd540b5525e7edd24dda2c48aee6033d203cb` |
| Prior b19 JavaScript, TypeScript, and ESLint checks | `P/typescript-tests.receipt.redacted.json` | `3d1d4d53290015813b5ca684974bc752b8fa931ee26d4a1bdbf4c6a56ebec183` |
| New focused Python guard tests | `/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/python-tests.receipt.redacted.json` | `7551858cd7a3f7ab135ddda1e1e1eb52889017815653bdbc56a082b8263ea5eb` |
| New focused JavaScript tests | `/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/js-tests.receipt.redacted.json` | `1e978f18492a3554a358fae520eeaaaa931defba5e4603d686ef7f2f55064158` |
| New TypeScript check | `/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/typescript.receipt.redacted.json` | `497a870f2bdebae5e7c210ecf5573f54c0cfc8c807b465020b568c0380933e9e` |
| New ESLint check | `/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/eslint.receipt.redacted.json` | `e8ef8e936ce6b601b127c43b7badfc7f189ffa7d5298e1d2c744541f3ba5e40f` |

## Next bounded step

```text
Keep the F28 and F29 outcomes unchanged. F30 ended
OUTCOME_UNKNOWN_PRESERVE_PENDING after the Target confirmation test failed;
the native RPC outcome is unknown and the host marker remains preserved. Do
not resend the F30 packet, create a replacement operation, or claim bilateral
consent from the Target signing request/proof handoff.

The bounded consent-control correction and its offline checks are complete;
they do not replace Android instrumentation. Build the APK pair after commit
and bind it to the external receipt at
`/gpu1-share/data/cicada-client/v164-f30-consent-button-wait-20261003/apk-build.receipt.redacted.json`.
Before another live step, require a fresh Root BOOT with actual READY and fresh
GO bound to the exact Client source/APKs, fixed Core target, Scope, and
deadlines. Keep the original
proof, pin, lease, tuple, fence, and six-flow checks; preserve Core Owner
signing custody, one-frame authorization, stop/wait, single ACK, and owned
cleanup. Do not reuse the F30 GO or its proof handoff. If the F30 operation
outcome remains unknown, keep its pending marker. Report every gate separately.
Physical Android, public HTTPS, and real native Worker acceptance remain
NOT_RUN until tested.
```
