# Client-Control v1.6.4: F37 Target list and consent validation

## Fixed target and tested APK pair

F37 ran Client commit `8e24b14a1f1eb80188e6e11b9f16d53d6afaf91d` against the
fixed clean Core target. Findings apply to this APK pair only.

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
| App APK SHA-256 | `06698b9a6cf47f10592f45e1f0b3fcbf24cead9333e2c9cfeba96c16e68ab487` |
| Test APK SHA-256 | `624e48439792ffff2e8779409d02ec33c28ab19c11e53bea73e2366ac03507d7` |
| Runtime | Android 15 emulator, API 35, x86_64 |

Evidence roots outside Git:

- `E=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f37-0213538-main-20261004/android`
- `L=/gpu1-share/data/cicada-client/v164-f37-0213538-launcher-20261004`
- `O=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f37-0213538-main-20261004/outbox`

## Observed stages and JUnit result

| Gate | F37 result |
|---|---|
| Target list refresh | **OBSERVED**: `MATCH_FOUND`, read state `OK_NONEMPTY`, one row, target present and visible, one scroll action returned |
| Target consent review | **WAITING_FOR_EXTERNAL_OWNER_SIGNATURE**; review receipt says a signer request was exported from the real UI; request contents are omitted |
| Target preparation | **PASS** at `REVIEW_READY` |
| Target consent control | **PASS** at `CONFIRM_READY`; proof ready, one enabled control, not busy |
| Submit progress | **OBSERVED** through callback, scope guard, dispatch, native bridge resolution, and `UI_RESPONSE_RETURNED`; observer says `native_ok=true`, `viewport=VISIBLE` |
| JUnit | **FAIL**: one failure in 43.344 s; the 30-second `SOURCE ACCEPTED` lookup failed at `kt753`; helper stack location `scrollToText` line 482; redacted error type `RuntimeError` |
| Target current grant / bilateral status | **UNKNOWN / NOT_ESTABLISHED** |
| Target `NONE` | **NOT_REACHED**; complete bilateral check at `kt754` was not reached |
| Native Worker, physical Android, public HTTPS | **NOT_RUN** |

The submit-progress sequence is `RN_CONFIRM_CLICKED`, `CONFIRM_OPENED`,
`ALERT_VERIFIED`, `ALERT_POSITIVE_CLICKED`, `CALLBACK_ENTERED`,
`SCOPE_GUARD_PASSED`, `REVIEW_CONSUMED`, `UI_SUBMIT_DISPATCHED`,
`NATIVE_BRIDGE_ENTERED`, `NATIVE_CALL_STARTED`, `NATIVE_RESOLVED`, and
`UI_RESPONSE_RETURNED`. The progress receipt reports
`promise_in_flight=false`, `native_packet_pending=UNKNOWN`, and
`reconciliation_required=null`. `native_session_methods_called_by_test=false`
means the instrumentation did not directly call a Native Session method; it
does not erase the separately observed app bridge submit.

At `kt751`, the test searched for the reread label; `clickLabel` at `kt752`
returned. It then failed the 30-second `scrollToText("SOURCE ACCEPTED")` lookup
at `kt753` (helper stack location `scrollToText` line 482). The complete
bilateral assertion at `kt754` was not reached. The refresh callback/result
and SOURCE status value were not retained. The submit observer's
`native_ok=true` and `viewport=VISIBLE` do not establish the current Target
grant. The unique failure cause remains **UNKNOWN**; this is distinct from
F35's response-text `NOT_VISIBLE` failure.

## Terminal and cleanup

The launcher terminal is **FAIL / `OUTCOME_UNKNOWN_PRESERVE_PENDING`**. No
retry is supported by this evidence. No separate Root ACK attestation or
independent Core closure is included in the reviewed F37 packet; no Core
acceptance or cleanup result is inferred. Android teardown and the separate
emulator absence check both report **PASS**. Physical Android and public HTTPS
remain **NOT_RUN**.

## W selector successor boundary

The next checkpoint is `W=/gpu1-share/data/cicada-client/v164-f37-key-status-viewport-20261004`.
It adds a fixed test ID to the reread action and requires a unique, actually
visible, enabled, clickable match before one click. It requires the fixed status
message to have actual visible text, searches backward and forward with at most
12 actions per direction within 30 seconds, and excludes `EditText` scrolling.
Recognized failed or non-accepted status messages fail the test; the existing
complete bilateral assertion remains required. This selector change does not
alter Hub, Native, cryptographic, Guard, or catalog behavior.

The F37 list and submit receipts do not prove that a unique selector caused the
failure: the status-read result and its viewport were not retained. The five
focused offline checks in W passed with unchanged source hashes:

| Command | Result | Receipt SHA-256 |
|---|---|---|
| `python3 W/focused-check.private.py js-tests` | PASS, 17 tests, exit 0 | `ed599ffeac0774367539008bd0eb4cdecf9f508747f1a6417fa08f5e771db4dd` |
| `python3 W/focused-check.private.py python-tests` | PASS, 23 tests, exit 0 | `5083fb77dd658a30e5bd90e25552afe20f248e0cf338523a7ae92050d655416c` |
| `python3 W/focused-check.private.py typescript` | PASS, exit 0 | `aad5a0518cedf9d0cd4024fc0b9326329a4694341cc02404463a0193954ab983` |
| `python3 W/focused-check.private.py eslint` | PASS, exit 0 | `bbb401f52cbec64d0b3679a743e061331d930fce3097f4e0de9883634e50e76e` |
| `python3 W/focused-check.private.py kotlin-regression` | PASS, 19 pure cases (10 viewport, 9 list), compile/runtime exit 0 | `0171d5aa67ba3410cec736a1d793e0e9920ab852632dd847d6686939097c1fb9` |

At this source checkpoint, the post-commit APK build and fresh live acceptance
are **NOT_RUN**. External
immutable receipts under W must bind the exact new commit, app/test pair, and
26 frozen references.

## Evidence index

Only safe phase names, result enums, booleans, bounded counts, and evidence
hashes are recorded. Request/proof contents, identifiers, credentials, and raw
JUnit contents are omitted.

| Evidence | Path | SHA-256 |
|---|---|---|
| Android artifact attribution | `E/android-artifacts.json` | `573611215c0772bd3e4f556d731c69f0ae1135fda3a17b8eeb695266b8799d06` |
| Target list refresh | `O/target-key-rn.phone-ui-list-refresh.redacted.json` | `36a33c2b81fb0c7562ee9fd49d33dcd56c4cb8608a0486ef37719ea706c0c711` |
| Target consent review | `O/target-key-rn.phone-ui-review.redacted.json` | `eda173568a638e466fdf645528e33fd93962b44c69ef850e5270533275a57125` |
| Target preparation | `O/target-key-rn.phone-ui-prepare.redacted.json` | `debc0f8575b5dc3fa392f64d4d9a363bda4ff26a444c5ab12e63b021ac8f4eea` |
| Target consent control | `O/target-key-rn.phone-ui-consent.redacted.json` | `05bfbc4fc9309d5c5bbeef328ce394bc5001121426c7ebf12287eb856dfa63e9` |
| Target submit progress | `O/target-key-rn.phone-ui-submit-progress.redacted.json` | `f7d33858aa3f0fc79663249d90b41d5a1cf0952adcb83264cd95aa1186bc9fc9` |
| Target UI result | `O/target-key-rn.result.redacted.json` | `2886a21e844e4defde04a622cf6538a83db6960cb8aa1d5228d1ac74639a1d18` |
| Target JUnit log (hash only) | `O/target-key-rn.instrumentation.private.log` | `4073716f302670b50157b90cae762813db41df37c8d8c67281171469515eb367` |
| Canonical launcher terminal | `L/terminal.private.json` | `096dd3aabc70cd2088840ab571bd712bb217829496fe9fd0baf564cb85b21537` |
| Android teardown | `E/android-teardown.redacted.json` | `fed9bf28a77be6de442534c61a34805784fc3610792df9593bc756ac44f7a99e` |
| Emulator absence check | `E/emulator-absence-check.redacted.json` | `5ec76034376e8772bbac2b6697a5bf19a8adde6749603c1a585928e1f5af2d81` |
