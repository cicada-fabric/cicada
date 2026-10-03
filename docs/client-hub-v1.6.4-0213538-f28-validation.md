# Client-Control v1.6.4: F24–F28 bounded validation

## Scope and fixed target

This record covers five successive bounded attempts against clean Core
`0213538b62ccf2533eccf546c80fc848804ea8e0`. It keeps each attempt's failure
and cleanup evidence separate. The full contract provenance is in the
[F19 target record](client-hub-v1.6.4-0213538-f19-validation.md); F20–F23
history remains in the [prior validation report](client-hub-v1.6.4-0213538-f23-validation.md).

| Input | Fixed value |
|---|---|
| Core commit / source dirty | `0213538b62ccf2533eccf546c80fc848804ea8e0` / `false` |
| Core contract / wire / schema / operation count | `client-hub-v1.6.4` / `1` / `57` / `55` |
| Protocol archive SHA-256 | `03a52f999f4b15ef375c180252bcd88561aa7b159b806933c802cc55f539b709` |
| Catalog SHA-256 | `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d` |
| Core source fingerprint | `27a83ef8406da7a4eef4395ac4b2d8e56b554c29f9075fa1f1c22dc12ca545e7` |
| Hub image ID | `sha256:3a71aeee4ae36b35f78b07f819dd0bedb9bca76188366b5a419ae3e237836b23` |
| Interoperability image ID | `sha256:0c11a3f059d93ea3e356399ba68e45ef6e13cf52ec490b7245c44d73cb707c2f` |
| Android emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| F28 Android runtime | Emulator, Android 15, API 35, `x86_64` |

F28 used the APK pair built from Client source
`8b1b6c54eff702918c426827a3673f9a112edbcc`:

| Artifact | SHA-256 |
|---|---|
| App APK | `02b5481da9f3e09c46d02d7e4a853b51d8c2482ceee7b58297ec79a9cbf9a44d` |
| Instrumentation APK | `d1e935afb0edc42f9dc6e3cf19ad78f6a6054553de115972b9f6aea1d3a78dc5` |
| APK build receipt | `KF/apk-build.receipt.redacted.json`, SHA-256 `acd1d9bb2f2a47936060bd19e86528ded9b32fe29875b30a5cf41cf367a37b01` |

The paths below use these evidence roots:

- `KF=/gpu1-share/data/cicada-client/v164-link-metadata-final-20261003`
- `L24`–`L28=/gpu1-share/data/cicada-client/v164-fNN-0213538-launcher-20261003`
- `E28=/gpu1-share/data/cicada-client/v16-deterministic-v164-f6-f28-0213538-main-20261003/android`
- `R28=/home/zyf/CICADA/.cicada-data/client-link-v164-fixture-28-clean021-20261003`
- `C28=/gpu1-share/data/cicada-client/v164-0213538-context-successor-20261003/coordinator-private/runs/v164-f6-f28-0213538-main-20261003`

## Attempt results

All times are UTC on 2026-10-03. In these four cancelled/preparation attempts,
`business=NOT_RUN` means the encrypted business flow was not started.

| Attempt | Actual commands and result | Business outcome |
|---|---|---|
| F24 | Bootstrap `0`, bootstrap preflight `0`, emulator stop `0`; paused at the cold APK-pin closure mismatch. | **NOT_RUN**; terminal `FAIL`. |
| F25 | Bootstrap `0`, bootstrap preflight `0`, emulator stop `0`; budget cancellation before prepare. | **NOT_RUN**; terminal `FAIL`. |
| F26 | Bootstrap `0`, bootstrap preflight `0`, emulator stop `0`; budget cancellation before prepare. | **NOT_RUN**; terminal `FAIL`. |
| F27 | Bootstrap `0`, bootstrap preflight `0`, `prepare-1` `1`, emulator stop `0`. The prepared pins used the inner Hub-ready SHA instead of the raw aggregate READY SHA. | **NOT_RUN**; terminal `FAIL`. The original mismatch remains recorded. |
| F28 | Bootstrap `0`, bootstrap preflight `0`, prepare `0`, bind `0`, carrier `0`, hot preflight `0`, flow `1` after `100.391` seconds, emulator stop `0`. | Encrypted SOURCE-side work completed and TARGET setup reached independent pins; the Android test failed before Target KEY. Terminal outcome remains **`OUTCOME_UNKNOWN_PRESERVE_PENDING`**. |

F24 ran from `13:17:27Z` to `13:20:20Z`; F25 from `13:28:16Z` to
`13:40:51Z`; F26 from `13:42:05Z` to `13:58:59Z`; F27 from `14:19:56Z` to
`14:31:44Z`; F28 from `14:46:21Z` to `15:00:25Z`. F27's one-field READY
binding calibration is recorded at `KF/f27-aggregate-ready-calibration.redacted.json`,
SHA-256 `6c87c31a73237fd9b02f1029a9dda4228099ef6f6a5d31885751a4392f8564c2`.
F28 used that raw aggregate READY digest in its plan and passed preparation,
binding, and hot preflight. This corrected the plan-data blocker; it did not
change the consent checks or establish their full success.

## F28 Android and encrypted-flow results

The Android test report records one JUnit failure after clicking the current
proof-read button: `kt295` failed while waiting for the scope row at
`scrollToText(" → ")`. The instrumentation command returned exit `0`, but
JUnit reported **one failure in 26.405 seconds**; this is not a test pass. The
launcher consequently recorded flow exit `1` after `100.391` seconds. The
observed UI failure does not establish the underlying preparation cause, which
remains **UNKNOWN**.

| Gate | F28 result |
|---|---|
| SOURCE enrollment, encrypted capabilities, independent pins, and fresh status after KEY | **PASS**. Hub status was SOURCE accepted, TARGET missing, `bilateral=false`. |
| SOURCE `NONE` terminal result and partial status | **PASS**. `current=false`, `bilateral=false`. |
| TARGET enrollment, encrypted capabilities, and independent pins | **PASS**. |
| Target KEY request and Owner signature | **NOT_RUN**. |
| Positive Target React Native confirmation/Alert | **NOT_RUN**. |
| Target `NONE` and bilateral KEY/`NONE` | **NOT_RUN**. |
| F28 business completion | **FAIL / OUTCOME_UNKNOWN**; the launcher/coordinator pending marker remains preserved. |

The Target signing request was not exported (`request_sha256=null`). This is
evidence of a pending coordinator phase, not proof that a Target grant packet
was created. No Android session-state file or ciphertext was exported, so the
underlying RPC pending state is **UNKNOWN**. The new diagnostics do not clear
native pending state, reset counters, or retry an operation.

The sanitized Core closure index records one Root business frame, zero retries,
four signature slots (SOURCE device grant, SOURCE KEY grant, SOURCE `NONE`
policy, TARGET device grant), and one coordinator terminal ACK. The owner actor
was stopped by the authorized SIGTERM path and its held process exited `143`;
the one ACK command exited `0`. The terminal result is `FAIL` with
`OUTCOME_UNKNOWN_PRESERVE_PENDING`; signing receipts and partial SOURCE status
do not establish bilateral acceptance.

F28 cleanup passed for the owned emulator, carrier, Hub, and network. The
Android teardown receipt reports the emulator removed; its final absence
inspection exited `1` because the expected object was absent. Core's final
owned-resource cleanup receipt reports `OWNED_CLEANED`, with two removal commands
at exit `0`, zero model calls, and the private fixture deleted. Both exact
absence checks report not-found (expected exit `1`), and all eight indexed
private path classes are absent. This evidence is limited to resources owned
by F28.

## Offline evidence and current build state

At source `8b1b6c54eff702918c426827a3673f9a112edbcc`, the cached focused Kotlin
host regression passed **29 tests**, exit `0`; receipt `KF/kotlin-host.receipt.redacted.json`,
SHA-256 `3a9c7de5acf50ffd3da7ea17d0d66143396a49d91463b1aec0093feab912283a`.
These host tests and the listed APK pair are bound to that source and do not
turn the F28 live failure into acceptance.

After F28, the bounded phone-UI diagnostic has the following Docker checks:

| Check | Result |
|---|---|
| Focused Python outcome-guard tests | **PASS**, 7 tests, exit `0`; receipt SHA-256 `69807ab64acca5d8d1ea98f2381fd540b5525e7edd24dda2c48aee6033d203cb`. |
| Focused JavaScript tests | **PASS**, 11 tests, 0 skipped, exit `0`; log SHA-256 `eb68def0e5b1d82b37d4405a47a25e2300833daeae54683f444cea964be3ec8c`. |
| TypeScript `tsc --noEmit` | **PASS**, exit `0`. |
| Targeted ESLint for the two changed files | **PASS**, exit `0`. |

That is **18 focused tests plus two static checks**, all using the immutable
Docker image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`,
with no network and no image pull. Python receipt:
`/gpu1-share/data/cicada-client/v164-f28-phone-ui-diagnostic-20261003/python-tests.receipt.redacted.json`.
The combined JavaScript, TypeScript, and ESLint receipt is
`/gpu1-share/data/cicada-client/v164-f28-phone-ui-diagnostic-20261003/typescript-tests.receipt.redacted.json`,
SHA-256 `3d1d4d53290015813b5ca684974bc752b8fa931ee26d4a1bdbf4c6a56ebec183`.
These are offline diagnostics; no new live fixture was run.

The executed commands inside that pinned Docker container were:

| Command | Exit code |
|---|---|
| `python3 scripts/interop/test_v164_phone_ui_outcome.py -v` | `0` |
| `node --test tests/linkConsentFlow.test.mjs` | `0` |
| `node node_modules/typescript/bin/tsc --noEmit` | `0` |
| `node node_modules/eslint/bin/eslint.js src/components/LinkConsentPanel.tsx src/platform/linkConsentFlow.ts` | `0` |

The receipts retain the complete `docker run --rm --pull=never --network=none`
argument arrays, read-only source/dependency mounts, timestamps, and log hashes.

The Android instrumentation build for the updated diagnostic source is pending
the next clean commit. Its post-commit receipt is expected at
`/gpu1-share/data/cicada-client/v164-f28-phone-ui-diagnostic-20261003/apk-build.receipt.redacted.json`.
Do not attribute that future APK or source to the F28 run. Physical Android,
public HTTPS, native Codex/Worker execution, Link fault-recovery testing, and
bilateral KEY/`NONE` acceptance remain **NOT_RUN**. Ordinary cross-user messages
remain unavailable while Core advertises `external_thread_links=false`.

## Evidence index and record integrity

These are Git-external evidence files. Private JSON and logs were read through
allowlisted summary fields; this report includes statuses, timings, and hashes
only, not credentials, private signing material, complete messages, or response
payloads.

| Evidence | Path | SHA-256 |
|---|---|---|
| F24 launcher command journal / terminal | `L24/command-journal.private.jsonl` / `L24/terminal.private.json` | `90b59a142db97f340b47a931e526ee2d7085d59d9ec66aeca35ebf70f93bb85e` / `149df7477b931e03c83029439065166a3675eab232f9e7500ca149c2d722ce76` |
| F25 launcher command journal / terminal | `L25/command-journal.private.jsonl` / `L25/terminal.private.json` | `3b9d5dc68472707829ed2da7d8deea3e2d38b7d81fe2270bbb40feceeeb46915` / `acef87364514a04964285bf5ca25d5eb9fe1d1c75338cb88da29f83295b128c7` |
| F26 launcher command journal / terminal | `L26/command-journal.private.jsonl` / `L26/terminal.private.json` | `e837b4482241d185b231bcbfddc0d391198072b784e25f366932300ab007f7f7` / `13e115d4c3f1c516e62043f5180ad49eb9bdb4482f11f4ef1577a6256aae4e03` |
| F27 launcher command journal / terminal | `L27/command-journal.private.jsonl` / `L27/terminal.private.json` | `c60c111bbf0d7ba433bcf2a812f8ca0d6edb84f0373ca3d3cf7cbc1d740b4dd8` / `3836a38b3a77f3f2a69f2e9a32448df06548b1ca851e8321ae4f72b0ab19370b` |
| F28 launcher command journal | `L28/command-journal.private.jsonl` | `14610e4d1ccd7a8ef2709a967e86b9684a6e48f4b1be1db7bb7235e27af0f160` |
| Original F28 terminal (`OUTCOME_UNKNOWN_PRESERVE_PENDING`) | `L28/terminal.private.json` | `33b633026b8f092fd9d68c07dc6a3cd8a9ce5e511f326da1ac7031344fa66e71` |
| Actual Target RN JUnit failure | `C28/outbox/target-key-rn.instrumentation.private.log` | `40facb9a16d41fe6ba0ce3af80a7a919ca3225b57e9ca3a4e0c77647bb3db15f` |
| Target UI wrapper command, exit, and timing | `E28/link-flow/target-ui-command.private.json` | `0396f49a09938aeba51fabace2421890ce63da1ca8aa08486437f96a448de494` |
| F28 Core actor/terminal/owned-closure index | `R28/evidence/attempt-08/stage-actor-terminal-owned-closure-index.redacted.json` | `be286346906f76293e3d5ccf2052f09df868876e4c7f2656582c755b69352b1b` |
| F28 single terminal ACK | `R28/evidence/attempt-08/terminal-consumer-ack.redacted.json` | `0315203697a41e791ba1f6a430246a192b9a66d43daf4addf337d7354e09582d` |
| F28 two-resource removal receipt | `R28/evidence/attempt-08/cleanup-1791039643515602808.json` | `8d8fbe5242f932a0c48dcc7f5c3c90701b9631e885b7bc05a8e326bf5684a3e9` |
| F28 Client bootstrap binding | `E28/bootstrap-binding.redacted.json` | `cb35fa2e19a96dd1efa0b11ecf63cece7049fab3c5daeb7bf0529c890305146a` |
| F28 Android teardown | `E28/android-teardown.redacted.json` | `43100a87bb30dbc7a0efeb016439a3d9f22077598349fc849c6cab113420ce78` |

## Next bounded-run instruction

```text
Read this F24–F28 report and the current section of
docs/cicada-core-handoff.md. Keep every failed attempt and the F28 terminal
OUTCOME_UNKNOWN_PRESERVE_PENDING unchanged. Do not resend, regenerate, or
silently clear any existing F28 packet, operation, sequence, proofs, or
pending marker. Do not infer that an unexported Target grant packet exists.
Its single terminal ACK has already run.

Keep clean Core 0213538, the full pinned images and catalog, independent
SOURCE/TARGET Owner pins, strict proof/lease/time/tuple/fence checks, the
one-frame Root authorization, and the existing six-flow order. Bind READY by
its raw aggregate digest; do not substitute the inner Hub-ready digest. Do not
extend the original deadlines, reuse F28 proofs, add retries, or send a new
business frame from a stale GO.

Wait for a fresh Main Root BOOT that produces actual READY and a fresh Root GO
bound to the clean source, exact APK pair, fixed Core images, current Scope,
and new deadlines. Only then perform the separately authorized bounded step.
Keep Core as sole Owner-signing custodian and preserve the actor stop/wait,
single terminal-ACK, and owned-cleanup rules. Record each encrypted gate,
Target confirmation, status and terminal outcome separately. If F28's
authoritative outcome remains unknown, retain its pending operation. Physical
Android, public HTTPS and native Worker acceptance remain NOT_RUN until tested.
```
