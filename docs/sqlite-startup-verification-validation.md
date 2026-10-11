# SQLite startup verification validation — 2026-10-11

The schema-59 startup change removes repeated whole-database checks during an already-applied reopen. It preserves every migration's schema checks and performs the full SQLite `integrity_check` and `foreign_key_check` once, before committing the original `BEGIN IMMEDIATE` transaction. Fresh and partially completed upgrades retain their original verification, legacy inventory, savepoint, failure/retry and APPLIED commit boundaries. No cache, `quick_check`, schema version or dependency was introduced.

The source base is `ad247387c041c9aaf6a33b40f5ba7c141654e242`, software `0.0.2`. Validation below exercised the dirty shipping migration candidate, whose exact source hashes are retained in the receipts. It does not transfer these results to a clean binary, native Runtime or Android build.

## Retained failure and measured cause

The original `policy-qa-a1` broad selected-family race run failed at each package's cumulative 180-second timeout. Its server stack sampled an already-applied reopen; its Store stack sampled a fresh migration. Both were runnable in SQLite integrity work. This supports fixture startup amplification of actual production initialization; it does not prove a deadlock or identify a provider problem. The original failure remains unchanged.

HTTP fixtures perform a fresh `Store.New` inside `Control.New`, then reopen that same database through a second `Store.New`. Store fixtures independently create fresh databases. The original normal run's 21 top-level tests contain 71 test RUN/PASS events. The current broad selector matches those same 21 tests without omissions or additions. Source inspection counts 36 fresh Store fixtures and 9 HTTP fixtures, each with one fresh initialization and one already-applied reopen; subcases sharing a parent fixture are not counted as separate initializations.

Original evidence: `.cicada-data/v01-next-gates-20261010/policy-qa-a1/ROOT-RUN.NONAUTH.json` and `out/race.jsonl` (SHA `88aa926eb8139a452a92ce908400c38dd81a956f89589950f34079de1b47f62e`).

## Startup measurements

One baseline and one after-change synthetic fresh/reopen pair ran normally and under race instrumentation, with the same offline Go image, cache, two CPU limit and 3 GiB memory limit. Timing instrumentation existed only in an ignored Go overlay; it did not omit SQL or checks. These timing results are separate from shipping regression compilation.

| Mode / startup | Before | After | Full integrity/FK calls before → after |
| --- | ---: | ---: | ---: |
| normal / fresh | 0.542 s | 0.526 s | 59 → 59 |
| normal / reopen | 0.302 s | 0.042 s | 59 → 1 |
| race / fresh | 13.803 s | 13.333 s | 59 → 59 |
| race / reopen | 9.788 s | 1.359 s | 59 → 1 |

After-change instrumentation recorded 59 schema verifications in both startup paths. Fresh startup also retained 59 Apply calls and 60 legacy inventory snapshots. Reopen race time decreased by 86.11% in this paired measurement. The small fresh-time difference is single-sample variation, not a claimed fresh-path optimization. Inclusive verification timings must not be added again to their integrity/inventory components.

Baseline review: `.cicada-data/v01-next-gates-20261011/race-audit/measurement-a1/MEASUREMENT-REVIEW.NONAUTH.json`, SHA `26edc5715d0269c22fe55672bdb96c119b4608e3cbb01dc00fbfffa23ba0110a`.

After-change review: `.cicada-data/v01-next-gates-20261011/race-audit/measurement-after-a1/REGRESSION-AND-TIMING-REVIEW.NONAUTH.json`, SHA `60e9f9deb94a2681a2a1c5ce9a72970ba085af2b572623917a8b15ac8d87c13d`. The combined operation exited 0 in 179.251 seconds; the shipping and ignored-overlay phases have separate logs and counts.

## Shipping regression and boundaries

Four targeted shipping tests, compiled without the timing overlay, passed normally and under race: 4 top-level plus 10 subtests in each mode, 0 failures and 0 skips. Normal package time was 2.892 seconds; race package time was 84.681 seconds.

The new reopen test rejects missing objects, a wrongly defined existing index, changed ledger ID/checksum/description, too-new schema, real foreign-key and CHECK-constraint violations, and a damaged SQLite header reporting `SQLITE_NOTADB`. Rejected reopen leaves the complete migration ledger unchanged and releases its transaction. Repeated successful startup preserves all 59 applied entries and their attempt counts. Existing tests retain legacy identities/data, concurrent-open serialization, and fresh interruption rollback/retry behavior.

The targeted selector was:

```text
^(TestV2MigrationsAppliedReopenFailClosed|TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable|TestV2MigrationsConcurrentOpenSerializesLedger|TestV2MigrationFailureRollsBackSchemaAndResumes)$
```

Independent postcheck confirmed the exact owned container ID/name/run label and process group absent, six original residents' full canonical configuration digests unchanged, and all 370 local compilation input rows unchanged. The surrounding repository was dirty and independently owned files were being edited; no whole-repository equality was claimed. No models, credentials or API calls participated.

## Complete selected-family race

The first broad-family race was **ABORTED_AFTER_CONFIRMED_SERVER_BUILD_FAILURE**. The frozen server source included a separately owned G5 test missing its `time` import. Actual compiler errors were `undefined: time` at lines 291, 377, 406, 420 and 448. No server test ran; Store recorded four test RUN events and two test PASS events before the authorized stop, without a package terminal. Store therefore remains UNKNOWN for this operation. Session 54677 exited 1 after 54.964 seconds, and no timeout/deadlock conclusion follows from this compile failure. The selector was:

```text
^Test(ClientLinkPolicySignerPreview|ClientLinkReviewPolicyEncryptedHTTP|CommunicationLinkPolicySignerPreview|CommunicationLinkReviewPolicy).*
```

Measured initialization cost projects about 480 seconds for the 36 fresh Store fixtures and 132 seconds for the nine fresh/reopen HTTP fixtures. The proposed finite budget is 600 seconds per package, 650 seconds for the Go command, a T0+690 work cutoff and 60 seconds for cleanup, with outer TERM at 750 seconds and KILL after 15 seconds. Only this race family is scheduled; normal/catalog/compat/vet are not repeated by that operation.

The prepared source fence includes server/Store dependencies, catalog and UI embedded assets, including three existing ignored generated UI files. Their actual bytes are pinned; ordinary Git cleanliness is not substituted for compilation provenance. The immutable output directory is `.cicada-data/v01-next-gates-20261011/race-audit/broad-race-a1`. Its original result SHA is `6939ffc791c6d15a924e72fff54410708d797f6dc418a74d4f16d2467e6a9dfa`. Separate `ABORT-CLOSEOUT.NONAUTH.json` records confirmed exact owned cleanup, six full resident canonical digests and the original 723 compilation inputs unchanged. The original result remains UNKNOWN with its secondary missing phase-exit-file error; it is not rewritten as PASS.

### Corrected a2 actual result

A new one-run authorization bound `broad-race-a2` to the corrected G5 import. Only that compilation input changed; the remaining 722 rows, including all actual UI embeds, remained fixed. The effective a2 operation exited 0 in 520.825 seconds with no overlay or additional phases:

| Package | Top-level PASS | Subtest PASS | Package time | FAIL / SKIP |
| --- | ---: | ---: | ---: | ---: |
| server | 7 | 22 | 141.152 s | 0 / 0 |
| Store | 14 | 28 | 508.450 s | 0 / 0 |

The actual 21 top-level and 71 test RUN/PASS identities exactly equal the original selected family; both packages passed. This completes that selected-family race at the recorded dirty candidate source, not all Go race tests or Native/Android acceptance. Store still required over 180 seconds: the reopen optimization did not make the original insufficient package budget adequate. The finite 600-second budget was supported by measured repeated fresh-fixture cost and was not increased during execution.

Evidence under `.cicada-data/v01-next-gates-20261011/race-audit/broad-race-a2`:

- `RESULT.NONAUTH.json`: SHA `d4246ff4c187ad01144d201caebd7b1a860de323dd747cdae0be9200d8d8a14f`.
- `out/race.jsonl`: SHA `cedadf84fd0c6bf75ea8a7a143e4a6f07cad9a92b9f4788e4410b547bdc35faa`.
- `COMPILE-SOURCE-FREEZE.NONAUTH.json`: SHA `24b98c2fe37bc5935fc901fcf04a90551ceb483cc264533256961f195ec5c35b`.
- `BROAD-RACE-POSTCHECK.NONAUTH.json`: SHA `97729e004be20f7381b9d0be4b8e8d56a046f829a1f8b3380f8dbd55ce8aeed0`.

One independent terminal postcheck verified all 723 compilation inputs before/after and against the current bytes, all six original full canonical resident digests, and exact owned container ID/name/run label, network label and process group absence. Cleanup is CONFIRMED and models/API calls remain zero. No whole-repository equality is claimed. Both the original 180-second race failures and the a1 compile-failure/abort remain immutable.
