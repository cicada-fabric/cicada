# Managed Node runtime outcome validation

This is a scoped development checkpoint over clean `c25dc731b41631993184211b65c8d0df14144c7a`, tested in a detached worktree with dirty source. Software defaults advance to `0.0.2`; historical `0.0.1-dev`/`0.1.0-dev` artifacts retain their original versions. Wire 1, `client-hub-v1.6.4`, Hub schema 59 and the 55-operation catalog are unchanged.

Ordinary app-server execution records the actual `exec.Cmd` start, including a starter error after a process exists. Failed execution after start records `INJECTION_UNCERTAIN`. Unconfirmed stop suppresses completed status/summary and keeps the native writer quarantined. The shared stdio client confirms IDs only from successful matching native responses and accepts completion only for that original Thread/Turn with `threadId`, `turn.id`, `turn.items` and a terminal `turn.status`. Foreign/malformed events keep the correct turn eligible to finish. Existing user approval, original-session resume and writer epochs remain authoritative; no private runtime IPC or new product protocol was introduced.

The final offline Go batch passed **7 top-level / 19 subtests** in `internal/codexapp` (0.015s) and **6 / 11** in `cmd/cicada` (1.340s), with zero failures/skips. It covers real child starts/waits, prestart/init/turn/partial-start failures, normal stop, custom joined and pure `ExitError` stop failures, writer quarantine, actual provider ledger outcomes, original approval RPC, permission wire and existing resource quarantine. It is deterministic process/protocol evidence, not model acceptance. A preceding source passed shared Control **6 / 3** (6.992s), sealed `goal.result` **1 / 0** (1.635s), and the broader requested Node regressions. Those results retain their earlier source; they were not rerun after the final custom-waiter refinement.

The final `-race` run of those exact codexapp **7 / 19** and Node **6 / 11** selectors also passed with zero failures/skips (1.037s and 5.807s). Its complete 1,211-file source inventory was unchanged during compilation/testing. Existing buildinfo/version metadata checks passed **3** tests; four existing release packaging/provenance static checks passed. Both Hub Docker defaults and both plugin metadata files match `0.0.2`. No business test was rerun merely for the version/document changes.

Valid RED evidence preserves nine malformed/foreign parser failures, a real started `turn/start` failure falsely reporting `providerStarted=false`, default `Cmd.Wait` cancellation despite observed successful process exit, and two erased custom `ExitError` failures. Default Wait now recognizes observed exit while still requiring process-group stop; custom waiters retain every error. The first two Node attempts failed on an invalid fixture's non-private SQLite parent; the third RED overlay referenced a missing file. A later positive fixture incorrectly required a custom `ExitError` to disappear and was corrected to use default Wait. All original logs remain. One old named-profile fixture FAIL lacks enough diagnostics for a cause and remains UNKNOWN despite later PASS. An earlier whole codexapp run's real-daemon smoke was SKIP, not native PASS.

Evidence is retained under `.cicada-data/node-runtime-validation-20261010/`: `FROZEN-VALIDATION.NONAUTH.json` SHA-256 `667584a7b5cb119e5a280f1483c8c1d9808671639a5a2634f4cb28ae73c64702`, source inventory `cf79bb967f05d4600d274163945039ecc676da8e49b8637da23a07e98a4f507d`, and exact commands/logs in `diagnostic4`, `final5`, `custom-wait6` and `final7`. This receipt precedes version/document edits and binds the five tested Go/test files. The fixed compiler was Go 1.27.1 bookworm digest `69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`, network-none, nonroot, read-only sources, two CPUs, 3 GiB and 256 PIDs, with a private cache. Seven exact owned compiler CIDs were confirmed absent. The six resident whole-object hash comparison was FALSE; three resident Hubs have dynamic healthchecks, but the retained hashes do not prove those are the only differences. No unchanged-resident claim is inferred.

`ResourceExecution.Wait` observes/reaps the root only; raw exit errors and group emptiness cannot prove an escaped descendant or external provider stopped. Existing Node `confirmMachineNodeResourceStop` deliberately quarantines and returns `ErrResourceStopUnverified`. Only the existing independent trusted `ConfirmStopped` verifier can release that resource fence, matching resource/lease/execution/epoch and receipt time after root Wait. That earlier checkpoint preserved this restriction; its setsid-escape regression passed. It had no new trusted physical-resource verifier, adopted foreground acceptance, real Native, Android, physical-device or public HTTPS gate. Product acceptance remains PARTIAL.


## Later full Go test-only overlay — 2026-10-10

The exact regression update to
`cicada-go/internal/server/machine_agent_approval_integration_test.go` was
validated as an overlay on clean production source
`308d7607cadc6cb83fe5aaa923adaf643a0aa32d`. The test file SHA-256 is
`edba25235b934adcaac660ab208ce66860d9493b0209e8a110edb05190115ce6`; it
exactly matches reviewed patch SHA-256 `c08da9aadad46b235401458015c8822f8a64ea5499f97b9363b7f10b0093adf5`. It updates the fake app-server completion event to the exact Thread/Turn/items
shape and expects failed completion with `executor_outcome_uncertain` when the
Codex app-server stop is unconfirmed and native writer ownership remains
quarantined. GPU quarantine, claim release and later same-resource rejection
assertions remain. The production Go source was not
changed by this overlay.

The full Go batch passed as `PASS_TEST_OVERLAY_SCOPE_ONLY`: 30 packages,
2,981 test PASS events, 23 SKIP events, zero failures, and build/gofmt/test/vet
exit 0. It made zero model calls; the owned container was absent. The result is
[recorded here](../.cicada-data/node-runtime-validation-20261010/full-go-overlay-r2-308d/ROOT-RESULT.NONAUTH.json)
(SHA-256 `6f5d06c3057d9b2f3e0ee326e3f99cd8b0de5c6384d2492b79bdb199ae05657f`);
the test event log SHA-256 is
`924c2e09271024ab0d1090c04bc69233991c237e2e8cf5ffa90d1be274a62534`.
These results are not a clean-source aggregate and do not upgrade Native,
physical-device, or public-HTTPS acceptance.
