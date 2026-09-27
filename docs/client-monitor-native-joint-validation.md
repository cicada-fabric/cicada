# Android and native Monitor joint acceptance — 2026-09-27

**Result: FAIL.** This is the single joint attempt on the frozen `client-hub-v1.3`
Hub; no rerun on a changed image is included. The native container exited `1`
after 202.81 seconds. This failure does not rewrite the earlier standalone
native Monitor **PASS** in [the architecture validation record](architecture-v2-native-validation.md)
or the Client-only emulator protocol results.

## Fixed inputs and provenance

| Component | Identity |
|---|---|
| Hub source / contract | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` / `client-hub-v1.3` |
| Hub image | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |
| Core runner source | Clean commit `877062f30835023a26bd546972aca1e83dcffcac` |
| Core native test binary | SHA-256 `43e964405f59fb9f10ccc14047fbced625eeccab516fcc3da8b4f233b98bccdf` |
| Go builder image | `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244` |
| Codex image / CLI / model | `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264` / `0.157.1` / `gpt-5.6-luna` |
| Installed Client app | Set H app SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| Initial AndroidTest APK | SHA-256 `0bb67beb0da959d9518520672720543f709b11024fa0af153c990fc819af9cd2`, test source `cc634e6ac1937d41fa35234862b9fde70da71c80` |
| Later AndroidTest APK | SHA-256 `ea6bcc09d456da0fd2b5fb14f11a92ba88f55e965a9eff474af86ccac3512601`, test source `1172000f5ebd03a34b0b589702f1fc7d56409433` |

The Client's initial artifact metadata records clean checkout `de139c9e8bd28e963eceabd3fe027dbb82edf0e3`; the later test-only APK did not replace the installed Set H app. See the [Client native acceptance report](../../CICADA_CLIENT/docs/client-monitor-v13-native-acceptance.md) for its APK stage records and selector exits.

## Completed Android setup

Six Android selectors passed. `prepareDevice`, `enrollOwnerAndCheckCapabilities`,
`confirmPendingNodes`, and `createOrReconcileGroup` each returned ADB/driver
exit `0/0` and `OK (1 test)` using the initial AndroidTest APK. The later APK
passed `assignMonitorRoleAndEnableBroadcastPermission` and
`exportEndpointManifests`, also with ADB/driver `0/0` and `OK (1 test)`.

These setup results do not establish Owner Group-key authorization. Android
reviewed and exported the three complete Endpoint manifests, but no external
Owner Group proof was signed and no encrypted `group.key_grant` was sent.

## Failure and unrun stages

The native runner created three real original Codex Threads and joined them to
two logical Nodes in the one test container. Each Endpoint had an epoch-1
`leased` binding with an unexpired lease. The Hub's legacy
`MarkStaleEndpoints` presence cleanup nevertheless marked the live Endpoints
`offline` from stale `last_seen` data. The next authenticated Session heartbeat
was rejected with HTTP `401`, and the native runner exited `1`. There were zero
model retries and zero replacement Threads.

No Owner Group proof or grant, positive `monitor.broadcast_prepare`, or Confirm
was performed. Monitor dispatch, recipient consumption, final status and the
Hub plaintext scan are **NOT_RUN**. The Codex model was used during Thread/Join
setup, but the failed attempt does not establish Monitor message handling or
recipient model consumption.

The bounded diagnosis summary is
`.cicada-data/native-android-joint-failure-20260927/summary.json`; it contains
the redacted runner outcome and provenance. The recorded command arguments and
exit results are in `.cicada-data/native-android-joint-failure-20260927/commands.json`;
raw private logs are not reproduced here. Cleanup commands for ADB reverse,
the emulator and the marked Hub fixture each exited `0`; a read-only Docker
check found no remaining fixture container. Cleanup removed the disposable Hub
state, so its bindings cannot be recovered from this attempt. The restricted
archive `.cicada-data/native-android-thread-recovery-20260927/` contains six
Thread JSONL records, three empty workspace/context sidecars and a hash manifest;
it contains no keys, caches or database. Preserved Thread records do not restore
a live Hub binding.

## Follow-up status

The stale-presence versus valid-binding-lease defect was fixed on `dev` in
`148c0ef927bd29c804430845cd9faa0dca2c508d`. The production change is limited to
`store/fabric.go`: the sweep exempts only a migration-READY Endpoint pointing to
its own current active binding with a nonempty lease owner and an unexpired
lease. Expired, revoked, superseded and unbound legacy entries still age out;
left and already-offline Endpoints retain their state. The fix does not change
`last_seen`, schema, migration or the Client contract.

Regression evidence distinguishes the pre-fix failure from post-fix passes:

| Gate | Result and source basis |
|---|---|
| Pre-fix regression reproduction | **RED**, exit `1`; saved in `.cicada-data/stale-v2-lease-housekeeping-20260927/store-red.log` and `.cicada-data/presence-housekeeping-regression-20260927/old-store-red.private.log`. |
| Store and Control packages | **PASS**, `go test -count=1 -timeout 15m ./internal/store ./internal/control`, exit `0`; Go 1.27.1 Bookworm, Store 110.430s and Control 32.980s. Includes `TestMarkStaleEndpointsUsesOnlyCurrentLiveV2LeaseAsPresence`. |
| Fabric package | **PASS**, `go test ./internal/fabric -count=1`, exit `0`, 7.903s, pinned Go image `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`. |
| Fabric regression race tests | **PASS**, exit `0`, 23.460s in the same pinned Go image: `TestLiveRenewedSessionSurvivesLegacyEndpointHousekeeping` and `TestExpiredOrLeftSessionStillFailsAfterPresenceHousekeeping`. |

The package and race runs used source at `bc219cd001d26e6464c623501744094aca131c8b`
with a dirty worktree containing the fix later committed as `148c0ef`; these
were not clean-checkout tests of the commit. Evidence is in
`.cicada-data/stale-v2-lease-housekeeping-20260927/` and
`.cicada-data/presence-housekeeping-regression-20260927/fabric-gate.json`.
The frozen `be0269e` Hub image `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` was not rebuilt or replaced, and
there has been no joint rerun against a fixed candidate. Monitor dispatch,
recipient consumption and the Hub plaintext scan therefore remain **NOT_RUN**.
Physical Android, dual-physical-Node operation and public HTTPS were not
exercised.
