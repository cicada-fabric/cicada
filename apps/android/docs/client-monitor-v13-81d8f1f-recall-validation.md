# Client-Control v1.3 native recall retry — `81d8f1f`

**Evidence date:** 2026-09-27
**Status:** Core native recipient stage **BLOCKED** at automatic model-tool approval review (test container exit `1`). Nine Android selectors are **PASS** on test APK `8c2f…`; the separate read-only status selector is **PASS** on test APK `4cbc…`. Product-UI status recovery remains **BLOCKED** by the existing filter. The strict delivery selector is **NOT_RUN**.

This is a fresh attempt with its own Hub fixture and evidence. It does not change or inherit the **FAIL** result from the earlier native attempt in [the candidate validation report](client-monitor-v13-81d8f1f-native-validation.md). The only native test-source change for this retry is two prompt strings clarifying the no-tool recall request; the assertions are unchanged.

## Fixed Hub target and client artifacts

| Item | Value |
|---|---|
| Hub source | `81d8f1f90895f41c4f5ea5c67a6281ccda9e1264` |
| Hub image | `sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f` |
| Hub source fingerprint | `50d0a9250631381949f2aa5e155424996aa13490759107e597d354e620a8b2c8`; clean |
| Contract revision | `client-hub-v1.3` |
| Bundle archive SHA-256 | `6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Installed product APK | Source `9568b2ff6d4e156b70484c10b7fd5195405004b0`; SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| Earlier test APK for the nine selector results | Test source `10cd3dcb3bd73e6513df428ced81d95788e1cb84`; SHA-256 `8c2f122e76e22f6845bbdaf0518146ed94a1f6895abdab1147d3010b4c531e09` |
| Read-only observation test APK | Test source `02cefa94bc6096f7196d1df572a22a1f64774d74`; SHA-256 `4cbc0e1ff0546b665e55136c1453334e282d19c380e26b63aa8601cd27a3f90b` |
| Core native test source | `d76e63009192422d13e0e3b413e857a27866c750` |
| Core native test binary | SHA-256 `15a436025b69c85e74b6151efdc4d0414cc082ff60cd2e0b6b643b47c64ae2e8` |
| Core helper SHA-256 | `3ba4008e86bd93fd30335efc8547407039bef5979fe62586fefbb9d0caaaf85c` |

The native test source and binary preflight passed independently; the record confirms the Hub source remains `81d8f1f…` (`native-runner-preflight.redacted.json`). The product app hash remained `f8c82d…8700` on device. The earlier nine selector passes belong to test APK `8c2f…`; they are not transferred to test APK `4cbc…`, which ran only the single read-only status selector. A product APK rebuilt by the test build (`c2c9f5…`) was not installed.

## Completed fresh-attempt gates

| Result | Check | Exit | Evidence |
|---|---|---:|---|
| **PASS** | Contract archive digest preflight | `0` | `archive-preflight.redacted.json` |
| **PASS** | Fresh v1.3 contract check | `0` (driver `0`) | `fresh-contract-check.json` |
| **PASS** | Start fixed Hub fixture | `0` | `hub-start.json` |
| **PASS** | Running Hub provenance matched fixed source/image/catalog | `0` | `running-hub-provenance.redacted.json` |
| **PASS** | Core native source/binary/helper preflight | `0` | `native-runner-preflight.redacted.json` |
| **PASS** | Recover fixture metadata after wrapper parse error without restarting or mutating Hub | `0` | `startup-metadata-recovery.redacted.json` |
| **PASS** | Build read-only status test APK only | `0` | `readonly-observation-test-build.json` |
| **PASS** | Install read-only status test APK only | `0` (driver `0`) | `install-observation-test.json` |

The fresh Hub is the same pinned development image, with `source_dirty=false`. Fresh-run evidence is kept separate from the previous attempt; no native result has been copied between them.

One setup wrapper attempt is retained as **FAIL** at the harness layer: after Hub start succeeded, the wrapper passed non-JSON helper text to `json.loads()` and exited `1`. The harness then recovered the unique owned fixture path from that private output and independently checked the marker/runtime. Recovery exited `0`; no second Hub start or repeated state mutation occurred. This is not a Hub or protocol failure. `fresh-run.json` retains the exact fixture/URL privately; they are not reproduced here.

## Android and Monitor selectors completed

All nine Android instrumentation selectors passed one JUnit test each with ADB and driver exit codes `0 / 0`, using the product and test APK hashes above:

| Result | Selector | Evidence |
|---|---|---|
| **PASS** | `MonitorHubInteropTest#prepareDevice` | `native-prepare-device.json` |
| **PASS** | `MonitorHubInteropTest#enrollOwnerAndCheckCapabilities` | `native-enroll-capabilities.json` |
| **PASS** | `MonitorHubInteropTest#confirmPendingNodes` | `native-confirm-nodes.json` |
| **PASS** | `MonitorHubInteropTest#createOrReconcileGroup` | `native-create-group.json`, `group-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission` | `native-role-permission.json`, `native-permission-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#exportEndpointManifests` | `native-manifests.json`, `native-endpoints-ready.redacted.json` |
| **PASS** | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `native-group-key-grants.json`, `native-scope-comparison.redacted.json`, `group-key-reviews.redacted.json` |
| **PASS** | `MonitorHubInteropTest#prepareExactTextAndReviewRoster` | `native-prepare.json`, `broadcast-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | `native-confirm.json`, `android-confirmed-handoff.redacted.json` |

Enrollment confirmed encrypted v1.3/catalog-pinned `session.capabilities`; the two-node confirmation and Group review passed. Three distinct original native Endpoints had current external Owner proofs. All three Group key grants were reviewed and confirmed on the phone and read back as `CURRENT`. The broadcast review and phone confirmation passed through Android `AlertDialog` prompts on `MainActivity`; this was not a rerun of the full React Native consent flow. The accepted business flow recorded exactly one positive/accepted Prepare and one outbound Confirm; a separate role-only negative permission probe was rejected. Duplicate Confirm was blocked locally before another RPC. The initial approval status was `APPROVED`; this does not imply dispatch or recipient consumption.

## Product UI status-recovery limitation

After app restart, the existing product UI omitted an already-reconciled Confirm from its `monitorStatusOperations` list because the filter requires `confirmStatusReconciled !== true`. A bounded UI attempt therefore had no query control and issued no status RPC. The redacted record confirms `status_rpc_triggered=false`, `new_prepare_count=0`, `new_confirm_count=0`, and `product_changed=false` (`readonly-ui-limitation.redacted.json`).

The first UI navigation attempt also had a **FAIL** for a cosmetic-arrow text locator; correcting that locator opened the panel, after which the actual reconciled-Confirm filter caused the **BLOCKED** status-recovery result. This is a UI visibility limitation, not a status response or RPC result. The installed product app remains unchanged. A separate test-only original-preview status observation is recorded below; it does not alter the product UI result or the strict delivery selector result.

## Read-only original-preview status observation

A separate test-only selector `MonitorHubInteropTest#readOriginalBroadcastStatus` passed one JUnit test with ADB and driver exit codes `0 / 0`. It used test APK `4cbc…` built from test source `02cefa94bc6096f7196d1df572a22a1f64774d74`; the installed product APK remained `f8c82d…8700`. The only installed artifact change was the test APK. A rebuilt product APK (`c2c9f5…`) was not installed. The earlier nine selector passes remain tied to test APK `8c2f…` and are not transferred to `4cbc…`, which ran only this status selector.

The status observation read the original preview without creating another Prepare or Confirm. It returned `APPROVED` with zero recipients, made exactly one status RPC, advanced the request sequence by one, left no pending request, and preserved the original operation/Confirm identifiers and sealed payload bytes. The result makes no dispatch or recipient-consumption claim (`native_consumption_claimed=false`). Evidence: `native-observed-status.json` and `android-observed-status.redacted.json`.

Reproduction command templates (replace placeholders only with the disposable run's owned values):

```sh
bash ./scripts/docker-build-android-test.sh

docker exec <owned-container> /opt/android-sdk/platform-tools/adb -P <owned-adb-port> -s <owned-emulator> install -r /out/observation-test.private.apk

docker exec <owned-container> /opt/android-sdk/platform-tools/adb -P <owned-adb-port> -s <owned-emulator> shell am instrument -w -e run_id <owned-run-id> -e class ai.cicada.client.hub.MonitorHubInteropTest#readOriginalBroadcastStatus ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner

# Template used for each selector in the earlier nine-selector run:
docker exec <owned-container> /opt/android-sdk/platform-tools/adb -P <owned-adb-port> -s <owned-emulator> shell am instrument -w -e run_id <owned-run-id> -e class ai.cicada.client.hub.MonitorHubInteropTest#<selector> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

Build, install, and selector records are `readonly-observation-test-build.json`, `install-observation-test.json`, and `native-observed-status.json`; each has exit code `0`, with the selector reporting `OK (1 test)`. The generic selector template above applies to the nine earlier selectors only with their original test APK `8c2f…`; the new `4cbc…` test APK ran only `readOriginalBroadcastStatus`. The strict delivery/expected-`ACCEPTED` selector remains **NOT_RUN**.

## Current native stage and pending results

The Core native recipient attempt is **BLOCKED**. Its test container exited `1` after automatic Codex approval review refused both MCP attempts in the same turn: the sealed payload and Group were not verified by the review, and an `approvalID` alone was insufficient. No bypass was attempted. The run produced no Monitor outbox, no child dispatch, and no model consumption. Core's retained evidence is at `/home/zyf/CICADA/.cicada-data/native-joint-recall-d76e630/{native-run.json,blocked-analysis.json,blocked-scoped-hub-scan.json,stage-confirmed.json}`; its redacted summary is `core-native-blocked.redacted.json`. The runner used native source `d76e63009192422d13e0e3b413e857a27866c750`, the binary hash recorded above, and pinned Codex image `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`. The sanitized command reference is a Docker invocation of that image running `/tmp/<owned-fixture>/bin/cicada-android-native.test -test.run '^TestMCPMonitorBroadcastAndroidClientNative$' -test.timeout=35m -test.v`; secret environment-file and disposable mount arguments are intentionally omitted. The full command and exit are retained in protected Core evidence. This is an approval-review block in the Core native stage, not a failure of the Android Client/Hub selectors.

The following remain **NOT_RUN** in this evidence set:

- Strict delivery/expected-`ACCEPTED` instrumentation selector.
- Monitor outbox / child dispatch and remote recipient model consumption.
- Any further model run; Core stopped at the approval gate.
- Any further native retry.

Physical Android, public HTTPS, and production endpoint acceptance are also **NOT_RUN**. The product-UI recovery attempt remains **BLOCKED** as described above. The read-only test selector's `APPROVED` status is not a delivery result.

## Cleanup and scoped privacy check

Disposable fixture, emulator, reverse mapping, and Core native container cleanup **PASS** with aggregate exit code `0` (`native-teardown.redacted.json`). Core completed its scoped scan and archive before removing its container; the resident Hub was untouched. Cleanup evidence is `native-remove-reverse.json`, `emulator-stop.json`, and `native-fixture-stop.json`; Core's cleanup record is `/home/zyf/CICADA/.cicada-data/native-joint-recall-d76e630/cleanup-native.json`.

The delivery-document and emulator-mount privacy preflight **PASS** with exit code `0` (`client-privacy-preflight.redacted.json`). This is a scoped check of the listed documents, emulator mounts, and credential exposure; it is not a universal secret audit.

The earlier startup-wrapper **FAIL** and subsequent metadata recovery **PASS** remain separate harness events. The current Core native stage is **BLOCKED**; it does not convert the previous attempt's native **FAIL**, and no result is transferred between attempts.

## Evidence location

Redacted result metadata and command records are under:

```text
/gpu1-share/data/cicada-client/monitor-v13-81d8f1f-recall-20260927T065926Z/evidence/
```

Private setup files, credentials, signing material, Thread identifiers, and message bodies are omitted from this report.
