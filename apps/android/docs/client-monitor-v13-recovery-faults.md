# Monitor v1.3 RPC recovery fault acceptance

**Date:** 2026-09-27

**Result:** **PASS** for the three outer Client RPC recovery-ledger scenarios below, on the fixed disposable Hub image and Android emulator. This follow-up does not alter the existing Set H acceptance record.

## Scope

Each scenario used a fresh disposable Hub and a fresh Android Owner device-key session. The fault proxy intercepted one encrypted `monitor.broadcast_prepare` request, seeded the Hub transport-recovery ledger from that exact ciphertext, and dropped the response. Each scenario recorded exactly one `FAULT_READY` across its proxy phases. The Android tests verified the recovery response, sequence and packet-retention behavior, and that no business dispatch was claimed.

This is transport-recovery-ledger coverage only. The fixture does not execute the Monitor Prepare business handler. No `monitor.broadcast_recover` lookup or Confirm was made. The uncertain case used generic authenticated `/rpc/recover` and a read-only `status.snapshot`; it checked that the snapshot did not clear the Monitor-specific `PREPARE_UNCERTAIN` fence. Native Monitor execution, recipient delivery, model consumption, physical Android, and public HTTPS are **NOT_RUN** by this suite.

## Pinned artifacts and build

| Item | Recorded value |
|---|---|
| Hub source / contract | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` / `client-hub-v1.3` |
| Hub image | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |
| Protocol archive SHA-256 | `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9` |
| Source cleanliness | `source_dirty=false`; fixed image label `org.cicada.build.dirty=false` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Client test source commit | `cc634e6ac1937d41fa35234862b9fde70da71c80` |
| App APK SHA-256 | `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` (unchanged from Set H) |
| Test APK SHA-256 | `0bb67beb0da959d9518520672720543f709b11024fa0af153c990fc819af9cd2` |
| Recovery helper | Go 1.27.1 Docker builder `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`; binary SHA-256 `2ddde2d128385e23ee97533e0078987e41c21b50abb76ae2e95ab47dd4530630` |
| Fault proxy | Core source commit `be0269e80c41e94881d131bd4f4b233e80b6ffe6`, SHA-256 `98d025419270b62ec229fcb15e91e18cbf0a0d0b22b6729e35900335b9ed9c43`; working copy matched pinned source, exit `0` |

`./scripts/docker-build-android-test.sh` exited `0` and produced the recorded app/test APKs. `python3 scripts/check-client-contract.py` verified all 15 imported payloads (exit `0`; `contract-check.json`). The fixed-image inspection exited `0`; the source archive and recovery-helper Docker build also exited `0`. Their complete command records are in `android-test-build-bounded.json`, `fixed-target.json`, `source-archive.json`, and `helper-build.json` under the evidence directory.

## Reproduction and results

Evidence root:

```text
/gpu1-share/data/cicada-client/monitor-v13-faults-20260927T043238Z/evidence/
```

Android instrumentation ran in the pinned Docker emulator; the host runner orchestrated Docker and ADB. These three scenario commands were each run from the Client repository and each exited `0`:

```sh
EVIDENCE=/gpu1-share/data/cicada-client/monitor-v13-faults-20260927T043238Z/evidence
FIXTURE_BINARY=/gpu1-share/data/cicada-client/monitor-v13-faults-20260927T043238Z/build/bin/client-recovery-fixture
python3 scripts/interop/monitor-recovery-faults.py "$EVIDENCE" processing --fixture-binary "$FIXTURE_BINARY"
python3 scripts/interop/monitor-recovery-faults.py "$EVIDENCE" uncertain --fixture-binary "$FIXTURE_BINARY"
python3 scripts/interop/monitor-recovery-faults.py "$EVIDENCE" legacy --fixture-binary "$FIXTURE_BINARY"
```

The commands above identify the completed run. To repeat them, use a new private evidence directory, start and install the emulator through `monitor-android.py`, and build the helper from the fixed source as recorded in `helper-build.json`. The runner refuses to overwrite an existing scenario directory.

Each scenario ran `MonitorHubInteropTest#prepareDevice`, `MonitorHubInteropTest#enrollOwnerAndCheckCapabilities`, and `MonitorRecoveryFaultTest#capturePrepareFaultPendingPacket`; every command and its Android driver exited `0`, with `OK (1 test)`. The recovery selectors and assertions were:

| Result | Scenario and recovery selector | Runner commit | Recovery assertion | Evidence |
|---|---|---|---|---|
| **PASS** | `processing` — `MonitorRecoveryFaultTest#recoverStillProcessing` | `84ed9627556d961279a30d74fc5501701984aa11` | `/rpc/recover` returned `STILL_PROCESSING`; the original encrypted packet remained pending, a replacement Prepare was blocked, and no business dispatch was claimed. | `processing-run2.json`; `recovery-faults/processing/evidence/recovery-result.json`, `recovery-markers.json` |
| **PASS** | `uncertain` — `MonitorRecoveryFaultTest#recoverSignedUncertain` | `69ecd268550151c9c786d46445df7eee120f0f30` | After `FAULT_READY`, the same Hub container and state mount restarted with the same Hub identity. `/rpc/recover` returned signed `OUTCOME_UNCERTAIN`; the exact retired ciphertext and `PREPARE_UNCERTAIN` metadata remained, a later read-only `status.snapshot` did not clear the Monitor fence, and a replacement Prepare was blocked. | `uncertain-run2.json`; `recovery-faults/uncertain/evidence/recovery-result.json`, `recovery-markers.json` |
| **PASS** | `legacy` — `MonitorRecoveryFaultTest#recoverUnavailable` | `69ecd268550151c9c786d46445df7eee120f0f30` | `/rpc/recover` returned `RECOVERY_UNAVAILABLE`; the original encrypted packet remained pending, a replacement Prepare was blocked, and no business dispatch was claimed. | `legacy-run.json`; `recovery-faults/legacy/evidence/recovery-result.json`, `recovery-markers.json` |

All three recovery selectors exited `0` at both the ADB and driver layers and reported `OK (1 test)`. The captured request and expected response sequence were both `2` in each fresh session. The redacted acceptance summary records **12/12** JUnit selectors passing across three independent Hub fixtures and three Android device-key sessions. The signed uncertain response consumed the original reserved response sequence exactly once; a second local recovery returned `NO_PENDING_REQUEST` without advancing either watermark. The subsequent authenticated snapshot was a separate read-only RPC and retained the unresolved Monitor fence.

For the uncertain scenario, Docker reassigned the Hub’s loopback host port on restart (`upstream_port_changed=true`). The corrected runner queried the post-restart port, confirmed the same Hub container/image/state mount and Hub identity, then retargeted only the owned proxy upstream while keeping the Android origin unchanged. The original and retargeted proxy logs show one `FAULT_READY` before restart and zero additional fault events after retargeting.

## Failed earlier attempts retained

These attempts remain **FAIL** records; the later passing reruns do not erase them.

| Attempt | Recorded outcome | Explanation and evidence |
|---|---|---|
| Processing attempt 1 | **FAIL** — `processing-run.json` exit `1`; recovery selector **NOT_RUN** | The capture JUnit passed, but runner `3e14ac8` missed the AndroidJUnitRunner class prefix on its first status line and did not reach the recovery selector. The attempt was archived at `recovery-faults/processing-attempt1/`; cleanup errors were empty. The corrected parser and processing rerun passed under runner `84ed962…`. See `processing-attempt1-archive.json`. |
| Uncertain attempt 1 | **FAIL** — `uncertain-run.json` exit `1`; recovery selector **NOT_RUN** | Health polling at the original loopback origin failed after same-container restart, so the recovery selector was not reached. The attempt was archived at `recovery-faults/uncertain-attempt1/`; cleanup errors were empty. Its evidence does not retain both port values, so it does not prove the exact original port transition. The successful rerun independently records that the upstream port changed and uses the corrected health/retarget procedure. See `uncertain-attempt1-archive.json` and the final `uncertain` recovery result. |

## Cleanup and limits

All three scenario records show the owned proxy stopped, ADB reverse removed, Android private session cleared, disposable fixture and synthetic keys removed, and `cleanup_errors=[]`. Aggregate teardown is **PASS**: `final-teardown.redacted.json` records removal of the owned emulator, proxies, and scenario fixture directories while leaving resident Hubs untouched; the evidence directory is mode `0700` and its files are mode `0600`. Emulator stop exited `0`.

These synthetic same-owner transport-ledger checks do not establish Monitor business acceptance, confirmation, real Node/Monitor behavior, physical-device security, public-network behavior, or production readiness. Raw operation IDs, Hub/Owner/device identifiers, keys, and request bodies are omitted from this report.
