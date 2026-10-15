# Client-Control v1.3 bounded native Monitor validation — `25013b5`

**Evidence date:** 2026-09-27

**Status:** **PASS** for the bounded Android emulator/native scenario. Pinned Hub provenance, archived artifact installation, all ten Android selectors, Node/Group setup, Owner Group signing, three current Group key grants, the Core native execution, and the final status selector passed. Both original recipient Threads consumed the exact body and context in this bounded run. Client-owned emulator/reverse cleanup passed; Hub/Core fixture cleanup remains Core-owned and pending at Client handoff.

This is a new bounded run against the pinned development Hub. It is independent of prior v1.3 runs: no earlier runtime or selector result is transferred into this report. The tested native sequence was one read-only lookup of the original `cicada_monitor_broadcast_preview`, followed by one broadcast attempt. Automatic approval remains enabled, with one tool call per model turn and no automatic retry.

## Fixed target and artifacts

| Item | Value |
|---|---|
| Hub source | `25013b51915124fa1da25e5fd37088eadf0e3d2d` |
| Hub image | `sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c` |
| Contract revision | `client-hub-v1.3` |
| Client source checkout for this run | `b7ffa7edc9094f3f4c2819f9c7eb50aa3eca380c` |
| Bundle archive SHA-256 | `5ad36a7492dd7751308eef6fe22c44175079cd212411ffbef580576b7f2597ce` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Reused product APK | Source `9568b2ff6d4e156b70484c10b7fd5195405004b0`; SHA-256 `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` |
| Reused instrumentation APK | Test source `02cefa94bc6096f7196d1df572a22a1f64774d74`; SHA-256 `4cbc0e1ff0546b665e55136c1453334e282d19c380e26b63aa8601cd27a3f90b` |
| Core native runner source | `0d532f2e3bb57a9c82df4967044e4f40861c45a6` |
| Core helper SHA-256 | `d542ca5df79983210bd58a6261384efd5d90cfb6890c8b4680d7b87f90ab9e7a` |
| Core native runner image | `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264` |
| Native model | `gpt-5.6-luna` |
| Core native test binary SHA-256 | `c992dd4ce9fdaeb6895ad827ae8e196155abba5009e2b3da1c4e5931eccd8589` |

The installed product and instrumentation APKs match the archived hashes above (`android-artifacts.json`); both archived installs exited `0` (`install-archived-app.json`, `install-archived-test.json`). Running Hub provenance passed with a clean source tree, the pinned image/catalog, and the expected v1.3 contract (`running-hub-provenance.redacted.json`). The Core helper source and SHA-256 match the values above. No earlier run result is transferred. The installed APKs were reused by their full hashes; no product or test code changed in this checkpoint. Independent inspection also matched the actual runner image and read-only mounted binary against its build metadata (`native-runtime-provenance.redacted.json`).

## Completed Hub and Client setup

| Result | Check | Exit | Evidence |
|---|---|---:|---|
| **PASS** | Verify running Hub source, clean tree, image, catalog, contract, and Core helper metadata | `0` | `running-hub-provenance.redacted.json` |
| **PASS** | Independently compare imported bundle bytes with the pinned archive | `0` | `bundle-image-import.json` |
| **PASS** | Run Docker contract checker with explicit source and catalog pins | `0` | `contract-check.json` |
| **PASS** | Install the archived product APK and test APK | `0` each | `install-archived-app.json`, `install-archived-test.json`, `android-artifacts.json` |
| **PASS** | Sign the scoped external OwnerDeviceGrant through the external host TTY flow | `0` | `owner-sign-device.json` |
| **PASS** | Sign scoped Owner Group grants after Native Join | `0` | `owner-sign-groups.json` |
| **PASS** | `MonitorHubInteropTest#prepareDevice` | `0 / 0` | `native-prepare-device.json` |
| **PASS** | `MonitorHubInteropTest#enrollOwnerAndCheckCapabilities` | `0 / 0` | `native-enroll-capabilities.json` |
| **PASS** | `MonitorHubInteropTest#confirmPendingNodes` | `0 / 0` | `native-confirm-nodes.json`, `two-node-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#createOrReconcileGroup` | `0 / 0` | `native-create-group.json`, `group-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission` | `0 / 0` | `native-role-permission.json`, `permission-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#exportEndpointManifests` | `0 / 0` | `native-manifests.json` |
| **PASS** | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `0 / 0` | `native-group-key-grants.json`, `native-scope-comparison.redacted.json`, `group-key-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#prepareExactTextAndReviewRoster` | `0 / 0` | `native-prepare.json`, `broadcast-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | `0 / 0` | `native-confirm.json` |
| **PASS** | `MonitorHubInteropTest#readNativeDispatchStatus` | `0 / 0` | `native-final-status.json`, `android-final-status.redacted.json` |
| **PASS** | Stage the Group once for the Core native phase | `0` | `native-stage-group.json`, `native-stage-confirmed.json` |
| **PASS** | Native Join readiness for three distinct original Thread/Endpoint candidates (two local, one remote; binding epoch 1) | As recorded | `native-ready.redacted.json` |
| **PASS** | Consume and remove the one-time pairing-code handoff | `0` | `pairing-code-consumed.redacted.json` |

Two Nodes were reviewed and explicitly confirmed; the Group dialog and exact Monitor permission scope were explicitly confirmed on the phone. The scoped external OwnerDeviceGrant and Owner Group grants were signed through the external host TTY flow. Native Join published candidate Endpoint proofs for the three original Threads; those candidate proofs preceded OwnerGroupGrant signing and are not described as current grants. All three Group key grants were independently read back as `CURRENT`; each exact scope was reviewed with one phone confirmation, and the host scope comparison passed. The accepted Android Prepare and outbound Confirm flow passed with exact body whitespace and an explicitly reviewed ordered two-recipient roster. This was one accepted Prepare and one outbound Confirm; these Client RPC results do not establish Core native delivery or model consumption. An inline post-import comparison helper had a **FAIL** (`NameError`, exit `1`) after the payload had been prevalidated. The independent archive-to-import byte comparison and pinned Docker checker then passed; this was a harness failure, not a Hub or protocol failure, and no extra Hub runtime was started for that helper error. The Android consent scope is instrumentation-driven `AlertDialog` prompts on `MainActivity`; it is not a full React Native product-flow acceptance.

## Core gates and runner preflight

The redacted gate audit preserves two separate exact-candidate attempts (`core-gates-and-runner.redacted.json`). Attempt 1 is a harness **FAIL**: six source/image/tag preservation checks exited `0`, but the wrapper then exited `1` because `GO_IMAGE` was undefined. It did not start a candidate Hub or run TCP tests. Attempt 2 passed the required TCP gate (`TestClientDockerHubRecoveryFixture` and `TestClientDockerHubSmoke`, test exit `0`) against the pinned clean Hub source/image and v1.3 contract. Hub health/capability provenance passed. The Core runner was built from the pinned clean archive in Docker; archive, extraction, and compile-only `go test -c ./cmd/cicada` each exited `0`, and the binary SHA-256 matched. No native binary execution is claimed by this preflight.

Attempt 2 also records nonzero cleanup command exits: test-container cleanup inspection `1` and Hub-container removal `1`. Hub cleanup inspection, stop, post-stop inspection, fixture-state cleanup, and candidate-image preservation each exited `0`. These observed command results are retained as-is; they are not rewritten as zero exits or treated as native protocol outcomes.

## Core native result and authoritative status

The sole Core native runner exited `0` on the pinned native image and binary. The run completed one original-monitor preview call and one dispatch call; the redacted outcome confirms the original three-Thread chain and exact body/context at both recipient Threads. Stable child de-duplication was checked in this run. These are run-specific observations and do not establish an arbitrary-fault exactly-once guarantee. Evidence: `core-native-outcome.redacted.json`. The scoped exact-string Hub DB/WAL/SHM scan passed under Core ownership; the Client did not read the Hub database. Automatic approval remained enabled, with one tool call per model turn and no automatic retry.

The native command used the pinned test image and this test suffix:

```text
<owned-fixture>/bin/cicada-android-native.test -test.run '^TestMCPMonitorBroadcastAndroidClientNative$' -test.timeout=35m -test.v
```

The native test exercised two logical Nodes in one native container at controlled original-Thread safe points; it did not test autonomous cold wake. Core-owned Hub and Node cleanup remains pending at Client handoff.

The tenth Android selector, `MonitorHubInteropTest#readNativeDispatchStatus`, passed with ADB and driver exit codes `0 / 0`. It read the existing broadcast's authoritative status as `DISPATCH_AUTHORIZED`, with both ordered recipients `ACCEPTED` (evidence states `RELAY_PERSISTED` and `NODE_REPORTED`). The one status RPC advanced the request sequence by one, left no pending request, and preserved the original operation/Confirm metadata and ordered roster. It created no Prepare or Confirm. The separate Core outcome confirms that both original recipient Threads consumed the exact body and context; this status selector alone makes no consumption claim. Evidence: `native-final-status.json` and `android-final-status.redacted.json`.

## Selector command and remaining gates

All ten fresh Android instrumentation selectors passed, each with ADB and driver exit codes `0 / 0`, using the installed product APK `f8c82d…8700` and test APK `4cbc0e…f90b`:

1. `MonitorHubInteropTest#prepareDevice`
2. `MonitorHubInteropTest#enrollOwnerAndCheckCapabilities`
3. `MonitorHubInteropTest#confirmPendingNodes`
4. `MonitorHubInteropTest#createOrReconcileGroup`
5. `MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission`
6. `MonitorHubInteropTest#exportEndpointManifests`
7. `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent`
8. `MonitorHubInteropTest#prepareExactTextAndReviewRoster`
9. `MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus`
10. `MonitorHubInteropTest#readNativeDispatchStatus`

The command template for each selector is:

```sh
docker exec <owned-container> /opt/android-sdk/platform-tools/adb -P <owned-adb-port> -s <owned-emulator> shell am instrument -w -e run_id <owned-run-id> -e class ai.cicada.client.hub.MonitorHubInteropTest#<selector> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

The driver command is `python3 scripts/interop/monitor-android.py "$E" test ai.cicada.client.hub.MonitorHubInteropTest#<method> --label <label>`. Each selector JSON in the table records the actual Docker/ADB argv, installed artifact identities and both exit codes. Other actual argv records include:

| Command | Exit | Record |
|---|---:|---|
| Pinned Docker Python image, `scripts/check-client-contract.py --snapshot-dir contracts/client-hub-v1.3-25013b5 --source-revision 25013b51915124fa1da25e5fd37088eadf0e3d2d --catalog-sha256 808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377 --contract-revision client-hub-v1.3` | `0` | `contract-check.json` |
| Core read-only helper `sign-groups <fixture> <private-manifests-export> <pinned-external-signer>` with three exact reviewed challenges | `0` | `owner-sign-groups.json` |
| Core helper `stage-confirmed <fixture> <private-prepared-export> <private-result-export>` | `0` | `native-stage-confirmed.json` |
| Core native Docker command with the test suffix above | Start `0`, native exit `0` | `/home/zyf/CICADA/.cicada-data/native-review-0d532f2/native-run.json`; `core-native-outcome.redacted.json` |
| Core helper `verify-private <fixture>` | `0` | Core outcome record; executed only by Core |
| Owned ADB `reverse --remove tcp:32849`, then `docker stop --time 10 <owned-emulator-container>` | `0` each | `native-remove-reverse.json`, `emulator-stop.json` |
| Read-only changed-document/import privacy review | `0` | `client-document-privacy.redacted.json` |

Teardown status at Client handoff:

| Result | Check | Exit | Evidence |
|---|---|---:|---|
| **PASS** | Remove the Client-owned reverse mapping and emulator | `0` | `client-teardown.redacted.json` |
| **NOT_RUN** | Remove the Hub fixture, native Nodes, and Core container from the Client side | — | Core-owned cleanup pending by explicit direction; fixture was not modified by Client |

Full React Native screen-flow acceptance, physical Android, public HTTPS, standalone Kotlin vector reruns, and Group stale/expiry/tamper scenario reruns are **NOT_RUN** in this checkpoint. The public wire/catalog/vectors are byte-identical to the previous imported snapshot; the earlier vector and rejection results retain their original run identities. Real Endpoint proofs were freshly verified by Kotlin in this run. The previously documented reconciled-operation UI limitation remains **BLOCKED** as a separate product follow-up; no new UI test or repair was attempted.

## Evidence location and reporting rules

Run evidence is retained under:

```text
/gpu1-share/data/cicada-client/monitor-v13-25013b5-review-20260927T115633Z/evidence/
```

This report uses redacted result and command metadata. Failures and blocked stages remain assigned to their original runs. Private logs, credentials, raw operational identifiers, signing material and message bodies are excluded from Git. Native dispatch, Hub acceptance, recipient delivery, and model consumption will be reported as separate outcomes; no layer will be inferred from another.
