# Client-Control v1.3 candidate validation — `81d8f1f`

**Evidence date:** 2026-09-27

**Offline bundle, checker, Android vectors, exact-image gate, and Client-to-Hub Monitor selectors:** **PASS**.

**Full Core native recipient scenario:** **FAIL** (native test container exit `1`). **Remote consumption:** **NOT_RUN**. **Old-run cleanup:** **PASS**.

This report records offline contract and Android public-vector checks, fixed-image Core smoke/recovery gates, real Android-to-Hub Group authorization and Monitor Prepare/Confirm, and the Hub's final dispatch status. The later Core-owned native recipient assertion failed after dispatch; this does not indicate a Client RPC or Hub approval failure. The earlier `be0269e` native failure remains in [its separate report](client-monitor-v13-native-acceptance.md); neither run's result is transferred to the other.

## Fixed candidate and contract bundle

| Item | Verified value |
|---|---|
| Hub source revision | `81d8f1f90895f41c4f5ea5c67a6281ccda9e1264` |
| Hub image | `sha256:0c484d1c10a9fd71e6ae74ddd7fec85ae6ae8cbecf2ece6f90d393892990a04f` |
| Image source fingerprint | `50d0a9250631381949f2aa5e155424996aa13490759107e597d354e620a8b2c8` |
| Image source state | `source_dirty=false`; role `hub` |
| Contract revision | `client-hub-v1.3` |
| Bundle archive SHA-256 | `6eaa692cc9e31e0482d94ed9f26ed277dfc91fd37333949d3e2517f498ba4061` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Imported snapshot | `contracts/client-hub-v1.3-81d8f1f` |

The fixed-image preflight verified the image labels and clean source metadata (**PASS**, exit `0`). The bundle import preserved all 15 payloads and original bytes, and left the previous snapshot unchanged (**PASS**, exit `0`). The exact candidate image was subsequently started and its running provenance matched the fixed image, source revision, and clean fingerprint (**PASS**, exit `0`). Core's exact-image gate ran `TestClientDockerHubRecoveryFixture` and `TestClientDockerHubSmoke`; both passed (test exit `0`).

## Contract checker and bundle checks

The checker was given the expected source revision and catalog digest explicitly. It verifies those caller-pinned values against the imported manifest and payload bytes rather than trusting values supplied by the candidate manifest.

| Check | Command / result | Evidence |
|---|---|---|
| Bundle import, 15 payloads | **PASS**, exit `0`; original bytes preserved | `bundle-import.json` |
| Fixed Hub image preflight | **PASS**, exit `0`; clean source fingerprint and expected labels | `candidate-image-preflight.json` |
| Running candidate provenance | **PASS**, exit `0`; running Hub matched the fixed image and clean source | `running-hub-provenance.redacted.json` |
| Core exact-image gate | **PASS**, exit `0`; recovery-fixture and Hub smoke tests | `core-exact-image-gate.redacted.json` |
| Core helper/native source preflight | **PASS**, exit `0`; clean helper source `28bd4626a2f29553a07c7e0f881da6c939016c01`, separate from Hub source | `runner-source-preflight.json` |
| Core signing helper correction | **PASS**; TTY-backed signer fix source `1ef25baf1a5d39e51394dcb87e00ec93a6826cc8`, helper SHA-256 `3ba4008e86bd93fd30335efc8547407039bef5979fe62586fefbb9d0caaaf85c`, distinct from fixed Hub image | Core helper provenance; initial blocked preflight in `signer-stdin-preflight.redacted.json` |
| Contract checker | **PASS**, exit `0` | `candidate-contract-check.json` |
| Checker CLI regressions | **PASS**, exit `0`; 9 offline regression cases | `contract-checker-regressions.json` |

The checker invocation used the pinned, network-disabled Python image `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`:

```sh
docker run --rm --network none --user 1000:1000 \
  --mount type=bind,src=/home/zyf/CICADA_CLIENT,dst=/workspace,readonly \
  -w /workspace --entrypoint python3 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  scripts/check-client-contract.py \
  --snapshot-dir contracts/client-hub-v1.3-81d8f1f \
  --source-revision 81d8f1f90895f41c4f5ea5c67a6281ccda9e1264 \
  --catalog-sha256 808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377
```

The regression command was run in the same container image with `--network none` and exited `0`:

```sh
docker run --rm --network none --user 1000:1000 \
  --mount type=bind,src=/home/zyf/CICADA_CLIENT,dst=/workspace,readonly \
  -w /workspace --entrypoint python3 \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  scripts/test_check_client_contract.py -v
```

The 9 regression cases cover default and explicit pins, tampered payloads, dirty source, wrong catalog, unlisted files, symlink/traversal rejection, manifest wire version, and Python optimized mode.

## Android artifact separation

| Artifact | Source | SHA-256 | Use |
|---|---|---|---|
| Installed product APK | `9568b2ff6d4e156b70484c10b7fd5195405004b0` | `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` | Retained unchanged; no new product APK was installed |
| Initial test APK | Test source `1172000f5ebd03a34b0b589702f1fc7d56409433` | `ea6bcc09d456da0fd2b5fb14f11a92ba88f55e965a9eff474af86ccac3512601` | Used for the first vector attempt, including the failed Monitor suite |
| Final test-only APK | Test source `10cd3dcb3bd73e6513df428ced81d95788e1cb84` | `8c2f122e76e22f6845bbdaf0518146ed94a1f6895abdab1147d3010b4c531e09` | Installed for the final offline vector rerun; product APK remained unchanged |
| App rebuilt alongside final test APK | Source `10cd3dcb3bd73e6513df428ced81d95788e1cb84` | `c2c9f5eb0047ba1d710feb9981e268932d12b04081792ee4e9a6c81754d1e5f2` | Build output only; **not installed** |

`./scripts/docker-build-android-test.sh` exited `0`. The test-only APK installation command was:

```sh
docker exec cicada-monitor-v13-81d8f1f-20260927T061404Z \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  install -r /out/canonical-vector-test.private.apk
```

Both the ADB and driver exited `0`. The test-only timestamp fix did not change production app source. These vector results exercise Android test code and public protocol vectors; they do not validate product UI flows or Hub runtime integration.

## Real Hub and Android setup

The running Hub provenance record matches the target image, source revision, and fingerprint listed above; fixture identity matched the marked setup (**PASS**, exit `0`). Core's exact-image recovery/smoke gate passed before Client enrollment. The Core helper/native source preflight was clean at commit `28bd4626a2f29553a07c7e0f881da6c939016c01`, separate from the Hub source and image.

The product APK remained `f8c82d…8700` (source `9568b2…`); the installed test-only APK was `8c2f122e…c531e09` (test source `10cd3d…`). Explicit phone approvals used instrumentation-driven Android dialogs on the App activity; these selectors do not repeat the full React Native consent-screen acceptance from Set H. All Android stages below passed one instrumentation test each, with ADB/driver exit codes `0 / 0`:

| Result | Selector | Stage | Evidence |
|---|---|---|---|
| **PASS** | `MonitorHubInteropTest#prepareDevice` | Device preparation | `native-prepare-device.json` |
| **PASS** | `MonitorHubInteropTest#enrollOwnerAndCheckCapabilities` | Enrollment and encrypted v1.3/catalog-pinned `session.capabilities` | `native-enroll-capabilities.json` |
| **PASS** | `MonitorHubInteropTest#confirmPendingNodes` | Confirm two explicitly configured logical Nodes | `native-confirm-nodes.json` |
| **PASS** | `MonitorHubInteropTest#createOrReconcileGroup` | Create/reconcile Group and review its scope in the UI | `native-create-group.json`, `group-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission` | Explicit Monitor role and broadcast permission confirmation | `native-role-permission.json`, `native-permission-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#exportEndpointManifests` | Export Endpoint manifests | `native-manifests.json`, `native-endpoints-ready.redacted.json` |
| **PASS** | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | Review and grant Group keys; read three endpoints as `CURRENT` | `native-group-key-grants.json`, `group-key-reviews.redacted.json` |
| **PASS** | `MonitorHubInteropTest#prepareExactTextAndReviewRoster` | Prepare exact text and review the ordered roster | `native-prepare.json`, `broadcast-review.redacted.json` |
| **PASS** | `MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | Confirm the reviewed envelope and read status | `native-confirm.json`, `android-confirmed-handoff.redacted.json` |
| **PASS** | `MonitorHubInteropTest#readNativeDispatchStatus` | Read final authoritative dispatch status | `native-final-status.json` |

The Android selector command pattern was:

```sh
docker exec cicada-monitor-v13-81d8f1f-20260927T061404Z \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  shell am instrument -w \
  -e run_id monitor-v13-81d8f1f-20260927T061404Z \
  -e class ai.cicada.client.hub.MonitorHubInteropTest#<selector> \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

Three distinct original native Threads/Endpoints had current external Owner proofs. The exact Group-key scope and Monitor permission were reviewed and confirmed on the phone. A signing-helper preflight initially reported **BLOCKED** after nested stdin reached EOF; its reproducer exited `0`, with zero signatures attempted and zero grants submitted (`signer-stdin-preflight.redacted.json`). Core corrected its TTY-backed signing helper at commit `1ef25baf1a5d39e51394dcb87e00ec93a6826cc8`, SHA-256 `3ba4008e86bd93fd30335efc8547407039bef5979fe62586fefbb9d0caaaf85c`; the subsequent current grants and phone confirmations passed. This Core helper is distinct from both the fixed Hub and the native Go test source.

The Android handoff record reports one positive Prepare and one outbound Confirm; a duplicate Confirm was blocked locally before another RPC. The final status selector made one read-only status RPC, not a new Prepare or Confirm. It returned `DISPATCH_AUTHORIZED` with exactly two ordered `ACCEPTED` outcomes: local `NODE_REPORTED` and remote `RELAY_PERSISTED`. Counters advanced by one and no pending operation remained. This status check passed, but `native_consumption_claimed=false`; it does not establish recipient consumption.

## Core native recipient result

The full Core-owned native scenario is **FAIL**. The detached test container exited `1`; the Docker launcher itself exited `0`. The sanitized command record identifies Core source `28bd4626a2f29553a07c7e0f881da6c939016c01`, native binary SHA-256 `3af7d347f2aba99d5d17366b6edcc70b631c422149434dbcf368d401064d26fe`, and test `^TestMCPMonitorBroadcastAndroidClientNative$` under runner image `sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`. The full Docker argv and per-run fixture/container values remain in `core-native-failure.redacted.json`; this report omits those private paths and identifiers.

After the native Monitor sent the approved broadcast and created both stable child messages, Core's local recipient no-tool recall assertion failed: `same_thread=true`, `local_context_matched=true`, `local_child_message_id_matched=true`, and `local_exact_body_marker_matched=false`. The local structured receive had passed the exact-body and message-identity checks. Android subsequently read the Hub's successful dispatch status; this later read does not pass the failed recall assertion. Remote recipient model receive was not reached, so remote consumption is **NOT_RUN**. The native model was `gpt-5.6-luna`; `core-native-failure.redacted.json` records the command and actual container exit. `core-native-stage-go.json` records only the preceding handoff and stage gates.

This run's Core native result remains **FAIL**. The separately authorized clarified-prompt retry is recorded in [its own report](client-monitor-v13-81d8f1f-recall-validation.md); no result is transferred to this run.

## Offline Android vectors

All three public assets matched byte-for-byte across the v1.3 bundle and installed final test APK (**PASS**, exit `0`):

| Asset | SHA-256 |
|---|---|
| `client-control-v1.json` | `f8b7e5d0a547cd1403645f9c3bd0b8f15f0b838ff66b0d5c0ff572c4be0861e0` |
| `endpoint-key-attestation-v1.json` | `735072be3d4b68fc54d50f7feb705a5adb5928214fa00348e6607c6a708d3b51` |
| `monitor-broadcast-consent-v2.json` | `012a0ed6d36d00e2b7d985e767d7221eb1db04f1eba60565f17c86364600996a` |

The final instrumentation suites all passed with ADB and driver exit codes `0 / 0`:

| Result | Selector | Tests | Evidence |
|---|---|---:|---|
| **PASS** | `ai.cicada.client.hub.MonitorBroadcastVectorTest` | 6 | `final-monitor-vectors.json` |
| **PASS** | `ai.cicada.client.hub.EndpointAttestationVectorTest` | 4 | `final-endpoint-vectors.json` |
| **PASS** | `ai.cicada.client.hub.ClientWirePublicVectorTest` | 5 | `final-wire-vectors.json` |

The recorded driver command was `python3 scripts/interop/monitor-android.py /gpu1-share/data/cicada-client/monitor-v13-81d8f1f-20260927T061404Z/evidence test <selector> --label <evidence-name>`, with the selector and label from the table. `offline-vector-acceptance.redacted.json` aggregates these 15 passing offline tests; its Hub-runtime field records the state when that offline phase was captured, before the subsequent Hub startup and setup documented below.

### Preserved first vector attempt

The first Monitor vector run is retained as **FAIL**: 6 tests ran and 2 failed; ADB exited `0` while the test driver exited `1`. Endpoint (4 tests) and Wire (5 tests) passed in that attempt. The synthetic test timestamps used `Instant.toString()`, which retained fractional trailing zeroes and did not match the required canonical Go RFC3339Nano form. The fix changed only test timestamp generation: it truncates the synthetic clock to seconds and formats timestamps canonically, with a deterministic 180 ms check. The production verifier was unchanged. The corrected test-only APK then passed all 6 Monitor vectors. Evidence: `initial-vector-attempt.redacted.json`, `candidate-monitor-vectors.json`, and the final suite records above.

## Runtime scope and remaining checks

| Result | Scope |
|---|---|
| **PASS** | Offline import/check of the fixed v1.3 bundle and clean Hub image metadata |
| **PASS** | Android public protocol-vector tests on an emulator with the retained product APK and test-only APK |
| **PASS** | Fixed Hub provenance and Core exact-image recovery/smoke gate |
| **PASS** | Encrypted Android enrollment, Node/Group setup, three current Endpoint key grants, explicit phone approval, Monitor Prepare/Confirm, and final Hub dispatch status |
| **FAIL** | Full Core native recipient scenario; test container exit `1` on local no-tool recall assertion after successful dispatch |
| **NOT_RUN** | Remote recipient consumption |
| **PASS** | Old-run fixture, emulator, ADB reverse mapping, and Core test-container cleanup after evidence archive |
| **NOT_RUN** | Physical Android, public HTTPS, and production endpoint acceptance |

This emulator run verifies real encrypted Android-to-Hub Monitor authorization and the Hub's dispatch state for the fixed development image. The overall Core native recipient scenario remains **FAIL** because of the post-dispatch local no-tool recall assertion. It does not prove remote consumption or establish physical-device, public-HTTPS, or production acceptance. The earlier `be0269e` failure and any separately authorized retry remain attributable to their own fixed sources, images, and evidence.

## Core evidence and cleanup

Core archived the old native run under `/home/zyf/CICADA/.cicada-data/native-joint-leasefix-28bd4626/`: `native-run.json`, `failure-analysis.json`, `failure-scoped-hub-scan.json`, `stage-confirmed.json`, and `cleanup-old-native.json`. Core's scoped scan covered only its disposable Hub SQLite/WAL/SHM files and found no synthetic private-text marker. The sanitized failure record says no Hub database or credentials were copied. The Client did not inspect the database.

Old-run cleanup is **PASS**, aggregate exit `0` (`native-teardown.redacted.json`). The owned ADB reverse mapping, emulator, Hub fixture, and Core native test container were removed; the individual cleanup command records each exited `0` (`native-remove-reverse.json`, `emulator-stop.json`, `native-fixture-stop.json`). The aggregate explicitly records `new_fixture_untouched=true`; the separate recall retry fixture was not modified.

## Evidence location

Redacted result metadata and command records are under:

```text
/gpu1-share/data/cicada-client/monitor-v13-81d8f1f-20260927T061404Z/evidence/
```

Raw private logs, credentials, device keys, signatures, operation identifiers, and message bodies are not included here.
