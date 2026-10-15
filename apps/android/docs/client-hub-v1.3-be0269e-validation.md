# Client Monitor validation — fixed Hub v1.3 / `be0269e`

**Evidence date:** 2026-09-27

**Branch at start:** `dev/react-native`

**Starting Client commit:** `a4007a51b53a36b15ecc02cbf50bdac4f744ec56`

## Acceptance status

The encrypted Monitor protocol path and listed Android emulator checks **PASS** on the fixed Hub image, including Set H's current-grant revocation guard and corrected React Native UI result adapter. This is **partial protocol acceptance**, not release acceptance. The UI flow was same-owner with synthetic Node and Endpoint fixtures; it displayed Hub `APPROVED` with an empty recipient outcome ledger. It does not demonstrate recipient delivery, a native Thread, native Monitor, Runtime delivery or model consumption.

The stale-permission negative test exposed a real failure on Client commit `7086095`: the Client sealed and submitted after `message.broadcast` had been revoked. Commit `69ecfa1` added authoritative pre-seal reads and independently verifies the current Monitor Group grant. The Set G attempt failed (**FAIL**) because it ran after the original Owner grant cutoff: the Client safely blocked with `MONITOR_PREVIEW_NOT_CONFIRMABLE` before sending Confirm, while the test expected `MONITOR_PREVIEW_REFRESH_FAILED`. The Set H rerun with current phase-3 grants passed (**PASS**): revocation produced `MONITOR_PREVIEW_REFRESH_FAILED` and `confirmAttempted=false`, so no Confirm was submitted. The Set G expiry-cutoff result remains a historical failed attempt.

The fixed Fabric parent display passed the Set G layout test. Set G's full UI flow failed (**FAIL**) because the native bridge returned a raw RPC shape while TypeScript expected a camelCase DTO. Set H fixed that adapter and the complete React Native Monitor flow passed (**PASS**), displaying Hub status `APPROVED`; recipient delivery was not demonstrated. The earlier permission failure remains attributed to `7086095`. The later `a712f79` APK has no final Monitor suite run in this evidence set; results from `69ecfa1` are not attributed to it. Physical Android and public HTTPS were **NOT_RUN**.

## Separately executed recovery fault follow-up

The subsequent [Monitor Prepare RPC recovery report](client-monitor-v13-recovery-faults.md)
records **PASS** for `STILL_PROCESSING`, signed `OUTCOME_UNCERTAIN` and
`RECOVERY_UNAVAILABLE` on three fresh fixed-image Hubs and Android sessions.
It used the unchanged Set H app APK with a new test APK from `cc634e6`.
The core helper populated only the RPC recovery ledger; no Monitor business
handler, Confirm or native delivery ran. The Set H tables and its `NOT_RUN`
entries below remain the results of that earlier run, with their original
artifacts and evidence. They are not silently replaced by the follow-up.

## Separately executed native Monitor attempt

The [joint native Monitor report](client-monitor-v13-native-acceptance.md)
records a subsequent **FAIL** on this same fixed Hub: the native runner could
not renew an original Session lease while waiting for Android authorization.
Six Android setup, permission and full-manifest selectors passed. No external
Group proof was signed, no Group grant was submitted, and no positive Prepare
or Confirm was sent. Delivery and final native status remain **NOT_RUN** for
that attempt. Its new test APK and core test source are recorded separately;
the installed Set H app was retained. This failure does not overwrite the
protocol/UI or transport-recovery results above.

## Fixed integration target

| Item | Value |
|---|---|
| Hub source | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` |
| Contract | `client-hub-v1.3`, wire v1, 33 catalog operations |
| Protocol archive SHA-256 | `68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Hub image | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |
| Image source fingerprint | `f21f206525c9deb6f959988d675606257ee796ae39f46b973f9bdd714cda7e4e` |
| Source cleanliness | `source_dirty=false`; image label `org.cicada.build.dirty=false` |

The imported package is [the v1.3 snapshot](../contracts/client-hub-v1.3-be0269e/manifest.json). The package’s pre-freeze prose was retained byte-for-byte. The recorded verification command was:

```text
python3 ../CICADA/scripts/client-contract.py verify /home/zyf/CICADA/.cicada-data/contracts/monitor-v13-be0269e/client-hub-68a7db6a3238605feb340012886dddd2054a577801154236c39d4ed7d84db2a9.tar.gz
exit: 0
```

`python3 scripts/check-client-contract.py` also exited `0`. The Client independently checked the archive digest, manifest, 15 payload files, source revision, clean-source flag, catalog and image labels. Evidence: `bundle-core-verify.json`, `contract-import-check.json`, `fixed-target.json`.

## Recorded Android artifacts

Instrumentation JSON records name the exact app and test APK used. Do not carry a result from one row to a different app APK.

| Set | Client source commit | App APK SHA-256 | Test APK SHA-256 | Use in this report |
|---|---|---|---|---|
| A | `537b92e99bf45476d8e0ea2793308cb70e8023df` | `832045f5fa2044a99f54c61534c0554abc563549937973a27c7e9e678f30315d` | `2cc6acbb9fe47427728930b8954f3c665d3f4b18d647f108dc6a87f0bf3245c5` | Historical runs |
| B | `586e736691d9ebcc8e672d2ecbe98ac802248f7d` | `832045f5fa2044a99f54c61534c0554abc563549937973a27c7e9e678f30315d` | `05d40d5ee8a36f8796c145f5e996911db2ed04a3e89f4e969a5d73523577b71c` | Historical runs |
| C | `7086095087d391992bb94f1bcf0651cd3bcb3a0c` | `7e27b3941cf8e268555f910accdd8e7e95263b2e951904f9d4365d939907a6a6` | `fb267dccc954cc37f14c9cd68306ae6e85881ea2008b96e9e22dd0c4ccff2410` | Original-packet loss/recovery and earlier stale-permission failure |
| D | `69ecfa18a20c20c2500c411b5e5cd1780d1bb494` | `939b0e748b4db3d0cc72ae4b66979dd94ef0e94f09f935f1b68d2d553cf8a7da` | `cd86525f427ff7de24cfa6bef0d55e1e194dcd20176cc3fd530e815e499cd557` | Final13 protocol suite |
| E | `02ec31c7742966b710cac8c272fd64fd9fa8f688` | `3c272dcfcdb2864cb270378c03d840611ec7dfe1e760b3e0227f6446faaafc3c` | `7368db99745e35d255bfe8a595c08bedc1cd09b6bfb15b62545f15c0575675ae` | Historical recovery-lock failure |
| F | `a712f79547c9d54dd31b92434566083f550b2b6f` | `883f6c3c63166f9016163622f34b2701202ea46cf3cd3ff3a15e96de55c6926b` | `cd86525f427ff7de24cfa6bef0d55e1e194dcd20176cc3fd530e815e499cd557` | Later build artifact; final Monitor suite **NOT_RUN** against this app APK |
| G | `31ec0cc4ba2e1704fffa06a88ea542cf239fb257` | `ab3707309bde741f9f6937f21c9bb5827a4ac456c297329830fa2fd7cb43dfe8` | `aba2d98487cb3d928b3b10d9401d19fdd4f99d114d326daee6f895a897c34720` | Final15 layout, grants, protocol guards and exact-packet recovery; full UI flow **FAIL**, fresh-grant permission negative **NOT_RUN** |
| H | `9568b2ff6d4e156b70484c10b7fd5195405004b0` | `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` | `aba2d98487cb3d928b3b10d9401d19fdd4f99d114d326daee6f895a897c34720` | Final16 complete UI, fresh-grant permission guard, recovery and tooling; full flow and listed protocol checks **PASS** |

Artifact metadata files are under `evidence/android-artifacts*.json`. A subsequent UI build or test APK requires its own artifact record and test results.

## Reproduction commands

All instrumented runs below used the isolated Docker Android container and emulator. The JSON records store the full command; this is its fixed prefix, followed by the selector in each table row:

```text
docker exec cicada-monitor-v13-20260927T005634Z-be0269e \
  /opt/android-sdk/platform-tools/adb -P 5070 -s emulator-5640 \
  shell am instrument -w \
  -e run_id monitor-v13-20260927T005634Z-be0269e \
  -e class <selector> \
  ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner
```

For these rows, `ADB/driver` reports the instrumentation command exit and the recorded driver exit. `JUnit` is the summary in the same JSON. Each evidence filename below is relative to:

```text
/gpu1-share/data/cicada-client/monitor-v13-20260927T005634Z-be0269e/evidence/
```

The final Android build log `android-build-13-current-authority.private.log` records Gradle tasks `:app:assembleDebug` and `:app:assembleDebugAndroidTest` and `BUILD SUCCESSFUL`; the exact shell wrapper was not recorded in that log. It produced Set D. `android-build-14-monitor-layout.private.log` also records successful assemble tasks for the later Set F artifact, but no final Monitor suite was run against Set F. Sets G and H were built with `./scripts/docker-build-android-test.sh` (exit `0`), recorded in `android-build-15-stable-host.json` and `android-build-16-native-result-adapter.json` respectively.

## Final13 protocol checks — Set D / `69ecfa1`

These records all used app SHA `939b0e748b4db3d0cc72ae4b66979dd94ef0e94f09f935f1b68d2d553cf8a7da` and test SHA `cd86525f427ff7de24cfa6bef0d55e1e194dcd20176cc3fd530e815e499cd557`. Each exact selector was invoked with the command above.

| Result | Exact selector | ADB/driver | JUnit | Evidence |
|---|---|---:|---|---|
| PASS | `MonitorHubInteropTest#readFixedCapabilitiesAfterAppUpdate` | `0 / 0` | `OK (1 test)` | `final13-capabilities.json` |
| PASS | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `0 / 0` | `OK (1 test)` | `final13-group-grants.json` |
| PASS | `MonitorHubInteropTest#prepareExactTextAndReviewRoster` | `0 / 0` | `OK (1 test)` | `final13-prepare-roster.json` |
| PASS | `MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus` | `0 / 0` | `OK (1 test)` | `final13-confirm-status.json` |
| PASS | `MonitorHubInteropTest#reconcileRejectedConfirmationWithAuthoritativeStatus` | `0 / 0` | `OK (1 test)` | `final13-rejected-status.json` |
| PASS | `MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission` | `0 / 0` | `OK (1 test)` | `final13-explicit-permission.json` |
| PASS | `MonitorHubInteropTest#exportEndpointManifests` | `0 / 0` | `OK (1 test)` | `final13-manifests.json` |
| PASS | `MonitorBroadcastVectorTest` | `0 / 0` | `OK (6 tests)` | `final13-monitor-vectors.json` |
| PASS | `EndpointAttestationVectorTest` | `0 / 0` | `OK (4 tests)` | `final13-endpoint-vectors.json` |
| PASS | `ClientWirePublicVectorTest` | `0 / 0` | `OK (5 tests)` | `final13-wire-vectors.json` |
| PASS | `ClientHubRecoveryLockTest` | `0 / 0` | `OK (6 tests)` | `final13-recovery-locks.json` |

The explicit-permission setup and Group-grant test passed with freshly prepared phase-2 grants; the old archived grants were not reused. The verified Group key status was `CURRENT`. See `phase2-fixture-preparation.redacted.json`, `final13-group-grants.json` and `final13-manifests.json`. No Owner, Group, Endpoint or key identifier is repeated here.

The positive Monitor flow passed against the fixed real Hub: capability read, preview and ordered consent review, user-confirmed v2 envelope submission, then status read. The Hub and the Android device were real services in the isolated test environment; the Node and Monitor/recipient Endpoints were **synthetic fixtures**, not native CICADA processes.

## Final15 layout, protocol guard and recovery checks — Set G / `31ec0cc`

These checks used app SHA `ab3707309bde741f9f6937f21c9bb5827a4ac456c297329830fa2fd7cb43dfe8` and test SHA `aba2d98487cb3d928b3b10d9401d19fdd4f99d114d326daee6f895a897c34720`. Instrumentation commands used the reproduction prefix above.

| Result | Exact selector / command | Exit | JUnit | Evidence |
|---|---|---:|---|---|
| PASS | `MonitorProductLayoutTest` | `0 / 0` | `OK (1 test)` | `final15-product-layout.json` |
| PASS | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `0 / 0` | `OK (1 test)` | `final15-group-grants.json` |
| PASS | `MonitorHubInteropTest#rejectChangedTextAndUnknownPreviewBeforeSending` | `0 / 0` | `OK (1 test)` | `final15-reject-body-preview.json` |
| PASS | `MonitorHubInteropTest#capacityReturnsOneBoundedRejectionWithoutRetry` | `0 / 0` | `OK (1 test)` | `final15-capacity.json` |
| PASS | `MonitorHubInteropTest#prepareResponseLossKeepsOriginalPacket` | `0 / 0` | `OK (1 test)` | `final15-dropped-prepare.json` |
| PASS | `MonitorHubInteropTest#recoverLostPrepareWithoutAnotherOperation` | `0 / 0` | `OK (1 test)` | `final15-recovered-prepare.json` |
| PASS | `MonitorHubInteropTest#confirmResponseLossKeepsOriginalSealedEnvelope` | `0 / 0` | `OK (1 test)` | `final15-dropped-confirm.json` |
| PASS | `MonitorHubInteropTest#recoverLostConfirmAndReadOriginalStatus` | `0 / 0` | `OK (1 test)` | `final15-recovered-confirm.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node node_modules/typescript/bin/tsc --noEmit` | `0 / 0` | — | `final15-typescript.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node --test tests/monitorBroadcast.test.mjs` | `0 / 0` | — | `final15-javascript.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node node_modules/eslint/bin/eslint.js .` | `0 / 0` | — | `final15-eslint.json` |

The product-layout test and `final15-layout-probe.redacted.json` record a visible Monitor panel host with measured dimensions and visible child controls, addressing the prior blank Fabric parent display case. The Group grant test recorded the freshly renewed phase-2 Owner grants as `CURRENT` at binding epoch 2; prior archived grants were not reused. Separately, `phase3-fixture-preparation.redacted.json` records a **PASS** normal synthetic Join refresh with epoch-3 leases for the Monitor and both recipient fixtures; this is fixture preparation, not Android acceptance. The Confirm proxy record `final15-proxy-confirm-accepted-drop.private.log` states `DROPPED` for `monitor.broadcast_confirm` after Hub HTTP `200`, and its `docker logs` command exited `0`. Prepare and Confirm exact-packet loss recovery passed on Set G; neither test used a replacement operation or a newly sealed envelope. A manual Set G flow reached Hub status `APPROVED`, but the UI did not render the status because the native result shape and TypeScript DTO adapter disagreed; this full UI flow failed (**FAIL**). The stale-permission test attempt was blocked safely by the elapsed grant cutoff; Set H later passed the revocation case with current grants.

## Final16 UI and fresh-grant protocol checks — Set H / `9568b2f`

These checks used app SHA `f8c82d7091ffebb6add77c003c55a6f033ad657475b51b62b512bef5b0ed8700` and test SHA `aba2d98487cb3d928b3b10d9401d19fdd4f99d114d326daee6f895a897c34720`. Instrumented tests used the Docker/ADB reproduction command above; each JSON record contains its exact command and artifact hashes.

| Result | Exact selector / command | Exit | JUnit | Evidence |
|---|---|---:|---|---|
| PASS | Full React Native Monitor UI flow; action sequence recorded in the `final16` tap/capture JSONs | `0` | — | `final16-product-ui.redacted.json`, `final16-fresh-approved-status.private.png` |
| PASS | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` | `0 / 0` | `OK (1 test)` | `final16-group-grants.json` |
| PASS | `MonitorHubInteropTest#grantEndpointKeysAndReadCurrent` after fresh-grant flow | `0 / 0` | `OK (1 test)` | `final16-fresh-group-grants.json` |
| PASS | `MonitorHubInteropTest#exportEndpointManifests` | `0 / 0` | `OK (1 test)` | `final16-fresh-manifests.json` |
| PASS | `MonitorHubInteropTest#rejectChangedTextAndUnknownPreviewBeforeSending` | `0 / 0` | `OK (1 test)` | `final16-reject-body-preview.json` |
| PASS | `MonitorHubInteropTest#capacityReturnsOneBoundedRejectionWithoutRetry` | `0 / 0` | `OK (1 test)` | `final16-capacity.json` |
| PASS | `MonitorHubInteropTest#rejectStalePreviewAfterBroadcastPermissionRevoked` | `0 / 0` | `OK (1 test)` | `final16-reject-stale.json` |
| PASS | `MonitorHubInteropTest#prepareResponseLossKeepsOriginalPacket` | `0 / 0` | `OK (1 test)` | `final16-dropped-prepare.json` |
| PASS | `MonitorHubInteropTest#recoverLostPrepareWithoutAnotherOperation` | `0 / 0` | `OK (1 test)` | `final16-recovered-prepare.json` |
| PASS | `MonitorHubInteropTest#confirmResponseLossKeepsOriginalSealedEnvelope` | `0 / 0` | `OK (1 test)` | `final16-dropped-confirm.json` |
| PASS | `MonitorHubInteropTest#recoverLostConfirmAndReadOriginalStatus` | `0 / 0` | `OK (1 test)` | `final16-recovered-confirm.json` |
| PASS | `MonitorHubInteropTest#readFixedCapabilitiesAfterAppUpdate` | `0 / 0` | `OK (1 test)` | `final16-capabilities.json` |
| PASS | `MonitorBroadcastVectorTest` | `0 / 0` | `OK (6 tests)` | `final16-monitor-vectors.json` |
| PASS | `EndpointAttestationVectorTest` | `0 / 0` | `OK (4 tests)` | `final16-endpoint-vectors.json` |
| PASS | `ClientWirePublicVectorTest` | `0 / 0` | `OK (5 tests)` | `final16-wire-vectors.json` |
| PASS | `ClientHubRecoveryLockTest` | `0 / 0` | `OK (6 tests)` | `final16-recovery-locks.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node node_modules/typescript/bin/tsc --noEmit` | `0 / 0` | — | `final16-typescript.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node --test tests/monitorBroadcast.test.mjs` | `0 / 0` | — | `final16-javascript.json` |
| PASS | `docker run --rm --user 1000:1000 -v /home/zyf/CICADA_CLIENT:/workspace:ro -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules:ro sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 node node_modules/eslint/bin/eslint.js .` | `0 / 0` | — | `final16-eslint.json` |

Set H was built with `./scripts/docker-build-android-test.sh` (exit `0`; `android-build-16-native-result-adapter.json`). The UI evidence shows the corrected native-to-TypeScript result adapter displaying Hub status `APPROVED` for the same-owner synthetic flow; the recipient outcome ledger was empty, so it does not show recipient delivery or native Thread consumption. Both Group-grant test runs reported all three phase-3 endpoints as `CURRENT` at epoch 3. In the stale-permission test, revocation produced `MONITOR_PREVIEW_REFRESH_FAILED` and `confirmAttempted=false`, so the native path rejected before sending a Confirm. The accepted-200 Prepare/Confirm loss tests recovered the original exact request/envelope and did not create a replacement operation or seal. `log-cicada-monitor-v13-20260927T005634Z-be0269e-proxy-phase3-prepare.private.log` records the Prepare response drop after Hub HTTP `200`; `final16-proxy-confirm-accepted-drop.private.log` records the corresponding Confirm response drop. Both `docker logs` commands exited `0` and have matching command JSON records. The final Kotlin vector/recovery suites passed 21 tests total (6 Monitor, 4 Endpoint, 5 wire and 6 recovery-lock tests); the encrypted capability read passed separately.

The first Set H UI Prepare attempt was **BLOCKED** by an expired Owner grant in the fixture, not by the bridge adapter: the original signed validity window ended at `03:53:14Z`, and signing a new Owner grant at `03:47Z` did not restart the grant lifetime derived from the manifest's issue time. A fresh manifest was then exported and signed with an Owner grant valid from `03:58:05Z` to `04:13:05Z`, and the complete same-owner flow passed. This fixture-scheduling attempt is distinct from Set G's UI adapter **FAIL**. Evidence: `capture-final16-flow-error-notice.json`, `phase3-manifests-preparation.json`, `final16-fresh-manifests.json`, and the final product UI evidence above.

## Exact-packet loss and recovery — Set C / `7086095`

Each test used app SHA `7e27b3941cf8e268555f910accdd8e7e95263b2e951904f9d4365d939907a6a6` and test SHA `fb267dccc954cc37f14c9cd68306ae6e85881ea2008b96e9e22dd0c4ccff2410`.

| Result | Exact selector | ADB/driver | JUnit | Evidence |
|---|---|---:|---|---|
| PASS | `MonitorHubInteropTest#prepareResponseLossKeepsOriginalPacket` | `0 / 0` | `OK (1 test)` | `corrected-dropped-prepare.json` |
| PASS | `MonitorHubInteropTest#recoverLostPrepareWithoutAnotherOperation` | `0 / 0` | `OK (1 test)` | `corrected-recovered-prepare.json` |
| PASS | `MonitorHubInteropTest#confirmResponseLossKeepsOriginalSealedEnvelope` | `0 / 0` | `OK (1 test)` | `corrected-dropped-confirm.json` |
| PASS | `MonitorHubInteropTest#recoverLostConfirmAndReadOriginalStatus` | `0 / 0` | `OK (1 test)` | `corrected-recovered-confirm.json` |
| PASS | `MonitorHubInteropTest#recoverOriginalPrepareAfterPreviewExpiry` | `0 / 0` | `OK (1 test)` | `corrected-expired-original-prepare.json` |

The proxy logs establish Hub acceptance before dropping the response: `proxy-prepare-accepted-drop.private.log` records `DROPPED` with `hub_status=200` for `monitor.broadcast_prepare`; the newly archived `proxy-confirm-accepted-drop.private.log` records the same for `monitor.broadcast_confirm`. The matching proxy log commands exited `0` (`proxy-confirm-accepted-drop.json` records `docker logs ...`, exit `0`). The tests then recovered using the durable original encrypted packet/envelope, preserved the original operation, and created no replacement Prepare or Confirm. The expired Prepare recovery was read-only and did not authorize confirmation.

## Revoked permission: failed negative and correction boundary

| Run | Exact selector / command | ADB/driver | Client commit / app APK | Evidence and finding |
|---|---|---:|---|---|
| FAIL | `MonitorHubInteropTest#rejectStalePreviewAfterBroadcastPermissionRevoked`, using the reproduction command above | `0 / 1`; no successful JUnit summary | `7086095087d391992bb94f1bcf0651cd3bcb3a0c` / Set C app SHA | `corrected-stale-permission-rejection.json`, `stale-permission-attempt.redacted.json`: the Client sealed and attempted Confirm after the explicit permission revocation; Hub rejected it. This is a real preflight regression, not a pass. |
| FAIL | `MonitorHubInteropTest#rejectStalePreviewAfterBroadcastPermissionRevoked`, using the reproduction command above | `0 / 1`; JUnit comparison failure | `31ec0cc4ba2e1704fffa06a88ea542cf239fb257` / Set G app SHA | `final15-reject-stale.json`, `final15-reject-stale.private.log`: expected `MONITOR_PREVIEW_REFRESH_FAILED`, received `MONITOR_PREVIEW_NOT_CONFIRMABLE`. The original Owner grant had expired before the test reached Confirm; the native preflight blocked before sending a Confirm. This verifies the local expiry cutoff but does not exercise permission revocation. |
| PASS | `MonitorHubInteropTest#rejectStalePreviewAfterBroadcastPermissionRevoked` with current phase-3 grants | `0 / 0`; `OK (1 test)` | `9568b2ff6d4e156b70484c10b7fd5195405004b0` / Set H app SHA | `final16-reject-stale.json`: revocation returned `MONITOR_PREVIEW_REFRESH_FAILED`, with `confirmAttempted=false`. The stale-permission guard rejected before submitting Confirm. |

The current reads use the encrypted Client RPC path. Topology CAS versions are not treated as signed Group manifest revisions. `CURRENT` status is not accepted as a substitute for verifying the signed Owner grant and Endpoint attestation.

`MonitorHubInteropTest#reconcileRejectedConfirmationWithAuthoritativeStatus` passed on Set D (`final13-rejected-status.json`); it exercises read-only status reconciliation after a rejected Confirm and ensures a second Confirm is not submitted. It is separate from the fresh-grant permission-revocation test that passed on Set H.

## Historical failures retained

These are earlier attempts, not current acceptance results. The records remain in the evidence directory; later passing attempts do not erase or relabel them.

| Failed attempt | Recorded result | Source/APK attribution | What the record says | Evidence |
|---|---|---|---|---|
| Initial prepare recovery | ADB `0`, driver `1`, JUnit NR | Set A / `537b92e`; app SHA `832045…30315d` | Recovery case failed; distinct from the later accepted-200 case. | `recovered-prepare-original-packet.json` |
| Accepted-200 Prepare recovery | ADB `0`, driver `1`, JUnit NR | Set B / `586e736`; app SHA `832045…30315d` | A still-current Owner grant was incorrectly rejected because the verifier required it to outlast the longer preview. Core confirmed the cover-the-entire-preview rule was wrong; Set C later passed recovered Prepare and expired read-only recovery. | `recovered-prepare-accepted-200.json` |
| Proof diagnosis | ADB `0`, driver `1`, JUnit NR | Set B / `586e736` | Diagnostic failure; not positive recovery evidence. | `diagnose-recovered-prepare-proof.json` |
| Recovery lock suite | ADB `0`, driver `1`, JUnit NR | Set E / `02ec31c`; app SHA `3c272d…afc3c` | A test expected the Monitor-local code before the global business-reconciliation guard. Expectations were corrected; Set D later passed the suite. | `final-recovery-locks.json`, `final-recovery-locks-corrected.json`, `final13-recovery-locks.json` |
| Earlier prepare, Confirm/status, vector and expiry attempts | ADB `0`, driver `1`, JUnit NR | Artifact metadata was not attached to each record; do not infer it from adjacent runs. | These include failed attempts later covered by distinct passing selectors. | `final-prepare-roster.json`, `final-confirm-status.json`, `kotlin-monitor-vectors.json`, `late-prepare-expiry.json` |
| Phase-2 permission setup | ADB `0`, driver `1`, JUnit NR | Set C / `7086095` | Earlier setup attempt failed. The same explicit role/permission selector later passed on Set D; this does not close the separate stale-permission negative. | `phase2-explicit-permission.json`, `final13-explicit-permission.json` |
| Proxy startup | Docker exit `125`, driver `1` | No Client APK | Container name was already in use. A later distinct proxy instance supplied the accepted-200 Prepare evidence above. | `proxy-start-drop-prepare.json` |
| Product UI startup | ADB/driver `1 / 1` | No Android artifact metadata in this record | This earlier startup attempt failed; a corrected startup, Set G layout test and Set H full UI flow later passed. | `ui-product-start.json`, `ui-product-start-corrected.json`, `final15-product-layout.json`, `final16-product-ui.redacted.json` |
| First Set H UI Prepare with an expired Owner grant | BLOCKED by fixture validity cutoff | Set H app SHA `f8c82d…8700` | The first UI attempt was correctly rejected because its signed Owner grant had expired; the fixture was refreshed without extending the old signed validity window, after which the full UI flow passed on the same artifact. This is a fixture-scheduling attempt, distinct from Set G's bridge DTO failure. | `capture-final16-flow-error-notice.json`, `phase3-manifests-preparation.json`, `final16-fresh-manifests.json`, `final16-product-ui.redacted.json` |

The early [evidence index](client-monitor-v13-evidence-index.md) is a point-in-time index of the earlier acceptance runs. This report adds the later Set C/Set D/Set G/Set H evidence and keeps the preceding failures attributed to their original runs.

## UI, runtime and security boundaries

- The Set G product-layout test and probe passed (**PASS**) for the previously blank Fabric parent case. Set G's full UI flow failed (**FAIL**) on the native/TypeScript DTO mismatch; the adapter fix then passed the Set H full UI flow, which displayed `APPROVED`. Recipient delivery was not demonstrated. This is not a general UI accessibility or usability audit.
- The Hub, test Node and Monitor/recipient Endpoints used here are synthetic/disposable. No native Monitor process, native Thread delivery, Runtime injection, model consumption or native Node pair was validated: **NOT_RUN**.
- Physical Android device: **NOT_RUN**. Dual physical Nodes: **NOT_RUN**. Public HTTPS endpoint: **NOT_RUN**.
- Live v1.3 Monitor `STILL_PROCESSING`, `OUTCOME_UNCERTAIN` and `RECOVERY_UNAVAILABLE` fault scenarios: **NOT_RUN**. Local uncertainty guards passed; earlier v1.2.1 live fault results remain historical.
- `privacy-check.redacted.json` is a scoped Set H audit: 18 known disposable secret representations across 204 worktree files and both uncompressed Set H APKs, with zero matches (command exit `0`). The earlier Set C result is retained separately as `privacy-check-set-c.redacted.json`. Neither is a universal secret audit.
- No result here establishes production readiness, public-network TLS behavior, Android hardware-backed private-key boundary, or blind-Hub peer-message confidentiality.
- No core repository edits, credential imports into Android/Git/APKs, pushes, merges or production deployment are part of this validation.

## Final16 provenance, privacy and cleanup

| Check | Result | Command / evidence |
|---|---|---|
| Fixed Hub image provenance after final runs | PASS | `docker image inspect sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783 --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}} {{index .Config.Labels "org.cicada.build.dirty"}}'`; exit `0`, `final16-runtime-provenance.json`. The recorded image is the fixed full image with the expected Hub revision and `dirty=false`. |
| Final Set H scoped privacy scan | PASS | `python3 /gpu1-share/data/cicada-client/monitor-v13-20260927T005634Z-be0269e/evidence/fixture_privacy_audit.py`; exit `0`, `privacy-check.redacted.json`: 18 known disposable values, 204 worktree files and both final APKs checked; no matches. |
| Owned proxy stopped | PASS | `final16-proxy-stop.json`, exit `0` |
| Emulator test container stopped | PASS | `emulator-stop.json`, exit `0` |
| Core synthetic fixture stopped | PASS | `final16-core-fixture-stop.json`, exit `0` |
| ADB reverse mapping removed | PASS | `final16-remove-reverse.json`, exit `0` |
| Aggregate teardown | PASS | `final16-teardown.redacted.json`: owned proxy and emulator removed, disposable Hub/Node/Owner private directory removed, resident Hubs untouched; evidence directory mode `0700`, files `0600`. No containers with the test's owned labels remained after teardown. |

The older Set C scan remains available as `privacy-check-set-c.redacted.json`; Set H's scan does not rewrite its result. Private cleanup command arguments and fixture material remain in the access-controlled evidence files, not in this report.

## Evidence location

Raw and redacted execution records are retained at:

```text
/gpu1-share/data/cicada-client/monitor-v13-20260927T005634Z-be0269e/evidence
```

Private fixture files, raw logs and screenshots remain access-controlled. This report intentionally omits Owner/Node/Group/Endpoint/device identifiers, keys, device codes and message bodies. Hub HTTP `200`, approval, `NODE_REPORTED` or `RELAY_PERSISTED` is not evidence of native consumption or successful work.
