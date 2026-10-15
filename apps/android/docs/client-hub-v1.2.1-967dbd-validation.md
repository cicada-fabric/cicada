# Client ↔ fixed Hub `client-hub-v1.2.1` validation

**Date:** 2026-09-26

**Client branch:** `dev/react-native`

**Client implementation commit:** `09ecfe761811ceaf37e6deea2842b8a3949dfa46`

**Group verifier timestamp fix commit:** `af3ad451e29d0c43142b3fc792272bbd6df75c84`

**Final live Group implementation commit:** `b676668e33c876c0d2c89bc3495fbd0d1e128c82`

**Scope:** fixed-image package/runtime checks and Android emulator interoperability. This report distinguishes evidence for the v1.2.1 target from the historical `41beaf0` report.

## Fixed target and artifacts

| Item | Value | Result |
|---|---|---|
| Hub source revision | `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` | **PASS** — protocol manifest reports `source_dirty=false`. |
| Contract revision | `client-hub-v1.2.1` | **PASS** — matches imported manifest. |
| Protocol archive SHA-256 | `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a` | **PASS** — package/manifest check reported successful. |
| Catalog SHA-256 | `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9` | **PASS** — matches imported manifest and checked image labels. |
| Full local Docker image ID | `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7` | **PASS** — image labels match the fixed revision and catalog. This is a local image ID, not a registry digest. |
| Earlier recovery/lost-response debug APK SHA-256 | `e75e994608e12b223fb3cb041cf1d3fba1d10411e519a317c4afc25e5c94fed3` | Used for the lost-response and recovery-fault runs; not a release package. |
| Earlier recovery/lost-response AndroidTest APK SHA-256 | `ad8bfa8c8b914677194f1cf493153eaaff67c817fc277d299b0a998a028456b8` | Used for the matching Android instrumentation runs. |
| Pre-fix E2E / Group candidate APK SHA-256 | `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197` | Used for Node setup and initial Group proof tests; it failed the later four-digit timestamp case. Not a release package. |
| Matching pre-fix AndroidTest APK SHA-256 | `50756de57eb0ef2d9ca55feab6222d78bc4849ddf68b203560138918ba8f7c7f` | Used for the matching candidate tests. |
| Corrected Group verifier APK SHA-256 | `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76` | Corrected four-digit RFC3339Nano handling; not a release package. |
| Corrected Group verifier AndroidTest APK SHA-256 | `711e00f9fee11582c81af14e5a2c9d77799412166a8a3cd7008ec7cb16d27ab0` | Used for the final Endpoint and wire/recovery-lock tests. |
| Final live Group debug APK SHA-256 | `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1` | Used for the later disposable one-Owner Group acceptance only. |
| Final live Group AndroidTest APK SHA-256 | `52e9e678666654d57bd127b5f616a3094e9a9925b9fe5b960632c7cb81d6f9d5` | Matching final Group instrumentation APK. |

The imported snapshot and its manifest are under [`contracts/client-hub-v1.2.1-967dbd`](../contracts/client-hub-v1.2.1-967dbd/manifest.json). Raw logs, credentials, test state, and private test identities remain outside Git at `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/`. The sanitized fixed-target summary is `evidence/fixed-target-summary.json` in that directory.

## Build and contract checks

| Check | Command | Result |
|---|---|---|
| Protocol archive and manifest | `sha256sum /home/zyf/CICADA/.cicada-data/contracts/client-hub-7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a.tar.gz`; `python3 ../CICADA/scripts/client-contract.py verify /home/zyf/CICADA/.cicada-data/contracts/client-hub-7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a.tar.gz` | **PASS**, both exit 0; archive SHA-256, full Hub commit, `source_dirty=false`, and catalog match the fixed values above. |
| Local Hub image metadata and running image | `docker image inspect sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7 --format '{{json .Config.Labels}}'`; `docker inspect cicada-client-hub-v121-967dbd --format '{{.Image}}'` | **PASS**, both exit 0 before the disposable Hub was removed; full image ID and labels match the fixed target. |
| Recovery/lost-response Android app/test build | `./scripts/docker-build-android-test.sh` | **PASS**, exit 0. Produced the earlier `e75e…`/`ad8b…` APK pair above. |
| Pre-fix Group verifier candidate build | `./scripts/docker-build-android-test.sh`; build log `/gpu1-share/data/cicada-client/group-audit-android-build.log`, Android test log `/gpu1-share/data/cicada-client/group-audit-androidtest.log` | **PASS**, exit 0. Produced `7042…`/`5075…`; later compatibility checking found the timestamp failure recorded below. |
| Corrected Group verifier build | `./scripts/docker-build-android-test.sh`; build log `/gpu1-share/data/cicada-client/group-audit-rfc3339-android-build.log`, Android test log `/gpu1-share/data/cicada-client/group-audit-rfc3339-androidtest.log` | **PASS**, exit 0. Produced corrected APKs `2762…`/`711e…`. |
| TypeScript compile | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules -w /workspace cicada-client-rn:dev ./node_modules/.bin/tsc --noEmit --noUnusedLocals --noUnusedParameters` | **PASS**, exit 0. |
| Lint | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace" -v /gpu1-share/data/cicada-client/node_modules:/workspace/node_modules -w /workspace cicada-client-rn:dev npm run lint -- --quiet` | **PASS**, exit 0. |
| Client contract checker | `python3 scripts/check-client-contract.py` | **PASS**, exit 0. |
| Documentation/worktree whitespace check | `git diff --check` | **PASS**, exit 0. |

Final Kotlin instrumentation ran on `emulator-5554` against the corrected `2762…`/`711e…` APK/test pair:

| Test | Command | Result |
|---|---|---|
| Public wire vectors | `docker exec cicada-client-interop-emulator /opt/android-sdk/platform-tools/adb -s emulator-5554 shell am instrument -w -e class ai.cicada.client.hub.ClientWirePublicVectorTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` | **PASS**, exit 0; JUnit `OK (5 tests)`. |
| Recovery lock | Same command with `ClientHubRecoveryLockTest` as the `-e class` value | **PASS**, exit 0; JUnit `OK (3 tests)`. |
| Endpoint proof, manifest, and owner proof | `docker exec cicada-client-interop-emulator /opt/android-sdk/platform-tools/adb -s emulator-5554 shell am instrument -w -e class ai.cicada.client.hub.EndpointAttestationVectorTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` | **PASS**, ADB exit 0; JUnit `OK (4 tests)`. |

Final wire and recovery-lock logs are `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/evidence/{ClientWirePublicVectorTest,ClientHubRecoveryLockTest}-rfc3339-final.log`; the Endpoint test log is `/gpu1-share/data/cicada-client/group-audit-rfc3339-androidtest.log`.

The corrected APK was also installed on a fresh Android 35 emulator (`emulator-5590`) for the UI and vector smoke:

```bash
CICADA_EMULATOR_VECTOR_CHECK=1 ./scripts/docker-emulator-check.sh
```

**PASS**, script exit 0. The five pages and composer opened, and `ClientWirePublicVectorTest` returned `OK (5 tests)`. Evidence is `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/evidence/rfc3339-final-ui-smoke.log`. The installed debug APK was SHA-256 `2762a2defd13a0d85bc9a7c96647cbe626f632314ac958d4d1fe689ebd346b76`; test APK was `711e00f9fee11582c81af14e5a2c9d77799412166a8a3cd7008ec7cb16d27ab0`.

The corrected `EndpointAttestationVectorTest` covers the published full Endpoint proof, synthetic manifest digests, and owner proof. Its `OK (4 tests)` supersedes the pre-fix candidate's `OK (4 tests)` and the earlier `OK (3 tests)` run; the pre-fix suite lacked the valid four-digit fraction case.

## Android encrypted session and lost-response recovery

| Validation | Command/evidence | Result |
|---|---|---|
| Encrypted `session.capabilities` | Independent Android session against the fixed Hub; exercised in the enrollment/session setup. Logs are in `evidence/{processing,uncertain,legacy}-enrollAndRead.log`. | **PASS**. |
| Current Node/Codex run enrollment and status setup | `enrollAndRead` on the `7042…` candidate against Hub port 8794 | **PASS**, JUnit `OK (1 test)`, ADB exit 0. It verified encrypted capabilities and status; log: `evidence/android-enroll-and-read.log`. This setup result does not establish Node binding or Group grant behavior. |
| Current Node binding | A fresh `cicada machine agent --once` reached the expected pending-device-code state (agent exit 1 before Client confirmation); the code was stored outside Git with mode `0600`. Android `confirmDisposableNodeForQueuedGoal` checked the previewed Node ID and called encrypted `nodes.confirm`. | **PASS** — Android runner and ADB exit 0, JUnit `OK (1 test)`. The complete approval and result flow also **PASS**; see [Real Node/Codex approval and result](#real-nodecodex-approval-and-result-pass) for all five tests and evidence paths. |
| Lost enrollment HTTP 201 | `python3 /gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/run-loss-tests.py` | **PASS**, runner exit 0. `ClientHubInteropTest#lostEnrollment201ReplaysPersistedGrantAfterSessionReconstruction`: JUnit `OK (1 test)`, ADB exit 0. Proxy log confirms upstream 201 was discarded downstream. |
| Lost encrypted RPC HTTP 200 | Same `run-loss-tests.py` command | **PASS**, runner exit 0. `ClientHubInteropTest#lostRpc200RecoversSameEncryptedResponseWithoutNewOperation`: JUnit `OK (1 test)`, ADB exit 0. Proxy log confirms upstream 200 was discarded downstream. |

The two instrumentation logs and their proxy logs are under `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/evidence/loss-v121/`. Both tests reused the exact persisted request; the RPC recovery returned the original response without a new operation.

## Real Node/Codex approval and result (PASS)

The E2E run used the fixed Hub image above, Client source commit `09ecfe761811ceaf37e6deea2842b8a3949dfa46`, debug APK SHA-256 `70423555e96381722d1bdc46633d32c0fca6dc32edae4dfb45865abc1059d197`, AndroidTest APK SHA-256 `50756de57eb0ef2d9ca55feab6222d78bc4849ddf68b203560138918ba8f7c7f`, and Android 35 emulator `emulator-5592`. Codex CLI was `0.156.1`, model `gpt-5.6-luna`; the Node binary SHA-256 was `2403dab2b03f0f702b9ba001642488fa3ac40dbd7950654d748565f159fe0f5c`.

The two APK install commands both exited 0:

```bash
docker exec cicada-client-interop-emulator /opt/android-sdk/platform-tools/adb -s emulator-5592 install -r /tmp/cicada-v121-final.apk
docker exec cicada-client-interop-emulator /opt/android-sdk/platform-tools/adb -s emulator-5592 install -r /tmp/cicada-v121-final-test.apk
```

Node was driven using `python3 run-node-once.py register`, `python3 run-node-once.py ready`, and `python3 run-node-once.py worker`. Each wrapper exited 0. The expected register state was `awaiting_owner_confirmation` (the agent process exited 1 before confirmation); after Android confirmation the ready and worker agent runs exited 0.

Each Android test used `python3 run-android-test.py <spec.json>`; the runner executed `docker exec cicada-client-interop-emulator /opt/android-sdk/platform-tools/adb -s emulator-5592 shell am instrument -w [private spec arguments] -e class ai.cicada.client.ClientHubInteropTest#<method> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner`. Private spec arguments are not stored in this report. All five runner/ADB invocations exited 0 and each returned JUnit `OK (1 test)`:

| Test method | Result |
|---|---|
| `prepareDevice` | **PASS** |
| `enrollAndRead` | **PASS** — encrypted `session.capabilities` and status read. |
| `confirmDisposableNodeForQueuedGoal` | **PASS** — Android previewed the expected Node ID and confirmed the pending Node code through encrypted RPC. |
| `submitBoundedRealCodexGoal` | **PASS** — the fresh Node Agent received the bounded Goal. |
| `approveOriginalRealCodexTurnAndReadResult` | **PASS** — Android accepted one approval on the original Codex turn and read the result. |

The verification summary reports one accepted original-thread approval; native Thread and Worker identity matched across the approval and result, with Worker attempt 1. The Worker and Goal completed, the Intent resolved, and the Hub returned HTTP 200 for the Node result. `goal.result` was present and byte-matched the Node result exactly (30 bytes, SHA-256 `073c6a7ecaf2bfe415bf6c56a1dc13aedd00bbb7bfd007100ede2dcb6548e4f1`). Redacted IDs: Node `client-test-node-v121…`, Intent `intent_2e429…`, Goal `goal_93873…`, Worker `worker_a56bb…`. Native Thread SHA-256: `4d0b7282b7f8d0db671aa2d429e4b00083eb89350e0a776ea0432f367d38a031`; Worker SHA-256: `249910ab0459805201ec4b68e0538d9346f9606d466520d64afa15ca97c732cd`.

The sanitized summary is `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/evidence/native-e2e-rerun/native-e2e-summary.json` (directory `0700`, file `0600`; evidence scripts `0700`). Raw per-step logs are in the same directory: `install-debug-apk-final.log`, `install-android-test-apk-final.log`, `prepare-device-final-apk.log`, `android-enroll-and-read.log`, `android-confirm-disposable-node.log`, `android-submit-real-codex-goal.log`, `android-approve-original-turn-and-read-result.log`, `node-register.log`, `node-ready.log`, and `node-worker.log`. The `7042…` APK predates the Group verifier timestamp fix; this E2E exercises the existing Intent/Node/Codex path and does not test Group key operations. The topology snapshot/Endpoint/Group membership probe was **NOT_RUN**.

The one-time Codex container used the provider environment file read-only at `/run/secrets/provider.env`; the secret was consumed only by that Codex process and was not logged. The Node process received no model API key or Hub bearer, and no credential was added to the repository or APK. After evidence capture, the proxy, temporary Node/Codex state, wrapper, code, and result marker were removed; the one-time Codex container used `--rm`. The dedicated emulator app state was retained for review. The disposable Hub `cicada-client-hub-v121-967dbd` was stopped and removed; resident Hub containers were left untouched.

**Corrected initial setup attempts:** one early `prepareDevice` output-capture/parser attempt failed and was later rerun successfully against the candidate APK. The first signer-container invocation also failed before a successful JDK 17 compilation. These attempts are preserved in the private command log, but none of the five final assertions depends on them.

## Recovery faults on the disposable fixed image

Each scenario used a new disposable `/tmp` Hub and an independent enrolled Android session. Run the scenario command for each case:

```bash
python3 /gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/run-fault-scenario.py processing
python3 /gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/run-fault-scenario.py uncertain
python3 /gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/run-fault-scenario.py legacy
```

Each command exited 0. The stepwise Android instrumentation checks for each scenario were `prepareDevice`, `enrollAndRead`, `switchEnrolledSessionToIsolatedFaultProxy`, and `faultProxyPersistsOneExactSnapshotPacket`, followed by that scenario's recovery test. Each reported JUnit `OK (1 test)` and ADB exit 0.

| Scenario | Android test | Result |
|---|---|---|
| Request remains in progress | `faultProxyRecoverStillProcessingKeepsExactPending` | **PASS** — exact original packet recovers as HTTP 409 `STILL_PROCESSING`; the pending request remains unchanged. |
| Hub restart after accepted request | `faultProxyRecoverUncertainReconcilesWithoutSecondWrite` | **PASS** — the fixture reached `FAULT_READY`; the runner restarted only the disposable `cicada-client-hub-v121-fault` container before recovery. Android received and verified the signed encrypted `OUTCOME_UNCERTAIN` result, retained uncertainty, and did not issue a second write. |
| Legacy request without a reserved response sequence | `faultProxyRecoverUnavailableFencesOriginalPacket` | **PASS** — exact original packet recovers as HTTP 409 `RECOVERY_UNAVAILABLE`; Client fences it without guessing a sequence or re-executing the operation. |

Evidence logs are under `/gpu1-share/data/cicada-client/hub-v1.2.1-967dbd/evidence/`: scenario instrumentation logs use `{processing,uncertain,legacy}-<method>.log`; proxy logs use `proxy-<scenario>.log`. Raw logs stay outside the repository.

**Failed initial attempt:** running the recovery fixture from a `/gpu1`-rooted location returned HTTP 502 because the core fixture requires a real `/tmp` root. This attempt is recorded as **FAIL**. It is not counted as an Android scenario result. The corrected runs above used disposable `/tmp` state and passed all three cases.

## Endpoint attestation and Group key status

The v1.2.1 wire contract corrects the v1 attestation signed bytes: ordered compact JSON contains a final `"signature":null` property when generating unsigned claims. The imported bundle includes a public synthetic vector with the full proof, public identity, signed-input bytes, and proof digest.

| Check | Result |
|---|---|
| Kotlin independent verification of the published Endpoint vector, synthetic manifest digests, and owner proof | **PASS** on corrected APK `2762a2…`: `EndpointAttestationVectorTest`, JUnit `OK (4 tests)`, ADB exit 0. |
| Android native Group preview/grant/status path | Implemented with import of an externally signed `signed_proof`, explicit Android confirmation and encrypted status reads. The APK does not import the owner private key; it verifies against the owner public approval key saved from authenticated enrollment. Candidate proof tests and the separate live acceptance passed. |
| RFC3339Nano four-digit fractional timestamp compatibility | **FAIL** on pre-fix APK `70423555…` because Kotlin `Instant.toString()` rejected a valid timestamp form; **PASS** after the fix on APK `2762a2…` in commit `af3ad451e29d0c43142b3fc792272bbd6df75c84`. Build and Endpoint test both passed. |
| Positive current-image `group.key_manifest/grant/status` flow | **PASS** in the later disposable Group fixture on implementation commit `b676668e33c876c0d2c89bc3495fbd0d1e128c82`, APK `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1`, AndroidTest `52e9e678666654d57bd127b5f616a3094e9a9925b9fe5b960632c7cb81d6f9d5`. A real native Codex Thread published a leased candidate; Android verified the manifest, accepted an externally signed Owner proof after an on-device tap, and read `CURRENT`. See the [separate acceptance report](client-group-key-v1.2.1-disposable-validation.md). |

This differs from the historical `41beaf0` report, which marked Group signing blocked because the v1.2 prose and implementation disagreed. The v1.2.1 contract and synthetic vector resolve that contract ambiguity. The initial candidate suite missed the valid four-digit fractional timestamp; the corrected suite includes it. The later Group acceptance uses its own final APK hashes and does not retroactively turn the older `7042…` Node/Codex APK into Group evidence.

### Later disposable Group acceptance on the final APK pair

The Group run used a new disposable Hub with the **same full fixed image ID** in this report, a synthetic external Owner, a separately signed Android device Grant, an owner-bound Node, and a real native Codex Thread. Its private evidence root is `/gpu1-share/data/cicada-client/group-key-v121-967dbd/evidence` (`0700`; files `0600`). The [Group acceptance report](client-group-key-v1.2.1-disposable-validation.md) contains the full command table, individual exits, hashed Endpoint/Session/Group/Node/binding labels and failure boundaries. Let `$E` denote that evidence root; command arguments carrying IDs, codes or proofs are omitted below.

| Check | Result | Command / exit | Evidence under `$E` |
|---|---|---|---|
| Package, image, encrypted `session.capabilities` | **PASS** | `client-contract.py verify <fixed archive>`: 0; `docker image inspect <full image ID>`: 0; `python3 "$E/run-android-test.py" "$E/external-capabilities.spec.json"`: 0, JUnit `OK (1 test)` | `fixed-target-provenance.json`, `external-capabilities.log` |
| Android Owner enrollment, pending Node confirmation, encrypted Group creation | **PASS**, with separate failed harness attempts below | `python3 "$E/run-android-test.py" "$E/prepare-device.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/reconcile-group.spec.json"`: 0, JUnit `OK (1 test)`; reviewed on-screen taps: 0 | `prepare-device.log`, `device-signer.private.log`, `reconcile-group.log`, native authenticated Join |
| Same native Codex MCP context: `cicada_join`, separate `cicada_publish_endpoint_key_candidate`; full manifest verification and external Owner signing | **PASS** | `python3 "$E/rapid-prepare-grant.py" finalui`: 0; Android manifest JUnit `OK (1 test)` | `codex-finalui.private.jsonl`, `native-finalui.private.json`, `manifest-finalui.log`, `group-signer-finalui.private.log` |
| Android explicit confirmation, encrypted grant and status | **PASS: `CURRENT`** | `python3 "$E/run-android-test.py" "$E/grant-finalui.spec.json"`: 0, JUnit `OK (1 test)`; on-screen tap: 0 | `grant-finalui.log`, `grant-finalui-dialog.private.png`, `grant-finalui.private.json` |
| Client tamper rejection; wrong Owner key selection; missing Group/Endpoint encrypted business rejection | **PASS**, limited to these checks | `python3 "$E/run-android-test.py" "$E/reject-tampered-proof-finalui.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/reject-wrong-scope.spec.json"`: 0; each JUnit `OK (1 test)` | `reject-tampered-proof-finalui.log`, `reject-wrong-scope.log` |
| Native binding lease expiry; signed proof expiry | **PASS: `STALE`, `PROOF_EXPIRED`** | `python3 "$E/run-android-test.py" "$E/status-stale-finalui.spec.json"`: 0; `python3 "$E/run-android-test.py" "$E/status-proof-expired-finalui.spec.json"`: 0; each JUnit `OK (1 test)` | `status-stale-finalui.log`, `status-proof-expired-finalui.log` |
| First manager-role assertion; combined Node preview/Group runner | **FAIL** as setup harness attempts; subsequent authenticated runs above passed | `python3 "$E/run-android-test.py" "$E/enroll-and-capabilities.spec.json"`: runner 1, ADB 0, JUnit `FAILURES!!!`; `python3 "$E/run-android-test.py" "$E/confirm-node-create-group.spec.json"`: runner 1, ADB 0, JUnit `FAILURES!!!` | `enroll-and-capabilities.log`, `confirm-node-create-group.log`; code-bearing spec deleted at teardown |
| Independent server submission of altered proof; second real Owner cross-owner authorization | **NOT_RUN** | No qualifying command; local Client rejected the altered proof, and fixture had one Owner | Not claimed by the positive result |
| Android hardware; public HTTPS | **NOT_RUN** | No command run | Emulator loopback only |

There is no remaining **BLOCKED** gate for the one-Owner positive path. The initial long Node state path blocked the Join socket, then a short real private path allowed the final run. After `PROOF_EXPIRED`, Node and Hub teardown, ADB reverse removal and emulator app-data clearing each exited 0; checks found no fixture container or mapping. The one-time synthetic Node code briefly appeared in process arguments and transient process inspection; it expired and its private spec was deleted. The Group report records this test-harness privacy finding. Existing N4/N5 recovery PASS results above are separate and were not rerun or relabeled for the final Group APK.

## Separate two-Owner authorization acceptance — 2026-09-26

The [two-Owner authorization report](client-two-owner-v1.2.1-967dbd-validation.md)
adds **PASS** evidence for two independently registered Owners on the same fixed
image. It does not alter the one-Owner run's `NOT_RUN` entries above. Client
instrumentation/fixture commit is `680fac2bf12c431ac02804e5db168669cf12941f`;
the debug APK is `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1`
and the distinct AndroidTest APK is
`342845155edf0333e3b81aa736d25945e8d83554a61c26fc1bf438c314d26ae0`.

Final evidence root:
`/gpu1-share/data/cicada-client/two-owner-20260926T024036Z-cto-9uslracc/evidence`.
`summary.redacted.json` contains classifications and hashed object IDs;
`android-artifacts.json` contains hashes and the Client source commit. The four
commands `python3 scripts/interop/two-owner-android.py /tmp/cto.9uslracc test
<method>` used methods `prepareTwoOwnerDeviceKeys`,
`enrollConfirmAndCreateOwnerGroups`, `exportOwnerGroupManifests`, and
`twoOwnerOwnershipAndRevocationMatrix`. Each returned runner exit 0, ADB exit 0
and JUnit `OK (1 test)`; matching `<method>.json` files record exact commands.

| Check | Result |
|---|---|
| Package, full image and encrypted capabilities identity | **PASS**; unchanged fixed values in this report, independently checked again. |
| Own Group grants and status for A and B | **PASS**; both `CURRENT`, with separate external signatures and phone confirmations. |
| A→B and B→A manifest/status/grant on real foreign objects | **PASS**; six authenticated HTTP 200 encrypted `permission denied` results. |
| Server-side altered Owner signature | **PASS**; independent test-only encrypted submission reached the Hub signature verifier and was rejected. |
| Local preflight, journal/response recipient isolation, unchanged target grants | **PASS**; independently asserted. Hub transport counters advance for authenticated business rejections. |
| Revoke A, fresh and original packet requests, B continuing normally | **PASS**; fresh request, `/rpc` replay and `/rpc/recover` returned HTTP 403; B retained `CURRENT`. |
| Cleanup and known synthetic-secret checks | **PASS**; fixture `stop` exit 0, `teardown.json`; 13 known secret values absent from checked files and both APKs. |
| New native Thread, N4/N5 recovery or vector reruns in this slice | **NOT_RUN**; existing results retain their original APK/run attribution. |
| Physical Android and public HTTPS | **NOT_RUN**. |

The Endpoint adapters in this slice are explicitly synthetic. They establish
authorization/protocol behavior, not a new native Codex acceptance. There is no
remaining **BLOCKED** item for this slice. Both fresh-run resources and the
earlier development-run resources were removed. The separate report preserves
the failed initial compile and strict-signer input-format attempts; all final
fresh-run stages passed. No core code or resident Hub was modified, and the
tests performed no direct database inspection or SQL mutation. Synthetic Owner
registration used the fixed image's supported offline CLI while its disposable
Hub was stopped.

## Other current-image work and platform limits

| Area | Result |
|---|---|
| Real Node/Codex approval flow | **PASS** on this fixed image; see the E2E section for APK hashes, commands, exits, redacted identities, and result byte-match. The earlier `41beaf0` result is historical and is not carried forward. |
| Physical Android device | **NOT_RUN**. |
| Public HTTPS | **NOT_RUN**. |
| iOS and native HarmonyOS | **NOT_RUN**; neither platform is the current validated target. |

## Historical boundary and security

The [historical v1.2 report](client-hub-v1.2-41beaf0-validation.md) records Hub commit `41beaf0fa57e8279ad993fa4ce070a33515851ba`. It previously marked the three fixed-image Android recovery fault cases `NOT_RUN` and reported a Group attestation contract mismatch. Those results remain unchanged as historical evidence; v1.2.1 has separate package, image, and Android results above. The prior real Node/Codex PASS is not evidence for this new image.

All integration state was disposable. The Android Client used its independently pinned Hub identity, owner-signed enrollment, encrypted `session.capabilities`, and encrypted `/v2/client/rpc`; it did not use `/v1` bearer APIs or inspect the Hub database. The fixed contract advertises `status_events=false` and `external_thread_links=false`. Cross-user Link records remain proposals, and this report does not claim ordinary peer content is hidden from Hub/Control. Emulator HTTP and these integration runs do not establish physical-device key isolation or public TLS validation.
