# Client-Control v1.6.1 acceptance — clean Core 144e079

## Scope

This record covers the Client checkout following
`65d6a399122055e1bd38dfb70fa93686806bee36` on `dev/react-native`.
It preserves the existing application and adds bounded acceptance drivers.
The full delivery commit is bound after the combined milestone commit in
`client-final-144e079-20261002/provenance/client-delivery.redacted.json`. No push, merge, model invocation or production deployment is authorized.

## Immutable target

| Item | Value |
|---|---|
| Core revision | `144e079ddf62a4e08f1d1cf9476ab41d25d28f5c` |
| Protocol / wire | `client-hub-v1.6.1` / `1` |
| Protocol archive SHA-256 | `0835e10f229900e120b458211469e80d9bb0804bd40cb8d464ef1a196bd11dee` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Core source fingerprint | `e64f244961d56265933dd75feec19d2b74fa934533abf9b750c061f09094a902` |
| Hub image ID | `sha256:04e8bcb4e22f4a00100b30a57d8cd5b3c65d5d4abe3d09844f5c121c26beb1bb` |
| Interop image ID | `sha256:4ddf7bdc25c7da2fd59024a1a85006f7370e40e14f9546d65fcbea9f2ac957d3` |

The 21 public payload files are imported under
`contracts/client-hub-v1.6.1-144e079/`. Their bytes and SHA-256 values match
the archive manifest, whose SHA-256 is
`d51991ea40c9d033c8b1d1ab019b6f273f9dd33de0730fea7bc5422ee2164175`.
The previous `fe565b4` snapshot remains historical evidence.

## Build artifacts

The final pair was built offline in Docker image
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
Docker's data root was `/gpu1-share/data/docker-root`.

| Artifact | SHA-256 |
|---|---|
| Debug application APK | `74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` |
| Final instrumentation APK | `17fd9e576c821eee3c5d7f434e40a29fc320d884d241c8a7c084960dea4f2621` |
| Compiled input fingerprint, 118 files | `8a08d5775a7b6abbd9187fc6c91420f5c9d66b859e1692329a43620565ba0a5e` |

The source fingerprint matched before and after the build. The application
APK equals the previous application binary because production code did not
change; current acceptance is separately attributed to this target and final
instrumentation APK. Artifacts and the exact Docker command are in
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/build-final/`.

## Acceptance matrix

| Gate | Result | Evidence |
|---|---|---|
| Archive manifest, 21 payloads, catalog and source pins | PASS | `provenance/contract-import.json` |
| Independent data, immutable Git and current raw modes, 806 inputs | PASS | `provenance/independent-inventory-verification.receipt.json` |
| Full Hub / interop image IDs and provenance labels | PASS | Same provenance receipt |
| Offline Docker contract checker | PASS | `provenance/contract-check-docker.receipt.json`, exit 0 |
| Recovery / Link driver AST and CLI checks | PASS | `driver-check/driver-static-check.json` |
| Corrected APK pair build | PASS | `build-final/build.receipt.json`, exit 0 |
| Android independent Kotlin matrix, 81 tests | PASS | Base v2 `android/deterministic-summary.redacted.json`, exit 0 |
| Offline React Native UI smoke checks | PASS | Base v2 Android UI receipts, exit 0 |
| Encrypted enrollment and current `session.capabilities` | PASS | Base v2 `android/directory.redacted.json` and encrypted role oracle |
| Enrollment HTTP 201 loss, exact Grant retry | PASS | Base v2 `android/enrollment-recovery.redacted.json`, selector exit 0 |
| RPC HTTP 200 loss, exact completed-response recovery | PASS | Base v2 `android/rpc-recovery.redacted.json`, selector exit 0 |
| Android `STILL_PROCESSING`, preserved pending and counters | PASS | Fresh live processing driver run and verify, exits 0; synthetic ledger injection |
| Android signed `OUTCOME_UNCERTAIN`, restart and reconciliation | PASS | Fresh uncertainty retry driver run and verify, exits 0; original failed driver retained |
| Android `RECOVERY_UNAVAILABLE`, preserved pending and counters | PASS | Legacy Android selector, carrier verification and corrected absence check before teardown; original driver remains FAIL |
| Actual Link policy status, both participating Owners | BLOCKED | No accepted legitimate Endpoint/Link producer |
| Configured Link policy / genuine foreign Owner guard | BLOCKED | Requires legitimate Link and independent external Owner proofs |
| Native Node / model delivery | NOT_RUN | Outside this bounded gate; no model calls |
| Physical Android | NOT_RUN | No physical device used |
| Public HTTPS | NOT_RUN | Only isolated development transport used |

Relative paths in the provenance column are under
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/`.
Base v2 means
`/gpu1-share/data/cicada-client/v16-deterministic-v161-144e079-base-v2-20261002/`.
Each PASS is limited to the stated layer. Original failed drivers and wrapper
errors remain FAIL; correction receipts are separately attributed.

## Completed-response recovery

The base session passed all five live Android selectors: capture and recover
enrollment, verify the authenticated Directory scope, and capture and recover
the completed RPC. Each selector reported `OK (1 test)`, ADB exit 0 and driver
exit 0. The encrypted session authorized the exact external-role intersection:
31 implemented operations from the 55-operation catalog. The manager
intersection is 39; this base fixture does not claim manager runtime acceptance.

The proxy recorded a real 201 and a real 200 before dropping their responses.
Separate opaque carrier records prove that the retry used the identical
enrollment request and the recovery used the identical signed encrypted RPC
packet. The returned full response SHA-256 equals the original response for
both cases. Android independently checked pending preservation, replacement
refusal, counters, ML-DSA signature and decryption for the recovered RPC.
See base v2 `android/response-loss-comparison.redacted.json` and
`android/base-live-summary.redacted.json` for exact commands, exits and cleanup.
All four carrier processes exited 0; response-loss proxy shutdowns were
expected SIGTERM (`-15`). The owned base Hub and emulator were removed.

## Retained initial failures

The first emulator start refused a nonexistent private evidence directory
before creating a container. Its exit was 1. The directory was then created
with caller ownership and mode 0700; the subsequent start succeeded.

The first build exited 0, but its instrumentation APK
`42ab3b5c0007bf28b50819522e066c48ef4653ecd5b7431843cfc227d0470349`
failed two new synthetic Session tests: their advertised permission sample
omitted `link.list`. Production correctly rejected the dedicated status flow
with `RPC_OPERATION_NOT_AUTHORIZED`. Only the synthetic test sample was
corrected. A necessary second build exited 0 and the full final 81-test matrix
passed. The initial APK, build receipt, failed test receipts and teardown remain
under `client-final-144e079-20261002/build/` and
`v16-deterministic-v161-144e079-base-20261002/android/`.
No failed or earlier APK result is transferred to the corrected pair.

## Execution boundary

Recovery fixtures use separate enrolled Android sessions and disposable Core
Hubs. The Android packet is captured while its network-none emulator has no
carrier or ADB reverse mapping. Only an opaque packet is temporarily exported
to a private file outside Git. The Client proves fixture ownership and rejects
unrelated containers sharing its state mount. The Core producer runs from the
pinned interop image with network disabled. For uncertainty and legacy recovery,
the owned Hub is stopped and its absence proved before the producer runs; the
same state is then restarted. The Client does not read the Hub database.
No replacement operation or guessed response sequence is created.

The additional processing case uses the Core maintainer's explicit exception:
only a fresh disposable fixture, its sole Client and a read-only snapshot
operation; no Worker, model or other pending request. The existing Core producer
accepts that fresh packet while the Hub remains running, after which Android
immediately recovers the original packet. The Hub container and identity must
remain unchanged. This is a synthetic durable-state injection. It does not
prove a genuinely concurrent business operation or crash. The CLI requires
`--allow-disposable-live-processing`; it is not a production fault endpoint.

The external synthetic Owner signer remains outside Android. No Owner private
key, Node/Hub bearer, real model credential or private recording is packaged or
committed. All sixteen unsupported consent operations remain closed. Policy
preview/grant and collaboration key consent are not enabled by the metadata
status view. A nonexistent Link does not prove the genuine foreign Owner guard.
Recovery always submits a signed encrypted original request. The 409 codes are
bounded public transport errors; they are not encrypted response packets and
do not authorize discarding pending state. The 200 uncertainty notice and
business responses are independently signature-verified and decrypted.

## Interrupted-request outcomes and retained driver failures

The first processing attempt used the safe offline producer followed by Hub
restart. Restart fences `PROCESSING` to `UNCERTAIN`, so recovery returned 200
and the Android assertion expecting `STILL_PROCESSING` failed. Its driver exit
was 1. That attempt is preserved under
`v16-deterministic-v161-144e079-processing-20261002/android/`; it is not a
passing processing test. The separately authorized fresh live case is under
`v16-deterministic-v161-144e079-processing-live-20261002/android/`. Its actual
driver run and verify exited 0, returned 409, preserved original pending/counters,
refused replacement operations and verified every cleanup flag. An outer
wrapper initially looked for a nested lifecycle field at the top level; its
failure is retained separately from the successful driver commands.

The first uncertain and legacy Android recovery selectors passed, but their
original drivers exited 1 in the host packet-absence check. The command passed
an unquoted `sh -c` argument through `adb shell`, which joins its arguments.
Only the Client Python driver was corrected using `shlex.join`; no APK,
protocol, device key or Hub implementation was changed. Original failures
remain intact. The final driver SHA-256 is
`577cef48eaff5839cc36114c15413016d9cbccf089b7d2bf60234b00ae29206a`.

For legacy, a correctly quoted absence check exited 0 **before emulator
teardown**, followed by independent Android and carrier receipt verification.
The correction is under
`v16-deterministic-v161-144e079-legacy-20261002/android/recovery-cleanup-correction.redacted.json`.
It binds the original failure, actual 409, packet/operation/counter continuity
and command timing. It is a correction receipt, not a replacement driver PASS.
The original bootstrap wrapper also retains its separate role-count assumption
failure and correction: external has 31 operations, manager has 39.

The first uncertain emulator was already removed when the host error was
diagnosed. Post-run protocol verification passes, but teardown cannot certify
the earlier host absence check. The necessary fresh uncertainty rerun passed preparation, run and verification
with exits 0 using the same final APK pair, and is recorded separately under
`v16-deterministic-v161-144e079-uncertain-retry-20261002/`. Its Android selector
verified signed encrypted `OUTCOME_UNCERTAIN`, retained the retired original
packet, refused a write before reconciliation and accepted a fresh authoritative
snapshot. Carrier evidence contains exactly the original recover request (200)
and the later snapshot (200); every cleanup flag is true.

## Reproducible command index

Exact expanded command arrays, exit codes and installed APK hashes are in the
referenced restricted receipts. The following are the corresponding entry
points; `E` is the case's `android/` evidence directory and `F` is its disposable
Core fixture directory.

| Command | Result / exit |
|---|---|
| Offline Docker `gradle --offline --no-daemon --project-dir /workspace/android :app:assembleDebug :app:assembleDebugAndroidTest` | Final build PASS / 0; initial build also 0, its failed matrix retained |
| Offline Docker `python3 -B scripts/check-client-contract.py` | PASS / 0 |
| `python3 scripts/interop/v16-android-deterministic.py E test` | Final base pair: 81 tests / 0; first pair: two failures / 1 |
| `python3 scripts/interop/v16-android-deterministic.py E ui` | Final base pair PASS / 0 |
| `client-network-fixture.sh setup --build-metadata <fixed std-build.json>` | Each owned fixture setup / 0 |
| `v16-public-device.py E --run-id <case> --profile <case-profile>` | Public-only device preparation; case receipts retain every attempt |
| `client-network-fixture.sh grant F --signer <pinned external CLI> --manifest <public manifest> ...` | External synthetic Owner Grant / 0 |
| `v16-stage-fixture.py --evidence E --fixture F/.cicada-client-network-fixture.json --public F/client-public.json --grant F/owner-device-grant-primary.json --run-id <case>` | Public enrollment staging / 0 |
| `v16-role-oracle.py E --manifest E/device-public.private.json --tag <case>` | Authenticated external role 31/31 / 0 |
| `v16-recovery-faults.py prepare --evidence E --mode <case> --fixture <marker> --public <public> --app-sha256 <fixed> --test-sha256 <fixed>` | Fresh fault preparation; case receipt records actual exit |
| Same driver `run`, plus `--allow-disposable-live-processing` only for the authorized live processing case | Live processing PASS / 0; retained prior failures / 1 |
| Same driver `verify --evidence E --mode <case> --app-sha256 <fixed> --test-sha256 <fixed>` | Live processing PASS / 0; uncertainty retry PASS / 0 |
| `client-network-fixture.sh cleanup F`; `v16-android-deterministic.py E stop` | Owned teardown only; case receipts record exits and absence proofs |

The base response-loss selectors and all five exact instrument commands are
listed in `base-live-summary.redacted.json`. Each uses the case's real `run_id`,
`scenario` and full selector name through `am instrument`; every base selector
reported one test, ADB exit 0 and driver exit 0. The same APK pair is used in all
subsequent sessions. Core Go/native results are not counted in this matrix.

## Evidence index and teardown

The aggregate restricted index is
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/provenance/acceptance-manifest.redacted.json`.
It binds each evidence path and SHA-256 to its stated acceptance layer. The
post-commit `client-delivery.redacted.json` in the same directory binds the full
Client commit, global Git identity, artifact hashes and compiled input
fingerprint. Neither file contains credentials or plaintext RPC payloads.

Final live processing evidence is
`/gpu1-share/data/cicada-client/v16-deterministic-v161-144e079-processing-live-20261002/processing-live-final.redacted.json`.
Final uncertainty evidence is
`/gpu1-share/data/cicada-client/v16-deterministic-v161-144e079-uncertain-retry-20261002/android/provenance/uncertain-acceptance.redacted.json`.
Legacy layer attribution is summarized in
`/gpu1-share/data/cicada-client/client-final-144e079-20261002/legacy-summary-for-root.json`.
These records retain exact command receipts and the original failed attempts.

Every owned case Hub and emulator was removed. Per-case teardown receipts prove
container and fixture absence; carriers stopped and ADB reverse mappings were
empty. Resident deployments were outside the fault-injection scope. Physical
Android, public HTTPS, iOS and native HarmonyOS remain `NOT_RUN`.
