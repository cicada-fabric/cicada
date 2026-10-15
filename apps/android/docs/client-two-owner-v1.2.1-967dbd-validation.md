# Client two-Owner authorization validation — v1.2.1 / Hub `967dbd8`

**Date:** 2026-09-26

**Client implementation commit:** `680fac2bf12c431ac02804e5db168669cf12941f`

**Result:** **PASS for the synthetic two-Owner authorization slice**

## Scope and fixed target

This acceptance verifies that two independently registered synthetic Owners and their Android device contexts remain isolated when using the Android Client's encrypted `/v2/client/rpc` path. Each Owner has a separate Group, Node binding, Endpoint candidate, device grant, and positive `CURRENT` key status. The four acceptance stages and all four Android instrumentation methods passed on the final fresh run.

The Node/Endpoint helper creates a synthetic Endpoint for authorization testing only. The fixture uses supported `/v2/fabric/node/join`, `/v2/fabric/whoami`, and `/v2/fabric/endpoint-keys` routes. The accepted `harness: "codex"` value is simulated adapter metadata: **no Codex process or native Thread ran**, and the result marker is `SYNTHETIC_ENDPOINT_AUTHORIZATION_ONLY_NOT_NATIVE_EVIDENCE`. This report does not claim native Node, Codex, or Thread acceptance.

The run used only newly created disposable fixture state and synthetic keys. Synthetic Owner registration used the fixed image's supported offline `owner-key register` CLI while the disposable Hub was stopped. Tests performed no direct database inspection or SQL mutation, read no real credentials, changed no resident Hub, and added no production test backdoor.

| Item | Fixed value | Check |
|---|---|---|
| Hub source | `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`, `source_dirty=false` | **PASS** |
| Contract | `client-hub-v1.2.1` | **PASS** |
| Protocol archive SHA-256 | `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a` | **PASS** |
| Catalog SHA-256 | `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9` | **PASS** |
| Full local Hub image ID | `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7` | **PASS** — health reported `ok`, clean source, and matching revision/catalog. |
| Client source commit | `680fac2bf12c431ac02804e5db168669cf12941f` | **PASS** |
| Debug APK SHA-256 | `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1` | **PASS** — identical artifact in the first and final runs. |
| AndroidTest APK SHA-256 | `342845155edf0333e3b81aa736d25945e8d83554a61c26fc1bf438c314d26ae0` | **PASS** — identical artifact in the first and final runs. |
| Final Go builder image ID | `sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244` | Recorded by the helper build. |
| Final emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` | Recorded by the final fixture. |
| Node/Endpoint helper SHA-256 | `a8277b7cf17e527c7d9e247e59f46d26577332c1c4e2ab50c5b625f2136b214d` | **PASS** — final helper binary. |

## Build and execution

The fixed contract verification command was `python3 ../CICADA/scripts/client-contract.py verify <fixed-contract-archive>` and exited **0**. The helper was built from the pinned clean core source with `bash scripts/interop/two_owner_node_fixture/build.sh`, exit **0**. The Android app and test APKs were built with `./scripts/docker-build-android-test.sh`.

| Run | Command/check | Result |
|---|---|---|
| First Android build | `./scripts/docker-build-android-test.sh` | **FAIL**, exit **1**. Kotlin test code had two `WireResponse`/`JsonObject` type mismatches. |
| Corrected Android build | Same command after aligning the test code with the response type | **PASS**, exit **0**. No product verifier rule was relaxed. |
| First-run Node helper build | `bash scripts/interop/two_owner_node_fixture/build.sh` | **PASS**, exit **0**. |
| Final helper source build, before Android acceptance | Same command; resolved Go builder and helper digests are recorded above | **PASS**, exit **0**; `node-helper-build-final.log` in the first evidence root. The fresh rerun reused this binary after SHA-256 verification; it did not rebuild it. |
| Android instrumentation methods | `python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test <method>` | All four methods below **PASS**, with runner exit **0**, ADB exit **0**, and JUnit `OK (1 test)` for each. |

| Android method | Result | Runner / ADB / JUnit |
|---|---|---|
| `prepareTwoOwnerDeviceKeys` | **PASS** | `0 / 0 / OK (1 test)` |
| `enrollConfirmAndCreateOwnerGroups` | **PASS** | `0 / 0 / OK (1 test)` |
| `exportOwnerGroupManifests` | **PASS** | `0 / 0 / OK (1 test)` |
| `twoOwnerOwnershipAndRevocationMatrix` | **PASS** | `0 / 0 / OK (1 test)` |

The fresh rerun used a read-only mount of only each Node's `relay.token` for the external Endpoint helper. The helper kept its Session bearer in memory. Both Node bootstrap commands returned exit **1** at the expected pending-device-confirmation boundary; Android confirmed each pending synthetic Node, after which both helper candidate-publish commands exited **0**. These bootstrap exits are recorded setup behavior, not failed authorization tests.

The corrected Android build ran while the new instrumentation was uncommitted on base `51eb8211015d6e01cde46d91afac1905fd008e8e`. Its final source was committed as `680fac2bf12c431ac02804e5db168669cf12941f` before the fresh rerun; the installed APK hashes were independently recorded again with that commit. No later Kotlin or app-source changes were made. The Android build image resolved to `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`. Go, emulator and helper binary execution in the final fixture used full fixed identities, not mutable tags.

The final run also completed six explicitly reviewed Android taps: `confirm-node-a`, `confirm-node-b`, `confirm-group-a`, `confirm-group-b`, `confirm-grant-a`, and `confirm-grant-b`. Each recorded exit **0**.

## Authorization and revocation results

All four acceptance stages passed:

1. **Independent setup:** A and B had matching `session.capabilities`, different Owner Groups, and separately verified Group manifests. Android confirmed each Owner's own pending synthetic Node and created that Owner's Group.
2. **Positive controls:** each Owner completed its own signed Group grant and independently read `group.key_status=CURRENT`.
3. **Cross-Owner isolation:** each side's attempts to read the other Owner's existing Group manifest/status or submit a grant received HTTP 200 with an encrypted permission denial. The Client also rejected the foreign manifest locally as `OWNER_KEY_ID_MISMATCH` and the foreign grant locally as `GROUP_CONSENT_MISMATCH`. A deliberately tampered public proof was rejected by the Hub as an encrypted signature rejection. Each Owner's own status and grant remained unchanged after the foreign attempts.
4. **Revocation:** after Owner A's admin device revoked A's target device, A's fresh request, exact old-package replay, and recovery attempt each received HTTP 403. Owner B remained `CURRENT` throughout.

The matrix separately recorded local Client preflight rejection, HTTP 200 encrypted business rejection, and HTTP 403 authentication rejection. Per-Owner request sequences and pending state remained isolated. Authenticated business rejections advance the Hub's transport ledger: A's independent driver used request/response sequences 10–14; B's used 12–15. Product-local preflight rejection left its persisted counters and pending state unchanged. After A's revocation, A's pending packet remained unchanged during B's probes, and A-admin re-read A's unchanged grant. The wrong-device response-open assertion rejected the recipient/route mismatch before KEM decapsulation; it is not an additional confidentiality experiment. The recovery attempt above verifies rejection after revocation; a lost-response or uncertain-outcome recovery rerun is **NOT_RUN** in this slice.

## First-run corrections and rerun

The first run is preserved as a distinct evidence record. Its initial Android build failed with the two test-only response type mismatches described above; the corrected build succeeded. In external signing, the first Owner A device-signing attempt exited **2** because the input public identity JSON was not canonical, and the first Owner A Group-signing attempt exited **2** because the manifest JSON was not canonical. Reformatting both signer inputs as compact canonical JSON made the retries pass; Owner A's admin device, Owner B's device, and Owner B's Group signing each exited **0**. The verifier was not weakened.

The final fresh run repeated all setup, signing, publication, and authorization stages successfully, with no signer or harness failures. It also confirmed the narrowed read-only Node credential mount described above.

## Commands and external evidence

The exact first-run private evidence root is `/gpu1-share/data/cicada-client/two-owner-20260926T020738Z-cto-ac7jtxi2/evidence/`; its redacted summary is `summary.redacted.json`. The final fresh-run evidence root is `/gpu1-share/data/cicada-client/two-owner-20260926T024036Z-cto-9uslracc/evidence/`; its redacted summary, artifact manifest, reviewed taps, privacy check, and teardown record are stored there. Private logs and signed public material remain outside Git; private fixture state and keys were removed.

The reproducible Android test invocations are:

```sh
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test prepareTwoOwnerDeviceKeys
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test enrollConfirmAndCreateOwnerGroups
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test exportOwnerGroupManifests
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test twoOwnerOwnershipAndRevocationMatrix
```

Each command exited **0** in the final run; each produced JUnit `OK (1 test)` and ADB exit **0**. `FIXTURE_DIR` was `/tmp/cto.9uslracc` in that run and `/tmp/cto.ac7jtxi2` in the initial run. These paths have been removed; a reproduction must allocate a new fixture using `prepare`. The command ledger records fixed-contract verification, disposable Hub creation/registration, emulator and APK installation, Node bootstrap, helper publication, signing, and cleanup. It includes public synthetic scope IDs in restricted files, but no credential values, pairing codes or private key bytes. `summary.redacted.json` replaces object IDs with SHA-256 labels.

| Final command, in execution order | Exit | Evidence under the final evidence root |
|---|---|---|
| `python3 scripts/interop/two-owner-fixture.py prepare` | 0 | `fixed-target.json`, `verify-contract.log`, `runtime-provenance.json`, `fixture-commands.jsonl` |
| `python3 scripts/interop/two-owner-fixture.py start-emulator "$FIXTURE_DIR"` | 0 | `emulator-start.log`, `emulator-ready.json` |
| `python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" install` | 0 | `android-artifacts.json`, `install-app.log`, `install-androidTest.log`, `adb-reverse.log` |
| Device preparation method, export `device-publics.json`, then fixture `sign-devices "$FIXTURE_DIR"` | Each 0 | `prepareTwoOwnerDeviceKeys.json`, `device-publics.private.json`, signing commands in ledger |
| Fixture `bootstrap-nodes "$FIXTURE_DIR"` and `android-config "$FIXTURE_DIR"` | Each 0; each nested Node command 1, expected | Ledger; secret-bearing bootstrap output intentionally not retained |
| Android runner `stage "$FIXTURE_DIR/android-fixture.json" fixture.json` and `stage "$FIXTURE_DIR/android-private-fixture.json" private-fixture.json` | Each 0 | Enrollment method below consumed and deleted private Node-code staging |
| Enrollment/Group method, export `groups.json`, then fixture `publish-endpoints "$FIXTURE_DIR"` | Each 0 | `enrollConfirmAndCreateOwnerGroups.json`, `groups.private.json`, `endpoint-A.private.json`, `endpoint-B.private.json` |
| Restage public fixture, manifest method, export `manifests.json`, then fixture `sign-groups "$FIXTURE_DIR"` | Each 0 | `exportOwnerGroupManifests.json`, `manifests.private.json`, signing commands in ledger |
| Restage public fixture, authorization/revocation matrix, export `result.json` | Each 0 | `twoOwnerOwnershipAndRevocationMatrix.json`, `result.private.json`, `summary.redacted.json` |
| `docker exec <fixture-emulator> /opt/android-sdk/platform-tools/adb -P 5060 -s emulator-5620 shell input tap <x> <y>` | 0 for each of six reviewed taps | `reviewed-taps.json` records actual coordinates and screenshot filenames |
| `python3 scripts/interop/two-owner-fixture.py stop "$FIXTURE_DIR"` | 0 | `teardown.json`, `cleanup-verification.redacted.json` |

`fixture` and `Android runner` in the abbreviated rows mean the two Python scripts named above; the complete sequence is in [the reproducibility recipe](../scripts/interop/two-owner-acceptance.md). Full instrumentation commands are recorded in each `<method>.json`, with raw output in `<method>.private.log`. The final `result.private.json` SHA-256 is `8ac524cc73c0c06df12ef97e5aa7c7bed93e5345a5096a13de7df86d5628874e`.

The following final-run labels are the first 16 hex characters of SHA-256 over
the exact UTF-8 ID. Full hashes are in `summary.redacted.json`; original public
IDs remain in restricted evidence. The session labels identify simulated
adapter sessions and do not attest native runtime identity.

| Object | Owner A label | Owner B label |
|---|---|---|
| Owner | `5204e76de2b04b8a` | `80f032818e074f95` |
| Group | `7ec40f7e863aa5ce` | `ed3d79b13abe5e90` |
| Node | `91eb03e652b4bcdf` | `2463608c3a006ec43` |
| Endpoint | `0c16365001d078c8` | `72ef07559b63f301` |
| Principal | `218e3f7f24793598` | `373e9daeb36895d7` |
| Synthetic session | `14ce062f65d29097` | `c9cc8d1ec3c5847d` |
| SessionBinding | `9b38d1197002d7e9` | `9442e21857d4f9e5` |

## Cleanup, limits, and separate evidence

Final cleanup **PASS**, exit **0**: only this fixture's Hub/emulator resources were removed, and its Owner/Endpoint private keys and temporary credentials were removed. Cleanup verification also **PASS**: zero labeled containers or `/tmp` roots remained, ADB port 5060 and emulator `emulator-5620` were closed, and evidence directories/files retained owner-only `0700`/`0600` permissions. A bounded privacy check **PASS**: 226 files and two APK archives were checked against 13 known synthetic private values, with zero matches. Its scope is those known fixture values; it is not a general secret scanner. Redacted result summaries and private test logs remain in the external evidence directory for review.

Physical Android, public HTTPS, native/Codex Thread verification, and lost-response/uncertain-result recovery reruns are **NOT_RUN**. The emulator's Owner contexts share one app UID and wrapping Keystore alias, so this acceptance tests protocol/device-context authorization separation and does not establish OS-level hardware-key isolation. It also does not establish production TLS or ordinary peer-content confidentiality.

No required gate in this authorization slice remains **BLOCKED**. Independent vector suites and new `STALE`/`PROOF_EXPIRED` timing runs are **NOT_RUN** in this slice. Existing results keep their original artifact attribution. The fixed contract's `external_thread_links=false` remains in force; no ordinary cross-user message capability was enabled.

Earlier N4/N5 recovery **PASS** evidence and the earlier native Codex Group acceptance remain separate results in the [v1.2.1 Hub validation](client-hub-v1.2.1-967dbd-validation.md) and [Group-key acceptance](client-group-key-v1.2.1-disposable-validation.md). They are not relabeled as evidence for this synthetic two-Owner slice.
