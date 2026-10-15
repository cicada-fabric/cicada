# Disposable Group Endpoint key acceptance — Client Hub v1.2.1

- **Date:** 2026-09-25
- **Branch:** `dev/react-native`
- **Client implementation commit:** `b676668e33c876c0d2c89bc3495fbd0d1e128c82`
- **Scope:** Android emulator, a disposable fixed-image Hub, an owner-bound Node, and one real native Codex Thread. This is a development acceptance result, not a physical-device or public-HTTPS result.

## Fixed target and artifact identity

| Item | Exact value |
|---|---|
| Hub source commit | `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` |
| Wire contract | `client-hub-v1.2.1` |
| Protocol archive SHA-256 | `7bf1e3702eadf9fc3ffd50a0e8ab1213db0844b2bf418b577b88ba239216bf8a` |
| Catalog SHA-256 | `25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9` |
| Full local Hub image ID | `sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7` |
| Final debug APK SHA-256 | `cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1` |
| Final AndroidTest APK SHA-256 | `52e9e678666654d57bd127b5f616a3094e9a9925b9fe5b960632c7cb81d6f9d5` |
| Earlier corrected Group APK SHA-256 | `74618fac76c513250618b02c39945d1e11329b5adeb730f6b17871ff31a1e187` |
| Earlier corrected AndroidTest APK SHA-256 | `9a2174ba05dde5613650f0fc35d16357da21d50a37c3347b483d75335867972b` |
| External signer binary SHA-256 | `cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1` |

The protocol archive passed `client-contract.py verify` with exit **0**. Image inspection and the running disposable container both matched the full image ID. Image labels and runtime `/healthz` reported the fixed source commit, catalog and `dirty=false`. Android's encrypted `session.capabilities` returned `client-hub-v1.2.1`, the fixed catalog, and the synthetic Owner's `external` role; the encrypted allowlist contained the Group key operations. The core development worktree was not used as the image or signer source. The signer was built with Docker Go 1.27.1 from a clean `git archive` of the fixed commit, using a build-local cache and the host's development proxy. No core source or database was modified.

## End-to-end result

The fixed core fixture's `start` command created a synthetic Owner, a pending Node and a new loopback Hub. Its preparation status was **not** treated as Group acceptance. Android generated its own device key; the separate Owner signer produced an exact device Grant outside the APK. Android pinned the fixture's public Hub identity independently, enrolled, and verified encrypted capabilities. The synthetic Owner was an `external` owner, so the earlier manager-role assertion was inapplicable; the external-role capabilities test passed.

Android displayed and accepted the pending Node. A later encrypted `topology.snapshot` and `topology.apply` created the Group. The bound Node Agent then ran on the host under the same OS account as authenticated Codex. One persistent Codex Thread was created in the fixture workspace. In a single resumed native MCP context, the model called `cicada_join`, then separately `cicada_whoami`, then separately `cicada_publish_endpoint_key_candidate`. All three tool calls completed. The Group, Endpoint, Node, Principal, native Session, binding ID and epoch agreed; the candidate returned `CANDIDATE` and a positive version. The final run's binding epoch was **5**, candidate version **4**. Truncated SHA-256 evidence labels are: Endpoint `60c759ef4779f704`, native Session `f07b532c5849788e`, Group `032ec8abe3d53563`, Node `005b45dd5e43dfd5`, binding `c1b450e8e445e901`. These are hashes of synthetic identifiers, not the identifiers themselves.

On the **final APK pair listed above**, Android requested encrypted `group.key_manifest` and independently checked the complete raw Endpoint attestation, ML-DSA-65 signature and public key, IDs and epoch, all revisions, candidate binding digest and manifest digest. The external signer rechecked the same full public manifest against the fixed Go E2EE implementation, required the exact digest confirmation, and produced a new `0600` signed proof. Android re-read and verified the exact manifest and proof, showed the Group, Endpoint, Node, binding epoch, candidate fingerprint and digest in a real phone dialog, and waited for an explicit ADB tap. The displayed digest prefix `3af728ed82a7` matched the separately reviewed manifest. Encrypted `group.key_grant` succeeded and a separate encrypted `group.key_status` returned **`CURRENT`** for that digest. The final `grant-finalui` Android test returned `OK (1 test)` with ADB exit **0**.

| Validation | Result | Evidence under the private evidence directory |
|---|---|---|
| Fixed archive, image and runtime provenance | **PASS** | `fixed-target-provenance.json`, `fixture-start.private.log` |
| Android device identity and encrypted external capabilities | **PASS** | `prepare-device.log`, `external-capabilities.log` |
| Owner Node binding and encrypted Group creation | **PASS**, with interrupted combined runner noted below | Android Node dialog/ADB tap; `reconcile-group.log`; native authenticated Join |
| Real native Join → whoami → separate key-candidate publish | **PASS** | `codex-finalui.private.jsonl`, `native-finalui.private.json` |
| Full Android manifest verification and independent external signing | **PASS** | `manifest-finalui.log`, `group-signer-finalui.private.log` |
| Android dialog → encrypted grant → encrypted status `CURRENT` | **PASS** | `grant-finalui.log`, `grant-finalui-dialog.private.png`, `grant-finalui.private.json` |
| Mutated Owner signature rejected before a new grant | **PASS**, Client-side rejection | `reject-tampered-proof-finalui.log` |
| Wrong Owner key selection and nonexistent Group/Endpoint status reads | **PASS**, local key fence plus encrypted Hub business rejections | `reject-wrong-scope.log` |
| Status after the native binding lease expired | **PASS: `STALE`** on the final APK | `status-stale-finalui.log` |
| Status after the signed proof expired | **PASS: `PROOF_EXPIRED`** on the final APK | `status-proof-expired-finalui.log` |
| A second real Owner attempting cross-owner access | **NOT_RUN**; this disposable fixture has one synthetic Owner | No second Owner enrollment |
| Physical Android device; public HTTPS | **NOT_RUN** | No device or public endpoint used |

The wrong-Owner check above is a rejected untrusted Owner **key selection** in Android plus a nonexistent Group scope rejected by the encrypted Hub. It is not a two-real-Owner authorization test. The tamper check flips a signature byte and establishes that the Client refuses to send another grant; it does not claim an independent Hub tampered-proof submission. The `STALE` transition was caused by the real native SessionBinding lease expiring; `PROOF_EXPIRED` was read after the accepted signed proof's validity ended. No Hub database or artificial fault route was used.

## Reproducible command and exit record

The private evidence directory is `/gpu1-share/data/cicada-client/group-key-v121-967dbd/evidence` (`0700`, files `0600`). Test specs containing signed public proofs must not be copied into Git; the expired synthetic Node-code spec was deleted at teardown. `commands.jsonl` records Android method labels, exits and log hashes with arguments redacted. Its historical command-string class label was hardcoded incorrectly as `ClientHubInteropTest` for Group methods; the per-run specs and runner source identify the actual `GroupKeyInteropTest` class, and the metadata typo has been fixed for future runs without rewriting historical entries. The principal commands were:

| Command (sensitive arguments omitted) | Exit / observation |
|---|---|
| `python3 /home/zyf/CICADA/scripts/client-contract.py verify <fixed archive>` | **0** |
| `/home/zyf/CICADA/scripts/client-group-key-fixture.sh start` | **0**, disposable fixed-image Hub prepared |
| `docker run ... golang:1.27.1 go build -mod=readonly -trimpath ... ./cmd/groupownersigner` | **0**, clean fixed-source archive |
| `group_owner_signer device-grant ...` | **0**, new `0600` Grant outside APK |
| `python3 <evidence>/run-android-test.py <evidence>/prepare-device.spec.json` | **0**, `OK (1 test)` |
| `python3 <evidence>/run-android-test.py <evidence>/external-capabilities.spec.json` | **0**, `OK (1 test)` |
| `python3 <evidence>/run-android-test.py <evidence>/reconcile-group.spec.json` plus visually reviewed `adb shell input tap 239 383` | Both **0**, `OK (1 test)`; the earlier combined runner was interrupted as described below |
| `python3 <evidence>/rapid-prepare-grant.py finalui` | **0**; native Codex tool sequence, Android manifest and external signer each completed |
| `python3 <evidence>/run-android-test.py <evidence>/grant-finalui.spec.json` plus reviewed on-screen `adb shell input tap 208 535` | Both **0**, `OK (1 test)`, `CURRENT` |
| `python3 <evidence>/run-android-test.py <evidence>/reject-tampered-proof-finalui.spec.json` | **0**, `OK (1 test)` |
| `python3 <evidence>/run-android-test.py <evidence>/reject-wrong-scope.spec.json` | **0**, `OK (1 test)` |
| `python3 <evidence>/run-android-test.py <evidence>/status-stale-finalui.spec.json` | **0**, `OK (1 test)`, `STALE` |
| `python3 <evidence>/run-android-test.py <evidence>/status-proof-expired-finalui.spec.json` | **0**, `OK (1 test)`, `PROOF_EXPIRED` |
| `./scripts/docker-build-android-test.sh`; Docker TypeScript check; Docker lint; `python3 scripts/check-client-contract.py`; `git diff --check` | Each **0** |

`EndpointAttestationVectorTest` passed again on the final APK pair (`OK (4 tests)`, ADB exit 0). The debug emulator loopback-policy test passed (`OK (1 test)`, ADB exit 0). The first attempt to run two instrumentation suites concurrently on the same emulator produced a process crash despite ADB exit 0; the sequential vector rerun passed. ADB exit alone is therefore never counted as a test PASS.

## Faults encountered and security boundary

The first Node Agent start failed because the fixture's long temporary path exceeded the Unix socket path limit. A shorter symlink let the Join bridge start but was correctly rejected by Node-local key storage, which requires a real state directory. The Client test used a private real short `/tmp` Node state directory, with the same local bearer kept only on the Node. The first Codex MCP attempt was blocked by the local `never` approval policy before reaching the Node; an isolated resumed turn with auto review then completed the actual native tools. An early signed manifest became unavailable after the leased binding expired; the Client stopped before `group.key_grant`. The final positive run was repeated within a fresh lease and is the result reported above.

The combined Node/Group instrumentation runner was disrupted by concurrent shell `uiautomator` access, while the on-phone Node confirmation consumed its one-time code. Android's encrypted topology reconciliation avoided repeating Node confirmation; a separate Android Group creation run passed after a direct, visually reviewed ADB tap. The later native Join confirms the Node was owner-bound. These failed harness attempts remain in private logs and are not counted as protocol acceptance.

The Owner private identity and Node bearer were never placed in the APK or repository. Signed proofs and test specs were held outside Git with restrictive permissions. The synthetic one-time Node code briefly appeared in the disposable instrumentation process arguments and one transient process-inspection output; it expired, its private spec was deleted, and the fixture was removed. This is a test-harness privacy finding: future runs should avoid process inspection while a code-bearing command is active. Android retained only its device-side key and independently pinned Hub public identity during the run; emulator app data was cleared after acceptance. All Client RPCs used the encrypted `/v2/client/rpc` session; no old `/v1` bearer path or direct Hub database read was used. The fixed contract still advertises `external_thread_links=false`; ordinary cross-user messaging was not enabled. Existing N4/N5 recovery PASS evidence in the [fixed-image report](client-hub-v1.2.1-967dbd-validation.md) remains historical evidence for those cases and is not relabeled as part of this Group test.

## Disposable fixture teardown

After the final `PROOF_EXPIRED` read, the Node Agent was verified by its process arguments and stopped with exit **0**. `adb reverse --remove tcp:32802` exited **0**. The core fixture's read-only `client-group-key-fixture.sh stop /tmp/cicada-client-group-key.xOfKixiw` exited **0**, removed the disposable fixed-image Hub, its state and the synthetic Owner private key. The separately allocated real short Node state directory was ownership and mode checked, then removed with exit **0**. `adb shell pm clear ai.cicada.client` exited **0**. A final `docker ps` fixture-label check and `adb reverse --list` returned no active fixture container or mapping. The expired Node-code spec was deleted from the private evidence directory.
