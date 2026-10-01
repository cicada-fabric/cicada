# Client-Control v1.6.1 deterministic integration validation

**Date:** 2026-10-01

**Client base:** `6b87c13c8a788de56f0ff5baf95fd96518281a67` on `dev/react-native`

**Scope:** public contract import, immutable image provenance, strict Node binding DTOs and isolated offline Android validation. No Hub, Node or model runtime is started for this checkpoint.

## Fixed delivery

| Item | Value |
|---|---|
| Core commit | `fe565b41bb1aa86d400a0ec98c528c856d0b9579` |
| Protocol / wire / operations | `client-hub-v1.6.1` / `1` / `55` |
| Protocol archive SHA-256 | `b5757b055bc871ef5f19fcc5ffe425813c6dea2ccc8cc64b4e74e1f1dcd8db55` |
| Catalog SHA-256 | `6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b` |
| Declared clean source fingerprint | `6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be` |
| Immutable Hub image ID | `sha256:df7a7f47404e127052a46899be7060539b57196a99a8042e2b853e8c6bdb8589` |
| Immutable interop image ID | `sha256:a6a88de73b1c8c00b38fafb4e9236c404b52b06165527a0b4e097c0f17f3a6be` |
| Core delivery report SHA-256 | `e0b0169743c8b55dbb7676fd7aa2ccfb97a3ad6f45fb00f0ebffb3406d9fe0db` |

The source archive is `/home/zyf/CICADA/.cicada-data/transport-recovery-delivery-20261001/contracts/client-hub-b5757b055bc871ef5f19fcc5ffe425813c6dea2ccc8cc64b4e74e1f1dcd8db55.tar.gz`. The imported snapshot is [the manifest](../contracts/client-hub-v1.6.1-fe565b4/manifest.json). A concurrent dirty Core working tree is not this source revision. Immutable Git blobs, manifest entries, and image/build metadata are checked separately.

The Core delivery reports its exact-image smoke and processing/uncertain/legacy recovery gate as PASS, exit 0, with owned cleanup. This is Core-layer evidence; it does not establish an Android encrypted session, native Endpoint Join, Monitor delegation or physical-device acceptance. No prior Client APK or Hub version supplies a PASS for this checkpoint.

## Independent source provenance gate — BLOCKED

All 21 archive payloads match their manifest SHA-256/size and immutable `fe565b4` Git blobs. The archive, catalog and delivery/build/source-info/image-label digests agree. These are separate successful checks; they do not resolve the independent build-input fingerprint gate.

The pinned `cicada-hub-build-inputs-v4` algorithm hashes full filesystem permission bits (`stat.S_IMODE`), while Git records only executable bits. Independent reproduction from pinned Git blobs and Git modes gives `60d046189ec735673ae3de5933f89ebde90d7bde649af16bad66286599f24043`; pinned blobs with current filesystem modes give `8299767452502bdb626a0f2f732d209822f88a99d96e548ed1d851564d597b5e`. Neither reproduces declared `6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be`. The concurrent dirty Core tree is not accepted provenance. Core independently reproduced both diagnostic values and confirmed the gate must remain **BLOCKED** pending actual captured build-input permission evidence or a separately delivered clean reproducible build.

No complete import/provenance PASS or live acceptance is claimed. No historical mode observation is invented and no metadata agreement substitutes for the missing independent input proof. The contract-only deterministic implementation proceeds with this limitation; no new Hub, Node or model runtime is started.

Import/checker evidence: `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/provenance/checks/contract-import-checks.json`, SHA-256 `52ab0f64745c249b7d7c9821def377d97866f8911fce3a6d818b985f9f5fa23d`. The Docker checker suite passed 11 tests, exit 0. Its recorded commands and image IDs are in that receipt.

## Node binding response verification

`nodes.confirm` returns `NodeControlKeyBinding`, including complete public Node and Hub Node-Control identities and exact approval evidence. `nodes.list` and `nodes.revoke` return the separate `NodeDeviceBinding` credential projection. The confirmation's `owner_binding_id` must equal the matching list record's `id`.

Kotlin validates the full ML-KEM-768/ML-DSA-65 public identities and key IDs, then independently computes the pinned `nodewire.IdentityFingerprint` bytes: `cicada/node-control/key-fingerprint/v1` plus NUL, KEM public bytes, NUL and signing public bytes. This differs from the Client device public-key fingerprint. It checks Owner, Hub, current enrolled device, trusted enrollment Owner key and ACTIVE state before consuming a successful confirmation response. Invalid evidence retains the original pending encrypted request; original-packet recovery runs the same checks. Private identities or extra public-identity fields are rejected.

The shared parser independently bounds the exact DTO and correlates the approved request, digest/version, public key IDs/fingerprints, Node epoch, Hub key version and approving device/key with the freshly reviewed candidate and current profile. Both independent trust confirmations and the native explicit confirmation Alert remain required. After confirmation, the actual encrypted `nodes.list` result is correlated with the verified binding. The Node DTO has no Client session-epoch field; the authenticated packet route and current profile lifecycle establish that boundary without inventing a field. Stored authorization from an older contract is disabled until fresh encrypted `session.capabilities` matches the new revision and catalog.

## Acceptance matrix

The corrected Docker build passed, exit 0, in 35.41 seconds. The compiled source fingerprint was unchanged before/after the build: `0b89a85d5c332faffb980851501c474942f28c1b047562e0daa547f27a32d7f0` over 112 files. Base commit is `6b87c13c8a788de56f0ff5baf95fd96518281a67`; the final delivery commit is recorded after the milestone commit.

| Artifact | SHA-256 | Bytes |
|---|---|---:|
| Debug app APK | `6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816` | 296,278,531 |
| Instrumentation APK | `abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec` | 1,106,595 |

The pinned Docker development image is `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`; build and checks use `--pull=never --network=none`. Exact argv and exits are stored in `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/build/build.receipt.json` and `checks/{js,typescript,eslint}.{argv.json,exit,log}`. The final-source JavaScript suite passed 59 tests across eight files; TypeScript and full ESLint exited 0 (22 warnings, no errors).

A preceding source candidate (`3323a0…`, 112 files) built successfully but failed TypeScript, exit 2, because a base64 validation predicate did not narrow `unknown` to `string`. Its original build and check receipts remain under `build/history/typescript-narrowing-candidate/` and `checks/history/typescript-narrowing-candidate/`. The explicit type predicate fixes that error; since the change affects only erased type metadata, the corrected and preceding APK bytes have identical hashes. No earlier candidate emulator acceptance is claimed.

All live Hub, native runtime, physical Android and public HTTPS gates remain `NOT_RUN`; native Monitor acceptance remains `BLOCKED` until a separately authorized Core fixture establishes its real authority path. The final isolated Android run passed 74 tests across 14 selectors, including all three new Node binding verifier tests. All ADB and selector driver exits were 0. Five offline React Native UI checks passed, exit 0. Start, test, UI and stop commands each exited 0; the emulator was removed, and the six pre-existing resident containers retained their exact IDs, images and running states.

| Gate | Result | Evidence and command exit |
|---|---|---|
| Archive manifest, 21 payloads and pinned Git blobs | **PASS** | `provenance/checks/contract-import-checks.json`; recorded command exits 0 |
| Catalog, immutable image IDs and delivery metadata agreement | **PASS** | Same receipt; catalog has 55 unchanged operation definitions |
| Independent clean build-input fingerprint reproduction | **BLOCKED** | Full historical filesystem permission inputs are not yet available; no complete import/provenance PASS |
| Offline contract checker regressions | **PASS**, 11 tests | Pinned Docker `python3 -m unittest -v scripts/test_check_client_contract.py`, exit 0 |
| Corrected app/test build | **PASS** | `build/build.receipt.json`, exit 0, SHA-256 `e2aca011823835b256437e80437aaa94dcf2456bf0b597eba10860fad9b0494d` |
| JavaScript / TypeScript / ESLint | **PASS**, 59 tests / exit 0 / exit 0 | `checks/final-checks.redacted.json`, SHA-256 `4ff7620d02c378e0596f2eba79cee4f5ab8b5f6fb4a0bf11eb142f4244c2ae9d`; 22 lint warnings, no errors |
| Independent public Node fingerprint oracle | **PASS**, exit 0 | `checks/public-node-fingerprint-oracle.redacted.json`; exact script SHA and public-only output retained |
| Kotlin local matrix | **PASS**, 74 tests / 14 selectors | `deterministic-summary.redacted.json`, SHA-256 `04b7ed05a58ebc53ccadc53376ec8253ace8347c18013ed098d372e8f9177936`; driver/ADB exits 0/0 |
| New Node public-key verifier | **PASS**, 3 tests | `node-control-key-binding.json`, SHA-256 `c33442e365694514ce4f4c13c4c1721c00687eb99452c8921e31076abc95d576`; driver/ADB exits 0/0 |
| Offline product UI | **PASS**, 5 checks | `ui-smoke-summary.redacted.json`, SHA-256 `da91c237f7fbfa6837b7aefc76014c3fdf9b4c54bb3ea1127c60cfdd0210dd46`; exit 0 |
| Owned emulator cleanup / six resident containers unchanged | **PASS** | `android-teardown.redacted.json` SHA-256 `f94a6bb3ea9e87e6c7795e349166032669df233b265b59f9c920f4db78ae1e56`; stop exit 0; final read-only absence receipt SHA-256 `d66e8a473d042e4cb00c1080ed9b5caa33c6fac081857eb75acc81826e65f2e8` |
| Current encrypted Hub `session.capabilities` and Node pairing | **NOT_RUN** | No new Hub or Node fixture started; pending provenance gate prevents live acceptance |
| Genuine native Endpoint / Monitor regroup acceptance | **BLOCKED** | Requires a separately authorized current Core fixture; old native Join failure remains historical |
| Physical Android / public HTTPS / iOS / native HarmonyOS | **NOT_RUN** | No qualifying environment or run in this checkpoint |
| New STT benchmark / model runtime | **NOT_RUN** | Existing local STT is preserved; no new model invocation |

Android evidence is at `/gpu1-share/data/cicada-client/v16-deterministic-v161-fe565b4-20261001/android/`. Each selector receipt records its actual command and exit code. The driver commands were:

```bash
python3 scripts/interop/v16-android-deterministic.py /gpu1-share/data/cicada-client/v16-deterministic-v161-fe565b4-20261001/android start --app-apk /gpu1-share/data/cicada-client/v161-fe565b4-20261001/build/app.private.apk --app-sha256 6262d427f3c99c3e7de217bada71d8615da52c1166f59d077b4886a5e1576816 --test-apk /gpu1-share/data/cicada-client/v161-fe565b4-20261001/build/test.private.apk --test-sha256 abbb764d459c60f8f31a7e92e22455754c804fdba48e7d99885bd2d53d552dec
python3 scripts/interop/v16-android-deterministic.py /gpu1-share/data/cicada-client/v16-deterministic-v161-fe565b4-20261001/android test
python3 scripts/interop/v16-android-deterministic.py /gpu1-share/data/cicada-client/v16-deterministic-v161-fe565b4-20261001/android ui
python3 scripts/interop/v16-android-deterministic.py /gpu1-share/data/cicada-client/v16-deterministic-v161-fe565b4-20261001/android stop
```

The host cleanup classifier initially expected a capitalized `No such`; Docker emitted lowercase `no such object`. The driver teardown itself passed. The original host-classifier FAIL receipt remains under `android/history/cleanup-case-sensitive-classifier.redacted.json`. A repeated read-only inspection verified absence and corrected the classifier receipt; no cleanup action, test or UI step was repeated. Expected `docker inspect` absence exits 1 and is not a test failure.

## Evidence and limitations

External receipts, exact argv arrays, exit codes, artifact hashes and cleanup evidence are under `/gpu1-share/data/cicada-client/v161-fe565b4-20261001/`, outside Git. The Client delivery commit is recorded in the post-commit receipt in that directory, avoiding a recursive document hash. Real Owner private keys, device codes, Node or Hub bearers and model credentials are absent from this import and checkpoint. Published synthetic test keys remain limited to public contract fixtures and instrumentation assets; they are not production credentials.

The earlier [4fb241b report](client-hub-v1.6-4fb241b-management-validation.md) remains historical. Its final `93d490…` APK owns local offline results; the older `9a6…` APK alone owns that report's connected results. Neither artifact certifies v1.6.1. The earlier native Join HTTP 404 is retained as a failure, not relabeled after Core source changes.
