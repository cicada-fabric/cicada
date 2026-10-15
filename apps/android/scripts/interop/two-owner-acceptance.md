# Disposable two-Owner Android authorization acceptance

This driver tests `client-hub-v1.2.1` against the clean `967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` Hub image pinned in `two-owner-fixture.py`. It uses a fresh Hub, two synthetic Owners, three independently generated Android device identities (A, A-admin and B), two synthetic Node credentials and two existing Groups/Endpoints. The Endpoint adapters are test doubles. No Codex process runs and this evidence is not native Thread acceptance.

The Owner private keys remain with the external signer. Each Node helper receives only its bearer file through a read-only mount and its private temporary Endpoint directory. Android receives public Hub/Owner identities, signed public Grants and a short-lived private file containing pairing codes. File contents are passed through stdin; instrumentation arguments contain only the nonsecret run ID. The Android device contexts share one emulator app UID and wrapping Keystore alias; independent PQ identities and request journals test authorization separation, not OS-level key isolation.

## Prerequisites

- Fixed protocol archive, clean core Git commit and full Hub image named in the Client README.
- Docker data root `/gpu1-share/data/docker-root`, local Android build/emulator images, and `/dev/kvm`.
- Existing external `group_owner_signer` binary built from the fixed commit. Its SHA-256 is checked before signing; build instructions are in `group_owner_signer/README.md`.
- Local Go 1.27.1 builder image and dependency cache. The Go helper and emulator images are selected by full image ID in the driver. `two_owner_node_fixture/build.sh` archives the fixed core commit into an external build directory and uses the same pinned builder; the driver verifies the helper binary SHA-256 before passing it a credential.

## Commands

Run from the Client repository. These commands never select a resident Hub.

```bash
./scripts/docker-build-android-test.sh
bash scripts/interop/two_owner_node_fixture/build.sh
python3 scripts/interop/two-owner-fixture.py prepare
```

Copy the **new** `fixture` path from the preparation result into `FIXTURE_DIR`. The result also names the private evidence directory. Keep the returned marker file intact until teardown.

```bash
FIXTURE_DIR=/tmp/cto.REPLACE_WITH_NEW_FIXTURE
python3 scripts/interop/two-owner-fixture.py start-emulator "$FIXTURE_DIR"
```

Wait for the private evidence directory's `emulator-ready.json` before installing. The emulator has fresh container-local AVD data, a dedicated port and ADB server, and a unique ownership label. The following commands pass no Owner private key, bearer or code value in process arguments:

```bash
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" install
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test prepareTwoOwnerDeviceKeys
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" export device-publics.json
python3 scripts/interop/two-owner-fixture.py sign-devices "$FIXTURE_DIR"
python3 scripts/interop/two-owner-fixture.py bootstrap-nodes "$FIXTURE_DIR"
python3 scripts/interop/two-owner-fixture.py android-config "$FIXTURE_DIR"
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" stage "$FIXTURE_DIR/android-fixture.json" fixture.json
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" stage "$FIXTURE_DIR/android-private-fixture.json" private-fixture.json
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test enrollConfirmAndCreateOwnerGroups
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" export groups.json
python3 scripts/interop/two-owner-fixture.py publish-endpoints "$FIXTURE_DIR"
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" stage "$FIXTURE_DIR/android-fixture.json" fixture.json
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test exportOwnerGroupManifests
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" export manifests.json
python3 scripts/interop/two-owner-fixture.py sign-groups "$FIXTURE_DIR"
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" stage "$FIXTURE_DIR/android-fixture.json" fixture.json
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" test twoOwnerOwnershipAndRevocationMatrix
python3 scripts/interop/two-owner-android.py "$FIXTURE_DIR" export result.json
```

The enrollment and grant stages require confirming the displayed synthetic Node/Group scopes on the disposable emulator. Use only that fixture's recorded container, ADB port and emulator serial for interactions. Do not attach a competing UI automation service while instrumentation owns the foreground activity.

The final matrix distinguishes local Client rejection, HTTP 200 with a signed encrypted business rejection, and HTTP 403 after device revocation. A-admin revokes A because the contract rejects self-revocation. Requests naming the other Owner use that Owner's actual existing Group, Endpoint and signed proof. The raw negative driver is instrumentation-only and does not relax the Android product verifier. Valid Grant records are re-read to establish unchanged target authorization state; the Hub's request ledger legitimately advances for an authenticated rejected request.

## Evidence and cleanup

The fixture and Android runners record commands, exit codes and private logs outside Git. An ADB exit code of zero is insufficient: the runner also requires JUnit `OK (1 test)`. Public object IDs are retained privately; only hashes and result classifications belong in the committed report. Preserve the APK hashes in `android-artifacts.json`, the exact Client implementation commit, the complete Hub image ID and protocol/catalog digests.

Always remove this run's resources, including after a failed preparation or interrupted test:

```bash
python3 scripts/interop/two-owner-fixture.py stop "$FIXTURE_DIR"
```

Cleanup validates the private marker, derived names, fixture labels and full image IDs before removing owned containers and private temporary state. It removes the emulator and its reverse mapping together, Owner/Endpoint private keys, Node credentials, pairing codes and Hub state. The restricted evidence directory persists for local review. A failed `prepare` prints its fixture/evidence paths and requires the same explicit cleanup; it does not imply acceptance. Physical Android and public HTTPS remain separate, unrun gates unless independently exercised.
