# Fixed-Hub Android to native Monitor fixture

This is a **run procedure**, not an execution report. The previous joint attempt
on the frozen `be0269e` Hub **failed** at Session renewal, as recorded in the
[joint validation report](client-monitor-native-joint-validation.md). The
[25013b5 candidate validation report](client-hub-v13-25013b5-validation.md)
tracks deterministic gates and the completed controlled run. This procedure targets
the unchanged `client-hub-v1.3` contract, clean Hub source
`25013b51915124fa1da25e5fd37088eadf0e3d2d`, and image
`sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c`.
The candidate includes the lease-presence fix and a read-only verified Monitor
approval preview. Prior `81d8f1f` candidate attempts did not complete the
two-recipient native chain; their outcomes remain separate historical evidence.
Record this run's Client commit and app/test APK hashes. Keep Client, Hub, native
runner, helper and test-binary identities separate.

The controlled 2026-09-27 run against this candidate completed the bounded
Android/native chain: one verified preview and one separately reviewed dispatch
on the original Monitor Thread, followed by receive/context assertions in both
original recipient Threads. Client strict status, Core scoped Hub ciphertext
scan, Intake's read-only Hub audit and fixture cleanup passed. The final
evidence and limits are in the [candidate validation report](client-hub-v13-25013b5-validation.md)
and [Client validation report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).
This run used two logical Nodes in one container; physical dual-Node/Android,
public HTTPS and full product-facing React Native consent UI remain **NOT_RUN**.

The test uses two logical Nodes in one container and three real original Codex
Threads. It does not demonstrate physical dual-Node operation or unattended
delivery. The fixed Codex image is
`sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264`,
with Codex CLI `0.157.1` already installed by the pinned shell-installer image;
the test model is exactly `gpt-5.6-luna`. The native test calls the model, so
the live run is not an offline check. Provider credentials must be in the
external host file `/gpu1-share/data/cicada/secrets/cicada.env`, mode `0600`,
passed with Docker `--env-file` only. Do not bind that file or the Hub's
`hub.env`, Owner private identity, or Node state into Android.

## Prepare the Hub and Android-owned state

From the CICADA root on the disposable Linux Docker host, start only the
fixed-image fixture:

```bash
./scripts/client-group-key-fixture.sh start \
  --build-metadata .cicada-data/monitor-approval-review-25013b5/build.json
```

Set `FIXTURE_DIR` to the exact `/tmp/cgk.*` directory printed by the command.
Keep it private and use a new fixture for each run. Make the second logical
Node and private pairing-code handoff:

```bash
./scripts/client-monitor-native-fixture.sh bootstrap-remote "$FIXTURE_DIR"
```

The command writes `native-monitor-node-codes.json` with `local` and `remote`
codes, mode `0600`. Keep this file on the host and delete it after both codes
are consumed. It never prints the codes.

Use the Client-provided app and AndroidTest APKs verified for this candidate with
`../CICADA_CLIENT/scripts/interop/monitor-android.py`. Give the driver a fresh
evidence directory under `/gpu1-share/data/cicada-client/` named
`monitor-v13-<run-id>/evidence`, with parent and evidence directory mode
`0700`. Record the Client commit and artifact hashes from its `install` record.
Set a unique `RUN_ID` matching `monitor-v13-<suffix>`; for example:

```bash
CLIENT=/home/zyf/CICADA_CLIENT
RUN_ID=monitor-v13-leasefix-20260927-a
ANDROID_EVIDENCE="/gpu1-share/data/cicada-client/$RUN_ID/evidence"
install -d -m 0700 "$(dirname "$ANDROID_EVIDENCE")" "$ANDROID_EVIDENCE"
HUB_PORT="$(python3 - "$FIXTURE_DIR/fixture-result.json" <<'PY'
import json, sys
from urllib.parse import urlsplit
print(urlsplit(json.load(open(sys.argv[1]))['hub']['url']).port)
PY
)"
android() { python3 "$CLIENT/scripts/interop/monitor-android.py" "$ANDROID_EVIDENCE" "$@"; }

android start
android install
android reverse "$HUB_PORT"
```

Keep this Bash session (and the `android` helper function) open for the
remaining steps.

Create a fresh Android device identity and export its public identity. Use the
external Owner signer to create a device grant, then stage the fixed Hub/Owner
fixture with that grant before enrollment:

```bash
android test ai.cicada.client.hub.MonitorHubInteropTest#prepareDevice
android export device-public.json

read -r OWNER_ID OWNER_KEY_ID HUB_ID < <(python3 - "$FIXTURE_DIR/fixture-result.json" <<'PY'
import json, sys
v = json.load(open(sys.argv[1]))
print(v['owner']['owner_id'], v['owner']['owner_key_id'], v['hub']['hub_id'])
PY
)
DEVICE_KEY_ID="$(python3 - "$ANDROID_EVIDENCE/device-public.private.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))['id'])
PY
)"
DEVICE_ID="android-${RUN_ID}"
SIGNER_BIN=/gpu1-share/data/cicada-client/group-owner-signer-build-967dbd-20260925/bin/group_owner_signer
test "$(sha256sum "$SIGNER_BIN" | awk '{print $1}')" = \
  cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1
"$SIGNER_BIN" device-grant \
  --private "$FIXTURE_DIR/owner-private/owner-private.json" \
  --device-public "$ANDROID_EVIDENCE/device-public.private.json" \
  --owner "$OWNER_ID" --device "$DEVICE_ID" --hub "$HUB_ID" \
  --expect-device-key "$DEVICE_KEY_ID" \
  --out "$FIXTURE_DIR/monitor-device-grant.json"

./scripts/client-monitor-native-fixture.sh config "$FIXTURE_DIR" "$HUB_PORT"
android stage "$FIXTURE_DIR/native-monitor-android-fixture.json" fixture.json
android test ai.cicada.client.hub.MonitorHubInteropTest#enrollOwnerAndCheckCapabilities
android stage "$FIXTURE_DIR/native-monitor-node-codes.json" node-codes.json
android test ai.cicada.client.hub.MonitorHubInteropTest#confirmPendingNodes
android test ai.cicada.client.hub.MonitorHubInteropTest#createOrReconcileGroup
android export setup.json
./scripts/client-monitor-native-fixture.sh stage-group "$FIXTURE_DIR" \
  "$ANDROID_EVIDENCE/setup.private.json"
./scripts/client-monitor-native-fixture.sh config "$FIXTURE_DIR" "$HUB_PORT"
android stage "$FIXTURE_DIR/native-monitor-android-fixture.json" fixture.json
```

`confirmPendingNodes` previews and explicitly confirms both Node IDs, then
deletes the staged pairing-code file. The Owner signer runs outside Android
and the Hub; it displays the exact scope and requires typed confirmation. Its
build boundary is documented in
`../CICADA_CLIENT/scripts/interop/group_owner_signer/README.md`: copy its
`main.go` into a temporary clean archive of source
`967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a` and build with Go 1.27.1. Use a
prebuilt binary only after checking the pinned SHA above. Do not use the old
`monitor-fixture.py` wrapper, which points at a dated signer path. Keep the
Owner private identity and signed proofs on the Owner host, never in the APK.
Do not initialize or update Hub state directly.

## Build the native runner and join the original Threads

Stage an allowlisted native runtime after Android created the Group:

```bash
./scripts/client-monitor-native-fixture.sh runtime "$FIXTURE_DIR"
```

Verify the pinned Codex image and its preinstalled CLI without running a model:

```bash
CODEX_IMAGE=sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264
test "$(docker image inspect --format '{{.Id}}' "$CODEX_IMAGE")" = "$CODEX_IMAGE"
docker run --rm --network none --entrypoint /usr/local/bin/codex "$CODEX_IMAGE" --version
```

Compile the Go test binary offline with the pinned Go 1.27.1 builder image. Run
from the CICADA root with module/build caches already populated; `GOPROXY=off`
and `--network none` prevent downloads. The source tree is mounted read-only,
module cache read-only, and build cache/output are the only writable mounts:

```bash
GO_IMAGE=sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -e GOPROXY=off -e GOCACHE=/cache -e GOMODCACHE=/go/pkg/mod \
  --mount "type=bind,src=$PWD,dst=/workspace,readonly" \
  --mount "type=bind,src=$FIXTURE_DIR/native-runtime/bin,dst=/out" \
  --mount 'type=bind,src=/home/zyf/go/pkg/mod,dst=/go/pkg/mod,readonly' \
  --mount 'type=bind,src=/home/zyf/.cache/go-build,dst=/cache' \
  -w /workspace/cicada-go "$GO_IMAGE" \
  go test -c -o /out/cicada-android-native.test ./cmd/cicada
```

Before the live run, require clean runner source commit
`0d532f2e3bb57a9c82df4967044e4f40861c45a6` and helper SHA-256
`d542ca5df79983210bd58a6261384efd5d90cfb6890c8b4680d7b87f90ab9e7a`.
After compilation, verify the test binary SHA-256 is
`c992dd4ce9fdaeb6895ad827ae8e196155abba5009e2b3da1c4e5931eccd8589`. The Hub
image revision does not identify this separately compiled test source; record
all identities independently.

Run the native test in one foreground-owned disposable container, redirecting
its output to a private log. The test creates the Monitor, recipient-a and
recipient-b original Threads; the first two join the local logical Node, the
third joins the remote logical Node. It writes
`native-runtime/native-monitor-endpoints.json`, then waits for the phone's
confirmation handoff. Keep this process alive while completing the Android
steps below. The exact Docker invocation is:

```bash
PROVIDER_ENV_FILE=/gpu1-share/data/cicada/secrets/cicada.env
test "$(stat -c '%a' "$PROVIDER_ENV_FILE")" = 600
umask 077
docker run --rm --network host --user "$(id -u):$(id -g)" \
  --env-file "$PROVIDER_ENV_FILE" \
  -e CICADA_MONITOR_ANDROID_NATIVE_E2E=1 \
  -e CICADA_MONITOR_ANDROID_FIXTURE="$FIXTURE_DIR" \
  -e CICADA_NATIVE_MODEL=gpt-5.6-luna \
  -e CICADA_CODEX_BIN=/usr/local/bin/codex \
  -e CICADA_NATIVE_CICADA_BIN="$FIXTURE_DIR/bin/cicada" \
  -e CODEX_HOME="$FIXTURE_DIR/native-codex-home" \
  --mount "type=bind,src=$FIXTURE_DIR/native-runtime,dst=$FIXTURE_DIR" \
  --mount "type=bind,src=$FIXTURE_DIR/node-state,dst=$FIXTURE_DIR/node-state" \
  --mount "type=bind,src=$FIXTURE_DIR/remote-node-state,dst=$FIXTURE_DIR/remote-node-state" \
  --mount "type=bind,src=$FIXTURE_DIR/native-runtime/bin,dst=$FIXTURE_DIR/bin,readonly" \
  sha256:742214d7f2b7f0cd6a4f5bd5ed1d55d0026c25de0f654dc868cfdf70882cf264 \
  "$FIXTURE_DIR/bin/cicada-android-native.test" \
  -test.run '^TestMCPMonitorBroadcastAndroidClientNative$' \
  -test.timeout=35m -test.v >"$FIXTURE_DIR/native-monitor-run.private.log" 2>&1 &
NATIVE_TEST_PID=$!
```

Wait at most 15 minutes for `native-runtime/native-monitor-endpoints.json` to
appear, checking every two seconds that the runner is still alive:

```bash
for _ in $(seq 1 450); do
  [[ -s "$FIXTURE_DIR/native-runtime/native-monitor-endpoints.json" ]] && break
  kill -0 "$NATIVE_TEST_PID" || { wait "$NATIVE_TEST_PID"; exit 1; }
  sleep 2
done
if [[ ! -s "$FIXTURE_DIR/native-runtime/native-monitor-endpoints.json" ]]; then
  kill "$NATIVE_TEST_PID" 2>/dev/null || true
  wait "$NATIVE_TEST_PID" || true
  printf 'BLOCKED: native Endpoint handoff did not arrive; retain the private log for review\n' >&2
  exit 1
fi
```

Do not print Thread IDs, credentials or the raw private log. The runner keeps the
same authenticated Session credential and binding epoch with a 30-second
heartbeat; it does not re-Join or replace any Thread.

## Grant, prepare, confirm and release the handoff

Once the native Endpoint file exists, rebuild the Android fixture with the
real Endpoint IDs and stage it on the emulator. The Monitor membership does
not exist before this native Join. Assign the Monitor role and explicitly
enable `message.broadcast` for only that Group membership; a Monitor role alone
does not grant broadcast permission. Then review and export the three full
Endpoint manifests:

```bash
./scripts/client-monitor-native-fixture.sh config "$FIXTURE_DIR" "$HUB_PORT"
android stage "$FIXTURE_DIR/native-monitor-android-fixture.json" fixture.json
android test ai.cicada.client.hub.MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission
android test ai.cicada.client.hub.MonitorHubInteropTest#exportEndpointManifests
android export manifests.json
```

Have the Owner review/sign each manifest using the pinned
external signer. The `sign-groups` action checks that the manifest scope
matches the real Owner, Group, Node, principal and Endpoint IDs, and writes
private proofs; Android must still explicitly approve each encrypted
`group.key_grant` and read `group.key_status=CURRENT`:

```bash
./scripts/client-monitor-native-fixture.sh sign-groups "$FIXTURE_DIR" \
  "$ANDROID_EVIDENCE/manifests.private.json" "$SIGNER_BIN"
./scripts/client-monitor-native-fixture.sh config "$FIXTURE_DIR" "$HUB_PORT"
android stage "$FIXTURE_DIR/native-monitor-android-fixture.json" fixture.json
android test ai.cicada.client.hub.MonitorHubInteropTest#grantEndpointKeysAndReadCurrent
```

After all three grants are current, request `monitor.broadcast_prepare` on the
phone, review the exact text and two-recipient roster, then explicitly Confirm
once. These existing Android selectors perform the Prepare and one explicit
Confirm. Export only the private Android `prepared.json` and `result.json`
records and stage the bounded handoff for the waiting test:

```bash
android test ai.cicada.client.hub.MonitorHubInteropTest#prepareExactTextAndReviewRoster
android test ai.cicada.client.hub.MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus
android export prepared.json
android export result.json
./scripts/client-monitor-native-fixture.sh stage-confirmed "$FIXTURE_DIR" \
  "$ANDROID_EVIDENCE/prepared.private.json" "$ANDROID_EVIDENCE/result.private.json"
```

The handoff contains preview/broadcast IDs, exact body digest, recipient
Endpoint IDs, status and original expiry, but not plaintext body or credentials.
The native runner dispatches on the original Monitor Thread and receives on
both original recipient Threads. The Hub's five-minute preview deadline
constrains dispatch; it does not extend or renew a Group grant. Complete the
phone Confirm and stage this handoff before the original preview deadline.

After the native test exits, save its exit code privately. Only after a native
exit `0`, run the Client's read-only
`MonitorHubInteropTest#readNativeDispatchStatus` selector against the same
Android Session. Require ADB/driver exit `0/0` and `OK (1 test)`: it checks two
`ACCEPTED` recipients with local `NODE_REPORTED` and remote `RELAY_PERSISTED`
evidence. This final Android status is separate from native Thread consumption.
Then run the narrow fixture check:

```bash
set +e
wait "$NATIVE_TEST_PID"
NATIVE_TEST_EXIT=$?
set -e
printf '%s\n' "$NATIVE_TEST_EXIT" >"$FIXTURE_DIR/native-monitor-run.exit"
chmod 0600 "$FIXTURE_DIR/native-monitor-run.exit"
test "$NATIVE_TEST_EXIT" -eq 0
android test ai.cicada.client.hub.MonitorHubInteropTest#readNativeDispatchStatus
./scripts/client-monitor-native-fixture.sh verify-private "$FIXTURE_DIR"
```

This checks the exact two-child chain marker and scans only the disposable Hub
SQLite/WAL/SHM files for the synthetic message body and Thread context markers.
It is a scoped plaintext-at-rest check, not a general database audit. Record
the Android test selectors/exits, Hub/container/image identity, native source
and test-binary hashes, Codex image/version/model, outer test exit and cleanup.
Keep raw evidence restricted and redact IDs, pairing codes, signer proofs,
Session/Node tokens and plaintext. Interpret layers separately: phone Preview /
Confirm, native Monitor dispatch, local `NODE_REPORTED`, relay persistence and
recipient Thread response are distinct outcomes.

Stop the Client-owned emulator/reverse mapping after the Go test exits, then
remove only the marked Hub fixture:

```bash
android stop
./scripts/client-group-key-fixture.sh stop "$FIXTURE_DIR"
```

The Go runner uses `--rm`; the Hub cleanup validates its original marker and
container labels. Do not stop the Hub before the native test and final Android
status read finish. The completed run recorded Android selector/status PASS,
native runner exit `0`, independent Hub audit PASS, scoped ciphertext scan PASS,
and owned cleanup exit `0`. The Android app/test, Hub, Go test source/binary and
Codex image remain separate evidence identities in the [candidate report](client-hub-v13-25013b5-validation.md)
and [Client report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).
This bounded run does not generalize to arbitrary prompts or payloads, physical
devices, full React Native consent UI, or public HTTPS. Physical dual-Node
operation and public HTTPS require separate evidence.
