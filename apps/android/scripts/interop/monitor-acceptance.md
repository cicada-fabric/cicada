# Monitor v1.3 Android interop acceptance procedure

This procedure exercises the Android Client's native ClientHub session against
one disposable Hub built from the frozen v1.3 core. The Node and three Endpoint
records are synthetic protocol fixtures. They are authorization test inputs;
they do not establish a native Thread, native Monitor, Runtime delivery, or
model-consumption path. This file is a procedure, not a test report; record the
actual run evidence separately and make no PASS claim until the recorded gates
have been reviewed.

## Fixed inputs and prerequisites

Use only this Hub identity:

| Item | Required value |
|---|---|
| CICADA source | `be0269e80c41e94881d131bd4f4b233e80b6ffe6` |
| Contract | `client-hub-v1.3` |
| Catalog SHA-256 | `808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377` |
| Hub image ID | `sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783` |
| Android emulator image ID | `sha256:ac9a2c457b10bb3397785941fc4b7884521b8431d9360b731c93ac6d6ea1521f` |
| Response proxy image ID | `sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358` |

The core fixture start command validates a completed `cicada.hub-build.v1` or
interop-result record, its clean source, catalog, image ID and runtime
provenance. From the CICADA checkout, use the metadata produced by its pinned
v1.3 interop run:

```sh
./scripts/client-group-key-fixture.sh start \
  --build-metadata .cicada-data/client-v13-be0269e/interop/result.json
```

Use the newly printed `/tmp/cgk.*` fixture directory for this run. Keep the
terminal output and fixture contents private: they include locally useful
identity coordinates and private-file paths. Do not copy those values into
this document, source control, screenshots for publication, or shared logs.
The fixture's Owner key is synthetic and remains outside the Hub and APK.

Before starting, make sure the existing Android app and test APKs have been
built with the repository's Docker Android test build. The Android driver
installs these files:

```text
android/app/build/outputs/apk/debug/app-debug.apk
android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
```

The driver requires Docker data root `/gpu1-share/data/docker-root`, the pinned
emulator image above, `/dev/kvm`, and a private evidence directory under
`/gpu1-share/data/cicada-client`. It checks ownership, permissions, image ID,
run ID, and emulator labels before operating on its container.

The external Owner signer must exist at the fixed path checked by
`monitor-fixture.py` and match its pinned SHA-256. If it is not already built,
follow [`group_owner_signer/README.md`](group_owner_signer/README.md), which
archives the fixed signer source and keeps the Owner private key on the trusted
signing host. Build the synthetic Node helper from the fixed core source into
the path checked by `monitor-fixture.py`:

```sh
FIXTURE_CORE_COMMIT=be0269e80c41e94881d131bd4f4b233e80b6ffe6 \
FIXTURE_BUILD_ROOT=/gpu1-share/data/cicada-client/monitor-v13-build/two-owner-node-fixture-build \
  bash scripts/interop/two_owner_node_fixture/build.sh
```

The helper build requires the pinned Go builder image already present locally.
It does not modify the CICADA checkout. It creates synthetic authorization
Endpoints only; do not describe its result as native Node or Monitor evidence.

## Create private run state and start the Hub and emulator

Run from the CICADA_CLIENT checkout. Choose a unique safe run label; keep the
evidence directory owned by the current user and mode `0700`:

```sh
RUN_ID=monitor-v13-REPLACE_WITH_UNIQUE_LABEL
EVIDENCE=/gpu1-share/data/cicada-client/$RUN_ID/evidence
install -d -m 700 "$EVIDENCE"
python3 scripts/interop/monitor-android.py "$EVIDENCE" start
```

The driver creates one owned emulator container and writes its selected
emulator and ADB server ports to `android-driver.json`. Preserve the marker;
the driver refuses to control an unmarked or differently labeled container.
Read `emulator_port` and `adb_port` from that private marker into local
`EMU_PORT` and `ADB_PORT` shell variables for the later reverse-removal step.
Wait for `$EVIDENCE/emulator-ready.json` to contain `"result":"READY"` before
installing; if the owned container exits without that marker, inspect only its
restricted emulator logs and stop this run before proceeding.
Install the already built app and test APKs:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" install
```

In a separate terminal, start the pinned core fixture with the command above.
Read the Hub's loopback port from that fixture's private output/result record;
do not paste it into shared output. Set shell variables locally:

```sh
FIXTURE_DIR=/tmp/cgk.REPLACE_WITH_PRINTED_SUFFIX
HUB_PORT=REPLACE_WITH_PRIVATE_LOOPBACK_PORT
PROXY_PORT=REPLACE_WITH_UNUSED_HIGH_LOOPBACK_PORT
```

`PROXY_PORT` must differ from `HUB_PORT`. Start a neutral forwarding proxy on
the same port that will later be used for the response-loss phases. The proxy
binds to host loopback, forwards only to this disposable Hub, and must be
running before any Android request is routed through it:

```sh
PROXY_NAME=cicada-$RUN_ID-proxy-neutral
docker run --rm -d --name "$PROXY_NAME" \
  --label "org.cicada.client-monitor-proxy=$RUN_ID" \
  --user "$(id -u):$(id -g)" --network host \
  -v "$PWD/scripts/interop/drop-first-response-proxy.py:/proxy.py:ro" \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 /proxy.py --listen "$PROXY_PORT" --target "$HUB_PORT"
```

Before staging the app configuration, verify that the container is running,
its image and `org.cicada.client-monitor-proxy` label match this run, and
`docker logs "$PROXY_NAME"` contains the expected `READY` line with the two
selected ports and no drop operation. Save that restricted log under
`$EVIDENCE`. Do not run a test while the proxy is not ready. Add the loopback
reverse mapping for the proxy port:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" reverse "$PROXY_PORT"
```

The Android app uses `http://127.0.0.1:$PROXY_PORT`; the proxy's upstream is
the private Hub loopback port. Never point this proxy at another Hub.

## Enroll the synthetic Owner and Node, then create the Group

Generate a fresh Android device identity and export only its public identity.
The export is retained in private evidence:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#prepareDevice
python3 scripts/interop/monitor-android.py "$EVIDENCE" export device-public.json
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  sign-device --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  config --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-android.py "$EVIDENCE" stage \
  "$FIXTURE_DIR/monitor-android-fixture.json" fixture.json
python3 scripts/interop/monitor-android.py "$EVIDENCE" stage \
  "$FIXTURE_DIR/monitor-node-codes.json" node-codes.json
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#enrollOwnerAndCheckCapabilities
```

`sign-device` has the external Owner signer approve the exact Android public
device identity; the Owner private key is not staged. The fixture JSON contains
public identities and signed grants, but remains a mode-`0600` private file.
The separately generated Node pairing code is staged only through the
driver's stdin-based `stage` action. Do not place its value in a command,
instrumentation argument, or log. The Node bearer stays under the fixture's
Node state directory and is never staged to Android.

Confirm the pending Node and create the Group through the encrypted Android
session. Each step has an explicit Android confirmation dialog. Export the
created Group coordinates only to private evidence, then publish three
synthetic Endpoint authorizations using the Node helper:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#confirmPendingNodes
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#createOrReconcileGroup
python3 scripts/interop/monitor-android.py "$EVIDENCE" export setup.json
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  publish --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  config --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-android.py "$EVIDENCE" stage \
  "$FIXTURE_DIR/monitor-android-fixture.json" fixture.json
```

The labels `monitor`, `recipient-a`, and `recipient-b` are synthetic
authorization records created for the same fixture Owner, Node, and Group.
Their synthetic session labels are not native Thread/session proofs. If the
one-time Node code expires before confirmation, run `monitor-fixture.py`'s
`refresh-node` action, regenerate and stage `monitor-node-codes.json`, and
repeat the explicit Node confirmation; do not print or copy the code into
evidence.

## Set the Monitor permission and grant the Endpoint keys

The Monitor role and explicit `message.broadcast` permission are independent.
The selected Monitor membership must first remain denied after role assignment;
then explicitly enable only that membership's permission. The test prompts for
the permission change. Export the three current Group Endpoint manifests only
after this revision change, have the external Owner signer sign each exact
manifest, and approve each grant on Android:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#assignMonitorRoleAndEnableBroadcastPermission
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#exportEndpointManifests
python3 scripts/interop/monitor-android.py "$EVIDENCE" export manifests.json
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  sign-groups --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  config --proxy-port "$PROXY_PORT"
python3 scripts/interop/monitor-android.py "$EVIDENCE" stage \
  "$FIXTURE_DIR/monitor-android-fixture.json" fixture.json
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#grantEndpointKeysAndReadCurrent
```

The Owner signer is external to the Android package. Grant proof files and
manifest exports remain in private fixture/evidence directories. Review each
Android dialog for the intended Group, Endpoint, and manifest before
confirming.

If a long run outlives its synthetic binding lease, start a separately recorded
phase using the helper's normal Join refresh:

```sh
python3 scripts/interop/monitor-fixture.py "$EVIDENCE" "$FIXTURE_DIR" \
  refresh --proxy-port "$PROXY_PORT"
```

This preserves the synthetic session and key identity, advances the binding
epoch through the supported Node API, and archives the previous public result.
It does not edit the Hub database or extend an old proof. Archive the previous
public `monitor-proof-*.json` and `monitor-manifest-*.json` files in a new private
fixture subdirectory, export fresh manifests after any permission change, and
repeat external Owner signing and the three explicit Android confirmations.
Record the new epoch and artifact set. Complete expiry-sensitive negative tests
before both the preview and Owner grant deadlines; a rejection because a grant
expired does not establish a permission-revocation test.
The fixture signer derives grant timestamps from the manifest's issue time.
Delayed signing does not restart the grant lifetime. Export fresh manifests
immediately before signing, inspect their signed deadlines, and complete the
intended test within that window.

## Run Prepare, Confirm, Status, and policy/recovery selectors

The positive path stores the verified consent preview and then asks for a
separate explicit approval before sealing and submitting the Monitor envelope:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#prepareExactTextAndReviewRoster
python3 scripts/interop/monitor-android.py "$EVIDENCE" export prepared.json
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#confirmReviewedEnvelopeAndReadStatus
python3 scripts/interop/monitor-android.py "$EVIDENCE" export result.json
```

The test's confirmation helper launches `MainActivity` and creates an Android
`AlertDialog` in instrumentation code. The tests invoke `ClientHubSession`
directly; they do **not** navigate or verify the React Native product Monitor
screen. The recorded dialogs prove instrumentation confirmation points, not
the production screen's layout or interaction flow. Verify the product UI
separately before claiming UI acceptance.

Response-loss tests use the same loopback proxy port but a new owned container
name for each phase. Before replacing a proxy, inspect its full image ID and
run label and stop it only if both match this run. Because the container uses
`--rm`, wait until `docker inspect` confirms its container name is gone and
verify the listening port is free before starting the next name. Keep logs
private, and require the new container's `READY` line before exercising the
app. `docker run -d` must itself exit zero, and `docker inspect` must show the
new container is running with the pinned image and this run's label. Do not
immediately reuse a just-stopped container name.

Use this sequence before each phase replacement, substituting the old
phase-specific container name. If the image/label output does not match, do
not stop that container:

```sh
OLD_PROXY_NAME=cicada-$RUN_ID-proxy-neutral
docker inspect --format '{{.Image}} {{index .Config.Labels "org.cicada.client-monitor-proxy"}}' "$OLD_PROXY_NAME"
docker stop "$OLD_PROXY_NAME"
until ! docker container inspect "$OLD_PROXY_NAME" >/dev/null 2>&1; do sleep 0.2; done
if ss -H -ltn "sport = :$PROXY_PORT" | grep -q .; then
  echo "proxy port is still listening" >&2
  exit 1
fi
```

After each new `docker run`, verify `{{.State.Running}} {{.Image}}` and the
run label, then wait for `docker logs "$PROXY_NAME"` to contain the expected
`READY` line for this phase's ports/drop operation. Keep the complete log in
the private evidence directory; a successful container start alone is not
proxy readiness.

For the Prepare loss branch, leave the Android session pinned to the proxy
port. Stop `proxy-neutral`, wait for removal and port release, then run the
instrumentation selector below while that port is intentionally unbound. This
first offline attempt creates a durable pending encrypted packet locally but
does not reach or mutate the Hub:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#prepareResponseLossKeepsOriginalPacket
```

Start a distinct `proxy-prepare` container at the same port with the pinned
proxy image and `--drop-operation monitor.broadcast_prepare` (the command
shape is shown below). Check its image, run label, `READY` line, and ports
before continuing. In the Android product's pending-request recovery UI, run
`/recover`. The expected `RECOVERY_REJECTED` means this exact packet was not
accepted during the offline attempt; it is not permission to create a new
Prepare. Explicitly choose the UI's one-time **retry original request** action
and approve its confirmation dialog. It must replay the same saved packet,
operation ID, and sequence. The proxy evidence must say `DROPPED` for
`/v2/client/rpc`, operation `monitor.broadcast_prepare`, and Hub status `200`.
Then recover the original Monitor Prepare read-only and verify that no new
Prepare was created:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#recoverLostPrepareWithoutAnotherOperation
```

Example exact Prepare-phase proxy command (with the run and ports supplied
only in the local shell):

```sh
PROXY_NAME=cicada-$RUN_ID-proxy-prepare
docker run --rm -d --name "$PROXY_NAME" \
  --label "org.cicada.client-monitor-proxy=$RUN_ID" \
  --user "$(id -u):$(id -g)" --network host \
  -v "$PWD/scripts/interop/drop-first-response-proxy.py:/proxy.py:ro" \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 /proxy.py --listen "$PROXY_PORT" --target "$HUB_PORT" \
  --drop-path /v2/client/rpc --drop-operation monitor.broadcast_prepare
```

For Confirm loss, first verify and inspect the same recovered prepared preview.
Stop `proxy-prepare`; verify its full image and run label, wait for container
removal and port release, then start `proxy-confirm` at the same port with
`--drop-operation monitor.broadcast_confirm`. Require its own `READY` line
before the next test. The instrumentation dialog asks for explicit approval;
the proxy must log the Hub-accepted HTTP `200` before discarding the response.
Recover the exact pending encrypted response and read status for that same
preview:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#confirmResponseLossKeepsOriginalSealedEnvelope
python3 scripts/interop/monitor-android.py "$EVIDENCE" test \
  ai.cicada.client.hub.MonitorHubInteropTest#recoverLostConfirmAndReadOriginalStatus
```

Example Confirm-phase proxy command:

```sh
PROXY_NAME=cicada-$RUN_ID-proxy-confirm
docker run --rm -d --name "$PROXY_NAME" \
  --label "org.cicada.client-monitor-proxy=$RUN_ID" \
  --user "$(id -u):$(id -g)" --network host \
  -v "$PWD/scripts/interop/drop-first-response-proxy.py:/proxy.py:ro" \
  sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358 \
  python3 /proxy.py --listen "$PROXY_PORT" --target "$HUB_PORT" \
  --drop-path /v2/client/rpc --drop-operation monitor.broadcast_confirm
```

Additional selectors and preconditions:

| Selector | Preconditions and purpose |
|---|---|
| `rejectChangedTextAndUnknownPreviewBeforeSending` | Creates a disposable preview; verifies changed body and unknown preview are rejected before sending. It saves the preview needed by the stale-permission selector. |
| `capacityReturnsOneBoundedRejectionWithoutRetry` | Run while the Monitor permission remains enabled, after the other Prepare/Confirm cases. It may occupy all live preview slots until their five-minute expiries. |
| `rejectStalePreviewAfterBroadcastPermissionRevoked` | Run promptly after `rejectChangedTextAndUnknownPreviewBeforeSending`, while its preview is unexpired. It revokes only the explicit permission and proves the old preview cannot be sealed. If capacity or other work makes the preview expire, use a fresh disposable fixture for these two selectors. |
| `verifyOriginalPendingPrepareEvidence` | Diagnostic only when investigating an original pending Prepare. It reads the exact stored request locally and must not be used to export device keys or draft plaintext. |
| `recoverOriginalPrepareAfterPreviewExpiry` | Run only with the original Prepare still pending and after its five-minute preview has expired; it checks readonly recovery and status, not confirmation. |
| `recoverExpiredStatusWithOriginalPacket` | Requires an original pending Status RPC whose response was lost; it verifies same-request recovery and an empty expired outcome ledger. |

`monitor-android.py test` accepts a fully qualified class and method selector,
as above, or a class selector. Run each method individually so the operator
can review each explicit Android confirmation before it proceeds. Do not start
a second instrumentation run while a first run is waiting on a dialog.

## Evidence, interpretation, and cleanup

For every driver action, retain its JSON command/exit record and restricted
`.private.log`. Test records include the JUnit summary; installation records
include the app and test APK hashes. Exported files are named
`*.private.json` (with an additional content-hash copy). Repeated action names
are moved into the private `history/` directory before replacement. Keep the
run tree mode `0700`; do not commit, attach, or broadly share raw records,
proofs, device codes, identity objects, prepared previews, status records, or
screenshots. A redacted summary may report versions, test selector,
exit/JUnit result, and hashes after independent review, but must omit IDs,
codes, keys, signed proof bytes, plaintext, and local paths.

`PREPARED`, `APPROVED`, and `DISPATCH_AUTHORIZED` are approval/reservation
states, not delivery or model-consumption results. An empty pre-dispatch
recipient ledger must remain empty in the evidence; do not synthesize
`PENDING` rows. `NODE_REPORTED` and `RELAY_PERSISTED` are evidence of their
named persistence layer only. They do not prove native Runtime or model
consumption or successful work. The fixture does not start a native Monitor,
native Thread, or physical Node.

Before cleanup, stop the current proxy only after verifying its container
image and run label. Then wait for automatic removal and verify the listening
port is free. Remove the ADB reverse entry for that proxy port using the
emulator container and ports recorded in `android-driver.json`:

```sh
docker exec "cicada-$RUN_ID" \
  /opt/android-sdk/platform-tools/adb -P "$ADB_PORT" -s "emulator-$EMU_PORT" \
  reverse --remove "tcp:$PROXY_PORT"
```

Stop the owned Android driver container, then stop the matching core fixture:

```sh
python3 scripts/interop/monitor-android.py "$EVIDENCE" stop
```

```sh
../CICADA/scripts/client-group-key-fixture.sh stop "$FIXTURE_DIR"
```

The core `stop` command validates its fixture marker and container ownership
before removing the disposable Hub and `/tmp/cgk.*` state, including the
synthetic Owner private key, Node credential, one-time pairing code, and Hub
state. Confirm that no proxy or owned fixture container remains. Preserve the
private evidence directory only for local review; delete it according to the
run's retention policy when review is complete. Cleanup does not turn this
synthetic protocol exercise into native Monitor or product-UI acceptance.
