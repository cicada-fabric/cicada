# Fixed-Hub Android Monitor Prepare recovery faults

Target: frozen `client-hub-v1.3` (wire v1), source commit
`be0269e80c41e94881d131bd4f4b233e80b6ffe6`, Hub image
`sha256:6cc7c2c67a8c15ad0bd7879d652cdaf07d5104fac29912ec33f04ac647587783`.
This is a reproducible runbook. Its three outer RPC recovery-ledger cases were
executed on 2026-09-27; see [Recorded execution](#recorded-execution) and the
linked Client evidence report. The run results do not cover Monitor business
execution or native delivery.

Each case needs a fresh disposable Hub database and a fresh authenticated Client
session. The first slice targets only `monitor.broadcast_prepare`;
`monitor.broadcast_confirm` is an optional later repeat, not part of this
acceptance. Do not call `monitor.broadcast_confirm` or claim that the Monitor
operation ran.

Start the existing v1.3 Group-key fixture by its exact frozen build metadata:

```bash
./scripts/client-group-key-fixture.sh start \
  --build-metadata .cicada-data/client-v13-be0269e/interop/result.json
```

Follow [the disposable fixture setup](client-group-key-disposable-fixture.md)
for Client enrollment and the isolated emulator's Hub identity pin. Record the
printed fixture directory as `FIXTURE_DIR`; use its Hub URL as the proxy target.
The Group-key script writes
`state/.cicada-disposable-client-group-key-fixture`. The Go companion requires
its own marker, so create this second marker in that same dedicated state
directory. First verify that `FIXTURE_DIR` is the exact directory printed by
`start`, beneath real `/tmp`, and still carries the Group-key marker:

```bash
set -euo pipefail
: "${FIXTURE_DIR:?Set the exact disposable fixture directory printed by start}"
FIXTURE_DIR="$(python3 - "$FIXTURE_DIR" <<'PY'
from pathlib import Path
import json
import os
import sys

requested = Path(sys.argv[1])
if requested.is_symlink():
    raise SystemExit('BLOCKED: fixture directory must not be a symlink')
root = requested.resolve(strict=True)
tmp = Path('/tmp').resolve(strict=True)
marker = root / '.cicada-client-group-key-fixture.json'
if (root == tmp or os.path.commonpath((str(tmp), str(root))) != str(tmp)
        or marker.is_symlink() or not marker.is_file()):
    raise SystemExit('BLOCKED: expected an owned Group-key fixture beneath /tmp')
data = json.loads(marker.read_text(encoding='utf-8'))
if (data.get('schema') != 'cicada.client-group-key-fixture.v1'
        or data.get('fixture_dir') != str(root)
        or (root / 'state').is_symlink()
        or not (root / 'state').is_dir()):
    raise SystemExit('BLOCKED: Group-key fixture marker/state does not match')
print(root)
PY
)"
printf 'disposable\n' >"$FIXTURE_DIR/state/.cicada-disposable-recovery-fixture"
chmod 0600 "$FIXTURE_DIR/state/.cicada-disposable-recovery-fixture"
```

Use both the proxy and helper from a clean checkout of the **same frozen Hub
source commit**, not from a later development tree. Set `HUB_SOURCE_DIR` to the
CICADA root of that checkout and verify its identity before compiling:

```bash
: "${HUB_SOURCE_DIR:?Set the clean be0269e source checkout}"
test "$(git -C "$HUB_SOURCE_DIR" rev-parse HEAD)" = \
  be0269e80c41e94881d131bd4f4b233e80b6ffe6
test -z "$(git -C "$HUB_SOURCE_DIR" status --porcelain=v1)"
docker run --rm --network none \
  -v "$HUB_SOURCE_DIR/cicada-go:/src:ro" \
  -v "$FIXTURE_DIR:/out" \
  -v /home/zyf/go/pkg/mod:/go/pkg/mod:ro \
  -w /src -e CGO_ENABLED=0 -e GOPROXY=off -e GOCACHE=/tmp/cicada-recovery-build-cache \
  golang:1.27.1-bookworm go build -buildvcs=false \
  -o /out/client-recovery-fixture ./cmd/client-recovery-fixture
HUB_URL="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hub"]["url"])' \
  "$FIXTURE_DIR/fixture-result.json")"
HUB_CONTAINER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hub_container"])' \
  "$FIXTURE_DIR/.cicada-client-group-key-fixture.json")"
```

This compiles the companion from source revision
`be0269e80c41e94881d131bd4f4b233e80b6ffe6`; record that source revision with the
test evidence. Its database must remain the regular SQLite
file under this fixture's `/tmp` directory. Start one proxy for the selected
scenario before the Client session begins. Configure the Client's Hub origin to
the proxy's reachable loopback address (`http://127.0.0.1:8790` through the
existing emulator port mapping); keep the Hub identity pin from the fixture's
`hub-identity.json`. The proxy forwards every non-target request. Its
`--hub-url` remains the direct loopback URL printed by the fixture. For example,
using the proxy from the same frozen source revision:

```bash
python3 "$HUB_SOURCE_DIR/scripts/client-recovery-fault-proxy.py" \
  --listen-port 8790 --hub-url "$HUB_URL" \
  --db "$FIXTURE_DIR/state/cicada.sqlite3" \
  --fixture-binary "$FIXTURE_DIR/client-recovery-fixture" \
  --scenario processing --operation monitor.broadcast_prepare
```

Repeat fixture start, marker creation and Client session setup for each row.
Have the Client send exactly one
`monitor.broadcast_prepare`, retain its original outer packet, wait for the
proxy's `FAULT_READY`, then recover through `/v2/client/rpc/recover` using that
exact packet. Do not call the Monitor-level `monitor.broadcast_recover` here;
that is a separate read-only lookup for a Prepare operation whose business
handler already ran.

| Proxy mode | Action after `FAULT_READY` | Expected outer recovery result |
|---|---|---|
| `processing` | Recover immediately; do not resubmit Prepare. | HTTP 409 `STILL_PROCESSING`. |
| `uncertain` | Save the marked Hub container ID, image ID, state mount source and Hub identity. Restart only that marked Hub with `docker restart --time 10 "$HUB_CONTAINER"`; re-read the published host port with `docker port "$HUB_CONTAINER" 8787/tcp` (the random port may change), then health-check the new direct loopback URL and verify the saved Hub identity. Keep the same DB mount throughout. Retarget the owned proxy upstream to the new Hub URL while retaining its original loopback listen port and selected `monitor.broadcast_prepare` match. The proxy does not enforce a forwarding-only mode: after retarget, the Client must send only original `/v2/client/rpc/recover` and the separate read-only `status.snapshot`, with no second Prepare; assert there is no second `FAULT_READY`. Leave the Android Hub origin and Client journal unchanged. | HTTP 200 signed/encrypted `OUTCOME_UNCERTAIN` using the reserved response sequence. |
| `legacy` | Recover immediately; do not resubmit Prepare. | HTTP 409 `RECOVERY_UNAVAILABLE`. |

The companion fixture marks only the outer request row. It reads the visible
RPC route and ciphertext packet digest; it does not authenticate the packet or
forward it to the Hub's Monitor handler. Thus these cases verify Client packet
retention/recovery behavior and the Hub's generic RPC recovery state machine,
not Monitor preview creation, confirmation, delivery or native execution. For
each case record the fixed Hub/build and Client APK identities, command and
instrumentation exits, `FAULT_READY` mode, returned status/code, and that the
same packet was recovered with no second Prepare. Redact operation IDs and
packet data as in the Client evidence policy. Do not report a Monitor business
success from any of these fault cases.

The offline Go fixture tests cover the three recovery responses and marker
guard; the proxy tests cover target-operation interception, forwarding and
concurrent requests. The fixed-image Docker recovery test currently uses
`status.snapshot`; neither those Go tests nor this procedure proves Monitor
Prepare business execution.

After recovery completes, stop the proxy and any Node agent started for setup,
then clean the exact fixture using its guarded teardown:

```bash
./scripts/client-group-key-fixture.sh stop "$FIXTURE_DIR"
```

Do not remove or recreate the Hub, its directory or DB before the `uncertain`
recovery call: startup recovery needs that same marked disposable DB. A Docker
restart can republish its random host port; only the proxy upstream changes.
Keep the same container ID, pinned image, database mount source and Hub
identity. Retain both proxy logs privately and verify the retargeted phase
emitted no second `FAULT_READY`; the proxy itself does not prevent a later
Prepare from matching. The existing stop command validates
fixture ownership and removes the Hub and its entire temporary directory,
including both markers.

## Recorded execution

On 2026-09-27, all three outer RPC recovery-ledger cases completed **PASS** on
fresh fixed-image Hubs and Android sessions: 12/12 JUnit selectors passed.
The [Client recovery-fault report](../../CICADA_CLIENT/docs/client-monitor-v13-recovery-faults.md)
contains exact evidence paths, artifact identities, exits, cleanup and the
retained failed first attempts. These results cover transport recovery and
packet retention only: the Prepare business handler, Monitor Confirm and
native delivery were not run. Model consumption, physical Android and public
HTTPS remain **NOT_RUN**.
