# Bounded Hub Nodes mode and the first Ubuntu Node

This delivery uses the existing ACTIVE Owner, account, App vault/device keys and
Hub identities. Its contract is [app-node-authority-v1](hub-app-node-authority-contract.md).
Account login does not confer Root or Node authority. Validation and remaining
platform limits are recorded [separately](hub-app-node-authority-validation.md).
These commands describe operator-reviewed startup; creating this guide does not
replace a resident service or authorize deployment.

## Hub startup

Use the retained Hub StateDir, including its database and all three existing
private files: Peer `e2ee/identity.json` (or the explicit existing Peer override),
`e2ee/client-control-identity.json` and `e2ee/node-control-identity.json`.
The new composition reads private regular mode-0600 files, refuses missing or
invalid identities and generates no replacements. Schema 63 adds authority
history while preserving existing account, Owner, public keys and replay state.

After the deployment owner has reviewed the binary/source and stopped its old
writer through the established operator procedure:

```sh
cicada serve --hub-nodes-only \
  --state-dir RETAINED_HUB_STATE \
  --host 127.0.0.1 --port 8787
```

Retain the existing trusted public HTTPS origin and reverse-proxy routing.
`--hub-nodes-only` is mutually exclusive with `--hub-only`, `--fabric-only`
and an enrolled strict Node PQ listener configuration. It does not initialize a
CA or downgrade configured strict PQ TLS. This bounded slice uses standard
trusted HTTPS plus application PQ proofs/envelopes; it does not claim strict PQ
TLS acceptance. Existing strict deployments keep their reviewed workflow.

The mode composes Store, hubowner, hubauth, the existing Node proof/binding
implementation and Fabric Node data-plane handlers. It never creates or starts
Control, registers local Machines, recovers Control intents, or starts a
planner, scheduler, Worker or Runtime. Old management/business APIs remain
unavailable. Health and existing identity response shapes are unchanged.

Public discovery is GET `/v2/owner/app-node/capabilities`, bounded to 8 KiB.
Only this mode advertises N3 availability. The App must validate that metadata
before its first N3 secret POST/pending write. A legacy Hub or another mode is
unsupported; it is not a reason to export identities, request a new Root code
or fall back to broader permissions.

## Ubuntu Node delivery

The first target is Ubuntu 24.04.3 x86_64, ordinary user `zyf` (uid 1000).
Use the reviewed standalone `linux/amd64` executable and its separately supplied
SHA-256/build provenance. The target needs no Go toolchain. ARM64 delivery is a
separate scope. Installing Codex or discovering an existing Codex 0.163.0 does
not establish Runtime consumption; this slice starts no model work.

Run as the ordinary user with one stable Node ID and private retained StateDir.
For a first installation only, copy the reviewed executable into a user-owned
binary directory. The placeholders below are delivery values, not credentials:

```sh
CicadaNodeRoot="${CicadaNodeRoot:-$HOME/Cicada/node}"
install -d -m 0700 "$CicadaNodeRoot" "$CicadaNodeRoot/state"
install -d -m 0755 "$CicadaNodeRoot/bin"
install -m 0755 /path/to/reviewed/cicada-linux-amd64 "$CicadaNodeRoot/bin/cicada"

"$CicadaNodeRoot/bin/cicada" machine agent --relay-only \
  --id STABLE_NODE_ID --name 'Ubuntu relay Node' \
  --state-dir "$CicadaNodeRoot/state" \
  --control-url 'https://REVIEWED_HUB_ORIGIN'
```

Use the same StateDir/ID on restart. Do not copy App/Owner private keys, Hub
StateDir, synthetic fixtures or another Node's identity into it. An existing
identity, credential, epoch or pending packet is retained and recovered; deleting
state to bypass proof is not an installation step. Run one Agent writer for that
state. No root login, SSH access from Hub, inbound Node port, global Manager
bearer, local build or inference service is required for this outbound path.

The Agent generates and retains its own first Node identity/credential locally,
proves the exact Node and current Hub Node-Control keys, and displays a finite
`Device code:`. The relay-only message directs the user to Cicada App. The
legacy protocol `VerificationURI` remains unchanged and is still validated;
this new mode does not ask the user to visit the absent browser approval page.

If the Agent stops before learning an approval completed while it was offline,
restart it with the same ID and StateDir. It recovers the exact retained INITIAL
candidate and original key, installs the durable approval and then continues
relay polling. An expired enrollment code does not erase a completed approval;
an unconfirmed code still needs explicit Owner approval within its deadline.

For this fresh Node, keep Cicada's binary, state and optional service source
together under that one configurable absolute base. Existing Hub/App paths and
existing Node identities are retained; this guide installs no path migration.

## Explicit App approval and recovery

Open the existing App profile/vault and log into the same account with its
already-proved ACTIVE Owner. Enter the Node's Device code. Review both full Node
and Hub Node-Control key IDs/fingerprints against the Node display. The code is
only a selector: Hub returns the exact persisted pending candidate and full keys.
The existing local Owner signs preview intent, then the user's explicit approval
signs the exact candidate, scope, grant/head and immutable deadlines.

Grant completion alone does not confirm the Node. The App then sends the one
allowed `nodes.confirm` under that exact grant instance. The durable Node effect,
budget, Client counters and sealed receipt commit together. App authority lasts
exactly prepare + fifteen minutes, bounded also by its exact account session.
The signed status read is for that Node only. There is no Root enrollment,
automatic renewal, broad management, Worker/Goal permission or identity export.

A confirmed binding initially has UNKNOWN liveness. The Agent's accepted empty
relay heartbeat produces CONNECTED for 120 seconds, then STALE without a newer
heartbeat. Future/pre-approval/malformed heartbeat data stays UNKNOWN. Worker
`machines.status` may remain offline; it is not changed to make a Node look
connected. CONNECTED does not prove an open SSE stream, Runtime readiness or
model consumption. The Agent reuses the existing authenticated heartbeat/SSE
data-plane paths and the narrow `node.binding.status` PQ RPC.

Keep original pending bytes when a response is lost. Retry the exact bytes or
use authenticated reconciliation. ABSENT and a matching Node name/ID cannot
settle an uncertain mutation. A successful historical receipt or permanent
original-route rejection fence closes that mutation; a late original cannot
execute afterward. An uncached read closes only through READ_EXPIRED. No recovery
hint resets or skips counters.

After lease/session expiry or explicit self-cancel, an already-confirmed Node
can receive a new explicitly approved READ_EXISTING status grant for the same
unchanged binding. It has no confirmation budget and cannot pair another Node.
Security revocation or changed keys/epochs/binding fail closed. A terminal,
unconfirmed first attempt may instead start a fresh explicit INITIAL by
re-entering a valid code once every original packet is settled and neither side has successful
confirmation provenance. Self-cancelling App access leaves a confirmed Node
binding intact; Node revocation requires its separately authorized workflow.

That may be the same still-valid PENDING code/candidate. It always requires a
new Owner consent/grant/head; an old packet cannot borrow the new authority.

Real Ubuntu user-process startup, native Windows UI/vault behavior, public HTTPS,
strict PQ TLS and actual Runtime results must each be recorded separately. A
Linux protocol fixture or cross-build is not acceptance for those environments.

## Optional user service after foreground approval

First complete foreground binding and confirm the same Node in the App. Stop
that foreground Agent before starting its user service; both use the same
ordinary `zyf` user, Node ID, binary and private StateDir. This optional template
has not been executed on the physical Ubuntu target by this checkpoint.

The unit's physical source stays inside NodeRoot. The OS user-service registry
may hold its normal registration symlink. Substitute the same reviewed Node ID
and HTTPS origin before running these operator commands:

```sh
CicadaNodeRoot="${CicadaNodeRoot:-$HOME/Cicada/node}"
install -d -m 0700 "$CicadaNodeRoot/systemd"
cat > "$CicadaNodeRoot/systemd/cicada-node.service" <<EOF
[Unit]
Description=Cicada relay Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="$CicadaNodeRoot/bin/cicada" machine agent --relay-only --id STABLE_NODE_ID --name "Ubuntu relay Node" --state-dir "$CicadaNodeRoot/state" --control-url https://REVIEWED_HUB_ORIGIN
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=default.target
EOF
systemctl --user link "$CicadaNodeRoot/systemd/cicada-node.service"
systemctl --user daemon-reload
systemctl --user enable --now cicada-node.service
```

No `User=root` or new service account is used. For continued operation after
all `zyf` login sessions end, the target's operator must enable user lingering
under its existing login policy, for example `loginctl enable-linger zyf` when
authorized. `loginctl show-user zyf -p Linger` reports the current setting.
Without lingering, survival depends on the lifetime of that user's manager.
This task changes no login policy and installs/starts no real unit.

Use `systemctl --user stop cicada-node.service` before a later foreground run
or maintenance. Do not erase state, change the stable ID or disable an existing
strict PQ profile to make another mode start.
