# Cicada development environment

The current unreleased version is `0.1.0-dev`; planned public product releases
use `0.1.x`. This does not change Architecture v2.3, Client wire v1, or the
frozen `client-hub-v1.3` contract. The root
[`docker-compose.yml`](docker-compose.yml) is a legacy single-host development
layout with three roles: `control`, an optional `worker` profile that currently
runs `sleep infinity`, and an optional Telegram connector. It does not describe
the Architecture v2 Node/Hub/Client deployment. For an isolated local Hub, use
[`./scripts/run-client-hub-dev.sh`](scripts/run-client-hub-dev.sh); for a
Fabric-only Hub run `cicada serve --fabric-only`, and run a v2 Node with
`cicada machine agent --relay-only` after owner-confirmed device-code binding.
The current architecture and evidence are in [CICADA.md](CICADA.md), the
[status matrix](docs/architecture-v2-status.md), and the
[Client↔Hub contract](docs/android-client-hub-contract.md).

The Control core is a static Go binary. The independent Android repository
connects through the versioned Client↔Hub HTTP/JSON and PQ packet contract;
this repository does not ship Android UI or local STT.

The two repositories follow the [joint development and acceptance workflow](docs/client-hub-development.md).
The operation catalog is authoritative for role allowlists; export a versioned
contract bundle with `python3 scripts/client-contract.py export --output .cicada-data/contracts`.
Published synthetic wire vectors must also be checked by the independent Kotlin
implementation before claiming cross-language compatibility.

## Monitor v1.3 and controlled native acceptance (2026-09-27)

The frozen `client-hub-v1.3` contract has four owner-guarded Monitor operations,
33 catalog operations and catalog SHA-256
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`. The clean
`25013b5` Hub candidate passed full Go/vet, focused race, contract/export and
exact-image disposable TCP gates. In the controlled Android/native run, one
read-only preview and one separate dispatch on the original Monitor Thread
were followed by receive/context assertions on both original recipient Threads.
Client's 10 selectors/final strict status, the Core scoped ciphertext scan,
Intake's read-only Hub audit and owned fixture/emulator cleanup all passed.
Exact identities, bounded claims and layer-specific evidence are in the
[candidate report](docs/client-hub-v13-25013b5-validation.md),
[native runbook](docs/client-monitor-native-fixture.md), [approval review](docs/monitor-broadcast-approval-review.md),
and [independent Client report](../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).

The run used two logical Nodes in one container. Full React Native consent UX,
physical Android/dual-Node operation and public HTTPS remain **NOT_RUN**;
unattended cold wake remains **UNSUPPORTED**. This is a bounded acceptance, not
a general prompt-injection defense. Earlier `81d8f1f` denials and `d76e630`/
`28bd462` failures are historical attempts, not the final candidate result.
Agent Network M1+ and Group Journal/Discussion remain proposed and unimplemented.
The older v1.2.1 Android PASS and idle-Hub measurements remain attributed to
their original source and image, as recorded in the [status matrix](docs/architecture-v2-status.md).

For Client protocol work, use the lightweight Hub path; it does not need a Codex
installation or model credentials:

```bash
python3 scripts/client-contract.py check
python3 -m unittest discover -s scripts -p test_client_contract.py
./scripts/test-client-hub-interop.sh
# For an ongoing Android developer session, keep a separate persistent Hub:
./scripts/run-client-hub-dev.sh
```

The disposable check never replaces the persistent developer Hub. Its sanitized
evidence goes to `CICADA_INTEROP_OUTPUT` when set. The image helper uses standard
proxy environment settings, or a reachable local port 7890; set
`CICADA_BUILD_PROXY=''` to force a direct build. The older full Codex/connector
setup below is only needed for its corresponding execution tests.

To measure core idle overhead, build from a clean checkout with
`scripts/build-hub-image.sh --image <unique-local-tag> --metadata-file <local-json>`,
then run `scripts/measure-idle-hub.sh --image sha256:<exact-local-image-id>`.
The measurement never pulls an image or uses a resident Hub: it allocates private
temporary state, caps the fresh Hub at 128 MiB/0.5 CPU, samples RSS and cgroup
usage, and removes its container/state. Results go to `.cicada-data/footprint/`.
They describe an empty idle Hub, not loaded capacity or Node/Codex/Android usage;
cgroup CPU includes sampling overhead. Remove only the unique test image tag
when finished. Do not run broad Docker prune commands on the shared host.

Architecture v2.1's temporary offline user-key bootstrap and its strict
non-routing boundary are documented in [docs/owner-approval-bootstrap.md](docs/owner-approval-bootstrap.md).
The Node-local Owner public-key trust procedure for explicit encrypted Links
is documented in [docs/node-owner-trust.md](docs/node-owner-trust.md). Sealed
peer paths support single-recipient `SEND/ASK/REPLY` over an explicit
cross-owner Link and same-owner, same-Group delivery across Nodes. On one Node,
same-Group sealed delivery uses the Node-local ledger and inbox without Hub
Relay message routing; authorization reads may still use Hub Guard and
Directory. Current MCP peer writes require sealed delivery; Sessions without that
capability fail closed. Historical plaintext remains readable under its existing
authorization. Legacy Monitor Federation body-write routes are retired. See the
current boundaries and test evidence in the
[status matrix](docs/architecture-v2-status.md).

For an offline backup of one Node, stop its Agent and use an explicit new
destination. `verify` checks every copied file and SQLite database. Restore
publishes only into a new or empty Node subtree and leaves the Agent blocked
by `recovery-pending.json` until the Hub binding, replay counters, pending
outbox and uncertain native injections are reconciled:

```bash
cicada machine backup --id NODE_ID --state-dir STATE_DIR --output NEW_BACKUP_DIR
cicada machine verify --backup NEW_BACKUP_DIR
cicada machine restore --backup NEW_BACKUP_DIR --state-dir NEW_STATE_DIR
cicada machine recovery inspect --backup NEW_BACKUP_DIR --state-dir NEW_STATE_DIR
```

`recovery inspect` takes the exclusive maintenance lock, re-verifies the backup,
checks the pending marker and restored file hashes/inventory, and opens known
SQLite files with immutable read-only connections for integrity and bounded
state counts. It does not start the Agent or contact the Hub, run migrations,
read message bodies or keys, or clear quarantine. Its output explicitly leaves
Hub binding/counter reconciliation and native-runtime consumption unchecked;
`agent_may_start` remains false. Missing/corrupt markers, files, or databases
fail closed. This inspection is evidence for an operator, not a reconciliation
or unquarantine procedure.

This covers only `STATE_DIR/nodes/node-<id>/`. Back up Codex native sessions
and any external MCP session/outbox state separately in the same maintenance
window. The Hub `migration backup` deliberately excludes `nodes/`; see the
[recovery limits](docs/architecture-v2-migration.md) before using a restored
Node.

The real Codex same-Node sealed Ask/Reply test passed with two native Threads;
its controlled Session binding and resume do not prove automatic MCP session
discovery or unattended wake. The opt-in real Codex cross-Node test passed with two isolated logical
Node state directories and real native Threads using `gpt-5.6-luna`. Both
logical Nodes ran on one Docker host; unattended wake and two physical
machines remain unverified. Same-Group broadcast passed a two-logical-Node fake-Codex full-chain;
it does not yet prove native broadcast delivery or user-authorized Monitor
broadcast. See the
[native validation record](docs/architecture-v2-native-validation.md).

The Docker daemon on this host is already configured with
`DockerRootDir=/gpu1-share/data/docker-root`, so image layers are stored below
`/gpu1-share/data`. The build helper also exports a portable image archive to
`/gpu1-share/data/cicada/images/`.

The build helper maps the container's `cicada` user to the current host UID and
GID so bind-mounted workspaces and state remain writable without root.

## First setup

Create the persistent directories and the runtime-only secret file. The key is
never copied into the image or the repository:

```bash
API_KEY='your relay key' ./scripts/bootstrap-cicada.sh
```

To create a Telegram-ready runtime file on first setup, also provide a bot
token and an independent connector secret:

```bash
API_KEY='your relay key' \
CICADA_TELEGRAM_BOT_TOKEN='123456:bot-token' \
CICADA_CONNECTOR_SECRET_TELEGRAM='random-hmac-secret' \
  ./scripts/bootstrap-cicada.sh
```

Build and export the image:

```bash
./scripts/build-image.sh
```

The image installs the official Codex CLI with:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
```

## Run

# Legacy Control/worker/Telegram Compose commands:
```bash
docker compose up -d control
docker compose --profile worker up -d worker
docker compose --profile telegram up -d telegram
docker compose exec control codex --version
docker compose exec control codex
```

For isolated Android Client development, start a fresh local Hub from the
current source with one command:

```bash
./scripts/run-client-hub-dev.sh
```

The helper builds the image with the local `127.0.0.1:7890` download proxy,
creates a private state directory under `.cicada-data/client-hub-dev`, and
binds the Hub to host loopback port 8787. Override `CICADA_BUILD_PROXY` or
`CICADA_CLIENT_HUB_PORT` when needed. This is a development bootstrap, not a
public HTTPS deployment. `GET /v2/client/capabilities` and
`GET /v2/client/identity` are publicly callable; device enrollment requires
a locally trusted owner key and its signed grant, and management RPC requires
the registered device's PQ key. The current capability status is `partial`;
see [the Client developer handoff](docs/client-hub-handoff.md),
[implementation prompt](docs/client-development-prompt.md),
[the exact Android contract](docs/android-client-hub-contract.md), and
[OpenAPI](docs/client-hub-v1.openapi.yaml). The separate Android repository
is not changed by this helper.

The Control API listens on `127.0.0.1:8787` on the host:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/v1/machines
curl http://127.0.0.1:8787/v1/workers

# Email and Calendar ingress use independent runtime-only connector secrets
# (`CICADA_CONNECTOR_SECRET_EMAIL` and `CICADA_CONNECTOR_SECRET_CALENDAR`) and
# sign the exact provider request bytes. See docs/information-connectors.md.

# Run a bounded non-Codex command worker by passing an explicit argv array.
curl -X POST http://127.0.0.1:8787/v1/goals \
  -H 'content-type: application/json' \
  -d '{"objective":"Print the build marker","harness":"shell","resources":{"argv":["/usr/bin/printf","SHELL_READY\\n"]}}'

# Register a remote execution machine, keep its profile alive, and execute the
# Codex or Shell Workers that Control assigns to it. The remote host needs the
# same workspace mount (or pre-provisioned contents) in this development line.
CICADA_MACHINE_ID=remote-1 CICADA_CONTROL_URL=http://127.0.0.1:8787 \
  cicada machine agent --interval 30s
```

When the legacy API is exposed beyond localhost, set `CICADA_API_TOKEN` in
the runtime-only secret file. Existing `/v1` management routes require
`Authorization: Bearer <token>`; the new `/v2/client` routes use their own
owner grant and encrypted device authentication, while `/`, `/healthz`,
Client capability and Hub public identity remain readable. The `cicada` CLI
reads the management bearer environment variable automatically. Place a
public Android ingress behind HTTPS and pin the Hub Control PQ identity via
an independent trust channel; the local helper does not supply public TLS.

Create a Goal and follow its event stream:

```bash
curl -X POST http://127.0.0.1:8787/v1/goals \
  -H 'content-type: application/json' \
  -d '{"objective":"Inspect this workspace and report its state"}'
curl http://127.0.0.1:8787/v1/goals/GOAL_ID/events

# Stream the same durable events as Server-Sent Events. `after` is the last
# numeric event ID already processed; reconnect with that offset.
curl -N http://127.0.0.1:8787/v1/goals/GOAL_ID/events/stream?after=0

# Receive an external information event. The connector secret stays in the
# runtime env; sign the exact JSON bytes with HMAC-SHA256.
printf '%s' '{"subject":"hello"}' | openssl dgst -sha256 -hmac "$CICADA_WEBHOOK_SECRET"
curl -X POST http://127.0.0.1:8787/v1/connectors/events \
  -H 'X-Cicada-Connector: mail' \
  -H 'X-Cicada-Event-ID: mail-1' \
  -H 'X-Cicada-Event-Type: message.created' \
  -H 'X-Cicada-Signature: sha256=HEX_DIGEST' \
  -H 'content-type: application/json' \
  -d '{"subject":"hello"}'
curl 'http://127.0.0.1:8787/v1/connectors/events?connector=mail'

# Record an explicit triage decision and optionally link the event to a Goal.
curl -X POST http://127.0.0.1:8787/v1/connectors/events/EVENT_ID/triage \
  -H 'content-type: application/json' \
  -d '{"status":"linked","goal_id":"GOAL_ID"}'

# External actions are opt-in by domain. An absent rule creates a P1 approval;
# destructive methods/capabilities always require approval. No credentials or
# request headers are accepted by Control.
GOAL_ID=goal_...
WORKER_ID=worker_...
curl -X POST http://127.0.0.1:8787/v1/permissions \
  -H 'content-type: application/json' \
  -d "{\"subject_type\":\"goal\",\"subject_id\":\"$GOAL_ID\",\"action\":\"external.fetch\",\"resource\":\"example.com\",\"effect\":\"allow\"}"
curl -X POST http://127.0.0.1:8787/v1/actions \
  -H 'content-type: application/json' \
  -d "{\"goal_id\":\"$GOAL_ID\",\"worker_id\":\"$WORKER_ID\",\"kind\":\"fetch\",\"url\":\"https://example.com\"}"

# If the action is pending approval, resolve it, then pass it to an isolated
# executor. The Control plane itself never performs arbitrary network access.
curl -X POST http://127.0.0.1:8787/v1/approvals/APPROVAL_ID \
  -H 'content-type: application/json' -d '{"decision":"approve"}'
curl -X POST http://127.0.0.1:8787/v1/actions/ACTION_ID/claim
curl -X POST http://127.0.0.1:8787/v1/actions/ACTION_ID/complete \
  -H 'content-type: application/json' -d '{"result":{"status":"ok"}}'

# Run the isolated browser action agent. Supply a concrete browser wrapper;
# Control never receives its cookies or login state. Use --once for one poll.
export CICADA_BROWSER_EXECUTOR_BIN=/opt/cicada/bin/browser-runner
export CICADA_BROWSER_PROFILE_DIR=/var/lib/cicada/browser-profile
cicada external agent --control-url http://127.0.0.1:8787 --once

# Create a monitor-only coordinator and attach a child Goal. The coordinator
# completes only after every child reaches a terminal state.
curl -X POST http://127.0.0.1:8787/v1/goals \
  -H 'content-type: application/json' \
  -d '{"objective":"Coordinate two independent checks","monitor_only":true,"budget":{"max_children":2}}'
curl -X POST http://127.0.0.1:8787/v1/goals \
  -H 'content-type: application/json' \
  -d '{"objective":"Run the first check","parent_goal_id":"PARENT_GOAL_ID"}'

# Queue a monitor correction for a running Goal.
curl -X POST http://127.0.0.1:8787/v1/goals/GOAL_ID/commands \
  -H 'content-type: application/json' \
  -d '{"command":"Re-check the result and continue with the latest constraint"}'

# Approval requests pause the Native Codex turn until a client resolves one.
curl http://127.0.0.1:8787/v1/approvals
curl -X POST http://127.0.0.1:8787/v1/approvals/APPROVAL_ID \
  -H 'content-type: application/json' \
  -d '{"decision":"approve"}'

# Native Thread collaboration uses explicit Cicada Join and authenticated
# Fabric v2 sessions. See docs/fabric.md for the end-to-end commands.

# Inspect the local post-quantum peer identity and pinned contacts.
curl http://127.0.0.1:8787/v1/identity
curl http://127.0.0.1:8787/v1/contacts

# Publish a signed identity announcement. A receiving Control verifies the
# ML-DSA signature and records a discovery request without trusting it.
curl -X POST http://127.0.0.1:8787/v1/identity/announcement \
  -H 'content-type: application/json' -d '{"label":"Alice"}' \
  > alice-announcement.json
jq -n --slurpfile announcement alice-announcement.json \
  '{announcement:$announcement[0]}' |
  curl -X POST http://REMOTE_CONTROL/v1/discovery/requests \
    -H 'content-type: application/json' --data-binary @-
curl 'http://REMOTE_CONTROL/v1/discovery/requests?status=pending'
curl -X POST http://REMOTE_CONTROL/v1/discovery/requests/REQUEST_ID/accept

The post-quantum contact and envelope boundary is documented in
`docs/e2ee.md`; historical Contact state is retained, but the old
`/v1/peer-messages` and `/v1/federation/messages` ingress is retired.

The inbound Telegram process, durable offset, normalized payload, and secret
boundary are documented in `docs/telegram-connector.md`.

The remote claim/result protocol, secret boundary, workspace requirement, and
failure semantics are documented in `docs/remote-execution.md`.

Workspace snapshot archives are content addressed and collected in the
background. Objects referenced by a Workspace or a snapshot Artifact are
retained; unreferenced objects are removed after the configurable grace period
(`CICADA_SNAPSHOT_GC_KEEP_SECONDS`, one day by default). A maintenance pass can
also be requested explicitly:

```bash
curl -X POST http://127.0.0.1:8787/v1/snapshots/gc
```

For an explicitly authorized cross-Control copy, fetch from the source CAS and
verify/store on the destination with the CLI. Both Controls should have their
API bearer tokens configured:

```bash
CICADA_SNAPSHOT_SOURCE_TOKEN="$SOURCE_TOKEN" \
CICADA_SNAPSHOT_DESTINATION_TOKEN="$DESTINATION_TOKEN" \
cicada snapshot replicate \
  --source-url https://source-control.example \
  --destination-url https://destination-control.example \
  --digest SHA256_HEX \
  --workspace-path /workspace/goal
```

The destination verifies the archive's SHA-256 digest before storing it and
attaches it to a Workspace only when the exact stable path exists. The
replication protocol never forwards plaintext workspace files through the
Control database; it transfers the already bounded deterministic archive.

Codex completion claims are checked by an ephemeral read-only `gpt-5.5`
verifier. Shell evidence stays local unless a Goal opts into model verification.
The verdict policy and failure behavior are documented in
`docs/completion-verification.md`.

For machines without a shared workspace mount, a Goal may declare
`resources.workspace_source` with a credential-free HTTPS Git URL and revision.
See `docs/workspace-provisioning.md` for the provenance and security contract.

Remote agents persist modified workspaces through the authenticated snapshot
endpoints. Archives are deterministic tar streams capped at 256 MiB and are
addressed by SHA-256; recovery jobs download the digest before starting the
harness. The Control CAS lives in `$CICADA_STATE_DIR/workspace-snapshots`.

For peer collaboration, join the intended native Codex Threads explicitly through
the Cicada MCP tools, then use `cicada_find`, `cicada_ask`, and
`cicada_reply` in the selected Group. The current command and authorization
contract is in [`docs/fabric.md`](docs/fabric.md). The old Control-to-Control
peer ingress and manual `cicada thread queue` interface have been removed;
their historical database rows remain available for migration.

Verify Docker storage, both containers, the official CLI installation, and the
effective relay configuration without exposing the API key:

```bash
./scripts/smoke-test.sh
```

Set `CICADA_SMOKE_INFERENCE=1` to include a real `gpt-5.5` request through the
relay. The normal smoke test checks authenticated endpoint reachability but
does not create a model response.

The shared directories are under `/gpu1-share/data/cicada/`:

```text
state/       persistent Codex state and future Cicada state
workspaces/  worker workspaces
logs/        Codex and Cicada logs
secrets/     mode-0600 runtime environment file
images/      exported image tarball and checksum
vendor/      optional upstream source checkouts
```

Codex reads `docker/codex-config.toml`. It selects model `gpt-5.5`, the
`basil` provider, and `https://basil.xin/v1`; the provider reads the API key
from the runtime-only `API_KEY` variable.

The reviewed Happy source checkout and reuse boundaries are recorded in
`docs/upstream-happy.md`.

The implementation language decision and the reasons for the Go core plus
TypeScript client split are recorded in `docs/language-decision.md`.

Development takes place on `dev`, as requested by the user. Review and verify
bounded milestones there; `main` remains a README-only unreleased placeholder
until a public release (see [Git history](docs/git-history.md)). Do not create a
permanent branch for each subtask. Pushing, releasing, and replacing resident
deployments are separate actions from running local tests. The current checkout
has `origin` set to `git@github.com:cicada-fabric/cicada.git`. The retired
`v0.2.0` tag was a historical prototype checkpoint; the current unreleased
product line is `0.1.0-dev` and planned public releases use `v0.1.x`. This does not change the
architecture or protocol versions. Changes land only after the checks
below pass.

The Go checks cover the durable store and the Control's process-level
recovery, monitor correction, and approval pause/resume paths:

```bash
cd cicada-go
go test -race ./...
go vet ./...
```

If Go is not installed on the host, run the same checks in the pinned builder
image used by the Dockerfile:

```bash
docker run --rm --network host \
  -e HTTP_PROXY -e HTTPS_PROXY -e ALL_PROXY \
  -v "$PWD":/src -w /src golang:1.27.1-bookworm \
  bash -lc 'export PATH=/usr/local/go/bin:$PATH && go test -race ./... && go vet ./...'
```
