# Cicada development container

The 0.3.0 development image is a single reusable image with three Compose roles:

- `control`: a long-lived manager container;
- `worker`: an optional execution container, enabled with the `worker` profile;
- `telegram`: an optional inbound connector, enabled with the `telegram`
  profile.

The Control core is a static Go binary. The Client/API boundary is HTTP/JSON;
the future personal client can use TypeScript without coupling the control
plane to a UI runtime.

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

```bash
docker compose up -d control
docker compose --profile worker up -d worker
docker compose --profile telegram up -d telegram
docker compose exec control codex --version
docker compose exec control codex
```

The Control API listens on `127.0.0.1:8787` on the host:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/v1/machines
curl http://127.0.0.1:8787/v1/workers

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

When the API is exposed beyond localhost, set `CICADA_API_TOKEN` in the
runtime-only secret file. The server then requires `Authorization: Bearer
<token>` on every Control API route; `/` and `/healthz` remain available for
the embedded client bootstrap and health probes. The `cicada` CLI reads the
same environment variable automatically.

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

# Run a real two-thread, two-way Codex conversation (uses the relay).
./scripts/two-thread-demo.sh

# The demo's message primitive is also available directly:
curl -X POST http://127.0.0.1:8787/v1/threads/messages \
  -H 'content-type: application/json' \
  -d '{"from_worker_id":"WORKER_A","to_worker_id":"WORKER_B","message":"Please verify this result."}'

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

# Seal an opaque peer envelope for a pinned contact.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"contact_id":"CONTACT_ID","message":"evidence is ready","aad":"goal=GOAL_ID"}'

The post-quantum contact and envelope boundary is documented in
`docs/e2ee.md`; it uses ML-KEM-768, ML-DSA-65, HKDF-SHA256, and AES-256-GCM.

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

For direct Control-to-Control delivery, set `CICADA_PEER_RELAY_URL` to the
remote Control's `/v1/federation/messages` endpoint and set
`CICADA_PEER_RELAY_TOKEN` to its API token. Control routes by public identity,
so the two databases do not need matching Contact IDs. It retries queued
envelopes in the background; duplicate transport IDs return the original
plaintext-free receipt. A third-party relay can forward the same opaque JSON
contract without receiving message plaintext.
```

For the manual two-TUI workflow, open two terminals and start one interactive
Codex session in each:

```bash
# Terminal A
./scripts/open-codex-thread.sh manual-a

# Terminal B
./scripts/open-codex-thread.sh manual-b
```

The helper creates the workspace before starting Codex and uses
`CICADA_TEST_MODEL` (default `gpt-5.5`) for the test TUI. If you start Codex directly, create the directories first with
`docker compose exec -T control mkdir -p /workspace/manual-a /workspace/manual-b`,
then pass `--model gpt-5.5` to the Codex command. The packaged runtime
configuration and the Control app-server also use `gpt-5.5`.

In a normal shell, list the session UUIDs after both TUIs have started:

```bash
./scripts/list-codex-threads.sh
```

For durable Control auditing, register the two sessions and queue the message
through the official Codex command boundary:

```bash
docker compose exec -T control cicada thread register A_UUID Thread-A /workspace/manual-a
docker compose exec -T control cicada thread register B_UUID Thread-B /workspace/manual-b
docker compose exec -T control cicada thread queue A_UUID B_UUID 'Thread A says: compare the two hypotheses and reply.'
docker compose exec -T control cicada thread deliveries
```

This invokes `codex queue` without a shell and records the delivery status. The
full API contract and permission boundary are in [`docs/manual-threads.md`](docs/manual-threads.md).

Give each TUI the other UUID and explicitly ask it to send a message. For
example, in Thread A type:

```text
Use the official queue command to send this message to Thread B:
codex queue --thread B_UUID --message "Thread A says: compare the two hypotheses and reply with your conclusion."
Then wait for Thread B's reply.
```

If Thread A asks for approval to execute that shell command, approve it in the
A terminal. Thread B receives the queued turn in its own TUI. To send the reply
back, enter the analogous instruction in Thread B with `A_UUID`. This path is
manual and uses Codex's native `queue` command; the Control API thread-message
endpoint and `two-thread-demo.sh` provide the durable/audited automation path.

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

Development starts from `develop`; feature work uses a dedicated branch such
as `feat/core-objects` or `feat/permission-trust`. Keep `main` for reviewed
releases. The current local checkout has `origin` set to
`git@github.com:cicada-fabric/cicada.git`. The current release baseline is
`v0.2.0` on `release/0.2.0`; the current unreleased line is `0.3.0-dev` and
continues on feature branches. It is merged only after the checks below pass.

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
  -v "$PWD":/src -w /src golang:1.22-bookworm \
  bash -lc 'export PATH=/usr/local/go/bin:$PATH; go test -race ./...; go vet ./...'
```
