# Cicada development container

The MVP development image is a single reusable image with two Compose roles:

- `control`: a long-lived manager container;
- `worker`: an optional execution container, enabled with the `worker` profile.

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
docker compose exec control codex --version
docker compose exec control codex
```

The Control API listens on `127.0.0.1:8787` on the host:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/v1/machines
curl http://127.0.0.1:8787/v1/workers
```

Create a Goal and follow its event stream:

```bash
curl -X POST http://127.0.0.1:8787/v1/goals \
  -H 'content-type: application/json' \
  -d '{"objective":"Inspect this workspace and report its state"}'
curl http://127.0.0.1:8787/v1/goals/GOAL_ID/events

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

# Seal an opaque peer envelope for a pinned contact.
curl -X POST http://127.0.0.1:8787/v1/peer-messages \
  -H 'content-type: application/json' \
  -d '{"contact_id":"CONTACT_ID","message":"evidence is ready","aad":"goal=GOAL_ID"}'

The post-quantum contact and envelope boundary is documented in
`docs/e2ee.md`; it uses ML-KEM-768, ML-DSA-65, HKDF-SHA256, and AES-256-GCM.
```

For the manual two-TUI workflow, open two terminals and start one interactive
Codex session in each:

```bash
# Terminal A
./scripts/open-codex-thread.sh manual-a

# Terminal B
./scripts/open-codex-thread.sh manual-b
```

The helper creates the workspace before starting Codex and pins the TUI to
`gpt-5.4`. If you start Codex directly, create the directories first with
`docker compose exec -T control mkdir -p /workspace/manual-a /workspace/manual-b`,
then pass `--model gpt-5.4` to the Codex command.

In a normal shell, list the session UUIDs after both TUIs have started:

```bash
./scripts/list-codex-threads.sh
```

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

Set `CICADA_SMOKE_INFERENCE=1` to include a real `gpt-5.4` request through the
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

Codex reads `docker/codex-config.toml`. It selects model `gpt-5.4`, the
`basil` provider, and `https://basil.xin/v1`; the provider reads the API key
from the runtime-only `API_KEY` variable.

The reviewed Happy source checkout and reuse boundaries are recorded in
`docs/upstream-happy.md`.

The implementation language decision and the reasons for the Go core plus
TypeScript client split are recorded in `docs/language-decision.md`.

Development starts from `develop`; feature work uses a dedicated branch such
as `feat/core-objects` or `feat/pq-e2ee`. Keep `main` for reviewed releases.
The current local checkout has `origin` set to
`git@github.com:cicada-fabric/cicada.git`; the MVP baseline is on
`feat/go-control-mvp`, thread messaging is on `feat/thread-messaging`, the
post-quantum envelope is on `feat/pq-e2ee`, and the core object work is on the
current feature branch.

The Go checks cover the durable store and the Control's process-level
recovery, monitor correction, and approval pause/resume paths:

```bash
cd cicada-go
go test -race ./...
go vet ./...

If Go is not installed on the host, run the same checks in the pinned builder
image used by the Dockerfile:

```bash
docker run --rm --network host \
  -e HTTP_PROXY -e HTTPS_PROXY -e ALL_PROXY \
  -v "$PWD":/src -w /src golang:1.22-bookworm \
  bash -lc 'export PATH=/usr/local/go/bin:$PATH; go test -race ./...; go vet ./...'
```
```
