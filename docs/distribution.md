# Distribution and deployment

Cicada is distributed as four cooperating pieces. The split keeps the Control
plane durable and easy to expose while keeping execution machines private:

| Piece | Installed where | Purpose |
| --- | --- | --- |
| `cicada` static binary | Control and worker hosts | HTTP Control, CLI, machine agent, and harness dispatch |
| OCI image and Compose file | A Control host (and optional connector host) | Reproducible server packaging with persistent volumes |
| Codex plugin package | Each operator's Codex environment | Natural-language shortcuts that call an already configured Control |
| Embedded web client/PWA | Served by Control; installed in a browser | Desktop panel and phone browser client |

The native iOS/Android application is the one intentionally deferred client.
The PWA remains usable on phones without a native package.

## Choose a topology

### One computer

Use this for evaluation or a personal laptop. Run Control and a local Worker
with the same binary and state root. The browser opens the local panel.

```bash
export CICADA_MODEL_API_KEY_FILE=/path/to/cicada-model-key
CICADA_SOURCE_DIR="$PWD" ./scripts/install-cicada-server.sh
sudo env \
  CICADA_SOURCE_DIR="$PWD" \
  CICADA_CONTROL_URL=http://127.0.0.1:8787 \
  CICADA_API_TOKEN_FILE=/var/lib/cicada/secrets/control.token \
  CICADA_MODEL_API_KEY_FILE="$CICADA_MODEL_API_KEY_FILE" \
  CICADA_MACHINE_ID=local \
  CICADA_WORKSPACE_ROOT=/var/lib/cicada/workspaces/local \
  bash ./scripts/install-cicada-worker.sh
```

The server installer does not print the API key or bearer token. It creates a
worker-ready bearer token at `/var/lib/cicada/secrets/control.token` and keeps
the model credential in the Compose-only `cicada.env` file. The worker command
installs the host binary and starts its systemd agent when available. For a
source checkout with a non-default data directory, pass the same
`CICADA_DATA_ROOT` to both installers. Create the file named by
`CICADA_MODEL_API_KEY_FILE` through the operator's secret store before running
these commands.

### A server plus private worker machines

This is the normal deployment. The server runs only `control`; every worker
has the static binary, the official Codex CLI when Codex jobs are wanted, its
own model/OAuth credentials, and a workspace root. Workers make outbound HTTPS
requests to Control and do not need an inbound firewall rule.

On the server:

```bash
sudo env CICADA_MODEL_API_KEY_FILE=/run/secrets/cicada-model-key \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/cicada-fabric/cicada/main/scripts/install-cicada-server.sh | bash'
```

The file named by `CICADA_MODEL_API_KEY_FILE` must already exist on the server,
be readable by the installer, and contain only the model credential. For a
remote install, the installer downloads the pinned `CICADA_REF` archive and
does not require a local checkout.

Copy the Control bearer token to a protected file on each worker (for example
`/etc/cicada/control.token`) through the operator's secret-management system.
Do not put the token in a shell history or a Goal prompt. Then install a
worker; the script builds the current pinned source when no release binary is
provided, or verifies a release asset when `CICADA_BINARY_URL` is set:

```bash
curl -fsSL https://raw.githubusercontent.com/cicada-fabric/cicada/main/scripts/install-cicada-worker.sh \
  | sudo -E env \
      CICADA_CONTROL_URL=https://control.example \
      CICADA_API_TOKEN_FILE=/etc/cicada/control.token \
      CICADA_MACHINE_ID=$(hostname -s) \
      CICADA_WORKSPACE_ROOT=/var/lib/cicada/workspaces \
      bash
```

The worker installer writes a mode-0600 systemd environment file and starts
`cicada-worker.service` when systemd is present. Set `CICADA_RUN_USER` to a
dedicated account if the worker should not run as the invoking user. Install
and authenticate the official Codex CLI for that account separately; Cicada
does not copy a Codex login or model credential between machines.

For air-gapped or release-only hosts, use a published static binary and a
checksum instead of compiling:

```bash
sudo env CICADA_BINARY_URL=https://github.com/cicada-fabric/cicada/releases/download/v0.3.0/cicada-linux-amd64 \
  CICADA_BINARY_SHA256=CHECKSUM \
  CICADA_CONTROL_URL=https://control.example \
  CICADA_API_TOKEN_FILE=/etc/cicada/control.token \
  bash ./scripts/install-cicada-worker.sh
```

Release binaries are produced by `scripts/build-release.sh` and published by
the tag workflow in `.github/workflows/release.yml`. A worker can therefore be
installed without Go by supplying `CICADA_VERSION` (for example,
`CICADA_VERSION=0.3.0`) or an explicit, checksum-pinned `CICADA_BINARY_URL`.

### Multiple people or multiple Controls

Each Control owns its SQLite state and its local identity. Link Controls only
through the signed directory/contact flow. Discovery is not trust: the
operator reviews a request, accepts it, and explicitly marks the Contact
trusted before encrypted peer messages are delivered. A relay carries opaque
envelopes; it does not receive plaintext or private keys.

### Development and CI

Use the repository Compose file and the `worker` profile for image-level
checks. The profile's `sleep infinity` process is a container shell for
inspection; production remote execution uses the host `cicada machine agent`
service or a purpose-built supervisor. `scripts/smoke-test.sh` checks the
Control health, auth boundary, PWA shell, and core API contract.

## Control installation and panel access

The server installer performs these steps in order:

1. obtain a pinned repository archive (or use `CICADA_SOURCE_DIR`);
2. create the private state, workspace, log, image, and secret directories;
3. preserve an existing secret file, or generate a random bearer token;
4. write Compose interpolation values without putting secrets in `.env`;
5. build and start only `control`; and
6. wait for `/healthz` before printing the panel and tunnel commands.

The Compose default binds Control to `127.0.0.1`, which is safe for a server
behind SSH. From an operator computer:

```bash
ssh -N -L 8787:127.0.0.1:8787 user@control-server
```

Open `http://127.0.0.1:8787/`, choose **Remote access**, paste the bearer token
for that tab, and select **Use for this tab**. For shared access, put an HTTPS
reverse proxy in front of the Control port, keep the bearer token requirement,
and use the HTTPS URL as the PWA origin. The installer deliberately does not
invent certificates or expose an unauthenticated public port.

On a phone, open that HTTPS URL in Safari/Chrome and choose **Add to Home
Screen** or **Install app**. The service worker caches only the static shell;
API responses, attachments, tokens, and private events stay out of the cache.

## How threads and machines connect

The stable path is:

```text
Codex plugin or browser
        │ HTTPS + bearer token
        ▼
Control (SQLite, scheduler, monitor, event stream, PWA)
        │ outbound HTTPS polling
        ▼
Machine agent ── official Codex / Claude / OpenCode / Happy / Shell / Browser
        │
        └── private workspace + bounded result/snapshot
```

The agent registers a non-secret capability profile, heartbeats, polls its
assigned jobs, claims one atomically, executes inside its workspace, uploads a
bounded snapshot, and reports the result. A stale machine is marked offline
and its Worker is requeued; the next machine restores the snapshot before
continuing.

Threads are logical durable sessions, not network sockets. A Codex session can
register itself and queue a message:

```bash
cicada thread register THREAD_ID 'laptop Codex'
cicada thread queue FROM_THREAD_ID TO_THREAD_ID 'share the benchmark result'
cicada thread deliveries
```

Goals own the monitor/worker graph, so separate threads on the same or
different machines communicate through Control's durable queue and event
stream. Cross-user communication uses the Contact/E2EE path and federation;
machines never need to open direct ports to one another.

## Codex plugin distribution

The repository contains a portable `cicada` plugin under
`.agents/plugins/cicada` and a repo marketplace under
`.agents/plugins/marketplace.json`. Install that package in Codex (or publish
the same package to the public plugin directory) and configure:

```text
CICADA_API_URL=https://control.example
CICADA_API_TOKEN=<read from the operator's secret store>
```

The plugin supplies the Cicada workflow and CLI examples. It does not install
Docker, create a server, or silently grant network access. Networking starts
only after a reachable Control URL and an authorized token are configured.
The current package has no bundled MCP endpoint because Cicada's stable
interface is its authenticated HTTP API and `cicada` CLI; a future hosted MCP
adapter can be added without changing the Control/worker protocol.

## First end-to-end run

1. Install Control with `install-cicada-server.sh` and record the private token
   file path.
2. Install one worker with `install-cicada-worker.sh`, a token file, and a
   workspace root; verify it appears in `cicada machine list`.
3. Configure `CICADA_API_URL` and `CICADA_API_TOKEN` for the Codex plugin, or
   use the CLI directly.
4. Create a Goal. Control schedules a monitor and Worker to a capable machine;
   the worker's logical thread and result remain durable across reconnects.
5. Open the panel through the SSH tunnel or HTTPS reverse proxy. Approvals,
   notifications, artifacts, raw bounded output, and Goal detail are all
   available there.
6. For a second person, exchange signed announcements, review and trust the
   Contact, then configure the federation/relay URL. Only trusted Contacts can
   send encrypted peer messages.

This flow covers the desktop client, phone browser/PWA, Control, remote
workers, Codex plugin, machine discovery, thread queues, recovery, and secure
peer boundaries. A native mobile binary remains outside this release line.
