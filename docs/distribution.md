# Distribution and deployment

This document separates the **v2.1 target topology** from the installers and
APIs that are runnable in the current worktree. Sealed-capable same-Group and
explicit Link traffic uses endpoint-held post-quantum message encryption;
legacy unsealed Fabric traffic can still be plaintext at Hub. Nested Groups,
same-Node local delivery, multi-Group membership, and Node device-code binding
have implementations, but multi-Group native validation and public PQ-only
transport acceptance remain open. The historical Contact flow decrypted inside
Control. Do not expose legacy peer APIs as a blind, cross-user Hub.

Cicada is distributed as four cooperating pieces. The split keeps the Control
plane durable and easy to expose while keeping execution machines private:

| Piece | Installed where | Purpose |
| --- | --- | --- |
| `cicada` static binary | Hub and Node hosts | Hub Control/Directory/Relay, Node agent, CLI, and native dispatch |
| OCI image and Compose file | A Hub host (and optional connector host) | Reproducible packaging with persistent volumes |
| Codex plugin package | Each operator's Codex environment | Natural-language shortcuts that call an already configured Control |
| Embedded web client/PWA | Served by the Hub; installed in a browser | Existing legacy management panel; the nested Group/Thread/link editor is a target |
| Separate Android Client v1 | User's phone; independent repository | Planned mobile entry for status, voice/text Control requests and authorized topology operations; remote use gated on Client↔Control NIST PQ E2EE |

Android is the only native Client in the first product version. iOS and other
native platforms are later possibilities. The existing PWA remains usable in
its legacy scope, but does not meet the Android↔Hub NIST PQ E2EE requirement.

## Target routing and trust boundary

**Cicada Hub** names the one publicly reachable server on which Control,
Directory, Relay, authorization, persistent state, and the panel may run.
These remain separate logical services. A Node opens an outbound persistent
HTTPS connection to the selected Hub; the Hub sends content-free wake hints
over that connection and the Node claims durable deliveries. Neither two Nodes
nor the Hub and a Node need an inbound path to the Node.

| Communication | Target data path | Center Relay count |
| --- | --- | --- |
| Two joined Threads on one Node | Sender MCP/local adapter → exact native `codex queue --thread` → receiver | 0 |
| Threads on two Nodes, one user | Node A → their shared Hub Relay → Node B | 1 |
| Threads owned by different users | Both Nodes enroll with one mutually selected Hub; same single-Relay path | 1 |

An individual can have several Groups, nested Groups, and a single native
Thread joined to several Groups. The panel shows one stable Thread with several
membership edges and explicit Endpoint communication links. A Group need not
have a Monitor. A Thread may broadcast within one selected Group if permitted;
a user may authorize a Monitor to compose/send that Group broadcast. Broadcast
recipient fan-out still obeys the per-recipient 0/1 Relay rule. Parent/child
Groups and Contact relationships do not grant access by themselves.

For two people with separate home Hubs, both Nodes must additionally connect
to the **same chosen Hub** for that link. Hub-to-Hub forwarding would introduce
a second Relay and is outside this topology. If no common Hub or direct route
is reachable, the system must report no route. The chosen Hub must not hold
peer decryption keys; Node/Endpoint adapters encrypt before transport and only
the authorized recipient decrypts. Sealed-capable routes implement this
application-message boundary; legacy unsealed routes do not. TLS alone does
not make a TLS-terminating Hub blind.

The Node device-code flow returns a Hub-specific verification path and a
short-lived code. A separately enrolled owner Client previews and confirms
the Node binding through encrypted RPC. The separate Android Client supplies
the verification UI; the legacy installer below still uses a protected
Control bearer token. External users need their own verified identity and
two-sided Link approval, not possession of the Node enrollment code.

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

This is the currently runnable installer path. The server process exposes
Control and Fabric routes on one HTTP origin; every worker has the static
binary, the official Codex CLI when Codex jobs are wanted, its own model/OAuth
credentials, and a workspace root. Workers make outbound HTTPS requests and
do not need an inbound firewall rule. It is not yet the device-code/PQ-encrypted
Hub deployment described above.

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

### Multiple people

The target is one selected Hub for a specific approved cross-user link. Each
person retains their own identity and must approve the visible Endpoint,
direction, scope, and expiry. Nodes owned by both people initiate outbound
connections to that Hub. One person's existing Home Hub does not forward the
message to another Home Hub. The current Contact flow is separate and its
Control API can see plaintext before encryption or after decryption; it does
not prove the target blind-Hub, native Thread-to-Thread path.

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

The Compose default binds Control to `127.0.0.1`. For a local development
panel, an operator may use an SSH tunnel; SSH is not the peer data-plane
transport and is not required by the target Hub topology. From an operator
computer:

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

The **current** installed path is:

```text
Codex plugin or browser ── HTTPS + bearer token ── Hub HTTP origin
                                            ├─ Control management + PWA
                                            ├─ Fabric Directory/Relay + SQLite
                                            └─ Node-initiated persistent event stream
Node agent ── outbound claim/receipt ── exact native Codex queue
```

The agent registers a non-secret capability profile, heartbeats, polls its
assigned jobs, claims one atomically, executes inside its workspace, uploads a
bounded snapshot, and reports the result. A stale machine is marked offline
and its Worker is requeued; the next machine restores the snapshot before
continuing.

Threads are native harness sessions wrapped by stable Fabric Endpoints. A
plugin installation or a running MCP server does not join a session. From a
normal Codex TUI, explicitly choose the target Group and invoke the plugin's
`cicada_join` tool. The equivalent operator fallback is:

```bash
cicada fabric v2 join --group grp_kernel --name planner \
  --session-token-file /run/user/1000/cicada/session.json
cicada fabric v2 members
```

This CLI join is for operator enrollment/discovery and does not install the
Node-local sealed delivery bridge. For peer Ask/Reply, Join from the native
Codex Thread with `cicada_join`, then use `cicada_ask`/`cicada_reply` through
MCP. The old CLI `send|ask|reply` and Hub plaintext POST routes are retired;
`fabric v2 receive` remains a read-only view of authorized historical rows.

The v2 join call uses the management bearer only for enrollment. Set
`CICADA_SESSION_TOKEN_FILE` or pass `--session-token-file` when the CLI should
persist the short-lived `CicadaSession` credential; it has no ambient default
credential file. Later peer commands authenticate with that origin-scoped
credential and derive the caller, Group, and membership from the server-side
binding. The old `endpoint`/v1 records remain available for migration; they do
not bypass v2 authorization.

For a destination on another machine, that machine's agent atomically claims
the Fabric delivery and invokes the official `codex queue --thread` command
against the exact native session. A correlated reply is queued to the original
session; if that Codex thread is unloaded, this alone may not start a turn.
The new Node-initiated event stream sends immediate, body-free wake
hints after durable Relay acceptance; reconnection and periodic reconciliation
cover missed hints. See [Fabric membership and Agent RPC](fabric.md). Current
cross-Group messages still use the old representative policy; direct authorized
links, local zero-Relay routing, blind PQ-encrypted Hub, and user-to-user native
Thread delivery remain migration work.

## Codex plugin distribution

The repository contains a portable `cicada` plugin under
`.agents/plugins/cicada` and a repo marketplace under
`.agents/plugins/marketplace.json`. Install that package in Codex (or publish
the same package to the public plugin directory):

```bash
codex plugin marketplace add cicada-fabric/cicada --ref main
codex plugin add cicada@cicada-repo
```

Then configure:

```text
CICADA_API_URL=https://control.example
CICADA_API_TOKEN_FILE=$HOME/.config/cicada/control.token
CICADA_MACHINE_ID=$(hostname -s)
```

The plugin supplies the Cicada workflow and a bundled local `cicada mcp` stdio
server. Its tools can explicitly join a harness-verified native session after
a Group is selected, query the Group-scoped Endpoint Directory, resolve
addresses, and perform `send` or correlated `ask/reply` without making the
model construct CLI commands. If the runtime does not provide a trusted
session ID, the join fails closed; one static session ID must never be reused
across threads. The plugin does not install Docker, create a server, or
silently grant network access. Networking starts only after the `cicada`
binary, a reachable Control URL, an authorized management token, and an
explicit join are available.

## First end-to-end run

1. Install Control with `install-cicada-server.sh` and record the private token
   file path.
2. Install one worker with `install-cicada-worker.sh`, a token file, and a
   workspace root; verify it appears in `cicada machine list`.
3. Configure `CICADA_API_URL`, `CICADA_API_TOKEN_FILE`, and the same
   `CICADA_MACHINE_ID` used by the local machine agent; open a normal Codex
   TUI, choose a Group, and say `@cicada join`.
4. Join a second Codex session on another Machine, then use `cicada_ask` from
   the first. Verify the target native session wakes, replies with the returned
   `request_id`, and the original session resumes.
5. Create a Goal. Control schedules a monitor and Worker to a capable machine;
   the worker's logical thread and result remain durable across reconnects.
6. Open the panel through the SSH tunnel or HTTPS reverse proxy. Live Fabric
   Network Cards, approvals, notifications, artifacts, raw bounded output, and
   Goal detail are available there.
7. Cross-user native Thread networking is not available yet. The retired
   Contact peer ingress is not a supported substitute for Endpoint links.

This current flow covers the desktop management browser, Control,
remote workers, Codex plugin, machine discovery, v2 Fabric sessions, and recovery.
It does not yet meet the target multi-Group graph, one-Relay cross-user
networking, or Hub-blind peer encryption. The separate Android v1 Client is
the next target and must not reuse the legacy bearer channel for sensitive
mobile management. See [Android Client ↔ Hub](android-client-hub-contract.md).
