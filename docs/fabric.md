# Cicada Fabric membership and Agent RPC

Cicada Fabric lets an already-running Codex thread join a user-owned network
without restarting the TUI or copying a thread UUID. The current v2 HTTP
implementation gives it a stable Endpoint and explicit membership in one or
more independently authorized Groups, publishes a
bounded Network Card, resolves addresses, and transports durable `send` or
correlated `ask`/`reply`. This page describes **currently runnable commands**.
The v2.1 target in [CICADA.md](../CICADA.md) adds nested Groups, explicit
links authorizing direct cross-Group and cross-user communication, and Group
broadcast; a Monitor is optional. Multi-Group Join/scope/Leave has
service/HTTP/MCP/CLI tests and a bounded same-host native Codex demo. A
versioned Group parent management API and non-routable CommunicationLink
proposal API exist, while graph editing, authorized direct links, broadcast,
and the local zero-Relay path remain open.

## What runs on each device

| Device | Required components | Purpose |
| --- | --- | --- |
| Cicada Hub | `cicada serve`, SQLite state, HTTPS reverse proxy | Co-hosted Control, Fabric Directory/Relay, permissions, panel; current peer body is not Hub-blind |
| Codex machine | `cicada` binary, `cicada machine agent`, official authenticated Codex CLI | Joins sessions and wakes an exact native thread with `codex queue --thread` |
| Codex TUI | Cicada plugin with bundled `cicada mcp` stdio server | Exposes Fabric tools inside the current session |
| Existing browser/PWA | A browser pointed at Hub | Legacy Goal/Endpoint management view; not Android v1 security boundary |
| Android Client v1 | User's phone (separate repository) | Planned status, local STT/text Control requests and authoritative management; sensitive Hub use requires NIST PQ Client↔Control E2EE |

The machine agent makes outbound HTTPS requests and opens a persistent Relay
event stream; the Hub sends body-free wake hints on that connection. Worker
machines require no inbound port. Run the agent as the same OS account that
owns the Codex login and sessions so it can resume those native threads.

## Install the network

Install Control on a server:

```bash
sudo env CICADA_MODEL_API_KEY_FILE=/run/secrets/cicada-model-key \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/cicada-fabric/cicada/main/scripts/install-cicada-server.sh | bash'
```

Copy the generated Control bearer token to a mode-0600 file on each Codex
machine through the operator's secret manager, then install its agent:

```bash
curl -fsSL https://raw.githubusercontent.com/cicada-fabric/cicada/main/scripts/install-cicada-worker.sh \
  | sudo -E env \
      CICADA_CONTROL_URL=https://control.example \
      CICADA_API_TOKEN_FILE=/etc/cicada/control.token \
      CICADA_MACHINE_ID=$(hostname -s) \
      CICADA_WORKSPACE_ROOT=/var/lib/cicada/workspaces \
      bash
```

Add the Cicada marketplace and plugin to Codex:

```bash
codex plugin marketplace add cicada-fabric/cicada --ref main
codex plugin add cicada@cicada-repo
```

Expose these variables to Codex and the plugin process:

```bash
export CICADA_API_URL=https://control.example
export CICADA_API_TOKEN_FILE=$HOME/.config/cicada/control.token
export CICADA_MACHINE_ID=$(hostname -s)
```

`CICADA_MACHINE_ID` defaults to the short hostname, matching the worker
installer. Set it explicitly when the machine agent uses a custom ID.

The Fabric service derives Endpoint ownership from its authenticated Cicada identity;
the OS account name is never accepted as an authorization claim.

The plugin declares a local stdio MCP server whose command is `cicada mcp`.
The client binary and Control are separate on purpose: installing a plugin
does not silently deploy a server or acquire a bearer token.

For Codex 0.155.1 with a Responses bridge that does not load deferred MCP
tools, the server-scoped setting below declares Cicada tools directly. It
does not change the model, grant tool approval, or enroll a Session. Apply it
to the intended runtime's configuration; the native acceptance script uses
only its isolated container configuration.

```toml
[mcp_servers.cicada]
command = "cicada"
args = ["mcp"]
omit_tools_from = ["deferred"]
```

`tools/list` succeeding alone does not prove the model has received the tool
declarations. The native demo's optional `--trace-tools` records only declared
tool names/types and selected response event types, never prompts or headers.

## Join from an existing TUI

Start Codex normally and work for as long as needed:

```bash
cd ~/AAA/le-wm
codex
```

Then explicitly choose a Group and say:

```text
@cicada join this thread to group grp_kernel
```

The plugin calls `cicada_join` with `group_id=grp_kernel`, then calls
`cicada_whoami` using the session credential returned by the explicit join.
The MCP server accepts a harness-provided native session ID, current directory,
and configured Machine ID as bounded metadata. It posts that metadata only
when the user invokes `cicada_join`; installation, MCP startup, and
`cicada_whoami` do not create an Endpoint. If the runtime cannot provide a
trusted native session ID, the join fails closed. Configure the adapter to
inject a value for that process when the harness supports it; never reuse one
static session ID across native threads. Repeating an explicit join is
idempotent: the `(harness, native_session_id)` binding returns the same stable
Endpoint ID while rotating the session credential.

The returned Network Card looks like:

```json
{
  "endpoint_id": "ep_…",
  "address": "le-wm@gpu1:~/AAA/le-wm",
  "name": "le-wm",
  "harness": "codex",
  "node_id": "gpu1",
  "status": "online",
  "tools": [
    "cicada_whoami",
    "cicada_list",
    "cicada_resolve",
    "cicada_inspect",
    "cicada_send",
    "cicada_ask"
  ]
}
```

The first-class Phase 3 wake path is Codex; other harnesses retain pollable
Endpoint messages until their native resume adapters are added. A runtime
adapter may inject `CICADA_NATIVE_SESSION_ID` for one process when it has
verified that value, but a static value shared by multiple native threads is
not a valid identity source.

## Directory and addresses

The stable route is `endpoint_id`. Users and agents normally use:

```text
endpoint_name@machine:workspace
endpoint_name@machine
endpoint_name
```

The resolver tries those forms in that order. A short form succeeds only when
it is unique among visible endpoints. An ambiguous query returns HTTP 409 and
the candidate addresses; it never silently guesses.

`cicada_list` returns live Machine and Endpoint metadata. `cicada_inspect`
returns one bounded Network Card. Neither operation returns a transcript,
system prompt, credentials, environment file, private memory, or workspace
contents.

## Send and ask

`send` is an asynchronous one-way message:

```text
cicada_send(target="benchmark@gpu2", message="Use commit abc123 for the next run")
```

`ask` creates a durable request:

```text
cicada_ask(target="benchmark@gpu2", question="What is the best result and configuration?")
```

Fabric returns `request_id = rq_…`. For a remote Machine, its agent atomically
claims the delivery and invokes the local official CLI with the exact target:

```text
codex queue --thread <native_session_id> --message <bounded Fabric prompt>
```

The target replies with `cicada_reply(request_id=..., message=...)`. Fabric
correlates the reply, marks the request replied, and wakes the original native
session through the same local or remote delivery path. If native wake is
temporarily unavailable, the durable envelope stays queued and the Endpoint
can claim it with `cicada_receive`.

Delivery uses a Session-bound Fabric credential and Group authorization; Node
claim/receipt uses a distinct Node credential. The current v2 message body is
plaintext in the Hub database. The old Contact path encrypts inside Control
and is not native Endpoint-to-Endpoint E2EE. Neither current path meets the
target in which Hub processes cannot decrypt peer content. Cross-user native
links need the new dual-owner authorization and Endpoint-held PQ keys.

## Operator CLI and HTTP API

The owner-authorized Client can create or revoke a same-owner Link proposal
through the encrypted `topology.apply` operation (`link.propose` or
`link.revoke`), and inspect it through encrypted `topology.snapshot`. The old
management-bearer `/v1/communication-links` HTTP routes have been removed.
The proposal names the source and target Endpoint/Group, direction (`forward`
or `bidirectional`), allowed `actions`, bounded `data_scopes`, expiry, and
one `transport_hub_id` for cross-Node links. Both Endpoints must currently
belong to their selected Groups and the same owner. A same-Node proposal has
no Hub. The state remains `PROPOSED` or `REVOKED`; a proposal and even two
key-bound signatures do **not** authorize Fabric delivery. Cross-user discovery
and links remain closed pending trusted invitation and Endpoint-held PQ routing.

Group nesting is a management operation. `PATCH /v1/groups/{child_id}/parent`
accepts `{"parent_group_id":"grp_parent","expected_version":1}` with the
configured management bearer; send an empty `parent_group_id` to detach.
The response contains the new Group version/revision. Stale edits, cycles,
and a parent from another owner/trust domain are rejected. The edge does not
grant access to parent or child messages, members, artifacts, or keys.

The CLI remains useful for recovery and automation:

```bash
# Join is an explicit enrollment. The command may discover the current
# harness session metadata, but it never joins merely because the CLI runs.
cicada fabric v2 join --group grp_kernel --name planner \
  --session-token-file /run/user/1000/cicada/session.json
cicada fabric v2 whoami
cicada fabric v2 use-group grp_secondary
cicada fabric v2 leave-group
cicada fabric v2 members
cicada fabric v2 find --node gpu2 benchmark
cicada fabric v2 send benchmark 'Use commit abc123 for the next run'
cicada fabric v2 ask benchmark 'What is the best result and configuration?'
cicada fabric v2 reply REQUEST_ID 'The verified answer is ...'
cicada fabric v2 receive
```

The join command can save the short-lived `CicadaSession` credential in an
explicit origin-scoped session file. Set `CICADA_SESSION_TOKEN_FILE` or pass
`--session-token-file`; the CLI has no ambient default credential file.
`CICADA_SESSION_TOKEN` is an explicit one-shot alternative. The selected
Group scope is saved with the private session file and sent as
`Cicada-Group-Scope`; `use-group` only succeeds if the server confirms this
Endpoint/Principal belongs to that Group. `leave-group` switches to a
remaining authorized Group, while `leave` exits all Groups. One-shot callers
can set `CICADA_SESSION_GROUP_ID`; this selects a scope but never grants
membership. A persisted file
records its API origin and native context, is written with mode `0600`, and is
never printed in the join result. Every v2 peer command uses
`Authorization: CicadaSession ...`; sender, Group, role, and approval fields
cannot be supplied as CLI authorization claims. The old `endpoint` registry
commands remain for pending historical records; their peer message claim route
has been removed. They cannot enroll or authorize a READY v2 session.

The corresponding authenticated v2 API families are:

```text
/v2/fabric/join                  # management bearer; explicit enrollment
/v2/fabric/whoami                # CicadaSession + optional validated Cicada-Group-Scope
/v2/fabric/leave-group           # withdraw only the selected Group
/v2/fabric/members               # CicadaSession
/v2/fabric/find                  # CicadaSession
/v2/fabric/send                  # CicadaSession
/v2/fabric/ask                   # CicadaSession
/v2/fabric/reply                 # CicadaSession
/v2/fabric/receive               # CicadaSession
/v2/fabric/heartbeat             # CicadaSession
/v2/fabric/leave                 # CicadaSession
```

The unauthenticated-by-session `/v1/fabric/*` peer routes and all legacy
`/v1/endpoints` routes have been removed. The embedded management panel reads
the `/v2/management/endpoints` projection through the management API; it requires
the operator bearer when `CICADA_API_TOKEN` is configured. Historical
Endpoint records remain in the database for migration; v2 session credentials
are required for collaboration.

Endpoint heartbeats drive `online`, `idle`, `busy`, and `offline` state. A
graceful leave records `left`. The Control monitor marks stale endpoints
offline using the same configured stale interval as Machines.
