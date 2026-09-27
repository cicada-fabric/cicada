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
service/HTTP/MCP/CLI tests and a bounded same-host native Codex demo. The
authorized cross-Node single-recipient Link path supports endpoint-encrypted
SEND/ASK/REPLY in two-logical-Node/fake-Codex tests. Same-owner, same-Group
single-recipient traffic is sealed on one Node without Hub Relay message routing
and across Nodes through one Hub. Same-Group broadcast has passed a two-logical-
Node/fake-Codex full-chain test; real native broadcast, user-authorized Monitor
broadcast and real cross-user native validation remain open.

## What runs on each device

| Device | Required components | Purpose |
| --- | --- | --- |
| Cicada Hub | `cicada serve`, SQLite state, HTTPS reverse proxy | Co-hosted Control, Fabric Directory/Relay, permissions, panel; sealed Link and sealed-capable Group peer bodies are opaque, while legacy unsealed Group sessions can still use plaintext Fabric |
| Codex machine | `cicada` binary, `cicada machine agent`, official authenticated Codex CLI | Joins sessions and queues delivery to an exact native thread; unloaded threads require an explicit native resume before consumption |
| Codex TUI | Cicada plugin with bundled `cicada mcp` stdio server | Exposes Fabric tools inside the current session |
| Existing browser/PWA | A browser pointed at Hub | Legacy Goal/Endpoint management view; not Android v1 security boundary |
| Android Client v1 | User's phone (separate repository) | Planned status, local STT/text Control requests and authoritative management; sensitive Hub use requires NIST PQ Client↔Control E2EE |

The machine agent makes outbound HTTPS requests and opens a persistent Relay
event stream; the Hub sends body-free wake hints on that connection. Worker
machines require no inbound port. Run the agent as the same OS account that
owns the Codex login and sessions so it can address those native threads.
`codex queue --thread` accepting an item is not proof of unattended wake for an
unloaded thread. The [upstream Codex issue](https://github.com/openai/codex/issues/44491)
documents a version where the item remains pending until `thread/resume`.
Current Cicada Node does not implement that cold-resume step, so keep native
consumption distinct from queue acceptance in receipts and acceptance claims.

## Install the network

Install Control on a server:

```bash
sudo env CICADA_MODEL_API_KEY_FILE=/run/secrets/cicada-model-key \
  bash -c 'curl -fsSL https://raw.githubusercontent.com/cicada-fabric/cicada/main/scripts/install-cicada-server.sh | bash'
```

Install the Node agent with its own owner-bound credential; the owner confirms
its one-time device code through the encrypted Client contract. A Control
management bearer is not a Node Relay credential. See [distribution](distribution.md)
and [Node pairing](client-hub-interop-v1.md) for the current bootstrap sequence.

Add the Cicada marketplace and plugin to Codex:

```bash
codex plugin marketplace add cicada-fabric/cicada --ref main
codex plugin add cicada@cicada-repo
```

Expose the Hub address and Node identity to Codex and the plugin process;
the machine agent keeps its Node credential outside the model process:

```bash
export CICADA_API_URL=https://control.example
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
`cicada_whoami` using a private session credential that is not shown to the
model. The local Node bridge checks the actual Codex Thread record and current
workspace before posting a Join with its Node identity. Installation, MCP
startup, and `cicada_whoami` do not create an Endpoint. If the runtime cannot
provide a trusted native session ID, the join fails closed; never reuse one
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

`cicada_list` returns visible Node and Endpoint metadata. `cicada_inspect`
returns one bounded Network Card. Neither operation returns a transcript,
system prompt, credentials, environment file, private memory, or workspace
contents.

## Send and ask

Same-Group `send` is an asynchronous one-way message:

```text
cicada_send(target="benchmark@gpu2", body="Use commit abc123 for the next run")
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

The target replies with `cicada_reply(request_id=..., body=...)`. Fabric
correlates the reply, marks the request replied, and wakes the original native
session through the same local or remote delivery path. If native wake is
temporarily unavailable, the durable envelope stays queued. For sealed-capable
Sessions, `cicada_receive` reads only the current native Session and Group's
injected Node inbox, including trusted kind, sender and request/reply metadata;
it does not read peer plaintext from Hub.

An explicitly approved cross-Group or cross-user Link uses a separate sealed
route from the same MCP tools:

```text
cicada_ask(link_id="link_…", data_scope="thread.message", question="What is the verified result?")
cicada_reply(request_id="rq_…", link_id="link_…", body="The verified result is …")
cicada_request_status(request_id="rq_…", link_id="link_…")
```

The current native Session is the sender. Its trusted local Node bridge
derives the destination from the signed Link and encrypts for the target
Endpoint; the reply bridge derives its route from the original Request. The
Hub Relay persists only signed `SEALED_V1` ciphertext and correlation metadata.
This sealed Link route has passed two-logical-Node/fake-Codex tests, not a real
cross-user native session or two physical machines. Sealed-capable same-Group
`target` SEND/ASK/REPLY uses the Node-local sealed path or the Node-only Hub
ciphertext route; older unsealed Sessions can still use legacy plaintext
Fabric and must not be presented as E2EE. Node claim/receipt uses a distinct
Node credential.

An Agent with both `message.broadcast` and `message.send` may broadcast to
one explicitly selected current Group; each recipient needs `message.receive`:

```text
cicada_broadcast(group_id="group_…", body="Build abc123 is ready")
```

The first result includes a durable operation ID and broadcast ID. The Hub
freezes up to 32 recipients in an immutable snapshot; the Node prepares an
independent sealed SEND for each recipient in batches of eight. Inspect
`cicada_operation_status`, and call `cicada_operation_retry` with the same
operation ID to continue another batch or reconcile an uncertain child.
`ACCEPTED` means persisted locally or at Relay, not consumed by a model.
The current implementation queues each child to its native Session; Group
notification/budget policy and user-via-Monitor approval are not yet wired.

## Operator CLI and HTTP API

The owner-authorized Client can create or revoke a same-owner Link proposal
through the encrypted `topology.apply` operation (`link.propose` or
`link.revoke`), and inspect it through encrypted `topology.snapshot`. The old
management-bearer `/v1/communication-links` HTTP routes have been removed.
The proposal names the source and target Endpoint/Group, direction (`forward`
or `bidirectional`), allowed `actions`, bounded `data_scopes`, expiry, and
one `transport_hub_id` for cross-Node links. Both Endpoints must currently
belong to their selected Groups. Two different owners use a one-time external
invitation to create the proposal, then each owner separately signs the
current key-bound manifest; the proposal or either signature alone does
**not** authorize delivery. A same-Node proposal has no Hub and is not yet
routable. Cross-Node Link SEND/ASK/REPLY is routable only while both grants,
keys, bindings, scope, action and expiry are current.

Group nesting is a management operation. `PATCH /v1/groups/{child_id}/parent`
accepts `{"parent_group_id":"grp_parent","expected_version":1}` with the
configured management bearer; send an empty `parent_group_id` to detach.
The response contains the new Group version/revision. Stale edits, cycles,
and a parent from another owner/trust domain are rejected. The edge does not
grant access to parent or child messages, members, artifacts, or keys.

The CLI remains useful for enrollment, discovery, and historical inspection.
Peer writes use the joined Codex MCP tools, which seal the message on the
source Node before a remote Hub sees it. A direct CLI Join alone does not
provision the local sealed-delivery bridge or Endpoint key:

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
cicada fabric v2 receive # read-only legacy plaintext history, if any
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
never printed in the join result. Every remaining v2 session command uses
`Authorization: CicadaSession ...`; sender, Group, role, and approval fields
cannot be supplied as authorization claims. The old `endpoint` registry
command has been removed; historical Endpoint records remain for migration
and cannot enroll or authorize a READY v2 session.

The corresponding authenticated v2 API families are:

```text
/v2/fabric/join                  # management bearer; explicit enrollment
/v2/fabric/whoami                # CicadaSession + optional validated Cicada-Group-Scope
/v2/fabric/leave-group           # withdraw only the selected Group
/v2/fabric/members               # CicadaSession
/v2/fabric/find                  # CicadaSession
/v2/fabric/send|ask|reply        # authenticated legacy plaintext writes retired: 410
/v2/fabric/receive               # CicadaSession; historical PLAINTEXT rows only, read-only
/v2/fabric/heartbeat             # CicadaSession
/v2/fabric/leave                 # CicadaSession
```

The unauthenticated-by-session `/v1/fabric/*` peer routes and all legacy
`/v1/endpoints` routes have been removed. The embedded management panel reads
the `/v2/management/endpoints` projection through the management API; it requires
the operator bearer when `CICADA_API_TOKEN` is configured. Historical
Endpoint records remain in the database for migration; v2 session credentials
are required for discovery and historical reads. Normal joined peer traffic
uses MCP → Node sealed delivery; neither a CLI peer-write command nor direct
Hub plaintext POST is an alternative transport.

Endpoint heartbeats drive `online`, `idle`, `busy`, and `offline` state. A
graceful leave records `left`. The Control monitor marks stale endpoints
offline using the same configured stale interval as Machines.
