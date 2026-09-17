# Cicada Fabric membership and Agent RPC

Cicada Fabric lets an already-running Codex thread join a user-owned network
without restarting the TUI or copying a thread UUID. Control gives the native
thread a stable Endpoint identity, publishes a bounded Network Card, resolves
human-readable addresses, and routes durable `send` or correlated
`ask`/`reply` messages.

## What runs on each device

| Device | Required components | Purpose |
| --- | --- | --- |
| Control server | `cicada serve`, SQLite state, HTTPS reverse proxy or SSH tunnel | Fabric Directory, resolver, durable messages, permissions, panel |
| Codex machine | `cicada` binary, `cicada machine agent`, official authenticated Codex CLI | Joins sessions and wakes an exact native thread with `codex queue --thread` |
| Codex TUI | Cicada plugin with bundled `cicada mcp` stdio server | Exposes Fabric tools inside the current session |
| Desktop or phone | A browser/PWA pointed at Control | Shows live machines, Endpoint Network Cards, Goals, approvals, and notifications |

The machine agent makes outbound HTTPS requests. Worker machines require no
inbound port. Run the agent as the same OS account that owns the Codex login
and sessions so it can resume those native threads.

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

Control derives Endpoint ownership from its authenticated Cicada identity;
the OS account name is never accepted as an authorization claim.

The plugin declares a local stdio MCP server whose command is `cicada mcp`.
The client binary and Control are separate on purpose: installing a plugin
does not silently deploy a server or acquire a bearer token.

## Join from an existing TUI

Start Codex normally and work for as long as needed:

```bash
cd ~/AAA/le-wm
codex
```

Then say:

```text
@cicada join
```

The plugin calls `cicada_whoami`. The MCP server reads the current
`CODEX_THREAD_ID`, current directory, configured Machine ID, and OS user. It
posts only that bounded metadata to Control. Repeating the operation is
idempotent: the `(harness, native_session_id)` binding returns the same stable
Endpoint ID.

The returned Network Card looks like:

```json
{
  "endpoint_id": "ep_…",
  "address": "le-wm@gpu1:~/AAA/le-wm",
  "role": "thread",
  "harness": "codex",
  "machine_id": "gpu1",
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

If a harness does not export its session ID, set
`CICADA_NATIVE_SESSION_ID`. The first-class Phase 3 wake path is Codex; other
harnesses retain pollable Endpoint messages until their native resume adapters
are added.

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

Control returns `request_id = rq_…`. For a remote Machine, its agent atomically
claims the delivery and invokes the local official CLI with the exact target:

```text
codex queue --thread <native_session_id> --message <bounded Fabric prompt>
```

The target replies with `cicada_reply(request_id=..., message=...)`. Control
correlates the reply, marks the request replied, and wakes the original native
session through the same local or remote delivery path. If native wake is
temporarily unavailable, the durable envelope stays queued and the Endpoint
can claim it with `cicada_receive`.

Delivery is authenticated by the Control bearer boundary and checked against
`fabric.send`, `fabric.ask`, and `fabric.reply` permission rules. The local
Fabric table is for one owner or trusted local Control. Cross-user messages
continue to use Contact approval and the existing E2EE federation path.

## Operator CLI and HTTP API

The CLI remains useful for recovery and automation:

```bash
cicada endpoint join --auto --name planner
cicada endpoint list
cicada fabric whoami ENDPOINT_ID
cicada fabric resolve benchmark ENDPOINT_ID
cicada fabric inspect benchmark ENDPOINT_ID
cicada fabric send ENDPOINT_ID benchmark 'message'
cicada fabric ask ENDPOINT_ID benchmark 'question'
cicada fabric reply ENDPOINT_ID REQUEST_ID 'answer'
cicada fabric claim ENDPOINT_ID
```

The corresponding authenticated API families are:

```text
/v1/endpoints
/v1/endpoints/{id}/heartbeat
/v1/endpoints/{id}/messages
/v1/fabric/list
/v1/fabric/whoami
/v1/fabric/events
/v1/fabric/resolve
/v1/fabric/inspect
/v1/fabric/send
/v1/fabric/ask
/v1/fabric/reply
/v1/machines/{id}/fabric-deliveries
```

Endpoint heartbeats drive `online`, `idle`, `busy`, and `offline` state. A
graceful leave records `left`. The Control monitor marks stale endpoints
offline using the same configured stale interval as Machines.
