# Same-host native direct message: bounded transport review

The default for any authorized Thread pair is the existing sealed Hub Relay.
Native direct delivery is an exception only when both exact target Threads are
proved to share a physical host and Codex account and a callable native API
can be guarded by CICADA. Sharing a Hub, Network, Node label, or Group does
not itself select direct delivery. This review records what can be used at the
current M1 checkpoint and what would need a separate native adapter; it does
not enable a new send route.

## Evidence and transport selection

The installed `codex-cli 0.157.1` exposes `codex queue --thread <id> --message
<text>` and `codex app-server` over stdio, Unix socket, or WebSocket. This
session's Codex TUI host also exposes a model-callable
`mcp__codex_tui__send_message_to_thread({threadId,prompt,model?})` tool, with a
1,000 UTF-8-byte prompt limit. That tool can send a follow-up to an existing
Codex task in this host. Its presence in the model's tool registry does **not**
establish a Node-process API, a stable CLI command, a Hub endpoint, or access
to another Codex host/account. No message was sent during this review.

The [official App Server documentation](https://learn.chatgpt.com/docs/app-server)
documents `thread/resume` for an existing ID, `turn/start` to begin generation
on a target thread, and `turn/steer` for an *active* turn with
`expectedTurnId`. It does not document `send_message_to_thread` as an
app-server method. `turn/start` is a paid/model-executing turn; `turn/steer`
requires an active turn. Neither is a transparent, durable peer inbox. The
documented `thread/inject_items` changes model-visible history without
starting a turn, so it also is not a peer delivery acknowledgement. CICADA's
existing `internal/codexapp.ProxyClient` reads exact thread status and queue
pages from a running daemon; it does not yet write or resume on that path.

| Situation | Current CICADA route | Bounded future selection |
| --- | --- | --- |
| Same Node ID, same Owner, same Group, two authorized native Threads | The existing *local Group optimization* uses an authorized Group card, Hub metadata-only `/local/authorize`, sealed `nodelocal` ciphertext, `/local/revalidate`, and `codex queue --thread` on the exact target. Peer body never travels through Hub Relay. This implementation is not evidence of the TUI direct API exception for arbitrary Thread pairs. | Keep this narrowly authorized path while evaluating native direct. A future adapter may replace only its final queue injection under the same Node ledger and Guard after proving exact physical host, account, and callable API. |
| Same physical host/account but different Node IDs, Groups, or Owners | Do not infer locality or authorization from a pathname, workspace, account name, or matching machine label. Existing cross-Node sealed Relay/Link routes still apply where authorized. | Select local direct only after both endpoints' current same-Network enrollments, exact native bindings, and same-host runtime ownership are proved by a trusted Node boundary. A cross-Group route additionally needs the precise bilateral Owner-approved Link, with each endpoint in its own Group mapped to that Network. |
| Different host or no verified native direct capability | Existing sealed Node/Hub Relay path. | Keep the sealed Relay path; no plaintext or implicit Group fallback. |

`cicada_network_resolve` provides a small Network card: Network ID, Endpoint
ID, nickname, capabilities, and access recency. It intentionally exposes no
Node address or native Thread ID. A nickname or `network_id` only selects a
candidate; it is never a delivery grant. The current same-Node optimization
in `mcp_local_group.go` instead uses an authenticated Group card with Node ID
and the Node bridge's independently verified original Codex session. It is
limited to the same Owner and same Group; it cannot authorize a cross-Group
Link or a Network-only member's private message.

The existing local path can avoid the Hub **payload** hop but still needs a
current Hub Guard/Directory metadata check. It is not yet the requested TUI
direct tool. See `cmd/cicada/local_group_bridge.go` for the source binding and
current route check, `cmd/cicada/machine_local_group.go` for ledger/decrypt and
pre-injection revalidation, and `cmd/cicada/machine_fabric.go` for the current
`codex queue` call. Hub loss or stale revocation state must fail closed before
new delivery; a cached nickname or old access token cannot widen grants.

## Receipt and recovery boundary

The sender needs one durable operation/message ID before native delivery. The
local Node ledger may acknowledge `LOCAL_PERSISTED` after recording ciphertext;
the receiving Node inbox may acknowledge acceptance after recording the exact
target binding. Neither means that Codex read the prompt. CICADA's current
`codex queue` returns no durable queue ID to this path, so a successful call is
only queue acceptance and remains `CONSUMPTION_UNCONFIRMED`. A timeout or crash
after starting the call may already have injected the prompt and must remain
`INJECTION_UNCERTAIN`, without blind retry. Any future direct adapter must
reconcile the same operation ID with a native receipt and keep one local writer
for each Thread; it must not create a second app-server or turn as a shortcut.

## Next bounded implementation gate

First establish whether the running Codex TUI host provides a supported,
process-callable local transport for the exact semantics of
`send_message_to_thread`. Tool metadata alone is insufficient; an agent
choosing to call that model-visible tool after a CICADA directory lookup would
have no server-enforced current Network/Link Guard. If no such transport is
available, do not invent an API or relay plaintext through Hub. Keep the
existing local sealed queue path and evaluate a version-gated app-server
adapter only against isolated synthetic Threads, with no production turn or
global configuration change. A passing gate needs exact target ID, active and
cold-thread behavior, busy/approval-waiting behavior, a durable correlation
witness, one-writer serialization, revocation immediately before delivery,
crash/retry uncertainty, and no payload in Hub Relay. Only then should an MCP
nickname resolution route be allowed to select native direct transport.
