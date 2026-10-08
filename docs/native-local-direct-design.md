# Same-host native direct message: bounded transport review

Sealed Hub Relay remains the default. Direct delivery is an exception requiring trusted proof of the exact same physical host and Codex account, a supported exact-Thread native API, and current Join/binding/lease/Guard authorization.

Current CLI 0.161.0 does not establish V67 eligibility: `thread/read` lacks an authoritative per-Thread account binding, while optional `account/read.workspaceRouting` describes daemon-current routing. `thread/queue/add` has no expected-account/auth-epoch fence, so an account switch between revalidation and submission remains unguarded; reconnect or protected UDS incarnation changes cannot preserve an assumed identity. API-key/null routing stays UNKNOWN. Node inbox `AccountID=hub.WriterScope` is a serial-writer scope, not native account proof (`machine_hub_context.go:180–184`). Fresh Node `local_send/local_ask` remain UNSUPPORTED; normal MCP SEND/ASK, including same-Node Group targets, still use sealed Hub Relay (`mcp_local_group.go:68–76`, `cross_node_group_bridge.go:195–208`). Existing local operations are scoped legacy replay/completion/control under current binding and Guard checks; fresh local Task handoff is not restored. This is not a blanket limit on Codex capabilities; [source/schema review](../.cicada-data/native-observer-wiring-20261007/root-native-capability-review-20261008a.NONAUTH.json) is not Runtime execution or proof of installed-binary/source equivalence.

Pinned official CLI 0.161.0 [sandbox source](https://github.com/openai/codex/blob/979011409de0a60b52f179721948e65531d26144/codex-rs/linux-sandbox/src/linux_run_main.rs#L412-L417) rejects legacy Landlock for a policy without full-disk write access: filesystem-restricted execution requires bubblewrap to isolate app-server sockets. It provides no workspace-write Landlock fallback. This source fact adds no sandbox or Native PASS; historical A6 cause remains UNKNOWN.

## Historical M1 / CLI 0.157.1 evidence and transport selection

At the historical M1 review, the installed `codex-cli 0.157.1` exposed `codex queue --thread <id> --message
<text>` and `codex app-server` over stdio, Unix socket, or WebSocket. That
session's Codex TUI host also exposed a model-callable
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

## Current transport selection

| Situation | Current CICADA route | Bounded future selection |
| --- | --- | --- |
| Same Node ID, same Owner, same Group, two authorized native Threads | SEND/ASK replay returns an existing durable result without signalling or requeueing. Correlated legacy reply/completion/control requires the private ledger and current caller authorization; an authorized reply can submit to the exact target. Fresh Node local SEND/ASK are UNSUPPORTED; normal MCP SEND/ASK use sealed Hub Relay. This historical mechanism is not V67 acceptance. | Keep scoped legacy replay/completion/control while evaluating native direct. A future adapter may replace only its final queue injection under the same Node ledger and Guard after proving exact physical host, account, and callable API. |
| Same physical host/account but different Node IDs, Groups, or Owners | Do not infer locality or authorization from a pathname, workspace, account name, or matching machine label. Existing cross-Node sealed Relay/Link routes still apply where authorized. | Select local direct only after both endpoints' current same-Network enrollments, exact native bindings, and same-host runtime ownership are proved by a trusted Node boundary. A cross-Group route additionally needs the precise bilateral Owner-approved Link, with each endpoint in its own Group mapped to that Network. |
| Different host or no verified native direct capability | Existing sealed Node/Hub Relay path. | Keep the sealed Relay path; no plaintext or implicit Group fallback. |

`cicada_network_resolve` provides a small Network card: Network ID, Endpoint
ID, nickname, capabilities, and access recency. It intentionally exposes no
Node address or native Thread ID. A nickname or `network_id` only selects a
candidate; it is never a delivery grant. The historical same-Node optimization
in `mcp_local_group.go` instead uses an authenticated Group card with Node ID
and the Node bridge's independently verified original Codex session. It is
limited to the same Owner and same Group; it cannot authorize a cross-Group
Link or a Network-only member's private message.

Scoped legacy replay/completion/control can avoid the Hub **payload** hop but still needs a
current Hub Guard/Directory metadata check. It is not yet the requested TUI
direct tool. See `cmd/cicada/local_group_bridge.go` for the source binding and
current route check, `cmd/cicada/machine_local_group.go` for ledger/decrypt and
pre-injection revalidation, and `cmd/cicada/machine_native_delivery.go` for the current
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
available, do not invent an API or relay plaintext through Hub. Keep scoped
legacy replay/completion/control and evaluate a version-gated app-server
adapter only against isolated synthetic Threads, with no production turn or
global configuration change. A passing gate needs exact target ID, active and
cold-thread behavior, busy/approval-waiting behavior, a durable correlation
witness, one-writer serialization, revocation immediately before delivery,
crash/retry uncertainty, and no payload in Hub Relay. Only then should an MCP
nickname resolution route be allowed to select native direct transport.
