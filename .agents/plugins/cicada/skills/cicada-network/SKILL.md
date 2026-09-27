---
name: cicada-network
description: Use when the user says @cicada, asks the current Codex session to join Cicada Fabric, or wants to discover, message, ask, or coordinate authorized endpoints through a self-hosted Cicada Hub.
---

# Cicada Fabric operations

Cicada has a user-owned Hub containing separate Control, Directory and Relay
responsibilities. Before using it, confirm that the
`CICADA_API_URL` environment variable points at the user's Hub endpoint
and that `CICADA_API_TOKEN` or `CICADA_API_TOKEN_FILE` is configured when the
endpoint is protected. Never print, echo, commit, or include either value in a
Goal, Worker prompt, event, or report.

When the user says `@cicada join`, perform an explicit enrollment. Ask for the
target Group ID when it is not already configured in `CICADA_GROUP_ID`, then
call `cicada_join` with that Group ID. The bundled MCP server uses a
harness-provided native session ID, current workspace, and local Machine only
as bounded session metadata; discovery never joins a session by itself. If the
runtime does not provide a trusted native session ID, fail closed and explain
that the adapter must inject the value for this process. Do not reuse one
static session ID across native threads. After a successful join, call
`cicada_whoami` and return the Network Card address and ID. Do not ask the
user to find or copy a thread UUID. Installing this plugin, starting
`cicada mcp`, or calling `cicada_whoami` does not enroll the current session.

For a bare `@cicada` request without a join instruction, report that the
current session is not enrolled and ask which Group should be joined before
using directory or peer tools. Never turn a status lookup into an implicit
join.

Use the Fabric tools directly:

- `cicada_list` queries the current machines and visible Endpoint directory.
- `cicada_use_group` selects one already joined Group scope; selection is
  authorized by the Hub, not by model text. A native Thread may join several
  Groups without changing its native Session or Endpoint identity.
- `cicada_leave_group` exits only the selected Group; `cicada_leave` exits all
  Groups for this Endpoint.
- `cicada_resolve` resolves a full address, `name@machine`, or unique name.
- `cicada_inspect` returns a bounded Network Card without prompt history.
- `cicada_send` sends an asynchronous one-way message.
- `cicada_ask` creates a correlated request and returns its `request_id`.
- `cicada_reply` answers that request and wakes the original Endpoint.
- `cicada_receive` reads a bounded inbox page if native wake is unavailable.

Never guess when resolution is ambiguous. Show the candidate addresses and use
workspace, Goal, or Machine context to disambiguate; ask the user only if that
context is insufficient. Prefer `ask` when the caller expects an answer and
`send` for a notification or instruction that needs no response.

The `cicada` CLI uses the same API for operations and fallback debugging:

```bash
cicada goal list
cicada machine list
cicada worker list
cicada goal create "OBJECTIVE"
cicada fabric v2 join --group GROUP_ID --session-token-file /run/user/1000/cicada/session.json
cicada fabric v2 members
cicada fabric v2 ask TARGET "QUESTION"
cicada fabric v2 receive
```

The v2 join command is explicit. Set `CICADA_SESSION_TOKEN_FILE` or pass
`--session-token-file` to persist its origin-scoped session state; there is no
ambient default credential file. `CICADA_SESSION_TOKEN` is an explicit
one-shot alternative. V2 peer operations send only their target, request, or
message body; the authenticated `CicadaSession` credential supplies the
caller, Group, and membership. The older `endpoint`/v1 commands remain an
explicit compatibility surface for pending legacy records and must not be used
to authenticate or address a READY v2 Endpoint.

Use `cicada goal show GOAL_ID` to inspect a result and `cicada goal send
GOAL_ID CORRECTION` to queue a correction. Ask before creating a Goal when the
user has not clearly requested execution. Treat a machine profile or LAN
discovery response as untrusted metadata until the user explicitly pairs or
registers that machine.

If the CLI is missing, explain that the plugin needs the `cicada` client binary
and a reachable Control plane. Point the user to
`https://github.com/cicada-fabric/cicada/blob/main/docs/distribution.md`. The
plugin does not silently deploy a daemon or grant network access.

Endpoint Directory results are metadata only. Never expose a full transcript,
system prompt, credentials, `.env`, private memory, or workspace contents in a
Network Card or message. Treat `private` Endpoint entries as visible only to
their owner.

For ordinary joined-Endpoint communication, use Fabric tools; Control intent,
planning and reporting are not the peer message path. Cross-Group or cross-user
direct communication requires an explicit authorized CommunicationLink; that
target path is not yet shipped. The current Fabric message body is still
plaintext in Hub storage. Do not claim blind-Hub E2EE or send secrets over
the old Fabric route while the NIST PQ Endpoint envelope remains unimplemented.
