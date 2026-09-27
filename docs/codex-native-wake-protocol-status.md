# Codex native Thread wake protocol status

This note records the boundary of the Codex app-server work in this change. It
does not claim unattended cold Thread wake is implemented.

## Implemented adapter boundary

`cicada-go/internal/codexapp.ProxyClient` is a read-only adapter preparation. It
uses the official `codex app-server proxy --sock <daemon-socket>` WebSocket
transport and can initialize, read the exact Thread status, and list a bounded
number of queue pages. It does not expose queue/add, queue/start, thread/resume,
or Thread creation. The existing stdio `Client` remains separate. The former
JSONL-over-proxy path was removed because `app-server proxy` speaks WebSocket.

The adapter requires a running daemon and checks the daemon-reported protocol
version before starting the proxy. It never starts a private app-server as a
fallback. `github.com/coder/websocket` is pinned at v1.8.15; its module declares
the ISC license ([release](https://github.com/coder/websocket/releases),
[package and license](https://pkg.go.dev/github.com/coder/websocket)).

## Protocol evidence and limits

An isolated Codex CLI 0.157.0 protocol probe observed that `thread/queue/add`
returns a queued submission and accepts `clientUserMessageId`, while
`thread/queue/list` returns `data` and `nextCursor`. Repeating queue/add with the
same client message ID and identical input produced two distinct queue entries.
That ID is therefore a correlation field, not an idempotency key. In the same
isolated probe, resuming the exact cold Thread returned that Thread in `idle`
state without starting a turn. A successful queue operation alone does not
prove that a Thread woke or that a model consumed the message. This agrees with
the [Codex queue contract](https://github.com/openai/codex/issues/44491).

A separate real Go adapter attempt against an isolated 0.157.0 daemon exercised
a loaded/idle synthetic Thread: initialize, Thread creation, queue/add, and
exact-ID thread/read succeeded, but queue/list returned zero entries for the
submission just added. The smoke failed on that mismatch. It did not call
`thread/queue/start` or `turn/start`; the result does not establish a reliable
queue witness for this loaded case.

A later read-only Go smoke passed against a pre-seeded cold fixture on an
isolated 0.157.0 daemon. The fixture was created with `thread/start`; the CLI
`daemon stop` reported that its daemon was unmanaged, so the isolated process
was matched by exact `CODEX_HOME` and command line, terminated, and restarted
to unload the Thread. Then `thread/read` confirmed `notLoaded` and an empty
queue before one synthetic `thread/queue/add`. The
smoke's redacted target label was `cold-fixture-A`; its native ID and unique
`clientUserMessageId` stayed in the disposable `CODEX_HOME` and are omitted
here. The smoke reported `exact_thread_id=true thread_status=notLoaded
queue_items=1 unique_submission=true read_only=true`. No API credential was
passed, and no `thread/resume`, `thread/queue/start`, or `turn/start` request
was sent. This confirms read/list behavior for this fixture only; it does not
test model consumption or establish automatic wake. The opt-in
`TestProxyClientRealDaemonReadSmoke` itself performs only initialize, exact
`thread/read`, and `thread/queue/list`; it requires an isolated daemon plus an
already-seeded cold Thread and queue entry.

## Production status

The Node production delivery path still uses the CLI queue operation, which
does not return a queue identity suitable for reconciliation. No automatic
cold resume is connected to `ProxyClient`. Do not infer `RUNTIME_INJECTED`,
Thread wake, or model consumption from queue acceptance. Queue-call crash or
timeout windows remain uncertain and must not trigger blind resubmission. A
future production path needs a durable, exact queue witness, current Node
authorization immediately before each execution entry, and an upstream-tested
state check before it can resume a cold Thread. Until then, cold wake remains
unimplemented and fail-closed.

## Verification

Offline deterministic protocol tests use a fake WebSocket daemon and cover
upgrade/framing, exact Thread IDs and states, queue pagination and ambiguity,
unsupported versions, and request cancellation. The real isolated Go cold
read/list smoke passed with exit code 0. Its exact in-container invocation was:
the following shell snippet is the test invocation after the fixture had
already been pre-seeded; it is not a standalone fixture creation script.

```sh
PROBE_HOME=/dev/shm/cicada-codex-readonly-probe.M5lozn
PROBE_SOCKET_TARGET="$(readlink -f "$PROBE_HOME/app-server-control/app-server-control.sock")"
read -r CICADA_CODEX_SMOKE_THREAD_ID < "$PROBE_HOME/thread.id"
read -r CICADA_CODEX_SMOKE_CLIENT_MESSAGE_ID < "$PROBE_HOME/client.id"
export CICADA_CODEX_SMOKE_THREAD_ID CICADA_CODEX_SMOKE_CLIENT_MESSAGE_ID
docker run --rm \
  -v /home/zyf/CICADA/cicada-go:/src \
  -v /home/zyf/go/pkg/mod:/go/pkg/mod:ro \
  -v cicada-go-buildcache:/cache \
  -v "$PROBE_HOME:$PROBE_HOME" \
  -v "$PROBE_SOCKET_TARGET:$PROBE_SOCKET_TARGET" \
  -v /home/zyf/.local/bin/codex:/home/zyf/.local/bin/codex:ro \
  -w /src \
  -e GOPROXY=off -e GOCACHE=/cache \
  -e HOME="$PROBE_HOME/isolated-home" -e CODEX_HOME="$PROBE_HOME" \
  -e CICADA_CODEX_BIN=/home/zyf/.local/bin/codex \
  -e CICADA_CODEX_PROXY_SMOKE=1 \
  -e CICADA_CODEX_SMOKE_THREAD_ID \
  -e CICADA_CODEX_SMOKE_CLIENT_MESSAGE_ID \
  golang:1.27.1-bookworm bash -lc \
  'export PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin; go test ./internal/codexapp -run ^TestProxyClientRealDaemonReadSmoke$ -count=1 -v'
```

The smoke exited 0 and emitted only the redacted state/count summary above.
The earlier loaded/idle smoke failure remains a separate limitation, not a
pass.
