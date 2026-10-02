# Node relay SSE frame write deadline

`relayNodeEvents` now gives each ready, wake, space and keepalive frame one
five-second deadline shared by its actual Write and Flush. The initial HTTP 200
is implicit in the first Write, after that deadline has been installed. Capability
probing sets and clears a deadline without flushing or committing a success
response. Both flush and deadline support must be found in at most 32 writer
layers before either Fabric subscription is registered. Standard
`http.ResponseController` then follows `Unwrap`, or uses forwarded methods.
A writer with missing capabilities, including a cyclic wrapper without a setter,
returns typed `http.ErrNotSupported` from the private probe. The handler responds
with HTTP 500 headers only, without a body or registered subscriptions.

A short write, Write error or FlushError ends the stream. Failed frames retain
the deadline so net/http finalization cannot gain an unbounded socket flush.
Only a successful Write and Flush clear the application write deadline. This
allows the existing 25-second idle keepalive interval and subsequent hints to
work. Clearing does not extend native TLS certificate validity: the unchanged
`pqtls.Conn.operationDeadlineLocked` continues to clamp operations to the
verified certificate NotAfter even for zero or later application deadlines.

The patch leaves current Owner/device/credential/TLS authority checks, generic
hint frames, durable claims, single-slot coalescing and unsubscribe semantics
intact. There is no subscriber quota, protocol/API/dependency change or goroutine
fallback. A revoked or canceled stream blocked in a previously admitted write
can finish that attempt or time out at its existing five-second deadline; this
is not immediate byte recall. Bytes already admitted or sent cannot be recalled.
The bound applies to the native and standard socket writers honoring deadlines;
an arbitrary trusted custom setter, Write or Flush implementation that ignores
its contract or blocks internally is outside that guarantee.

## Deterministic test definitions

All fixtures are disposable synthetic data, with private material removed by
TempDir cleanup. Writer compilation and tests are **NOT_RUN**; the supervisor
validates the frozen source with scoped normal/race/native gates.

- `TestRelayNodeSSEWriteDeadlineFrame`: an instrumented writer behind an
  Unwrap-only wrapper proves one shared deadline, success-only clearing,
  short-write termination and Write/Flush/clear error propagation. These are
  capability and error-path unit assertions, not real socket evidence.
- `TestRelayNodeSSEWriteDeadlineUnsupported`: typed unsupported and malformed
  cyclic-wrapper refusal, HTTP 500, zero body writes and zero subscriptions.
- `TestRelayNodeSSEWriteDeadlineTCPBackpressure/write-cancel` and
  `/flush-revoke`: a real loopback HTTP/1.1 socket stops reading. A test-only
  wrapper amplifies a subsequent authorized wake frame with a 16 MiB SSE comment
  after the peer has read HTTP 200 and the complete ready frame. A small
  synthetic TCP send/read buffer to reach actual socket backpressure. The
  underlying partial write must return a timeout. Actual request-context cancel
  or committed Owner-binding revocation occurs while the handler is active;
  handler return and both unsubscribe operations are bounded and checked before
  Store close. Padding is an artificial amplifier; it does not establish how
  frequently ordinary small generic frames saturate a production connection.
- `TestRelayNodeSSEWriteDeadlineIdleKeepalive`: a real socket receives ready,
  waits for the actual 25-second keepalive, then receives a new wake. It verifies
  the short frame deadline was cleared without shortening the idle interval.
- `TestNodePQTLSSEWriteDeadlineBackpressure/write-revoke` and `/flush-cancel`:
  same-process actual native mTLS/socket cases reuse `nodeTLSProcessBuild`, with
  real synthetic OwnerDevice approval, committed TLS ACTIVE and exact native
  pins/epochs/current Guard. The native peer completes authentication and sends
  the production SSE request, reads HTTP 200 and ready with a finite read deadline,
  then stops reading. The real recheck ticker is active when a claim hint is
  published and test-only padding amplifies its Write or Flush and saturates
  that real TLS socket; there is no fake blocking writer. TLS-only revocation
  retains a valid bearer and commits to the actual Store. Timeout, handler
  unsubscribe and joined HTTP lifecycle precede Store close.
- `TestNodePQTLSSEWriteDeadlineIdle`: actual native ready, idle beyond five
  seconds, a current-authorized space hint and real TLS-only revocation. This
  verifies native zero application deadline retains idle functionality.

Native cases require `pqtls.Available`. When the native fixture executable is
explicitly requested, unavailable is fatal, not skipped. Default unavailable
builds assert the typed native unavailability and report native cases NOT_RUN.
The existing six `TestNodePQTLSProductionSSE` two-process cases remain unchanged
in their assertions. Their observation writer only gains Unwrap and FlushError
forwarding, so it cannot conceal native flush errors.

Unsubscribe inspection uses test-only reflection on the lengths of
`fabric.Service.nodeEvents` and `spaceEvents` after the handler and producer
operations have joined. It uses no unsafe access, public subscriber API or
channel/key inspection. It checks cleanup, not a new subscriber-capacity policy.
The new native cases are single-process loopback transport evidence; existing
six-case process topology and any later supervisor receipts retain their own
source and validation attribution. This patch makes no deployment, Android,
public HTTPS, model/native Session Runtime or total subscriber-capacity claim.
