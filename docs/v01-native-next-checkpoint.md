# Native next checkpoint — 2026-10-10

Native acceptance remains **PARTIAL**. The timeout ABI fault is reproduced and
repaired. Fresh zero preparation passed independent review; Root then ran one
real G1, which failed after 180 seconds with RuntimeError at terminal Native
audit. The earlier TypeError is absent. No follow-up paid retry is authorized.
Root supervises the user's existing bounded-testing authorization; no duplicate
credential or user approval is required. Existing dirty work and historical
receipts are preserved. No Client source was changed.

## Latest repaired-source G1 and remaining response rejection

Root's single `cicada-two-turn-g1cli0162timeout20261010d2` exited 1 after 180
seconds. Actual status is **FAIL/RuntimeError** at
`original_managed_join_and_context`; failure_origin is
`<effective-request-observer-audit>::audit:60`. There is one paid submission,
one actual started turn and one started event. Result SHA-256:
`80233230d37336feba2b8756181e565ddcf7e1001a7862aafe4cb657afbe9647`.

A admitted two Host broker connections; B admitted none. Broker event statuses
are FORWARDED and UNKNOWN_UNSUPPORTED. The second connection records
CLOSED_FAILURE/READ_HEAD with shutdown_requested=false. This phase means the
**upstream response** path: `Observer.handle:784` calls `Reader.until`, whose
recv reaches `RealGuard`/F1 `GuardedSocket.recv:193` and its response validator.
The client request head was read earlier in READ_REQUEST. Origin pair counters
show 3794 bytes received from LOOPBACK and sent to UDS, and 50176 bytes in the
reverse direction; these counters do not prove a parsed response head or status.
An origin UDS receive reset (errno104) followed the recorded READ_HEAD failure;
neither pair is upgraded from STREAM_IO to DRAINED.

The fixed refusal code narrows the candidate rules to response status invalid
or non-2xx, trailer/upgrade, nonidentity encoding, sensitive header or token
echo in F1, or subsequent Core status-line/transfer-encoding rejection. It does
not identify the actual rule. Existing `native_broker.RealGuard` has safe
response_status_code/response_rejection enums, but actual `PeerNativeBroker`
sets response_metadata=false both in its constructor and in connect. Its
handle_bound returns before emitting a response-metadata sidecar. HTTP status
in the Native safe error is null; no current Provider403, quota or account cause
is established. No response-head bytes or sensitive payload were exported.

Actual config/read and ThreadStart projections for A/B retain
approval_policy=never, approvals_reviewer=user, model=gpt-5.6-luna and
model_provider=basil. Actual A turn/start retains never/user/gpt-5.6-luna.
The RPC journal contains zero approval request methods; cicada_join has one
started and one completed tool item. Historical automatic-review failures do
not describe this execution.

Both EOFs and cleanup are confirmed, with empty cleanup error classes. The
independent postcheck covers fourteen owned selectors and run labels, networks,
UDS and owner process absence, six unchanged residents, and all bound source
and compiler inputs. Root subsequently removed only the three recorded empty operator roots; its
cleanup receipt SHA is
`9de0aa28298a05a645b9d3fc5aae60744c031beaa6a0d8bbeb4546ec727b8735`.
Independent postcheck SHA-256:
`6fef835b1d226ce7fd843a5a91cbe92b5b157bc1efb99f4b7fb6917d1d656fe9`.
Its status is PASS_CLEANUP_ONLY; actual Native FAIL is preserved.

The next step is offline verification of the existing response metadata path
with synthetic response headers, comparing metadata-off/on refusal codes and
forwarded bytes. Any later proposed instrumentation should reuse those enums
and retain the same parser, guard, budgets and oracles. No observation change
or new Native run follows automatically from this diagnostic.

## Earlier actual G1 and proven timeout ABI root cause

Root ran exactly one `cicada-two-turn-g1cli0162origin20261010a001` with CLI
0.162.1 and the reviewed paid Peer wrapper. It retained c001's `--native-https`,
`--native-normal-seconds 600`, `--enable-closed-failure-diagnostics`, effective
source hashes and original oracles. Actual result is **FAIL/TypeError** at
`original_managed_join_and_context`, exit 1, with one paid submission, one
started turn and one started event. Result SHA-256:
`6cbac8acecfb9ef460fa7023eec20eef30b57017627b6c396f5980f2dc53e3ed`.

Actual Peer `wait_turn(..., timeout=None)` forwards None explicitly at derivative
line 787 after legacy `manual_turn` calls it without a timeout at
`managed_gate.py:631`. Inherited `migration.wait:214` calls `self.limit(None)`,
which reaches paid `bind_policy.limit:1181` and evaluates `min(None, left)`.
The inherited wait and automatic methods both default to 180. G2 already has a
separate timeout adapter and does not take this G1 failure path.

Pure-memory replay loaded the actual paid gate, migration and Peer class under
denied external effects, without calling a fixture constructor. It used only
the retained actual turn/start response's turn-ID projection. Actual manual_turn
reproduced TypeError after one request and **before RPC.check**; explicit 180
reached actual `TypedRPC.check:209` and preserved the same pending RuntimeError
object. Replay SHA-256:
`1009761ab91a9fb5826a28a7d15157906524040c90ad3f1845476b7bb6ecd945`.

The LIMIT failure was recorded in normal phase with aborted=false,
43,318,998 ns before A's fatal Native audit record. A later reported RuntimeError,
category other, null HTTP status, retry false and STREAM_DETAIL_WITHHELD. Both
Nodes recorded zero Host broker admissions and zero origin connections. The
harness fault is established; an initiating provider failure and the Runtime
error's cause are **not** established. Earlier replay omitted the actual Peer
layer and missed this ABI fault. Actual public failure_origin is null because
the terminal paid derivative filename is outside the fixed public whitelist.
No parser relaxation or additional traceback framework was introduced.

Both EOFs were EXPECTED_EOF_CONFIRMED, cleanup true and cleanup error classes
empty. Independent postchecks confirmed fourteen exact Docker ID/name selectors
absent, owned run-label queries empty, mapped UDS/daemon directories, origin
children and queue/provider sockets absent, broker/relay owners stopped and all
six resident ID/image/PID/restart/start/status records unchanged. Three operator
roots remain empty private directories; retained aliases have absent targets.
Full source/artifact inputs were rechecked. Postcheck SHA-256:
`ded763aa8d53ee03ee3f18963753b92215fca32c8e5704933ac91af7423333cd`.
Cleanup does not upgrade the original FAIL, whose bytes remain unchanged.

## Implemented repair and offline QA

Root authorized a small G1 adapter at tracked
`scripts/native_observer/request_observer_gate.py::load_gate`. None now omits
the inherited wait/automatic timeout argument, preserving actual default 180.
Numeric timeouts pass through unchanged. Existing G2 handling, absolute
normal/terminal/cleanup ends, guards, parser, retries and original context/reply
oracles are unchanged. The existing safe catch projection in
`request_observer_run.py` remains unchanged; it exports no exception message,
locals, private paths or payloads.

Tracked regression uses actual Peer/migration/bind_policy methods and the
retained turn-ID projection. Twenty cases cover G1/G2 manual, wait and automatic
paths, None and explicit numeric timeouts, one-second remaining deadline clips,
original RuntimeError identity, exactly one successful Peer drain and expired
absolute deadlines before RPC checking. **Six selected checker tests and
eighteen binding tests PASS, zero skips**, under denied external effects.
This agent launched no Docker, Runtime or model during repair/QA.

Root subsequently ran the full wiring suite: **49 tests, 47 PASS, two explicit
SKIP, zero FAIL**, in 54.308 seconds with no model calls or Runtime launches.
The skipped retained A/B reply replays are not counted as passes. Receipt
`ROOT-FULL-WIRING.NONAUTH.json` SHA-256:
`244dab9745fd111de42d58e724a2bc5f28c87823756f06d9f274d3791ab6e605`.
This offline QA does not prove Native completion.

The first test draft loaded the DTO's old binding into shared legacy globals,
causing a later current-binding assertion. Its failed log is retained in
`bundle-timeoutabi20261010d`. The final test uses the selected current binding
while preserving the DTO's original provenance. Final bundle:
`bundle-timeoutabi20261010d2` under the ignored Native evidence root.

| Current frozen evidence | SHA-256 |
|---|---|
| Binding | `a9729fa7042557e302fac1c0af9337182a7bf8597e1b831b63bb664b9c84a6bd` |
| Tracked gate | `979f0e5493e9ca99b56c8d8782476705f8fe76b4efc62181a17ec17b853dc4a7` |
| Tracked checker | `e0966aec97060d665f9736662eb0ec6363bb493cc47bb77f0043699b98834eaa` |
| Unchanged tracked run | `b8eb1a6ae4041087ed24db551f5d99212b774afeab8f30ca2467575adebccce1` |
| Six checker tests | `d3ea3fadc159cb617881a0789a76232e4befdc67f426fd35076a577e4053ab44` |
| Eighteen binding tests | `d286900936f9c1e7d384e29b25029bbb5e2d8411a14c3cf9ee3c9601e2c1804b` |
| Full component recheck | `2dcf54c1ab780020f8117e544a320e98b14b46801c13a96d01f4ffc06feff5db` |
| Fresh paid entry | `d7d47aad22545409455aaca458c0b72c80828ac0fa93e25b09372d4fa4b01b3f` |

The fresh paid entry preserves the old 8003-byte wrapper except for one exact
64-byte PUBLIC_GATE hash substitution, explicitly mapped in its fresh manifest.
Historical Peer, phase-reader, broker, observer and paid-wrapper files are
unchanged. Full binding checks cover 84 rows and 457 product/220 helper compiler
inputs. No product rebuild or Runtime image replacement occurred.

Repository HEAD at this checkpoint is
`c9b2935da17167ce7694abaeffca22aaa0daa3f2`. Artifacts retain their tested clean
origin `631666c8f86349e1b1e81c318f324c7897588683`, separately from HEAD and the
changed Python harness. CLI remains 0.162.1, Runtime `e9690980…697e`, Hub
`c87cf47a…066b`, product `3baf7bfb…efae`, helper `6fb8777d…b58`, fingerprint
`d9ca7c7d…a5ad`. Local CLI/help was checked; no new Codex feature is required.

## Actual zero preparations and next execution

The **old zero actually PASSed**, exit 0, under binding `92c8a22a…33ccf`:
`cicada-two-turn-zerocli0162-origin10a01` in `bundle-origin20261010a`, result SHA
`d4cdd2724d63356a07bd28984db8a502018e2678c9f241d0697147a4e0db1b80`.
Both EOFs and all zero counters passed independent review. It belongs to its
original source and cannot satisfy the repaired binding's preparation guard.

At the initial ABI repair freeze, the **new zero was NOT_RUN**. Root subsequently
ran its single reviewed command with a one-time T0+300 absolute cutoff,
outer TERM310/KILL+15. Actual
`cicada-two-turn-zerocli0162-timeoutabi10d2` exited 0 in 34 seconds with
PREPARATION_PASS_NATIVE_NOT_RUN. Its result SHA-256:
`42cf3fa128c0743bb21b0e9af8318243c8a9bb979f90e76b221a469a9277b3ce`.
Independent postchecks now PASS: two actual EOFs; zero model, turn, event and
submission counters; cleanup true/errors empty; fourteen actual owned selectors
and run labels absent; mapped UDS/daemon directories absent; six residents
unchanged; full source/compiler/binary/preparation pins rechecked.
Postcheck SHA `92266ef97ed679ccd697d33d3a9bf3fb160862fad1085b8b018869021eedbbb1`;
review SHA `f52deb2b90d7dbf523ebd86d79980a0a8137282cf4481ab815cd6b95ee7fbd0d`.
This proves zero setup/cleanup, not paid provider parity or Native completion.

A preparation-bound paid manifest, exact typed GO schema projection and
operator argv were frozen in the same bundle as **NOT_GO / NOT_RUN**. The manifest
pins the new actual zero and independent review; the previous pre-zero draft
and all older receipts remain unchanged. No valid GO is created by preparation.
Root subsequently materialized fresh owned paths, bounded public DNS origin
receipt, absolute cutoff/expiry and its supervisory GO, then ran the single G1
reported above. The original preparation drafts remain historical NONAUTH
records; they are not reusable execution authority.

Keep paid transport flags, gpt-5.6-luna/zzswitch, workspace-write sandbox,
encrypted MCP, PQTLS, zero retries and original Thread/context/reply predicates.
Budgets remain 600/30/30/660 with outer690/KILL+15; G1 caps remain 5/3/2 and
accepted TCP connections sixteen per Runtime. EOF, network/tool success, queue
ACK and cleanup do not prove Native completion. No blind retry, new Thread or
budget expansion follows from a failure.

Existing `$CICADA_NATIVE_ENV_FILE` metadata is regular0600, parent0700, current
owner. Contents and key/account validity were not inspected. The real paid
Peer lane preserves Host broker-only credential access, with no credential or
private broker-root Runtime mount. The user need not provide credentials again.

## Other gates still open

Prior `cli0162120261010a002` completed six turns with original A/B context and
reply predicates passing, then failed its exact denial classifier. The retained
actual production DTO has failed/nonretryable status, absent isError and the
known Node Relay HTTP404. Existing exact classifier branch and offline replay
accept it; historical paid FAIL is preserved. Live denial-tail completion and
G3 authenticated encrypted Control restoration remain unproved.

Prior G2 c001 failed initial join/context with CLOSED_FAILURE/READ_HEAD before
shutdown. Retained evidence lacks response-head bytes and the exact rejected
rule; its unique parsing/provider cause remains UNKNOWN. The G1 None ABI fix
does not resolve or relax that guard. G1 still needs full same-Group Ask/Reply
and both original-session context predicates; G2 needs its full six-turn flow
and real hidden-member/revoked-Link tail. Mocks or new same-name Threads cannot
close these gates. Completion-runner metadata fixes, Android, physical devices
and public HTTPS remain independently attributed in the
[current closeout](v01-current-closeout-20261009-validation.md).
