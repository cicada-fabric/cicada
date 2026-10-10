# Native next checkpoint — 2026-10-10

The latest bounded Native diagnostic E3 remains **FAIL/QueueOracleError** at
`managed_hub_blind_terminal_oracle`, with `WRITER_EPOCH_STALE`. Five actual turns
completed the original A/B context and exact correlated reply predicates;
all eleven response observations were HTTP 200 / HEADER_ACCEPTED. Those scoped
witnesses do not turn the terminal FAIL into Native acceptance. Production
Control was absent (`NO_CONTROL_BUSINESS_OBJECT`, `dependency_proven=true`),
with authenticated management HTTP 503; restore/status-query acceptance is open.

[Actual E3 result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-rspmeta20261010e2/request-observer-native-result-cicada-two-turn-g1cli0162rspmeta20261010e3/result.json) SHA-256:
`b7e80cace4eccad0d58d0905e0399b557dfcb25c1d997d595aaaa3ba7ea5a262`.
[Independent cleanup/pins postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/INDEPENDENT-POSTCHECK.NONAUTH.json) SHA-256:
`5a6c03671dff8fcd4a8342875bac5f582ec16b1796b26d672b960db48b01adbf`
passed both EOFs, fifteen owned selectors, full source pins and six unchanged
residents. Its status is cleanup/pins PASS only, with actual Native FAIL retained.

[Source and receipt chronology](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/WRITER-EPOCH-ROOTCAUSE-AND-MINIMAL-PROPOSAL.NONAUTH.json) proves the test-only mismatch:
QUEUE_ACCEPTED was committed under writer epoch 1; publishing the exact remote
receipt reacquired the real native writer at epoch 2. NativeOperationOutcome
preserves the accepted historical operation. The terminal Python oracle wrongly
required the historical commit epoch to equal the latest acquisition epoch.
The test-only historical queue predicate is now implemented. Five selected
[offline checks](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/rspmeta-terminal-diagnosis20261010e3/HISTORICAL-QUEUE-SELECTED-QA.NONAUTH.json)
passed (0 skips/failures, 0.716s), receipt SHA-256
`f14813e9ba9b4a6300e6df2d3a455c23cd0315408ae9eb7fa993542501084f8a`.
The retained E3 strict verifier still rejects WRITER_EPOCH_STALE; historical
receipt acceptance does not grant current writer authority or prove consumption.
Production fencing is unchanged. G2's selector is not activated; any reuse of
this predicate for G2 needs source-backed scope and offline checks first.

Fresh queuehist10f1 zero preparation now actually passed
PREPARATION_PASS_NATIVE_NOT_RUN, with zero model calls, turn/event starts and
paid submissions, using binding
`173ee23fe6205be758d7730c6ddcf3264a2d6e4c8c47dea93c5c8086da884827`.
[Actual zero](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-queuehist20261010f1/native-preparation-cicada-two-turn-zerocli0162-queuehist10f1/result.json)
SHA `baac7a365a37c2c6f52d1fd4e08b750b7dbbd03c2f114a4b253f0c080d732462`;
independent cleanup/residents SHA
`27b1f8468eb63445e7bbbcfe458841eb7e67fc0ddc5e0d89bcb8f7e02ad167b5`,
full pins/counters SHA
`9432055265f89d5ada67fbe195dbb7da88da4611704ae733bf729bd9c105673a`.
Two EOFs, fourteen owned selectors, full source/compiler/wiring pins and six
resident snapshots passed independent postcheck. This is preparation only,
not new paid Native acceptance. Root's separate five selected checks passed
in 0.282s with the absolute binding path/SHA; the initial relative-path
CURRENT_BINDING_PARENT failure before tests is retained separately.
The dynamic clean G1 launch helper is prepared **NOT_GO**; the fresh
current-source real G1 gate is **NOT_RUN**. Zero preparation creates no model GO.

E3 artifacts retain clean product origin
`631666c8f86349e1b1e81c318f324c7897588683`, product SHA
`3baf7bfbd217ac3d24be0fb3f41dfe5797ffc17a38f1f6c2b79dbe3b1209efae`,
Hub image `sha256:c87cf47a3ed1b48832a3ec638d98f2f3359d1e6cd2dd06b51cf80de3989e066b`
and Runtime image
`sha256:e9690980b153132186780c66126a78b98ed87c3d5e99abf3303b6277e48f697e`.
These differ from later repository source and both the clean-b06 and dirty-b06 Link images.

Fresh source-bound zero preparation passed; next validate G1; G2 denial and G3
authenticated encrypted restore remain separate gates. Current Android, remaining native Runtime scopes, physical-device
and public-HTTPS acceptance require independent evidence. No new paid PASS is
claimed. Overall v0.1 remains **PARTIAL**.

## Historical repaired-source G1 and response rejection

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

Offline verification and the existing response metadata adapter are now
implemented, as recorded below. Paired synthetic responses retain the same
refusal codes or forwarded bytes. The next preparation is a fresh source-bound
zero and independent review; diagnostic Native remains NOT_RUN, with no GO.
The parser, guard, budgets and oracles are unchanged, and no new Native run
follows automatically from this diagnostic.

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

| Frozen tested timeoutabi10d2 evidence | SHA-256 |
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

## Historical response-metadata preparation — then NOT_RUN

At this earlier preparation checkpoint, before E3, Root authorized only the tracked gate/checker
repair. The selected G1 Peer instances now install a small diagnostic adapter
when actual native_config receives run_native=true, native_https=true and
closed_failure_diagnostics=true. Actual run.py maps the existing CLI diagnostic
flag to that last field. All other modes, including G2 and zero execution,
retain their previous behavior.

Each handle_bound call owns a threading.local context with its frozen,
parent-bound Association and its own returned RealGuard. connect enables only
that Guard's existing response metadata parser before its first recv. Native
response_metadata remains false, inherited handle_bound is unchanged and no
shared response_guard is written. A broker has one synchronous owner handler;
A/B owners are separate threads. Tests additionally interleave handlers on one
instance to confirm TLS isolation. Original binding, validation, exceptions,
16 connections, inherited wait default180 and 600/30/30/660 budgets are retained.

Sidecars contain only fixed schema/ordinal labels, response-status integer or
null and existing rejection enums. The ordinal means **observation**, never
admitted connection. Only a validated io_sink callback sequence provides the
handler's Observer association; missing, invalid or repeated sequence means
UNKNOWN. A noncallable original sink prevents installation. Each Node has at
most sixteen records, each at most1024 bytes, with mode0600 and exclusive create.
Counters are bounded and locked; diagnostic failures become observable UNKNOWN
without replacing a successful event or the original Native exception. No
headers, body, tokens, exception text, private paths or new parser are captured.

Four selected metadata checks and the retained actual Peer/migration timeout
ABI regression **PASS: 5 tests, 0 skips/failures, 1.165 seconds**, under denied
external effects. Coverage includes seven off/on Guard equivalence cases,
original exception/event identity, diagnostic write failure, no Guard/sink,
duplicate/invalid sequence, idempotency, the record bound, A/B and same-instance
TLS isolation, actual CLI-to-namespace mapping and the ABI's twenty subcases.
The ABI test derives its current in-memory entry by the same sole PUBLIC_GATE
pin substitution; its historical saved wrapper and DTO remain unchanged.

| New offline source/preparation | SHA-256 |
|---|---|
| Gate | `be01d48cd4b26f7aa4d8d09e4c621ac6cc6f294006c1be8131bd73dfa79ee9d9` |
| Checker | `318c8e75d9065683299813a721920b11bee7514f65154a4cad980cc26501d8c5` |
| Fresh binding | `6f4ebf82ddf730756f02102880a154d91688bdb6768ae30318f6e2ab0196e5ea` |
| Selected QA | `a842c5cd85139a8cc52196f3bb4a998892eb1004c5cea9c5b774a09da637c519` |

The fresh binding was generated and fully rechecked by the unchanged existing
program in ignored `bundle-rspmeta20261010e2`. Product/helper/Runtime artifacts
retain clean631 attribution and CLI remains0.162.1. The earlier full47+2 QA and
actual FAIL remain attributed to timeoutabi10d2, not this new source. This
adapter has **NOT_RUN** Native diagnostic status and no GO. A fresh zero,
independent postcheck and separately reviewed bounded execution would be needed
before any new paid diagnostic; no model or Docker was launched for this repair.

## Historical zero preparations and execution bindings

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

## Remaining gates after E3

Fresh source-bound zero preparation passed; next validate G1; G2 denial and G3
authenticated encrypted restore remain separate gates. Current Android, remaining native Runtime scopes, physical-device
and public-HTTPS acceptance require independent evidence. No new paid PASS is
claimed. Overall v0.1 remains **PARTIAL**.

Earlier six-turn and denial-tail failures, old bindings, zero preparations and
artifact identities above retain their original scope. No historical receipt
is rewritten by the terminal-oracle correction.
