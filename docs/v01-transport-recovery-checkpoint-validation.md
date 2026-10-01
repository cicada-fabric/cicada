# v0.1 transport / recovery checkpoint validation

Status: **bounded checkpoint PARTIAL; evidence ready for Root commit/delivery**
(2026-10-01).
Architecture v2.3 and product v0.1 acceptance remain **INCOMPLETE**. This note
separates implementation, process-level gates, native observations and external
Client acceptance. `CICADA.md` is unchanged; V64's bounded PARTIAL evidence does
not raise PASS counts or claim overall matrix completion.

## Source and delivery boundaries

The main worktree is based on the committed module checkpoint
`1547f2eb47094d2faa7fd0194008fcb3d45f8db0`; the reviewed eight-file contract
correction was already uncommitted when this documentation slice started.
Root has also applied 13 backup and two repair
files plus six native test/driver/document files and frozen the application code
for combined QA. Root subsequently applied three capacity test/driver/doc files
and the M4 startup/retained-review driver overlay. Those later patches leave Go production code unchanged,
but build/script inputs have changed; new-source incremental gates remain separate
from that preceding full suite.
The pre-QA [source record](../.cicada-data/combined-checkpoint-20261001/source-before.json)
identifies dirty `1547f2e`, Hub-build fingerprint
`750cc44753fe0e0a0c81b768866a2ae49d6a6e95124be746a217da650862b4b8`
and the v1.6.1 catalog below. The completed
[combined QA report](../.cicada-data/combined-checkpoint-20261001/report.json)
records the same before/after Hub fingerprint and 24 stable changed code/test/
script inputs. Documentation remained editable; the report lists changed
document hashes during the run, not an immutable full-tree snapshot. Root has
frozen the later inputs; the clean commit/image remain pending. A dirty build
must be identified by its actual source
fingerprint and file hashes, not attributed solely to its HEAD.

The later [incremental report](../.cicada-data/combined-checkpoint-20261001/incremental-after-capacity/incremental-report.json)
identifies dirty `1547f2e`, fingerprint
`6ab2d94a26dd41082f3177006095408b25d4e8c05cd54315db6c325be92eb5be`,
with stable before/after Hub inputs and 26 changed code/test/script file hashes.
Its SHA is `2b6334f9a2cff0f34a17f9dc07c941e7a4f8d35c77a44c52d23e8cc130bfd492`.
Server default tests pass 94 top + 67 sub, one package, four explicit skips;
server vet, contract, Python 8 + synthetic native-driver 10, shell syntax,
gofmt and diff checks exit 0. Capacity and the three Docker interop tests skip
in that default package run; separate actual Docker evidence retains its own
source. The 1,116/575 full suite is **not rerun or relabelled** for `6ab2d9…`.

The accepted **previous** clean Client delivery is
`4fb241b5e824eb752ceb85586089f44c408e1e7e`, source fingerprint
`31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2`,
contract `client-hub-v1.6`, wire `1`, software `0.1.0-dev`, catalog 55 operations.
Its [delivery metadata](../.cicada-data/next-checkpoint/closure-20261001T165647Z/clean-delivery/metadata.json)
pins the bundle and Hub/test images and records the exact-image disposable gate
PASS. Android and native Runtime on that image remain NOT_RUN in that record.
The older f4 Android receipt keeps its own Client commit/APK/image attribution.
Neither is relabelled as the new contract or transport acceptance.

The C4 full-suite result (1,105 top-level + 553 subtests, 27 packages, 12 skips,
0 failures) belongs to its **dirty** `31dc…` source on f4 and the
[C4 gate summary](../.cicada-data/next-checkpoint/closure-20261001T165647Z/gate-summary.json).
The clean delivery and dirty full-suite run share build inputs but are distinct
records. C3 permissions/topology failures and earlier f55/432f/native failures
remain in their historical reports. A skip is not a pass.

## Layered current evidence

| Layer | Observed evidence | Acceptance boundary |
| --- | --- | --- |
| Main combined regression | Root verified full Go: exit 0, 1,116 top-level PASS + 575 subtest PASS, 28 packages PASS, 12 skips, 0 failures. Vet, corrected writable-output build, contract v1.6.1/55 and Python contract 8 + native-driver 10 exit 0. Optional PQ run-2 race exits 0: 23 top + 36 sub, one package, no skips/failures; optional vet exits 0. QA records stable code/Hub-build inputs. | Bounded **PASS** on dirty `750cc4…` inputs only; later code changes need their own gate. Retain first build's read-only output-path **FAIL** and first optional PQ setup's missing `openssl/ssl.h` race/vet **FAIL** before tests. A skip is not a pass. |
| Later capacity/driver integration | Stable dirty `6ab2d9…` inputs pass server 94 top + 67 sub, vet, contract, Python 8 + synthetic-driver 10, shell/gofmt/diff. | Four default server tests skip; actual capacity PASS is the separate `c23ef9…` run. Earlier full Go and optional PQ remain attributed to `750cc4…`; no full-suite/native transfer to this later source. |
| Isolated PQ adapter | `acec068e0066f8ea5fcf5492c9854c369f25fc83`: 15 bounded gates exit 0; package/race each 22 top + 36 sub, no failures/skips. OpenSSL 3.5.9, pure MLKEM768, ML-DSA-65 authentication, TLS_AES_256_GCM_SHA384, ALPN http/1.1. | Independent package source only. Main integration has a separate teardown failure below; this PASS is not product TLS or blanket main acceptance. |
| PQ integration and repair | Clean `1547f2e` enabled-race attempts fail: first for missing fixture environment, second at process exit with SIGSEGV despite 22 top + 36 sub assertions passing. Stub passes 3 top + 13 sub. Separate repaired source passes standard and race, each 23 top + 36 sub, exit 0; current dirty main's optional race repeats 23 top + 36 sub with exit 0 and no skips/failures. | Retain historical integration and new setup **FAIL** records. Main result has its own stable-source QA receipt. The original focused negative control passed and does not prove the crash cause. |
| Client contract correction | Reviewed eight-file `client-hub-v1.6.1` patch: check, Python 8 methods/5 drift cases, catalog 2, server 6 top/5 CAS sub, race 2 top/5 sub, vet all exit 0; zero skips. | Actual `nodes.confirm` is `NodeControlKeyBinding`; list/revoke remain `NodeDeviceBinding`. No DTO/auth redesign or delivery claim. |
| Node backup archive v2 | Root verified the 14-file independent source/report and applied 13 code/document files, leaving migration consolidation here. Focused race passes 8 top + 4 sub. Full three-package run initially fails on a permissive `0755` CLI fixture; nodebackup/nodelock pass, and corrected owner-private CLI fixture rerun passes. | Synthetic archive/locking gates only; the initial full-run **FAIL** is retained. Product reconnect, production restore and reconciliation are not accepted. |
| Native G1 real-4 | Terminal **PASS** on its own dirty source: seven actual Codex CLI turns, two original Threads on separate Docker Nodes, offline ASK/outbound reconnect, exact ASK/REPLY receives, context witnesses, structural Control exclusion and Hub-blind marker oracle. | One physical host, controlled resume and loopback HTTP. B replies before its receive call; exact-receive audit separately verifies both messages. Queue records remain `CONSUMPTION_UNCONFIRMED`; this does not prove unattended consumption, current combined main, physical hosts or public HTTPS. |
| Native M4 attach/continuation | Attach-1/continuation and attach-2 deadline attempts remain **FAIL**. Attach-3 actual Android app UI pairing (emulator) **PASS**, exit 0, on final APKs: full pins, fresh preview, both checkboxes/native alert, confirm ACK and authorized positive-version `nodes.list`; current Node SSE authority passes. Seed and Join resume use the same UUID, but Join tool **FAIL**; no Endpoint/proposal. | **PARTIAL**: UI binding is separate from failed native Join. Post-failure local-record/context checks are NOT_RUN. Owned Node cleanup follows terminal failure, not wait expiry. Monitor proposal/delegation/application and physical Android remain NOT_RUN/unaccepted. |
| Independent Client | Reported 71 Kotlin/13 selectors, 5 offline UI, 55 JS, bounded encrypted directory/capabilities and four final-APK enrollment/RPC response-loss selectors; actual UI pairing and scope-read receipts are separately verified. Local adapters implement 38/55 operations with 17 closed. | Fixed `9a6a…`/`3cbe…` APKs and clean 4fb/v1.6 Hub; public/session intersection and server Guard remain authoritative. Native current Endpoint/Monitor positive, broader faults, physical Android and HTTPS are separate. |
| Capacity | Independent run-2 **PASS**, exit 0: actual TCP, one 1-CPU/128-MiB Hub, 64 synthetic Endpoints, two synthetic Nodes, 16 workers and 64 requests; 46 HTTP 200, 17 HTTP 202, one expected HTTP 429. Retain run-1 fixture-status **FAIL**. | **V64 PARTIAL (bounded sample)**; no global PASS or percentage increase. Independent dirty 4fb/v1.6 source, plain fixture HTTP, no native, physical or public HTTPS. This does not certify main capacity or the PQ adapter. |

### PQ failure and repair attribution

The independent adapter report is
`/home/zyf/CICADA_pqtls/.cicada-data/PARALLEL_REPORT.md`; its final source SHA map,
commands/log hashes, exact profile/negative cases, binary/runtime sizes and
16-connection resource sample remain attributed to that worktree.
The main failures and stub result are retained in
[the integration result](../.cicada-data/pqtls-integration-20261001/result.json).
No assertion count converts a nonzero process exit into PASS.

The separate repair addresses an identified OpenSSL nondefault library-context
thread-cleanup requirement. The original focused negative control did **not**
reproduce the teardown SIGSEGV, so this requirement violation is not a proven
root cause of that crash. The repaired C bridge calls `OPENSSL_thread_stop_ex`
before returning from context-using C calls and before freeing the nondefault
library context; serialized calls may run on different Go OS threads.
The independent [repair result](/home/zyf/CICADA_pqtls_repair/.cicada-data/pqtls-thread-stop-20261001/run3/RESULTS.json)
has SHA-256 `f622c116006e4c7a1f4c628e46115e4b77686984a813e12c9b00532c89ac15d8`.
It records dirty base `1547f2e`, `bridge.c` SHA
`5b2090b670a39e49b77db7c49e14b37eb80c581cb0ca303c8976f365c268b13d`
and `openssl_test.go` SHA
`80bd50dbc1c67a4a31dd7fa9c9e9e91f851a70f0b0bce3f0e082f59df187a72f`.
Pinned offline Go/OpenSSL tests run as UID 1000: focused original and repaired
exit tests each pass, repaired standard and race each pass 23 top + 36 sub with
exit 0, and vet passes. Main combined optional run-2 separately repeats race
23 top + 36 sub and vet with exit 0 in
`../.cicada-data/combined-checkpoint-20261001/pqtls-evidence-run2`;
its earlier setup run failed before tests because the include path could not
find `openssl/ssl.h`. Corrected mount paths fix that setup; they do not explain
the historical teardown SIGSEGV. The combined report SHA is
`c3ccc85b13a94207b583f0effea3097cbc5bb4bfd9cefaf8aecdfd967c3e9c38`;
main race log SHA is
`2350bb6a528ed7bd42e7593af6352c55f684bff90a6b4de05904baa3e5406199`.
Corrected build output SHA is
`5d19249c9b2106e1943c9051a66f35de759d33370234af0cb6c0c40f111654c0`.
These results do not transfer to later changed code. See the
[adapter decision and lifecycle limits](pqtls-openssl-transport.md).

Even a repaired module PASS leaves Hub/Node production listeners, certificate
enrollment/rotation/revocation, current binding/epoch Guard, Client transport,
arm64 execution and public HTTPS unaccepted. A terminating TLS proxy is a
plaintext trust endpoint. Application NodeControl/Endpoint E2EE remains separate.

### Contract source

The contract-only source fingerprint is
`dd6d06d7055c846efe39d4d5f477ab6318650f47cd2a0741be861d14c1396bb4`
(dirty `4fb241b` base). Its source map/report/gates are in
`/home/zyf/CICADA_client_contract_fix/.cicada-data/CONTRACT_REPAIR_REPORT.md`.
The 55 operation definitions/roles and wire framing are unchanged. Changing the
catalog revision header changes its raw SHA from `1ef2723f…` to
`6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b`.
The initial regression compile failure (zero tests executed) is retained; only
the corrected frozen-source gates passed. Root owns the new package/image export.

### Recovery boundary

The accepted independent [backup report](/home/zyf/CICADA_node_backup/.cicada-data/writer-root-focused/report.json)
has SHA-256 `77bb2223a9c864025b29922f686dcd64e83a03de68e4ca65911a8b6461a3fb80`
and identifies its 14 uncommitted files on base `4fb241b`. Root verified those
hashes before integrating 13 files; the migration note is consolidated here.
The focused race passes 8 top + 4 sub. The full three-package run exits 1 on
the CLI test's `0755` WriterRoot fixture; nodebackup and nodelock pass in that
run. After explicitly making only the synthetic fixture `0700`, the full CLI
package rerun exits 0. This retained failure is not a production permission
repair or a retroactive full-run PASS. The combined main run is separate.

Archive v2 includes the Node-wide provider-admission and native-history SQLite
sidecars, `.native-writers` and `nodes/.locks`, under a common WriterRoot lifetime
fence. Agents share the writer-root lock; offline backup/restore needs exclusive,
nonblocking ownership. The archive does not make executing claims replayable or
discard missing admission intents, generations, writer epochs or replay counters.
Pending restores and legacy missing fences stay quarantined. There is no product
clear-quarantine/reconnect command yet. Preserve the original state and use an
explicit, exact reconciliation/stop fence before future reconnect; recreating an
empty sidecar or resetting counters is not recovery. Scope and operator
constraints are in [Node backup and WriterRoot recovery](node-backup.md).

### Bounded capacity source

The independent [run-2 result](/home/zyf/CICADA_capacity/.cicada-data/hub-bounded-capacity-20261001/run-2/result.json)
SHA is `95edb38c0d69445e75a24e5bf332ede9896fbce81bdd00608ea58fc88c7da6c1`.
It identifies dirty `4fb241b`, Hub-build fingerprint
`c23ef957d5520bfacfa433133d94a73e12cc29eb54c2cf4acc6ab45ad4689d84`,
Hub image `sha256:18494052f1047197b259ea075b202d7f37b68eb5218f0833a7fffa6fcb214e07`.
The 64-request sample reaches 16 in-flight HTTP workers with 46 directory reads,
17 ASK submissions and one SEND. ASK admission accepts 16 at the sender limit
16 and rejects the next with 429/Retry-After 1; p50/p95 are 276.425/694.536 ms.
The Hub stays running under one CPU and 134,217,728-byte memory/swap limits;
host `/proc` VmHWM is 33,464 KiB and Docker reports no OOM kill. Four later HTTP
calls observe `CANCEL_REQUESTED`, `REPLIED` and an exact retry `OPEN` after slot
release. These are protocol states, not confirmed process stop or model receipt.
Run-1's `active` versus `online` fixture assertion failure remains retained;
only the corrected fixture/arithmetic run passes. Synthetic callers, one Hub
and one SQLite state cannot establish sustainable fleet capacity, real native
sessions, physical Nodes, current main or PQ transport overhead. V64 becomes
PARTIAL for this sample; the PASS count and overall completion do not increase.
The integrated [capacity report](hub-bounded-capacity-validation.md) preserves
both source/image identities, named Go-test lifecycle and owned-resource cleanup.

### Native terminal provenance and Client receipt boundary

Native real-1 failed for missing config before model execution; real-2 failed for
invalid disabled-MCP config before model execution; real-3 ran three actual turns
and seed witnesses but did not call Join, so it failed. Real-4 uses Codex CLI
0.159.3 and direct, narrow, required MCP startup preflights with two original
Threads on two Docker Nodes at one physical loopback host. Its terminal
[result](/home/zyf/CICADA_native_e2e/.cicada-data/native-two-node-real-4/result.json)
SHA is `74e83ccaa17a6c862e2047b492bccfc6e61f426fb843404d298c6dfb7e3624bc`.
It belongs to dirty `4fb241b`, source fingerprint
`bc6def6eef27ffeddde5351fe8a3b280fbfeae186c0e0d007ccd7fa724490841`,
Hub image `sha256:20bde71f1284de269561116a8ec5f71a2d1f0c930e8593f6cf2880d509892da9`,
CICADA binary SHA
`b6bd1a92ebf7876363ec56550b87d8f340412260c35c737e0c54b7f8caf0c16b`
and driver SHA
`2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86`.
Seven actual CLI turns retain the original local session records and context
witnesses. Both exact sealed messages are independently present in completed
receive tool results without error, as verified by
[the exact-receive audit](/home/zyf/CICADA_native_e2e/.cicada-data/native-two-node-real-4/exact-receive-message-audit.json).
Its SHA is `aee1c01612498b2fc0fc3eb868abac33ad709161f8cc32176c09d5356a688551`;
the completed-tool/order audit SHA is
`29948fdab46a36dd5d4c3324dee2e7944ef8db4d6d43104ccdb4ceb64b039daf`.
B called reply before receive, so tool order is not a receive-before-reply proof.
The durable records remain `CONSUMPTION_UNCONFIRMED`; do not replace that state
with ACK/confirmed consumption. Separate Node namespaces deny Hub-to-Node and
Node-to-Node inbound paths. Production `--fabric-only` records zero Control
business calls structurally (Control is not constructed), with authenticated
management HTTP 503; invocation counts were not instrumented. Hub database,
WAL and log marker checks remain blind; no Node keys/provider credentials are
mounted into Hub. Owned resources were cleaned. This does not transfer to the
new contract, adapter, backup or current combined source.
The native owner's [public report](v01-two-node-native-validation.md) is now
integrated by Root with six test/driver/document files. Their frozen patch is
separate from the earlier executed driver and Hub source; Root owns separately
attributed test overlays. M4's first coordination failure and attach-2 deadline
failure remain failures. Attach-2 had zero model calls, no confirmation and no
Runtime evidence; its own Node/keys were removed before Client UI. A read-only
Client preflight subsequently passes. Attach-3 uses a new Node/key and retained
fixture; a ready file is coordination, not authorization.
Its earlier UI failure preceded preview (test utility/IME handling), without
confirm or model evidence at that point. The original controller was terminated
with SIGTERM
143 for an explicit retained-resource handoff; no Codex log/session-before or
proposal existed then. Validated takeover and post-proposal `WAIT_OWNER_REVIEW`
do not prove approval. The later actual Android app UI run in the emulator
separately passes reviewed
full Node/Hub pins, fresh preview, two checkboxes and native confirmation alert,
confirm ACK and authorized positive-version list on the unchanged final APKs.
The current Node's SSE authority check passes. The actual seed and Join resume
use the same native UUID, but Join returns actual tool HTTP 404 with a
44-byte public error, not a provider failure. No Endpoint or Monitor proposal
is produced. The owned Node is cleaned after that
terminal failure; this is not wait-deadline cleanup. The seed has an exact local
session record/context witness; the failed Join short-circuits its subsequent
local-record/context assertions, so those are NOT_RUN. Two actual CLI turns
do not establish complete post-Join context continuity. No paid retry is claimed;
`internal/fabric/service.go` rejects direct Group Join by a new native session
without an existing Endpoint when that Group has a Network ID. The fixture
omitted native Network enrollment. The current-APK read-only encrypted snapshot
check passes without `topology.apply`: both saved Groups are ACTIVE on the same
nonempty ACTIVE Network with unchanged version 1, and the snapshot Owner matches
the enrolled synthetic Owner. Its
[redacted receipt](/gpu1-share/data/cicada-client/v16-deterministic-offline-management-20261001-final/android/group-scope-current.redacted.json)
SHA is `0833612aae9512bb86c4e9ddd90d85d93063f968e58fdc8f7765e170031efe94`.
It does **not** assert/export each Group's owner field; phone list evidence also
does not export each Node's owner field. Exact 404 branch attribution therefore
remains qualified; no Hub DB is read. For a Network-backed Group, the required
sequence is explicit Network Join,
Owner-approved Group admission, then same-original-Thread Group Join; Node
pairing or Network identity registration does not grant Group traffic authority.
No guard weakening or paid model retry is accepted by this record. The
[terminal native result](/home/zyf/CICADA_native_e2e/.cicada-data/m4-native-attach-3-controller-2/result.json)
SHA is `bb44440bcd8f3a0a13f0d51a22f2a55fa208be99b3ec68885d360ae3dae229b3`,
and the [sanitized classification](/home/zyf/CICADA_native_e2e/.cicada-data/m4-native-attach-3-controller-2/join-failure-classification.json)
SHA is `9beb504c287c81c9734ea445771760178f2530578fbbf6dcfaddbe7bbe9e5e03`.
The [controller execution receipt](/home/zyf/CICADA_native_e2e/.cicada-data/m4-native-attach-3-controller-2/controller-execution.redacted.json)
SHA is `b26d1f918644f98b079546e656e43ab2ba4d9f40247b915ef5dec3bb79a70ffe`.
It records terminal exit 1 witnessed in the original tool response; the exact
controller argv was not retained in the artifact. No reconstructed command is
presented as the executed command.
The executed M4 driver SHA is
`8a7b21321ab813b26af87eb6bda679d76176719c2afa300ba073daad8c919e78`;
shared driver SHA remains `2979b546…` from G1. Its source is not silently
relabeled as the later integrated driver overlay.
The [actual UI pairing receipt](/gpu1-share/data/cicada-client/v16-deterministic-offline-management-20261001-final/android/node-pairing-ui.redacted.json)
SHA is `b9b26faea3d2ecdfc7469898892a684097717be8a662ec70641956fd16a35815`.

The reported Client APK SHA is
`9a6a6f03a72b73b769d4df6824e4a6926adc92523b1641f895789f4de97cc12e`,
test APK `3cbe5861146a1c2dfd1f1c676340a469b97e9526215d4c141875372ed685fcd1`.
The [independent Client report](../../CICADA_CLIENT/docs/client-hub-v1.6-4fb241b-management-validation.md)
identifies its dirty Client source fingerprint
`36ceac796e22c6516096f07bc1979928b8627efc3a90398b6789dd28c3ec2413`
over 110 files on Client base `9cf2b81`. It reports 38 local operation adapters,
17 closed, and an external-role intersection allowing exactly 30/38 against 47
advertised operations; availability is not caller authorization. Earlier APKs,
two-Group checks and the old f4 Client's 35/20 counts retain their own source.
Its still-historical expired attach-2 candidate and DTO discrepancy are not
attach-3 acceptance or an imported v1.6.1 contract. The actual current UI
pairing and read-only scope receipts above provide the later bounded acceptance.
These results do not deliver a new contract revision or
blanket 55-operation/Monitor/native acceptance. Existing Client fixtures remain
immutable. No Android files or running native fixtures are modified by this note.
The Client's next target-Membership preflight correction requires its own new
APK/build/tests; none of these `9a6a…`/`3cbe…` results transfers to that work.

## Ordered remaining work

1. Commit the reviewed bounded source/evidence without transferring older
   full-suite/native/Client results. Root owns the new clean package/image and its
   exact-image disposable gate; no transfer from C4 or an independent worktree.
2. Wire direct Hub/Node PQ TLS with dedicated certificate/pin enrollment,
   chain/SAN/algorithm/profile checks, mutual auth, rotation/revocation and
   request-level current owner/binding/epoch Guard. Separate isolated fixture HTTP
   from production exposure; credentials do not make plaintext HTTP safe.
3. Add explicit post-restore reconciliation before clearing quarantine or
   reconnecting; prove sidecar/ticket/key/counter consistency and confirmed-stop
   fencing without deleting legacy state or automatically replaying uncertainty.
4. In the separately owned next v0.1 slice, connect native Join/renew to automatic
   directory-only Network identity binding through the existing API/helper,
   followed by explicit Owner Group admission and same-Thread Group Join. This
   is planned isolated work, outside the frozen `6ab2d9…` checkpoint; it adds no
   API roles, Group grants or traffic authority. Retain the failed original run
   and uninstrumented 404 attribution. Complete current-source native G1/M4 and
   independent Client consent/Monitor fault/revoke cases. Keep one-host Docker,
   physical devices, public HTTPS and
   busy unattended wake as separate outcomes.
5. Review the independent bounded protocol/load gate on its own source. Later
   run product transport/restore capacity and physical/public deployment gates
   after their prerequisites. V64's bounded PARTIAL sample is not a global PASS.

These are v0.1 closure steps, not permission to broaden v0.2 scope, push/release,
replace resident deployments or rotate real keys.
