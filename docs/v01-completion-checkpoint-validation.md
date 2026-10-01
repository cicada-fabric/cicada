# v0.1.x completion checkpoint (2026-10-01)

This report records a bounded backend/framework checkpoint, with each result
attributed to its tested source. Overall status is **PASS (bounded backend/framework checkpoint)**. Clean
artifact handoff identifiers follow the single checkpoint commit. It does not claim Architecture v2.3 completion,
Android v1.6 acceptance, a push/release or one source identity for all results.

## Final frozen code: 2858 (2026-10-01)

The final live Go/checker/test code is frozen at source fingerprint
`2858c57ec3bc33f5f4d03f4f8c75ec6c13f89fd128a3a8a493b7c7605af51e17`, dirty
`dev` base `bd79ff93c90ecafc28a2471dd9523444903b39e6`.
[Source metadata](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-final-source.json)
records code identity separately from documentation. Production code matches
54f; final changes correct three synthetic private-socket/absent-listener
fixtures and add two public synthetic cryptographic vectors plus strict checks.
Final full Go **PASS**: 27 packages, 1,092 top-level PASS + 547 subtest PASS,
12 top-level SKIP, 0 FAIL; vet EXIT 0. The three repaired fixture selector and
its race gate each passed 3 top-level + 3 subtests. Gofmt and diff checks passed.
[Final Go summary](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-test-repair-final-go/final-summary.json),
[JSON events](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-test-repair-final-go/go-test.jsonl),
[vet log](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-test-repair-final-go/go-vet.log).
Root independently counted events; source fingerprint remained 2858 before/after.
[Production equivalence](../.cicada-data/v01-finish-20260930T145216Z/production-equivalence-final-vs-54f.json)
confirms final production matches 54f; only three test files and two testdata
files differ, with no production embedding of those testdata. The 54f full-Go
three-fixture FAIL remains historical evidence, not a production Guard bypass.

Contract is `client-hub-v1.6`, wire 1, 55 operations; catalog SHA-256
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`.
Policy vector SHA-256 is
`aab0a7074fb32523f75bb89f9a61f4725d9f462c2d83eec33d23f79609fc5907`;
BROADCAST consent vector SHA-256 is
`c18b237047a6963b95844a1a32307794e6b353150313b77ab2ce84393b0ab8ea`.
Policy canonical input has eleven claims without signature; BROADCAST has twelve
claims including `signature:null`. TASK remains separate. Go e2ee full package,
seven contract-unit tests, including three new vector checks (26 tests in full Python discovery) and intermediate contract check/export/verify
passed before this final independent gate. Public vectors are available, but
independent Kotlin/current-authority/native consent/Android results do not follow
from synthetic vectors or catalog availability.

Final independent contract/Python/shell evidence is recorded under
`.cicada-data/v01-finish-20260930T145216Z/checkpoint-2858-contract-draft/`;
Contract check/export/verify PASS, stdlib discovery PASS26 tests and all20 shell
syntax checks PASS. Dirty bundle SHA-256 is
`9b252f0097a951973409df8254ee9567e491f1a162ceed251d4b2f3a27548004`; it contains
21 payload files plus manifest, including both new vectors. Each result JSON
records exact commands, exit codes, cwd and private log hashes. Documentation is
in the contract payload; this first dirty export retains its own bytes and is
not a final clean handoff. Root exports/verifies the clean package after commit. Final clean Git commit, exact clean Hub image and clean bundle
are obtained from fixed delivery directory
`.cicada-data/v01-finish-20260930T145216Z/client-v1.6-clean-handoff/metadata.json`
and `HANDOFF.md`; dirty gate packages are not the clean handoff.

### Separately attributed 54f gates

54f fingerprint `54f368f43ef6ede947cee452b47688654b38b37a4464d92caf5bc450727710c2`
passed vet, bounded Browser and three disposable Docker suites. Evidence:
[Browser](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-54f-browser/result.json),
[Client](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-54f-suite-client/result.json),
[Network M1](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-54f-suite-network-m1/result.json),
[Group Spaces M2](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-54f-suite-group-spaces-m2/result.json).
The full-Go run recorded three cmd fixture failures; see
[original output](../.cicada-data/v01-finish-20260930T145216Z/checkpoint-54f-go-full/go-test.jsonl).
One synthetic socket lacked private mode; two absent-Node Ask fixtures expected
REFUSED although production ENOENT is retryable UNKNOWN. The final fixture fixes
preserve Guard and original failure evidence. Socket focused/race and five-target
release builds passed separately; no release was published.

54f real native multi-Hub Join passed 160.92 s on CLI 0.159.3/gpt-5.6-luna:
three CLI turns preserve the original Session through Hub B then Hub A resume,
Hub pins/credentials/Endpoint/cache isolation, wrong-Hub token 401 and Control 0.
One container/OS user hosts two logical TCP Hubs; this is not two Hub processes,
physical Nodes, peer payload injection or provider request-count proof. Known
scope reuse remains a shared native-memory risk. This result is not transferred
to 2858. [Evidence](../.cicada-data/v01-finish-20260930T145216Z/multihub-native-54f-20261001T1230Z.json).

## Historical f55 and 432f candidate results

The historical f55 product candidate was read-only snapshot
`final-code-git-snapshot-20261001T102124Z`, fingerprint
`f55b5255628030857ac88bd7edbd6da7da1b63d543014c76111f9219f46ad255`, based on
revision `bd79ff93c90ecafc28a2471dd9523444903b39e6` with `dirty=true`. The
coherent snapshot metadata is
[here](../.cicada-data/v01-finish-20260930T145216Z/final-code-snapshot.json).
Its Hub image is `sha256:da88805eaa1987a1c6e06448fc5cddf7d4ce368e8b5eeb3071a1406dad2cb977`
([build metadata](../.cicada-data/v01-finish-20260930T145216Z/final-code-hub-build-20261001T102124Z.json)).
Catalog SHA-256 is unchanged at
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c` (v1.6,
55 operations). The source is a dirty bd79-based candidate, not a clean
handoff or released build. Vet, contract check and 19 Python tests passed on
this source. The full Go run and all three Docker suites have now passed on
f55. Evidence: [full Go summary](../.cicada-data/v01-finish-20260930T145216Z/final-code-full-go-20261001T102124Z.json), [vet](../.cicada-data/v01-finish-20260930T145216Z/final-code-vet-20261001T102124Z.json), [contract](../.cicada-data/v01-finish-20260930T145216Z/final-code-contract-20261001T102124Z.log), [Python](../.cicada-data/v01-finish-20260930T145216Z/final-code-python-20261001T102124Z.log), and the Client, [Network M1](../.cicada-data/v01-finish-20260930T145216Z/final-code-network-m1-20261001T102124Z/result.json), and [Group Spaces M2](../.cicada-data/v01-finish-20260930T145216Z/final-code-group-spaces-m2-20261001T102124Z/result.json) Docker results. The Client Docker result is [here](../.cicada-data/v01-finish-20260930T145216Z/final-code-client-20261001T102124Z/result.json). Do not attribute the previous candidate's Browser, M5, Node-Control overlay or real-runtime results to f55.

The preceding candidate was the read-only source snapshot
`repair-accepted-git-snapshot-20261001T094228Z`, with source fingerprint
`432f3971f51945a054d3519a9a1bbd197d987be20d998f4339df0df637737c21`, based on
clean `dev` commit `bd79ff93c90ecafc28a2471dd9523444903b39e6` plus dirty changes.
It is not attributable to that commit alone. The candidate contract declares
`client-hub-v1.6` and 55 operations; catalog SHA-256 is
`1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c`. This
contract identity is not a Client release or approval to consume it.

The disposable Client smoke test fixture and its runner were repaired;
Root supervised acceptance and did not author the fixture change. The independent Client-suite rerun passed on live source fingerprint
`cf168780319bee471fde350060d8c34f2e7c7e3ba598b942e67bcd4e78e33611`, with Hub
image `sha256:bde5f0090253e2d05e23d975351f5ddf2b80784dc491063f7ea20e732c84f123`
and test image
`sha256:d70832ad000f5359de6b839e11fd7dfe2dcd0344deebb9527e3f82aabe6dcef9`.
That result is not transferred to 432f and does not replace the failed
full-source Docker gate. Root's source comparison reports eight Go files
gofmt-equivalent to 432f; the source fingerprint and image nevertheless differ.

## Results on the preceding 432f candidate

| Gate | Result | Bounded scope and evidence |
|---|---|---|
| Full Go | **PASS** | 1,079 top-level tests and 535 subtests passed; 26 packages passed, 12 top-level tests skipped, zero failures. [JSON summary](../.cicada-data/v01-finish-20260930T145216Z/accepted-full-go-20261001T094228Z.json) and adjacent JSONL retain the exact run. |
| `go vet ./...` | **PASS** | [Vet record](../.cicada-data/v01-finish-20260930T145216Z/accepted-vet-20261001T094228Z.json). |
| Focused race | **PASS** | 20 tests across `cmd/cicada`, `internal/nodelock`, `internal/nodeinbox`, and `internal/store`; see [race log](../.cicada-data/v01-finish-20260930T145216Z/node-focused-race-432f-20261001T094228Z.log). This is not `-race ./...`. |
| Python and shell syntax | **PASS** | Python `unittest discover scripts -p 'test_*.py'`: 19 tests, zero skips. All 20 `scripts/*.sh` passed `bash -n`. The Python count excludes the separately counted release-script suite. |
| Contract and public vectors | **PASS** | Contract check reports v1.6/55 operations and the catalog hash above. Seven public-vector Go test names passed, including four crypto subtests. The fixtures are synthetic. |
| WebCrypto WASM | **PASS** | Production and interop Go WASM builds from the read-only snapshot passed; Node 24.16 ran `scripts/test-web-panel.mjs`, including production PQ/Wire and UI model checks. Generated artifacts were temporary. |
| Headless browser | **PASS, bounded** | [Browser result](../.cicada-data/v01-finish-20260930T145216Z/browser-v16-432f3971-20261001T095158Z/result.json): disposable Hub image `sha256:c3dcf3575309d07f336e0173fda2bf74adbba01ed729b2769d38fb4d9aabd597`; Chromium 151 image `chromedp/headless-shell@sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04`; Node 24.16.0. Hub pin, production WASM, encrypted IndexedDB vault/unlock, external Owner grant/device enrollment, encrypted topology/status/canvas, topology apply and cross-tab pending-write refusal passed. `uncertain_write_fence` is `NOT_RUN_NO_FAULT_INJECTION`. The fixture used a loopback secure-context override; public HTTPS was not tested. Owned fixture cleanup passed. |
| M5 bounded service gate | **PASS, same process** | Two production Fabric handlers/SQLite stores and the multi-Hub relay-only Agent were exercised over real TCP in one Go process. [Result](../.cicada-data/v01-finish-20260930T145216Z/repair-accepted-git-snapshot-20261001T094228Z/.cicada-data/m5-multihub-20261001T095507Z-1946487/result.json). This is not two Hub processes, isolated Docker Node namespaces, native execution, or Android. |
| Five-target release build | **PASS, separate identity** | The build's own fingerprint is `c411c70998426592ea4aa4c13da8f01308b9aac182ce482f8ad9214a9f343cc9`, not 432f. Five target builds and seven packaging tests passed with zero skips; see [build log](../.cicada-data/v01-finish-20260930T145216Z/accepted-release-build-432f.log) and [smoke log](../.cicada-data/v01-finish-20260930T145216Z/accepted-release-smoke-432f.log). No release was published. |
| Idle footprint | **PASS, one measurement** | On the 432f Hub image, a fresh idle instance measured 13,856,697 image bytes (~13.2 MiB) and 31,727,616 bytes RSS (~30.3 MiB), with no devices or native threads. [Private footprint record](../.cicada-data/v01-finish-20260930T145216Z/accepted-footprint-432f/idle-hub-20261001T095516Z-50558eab.json). This is not a load or capacity result. |

## Failed and not-run gates

The initial 432f three-suite Docker interop gate exited 1. Its `client`
sub-suite failed in `internal/server.TestClientDockerHubSmoke`: the old test
fixture posted the retired Node-pairing DTO and received HTTP 400. The
`network-m1` and `group-spaces-m2` sub-suites passed. The synthetic test fixture was updated to use the current PQ Node identity/proof and encrypted
Owner preview/confirm flow. A separate rerun used
`bash scripts/test-client-hub-interop.sh --suite client`; both `TestClientDockerHubSmoke` and
`TestClientDockerHubRecoveryFixture` passed on cf168. See the
[432f interop summary](../.cicada-data/v01-finish-20260930T145216Z/accepted-interop-summary-20261001T094228Z.json)
and [cf168 result](../.cicada-data/client-interop/20261001T100216Z-1968943/result.json).
This is a repaired fixture result on a different source/image, not a clean
re-run of all three suites on 432f. The full Client suite subsequently passed
on f55 as well; see its exact result above.

The joined V68 Docker gate **FAILED** in two retained attempts: one stopped at
`fabric_only_control_absent`, a later NAT-bridge attempt stopped at
`real_node_join`. See [first result](../.cicada-data/v01-finish-20260930T145216Z/accepted-v68/v68-joined-20261001T095253Z-1930337/result.json)
and [later result](../.cicada-data/v01-finish-20260930T145216Z/accepted-v68/overlay-20261001T1007Z/run-evidence/v68-joined-20261001T100729Z-1996718/result.json).
Cleanup was recorded. Neither run establishes the joined two-private-Node
scenario, and neither is reported as an external prerequisite BLOCKED result.

The later joined V68 driver **PASS** belongs to base 432f plus the reply-correlation test helper, fingerprint `840a2209dd38d94fff98772d4492a3ca1a7b7ff06dfa41d794c204c0017ce11a`, not f55: [result](../.cicada-data/v01-finish-20260930T145216Z/accepted-v68/overlay-reply-helper-20261001T112811Z/evidence/run-evidence/v68-joined-20261001T112831Z-2204008/result.json). Two real Node agents use separate private Docker bridges and one Hub. Outbound Node event streams returned 200; Hub-to-Node and Node-to-Node connections were denied, with no published Node ports. MCP Join/ASK/receive/REPLY, two Hub restarts, durable DB, same-message exact outbox retry, reconnect deduplication, wrong-ACK denial and Hub ciphertext checks passed. The queue is a recording fake, so this is real Node/protocol/topology coverage rather than native Runtime consumption. `TestV68ReplyCorrelationUsesRequestAndAskMessageSeparately` verifies REQUEST ID and original ASK message ID independently; production uses `RequestID == request_id` and `ReplyTo == original_message_id`. Exact labelled cleanup passed. Both earlier V68 FAIL records remain unchanged.

The first Node-Control HTTP protocol run on the preceding 432f evidence set **FAILED** at
`TestNodeControlV1HTTPProtocolFlow`; its temporary container was removed but
scratch cleanup was recorded as failed. A later [exact scratch-cleanup receipt](../.cicada-data/v01-finish-20260930T145216Z/accepted-node-control-432f/cleanup-node-control-root-cache-20261001T100649Z.json) records removal; it does not change the old FAIL result. A later independent driver overlay
(`87fa61f5…`) ran the same selector against product source 432f and **PASSED**
within `HTTP_PROTOCOL` scope. Its result is
[here](../.cicada-data/v01-finish-20260930T145216Z/accepted-node-control-432f/overlay-20261001T1012Z/repo/.cicada-data/node-control-v1-flow/20261001T101124Z-2005531/result.json).
This is production HTTP handler/SQLite protocol coverage with synthetic
identities; it is not an installed Node agent, native Runtime recovery, Android,
or public HTTPS result. Preserve the earlier failure at
[its original result](../.cicada-data/v01-finish-20260930T145216Z/accepted-node-control-432f/20261001T095507Z-1946485/result.json).

The first opt-in real Worker approval run **FAILED** with
`failed_stage=native_approval_not_observed` in
`TestMachineAgentBinaryRemoteApprovalEndToEnd`; that original record alone did not
establish why approval was not observed. The later driver repair and PASS are
recorded below with separate source attribution. This run is distinct from the browser, Go tests,
or the Node-Control HTTP protocol gate. See [native result](../.cicada-data/v01-finish-20260930T145216Z/accepted-native-worker-432f.json).

The composite `scripts/test-architecture-v2-completion.sh` has not itself been run as one unified gate. Full Go and all three Docker suites on f55 have completed. The new Node socket production fix needs a separately frozen full-source gate; joined V68 has now passed on a separate test-helper overlay; the repaired Worker-approval driver passed on 432f plus driver-test overlay. The following remain **NOT_RUN** at this checkpoint: Android against the v1.6
candidate; native peer acceptance specifically on f55; two isolated Hub processes with two outbound-only Nodes;
physical dual-Node testing; public HTTPS; browser uncertain-write fault
injection; capacity/stress; provider-specific real Runtime throttling; and
production process-stop/reconciliation. A native Worker approval attempt is
not evidence for native peer messaging. The earlier bounded Android v1.5
result remains attributed to its fixed bd79 Hub, Client commit/APK and protocol
package; see the [Client v1.5 report](../../CICADA_CLIENT/docs/client-hub-v1.5-bd79ff9-validation.md).

## Later bounded Browser and native peer results

f55 Browser **PASS** on the exact Hub image above: production Go WASM, Owner Hub pin, encrypted IndexedDB vault/unlock, enrollment, encrypted topology/status/canvas, topology apply and cross-tab pending-write refusal. [Result](../.cicada-data/v01-finish-20260930T145216Z/final-code-browser-f55/result.json) records cleanup PASS. Uncertain-write fault injection and public HTTPS remain NOT_RUN; pointer gestures are not independently asserted by the recorded steps.

Real Codex 0.159.3 same-Group cross-Node ASK/REPLY **PASS** (282.74 seconds) on unmodified 432f product/test source: [result](../.cicada-data/v01-finish-20260930T145216Z/native-cross-node-ask-reply-432f-20261001T101645Z.result.json). Two logical Nodes ran in one disposable container and used controlled safe-point resume. Original Thread IDs and old context survived; encrypted delivery and zero Control business calls were asserted. This is bounded G1/G3 evidence, not physical dual-Node or unattended cold wake.

Real same-Group broadcast **PASS** (298.14 seconds) on 432f product source plus the owned native test overlay: [result](../.cicada-data/v01-finish-20260930T145216Z/native-broadcast-pinned-fixture-owned-overlay/result.json) and [acceptance summary](../.cicada-data/v01-finish-20260930T145216Z/native-broadcast-pinned-fixture-owned-overlay/acceptance-summary.json). Both recipient original Threads accepted real native queue items, called scoped `cicada_receive`, consumed the broadcast and retained their initial context. Hub peer plaintext and Control business calls were absent. The test-only fix pins the bridge's trusted Hub/native-writer context using the existing helper; production and Guard were unchanged. Owned test SHA-256 is `976f928c836994aa2fb8e84220da0f329c476c1bb427f7727a06c76e8c63e18c`; test binary SHA-256 is `d07c88f650d558ea67ae73a864bad64a2b39bcd85ce2e71590e0ca062893e87b`. Cleanup removed the exact disposable container and its private CODEX_HOME tmpfs.

Preserve the [initial broadcast FAIL](../.cicada-data/v01-finish-20260930T145216Z/native-same-group-broadcast-432f-20261001T102300Z.result.json) and the [diagnostic overlay FAIL](../.cicada-data/v01-finish-20260930T145216Z/native-broadcast-diagnostic-owned-overlay/result.json): both preceded explicit native queue. Diagnostic children were two hard DELIVERY_REJECTED outcomes, two absent ledger records and two successful Hub local authorizations. The fixture had passed a bare context to the bridge; `recordLocalNativeContext` correctly rejected missing pinned Hub/WriterRoot/WriterScope. A zero-model regression demonstrates bare-context rejection and pinned-context acceptance. Neither native PASS transfers to f55, Android, public HTTPS, multi-host deployment or cold wake. Root supervised this work; the native acceptance agent authored the owned-test change.

Worker approval's earlier `native_approval_not_observed` FAIL remains retained evidence. The driver passed a host workspace path where the container only mounted `/workspace`. The repaired actual-cwd/same-path mount driver passed `TestMachineAgentBinaryRemoteApprovalEndToEnd` on immutable 432f product source plus a Go-test driver overlay: **PASS**, 76.83 seconds, exit 0; [result](../.cicada-data/v01-finish-20260930T145216Z/worker-approval-cwd-fix-432f.json). Codex 0.159.3/gpt-5.6-luna exercised the actual Node binary, PQ Owner-confirmed enrollment, sealed NodeControl, exact original Thread and approval attempt 1, Client-path command approval acceptance, target-file write, Worker completed and Intent resolved. This is real native execution/approval evidence, not Android or public HTTPS. The initial new-driver NameError occurred before Go/model execution (zero calls), was repaired and retained as a separate driver failure; the one effective real attempt passed. Provider failure is not established, and the old FAIL is not rewritten. M5's earlier EXIT 2 argument failure and EXIT 1 long-Unix-address fixture failure occurred before model calls (zero model calls); retain those attempts separately from the new production socket fix and its pending source gate.

V34 remains PARTIAL: runtime `recordMachineNodeProviderOutcome` emits only COMPLETED, FAILED_NOT_INJECTED and INJECTION_UNCERTAIN. The ledger supports rate-limited/retryable not-injected classes, but the actual runtime does not emit them. `ProviderAdmissionOutcome` currently lacks Attempt; an old-attempt fence and tests are required before structured retry is enabled. This is a future activation safety gate, not an observed runtime cross-attempt failure, and this checkpoint does not expand implementation scope. Real provider throttle/backoff remains NOT_RUN.

The bounded real M5 Join gate later **PASS** belongs to source `54f368f43ef6ede947cee452b47688654b38b37a4464d92caf5bc450727710c2`: `TestMCPSealedNativeThreadJoinsTwoIndependentHubsNative`, 160.92 seconds, exit 0; [result](../.cicada-data/v01-finish-20260930T145216Z/multihub-native-54f-20261001T1230Z.json). Codex 0.159.3/gpt-5.6-luna used three CLI turns: create original Thread, resume Join/whoami on Hub B, then resume Join/whoami on Hub A. Exact Session remained unchanged; origin/pins/Node credentials/Endpoint/cache stayed isolated; a wrong-Hub token returned 401; known scope count moved 1→2 with shared-memory risk explicit and Control business calls zero. Replay metadata was synthetic and isolated. This was one container/OS user with two logical TCP Hubs, not two independent Hub processes or physical hosts; it did not inject peer payloads or measure provider request counts. It does not transfer to the later source after test/vector changes.

## Remaining delivery and acceptance

The final frozen code is 2858 above. Full Go/vet and independent dirty contract/Python26/shell20 gates passed.
Final clean export follows the single checkpoint commit. Root then creates one
clean checkpoint commit and exact clean Hub/bundle artifacts; dynamic identities
are recorded in the fixed clean handoff directory, not guessed in tracked docs.

Physical dual-Node, two independent Hub processes, Android v1.6, public HTTPS,
Browser uncertain-write fault injection, runtime structured provider throttle,
complete native cross-Owner authority/consent and production stop/reconciliation
remain separate unrun/partial gates. Pure PQ TLS profile is NOT_IMPLEMENTED.
Application-layer NodeControl PQ and ordinary TLS do not close that transport gap.
Original failures and prior source-specific successes remain intact. The
[completion ledger](completion-ledger.md) is the itemized status source; this
bounded backend/framework checkpoint is not overall architecture completion.
