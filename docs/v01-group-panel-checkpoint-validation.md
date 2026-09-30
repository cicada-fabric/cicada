# v0.1.x Group Space and Hub panel checkpoint validation

The 2026-09-30 result is a **bounded PASS** for dirty source fingerprint
`c33f63aa94289ba3affcc924c161d1a48b9ac3b94a2c8c466907c46cd1a97287`
at `dev` HEAD `f30892fcd79a27bfe5604575deaecebe52c5ec50`. The fingerprint
was the same before and after the gates; HEAD alone does not identify this
build. The software version was `0.1.0-dev`, Hub schema v41, Client contract
`client-hub-v1.5` with 46 operations, and encrypted wire v1. The Hub image
used for the final browser gate was
`sha256:6940829857d0135fd21349a55a367dc530f4c3cf4c3282aa62c841729af3d123`.
The [gate summary](../.cicada-data/v01-checkpoint-20260930T133728Z/gates-summary.json),
[source record](../.cicada-data/v01-checkpoint-20260930T133728Z/source-before.json),
and [build metadata](../.cicada-data/v01-checkpoint-20260930T133728Z/build.json)
hold the exact identities. No production key or resident Hub was used as a
disposable fixture.

After this gate, a [format-only mapping](../.cicada-data/v01-checkpoint-20260930T133728Z/format-only-delta.json)
records removal of one trailing LF from `panel-bootstrap.js`: tested source
`c33f63aa…` maps to final source fingerprint `586ca8adbbcf9ea18c83f03e59267ad848c10792452520f5d499ef08ae340f17`.
Go, native, cryptographic and contract inputs did not change. Every gate below
remains attributed to `c33f63aa…`; any clean image or JS/UI/browser recheck
after the checkpoint needs its own build and result record.

| Layer | Recorded result | Scope |
|---|---|---|
| Go | 1,336 PASS, 11 SKIP, 0 FAIL, 25 packages | `go test -buildvcs=false -json -count=1 -timeout 15m ./...`; [JSONL](../.cicada-data/v01-checkpoint-20260930T133728Z/go-test.jsonl). SKIP is not PASS. |
| Static/contract | vet 0; eight Python PASS; Go WASM/Node model vectors, gofmt, module verify, shell syntax and diff checks all 0 | [summary](../.cicada-data/v01-checkpoint-20260930T133728Z/gates-summary.json) and respective bounded logs. |
| Focused race | 36 PASS, 0 SKIP/FAIL, five packages | [race JSONL](../.cicada-data/v01-checkpoint-20260930T133728Z/race.jsonl), including atomic topology and durable native outcome tests. |
| Disposable real-TCP Hub | Client, Network M1 and Group Spaces M2 all PASS at this fingerprint | [Client](../.cicada-data/v01-checkpoint-20260930T133728Z/interop-client/result.json), [Network](../.cicada-data/v01-checkpoint-20260930T133728Z/interop-network-m1/result.json), [Group Spaces](../.cicada-data/v01-checkpoint-20260930T133728Z/interop-group-spaces-m2/result.json). The Group Spaces fixture uses synthetic native sessions. |
| Real browser | Chrome 151 PASS against the pinned Hub image and same fingerprint | [Browser result](../.cicada-data/v01-checkpoint-20260930T133728Z/browser-final/result.json): manual Hub pin, production Go WASM, encrypted IndexedDB vault/unlock, offline Owner grant/device enrollment, encrypted topology/status/canvas, visible Group and cross-tab pending-request refusal. Disposable Hub, browser, network and fixture cleanup PASS. |
| Real native Runtime | `TestMCPSealedCrossNodeGroupAskReplyNative` PASS, 325.20 s | Codex CLI 0.159.2, requested `gpt-5.6-luna`, two logical Node identities/state roots in one disposable runtime container, one real Fabric HTTP handler, controlled queue/resume safe points. Original Thread identity/context, ASK/REPLY correlation, Hub HTTP/DB plaintext absence and zero Control business HTTP calls were asserted. The [summary](../.cicada-data/v01-checkpoint-20260930T133728Z/gates-summary.json) holds bounded IDs and binary/log hashes; private Runtime logs are not reproduced here. |

The same-image [idle footprint sample](../.cicada-data/v01-checkpoint-20260930T133728Z/footprint-final.json) PASS measured one fresh empty Hub at 30,756 KiB RSS, a 20,594,848-byte stripped binary and 8,986,668-byte gzip-9 binary; Go/Node/Python/Codex were absent from the Hub runtime and owned fixture cleanup passed. This is one idle point, not a load or capacity benchmark. An [earlier startup attempt](../.cicada-data/v01-checkpoint-20260930T133728Z/footprint.json) failed because its non-loopback synthetic API token was omitted; the corrected standalone fixture supplied the token and did not change the frozen source.

The executable gate entry points are `go test -buildvcs=false -json -count=1
-timeout 15m ./...`, `go vet ./...`, `python3 scripts/client-contract.py
check`, `python3 -m unittest discover -s scripts -p 'test_*.py'`, and
`scripts/test-client-hub-interop.sh --suite client|network-m1|group-spaces-m2`
(one suite per invocation with an owned fresh output directory). The browser
entry point is `node scripts/test-hub-web-panel-browser.mjs` with
`CICADA_HUB_IMAGE`, `CICADA_BUILD_METADATA`, and the exact
`CICADA_EXPECT_SOURCE_FINGERPRINT` set as the script requires; its driver hash
and pinned image are in the browser result. Real native validation is opt-in
with `CICADA_CROSS_NODE_NATIVE_E2E=1` and an isolated Codex credential/runtime
fixture. The summary and JSONL are the authority for the executed source and
outcomes; these entry points alone are not a claim that an arbitrary rerun
uses the same image, credential state or fingerprint.

Schema v38 added a commit-order Group Space change cursor without rewriting
signed record sequence or old ciphertext; v39 added exact regroup delegation
and request route purpose; v40 added independent dual-Owner admission, join
and new-record key proofs. Schema v41 makes Client nested `group.create`,
Owner Membership, parent relation and exact request recovery one SQLite
transaction. Its Store tests cover wrong Network/parent, revoked membership,
stale device/key/epoch/Hub, failed Membership insertion, exact retry, reopening
and a synthetic v41 `after_apply` interruption that rolls back then reapplies.
The existing v38–v40 migration IDs/checksums were not rewritten. This is
synthetic upgrade/restart evidence, not production StateDir power-loss
recovery. There is no parent-version field in the current Client DTO, so the
atomic create does not claim parent CAS. The Store-only custom trust-domain
positive test does not override the current encrypted Client session guard,
which still rejects a non-Owner-ID trust domain.

M5's durable native-writer outcome in this gate records injection state before
the queue command and refuses blind reinjection after an uncertain started
command. A durable accepted outcome can support a currently authorized Relay
receipt; it does not prove model consumption or exactly-once external effects.
The authority and recovery limit are in [native writer recovery](native-writer-recovery.md).
This gate does not prove complete two-Hub service isolation or Client selection.

Earlier failed attempts retain their own identities. The first Codex CLI
0.159.2 attempt missed `CODEX_HOME` in a stdio MCP test helper. At
`e13b3848…`, the [native gate](../.cicada-data/architecture-wide-finalfix-20260930T123606Z/gates-summary.json)
failed at its final route allowlist after prior ASK/REPLY assertions passed.
At `434c4eb6…`, the [rerun](../.cicada-data/architecture-wide-nativefix-20260930T125600Z/gates-summary.json)
failed at first Join when the model shortened the synthetic Group ID; that
attempt ran no ASK/REPLY. The first browser invocation for `c33f…` was
[BLOCKED](../.cicada-data/v01-checkpoint-20260930T133728Z/browser/result.json)
by an older driver's hardcoded expected source before opening a fixture; the
updated driver produced the final image-pinned Browser PASS above. These
failures are neither erased nor relabeled as passes.

Current Android `client-hub-v1.5`, physical Android/Nodes, public HTTPS, a
joined V68 chain with two private Docker Node network namespaces, unattended
cold wake, real native crash at the injection window, browser
`OUTCOME_UNCERTAIN` fault injection, M3 immediate-message references/Network
Task offer, cross-Owner Group Space history, and complete two-Hub M5 service
and product flows remain **NOT_RUN or PARTIAL** as listed in the
[completion ledger](completion-ledger.md). The real native PASS uses one
container with two logical Nodes and controlled resume; it does not satisfy
those other layers. Historical Client APK4 results do not transfer to v1.5.
