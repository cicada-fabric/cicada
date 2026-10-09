# Current validation closeout — 2026-10-09 — v0.1 PARTIAL

This record is the single current-status index, not a cumulative PASS count. Keep
the individual historical records and failed attempts at their original source
and artifact attribution. It does not change `CICADA.md`, the Client contract,
or any product policy.

## Source and artifact attribution

| Item | Verified identity |
|---|---|
| Core source | clean commit `dabce1740f91a40c5451fca90522d17f27b09a54`; tree `9a253f4410bad64f8928ceaae032395356acf681`; tracked archive SHA-256 `bc83971e35c1a3beecd632b373df51b4ff4a5799ab4e1498f85ff46926fc62ca`; source fingerprint `89a0530582e098e75fb8ab0df67ec99350e2023e1a8f5f7fe44c405d8f10eef7` |
| Go toolchain | `go1.27.1 linux/amd64`, pinned image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195` |
| Hub/product | contract `client-hub-v1.6.4`, catalog 55; Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9` |
| Separately built binaries | The PQ package Node binary SHA-256 is `d78b2af426d444648bb8a2f609d20783faa5e8783bc1cc96ec388a7237c56208`; the Hub image's extracted shipped `cicada` binary SHA-256 is `7b04eceefa40efba51a98db540f745a22bd4b06ef1db388cd6729d30dfdf2929`. They are distinct builds attributed to the same clean Core source; neither hash identifies the other artifact. The M5 helper is a separate dirty build. |

The Go package tests below used the tracked-clean archive. Separate fixture
helpers have their own source pins; in particular the M5 helper is from an
independent dirty checkout and must not be attributed to the Core commit alone.

## Current bounded evidence

| Lane | Result | Limit and evidence |
|---|---|---|
| Default Go suite | `PASS_WITH_OPTIONAL_SKIPS`: 30 packages; 1,522 top-level pass events and 1,408 subtest pass events; 22 explicit skips; zero failures. Build, default tests, `go vet ./...`, and read-only `gofmt -l` passed. | Final receipt `.cicada-data/coherent-full-go-capacity-20261009a/runs/dabce1740f91-20261009T182113Z-1132233/result.NONAUTH.json`, SHA-256 `42cf1912a7a2e7f083288efbedf66315ca0093eaf7f08c6bc320f930716b01b5`. The runner used `umask 0022` only for the Go test subprocess so public-mode fixture tests retain their intended modes; the earlier same-source harness failure is preserved. The 22 skips remain skips, including Native and Docker acceptance tests. |
| Shipping package fixture | `PASS_SCOPED_DISTRIBUTION_AND_POSTCHECK`: `TestPQDistributionActualHubNode` plus four subtests. | Root postcheck `.cicada-data/pqtls-package-gate-phasec-20261009a/ROOT-POSTCHECK.NONAUTH.json`, file SHA-256 `07a483ed14e0a6d6580ed2311f92c9a0cdee43af259c8e329cd09c3fb7ccaa1a`, references run-result SHA-256 `80137103d3fbca556b491f2ec35a61e0726dd1f9b5b1046afe12ac4a6f6d74ea`. This is a bounded package/distribution test, not full Native, physical-device, or public HTTPS acceptance. |
| Relay Ask admission / schema v59 | Scoped admission-count index and schema-59 benchmark evidence; focused changed-logic race passed 8 top-level / 10 subtests. The prior failure/timeout and correction attempts keep their original attribution. | [Detailed record](relay-admission-performance-validation.md). This is a capacity/query result, not a full Go or Native gate. |
| Endpoint Resolve capacity | Active Service and legacy Control scan eligible candidates in bounded stable pages, preserving exact/qualified precedence and authorization/binding filters; focused normal/race selectors passed. | [Source and limits](directory-resolve-capacity-validation.md). No schema/index/API contract change; not fleet capacity evidence. |
| Node sealed pre-writer phase diagnostics | Focused normal/race checks passed 6 tests / 3 subtests each; phase logging does not change admission or prove queue acceptance. | [Independent record](node-sealed-phase-diagnostics-validation.md). |
| Group/Fabric cross-feature stress | Nine selected tests across four workload stages and a successful builder; zero failures/skips and owned cleanup verified. | [Stress record](v01-group-fabric-stress-validation.md). Tested dirty source `1ad5a96414c2d888f70c5b61467b3b1e4a382a91` (946 Go files; source-tree SHA-256 `a33879ff…fd0ae`), not clean `dabce174` alone. |
| Static contract / packaging checks | Contract 17/17 and build-input inventory 6/6 passed. Release packaging reported 14 pass, 5 skip, 0 fail. | Receipt `.cicada-data/root-static-closeout-20261009a/RESULT.NONAUTH.json`, SHA-256 `50fe1a9fdc7a7d71ab770622c6b1edcde3f4efb693a123eacee9b38560ddbcaa`. It is a separate dirty `1ad5a964` static-check snapshot; five skips are for unavailable release/PQ artifacts, not passes. |
| M5 multi-Hub protocol fixture | `SCOPED_PASS`, 83 seconds: two disposable Hubs and two production Multi-Hub Agent processes; synthetic sessions, owner-bound heartbeat/Network claims, Hub ciphertext and cross-Hub denials were exercised. | `.cicada-data/m5-pqtls-protocol-20261009b/receipt.json`, SHA-256 `c62daab2881408ad12da6fc88dc05f4e160d8d146fafa6c16355d02d609588c0`; Root postcheck `.cicada-data/m5-pqtls-rootops-20261009b/POSTCHECK.NONAUTH.json`, SHA-256 `f3bd7fcc1b8cda9553ecb7632df33b9a5c73bb115210bf708e62dac877668f36`. The gate used HTTP/TCP on its owned Docker network; PQTLS handshake, Native Runtime, Android, physical devices and public HTTPS were not asserted. |
| Protocol interop | `PASS_SCOPED_PROTOCOL_INTEROP`, 76.412 seconds: five top-level tests and three nested recovery subtests, no skips/failures. Client smoke/recovery: 2 top-level + 3 subtests; Network M1: 1; Group Spaces M2: 2. | Result `.cicada-data/protocol-interop-current-20261009a/root-run-20261009a/result.NONAUTH.json`, SHA-256 `e3d1ab406dc31afe2495d1fe6d76aa7bce155cfdd422919a3c8f347712dd0247`. It used synthetic fixture credentials and real loopback TCP. It is not Android, a PQTLS handshake, Native Runtime, physical-device, or public HTTPS evidence. |
| M4 owner-revoke integration overlay | `PASS_SCOPED_TEST_OVERLAY`, 160.535 seconds: normal cmd selector, three store selectors, then the same cmd selector under `-race`; 5 top-level pass events, 0 subtests, skips, or failures. The overlay extends the existing encrypted owner/Monitor Group Spaces fixture to revoke a delegation, verify the version advance, and deny a later apply without changing the accepted prior result. It does not measure a native scheduled wake. | Result `.cicada-data/m3-m4-revoke-fixture-20261009a/run-m3-m4-revoke-20261009a002/result.NONAUTH.json`, SHA-256 `1e2a1f6b54916ae4b2ef133a0255231b8d6c8ea6a2d44f340f2ff2bce98c1e02`; overlay test SHA-256 `f186136f7c61fc71f89f3b3a3e6d56bb8a0b436d0dfc6769acffe82336cb24f0`. The tested Go source is the clean `dabce174` snapshot, but revocation assertions come from this ignored test overlay and are not present in the tracked test at that commit. The runner verified zero Go-cache writers before launch. An Endpoint go-list startup process briefly shared the cache and exited naturally after about 1.12 seconds, before any tests ran; no claim is made that it was stopped by Root. The run passed all source, mount, test, and exact-container cleanup checks, and a post-run check found no cache writer. |
| M3 space-event parser routing overlay | `PASS_SCOPED_TEST_OVERLAY`: the focused normal and race selectors each passed 2 top-level tests and 2 subtests, with no skips or failures. The added `httptest` SSE case verifies `space` reaches only the space channel, while `ready` reaches both the space and claim channels; the pre-existing wake-hint assertions also pass. | Result `.cicada-data/m3-space-routing-overlay-20261009a/run-m3-space-routing-20261009a003/RESULT.NONAUTH.json`, SHA-256 `45f5387b3c6e32729fb0594e79c993840a61d17688a5feb6e2b14d90a4407b60`; ignored overlay test SHA-256 `53fc748a08c98b890443780d607b721edc44ca6f25517c993b104eaab9edfeef`. It used clean snapshot `dabce174` with an ignored test overlay, no Native Runtime, credentials, provider calls, or model calls. This proves Go SSE parser channel routing only; it does not observe the space-sync worker, Agent job loop, or Native Runtime wake behavior. |
| TCP connect deadline/cancellation test overlay | `PASS_SCOPED_TEST_OVERLAY`, 45.127 seconds: normal and `-race` each reported 6 top-level and 6 subtest passes; 0 failures or skips. It checks a finite default connect deadline, preservation of an earlier parent deadline/cancellation, and that cancelling the connect context does not close an established connection. | Result `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/RESULT.NONAUTH.json`, SHA-256 `a315b9167c0df5592d8af73f0e9fc54110e2b61d1073a6af5dc44fda6d287d04`; independent postcheck `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/POSTCHECK.NONAUTH.json`, SHA-256 `91ba50c74a4712ed7e154429a16d50a6f06340ffde70dcf4405b0cc73c37aa7d`. The test and `internal/pqtls/openssl_linux.go` came from an ignored Go overlay (`openssl_tcp_dial_test.go` SHA-256 `b060c9222cadf8b5653c64f3aa92b2655c1d3d49ee4ca03ec381bf68c3d42e60`; implementation overlay SHA-256 `83891a97855ce44a0152f20b0c8dc4c6d0d8709d7f2345dc9b17b4e4be70fb7d`), not the clean `dabce174` source. Both receipts record 1,177 source rows and protected containers unchanged; cleanup and the exact owned-ID absence check passed. |
| Native fresh-restart startup gate `phasec20261009e` | `PASS_STARTUP_ONLY`, 48.403 seconds: both CLI 0.162 sessions completed the bounded restart; the strict fresh-connection predicate passed with one accepted new connection per Node and zero turn events/provider POSTs. The restart witness omits anchor/count/elapsed telemetry, so this is startup-only, not Native Ask/Reply or recovery. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/peer-startup-zero-fresh-witness-result-phasec20261009e/STARTUP-RESULT.NONAUTH.json`, SHA-256 `8035fd8640da9bdd0caae9890b8d538d1968551850ea8784ddd14c780d16b747`; source artifact clean `dabce174` / fingerprint `89a05305…10eef7`. |
| Prior Native original-thread attempt `a003` | **FAIL / G1–G2 incomplete.** Three actual turn starts and completions were observed: A and B joined on their original Threads, then A completed same-Thread second-Group join/use/leave/whoami. Original Threads: A `01a12234-68bf-7373-8324-f2e169c92a5b`, B `01a12234-6b59-7f60-b241-5bf166a088d7`. Bilateral endpoint consent passed. A's initial seed echo was present; B's status is `MISSING_PENDING_CONTINUITY`, a pending witness rather than evidence of model amnesia. No Ask/Reply or context witness was recorded. The follow-up fresh Hub restart did not establish a PQTLS-ready witness (`PQ_READY_UNPROVEN` within the bounded 5-second QA wait); this does not identify a network cause or establish the production reconnect bound. `provider_request_count` was not instrumented, so turn events are not provider-request counts. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a003/result.json`, SHA-256 `e50d159da47fba3d503254eec91313e341a13d2adb2cc7339294c8dd0d1aafa9`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a003/POSTCHECK.NONAUTH.json`, SHA-256 `2d0af104b0aec63c3ce341ecceebb4fb51bc738ada523268c9315117a131823d`, confirms owned Docker absence and six residents unchanged. The run reports owned-resource cleanup true and both Observers at expected EOF; its private state was retained. Earlier a002 remains a separate failure with cleanup false and Observer UNKNOWN; a003 does not rewrite that history. |
| Prior Browser/panel gate `G` | **PASS, scoped Browser workflow**, 29/29 checks. Headless Chromium verified vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty/recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle behavior, selected-group confirmations, cross-node link metadata, and authority denial. All seven asset/identity requests returned 200. Two Chromium cgroup samples were 116 then 132 processes against `pids.max=256`; `pids.events:max` and sampled OOM counters stayed zero. | Result `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/browser-output-phasec20261009a007/result.json`, SHA-256 `99578efc76b71ba6d0bf18f1b6f59a94ff194cb3322b6ffd250cfc7f22ee6dcc`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/POSTCHECK.NONAUTH.json`, SHA-256 `e5bb464b37a2743ec9957ca7b108db106a304d33a2a69e37b6671c2bf09649e8`, confirms exact owned IDs absent and six residents unchanged. This earlier gate remains in its original scope; current status is in the following row. |
| Current Browser/panel gate `public-browser-checkpoint-actual-20261009a` | `PASS_SCOPED_BROWSER`, 125.209 seconds: all 29 browser steps passed, including vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle, selected-group confirmation, cross-node link metadata, and authority denial. | Result `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/browser-output-public20261009a001/result.json`, SHA-256 `1e5717c90bf052fe74350df2c2dcb294294f61c92a6e4406ca6ec91657311496`; source script `scripts/test-hub-web-panel-browser.mjs` SHA-256 `fc9021aa4eec38d68147d26597ace0231c8b16ef9ad3eb7cee83e78784842598`, private source-derived resource/deadline/cleanup envelope SHA-256 `047089ca38ebab7481dd45a8d17acb72a977b843c999081770e092a8d2ee62c0`; clean Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9`; Chromium image `sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04` (Chrome 151.0.7922.109). Root postcheck `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/ROOT-POSTCHECK.NONAUTH.json`, SHA-256 `4d0b6239fe6f49db2f71da2c0c6ebaca4a516ba44cbf4aa1a5f26d61b19b4ab9`, records 14 captured IDs absent, four planned names and the network absent, and six residents unchanged. Two successful short-lived `--rm` CLI containers had no captured IDs, so this does not claim ID-level proof for all 16 launched containers. This localhost/browser fixture is not Android, physical-device, public-HTTPS, or Native Runtime acceptance. |
| Current Native original-thread attempt `a004` | **FAIL / G1–G2 incomplete.** Four turn-start submissions on original Threads A (3) and B (1); failure at `original_a_managed_ask`. A ordinal 6 reported `UNKNOWN_IO`. Source-derived analysis explains the missing detail: five six-phase connections used 30 notes; the sixth reached the 32-note recorder cap before `PROXY_CONNECT_ACCEPTED`. The actual phase array was not persisted. A separate source-only derived-cap test passed 4 checks; the fix was not integrated into this paid run. The provider-request count is uninstrumented, with no HTTP/TLS result, so the underlying I/O cause remains unknown. Read-only projections confirm one A→B request `OPEN`, Fabric ASK `queued`, outbox `RELAY_ACCEPTED`, recipient inbox/delivery attempt `CLAIMED`, and no reply ID; B's matching writer record is epoch 1 `INJECTING` with `queue_accepted=false`. Relay acceptance and claim are not Node queue acceptance, Runtime consumption, or a B answer; A recovery/context remains unproven. The run reports cleanup false, four cleanup `RuntimeError` classes, and both Observers `UNKNOWN_RETAINED_SUBSCRIBER`. | Native result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a004/result.json`, SHA-256 `71caa8a9ae7f2756313e84b7bcac76a7e29e01ad8f79280e512dc08814b34f09`; source-only phase-cap analysis and four-test receipt `PHASE-CAP-ROOTCAUSE.NONAUTH.json`, SHA-256 `d97a1ada46297f72dafbf6a210d9e6009fc8690b9df303bb106c96410a35bd3d`; Relay projection `relay-projection-closed.NONAUTH.json`, SHA-256 `f4bed239a8c7b859ce066259fb1692a0a66bf017138d5254a0b1cb1e718bebd9`; writer projection `native-writer-projection-closed.NONAUTH.json`, SHA-256 `f1a698ea459281594957fe107dc694ab74ba530212b6fc5429e2c24ef8ee08df`; Root postcheck SHA-256 `9e131ff942e86b886e2cff414213ce0bb6129ff4223a36703cfa0ee7a01282fa` confirms recorded containers, networks, helper names absent and six residents unchanged. The postcheck does not change the run's cleanup/Observer fields; three Root-owned mode-0700 forensic directories remain. Root read-only Relay projection `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a004/ROOT-RELAY-STATE.NONAUTH.json`, SHA-256 `4b64f5e25f28107cbd30194a3537240b1913d335f3706a809482fae695846236`, independently confirms request state and no reply. No message body or digest was selected. |

## Current Native attempt `a004`

Read-only projections confirm the A-to-B Ask is `OPEN`, Fabric `queued`, outbox
`RELAY_ACCEPTED`, and recipient inbox/delivery attempt `CLAIMED`; the matching B
writer state is `INJECTING` at epoch 1, with `queue_accepted=false`. The request,
message, attempt, endpoint and binding identities match across projections. No reply
ID is present. Thus Relay persistence and delivery claim are established, while
Node queue acceptance, Runtime consumption, B's answer, and A's recovery/context
remain unproven. The source-derived phase-cap analysis and its four pure checks
explain the missing ordinal-6 diagnostic detail, not the underlying I/O result;
the paid wrapper was not rerun with that derived fix. The separate Root
postcheck confirms Docker absence and unchanged residents but does not rewrite
the run's cleanup-false/Observer-UNKNOWN fields.

Superseded failure records remain unchanged: Native a002 result SHA-256
`d3fbe7b200a35a0d03fdf376edd24515f70eb4f1094e09998f3c32507b083287` and
Root postcheck `479ecb1fa165f4b36b3a961aebef4c57770086c04ffecd3bb829f52c2d72cd8e`
preserve the earlier cleanup-false/Observer-UNKNOWN outcome. Browser D result
SHA-256 `d4b466df69df93b5929dd9284b881fa2fe5cd447a89d3c9f317ab9f3e13d24e7` and
Root postcheck `24eb1d0798fab0e7c989019f05d6b058f817a4f24a339a8768c127684c53aaa2`
preserve its 45-second second-tab wait failure before the cross-tab guard. M4
overlay run `run-m3-m4-revoke-20261009a001` result SHA-256
`52b5a6c9207e6f989a27b3c89be039f0041fbe1bc3f1cbff03b1cd7c14875e19` preserves
the label-projection prestart failure; that container never started. Its
closeout SHA-256 is `5a4bf80d0402f46165ff1ba7dc28779f36725658f31dbd2d6b90c339669a9051`.

The six protocol-interop containers each matched their inspected HostConfig:
Hub containers were 1 CPU / 1 GiB / 128 PIDs on bridge networking; test
containers were 2 CPU / 3 GiB / 256 PIDs on host networking. Both roles used
UID/GID `1000:1000`, read-only root filesystems, all capabilities dropped, no
added capabilities, and `no-new-privileges`. Environment values were not
collected. All six exact owned container IDs were absent after cleanup, with
no forced kill. The independent Root postcheck above confirms the six resident
containers remained unchanged.

The exact interop selectors and one-T0 bounds are in
`.cicada-data/protocol-interop-current-20261009a/PREPARED.NONAUTH.json`:

```text
^TestClientDockerHub(Smoke|RecoveryFixture)$
^TestNetworkM1DockerHub$
^TestGroupSpacesM2(HTTPHistoryRetentionAndTopicCAS|DockerHub)$
normal deadline 600s; cleanup deadline 660s; external hard cap 690s
```

Recorded command shapes for the two aggregate checks:

```sh
cd cicada-go
go build -buildvcs=false -mod=readonly -o /tmp/cicada-machine-agent ./cmd/cicada
(umask 0022; go test -buildvcs=false -mod=readonly -p 2 -count=1 -timeout=15m -json ./...)
go vet -buildvcs=false -mod=readonly ./...
```

```sh
/usr/bin/timeout --signal=TERM --kill-after=60s 690s \
  /usr/bin/python3 -B .cicada-data/protocol-interop-current-20261009a/run_current_protocol_interop.py \
  --output .cicada-data/protocol-interop-current-20261009a/root-run-20261009a
```

These are the actual private-runner command shapes for the aggregate Go and
three-suite interop gates. Existing tracked script entry points for the
individual bounded checks are:

- Client, Network M1, and Group Spaces M2: `scripts/test-client-hub-interop.sh --suite client`, `--suite network-m1`, or `--suite group-spaces-m2` (each suite runs separately).
- PQTLS package: `scripts/test-pqtls-packaging.sh` (requires accepted package, stage, and build-receipt inputs).
- M5 multi-Hub fixture: `scripts/test-multi-hub-docker.py` (requires accepted producer/build inputs).
- Static contract and inventory: `scripts/test_client_contract.py` and `scripts/test_build_input_inventory.py`.
- Release packaging: `scripts/test-release-packaging.py`.

The combined interop run's exact HostConfig and one-T0 evidence came from the
ignored private runner above, not from one public combined-suite script.

## Native G1–G5 and M3–M5 status

The acceptance definitions remain in `CICADA.md` §39; this table reports
evidence without redefining them. Review of the clean `dabce174` baseline found
equal-jitter reconnect backoff capped at 30 seconds and a 10-second PQTLS
handshake cap, without an SSE deadline around TCP dial. A separate connector
test overlay with a 30-second TCP connect cap passed normal and race checks
(above); that overlay result does not change the clean baseline or explain
a004. The a004 source-derived recorder-cap finding explains lost diagnostic
detail, while its underlying I/O cause remains unknown.

| Gate | Current state |
|---|---|
| G1 — original-context in-group Ask/Reply | **Open.** A must ask; B must read its own seeded context and reply in its original Thread; A must receive and continue in its original Thread. a004 proves Relay acceptance and a recipient delivery claim; the matching B writer remains `INJECTING` with queue acceptance false. No reply ID, B answer, or A continuation/context witness was recorded. B's seed echo remains pending. |
| G2 — same-thread multi-Group / cross-Group direct Ask/Reply | **Partial setup only.** a004 recorded four turn starts on original Threads A/B and persisted one Ask through Relay to a claimed recipient delivery attempt; B's matching Node writer did not reach `QUEUE_ACCEPTED`. Direct cross-Group reply and recovery remain unproven. Still required: scoped Link to B in another Group, direct A→B Ask/Reply in the original Threads, proof no Manager-mediated business path, then revoke the Link and prove denial without exposing other Group data. |
| G3 — Control-independent communication | **Open.** Disable/fail Control business handling and repeat the accepted G1/G2 path, using invocation counts or dependency assertions to show no hidden Control business interpretation/forwarding; then restore Control and verify status queries. Existing route-counter tests are not that live Native demonstration. |
| G4 — restart, loss and duplicate recovery | **Scoped evidence only.** Queue-recovery selectors and Browser uncertain-write recovery passed in their fixtures. Still required: inject faults before send, after Relay commit, after durable Node receive and after native injection; restart and verify IDs, receipts, lease state and uncertain-window behavior. Native crash acceptance was skipped in the default Go run. |
| G5 — permission and data boundaries | **Scoped evidence only.** Privacy, approval and Browser authority-denial checks passed in bounded fixtures. Still required: live forged sender/Group/Link denials, cross-Group Artifact denial, revocation invalidation, Monitor non-approval and search/export non-leak cases. |
| M1 / M2 | Current Network M1 and Group Spaces M2 interop selectors passed. Remaining framework-wide semantics are not closed by those selectors. |
| M3 | Open: prove Journal/topic references, authorized Network private/task/recipient delivery, merged-cursor hints only, and endpoint pagination/unread behavior without content/member disclosure or wake semantics. The scheduled Group Space path is separated in source: Hub `CommitGroupSpaceWrite` emits a space event; SSE encodes `event: space`; the Agent parser routes that event to `spaceWake`, consumed only by `runMachineSpaceSyncWorker`/`reconcileGroupSpaces` to update the private fetch cursor. The [M3 parser-routing regression](m3-space-event-routing-validation.md) confirms only that `space` reaches the space channel and not the claim channel; it does not test the worker or Agent job loop. Source shows the channel is not routed through claim `wake` or `localWake`/`processLocal`; the Agent's separate Control polling loop owns `processJobs`. `event: ready` is different: it schedules both reconciliation and claim reconciliation. Existing production SSE cases distinguish `active-space` from `active-wake`, but do not observe a Native process/model. The current tests can assert parser/channel routing using `streamMachineRelayEventsWithSpaces` and an HTTP test server; no existing seam measures Native wake behavior, and this parser result is not such an assertion. The M4 revoke overlay does not cover M3 delivery/unread. |
| M4 | Partial fixture evidence only: the encrypted Group Spaces integration overlay verifies owner revocation, version advance, and denial of a later delegated apply. Still open: full Monitor-proposed, owner-signed, exact Network/Group/operation/expiry grant and CAS/audit boundaries, plus no self-authorization, widening, history copy, or key/context migration in the required acceptance path. |
| M5 | **Scoped HTTP/TCP evidence only.** The two-Hub Agent fixture passed; still separate are Native/PQTLS handshake, Client pin/device/session/replay behavior, and physical deployment acceptance. |

## Independent Client attribution

The independent `../CICADA_CLIENT` checkout was read-only and clean at
`dev/react-native` HEAD `9b56832c9701b0ba469d8703fdf61611e0208f98` (tree
`907ce40fafcc003194407362ff2f80450604d6c2`, 31 commits ahead of its remote
tracking branch). Its latest validation located here, F38, applies to Client
commit `caa9e4c725a841a1ce8488fbf339ca554d2939ed`, not that current HEAD. F38
is a bounded Android-emulator consent fixture; it is separate from this Go
protocol interop and is not current Android acceptance for this Core build.
No Client source was changed.

## Next acceptance order

1. Integrate the source-derived phase-note cap fix into the next checkpoint source, then refresh that source's build/equality binding and preparation. Its four source-only tests pass; the paid wrapper has not yet used the fix.
2. After Root reviews that preparation, authorize at most one bounded original-Thread G1/G2 attempt with first-fault evidence. It must prove B's original-context read, reply, and A's continuation; the Relay-accepted Ask and `INJECTING` writer state in a004 do not prove Native queue acceptance. Review production TCP-dial bounds separately rather than attributing a004 to them.
3. Close G3 with Control business disabled and invocation counts or a
   dependency assertion, then restored status queries; close G4 with the four
   fault-injection points; close G5 with the live permission/data-denial matrix
   in the table above.
4. Complete M3 cursor/unread, M4 owner-signed Monitor delegation, and M5
   Native/PQTLS plus Client pin/device/session/replay acceptance separately.
   Record Android, physical-device and public-HTTPS outcomes on their own
   applicable gates; none is inferred from these fixtures.
   Overall v0.1 remains **PARTIAL**; no completion percentage is implied.

## Scope boundaries

The current status entries in the architecture status, plan, completion ledger,
and Client/Hub guide link to this record. The distribution schema row is v59,
matching `CurrentV2SchemaVersion` at `cicada-go/internal/store/migrations_v2.go:24`.
Schema, software, contract, source, and image identities remain distinct. The
Browser fixture is localhost-only; the PQ package Node binary, Hub image, and
M5 HTTP/TCP fixture are separate artifacts and do not establish Native PQTLS,
Android, physical-device, or public-HTTPS acceptance. Client results remain
attributed to the independent Client checkout; no Client source changed.
