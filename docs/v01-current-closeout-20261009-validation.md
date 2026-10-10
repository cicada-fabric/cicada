# Current validation closeout — 2026-10-09 — v0.1 PARTIAL

This record is the single current-status index, not a cumulative PASS count. Keep
the individual historical records and failed attempts at their original source
and artifact attribution. It does not change `CICADA.md`, the Client contract,
or any product policy.

<a id="latest-native-timeoutabi"></a>

## Current Native timeout ABI checkpoint — 2026-10-10

The latest single real G1 is **FAIL**, exit 1 after 180 seconds, at
`original_managed_join_and_context` with RuntimeError and public origin
`<effective-request-observer-audit>::audit:60`. It has one submission, one actual
started turn and one started event. [Actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/request-observer-native-result-cicada-two-turn-g1cli0162timeout20261010d2/result.json)
SHA-256 `80233230d37336feba2b8756181e565ddcf7e1001a7862aafe4cb657afbe9647`.

The earlier G1 timeout ABI fault is proven by an actual Peer/migration replay:
manual_turn omitted timeout, Peer forwarded None and paid limit evaluated
min(None,left) before RPC.check. The tracked G1 adapter now preserves inherited
wait/automatic default 180 when timeout is None, without changing numeric
values, remaining deadline clips or G2. The new actual execution has no such
TypeError. This establishes that repair, not completed Native context acceptance.
Its compiled artifacts still originate at clean631; Python harness changes and
repository HEAD `c9b2935da17167ce7694abaeffca22aaa0daa3f2` are separate identities.

Fresh zero preparation exited 0 in 34 seconds with
PREPARATION_PASS_NATIVE_NOT_RUN, result SHA
`42cf3fa128c0743bb21b0e9af8318243c8a9bb979f90e76b221a469a9277b3ce`.
It belongs to binding
`a9729fa7042557e302fac1c0af9337182a7bf8597e1b831b63bb664b9c84a6bd`;
older zero receipts do not satisfy this binding. Six selected wiring tests and
18 binding tests passed without skips. Root's subsequent [full wiring QA](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/ROOT-FULL-WIRING.NONAUTH.json)
records 49 tests: **47 PASS / 2 explicit SKIP / 0 FAIL**, 54.308 seconds,
zero model calls and Runtime launches; SHA
`244dab9745fd111de42d58e724a2bc5f28c87823756f06d9f274d3791ab6e605`.
Skipped retained A/B reply replays and older failed test drafts remain separate.

A's broker event statuses are FORWARDED then UNKNOWN_UNSUPPORTED; A admitted
two connections and B none. The second connection's CLOSED_FAILURE/READ_HEAD
with shutdown_requested=false is **upstream response** checking, not client
request-head checking. The exact response status/rejected rule is UNKNOWN:
PeerNativeBroker sets response_metadata=false in constructor and connect,
so existing RealGuard response_status_code/response_rejection enums were not
emitted. Fixed candidate rules include non-2xx/status, encoding, sensitive
header/token guard and subsequent Core response rules. Native HTTP status is
null. Actual configs and A turn/start retain approval_policy=never,
approvals_reviewer=user, gpt-5.6-luna/provider basil; no approval request method
was observed. No provider403, quota or automatic-review cause is established.
The two origin STREAM_IO pairs are not DRAINED or Native PASS.

The [independent postcheck](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/native-g1-root-idxrd5vg/INDEPENDENT-POSTCHECK.NONAUTH.json)
SHA `6fef835b1d226ce7fd843a5a91cbe92b5b157bc1efb99f4b7fb6917d1d656fe9`
is **PASS_CLEANUP_ONLY**: both actual EOFs, cleanup/error checks, fourteen owned
selectors and run labels/network/UDS absence, six unchanged residents and full
source/compiler pins. Root removed only the three empty operator roots;
[cleanup receipt](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-timeoutabi20261010d2/native-g1-root-idxrd5vg/ROOT-EMPTY-OWNED-TEMP-CLEANUP.NONAUTH.json)
SHA `9de0aa28298a05a645b9d3fc5aae60744c031beaa6a0d8bbeb4546ec727b8735`.
Retained private Native state and all original FAIL receipt bytes remain intact.

The next action is an offline design/review for connecting existing safe
response enums at the actual Peer seam. Preserve original parser/refusals,
Thread/context/PQ/ALPHA/BETA/reply oracles, 600/30/30/660 budgets, outer690/+15,
5/3/2 turns, TCP16 and retries0. This record authorizes no source change or new
paid run. Existing credentials need not be supplied again. G1 same-Group,
G2 live denial tail and G3 restored authenticated encrypted status remain open;
Android/current Client-image acceptance, physical devices and public HTTPS
remain independently attributed. See [detailed facts and frozen sources](v01-native-next-checkpoint.md).

## Source and artifact attribution

| Item | Verified identity |
|---|---|
| Prior full-suite Core source | clean commit `dabce1740f91a40c5451fca90522d17f27b09a54`; tree `9a253f4410bad64f8928ceaae032395356acf681`; tracked archive SHA-256 `bc83971e35c1a3beecd632b373df51b4ff4a5799ab4e1498f85ff46926fc62ca`; source fingerprint `89a0530582e098e75fb8ab0df67ec99350e2023e1a8f5f7fe44c405d8f10eef7` |
| Go toolchain | `go1.27.1 linux/amd64`, pinned image `sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195` |
| Prior Hub/product | contract `client-hub-v1.6.4`, catalog 55; Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9` |
| Separately built binaries | The PQ package Node binary SHA-256 is `d78b2af426d444648bb8a2f609d20783faa5e8783bc1cc96ec388a7237c56208`; the Hub image's extracted shipped `cicada` binary SHA-256 is `7b04eceefa40efba51a98db540f745a22bd4b06ef1db388cd6729d30dfdf2929`. They are distinct builds attributed to the same clean Core source; neither hash identifies the other artifact. The M5 helper is a separate dirty build. |

The default Go suite and prior package/Browser artifacts retain the `dabce174`
archive attribution. Current clean `631666c8f86349e1b1e81c318f324c7897588683`
contains the TCP connector and Browser QA changes plus the previously tested
M3/M4 test bytes. Its fresh build has fingerprint
`d9ca7c7d51f25c26ff60a3ae3d13e4d853e7a20a691926e14864427a06a0a5ad`;
build/equality and keyless preparation do not establish a new full-suite PASS.
Separate fixture helpers retain their own pins; the earlier M5 helper is not
attributed to either clean Core commit alone. The new Apache artifacts separately
record revision `631666c8f86349e1b1e81c318f324c7897588683` plus dirty pinned inputs:
standard source fingerprint `f71151e3298e63d1fa6dffe34f9506a18830cc5506429d129900e665130736cb`,
PQ `97e7e92cf4584f5cc4300b31f3f58726637cc757123db8529b607470b8c76ba9`.
They are not solely clean631 or the Native-built artifact above.

## Current bounded evidence

| Lane | Result | Limit and evidence |
|---|---|---|
| Apache-2.0 source inclusion | Exact official LICENSE is included by standard/PQ packaging and both Hub Dockerfiles; third-party notices remain separate. Initial deterministic checks passed 19 packaging / 6 inventory tests, with 2 optional artifact SKIPs. | [Original deterministic receipt](../.cicada-data/apache-license-packaging-20261010a/actual-repository-qa/RESULT.NONAUTH.json), SHA-256 `f35b5e039bb020f3fff65f9bb21733183f052a855d2afd5d9558b6f09803e666`. A subsequent exact standard-Hub input-enumeration correction passed 2 focused source-info checks; prior skips remain skips. |
| Actual standard/PQ artifact checks | Five standard target binaries and the Linux amd64 PQ package were built. The initial release operation remains FAIL: 20 tests passed and the synthetic Git-provenance fixture failed because the env-isolated container had no global Git identity. Check-only rerun with the existing server public Git config mounted RO passed 21/21, 0 skips/errors/failures, exit 0 in 19.127s; no rebuild. | [Original release result](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/RELEASE-RESULT.NONAUTH.json), SHA-256 `a96638df827356cdd881f8966a3a7ea74a073638fbb9c8e0060355e6d1ce3731`; [separate check-only result](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/ARTIFACT-CHECK-ONLY-RESULT.NONAUTH.json), SHA-256 `ac1288c68172db2f9f7a89c661c7ddaf19ddc83dd88dade84e6d746d9af35526`. Exact LICENSE/checksums/notices and real smoke checks passed; artifacts unchanged, exact owned container absent and six residents unchanged. No publication or formal release. |
| Actual Hub image LICENSE inspection | Standard and PQ image builds exited 0; create-only inspection confirmed exact root LICENSE, nonroot images and 11 Go third-party module notices each, with PQ OpenSSL notices retained. Images were not started. | [Image inspection](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/IMAGE-LICENSE-RESULT.NONAUTH.json), SHA-256 `10372a9516c8262acb32a62ac7a5419f58fcf2e5dac63a17a047d4182064ad8d`; [Hub operation](../.cicada-data/apache-license-packaging-20261010a/actual-artifact-build/HUB-RESULT.NONAUTH.json), SHA-256 `f9216e5a6accbbb98b1115f3f944b01bc84fb3558ca45ef2cafc41474de623db`, 160.707s. Standard image `sha256:0787fe846aaf48bde340ebc9fdf1e9373fa294cee36c8356db66576a3d79bd7c` / 14,345,904 bytes; PQ `sha256:b4dafdcad80ab9f5b86f17b7e4b9a9d0914df4c6bd0848a444d570aa91a96866` / 14,644,505 bytes. Exact inspection containers absent; six residents unchanged. Not a Hub runtime or capacity test. |
| Current clean631 build / equality | `PASS_BUILD_PROOFS`: 457 product and 220 helper compiled-input rows; fresh product binary SHA-256 `3baf7bfbd217ac3d24be0fb3f41dfe5797ffc17a38f1f6c2b79dbe3b1209efae`, helper `6fb8777d7a68d2e38fd454e405123af08931ed2ee256ebdcb7629290e0c65b58`; PQ Hub image `sha256:c87cf47a3ed1b48832a3ec638d98f2f3359d1e6cd2dd06b51cf80de3989e066b` (about 14.6 MB). | [Build/equality report](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/BUILD-PROOFS-RETRY.NONAUTH.json), SHA-256 `60b0f0631cacc7eaaa5dd0c0cb9ff1e6af5420d161cbc6314b29aa53bf51d02b`; the original failed Hub build remains separate. Current Agent wiring manifest has 37 pinned inputs, SHA-256 `a87ab5379ee06c8ede85c1a62aec60049671346b8bc543db17c525c131918e91`. Image size is not capacity evidence. |
| Current clean631 keyless startup | `PASS_STARTUP_ONLY`, Root wall 31.269 seconds / inner startup 26.013 seconds: actual Hub, two Agents, CLI/MCP, mapper and queue-control denial checks; no native turns, credential callbacks or origin/provider dispatch. | [Main result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasecap20261009b/peer-startup-zero-phasecap20261009b001/result.json), SHA-256 `34c11c67bdef311b5328ddca1aae88505d2442174d8a3f6d303a2d8eb38bf6d1`; startup receipt `7c7376135916682c523af34e689cc65272f6ccd8366ba5eb771f41164e4fac07`; [Root postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b001/CURRENT-KEYLESS-STARTUP-POSTCHECK.NONAUTH.json), SHA-256 `2c3b3b53f14afd544a949e86570c15dae808be71f8f0aa06d35ede17d19e9b8b`. This is preparation, not queue consumption or Ask/Reply. |
| Current G4 official CLI 0.162.1 queue-crash gate | `PASS_INJECTED_BEFORE_LEDGER_REAL_QUEUE_ONLY`: one official queue submission over an independent saved B fixture, test exit 0, zero new turns/provider egress. Saved B `01a12336-b99e-7350-821a-3e99742f58e6` had two turns / ten items; uncertainty and reinjection refusal remain the tested boundary. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/result.NONAUTH.json), SHA-256 `51cadc91c894e4feff454a3552035943677d2a5671632e8c6401029cc473b291`; [Root postcheck](../.cicada-data/native-observer-wiring-20261007/g4-cli01621-native-20261010a/output-01621-001/ROOT-POSTCHECK.NONAUTH.json), SHA-256 `2e7fac77e020c32ebfc65cac18b0ae7aece6ec4d9243a80c1bc41c2d6090a275`, confirms four exact CID/name selectors absent, fixture deleted and six residents unchanged. Test source `b28cae8d017d9ec148223c603a85d5934e4800e50f4543414368d533d7cbbb17`. Prior [CLI 0.162 evidence](../.cicada-data/native-observer-wiring-20261007/g4-cli162-runtime-20261009a/result.NONAUTH.json), SHA-256 `4e3c6e11a7e70f595b8f2d8693e1b907861306a79d297d9a07a764829a4bb6d3`, remains separate. Not full G4 or model consumption. |
| G4 production component process windows | Actual helper/process tests cover outbox pre-send, Fabric HTTP post-commit/pre-ACK kill/restart, and Node claim/inbox+journal pre-receipt kill/reaccept dedup. Wrong epoch/digest ACKs are rejected; Ask/Reply IDs persist. Normal and race each passed 1 top-level / 2 subtests, 0 failures/skips; total 115.230s. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g4-process-boundaries-20261009f/result.NONAUTH.json), SHA-256 `6cd8d85113fa3d896ff5e89da4544899127bcf75a15c4569bee78eb07ce721c3`; test SHA-256 `ca1a572f4410cfed0a8281025e7a82836706a636df8ff1183304d1ae29c06b23`, dirty631 plus that test. Not a full MCP daemon or Runtime/model test; credential reads 0, owned container absent. Earlier a–e format/cache/compile/noexec/fixture-auth failures remain retained. |
| G5 retained HTTP / live-U boundaries | HTTP privacy and Monitor approval-denial normal/race gates passed; real unjoined zero-turn U was hidden by production Directory in the separate CLI **0.161** fixture. | [HTTP source/receipts](g5-http-privacy-validation.md) and [Monitor/live-U source/receipts](g5-native-monitor-boundary-validation.md). Current test hashes remain `de31d376…612` and `ce932ff7…33a`. U is not a 0.162/context/recovery result; its provider count is `NOT_INSTRUMENTED`. These scoped results are not full G5. |
| Current CLI 0.162.1 live-U Directory gate | `PASS_LIVE_ZERO_TURN_U_DIRECTORY_ONLY`: real non-ephemeral U `01a12333-bdb4-7fa0-b821-6dda6b264c04` was loaded before/after, hidden from Directory, then unsubscribe was confirmed; zero turn starts. | [Actual receipt](../.cicada-data/native-observer-wiring-20261007/g5-native-current-20261010a/output-01621-001/result.NONAUTH.json), SHA-256 `af4c8293c3d5a07e644af9b6fce2cd4ae830717e3c4c6ab49511fd135922afdf`; [host result](../.cicada-data/native-observer-wiring-20261007/g5-native-current-20261010a/output-01621-001/host-result.NONAUTH.json), SHA-256 `c4adb828f3af2e4f5694aa33fad802e2e3916e776b35698cb9b123eb91a9b012`, confirms cleanup and six residents unchanged. Empty U durable metadata was not materialized; context is `NOT_PROVEN`. This does not close all G5 or replace historical 0.161 evidence. |
| Default Go suite | `PASS_WITH_OPTIONAL_SKIPS`: 30 packages; 1,522 top-level pass events and 1,408 subtest pass events; 22 explicit skips; zero failures. Build, default tests, `go vet ./...`, and read-only `gofmt -l` passed. | Final receipt `.cicada-data/coherent-full-go-capacity-20261009a/runs/dabce1740f91-20261009T182113Z-1132233/result.NONAUTH.json`, SHA-256 `42cf1912a7a2e7f083288efbedf66315ca0093eaf7f08c6bc320f930716b01b5`. The runner used `umask 0022` only for the Go test subprocess so public-mode fixture tests retain their intended modes; the earlier same-source harness failure is preserved. The 22 skips remain skips, including Native and Docker acceptance tests. |
| Shipping package fixture | `PASS_SCOPED_DISTRIBUTION_AND_POSTCHECK`: `TestPQDistributionActualHubNode` plus four subtests. | Root postcheck `.cicada-data/pqtls-package-gate-phasec-20261009a/ROOT-POSTCHECK.NONAUTH.json`, file SHA-256 `07a483ed14e0a6d6580ed2311f92c9a0cdee43af259c8e329cd09c3fb7ccaa1a`, references run-result SHA-256 `80137103d3fbca556b491f2ec35a61e0726dd1f9b5b1046afe12ac4a6f6d74ea`. This is a bounded package/distribution test, not full Native, physical-device, or public HTTPS acceptance. |
| Relay Ask admission / schema v59 | Scoped admission-count index and schema-59 benchmark evidence; focused changed-logic race passed 8 top-level / 10 subtests. The prior failure/timeout and correction attempts keep their original attribution. | [Detailed record](relay-admission-performance-validation.md). This is a capacity/query result, not a full Go or Native gate. |
| Endpoint Resolve capacity | Active Service and legacy Control scan eligible candidates in bounded stable pages, preserving exact/qualified precedence and authorization/binding filters; focused normal/race selectors passed. | [Source and limits](directory-resolve-capacity-validation.md). No schema/index/API contract change; not fleet capacity evidence. |
| Node sealed pre-writer phase diagnostics | Focused normal/race checks passed 6 tests / 3 subtests each; phase logging does not change admission or prove queue acceptance. | [Independent record](node-sealed-phase-diagnostics-validation.md). |
| Group/Fabric cross-feature stress | Nine selected tests across four workload stages and a successful builder; zero failures/skips and owned cleanup verified. | [Stress record](v01-group-fabric-stress-validation.md). Tested dirty source `1ad5a96414c2d888f70c5b61467b3b1e4a382a91` (946 Go files; source-tree SHA-256 `a33879ff…fd0ae`), not clean `dabce174` alone. |
| Static contract / packaging checks | Contract 17/17 and build-input inventory 6/6 passed. Release packaging reported 14 pass, 5 skip, 0 fail. | Receipt `.cicada-data/root-static-closeout-20261009a/RESULT.NONAUTH.json`, SHA-256 `50fe1a9fdc7a7d71ab770622c6b1edcde3f4efb693a123eacee9b38560ddbcaa`. It is a separate dirty `1ad5a964` static-check snapshot; five skips are for unavailable release/PQ artifacts, not passes. |
| M5 multi-Hub protocol fixture | `SCOPED_PASS`, 83 seconds: two disposable Hubs and two production Multi-Hub Agent processes; synthetic sessions, owner-bound heartbeat/Network claims, Hub ciphertext and cross-Hub denials were exercised. | `.cicada-data/m5-pqtls-protocol-20261009b/receipt.json`, SHA-256 `c62daab2881408ad12da6fc88dc05f4e160d8d146fafa6c16355d02d609588c0`; Root postcheck `.cicada-data/m5-pqtls-rootops-20261009b/POSTCHECK.NONAUTH.json`, SHA-256 `f3bd7fcc1b8cda9553ecb7632df33b9a5c73bb115210bf708e62dac877668f36`. The gate used HTTP/TCP on its owned Docker network; PQTLS handshake, Native Runtime, Android, physical devices and public HTTPS were not asserted. |
| Protocol interop | `PASS_SCOPED_PROTOCOL_INTEROP`, 76.412 seconds: five top-level tests and three nested recovery subtests, no skips/failures. Client smoke/recovery: 2 top-level + 3 subtests; Network M1: 1; Group Spaces M2: 2. | Result `.cicada-data/protocol-interop-current-20261009a/root-run-20261009a/result.NONAUTH.json`, SHA-256 `e3d1ab406dc31afe2495d1fe6d76aa7bce155cfdd422919a3c8f347712dd0247`. It used synthetic fixture credentials and real loopback TCP. It is not Android, a PQTLS handshake, Native Runtime, physical-device, or public HTTPS evidence. |
| M4 owner-revoke integration overlay | `PASS_SCOPED_TEST_OVERLAY`, 160.535 seconds: normal cmd selector, three store selectors, then the same cmd selector under `-race`; 5 top-level pass events, 0 subtests, skips, or failures. The overlay extends the existing encrypted owner/Monitor Group Spaces fixture to revoke a delegation, verify the version advance, and deny a later apply without changing the accepted prior result. It does not measure a native scheduled wake. | Result `.cicada-data/m3-m4-revoke-fixture-20261009a/run-m3-m4-revoke-20261009a002/result.NONAUTH.json`, SHA-256 `1e2a1f6b54916ae4b2ef133a0255231b8d6c8ea6a2d44f340f2ff2bce98c1e02`; overlay test SHA-256 `f186136f7c61fc71f89f3b3a3e6d56bb8a0b436d0dfc6769acffe82336cb24f0`. The tested Go source is the clean `dabce174` snapshot, but revocation assertions come from this ignored test overlay and are not present in the tracked test at that commit. The byte-identical tested file is now tracked at `631666c`; this does not reattribute the original run. The runner verified zero Go-cache writers before launch. An Endpoint go-list startup process briefly shared the cache and exited naturally after about 1.12 seconds, before any tests ran; no claim is made that it was stopped by Root. The run passed all source, mount, test, and exact-container cleanup checks, and a post-run check found no cache writer. |
| M3 space-event parser routing overlay | `PASS_SCOPED_TEST_OVERLAY`: the focused normal and race selectors each passed 2 top-level tests and 2 subtests, with no skips or failures. The added `httptest` SSE case verifies `space` reaches only the space channel, while `ready` reaches both the space and claim channels; the pre-existing wake-hint assertions also pass. | Result `.cicada-data/m3-space-routing-overlay-20261009a/run-m3-space-routing-20261009a003/RESULT.NONAUTH.json`, SHA-256 `45f5387b3c6e32729fb0594e79c993840a61d17688a5feb6e2b14d90a4407b60`; ignored overlay test SHA-256 `53fc748a08c98b890443780d607b721edc44ca6f25517c993b104eaab9edfeef`. It used clean snapshot `dabce174` with an ignored test overlay, no Native Runtime, credentials, provider calls, or model calls. The byte-identical tested file is now tracked at `631666c`. This proves Go SSE parser channel routing only; it does not observe the space-sync worker, Agent job loop, or Native Runtime wake behavior. |
| TCP connect deadline/cancellation test overlay | `PASS_SCOPED_TEST_OVERLAY`, 45.127 seconds: normal and `-race` each reported 6 top-level and 6 subtest passes; 0 failures or skips. It checks a finite default connect deadline, preservation of an earlier parent deadline/cancellation, and that cancelling the connect context does not close an established connection. | Result `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/RESULT.NONAUTH.json`, SHA-256 `a315b9167c0df5592d8af73f0e9fc54110e2b61d1073a6af5dc44fda6d287d04`; independent postcheck `.cicada-data/pqtls-connect-timeout-proposal-20261009a/actual-overlay-normal-race-20261009c/POSTCHECK.NONAUTH.json`, SHA-256 `91ba50c74a4712ed7e154429a16d50a6f06340ffde70dcf4405b0cc73c37aa7d`. The test and `internal/pqtls/openssl_linux.go` came from an ignored Go overlay (`openssl_tcp_dial_test.go` SHA-256 `b060c9222cadf8b5653c64f3aa92b2655c1d3d49ee4ca03ec381bf68c3d42e60`; implementation overlay SHA-256 `83891a97855ce44a0152f20b0c8dc4c6d0d8709d7f2345dc9b17b4e4be70fb7d`), not the clean `dabce174` source. These implementation/test bytes are now tracked at `631666c`; the old run remains an overlay result. Both receipts record 1,177 source rows and protected containers unchanged; cleanup and the exact owned-ID absence check passed. |
| Native fresh-restart startup gate `phasec20261009e` | `PASS_STARTUP_ONLY`, 48.403 seconds: both CLI 0.162 sessions completed the bounded restart; the strict fresh-connection predicate passed with one accepted new connection per Node and zero turn events/provider POSTs. The restart witness omits anchor/count/elapsed telemetry, so this is startup-only, not Native Ask/Reply or recovery. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/peer-startup-zero-fresh-witness-result-phasec20261009e/STARTUP-RESULT.NONAUTH.json`, SHA-256 `8035fd8640da9bdd0caae9890b8d538d1968551850ea8784ddd14c780d16b747`; source artifact clean `dabce174` / fingerprint `89a05305…10eef7`. |
| Prior Native original-thread attempt `a003` | **FAIL / G1–G2 incomplete.** Three actual turn starts and completions were observed: A and B joined on their original Threads, then A completed same-Thread second-Group join/use/leave/whoami. Original Threads: A `01a12234-68bf-7373-8324-f2e169c92a5b`, B `01a12234-6b59-7f60-b241-5bf166a088d7`. Bilateral endpoint consent passed. A's initial seed echo was present; B's status is `MISSING_PENDING_CONTINUITY`, a pending witness rather than evidence of model amnesia. No Ask/Reply or context witness was recorded. The follow-up fresh Hub restart did not establish a PQTLS-ready witness (`PQ_READY_UNPROVEN` within the bounded 5-second QA wait); this does not identify a network cause or establish the production reconnect bound. `provider_request_count` was not instrumented, so turn events are not provider-request counts. | Result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a003/result.json`, SHA-256 `e50d159da47fba3d503254eec91313e341a13d2adb2cc7339294c8dd0d1aafa9`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a003/POSTCHECK.NONAUTH.json`, SHA-256 `2d0af104b0aec63c3ce341ecceebb4fb51bc738ada523268c9315117a131823d`, confirms owned Docker absence and six residents unchanged. The run reports owned-resource cleanup true and both Observers at expected EOF; its private state was retained. Earlier a002 remains a separate failure with cleanup false and Observer UNKNOWN; a003 does not rewrite that history. |
| Prior Browser/panel gate `G` | **PASS, scoped Browser workflow**, 29/29 checks. Headless Chromium verified vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty/recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle behavior, selected-group confirmations, cross-node link metadata, and authority denial. All seven asset/identity requests returned 200. Two Chromium cgroup samples were 116 then 132 processes against `pids.max=256`; `pids.events:max` and sampled OOM counters stayed zero. | Result `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/browser-output-phasec20261009a007/result.json`, SHA-256 `99578efc76b71ba6d0bf18f1b6f59a94ff194cb3322b6ffd250cfc7f22ee6dcc`; Root postcheck `.cicada-data/native-observer-wiring-20261007/current-browser-phasec-20261009g/POSTCHECK.NONAUTH.json`, SHA-256 `e5bb464b37a2743ec9957ca7b108db106a304d33a2a69e37b6671c2bf09649e8`, confirms exact owned IDs absent and six residents unchanged. This earlier gate remains in its original scope; current status is in the following row. |
| Current Browser/panel gate `public-browser-checkpoint-actual-20261009a` | `PASS_SCOPED_BROWSER`, 125.209 seconds: all 29 browser steps passed, including vault/unlock, owner grant/enrollment, encrypted topology/canvas, uncertainty recovery, cross-tab refusal, Group-parent preview/CAS/restart/stale/cycle, selected-group confirmation, cross-node link metadata, and authority denial. | Result `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/browser-output-public20261009a001/result.json`, SHA-256 `1e5717c90bf052fe74350df2c2dcb294294f61c92a6e4406ca6ec91657311496`; source script `scripts/test-hub-web-panel-browser.mjs` SHA-256 `fc9021aa4eec38d68147d26597ace0231c8b16ef9ad3eb7cee83e78784842598`, private source-derived resource/deadline/cleanup envelope SHA-256 `047089ca38ebab7481dd45a8d17acb72a977b843c999081770e092a8d2ee62c0`; clean Hub image `sha256:8e84951bc67777ff2cac12e501c95e6cbc7d572e5baef73002ddd0ec8eb000b9`; Chromium image `sha256:2d349b544a1ea6b5b5fd7c0fe99215ff662339c57407ee2e8c0a11af93516b04` (Chrome 151.0.7922.109). Root postcheck `.cicada-data/native-observer-wiring-20261007/public-browser-checkpoint-actual-20261009a/ROOT-POSTCHECK.NONAUTH.json`, SHA-256 `4d0b6239fe6f49db2f71da2c0c6ebaca4a516ba44cbf4aa1a5f26d61b19b4ab9`, records 14 captured IDs absent, four planned names and the network absent, and six residents unchanged. Two successful short-lived `--rm` CLI containers had no captured IDs, so this does not claim ID-level proof for all 16 launched containers. This localhost/browser fixture is not Android, physical-device, public-HTTPS, or Native Runtime acceptance. |
| Prior Native original-thread attempt `a004` | **FAIL / G1–G2 incomplete.** Four turn-start submissions on original Threads A (3) and B (1); failure at `original_a_managed_ask`. A ordinal 6 reported `UNKNOWN_IO`. Source-derived analysis explains the missing detail: five six-phase connections used 30 notes; the sixth reached the 32-note recorder cap before `PROXY_CONNECT_ACCEPTED`. The actual phase array was not persisted. A separate source-only derived-cap test passed 4 checks; the fix was not integrated into this paid run. The provider-request count is uninstrumented, with no HTTP/TLS result, so the underlying I/O cause remains unknown. Read-only projections confirm one A→B request `OPEN`, Fabric ASK `queued`, outbox `RELAY_ACCEPTED`, recipient inbox/delivery attempt `CLAIMED`, and no reply ID; B's matching writer record is epoch 1 `INJECTING` with `queue_accepted=false`. Relay acceptance and claim are not Node queue acceptance, Runtime consumption, or a B answer; A recovery/context remains unproven. The run reports cleanup false, four cleanup `RuntimeError` classes, and both Observers `UNKNOWN_RETAINED_SUBSCRIBER`. | Native result `.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasec20261009a/request-observer-native-result-cicada-two-turn-peerphasec20261009a004/result.json`, SHA-256 `71caa8a9ae7f2756313e84b7bcac76a7e29e01ad8f79280e512dc08814b34f09`; source-only phase-cap analysis and four-test receipt `PHASE-CAP-ROOTCAUSE.NONAUTH.json`, SHA-256 `d97a1ada46297f72dafbf6a210d9e6009fc8690b9df303bb106c96410a35bd3d`; Relay projection `relay-projection-closed.NONAUTH.json`, SHA-256 `f4bed239a8c7b859ce066259fb1692a0a66bf017138d5254a0b1cb1e718bebd9`; writer projection `native-writer-projection-closed.NONAUTH.json`, SHA-256 `f1a698ea459281594957fe107dc694ab74ba530212b6fc5429e2c24ef8ee08df`; Root postcheck SHA-256 `9e131ff942e86b886e2cff414213ce0bb6129ff4223a36703cfa0ee7a01282fa` confirms recorded containers, networks, helper names absent and six residents unchanged. The postcheck does not change the run's cleanup/Observer fields; three Root-owned mode-0700 forensic directories remain. Root read-only Relay projection `.cicada-data/native-observer-wiring-20261007/current-peer-refresh-20261009phasec/agent-current-pin/native-rootops-phasec20261009a004/ROOT-RELAY-STATE.NONAUTH.json`, SHA-256 `4b64f5e25f28107cbd30194a3537240b1913d335f3706a809482fae695846236`, independently confirms request state and no reply. No message body or digest was selected. |

<a id="latest-native-entryfix"></a>

## Prior Native attempts `drainfix20261010c001` and deterministic wiring

Both actual c attempts remain **FAIL** at `original_managed_join_and_context`:
G1 exit 1 / 31.670s / `TypeError` / one started turn; G2 exit 1 / 198.067s /
`RuntimeError` / two started turns. G2's closed I/O classification is READ_HEAD
parser rejection; the exact rejected rule and upstream-hop cause are **UNKNOWN**.
Neither result closes original-context acceptance, the G2 denial tail or G3 restore.

| Lane | Actual result | Root postcheck |
|---|---|---|
| G1 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-drainfix20261010b/request-observer-native-result-cicada-two-turn-g1drainfix20261010c001/result.json), SHA-256 `64c7ad628ae639c5c54e41c312fcdaf8d4f0e8d134370b66c970af5099b2e49e` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1drainfix20261010c001/POSTCHECK.NONAUTH.json), SHA-256 `1526f35efe19df394999f6bad4e5af56e1e21fc3d7a5e83d97122ecd78cc6220` |
| G2/G3 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-drainfix20261010b/request-observer-native-result-cicada-two-turn-g2drainfix20261010c001/result.json), SHA-256 `7cfb9f64de43a15edb6865863ac5c835874f56f4dd03ea4ec20a362a736c8270` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2drainfix20261010c001/POSTCHECK.NONAUTH.json), SHA-256 `dc0fa6deb6014a8fdb4c273befce96b69b4880a84ddb8380062533de33fee312` |

Both report `cleanup_owned_resources=true` and both Observers
`EXPECTED_EOF_CONFIRMED`; each Root postcheck confirms 14 owned selectors absent,
source pins unchanged and six protected residents unchanged. Cleanup is separate
from the Native FAIL. The linecache and EOF/drain fixture corrections do not
rewrite the earlier b entries or d Observer-UNKNOWN results. Compiled Go artifacts
retain clean631 attribution; current Python QA changes have their own source pins.

The full deterministic wiring suite now reports **45 PASS / 2 explicit retained
A/B replay SKIPs / 0 failures or errors**, exit 0, 50.403s; no Runtime, provider or
model calls. [Actual suite receipt](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010c/SUITE-RESULT.NONAUTH.json),
SHA-256 `0375ad7c3b5bf6e499ec22feee1bdf1616fb58e85b3f50d1e4b2407ec9d85429`,
pins checker `2b4a8e8f154f15edae5aac3fb7aa9dd39535ef1cbc0723109baba17b70a3b814`
and the fresh immutable test binding below. Shipping defaults and all rejection
oracles are unchanged; the tests explicitly select coherent current metadata.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/native_observer/request_observer_wiring_checks.py \
  --current-binding-file /home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010c/binding.NONAUTH.json \
  --current-binding-sha 4c019a1606bee9ac4743675d294e23c39123707876c9afa3704057c5b536ad37
```

The initial default full47 result remains FAIL (27 PASS / 18 ERROR / 2 SKIP).
[Fixture revision a](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010a/SUITE-RESULT.NONAUTH.json)
remains FAIL (36 PASS / 7 ERROR / 2 FAIL / 2 SKIP);
[revision b's immutable count correction](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-checks20261010b/SUITE-COUNT-CORRECTION.NONAUTH.json)
records 44 PASS / 1 ERROR / 2 SKIP, preserving its original receipt and log.
The final PASS is deterministic fixture validation, not Native acceptance.

## Prior preparation and entry attempts `drainfix20261010b001`

The two corrected zero-preparations passed in 34.529s / 35.182s, with no
Native/model/credential dispatch. Their source checks, fourteen exact Docker
ID/name selectors and two actual socket absences per lane, and six protected
residents were independently verified; preserved symlink state is not absent.
[G1 zero execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/zero-rootops-g1drainfix20261010b001/ACTUAL-ZERO-EXECUTION.NONAUTH.json),
SHA-256 `db32b26fc299da6863a471e457ea7aef4b892273507484305a6a901137ad193e`,
and [G2 zero execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/zero-rootops-g2drainfix20261010b001/ACTUAL-ZERO-EXECUTION.NONAUTH.json),
SHA-256 `1074e1c1363ac3e0e1c02c60bcb98cb51cf90e173c7cade067b522e44667ac0c`,
prove preparation only. The narrow EOF/drain correction passed three focused
Root checks and effects-denied preflight; it preserves terminal failure and
requires actual EOF. It does not identify the earlier initiating provider hop.

The subsequent G1/G2 entry attempts exited 2 after claim, before result
construction, at the selected-source loader: 3.020s / 3.570s. There is no Native
result; Runtime/model/effect counts remain **UNKNOWN**, not zero.
[G1 entry execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1drainfix20261010b001/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `c900c1344f39ab617c025c9f945db36b45ea8f821737212c4f21c118280b7121`,
and [G2 entry execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2drainfix20261010b001/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `fb4cdc14f271bad6892a234f9e97f790df80432bdd1cd8aac5de6df0a19c7444`,
remain failed entries. Effects-denied reproduction found that compiling the
public candidate under a synthetic filename makes `inspect.getsource` in
`install_native_rpc_shutdown_drain` fail before the constructor. A minimal
fixture-only linecache correction enabled the later c attempts above;
no Native PASS or completion is claimed. Prior input/source failures and
all earlier scoped proofs remain unchanged.

## Prior Native attempts `g1entryfix` / `g2entryfix20261010d001`

Both prior attempts remain **FAIL** at `original_managed_join_and_context`:
G1 exit 1 / 34.680s / `TypeError`; G2 exit 1 / 97.036s / `RuntimeError`.
Each reports one started Native turn/submission. Real Threads exist, but neither
result establishes full RPC or original-context acceptance. Cause is under
read-only investigation; the exception class alone does not identify it.
The separate private inputs are pinned by [binding `bundle-g1g2tlsfix20261010f`](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/binding.NONAUTH.json),
SHA-256 `fbf9b3155eb00bae107a6e61e4c4ae230c305775f90752afac1a3266f37cd9e9`;
[G1 wiring](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/WIRING-MANIFEST-G1-PHASE-CURRENT.NONAUTH.json)
and [G2/G3 wiring](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/WIRING-MANIFEST-G2-G3-PHASE-CURRENT.NONAUTH.json) retain their own source pins.

| Lane | Original result | Later Root Docker postcheck |
|---|---|---|
| G1 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/request-observer-native-result-cicada-two-turn-g1entryfix20261010d001/result.json), SHA-256 `2b1f5ad94702f8ccb933eef0c6bf16495ea506f1fb0a24412c3179e4a5380457` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g1entryfix20261010d001/POSTCHECK.NONAUTH.json), SHA-256 `55ad203ce433b2f256cb0d92fde287a6d76d96acb5e30a14f61de2ccc9b4520b` |
| G2/G3 | [Result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-g1g2tlsfix20261010f/request-observer-native-result-cicada-two-turn-g2entryfix20261010d001/result.json), SHA-256 `55ddb00df3d0dbf5ebee79f655117fbe7b22bf3b1ec155b7c935ea710f76f0f5` | [Postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-g2entryfix20261010d001/POSTCHECK.NONAUTH.json), SHA-256 `8526b92e74b9d146bf3860f94dd8fb61c74aed5b9c25891ae04b43f6b69cb53b` |

Both original results report `cleanup_owned_resources=false` and both Observers
`UNKNOWN_RETAINED_SUBSCRIBER`. Later Root postchecks prove all nine exact owned
Docker selectors absent per lane and six residents unchanged. That limited
absence proof does not rewrite cleanup, Observer or business verdicts. Prior
six-turn context evidence and all failed attempts keep their original scope.

## Prior Native CLI 0.162.1 attempt `cli0162120261010a002`

The [actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-cli0162120261010a/request-observer-native-result-cicada-two-turn-peercli0162120261010a002/result.json),
SHA-256 `971bb4c37e4771d2baede4170653a2c81cd21b7c5799fad7f47642bc64ffbae5`,
remains **FAIL**, `RuntimeError`, at the zero-model
`g2_actual_hidden_members_and_revoked_link_denial` stage (106.609 seconds).
All six turns completed (four manual, two automatic). Original A
`01a12336-b700-7da1-84e6-36658f71cb38` passed completed/correct-answer/inline-correlation
and both context-marker predicates. Original B
`01a12336-b99e-7350-821a-3e99742f58e6` passed all five recorded seeded-reply,
original-thread, request/receive correlation and validated-Link booleans.
These are scoped cross-Group original-thread context proofs, not same-Group G1
or complete G2/G3 acceptance. G3 restore was not reached. Control-object exclusion
records `dependency_proven=true`; its invocation count remains `NOT_INSTRUMENTED`.

Cleanup is true and both Observer EOFs are confirmed. The initial Root postcheck's
network-absence predicate falsely failed and remains retained; the
[corrected postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-cli0162120261010a002/POSTCHECK-CORRECTED.NONAUTH.json),
SHA-256 `ead36b56b427a75c7029c271303ff56dad769ffe29cd07be09a830b3bdc81e73`,
combines four exact network-not-found checks with the prior 13 container checks:
17 selectors absent, zero cleanup fallback, six protected residents unchanged.
Source remained unchanged during the run; clean631 artifacts retain their build
attribution, separate from the current CLI/QA inputs. No overall PASS is implied.

## Prior Native attempt `receiptc20261009c002`

The [actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-receiptc20261009c/request-observer-native-result-cicada-two-turn-peerreceiptc20261009c002/result.json),
SHA-256 `c5993fb489c487cc7b75704e33a54bc131ef44452681a95179df4c90bcb61fc9`,
remains **FAIL** at `actual_queue_original_a_receive_context`. All six turns
completed (four manual, two automatic). B's full correlated seeded reply/context
predicate passed; A completed in its original Thread with both context-marker
booleans true. Production correctly prepended the shared-memory-risk warning
([producer](../cicada-go/cmd/cicada/machine_sealed_receive.go#L745)); the QA
canonical-reply prefix check did not recognize it. The subsequent retained-A
strict full-field/context/warning replay passed 1 test, 0 skips ([receipt](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/scope-warning-root-qa-20261010b/result.NONAUTH.json),
SHA-256 `42797bc0df3cee4911d8f3a24c5f44d169aa398d996403ab872c78db8b90942d`).
The earlier setup-only failure is retained; this replay does not upgrade the
original paid FAIL.
The [actual execution](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-receiptc20261009c002/ACTUAL-NATIVE-EXECUTION.NONAUTH.json),
SHA-256 `632f5d0e417ec7dfd6d1ce867e8fb1a358dc809918aeec59f4ade43332cc2da5`,
records 94.252 seconds. Cleanup is true, both Observer EOFs are confirmed, and
[source/owned-resource postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-receiptc20261009c002/POSTCHECK.NONAUTH.json),
SHA-256 `63be47013af306f8c7da39d210709a2cc97d1ccdaa9298ecb3c59a0c839841f8`,
keeps source and six protected residents unchanged. Clean631 Go artifacts are
separate from dirty QA/G4 test changes. G3 restore and Link revoke were not reached.

## Prior Native attempt `phasecap20261009b002`

The first paid entry `phasecap20261009b001` stopped at `GO_TYPED_BINDING`, before
Runtime/model dispatch: the Root GO supplied the fixed HTTPS upstream URL where
the typed binding requires the Runtime loopback URL. The provider stayed
`https://api.zzswitch.com/v1`; the guard was preserved. Its
[closed reproduction](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b001/PRESTART-GUARD-ROOTCAUSE.NONAUTH.json)
is not a Native failure or a production configuration change.

The corrected entry ended **FAIL**, exit 1, Root wall 89.779 seconds. Its
reported stage is `actual_queue_original_b_receive_reply`, not proof that B
failed to reply. Six Native turns started (4 manual and 2 automatic) on
original SIDs A `01a122d8-068d-7e71-914e-a40c3610f8c0` and B
`01a122d8-0925-7973-8633-30529be4ac0c`; five completed audits include B's
`cicada_receive` and `cicada_reply` in its original Thread. Read-only durable
state confirms request `rq_9688c14ad36e590918eca8938539e75d` is `REPLIED`;
B's Ask inbox/attempt is `INJECTED` and its writer is `QUEUE_ACCEPTED`. The
correlated reply outbox is `RELAY_ACCEPTED`; A's inbox/attempt is `INJECTED`
and writer is `QUEUE_ACCEPTED` at binding epoch 2. Receipt layers include
`RELAY_ACCEPTED`, `NODE_RECEIVED`, `CODEX_QUEUE_ACCEPTED` and
`CONSUMPTION_UNCONFIRMED`: durable reply and A queue acceptance are proven,
not final A consumption/context completion. The
[closed Relay/Node/writer projection](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/RELAY-NODE-WRITER-CLOSED-METADATA.NONAUTH.json),
SHA-256 `dc16e68872118443e0ec26dd2fbb6b49d87606fb5d068a7c5846fc649231917a`,
contains no message body or ciphertext. A separate
[B seeded-reply replay](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/B-ORIGINAL-SEEDED-REPLY-WITNESS-REPLAY.NONAUTH.json),
SHA-256 `314c53d19855e7263053e694e855198a3c028ce38b8c74c1cc57f8c71df30cfb`,
confirms exact received Ask IDs/sender, reply equality to the expected seeded
phrase and seed-marker presence; the question excludes the seed/answer.
This receipt proves only those synthetic-seed/actual DTO booleans. The raw
legacy `executed-managed-managed_gate.py` copy does not establish which
selected method executed. Scenario loading compiles the six-turn G2 flow to
call `self.g2_b_continuity`; the tested source's `G2_RECEIVE_CURRENT_LINK`
predicate required `receive.messages[0].link_id`, which the receive DTO does
not provide. This is a source-reproduced mismatch, not proof that the raw
legacy reply-argument guard executed. The earlier replay receipt
`12312154…19223` failed setup with `ModuleNotFoundError`; its false sentinels
are not evidence of B amnesia. The original run remains FAIL. The sixth, automatic A turn
started then ended with native error category `other`, no HTTP status and
`willRetry=false`. That error and A broker ordinal 7 `UNKNOWN_FRAMING` are
under investigation; observed A shutdown may be secondary and does not
establish a provider/framing root cause. Source remained
unchanged. The
[actual result](../.cicada-data/native-observer-wiring-20261007/request-observer-current-0162/bundle-phasecap20261009b/request-observer-native-result-cicada-two-turn-peerphasecap20261009b002/result.json),
SHA-256 `558f938fab6e0e0211b2f5c92f5876a245665c7a165d8b1b052544f06fa2e7f9`,
reports cleanup false, four cleanup `RuntimeError` classes and both Observers
`UNKNOWN_RETAINED_SUBSCRIBER`. The independent
[Root postcheck](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/native-rootops-phasecap20261009b002/POSTCHECK.NONAUTH.json),
SHA-256 `3782ab47f7e95b8fd51187fd517e67f46e1d31f88158e880cc716ea902f37370`,
confirms 11 owned selectors absent, zero fallback actions and six protected
residents unchanged. It does not upgrade the run's cleanup/Observer verdict.
The minimal contract correction passed three focused synthetic tests
(0 skips, 0.034s) and a full current selected B helper replay over retained
actual events (1 test, 0 skips, 0.022s). The
[Root focused summary](../.cicada-data/native-observer-wiring-20261007/current-peer-refresh-phasecap20261009b/receipt-contract-root-qa-20261009a/ROOT-FOCUSED-SUMMARY.NONAUTH.json),
SHA-256 `da48dc38ab09b3b58a1850f518e830996b99a5c2aa65f36941076675340cf969`,
pins gate `7f665856…03f11` and wiring checks `468ddfe5…fbf95`. The default
58-test run remains FAIL (19 errors, 0 skips, 3.539s), including frozen-binding
`PUBLIC_SOURCE_CHANGED` and old compiled-proof `G2_SOURCE_BYTES_MODE_CHANGED`
rejections. An initial nonexistent selector also failed and was retained;
the corrected focused selector passed. These passes do not upgrade that broad
run or paid002, establish A continuation, or uniquely explain A shutdown.
Fresh wrapper/binding preparation remains separate from new Native acceptance.

## Prior Native attempt `a004`

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

The acceptance definitions remain in `CICADA.md` §39. Current clean631 has
the finite TCP connector bound; its test evidence retains the earlier overlay
attribution. Prior paid002's receive-DTO correction and receiptc002's warning
prefix correction/replay retain their original FAIL records. Prior CLI 0.162.1
six-turn evidence passed both original-thread reply/context predicates, then
failed at the zero-model G2 denial tail. Earlier c G1/G2 attempts failed during
initial managed join/context after one/two started turns; their owned cleanup
and actual EOF checks passed. Latest timeoutabi10d2 G1 is FAIL/RuntimeError at
audit:60 after one started turn; its None TypeError is repaired. Upstream
response READ_HEAD is proven, but the exact rejection rule remains UNKNOWN
because existing response metadata is disabled in the actual Peer path.
Earlier b post-claim loader failures retain UNKNOWN effect counts. Current deterministic full49 passed 47 tests with 2 explicit replay SKIPs;
earlier full47 (45+2) remains source-attributed; that does not close
same-Group G1, the G2 denial tail or G3 restore.

| Gate | Current state |
|---|---|
| G1 — original-context in-group Ask/Reply | **Open separately.** Latest timeoutabi10d2 G1 remains FAIL/RuntimeError at audit:60 after one started turn; None ABI TypeError is absent, cleanup/EOF passed, full RPC/context acceptance did not. Earlier b failed entry counts remain UNKNOWN. Prior cross-Group witnesses do not establish the same-Group path. |
| G2 — same-thread multi-Group / cross-Group direct Ask/Reply | **Partial.** Prior six-turn setup/context predicates passed but denial tail failed. Latest c G2 remains FAIL during initial managed join/context after two started turns, with cleanup/EOF passed and exact READ_HEAD rejection rule UNKNOWN. Earlier b failed entry counts remain UNKNOWN. |
| G3 — Control-independent communication | **Scoped positive evidence:** current actual result records `NO_CONTROL_BUSINESS_OBJECT`, `dependency_proven=true` from production `serve --fabric-only`, and authenticated management HTTP 503. Invocation counter is `NOT_INSTRUMENTED`; restore/status-query acceptance is `NOT_RUN`. This does not close all G3 or imply an accepted in-group G1 path. |
| G4 — restart, loss and duplicate recovery | **Scoped window evidence passed:** three production component/helper-process boundaries (pre-send, Hub post-commit/pre-ACK, Node durable receive/pre-receipt) passed normal/race. The independent official 0.162.1 post-injection/pre-ledger gate passed with uncertainty retained and reinjection refused. These sources cover their respective windows; they do not prove full MCP-daemon or Native/model consumption recovery. The default-suite SKIP does not negate either actual scoped result. |
| G5 — permission and data boundaries | **Scoped predicates passed:** production HTTP forgery/Directory/Artifact denials, same-SID multi-Group grant refusal, independent Monitor approval authentication denial, historical 0.161 live-U and current 0.162.1 live-U Directory invisibility. Current U has zero turns and no materialized durable metadata/context proof. Source-equal deterministic tests cover authorization at pending delivery, writer-wait revocation and scoped reads, with recording/synthetic Native queue rather than model consumption. Shared-SID memory isolation is not proven or promised; the warning describes that limit. Generic export is unsupported, not an added gate. The actual G2 revoked-Link tail remains open. |
| M1 / M2 | Current Network M1 and Group Spaces M2 interop selectors passed. Remaining framework-wide semantics are not closed by those selectors. |
| M3 | **Scoped backend/integration evidence:** selected reference schema/pointer projection, Network Task/broadcast scope/epoch/revocation, commit cursor/unread reconciliation and parser space/claim separation have existing tests. `TestGroupSpacesMCPAcrossNodesWithLostCommitResponse` exercises reconciliation without mark-read; the parser test does not measure the long-running Agent/job loop or Native wake behavior. Full reference-to-immediate-delivery and scheduling claims remain bounded by their actual tests. |
| M4 | **Scoped v0.1 path passed:** Monitor MCP proposal, Owner encrypted delegation, guarded apply, topology projection, Owner revoke/version advance and subsequent apply denial; Store tests cover exact scope, CAS/audit, role revocation, reader separation and old key-consent fencing. The tested revoke-overlay bytes are now tracked at `631666c`. Full user/admin hierarchy and delegation UX remain explicitly v0.2, not a new v0.1 gate. |
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

## Remaining acceptance gates

- **Implementation:** keep the adopted interfaces, Guard/crypto and explicit Join boundaries; no new implementation completion is inferred from these runs.
- **Passed scoped checks:** deterministic/integration, TCP/Browser, G4 windows, G5 authorization and Apache artifact inclusion retain the evidence above; they are not blanket Native acceptance.
- **Current Native:** review the existing response-metadata adapter design for latest timeoutabi10d2 G1; preserve earlier G1/G2 failures and the unresolved upstream READ_HEAD predicate; retain strict original-context and denial-tail oracles. No blind retry or completion claim.
- **External:** current Android interoperability, physical Nodes/devices and public HTTPS remain separately NOT_RUN; historical external evidence is not current acceptance.

| Priority / boundary | Required remaining evidence | Current limit |
|---|---|---|
| G2 denial tail | Resolve the current initial-turn failure with evidence, then review separately authorized unchanged hidden-members/revoked-Link predicates. | Prior six-turn original A/B context witnesses passed; latest c G2 is FAIL with true cleanup and unresolved READ_HEAD rule. |
| G1 same-Group | Pass the original-context in-group Ask/Reply path under Root supervision of existing bounded authorization. | Latest timeoutabi10d2 G1 is FAIL/RuntimeError after one started turn; true cleanup does not close G1. Earlier failed entries/results remain retained. |
| G3 restore | Restore management and pass authenticated encrypted status queries while retaining independent peer communication. | Control-object exclusion/management 503 passed; invocation count uninstrumented, restore not reached. |
| G4 / G5 scope | Retain the three process-window and current CLI injection-window results, production HTTP authorization/Monitor denials, deterministic queue/read revocation and current live-U denial. | These predicates have scoped PASS evidence; they do not claim full daemon/model recovery or shared-SID memory isolation. No extra model turn is required for a deterministic HTTP Guard predicate; the failed actual G2 revocation tail stays separate. |
| Apache distribution artifacts | **Scoped artifact inclusion checks passed:** standard/PQ assets and both Hub images contain exact LICENSE and preserved third-party notices. | The original release-operation test error remains FAIL; separate existing-artifact checks passed 21/21. No publication, formal release or replacement of resident images. |
| External Client / deployment | Current Android interoperability, physical devices, public HTTPS, and Client pin/session/replay acceptance require their own evidence. | Earlier Client and local protocol/package/Browser results retain their separate sources; they are not these external gates. |

Preserve prior paid FAILs, guard refusals and UNKNOWN records. M3/M4 backend and
M5 HTTP/TCP evidence retain their tested scopes; v0.2 permission UX is not a new
v0.1 requirement. Overall v0.1 remains **PARTIAL**, without a completion percentage.

## Scope boundaries

The current status entries in the architecture status, plan, completion ledger,
and Client/Hub guide link to this record. The distribution schema row is v59,
matching `CurrentV2SchemaVersion` at `cicada-go/internal/store/migrations_v2.go:24`.
Schema, software, contract, source, and image identities remain distinct. The
Browser fixture is localhost-only; the PQ package Node binary, Hub image, and
M5 HTTP/TCP fixture are separate artifacts and do not establish Native PQTLS,
Android, physical-device, or public-HTTPS acceptance. Client results remain
attributed to the independent Client checkout; no Client source changed.
