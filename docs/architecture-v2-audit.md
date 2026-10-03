# Architecture v2.3 当前事实审计

## 2026-10-03 current audit — bounded checkpoint PASS; product PARTIAL

Main 的九文件 dirty 候选基于 `1ca0d3b4`，已接入 Approval commit-time Guard、build provenance/packaging 与 Node SQLite/WAL bounded opener retry。全 Go、工件/PQ/Compose 及 disposable Client Docker 的本轮门禁通过；17 项 Go SKIP 不计 PASS。源码、镜像和历史失败归属见[本轮验证记录](v01-final-release-exit-checkpoint-validation.md)。

这些结果不是 Android 在线业务或真实双 Agent Golden 验收。Native zero-turn 仅证明 LIVE_METADATA_ONLY 与 EOF；real two-turn、完整 real A→B→A 及 Android business **NOT_RUN**。整体 v0.1／Architecture v2.3 仍 **PARTIAL**；完整管理员/RBAC/委派 UX 属 v0.2。

## Historical audits before the clean-1ca baseline

以下全文保持其当时源码、镜像、APK、Runtime 和结果归属；旧 current 标题不是本节当前结论。

## 2026-10-02 current audit — 86-path integration; QA PASS（有限范围）

Main `dev` 的集成候选基于 Git HEAD `c146d58f67f6f4b3e14a8e56a8c68ddc60400713`，工作树含未提交变更；
完整源码 canonical SHA-256 为 `ec160b087221e3118022fcb22b04af1338fea5ea3257e5bf84580af346afa9d1`（1052 个路径），STD 构建输入
`source_fingerprint` 为 `4380e9f5c65c7905170fad152131dcc99d4f1acfbe9768bbe80ed30246ef7032`（882 项）。两者范围不同，均不能只归于 HEAD。
当前软件 `0.1.0-dev`、Architecture v2.3、Hub schema **57**、
`client-hub-v1.6.4`、encrypted wire **1**、catalog **55** 项操作分别记录；
catalog SHA-256 为 `953486eab6ef91ed52e4dface5fcd06ecb4b75961ef753e79532c6109bd6f93d`。

已机械集成 **86 路径 = panel 6 + review policy 13 + Task privacy 30 + D2 TLS 27 + N2 reliability 10**。
机械集成证明精确源码合并与保全，不能替代运行验收。当前统一 QA 为 **SCOPED_PASS**：41 个有限命令，243 top-level＋308 subtests，
0 fail/0 skip，30 条test-binary执行记录（18 unique SHA）；D2独立51命令的有限检查亦PASS。
这些结果仅归ec160/STD4380，不是全仓、real Runtime或新clean交付PASS。
完整身份、各范围、证据入口和下一出口见[本检查点验证](v01-group-peer-runtime-checkpoint-validation.md)。

本轮有限范围已接入：Group nesting的显式Owner动作/CAS；policy preview/grant 的当前
reviewer permission与leased binding以及双侧原proof投影；Task peer仅返回责任metadata，
拒绝旧plaintext submit，definition/result绑定已存exact Endpoint Group sealed SEND。
普通SEND只是candidate，registered reference与当前assignment/ArtifactACL/epoch/CAS才产生Task权威。
合法Control管理prose/history保留，Hub返回的Owner key是discovery，不能替代独立local pins。

N2复用持native writer后的当前Guard与原attempt/outcome；队列接受仍为
`CONSUMPTION_UNCONFIRMED`，unknown不自动重投。sealed SEND内部DTO接受既有Hub202的
`sequence`，保留strict unknown-field decode；Relay序号与Endpoint encrypted序号不同。
D2支持停止→精确离线维护→checked Hub/Node restart，非热加载或自动续期。
普通recovery.status仍依赖management provider，Control-free仅独立fresh TLS current query。

Android 既有已验收运行基线仍为 clean 144 / v1.6.1；e8 / v1.6.3 导入与
offline Kotlin candidate checks 只归原来源。Client 当前本地策略为 **39 implemented / 16 closed**，
五项 `link.key_manifest`、`link.key_grants`、`link.key_grant`、
`link.review_policy_preview`、`link.review_policy_grant` 及独立 directory permission
extension 继续关闭，待新 clean 工件交付后分别验收、逐项开放。
`link.review_policy_status` 已实现 metadata 读取，不在这五项中；它不授予签名、路由或投递权限。

旧 clean-144 Android/native、e8、原48与各组件结果保持原 source/image/APK/selector
归属；历史 FAIL、timeout、SKIP 和 NOT_RUN 均保留。本组合实际 native Runtime/model、
Android、物理设备、公网 HTTPS、生产恢复/部署验收不由 Go、cgo/OpenSSL 或合成门禁推导。
恢复 metadata 不授权解隔离、重试、重建 counter 或外部副作用重做；整体 v0.1/v2.3 仍为 **PARTIAL**。


本组合实际[QA receipt](../.cicada-data/integrated-next-core-20261002/qa/receipt.json)
SHA `567ea1f0c88192c0bd639b9d1a5804cd11a6a68e6a857f6697642d20c2e4256c`；
[D2 FINAL_REPORT](../.cicada-data/integrated-next-core-20261002/d2-qa/main-freeze1/FINAL_REPORT.json)
SHA `8e58b8a28d263f629279b0bc6cb038b78f9e5ba77bfe07e4559236f4a6d8e89f`。
两个本轮preflight FAIL保留原证据；新的clean工件交付仍待完成。

## Historical audits before integrated-next-core

以下旧current段、测试和缺口保留其历史来源；不得把“尚未集成Main”等当时结论外推到上方86路径。

## Historical prior checkpoint — 2026-10-02 integrated candidate — focused QA PASS; clean artifact pending

Main dirty source-input fingerprint `72ec78fb9e03c647f73bf611e52802301b5db7831e32485b8f3d444240aff8b4` on Git HEAD `144e079` integrates the directory/native/relay/ML-DSA work, the final Monitor/ACK correction and Link-proof patch. Candidate contract `client-hub-v1.6.3` has catalog SHA `5ab7cda2b9583d102c21113e1a3c0cdeb6764f3751154cf638006ad7036276bf`; wire 1, 55 operations and Hub schema v55 are unchanged. The integrated focused normal gate passed 49 top-level + 128 subtests across six packages, with zero skips/failures and six executed test binaries. Affected vet/build, contract check/export/verify, and Python 15 tests + 17 subtests passed. Source and standard/Go input metadata (835 / 829 entries) matched before and after. The [receipt](../.cicada-data/combined-link-proof-20261002/receipt.json) SHA is `6416728daca6fdf4e95f0b0fc60f06ad6dd4ca77ed910ab7c1f2ba90fe8c12e7`.

This current receipt is a focused combined-source gate; it is not a full default, tagged, or race rerun on `72ec78…`. Earlier full/tagged results and the broad Store race timeout stay attributed to `cb4d`; that timeout is FAIL. The integrated local dirty-source bundle `8b22ceb043067a8e41324f943795f89b9e04d447f30143bef69c43773cc0a2b9` proves contract integrity only. A checkpoint commit, clean v1.6.3 standard/PQ artifacts, exact-image gates and current Client selector remain pending. Overall architecture v2.3/v0.1 remain PARTIAL.

The final seven-path Monitor/ACK component source `31e36040363e100547303becc5267f7377af4d7dcdf897b7333a6d81885be495` passed focused normal and race at 19 top + 38 subtests each, zero skips/failures; affected vet/build exited 0. Its [receipt](../.cicada-data/combined-directory-relay-csr-20261002/monitor-repair/final/receipt.json) SHA is `40b21ebb5631cf7d60898e612b2cad00b8325c333d420b5a9d1bd73aacc4f304`. The separate 14-file Link-proof component passed focused normal/race and encrypted loopback TCP on `144e079 + Directory15`; its [results](/tmp/cicada-link-client-proof-20261002/results.json) SHA is `51b441940f1b657fae633ff248d1d6c8221dd7fa7c36cb2212c6f663187e7bb0`. Root verified those exact Link14 bytes/raw modes in Main. These component receipts supplement the integrated focused gate, but do not turn it into full/tagged/race acceptance.

A fifth zero-model native fixture used immutable clean-144/v1.6.1, not the v1.6.3 candidate. It is `READY_HELD_LIVE_FOR_CLIENT`: two endpoints joined and a visibly synthetic Owner device RPC created a `PROPOSED` Link with review policies `NONE` and no accepted sides. Its receipt records 97/97 commands exit 0, four native app-server starts and zero model/provider/turn/inject calls. The [execution receipt](/tmp/cicada-client-link-native-fixture-20261002/private-hop-freeze/approved-execution/result.json) SHA is `85ac6f8ff5f01dfac780cc9a4b53209fc9be679026cec1d9b8e0f890c697d4b1`; the independently checked three-container/three-bridge [public topology](/tmp/cicada-client-link-native-fixture-20261002/private-hop-freeze/approved-execution/new-public-topology/public-topology.json) SHA is `db4a30d22d487bc008ab9af87e518bf58a2cbfb8aabc143e3ed29fc284072dda`. It remains held for Client follow-up; cleanup has not run. Four prior fixture failures remain retained. This is not Android approval, Link activation, native Ask/Reply or message consumption.

The Client carrier preflight fails because its legacy exact-one-Hub guard rejects the valid two-Node/three-bridge topology. A dedicated Client correction is in progress against the exact public inventory; selectors are **NOT_RUN**. PQ authority D1, Task handoff and restore validation remain separate worktrees, not integrated or accepted in Main. Same-Node default Hub Relay has bounded component proof; `nativeDirect` remains unsupported. The separate Task worktree review found peer list/get/claim/renew/accept currently return objective or acceptance prose, while `task_submit` summary lacks explicit Manager recipient/purpose. Treat this as a v0.1 security release gap: the next slice needs trusted purpose classification, existing sealed-object transport plus small metadata DTOs for peer definitions/results, Task/ArtifactACL and current binding/ownerEpoch checks, and rejection of legacy plaintext routes. Legitimate Control-management plaintext remains explicit. These boundaries do not change the overall PARTIAL status.

## Historical 2026-10-01 Network directory-only native binding guard correction

On dirty source `f4e4725c5d81c54b166f4291b9d450c70954e6df`, the five-file correction fingerprint is `65ab2a5b67a6556efb1228b3ca7516e1be68d63b8348d08c2b21ca8bbbd2a43a` (per-file hashes and commands: [focused evidence](../.cicada-data/next-checkpoint/network-member-binding-20261001/result.json)). `EnsureNetworkDirectNativeBinding` now requires current Network membership/session/identity scope but does not require a direct-send/receive, Task, or Broadcast action grant. The Group admission path remains separately authorized and persists only member role; no traffic permission, key grant, or key material is inferred. Candidate/key publication and peer/traffic routes keep their existing action-purpose guards.

The six Store selectors and the production HTTP entrypoint selector passed on that owned-source fingerprint. Focused race selectors passed for three Store selectors (120.830 s) and the HTTP selector (17.788 s); logs are `store-focused-final2.log`, `server-focused-4.log`, `store-race-focused-final.log`, and `server-race.log` in the evidence directory. An earlier broader Store race run timed out after five minutes during repeated migration-fixture setup; it was not a race report or a pass and remains recorded as such in `store-race.log`. This is a bounded guard correction, not full-suite, Browser, Client, or Node-intent acceptance. No schema, wire, key, or cryptographic format changed.

## Historical 2026-10-01 C4 unified checkpoint (bounded PASS)

The frozen C4 source fingerprint is `31dccec5b771589c1b93eb851d4539932202ad664fd8842e3764d676a99c0fc2` (dirty `dev` based on `f4e4725c5d81c54b166f4291b9d450c70954e6df`, catalog v1.6/55 operations). The full Go gate passed with 1,105 top-level tests, 553 subtests, 27 packages, 12 skips and no failures; build, vet, contract and Python 26 also passed. The Client, Network M1 and Group Spaces M2 Docker tests ran and passed, as did the 12-step loopback Browser gate. See the [canonical ledger entry](completion-ledger.md#architecture-v23-completion-ledger) and [frozen gate evidence](../.cicada-data/next-checkpoint/closure-20261001T165647Z/gate-summary.json). C4 still does not accept native Runtime, physical Nodes or public HTTPS; pure PQ product TLS is not implemented.

The predecessor C3 Docker failures and Browser `context_policy` projection failure remain separately recorded at fingerprint `5b8f151377455ded03a5b71113528c51c3c1e2363855bad0d4e59ce517b9ebf3`; C4 reran and passed the affected gates after repairing the interop test-stage permissions and topology snapshot projection. The [C3 summary](../.cicada-data/next-checkpoint/closure-20261001T161902Z/gate-summary.json) is retained unchanged.

## 2026-10-01 Node provider attempt and intent fencing

Provider outcome writes now carry an exact positive `Attempt` and update only that live generation; delayed outcomes from an older generation are rejected, including an identical outcome class. The Node-wide provider sidecar adds `node_provider_admission_intents_v1`, binding an immutable hash of the locally generated admission intent to `(execution_id, provider_id, attempt)`. A version-2 local claim ticket persists the random intent beside the sealed claim before provider execution. If sidecar admission commits but persisting its returned generation fails, a recovered READY ticket can repeat admission with that same pre-existing intent and recover only its matching generation; it never adopts a generation by reading “current attempt.” EXECUTING tickets are not automatically redispatched.

Legacy version-1 tickets and legacy admission rows without an exact intent binding remain held and fail closed. They are not silently assigned a token, retried or migrated; explicit local reconciliation requires an exact ticket/generation and, for resource-bound work, an exact confirmed-stop fence. The provider ledger's bounded admission/backoff and uncertainty state are implemented, but the Runtime does not yet emit structured provider rate-limit/retry outcomes; real provider throttling remains unaccepted. Focused race evidence is retained in [`provider-admission-wal-intent-20261001`](../.cicada-data/provider-admission-wal-intent-20261001/run-20261001T161224Z/go-test-race.log); full acceptance belongs to C4, not that earlier focused run.

## Historical 2026-10-01 Go 1.27.1 PQ transport capability and exposure audit

This is a transport capability diagnostic, not a new CICADA build/test acceptance and not a change to `CICADA.md`'s cryptographic requirements. The standalone synthetic probe used container `golang:1.27.1` (`sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244`) with `--network none`; source, exact command, toolchain source excerpt, raw stdout/stderr, exit code and file hashes are retained under [`../.cicada-data/next-checkpoint/pq-transport-audit/`](../.cicada-data/next-checkpoint/pq-transport-audit/). It established local TLS 1.3 mutual authentication using synthetic ML-DSA-65 certificates and pure ML-KEM-1024, negotiated `TLS_AES_128_GCM_SHA256`, and rejected an X25519-only client. It exited 0. This does not satisfy the specified pure ML-KEM-768 plus `TLS_AES_256_GCM_SHA384` profile and does not exercise CICADA's server, Node, proxy, deployment or application protocol.

The evidence is independent of product source identity: the repo HEAD at probe start was `f4e4725c5d81c54b166f4291b9d450c70954e6df`; the subsequently frozen closure candidate `d205771bee22a79ec2c55e47f733d2b46e533c582e3c108e35b4c60c3c0cf0bb` did not supply the standalone probe. Neither the candidate's Go/full-gate result nor its Docker evidence is transferred to this diagnostic.

At the exposure-audit snapshot, the production `serve` and `serve-fabric` paths called `ListenAndServe` without a TLS config; `validateServeExposure` accepted non-loopback when an API bearer was present. `docker/Dockerfile.hub` defaulted to `serve --host 0.0.0.0`, while owned fixtures relied on this internal bind with their own network/host-port boundaries. Compose used host loopback, and Docker fixture publication did not make all external deployments loopback-only. At that time `main_security_test.go` treated a configured token as sufficient for non-loopback exposure. Bearer authentication did not encrypt HTTP.

At that snapshot, remote Node enrollment checked the `https` scheme and clients used Go's default system-root/hostname-verifying transport; product TLS client certificate/mTLS, Hub ML-DSA pin and exact PQ group/suite gates were absent. Node auth remained application bearer/NodeControl-key authorization. The application E2EE and visible metadata boundaries described here remain independent of transport TLS.

Primary-source checks: [Go 1.27 release notes](https://go.dev/doc/go1.27) and [crypto/tls API](https://pkg.go.dev/crypto/tls); [TLS ML-KEM draft](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) and [TLS ML-DSA draft](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/); [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), and [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html). Go 1.27.1 source in the probe image listed hybrid ML-KEM-768 groups and pure ML-KEM-1024, but no pure ML-KEM-768; its public `CipherSuites` field only configured TLS 1.0–1.2, not TLS 1.3. That standard-library limitation remains the probe's result. At audit time the optional OpenSSL adapter had demonstrated the profile but product endpoint wiring had not yet reached Main; later Main integration and its source-specific status are listed above. No cryptographic specification changed.

At the time of this exposure audit, implementation planning called for separating disposable HTTP fixtures from production listener exposure. Later Main integration supplies direct PQ listener/client and current-authority wiring; exact-image acceptance and new image remain pending. This audit changed no listener, key, dependency or deployment.

## 2026-10-01 Native context history coverage boundary

The shared Node `WriterRoot` registry now reports `native_history_coverage=CICADA_KNOWN_ONLY` for every checked decision. A fresh/empty registry with `shared_memory_risk=false` means only that no conflicting Cicada-recorded scope was found; it does not prove that the native Runtime has no earlier thread history or that an unobserved path did not reuse it. A bypass that did not check the registry must report `NOT_CHECKED`. The registry stores hashed native identity and bounded scope/binding metadata, not conversation contents or native filesystem locators. A Group-only Join legitimately has an empty `NetworkID`; the registry requires at least one trusted Group or Network scope, and requires a real Network ID for `dedicated_network` or a Network-only scope.

Known `dedicated_thread` and `dedicated_network` rows remain authoritative across Leave, rebind, Endpoint replacement and Hub changes under the same trusted Node account/native identity. Ordinary scopes may be reused but are reported as a shared-memory risk; a dedicated Thread conflicts with any different known scope, and a dedicated Network permits other Groups only within the same Network. The current focused `TestNativeContextHistory*` tests cover Group-only scope, the empty-registry coverage label, symmetric known-history conflict cases, reopen/rebind retention, cross-Hub conflicts and exact retries at small test caps. This is a deterministic registry test result, not native Runtime, cross-process multi-Hub or full-Go acceptance. Existing full-history and external-runtime visibility limits remain.

## 2026-10-01 v0.1.x acceptance checkpoint

The historical f55 product candidate was frozen as source `f55b5255628030857ac88bd7edbd6da7da1b63d543014c76111f9219f46ad255` (dirty bd79 base) and Hub image `sha256:da88805eaa1987a1c6e06448fc5cddf7d4ce368e8b5eeb3071a1406dad2cb977`. Its full Go, vet, v1.6 contract, 19 Python tests and three disposable Docker suites passed. The detailed 1,079 Go + 535 subtest counts and image-specific results are in [the checkpoint report](v01-completion-checkpoint-validation.md). This is a dirty development candidate, not a clean Client handoff or release.

The preceding 432f snapshot has separate PASS/FAIL results: full Go, vet, focused race, contract/vector, WASM and bounded Chrome loopback flow passed; its Client Docker fixture failed and was repaired only on different source/image `cf168`; a bounded same-process M5 test passed; V68 and the first real Worker approval run failed; later 840a joined Docker and 432f Worker driver-overlay passed with separate source attribution; the first Node-Control HTTP driver failed but a later synthetic-identity HTTP_PROTOCOL overlay passed on 432f product source. None of these 432f Browser, race, M5, V68 or native results transfers to f55. The source-specific report preserves exact logs, result paths and cleanup states.

The f55 Browser passed with the limits above; Joined V68 passed on a separate 840a test-helper overlay; the prior 2858 production-equivalent source gate passed before C4. C4 later passed the fixed-image Browser and three actual Docker test suites on its own source. Two isolated Hub processes, physical dual-Node, public HTTPS, capacity stress, provider-native throttling and production process-stop/reconciliation remain unaccepted or NOT_RUN. The C4 `uncertain_write_fence` Browser step used controlled synthetic durable-state injection, not an actual process-kill window. M5's bounded same-process result is not a dual-Hub deployment gate. The independent Client v1.6 result belongs to clean f4 and Client commit `9cf2b81`; it does not transfer to C4. No result implies complete Architecture v2.3 delivery.

## 2026-09-30 全剩余目标核对（M2 checkpoint 后）

审计起点为干净 `dev` `f30892fcd79a27bfe5604575deaecebe52c5ec50`，其 M2 验收记录仍归属既有 dirty fingerprint。`5414d6edee44e2be1cad04d10181fd1a23ccd3bf0004fa3fb7bb66776448de83` 的[后端门禁](../.cicada-data/architecture-wide-accepted-20260930T121202Z/gates-summary.json)前后源码一致：1,307 Go PASS、11 SKIP、25 包 PASS、vet PASS、13 项 race PASS、八项 Python PASS、三套 disposable real-TCP Docker PASS。另一个[真实浏览器结果](../.cicada-data/hub-web-panel-browser/20260930t131113z-251515-c3ac163f/result.json)在同一 fingerprint 的 Hub 镜像 `sha256:6a21824109c755cc47b345d0cd63b97c49b0d51306420c160ba4ab7b8aa9b475` 上，以 Chrome 151 和 loopback fixture **PASS**：Owner Hub pin、Go WASM、加密 vault、设备加入、加密 topology/status/canvas 与可见 Group。它不是公网 HTTPS；`UNCERTAIN` 写入故障注入 **NOT_RUN**。随后 `e13b3848…` 的[全 Go 门禁](../.cicada-data/architecture-wide-finalfix-20260930T123606Z/gates-summary.json)为 1,308 PASS、11 SKIP、25 包、vet 与八项 Python PASS，但其真实 Codex CLI 0.159.2 在最终 route allowlist **FAIL**；`434c4eb6…` 的[原生重试](../.cicada-data/architecture-wide-nativefix-20260930T125600Z/gates-summary.json)因模型截短 synthetic Group ID 在首个 Join **FAIL**，该次未运行 ASK/REPLY。更早一次 stdio MCP helper 缺 `CODEX_HOME` 也为 FAIL。v41 原子 nested Group 创建和更新的 M5 durable-completion 测试已进入 `c33f…` 独立冻结门禁并通过；旧 PASS 仍只归属原 fingerprint。最终 [c33f 有界检查点](v01-group-panel-checkpoint-validation.md)同源前后不变：1,336 Go PASS/11 SKIP/0 FAIL/25 包，vet、36 项 race、八项 Python、WASM/格式/模块/脚本、三套 disposable Docker 均 PASS；Chrome 151 loopback 浏览器在 image `sha256:6940829857d0135fd21349a55a367dc530f4c3cf4c3282aa62c841729af3d123` PASS。真实 Codex CLI 0.159.2 的同 Group 两逻辑 Node ASK/REPLY 以受控 safe-point resume PASS（325.20 秒；原 Thread/context、密文、Control 0 调用断言）；它们在一个容器里，非 V68 双隔离网络 Node/物理机/cold wake。当前 Android v1.5、物理 Node、公网 HTTPS 仍 **NOT_RUN**。根矩阵见[完成账本](completion-ledger.md)。

当前 M3 已有工作树接线：Core 在 `internal/store/group_space_sync_v2.go` 和 Fabric `group_spaces.go` 提供 commit-order hint/read cutoff/read-state/mark-read；Server 在 `spaces_v2.go` 与 Node SSE route 中接线；Node 本地 Unix bridge 和 MCP 提供同步工具，并在 Node 分离 space sync 与 peer wake。`TestGroupSpaceSyncUsesCommitOrderAndRetainsWatermarkAfterPurge` 覆盖乱序 commit 与 purge 后水位；这些代码已进入上述确定性后端门禁，但即时 SEND/ASK/广播引用、Network Task offer 与真实 native 未读行为尚未闭环。

M4 已有精确 Owner route/delegation、Monitor proposal、CAS apply 与 audit 的确定性实现及 `TestDelegatedRegroupExactOwnerConsentCASAndAudit`；它不证明真实 Owner/Monitor 产品流。M5 已通过的旧测试 `TestMachineHubContextPinsNodeTokenAndOrigin` 与 `TestNativeWriterSerializesAcrossHubScopesAndPersistsEpoch` 只证明本地 origin/token pin、writer 串行化与 epoch 审计；后续 durable native-outcome 测试在 `c33f…` 有界门禁 PASS，只覆盖已测试的本地迟到/不确定完成路径；不把旧 epoch 测试说成该 fence。两 Hub、两 Node、独立 Client 的真实服务闭环仍缺。Web canvas 在 `5414…` 和 `c33f…` 各有独立 image-pinned Chrome 151 loopback PASS；v40 新记录跨 Owner Group board 在双方独立 consent/admission/key proof 下有 Store/Nodekeys 确定性测试，跨 Owner 历史继续拒绝，Android/native 内容体验未验收。v41 将 Client `topology.apply` 的 nested `group.create`、Owner Membership、parent 与请求恢复账本纳入单事务；隔离 checkout 的 Store/Control 全包、定向 race 与 vet 已 PASS，主仓 `c33f…` 全量 Go/race/迁移门禁亦 PASS，不声称 parent CAS。V67 现有 same-Node native queue 证明与一般 TUI direct adapter unsupported 分开列为 PARTIAL；V68 按 Docker 隔离 Node 标准判断，不额外要求双物理主机。Managed Blob 写入已有 executor epoch fencing；GPU/workspace/general shell/长 Native execution 仍是 advisory。

部署审计确认旧 `docker-compose.yml` 的 worker profile 是 `sleep infinity`，控制服务复用含 Codex 的旧开发镜像和共享 `cicada.env`；旧安装脚本默认 `main` 且要求模型/API bearer。当前可用的安全 bootstrap 原语是 `/v2/nodes/device-code`、Android encrypted `nodes.preview/confirm` 和 Node 只出站 `machine agent`，不是 PIN 替代身份/Owner grant。本轮改造目标转为本机轻量 Hub + 可选 Node agent；生产公网 HTTPS 与 runtime/pairing UX 仍分层记录，不将本地 compose 当成公开 release。

## 2026-09-30 M2 Group Spaces 后端有界验收审计（历史冻结源）

冻结源码 fingerprint `76becd7a479dfd801427fc470c376517227f67b293392d4cd7e314f5fa5b6e7c` 前后一致；全 Go 25 包 1292 tests PASS、0 FAIL、11 opt-in Docker/native SKIP，vet EXIT0，见 [accepted Go gate](../.cicada-data/m2-20260930/accepted/go-gates.json)。SKIP 不计 PASS。六包聚焦 race 与 M2、Client、Network M1 三套独立 disposable Docker 门禁均 EXIT0；gofmt、Client v1.4 合同、八项 Python、shell 语法、diff 检查亦 EXIT0。各层证据见 [M2 validation](group-spaces-m2-validation.md)、[race](../.cicada-data/m2-20260930/accepted/race.json)、[本地检查](../.cicada-data/m2-20260930/accepted/local-checks.json)及 [M2](../.cicada-data/m2-20260930/accepted/group-spaces-m2-docker/result.json)、[Client](../.cicada-data/m2-20260930/accepted/client-docker/result.json)、[Network](../.cicada-data/m2-20260930/accepted/network-m1-docker/result.json) Docker 结果。

边界审查实测 32 名合法读者和 16 KiB 正文时，commit JSON 为 2,116,357 B，16 页读投影为 2,530,333 B；Node/HTTP 与持久 sealed cache 因此采用 4 MiB 有界上限。每份新 reader envelope、历史重封装都从既有 Node `(Endpoint,key)` 持久出站序号账本单独预留，不能误用 Group-local record sequence；已经缓存的丢响应重试复用原字节且不前进序号。聚焦 MCP 测试包含这个精确重试/序号性质和 Topic resolve/get/reopen CAS。

该历史 M2 候选从 `dev` `7c4194155d6c0c342671299e447c907f0b1d94d6` 起步，源码为 dirty 工作树；不能把测试归于单独 HEAD。M2 新链使用现有 Node 凭据与 Joined Group Session 双重鉴权；Hub/Store 当前 Network、Group、Endpoint、绑定 epoch、membership/lease 与 `space.read/write/moderate` Guard 在 prepare、commit、get/list 和单记录历史步骤分别复查。Node 核对原 Codex session record、Hub current binding、独立安装的 Owner 公钥、当前或签入时刻的 Endpoint key proof、外层重封装者与内层原作者签名，才将 16 KiB 内正文返回 MCP。Hub 只持久化逐读者密文、签名证明和受限路由元数据；Node bearer 与私钥不出 Unix 桥。该 M2 切片拒绝跨 Owner Group、明文 HTTP 降级、模型自称 Owner 批准和旧成员原 ciphertext 对新成员的自动扩权；后续 v40 已新增双 Owner 新记录路径，不回填 M2 历史。

聚焦合成两 Node MCP 测试已通过原作者与另一读者解密、丢 commit 响应后的原字节重试、模型伪造 sender、撤写拒绝、撤读再授后的 cutoff 拒绝与独立 Owner 离线签精确旧记录后的重封装读取。该证据只覆盖测试中的合成 Codex session record 和 in-process Hub HTTP handler；独立 disposable real-TCP Docker、合法容量上限、全 Go/vet/race 和源码指纹均已在上方对应候选证据中独立验证。M2 [合同](group-spaces-m2-contract.md)取代旧 [设计提案](group-collaboration-spaces-design.md)中的拟议接口名；Client v1.4 管理合同、Android 内容界面、真实原生 Runtime、物理 Node、公网 HTTPS 没有借此获得 PASS。

## 2026-09-28 M1 Network backend 验收通过

当前 v36 backend 候选在 `HEAD=733ca8640f86f4944b4f8d8f7c38f6cd929212f2`、`dirty=true`、源码指纹 `479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe` 上通过全 25 个 Go 包测试、vet、gofmt、16 项精准 race，以及隔离的 Client 与 Network disposable Docker 门禁；门禁前后源码指纹一致。证据见 [本轮 Go 门禁](../.cicada-data/m1-final-20260928/accepted/go-gates.json)、[Docker 门禁](../.cicada-data/m1-final-20260928/accepted/docker-gates.json)、[M1 代码审计](m1-code-audit.md)与 [M1 验证矩阵](network-m1-validation.md)。这是该 dirty 候选的 backend 验收，不是仅凭 HEAD 的干净构建，也不代表 Android、真实 native Runtime、物理设备或公网 HTTPS 已运行。

本轮 v36 为无 Group 的 Network Endpoint 增加真实 native delivery binding、Endpoint 公钥候选、Owner 接受的 key grant、一次性 nonce 与消息路由五类账本。Network membership、目录、原生 writer、公钥授权和密封 Relay 各守其职；direct SEND/ASK/REPLY 复用原有 Relay request、inbox、attempt、receipt 状态机和 Node 本地持久 outbox/inbox，不建立影子 Group 或新常驻 worker。Group SessionBinding 与 Network access session 均不能单独充当另一种授权。跨 Network 的相同 Endpoint 与 idempotency key 在独立 scope 内处理；撤权、重新加入或真正 native writer 接管不得让旧尝试恢复。

Endpoint 自证明和 Owner key grant 使用固定 canonical 签名输入；Node 在加密和解密前用本地独立固定的 Owner 公钥验证 Hub 返回的证据。Owner 预览可见原生 Thread locator，peer bundle 不返回该 locator；Node 还要比对 Owner 签名 manifest 内的 native Session digest 与本地已验证 Thread。公开向量仅含标明为 synthetic 的材料，不能用于部署。现有 Group-only native writer 与 Network-only 路由的共存、恢复、最终注入授权及真实 HTTP/Client v1.4 门禁已纳入本轮合成与 disposable HTTP 验收；真实 native Runtime、Android、物理设备和公网 HTTPS 尚未验证。

本轮跨入口审计还修复两项确定问题：双向 JSON-RPC 中 server request 的数值 ID 可与 client request 碰撞，旧 stdio 与 WebSocket adapter 会把它误当 response；两种 adapter 现先按 method 区分请求/响应，fake 协议回归覆盖同 ID。Hub SQLite 含 ratchet 密钥，原默认 StateDir/DB 权限可能受 umask 022 影响向其他本机 UID 开放；Store 初始化现将专用目录收紧为 0700、DB 与已有 WAL/SHM/journal 收紧为 0600，拒绝目标 symlink，保留既有数据。原生 SessionBinding lease 与 mapped Network 授权期限均改按 RFC3339Nano 实际时间比较，坏日期拒绝；目录分页前的 SQL 期限过滤也使用同一精确判断。上述修复已纳入顶部列出的最终门禁。

## 2026-09-28 M1 ACTIVE 入口与撤权复审（有界检查点 PASS）

本轮候选保持 Hub schema v35 和冻结的 Client `client-hub-v1.3` / 33 operations。Network access credential 与原生 Group SessionBinding 分离：前者只可访问当前 Network 的目录和获授邀请操作；它不能凭 `Cicada-Group-Scope`、请求体中的 Node ID 或 operator bearer 取得 Group、Node、device、approval 权限。同一原生 Thread 可分别加入 A/B，A 的续期或退出不更换 B 的 access session，也不替换 Group native writer。ACTIVE 未映射 Group 继续拒绝；Control 业务服务为 nil 时，Fabric HTTP 的合法密封 ASK/REPLY 可独立完成。

映射批准会推进 Group 授权 revision，使旧 Group key-grant proof 失效；Owner 须在明确 Network enrollment 后重新 Preview、签名并接受当前 Group Endpoint key grant。Network 撤权还会推进相应 Group/Endpoint 授权 revision，旧消息与旧注入尝试不得因重新加入而复活。定向真实 HTTP 测试覆盖 mapped Network 上同组 sealed ASK→claim→delivery authorization→REPLY→REPLIED，以及目标撤权后旧 SEND/ASK 重试、新 SEND/ASK 和待决 REPLY 入队拒绝。MCP 定向测试覆盖 Network-only 私有状态只可目录、Group 工具本地拒绝。全 Go、vet、聚焦 race、合同与八项 Python、默认 Client 和独立 ACTIVE Network disposable Docker 门禁均通过；准确 dirty source fingerprint、两套隔离 fixture 与清理核对见 [Go 门禁](../.cicada-data/checkpoint-next-20260928/go-gates.json)、[Client 结果](../.cicada-data/checkpoint-next-20260928/client-docker/result.json)、[Network 结果](../.cicada-data/checkpoint-next-20260928/network-docker/result.json)及[清理记录](../.cicada-data/checkpoint-next-20260928/cleanup.json)。参阅 [M1 合同](network-m1-contract.md) 和 [验证矩阵](network-m1-validation.md)。

本轮 `AcceptTaskResultForActor` 在写事务复查完整 native actor；其他 Task Claim/Release/Renew/Submit 写入口在写事务复查当前 Network、Endpoint 和 Owner 绑定，但不等同于完整 native actor scope。旧入口与历史读的全面矩阵仍未完成。全量合成账本保全已验证：93 个保全摘要条目（含 v34 迁移账本；52 个非空）一致，9 张新增 Network 表在注入失败后回滚；迁移 dry-run 的完整影响清单与真实 StateDir 一致备份、恢复演练仍未验收。ACTIVE Client `group.create` 无 Network selector 是下一轮 Client 合同协作，不在本次冻结目录上静默补字段。Network-only 且无 Group 不能 DM；跨不同 Group 的 Link 要求双方各有同一 Network 下的有效 Group scope 与双向 Owner 授权。真实 native Runtime、Android、双物理机、公网 HTTPS 本轮均 **NOT_RUN**；整体 M1 **NOT_COMPLETE**。

## 2026-09-27 M1 Network scope 与旧入口审计（起点 `0cda614`）

下表是 M1 的实施前审计快照，不代表当前代码或验收结论。`dev` 在
`0cda61460757246789970782584b1e904173e653` 干净起步。该提交的 Go 核心没有
`NetworkMembership`、`NetworkAdmin` 或可信 `network_id`：既有 Guard 以 Group、
Endpoint、Principal、SessionBinding 和 owner 为主要作用域。现有 Group 边界不能
被误写成同 Hub 多 Network 已隔离。

风险最高的是只加 Network 新路由而未把可信 scope 推进现有服务和 Node 检查点：

| 旧路径 | 起点行为与 M1 风险 | M1 必须覆盖的检查点 |
|---|---|---|
| `internal/fabric/service.go`: `JoinForNodeCredential`, `join`, `AuthenticateForGroup`, `Authorize`; `internal/fabric/model.go`: `Actor` | Join 按 Harness/native Session 全局定位 Endpoint，再以单个绑定续租/轮换凭据；Actor 及授权上下文包含 Group 而无 Network。模型或 HTTP header 自带的 scope 不能建立成员身份。 | 每个 Hub/Network 注册需可独立认证、授权并撤销；不得为同一原生 Session 切 Network 时夺取当前 Node writer、重建 native Session 或覆盖其他 scope 的 binding/receipt。Network membership 与 Endpoint-Group join 分开求交。 |
| `internal/server/server.go`, `internal/server/fabric_v2.go`: `/v2/fabric/*` | Session credential 后由 `Cicada-Group-Scope` 选已加入 Group；对 legacy 上下文未强制 Network scope。JOIN 使用另一公共入口。 | 每个旧 route 必须将可信 Hub/Network scope 映射进统一 Core Guard，或对无法安全映射的请求显式拒绝；不能把传入的 Network ID 当作 credential。 |
| `internal/fabric/relay.go`: `Send`, `Ask`, `Reply`, `Request`, `CancelRequest`, `Receive`, `ClaimNodeDeliveries`; `internal/store/relay_v2.go`: `ReceiveRelayInboxForBindingGroup`, `ClaimRelayInbox`, `ClaimRelaySealedV1Inbox` | 请求及收件记录保存 Endpoint、Principal、Group 与绑定 epoch。读历史、回 Reply 和 claim 以 Group 为边界。Node claim 会扫描该 Node 上多个 Endpoint；SQL 当前检查 recipient 的 Group join，却没有 Network membership。 | enqueue 和每次状态/历史读取都检查当前源、收件方 Network membership 与资源范围；Reply/status/cancel 复核原请求的可信 Network；claim 不能只依赖 Group。撤权后 enqueue、claim 和收件读取都要拒绝。 |
| `internal/fabric/local_delivery_authorization.go`, `internal/store/local_delivery_authorization_v2.go`, `internal/fabric/native_wake_authorization.go`, `internal/fabric/sealed_link.go` | same-Node 授权/最终 wake 和 sealed Node claim 以 Endpoint、Group、binding、Link 或 Node 凭据为锚。Node scope 可包含多个新 Network registration。 | 源与目标 Network 必须相同或满足精确已授权规则；在最终 Node injection/wake 入口重新验证当前 grant/revision。一个 Network 的权限不能借同 Node、本地队列或共用 binding 写入另一个。 |
| `internal/fabric/artifact_v2.go`, `internal/store/artifact_v2.go`, `internal/fabric/task_v2.go`, `internal/store/shared_task_v2.go`, `internal/server/task_v2.go` | Artifact read grant 和 Shared Task/list/claim/result 以 Principal、Group、Task/Artifact scope 授权；直接 Store 方法也可调用，不能只在 HTTP 边界加租户检查。 | Group 资源须经其唯一 Network 映射后授权；Task offer/claim/result 单独核验 Network grants，不能暴露任务来源 Group、历史或 Artifact。撤权复查覆盖 claim、修改、结果和证据读取。 |
| `internal/server/directory.go`, `internal/server/federation_v2.go`, `internal/server/groups.go`, `/v2/management/endpoints` | 旧目录 announcement/records、GroupCard/federation 集合、Group 与管理 Endpoint API 由管理 bearer/owner 上下文处理，没有 Network 地址空间。 | 对现有用户 API 做显式 scope 迁移；全局管理凭据不能充当 NetworkAdmin，也不能让按 nickname 查询先于 scope 过滤。重复 nickname 必须在授权范围内返回歧义。 |

当前 v35 使用 additive schema、只读 inventory、prepare/mapping、版本校验 approve，再单向 activate。`PREPARING` 时只有尚未映射的旧 Group 是 `LEGACY_UNSCOPED`；`APPROVED` Group 在激活前立即受到严格 Network Guard，Network 新 API 从引入起亦严格校验。激活后仍未映射的 pending Group fail closed。合成 v34→v35 测试仅证明选定 Client key/device/replay、Monitor、Group/Endpoint/原生绑定状态保留；无 Network enrollment revision 的旧排队消息保持原 ID，但映射后不自动获得新授权。

有界基础检查点 `b0081a0` 的独立 Docker Client 与 Network suite 均通过；测试专用提交 `f9d3c7e` 将旧迁移 fixture 的 v34 ledger 预期补至 v35，随后完整 Store 包复验通过。它不等于完整 M1：跨旧入口、撤权后历史读取、Node 投递及管理边界仍有矩阵缺口。冻结的 Client v1.3 `group.create` 不带 Network selector；默认 PREPARING Client gate 不能证明 ACTIVE Hub 兼容，ACTIVE 上缺少 Network 的新 Group 申请会被拒绝。详细证据和未完成项见 [迁移说明](architecture-v2-migration.md) 与 [M1 验证](network-m1-validation.md)。

## 2026-09-27 Monitor intake 与 Node notice scan 有界性复审

v34 在现有账本上增加 consent 元数据列、三条活动记录索引和 per-Node notice
cursor。Admission helper 在同一 SQL transaction 中通过带 `LIMIT/OFFSET` 的
索引探针检测是否已达到阈值，不遍历完整历史账本：16 个未过期 PREPARED/
APPROVED/DISPATCH_AUTHORIZED 记录封顶每个 owner/device，64 条封顶同 Owner 的
所有设备。过期记录不计；设备撤销仅停止未来授权，不提前回收其仍有效的容量。
错误信息不区分触发的是哪一层限额。Helper 由新 Prepare 分支在确认精确重试之后
调用，所以同一已持久请求的幂等恢复不消耗新槽。

Node 列表不再在一次 Store 锁持有期间扫描任意数量的历史页并逐条运行完整 Guard。
每次最多取 16 个 owner-wide 活动候选，先按 expiry/preview ID 从索引分段读取；
随后在 Go 中排除非本 Node 的记录及最终回执，并对其余项逐条重验当前完整 Guard。
因此一次最多做 16 次深度候选检查，但不保证返回 16 条；其他 Node 的条目也会占用
当前 page。候选包含准备态以外仍有效的批准记录，但不改变授权或回执。

持久游标以 Node 为键、owner 和 `(julianday(expires_at), preview_id)` 为位置，
在列表 transaction 内推进。崩溃/重启保留位置；当已无更大位置时回卷至小于或等于
当前 cursor 的记录，使仅剩的一条未 ACK 通知仍可再次读取。即便候选因 Node、Guard
或终态回执被排除，也推进已检查位置，避免永久停在坏行。游标不是 ACK/授权；空页
可能只是扫描到其他 Node 或被 Guard 拒绝的条目，消费者必须继续定期 reconciliation。
SSE hint 合并时，后续轮询负责逐页推进，不能承诺积压工作都由单次 hint 即时送达。

验证覆盖设备与 owner 过限、准确重试绕过新配额、过期释放、已撤销设备仍占槽、
v33→v34 保留已有 preview、超过首个 page 的有效 notice、重启后推进，以及单 pending
row 无 ACK 时重复可见。Go 1.27.1 Bookworm 聚焦 Store limits/migration tests 通过。
五项 Store Monitor 并发、重启与 uncertainty -race 测试也通过（67.007 秒）。
Client contract check 和七项合同/恢复 Python 测试也通过；定向 TCP Monitor HTTP
lifecycle 与 Relay 测试通过。整仓 `go test -count=1 -timeout 15m ./...` 与
`go vet ./...` 先前通过；随后修正 Confirm response projection/OpenAPI mismatch 与
inactive Group 拒绝，并通过受影响 Control/Server 全包测试、vet 和聚焦 race 复验，
Store Monitor 并发/恢复 race 也通过。仅最终干净 artifact 和 Docker 门禁待确认。先前
2026-09-26
审计中“Store 候选页 64、总扫描 CPU 随陈旧候选增长”
是 v33 快照；当前页为 16 并有持久轮转游标。它仍是有界批次而非“每次完整清空队列”
保证，新的 Android/native Monitor 与公网 HTTPS 验收仍为 **NOT_RUN**。

## 2026-09-26 Node 管理通知与资源边界复审

v31 的授权账本不是完整执行链。此次接入使用独立管理通知 inbox、Node 专用
Fabric 路由和仅接受批准 ID 的 `cicada_monitor_broadcast`。Node 校验本地独立
Owner 信任以及原始登记签名后才打开 Client→Monitor 密文；Hub 提供的公钥不能
替代本地信任。原登记只保存 nonce 摘要，故 v32 增量保留原始公开签名 Grant；
历史设备缺少该证据时，新增 Monitor 路径拒绝，不能重新授信或凭空生成证据。

资源审查发现：无新通知且 inbox 尚不存在时不应创建 SQLite 文件；已有 regular
inbox 仍须打开以恢复持久工作。`TestMachineMonitorNotificationEmptyListDoesNotCreateInbox`
验证前一边界。通知列表之后原有重复 detail 查询；未完成/重试广播的本地进度
也曾覆盖旧 ACCEPTED 结果。本轮保留一次注入前复核、删除冗余读取并实现单调
结果合并。Hub 列表每页 64 个候选、最多返回 16 条；活动通知有期限索引。这限制
单页内存，但大量尚未过期、仅在逐条 Guard 复核时才发现已撤权的候选仍会增加
总扫描 CPU，不能称为与历史量无关的常数复杂度。不得用硬截断造成合法通知饥饿。

安全与轻量同时验收：继续使用 Go、SQLite 和现有出站连接，不新增常驻协调
服务；每次通知列表最多 16 项，Group 广播最多 32 人、每批最多 8 项，正文与
报文有上限。干净 `f1b99c4` 精确镜像通过 disposable Hub smoke/recovery；首轮
空闲测量记录 RSS 约 25.7 MiB、受限 cgroup 内存低于 128 MiB，但 cgroup CPU
含探针开销，Hub PID 1 统计的复跑结果待补。测量只描述空闲 Hub，不代表模型、
Node 或负载边界。不将后量子应用消息保护表述成所有 TLS/历史明文路径均已完成
同等保护。

## 2026-09-26 Monitor 广播与旧写入口审计

起点为干净 `dev` / `45206a2`。现有 MCP 普通 SEND/ASK/REPLY 经 Node 密封，
公开 `/v2/fabric/send|ask|reply` 在读正文前返回 410；但旧
`internal/fabric/gateway.go` 的 Federation 请求/结果仍直接写入 Hub 明文消息。
该旧双代表路径不满足 v2.1；本轮退役其业务写入口，保留历史表与授权查询。
内部 `fabric.Service.Send/Ask/Reply` 的历史测试能力不等于生产密文路径，不能
据其测试宣称 Hub 从未见过旧正文。

V73 需要可信设备请求、独立确认、固定接收者范围与端点密文。本轮新增内部
授权账本与 Client→Monitor 密文原语；未开放 Client 广播操作，不宣称完整
用户广播已可用。Node 原广播快照只在开始时校验，子消息会重新解析当前密钥；
现在在实际密封前比较固定快照中的源/目标身份、成员版本、绑定和密钥证据，
拒绝中途换绑/换钥。现有 Client v1.2.1 合同保持不变。

## 2026-09-24 恢复与结果读取复审

N4 修复前，`RegisterClientDeviceFromOwnerGrant` 在设备已持久登记但 HTTP 201
丢失时拒绝重试；`client_device_requests_v2` 只保存最终响应密文，没有把分配的
Hub 响应序号与请求绑定。Hub 在序号递增后、响应缓存前崩溃会让 Android 的
单调序号检查永久卡住。现有 v29 标记/预留与独立 `/rpc/recover` 处理该窗口；
旧请求无标记时仍不能安全修复。`intent.status` 原只显示 Control 派发和 Goal
关联；`status.snapshot` 只投影状态。新增 `goal.result` 从 owner 归属 Intent
推导目标 Goal，提供有界最终摘要/证据元数据。此前
`TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 是 Node HTTP 协议替身测试，
真实 Agent/Codex 与 Android 收取结果仍是单独验收。下节为 N1–N3 初始审计，
其中“待修复”描述当时状态。

## 2026-09-24 Client / Hub 联合工程审计

本次整改基线为 `dev` 的 `7c0efc4df6209785df4fc4694792ff5c9163141a`，
开始时工作树干净。Docker Go 1.22 中 `go test -count=1 ./...` 与
`go vet ./...` 均通过。实际 RPC dispatcher 已有 28 项操作、外部 owner
可用 21 项；旧交接仍写 25/18，并遗漏 Group 公钥授权操作。三个独立的
operation 列表、缺源码来源的开发 Hub 镜像以及只有 release 的 CI，使两个
仓库无法稳定核对接口与测试版本。证据分别在 `internal/server/client_rpc_v2.go`、
`scripts/run-client-hub-dev.sh` 和 `.github/workflows/`。

整改使用嵌入的 `internal/clientcontract/catalog.json` 统一运行时角色目录，
同时保留请求内的资源级 Guard；新增轻量 Hub、源码标识、协议包和独立
Docker 互操作入口。完整范围、验收与后续顺序见
[联合开发规范](client-hub-development.md)。本轮没有修改独立 Android 仓库。

另发现两项需单独修复的恢复缺口：Client 收到登记响应后才保存 enrollment，
而 Hub `RegisterClientDeviceFromOwnerGrant` 拒绝重复设备登记，响应丢失后缺少可信恢复；
已持久化 RPC 的 `UNCERTAIN` 也缺少两端一致的 pending 退休协议。它们不因
本轮整理而消失，不能靠重新信任密钥、重置计数或忽略 epoch 解决。

审计日期：2026-09-23。代码基线为 `main` 的 `f4fa7eb8d948ae09834be0b5ec2695205cba536f`，增量在 `dev` 开发。**下表保留初始审计事实，不代表最新可调用接口**：当时 Hub schema 到 v16，Node 本地 crypto DB 到 v3，并增加 Endpoint 自签名公钥候选、持久密文收件及离线签署的 Link Grant；它们尚未接入 Fabric 密文消息路径。后续 Hub v17–v21、Client PQ 入口和旧接口退役见 [status](architecture-v2-status.md) 与 [migration](architecture-v2-migration.md)。目标契约以根目录 [CICADA.md](../CICADA.md) 为准。旧版已运行的路径不自动满足新版验收。

## 两个顶层视图的现状

部署视图是 **Node / Hub / Client**。现有 `cmd/cicada`、`internal/server` 可将 Control、Directory、Relay 和 Web UI 组合在一个 Hub 进程；`serve --fabric-only` 能不构造 Control 业务服务；`machine agent --relay-only` 以 Node 凭据调用 Relay。`internal/server/relay_node_v2.go` 提供 Node 主动建立的 HTTPS/SSE wake hint 流，`cmd/cicada/machine_relay_events.go` 负责重连；这已做定向测试，但尚未完成持续运行 Hub 与隔离 Docker 网络的完整演示。同 Node 消息目前仍走中心 Relay，不能宣称零中心 Relay。

逻辑参与者是 **User / Control / Worker / Monitor**。Control 的 Goal、Machine、Worker、Approval 等旧能力还在；Monitor 角色存在，但现有跨 Group `gateway_v2` 仍要求代表间接转发。v13 已保存不可路由的 CommunicationLink 提案；新版 Monitor 可选、Endpoint 授权直达、跨用户共同 Hub、组内广播尚未实现。Thread、Endpoint、Principal、Group 是独立对象，不是额外的顶层参与者。

## 代码与验收证据

| 范围 | 当前事实 | 关键代码/测试 | v2.1 缺口 |
|---|---|---|---|
| 显式 Join、身份和授权 | `Principal`、`Group`、`Membership`、`SessionBinding` 与稳定 Endpoint 已有；未 Join 不可见，MCP/HTTP/CLI 的 v2 操作走 Session 凭据；旧 READY Endpoint 被 v1 Fabric 入口隔离。审计时旧手工 `/v1/threads/queue` 仍有已 Join 防护，随后该接口和实现已删除。v11 Endpoint-Group 多对多关系接入第二组 Join/切换/逐组 Leave、Directory/Relay scope；同机双容器真实多组 Ask/Reply 已通过。v12 父子 Group 管理只改变拓扑，不继承授权。 | `internal/store/fabric_v2.go`、`endpoint_group_v2.go`、`group_hierarchy_v2.go`、`internal/fabric/service.go`、`cmd/cicada/mcp.go`；`TestOneNativeEndpointUsesTwoGroupsWithoutCrossGroupMailboxLeak`、`TestNestedGroupDoesNotInheritPrincipalOrEndpointAuthorization` 及 `architecture-v2-native-validation.md`。 | `fabric_endpoints.group_id` 与 SessionBinding `group_id` 仍是旧主组投影；嵌套面板编辑、跨组直连及跨用户权限尚未实现。 |
| Directory/Relay/Node | 同组 Directory 拒绝歧义和越权；Relay request/outbox/inbox/attempt/receipt/cursor 持久化；Node SQLite inbox 去重并在注入不确定窗口停重试；Node 出站 SSE 已实现。 | `internal/store/relay_v2.go`、`internal/nodeinbox/inbox.go`、`internal/server/relay_node_v2.go`、`cmd/cicada/machine_fabric.go`；`TestDirectoryIsGroupScopedAndNeverGuesses`、`TestRelayV2ForgedAckRejectedAndFailureRequeues`、`TestRelayNodeOutboundEventStreamWakesAfterDurableAsk`。 | 同 Node 本地路径、单共同 Hub 的 Docker 网络实测与 Hub-blind 端点密文未完成；`fabric_messages.body` 当前仍为明文。 |
| 原生 Codex | 使用真实官方 `codex queue --thread` 和 `exec resume`；G1 同机两个隔离逻辑 Node 的真实模型经 MCP Join/Ask/Reply，A/B 原 Session ID、上下文连续。 | `cmd/cicada/machine_fabric.go`；[原生验收](architecture-v2-native-validation.md) 中的 G1 证据。 | 不能推出双物理机、前台并发输入安全或新版同 Node 直达。 |
| Control 隔离 | `internal/fabric` 不导入 Control 业务；`serve --fabric-only` 的旧 G1/G2 能运行，管理 API 返回 503。 | `TestFabricV2WorksWithoutControlBusinessService`、`TestControlBusinessDisabledPeerRPC`，真实演示日志。 | 新直达/广播路径仍需同样的禁用业务测试与调用计数。 |
| 旧 GroupGateway | Group Card、Contract、代表 owner/epoch、Mailbox、FederationRequest/Result 同库状态机与来源记录已测试；旧 MA→MB→B1 真实原生演示通过。 | `internal/store/gateway_v2.go`、`internal/fabric/gateway.go`；`TestMonitorMediatedCrossGroupCollaboration`、[原生验收](architecture-v2-native-validation.md)。 | 它是**待退役旧路径**，不能计为新版可选 Monitor 或直接跨组/跨用户通信。历史请求、证据与身份必须可迁移/审计。 |
| 新 CommunicationLink 提案与独立签署 | v13 对双方明确活跃的 Endpoint-Group 关系保存同 owner 的版本化合同草案，跨 owner 不接受，提案不参与 Fabric 路由；现有跨组明文 Ask 仍拒绝。v15/v16 增量保存独立用户公钥和精确合同的两侧 ML-DSA Grant，登记只能经本地离线可信流程，不能由管理 bearer、Node/Session 凭据隐式代签；即使双侧记录存在，Link 仍是 `PROPOSED`。 | `internal/store/communication_links_v2.go`、`owner_approval_keys_v2.go`、`communication_link_grants_v2.go`、`internal/e2ee/owner_link_grant.go`、`internal/server/communication_links.go`；`TestCommunicationLinkProposalRejectsForeignOwnerAndNeverBecomesActive`、`TestLinkProposalCannotOpenPlaintextCrossGroupPath`、Grant 定向测试。 | 当前离线 bootstrap 尚无 Android/远程 owner-device 身份与 PQ Client 会话；外部 Card、可信双方 Endpoint pin、端点密文和新路由均缺。 |
| Task/Lease/Artifact | v6–v10 已有 scoped Artifact、Shared Task 原子 claim/结果、ResourceLease 冲突身份、handoff 和副作用 ledger；只读管理视图已接入 UI。 | `internal/store/shared_task_v2.go`、`resource_lease_v2.go`、`shared_task_handoff_v2.go`、`shared_task_side_effect_v2.go`；`TestSharedTaskConcurrentClaimAndStaleCandidate`、`TestResourceLeaseConcurrentAcquireAcrossStoreHandles`、`TestSharedTaskSideEffectIntentSurvivesStoreRestart`、`TestGroupManagementViewIsWiredIntoHomePage`。 | GPU/工作区真实执行器强制 fencing、外部副作用对账、可编辑拓扑面板未完成。 |
| Contact/密码学 | 旧 Contact peer link 的 ML-KEM/ML-DSA/ratchet/replay 状态保留；旧 Control API 会接触明文。Endpoint 密文封装及 Node-local seal/open 组合 API 已有：后者按精确 pin 和调用方可信 route 密封、持久化、解密与原子 replay/inbox，但未接入真实 Fabric transport/native injection。新 Endpoint key attestation 用 ML-DSA-65 自签名，并绑定 Endpoint、Principal、Node、当前 SessionBinding ID/epoch；v14 Hub API 只登记 `CANDIDATE` 公钥并向调用者当前 Group 可解析的 Endpoint 提供 scoped read。候选不等于 owner-approved/trusted pin，不可用于路由或加密。Node 本地 crypto-state API 提供 durable sequence/outbox/replay 和原样入站密文存储，并以独立 schema v3 保留精确作用域、需外部核验指纹的 peer pin；这些尚未接入可信用户批准来源。 | `internal/control` Contact/peer 实现、`internal/e2ee/endpoint.go`、`endpoint_attestation.go`、`internal/fabric/endpoint_keys.go`、`internal/server/endpoint_keys_v2.go`、`internal/nodekeys/crypto_state.go`、`internal/nodekeys/endpoint_messages.go`；[E2EE 说明](e2ee.md)。 | Hub 对普通 peer 正文失明、可信双边 pin、端点密文路由、native outbox/inbox/decrypt/replay 集成和撤权后密钥处理未实现。当前 Join Session credential 的根授权仍来自配置的管理 bearer；若 `CICADA_API_TOKEN` 未设置或 scope 过宽，自签名和 Session credential 都不能建立独立用户的 bootstrap trust。 |
| 迁移与恢复 | Hub `schema_migrations_v2` 到 v16；v14–v16 仅新增 Endpoint 公钥候选、用户批准公钥和 Link Grant 表，不改写旧 Endpoint/Contact/密钥/ratchet/replay 数据。Node-local crypto DB 增量到 v3，新收件将密文与 replay 同事务提交，旧 replay-only 行不冒充可恢复收件。旧 Endpoint 默认 `MIGRATION_PENDING_GROUP`；v11–v13 行为不变。有只读 inventory 与 Hub StateDir `migration backup/verify/restore`，但 Node 私钥和 crypto-state 文件不在其中。 | `internal/store/migrations_v2.go`、`endpoint_keys_v2.go`、`owner_approval_keys_v2.go`、`communication_link_grants_v2.go`、`internal/nodekeys/crypto_state.go`、`cmd/cicada/migration_backup.go`。 | v14–v16 合成旧库中断/重跑与 Node v1/v2→v3 测试通过；真实生产演练、完整 Node 备份、密钥/计数一致恢复及恢复后联网对账未实现。 |

## 实际运行边界

当前 v16 工作树在 Docker Go 1.22 中通过 `go test -count=1 ./...` 与 `go vet ./...`；`internal/e2ee`、`internal/store`、`cmd/cicada` 的 `go test -count=1 -race` 退出码为 0。完整 `-race ./...` 未运行。测试证明相应代码范围，不证明新拓扑部署。真实 G1 与旧 MA→MB G2 均在**同一物理主机、隔离逻辑 Node** 上完成；G1 是模型自主 MCP Join/Ask/Reply，旧 G2 不能代替新版 direct-link G2。没有双物理机、公网、双用户共同 Hub、Group broadcast 或 Hub-blind PQ E2EE 的运行证据。

## 迁移结论

新版必须在保持 Endpoint/native Session、Goal、Contact、消息、Approval、密钥、ratchet/replay 数据的前提下，逐步新增 Endpoint-Group Membership、Group nesting、CommunicationLink 和广播投递。v14–v16 新增公钥候选、用户批准公钥与 Link Grant 表；它们不激活消息路由，且不改写旧数据库记录和密钥。双边可信 Endpoint pin、可路由连线、端点密文和广播迁移尚未执行。旧跨组代表写入/API 要在新路径验收和数据对账后退役，不用全局宽权限 Group、删除表或重建 Session 代替迁移；详见 [migration](architecture-v2-migration.md)。

## 现行接口补充审计（2026-09-23）

上述表格保留初始 v16 基线。当前本地 `dev` 的 Hub schema 已至 v26，Node crypto DB 至 v5；精确实施状态见 [status](architecture-v2-status.md)。Client 公开入口固定为 `/v2/client/capabilities`、`/identity`、`/devices/enroll`、`/rpc`，管家 owner 可用 25 个加密 RPC operation，外部 owner 仅可用其中 18 个；加密 `session.capabilities` 返回当前设备的实际范围。`status_events` 和可路由的 `external_thread_links` 仍明确为 `false`。Client 端代码属于独立仓库，本仓库没有修改它。

`TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 验证加密 Client Intent 使 Hub 持久创建 owner-tagged Goal/Worker，绑定 Node 用自己的 bearer 心跳、领取、传精确 Workspace 快照和回报结果；旧管理 bearer 与 Node bearer 不能互相替代。服务端 HTTP 测试没有启动真实 Node Agent/Codex，CLI 的同路由收发另有定向测试。`internal/server/relay_node_v2.go` 的 Node 授权证据读入口在同一 Store 事务内重验当前 Node/owner 绑定、Link scope 和双侧 key-bound Grant；Node-local verifier 只在独立可信 Owner key 和完整签名核验后建立非路由 pin。该 Bundle 不能自行证明获取时的新鲜性，生产路由仍需在线重验 Guard；跨组端点密文投递尚不存在。

旧 `/v1/communication-links` HTTP 路由和无调用方的 Control peer 转发方法已删除；同 owner Link 管理经 Client 加密 `topology.apply`，旧数据仍保留。Node DB v4/v5 只增量扩展 pin 证据和 Owner key trust，旧 pin 不自动获得跨组权限。当前 `go test -count=1 ./...` 与 `go vet ./...` 在 Docker Go 1.22 通过；`server`、`nodekeys` race 包通过，`store` 全包 race 在默认 10 分钟超时，停在既有备份校验测试，需定向复验。真实 Android 互操作、双物理机、新跨组直达与 Hub-blind E2EE 仍无验收证据。

## 2026-09-24 同 Node 路径再审计

本节记录相对初始审计的新事实，不回写上方的历史基线。`cmd/cicada/mcp_outbox.go` 原同组 `target` 路径会调用 Hub 的 `/v2/fabric/send|ask|reply` 明文入口；`internal/store/relay_v2.go` 的旧消息正文和 Control 可访问的旧 Contact 路径也不能算 Hub-blind。显式 Link 的跨 owner `SEALED_V1` 路径另有 Node 本地密封和 Hub 密文 Relay，不受这次同机改动替代。

本轮增加的同 Node 路由由当前 Codex Session 经 MCP outbox、受保护的 Node Unix socket 进入本机持久密文账本。Hub 的 Node+Session Guard 只返回同 owner、同 Group、同 Node 的当前身份/绑定/候选公钥快照；消息正文、request/reply correlation 和注入队列都由 Node 持有，Hub Relay 消息 API 不参与该路径。Node 在注入前重新向 Guard 查权。Node Join 现在自己核对 Codex 本地 session record，成功的 sealed-capable Join 发布当前绑定的 Endpoint 公钥候选；候选不是跨 owner 授权。`internal/nodeinbox` 仍保留分层原生注入状态，包括无法确认时停在 `INJECTION_UNCERTAIN`。

新路径暂仅支持同 owner、同 Group、同 Node 的单播；同 Group 跨 Node 的 sealed 路由未实现，带新能力的 Session 在这类请求上显式失败，不回退到旧明文 peer 写入。Hub Guard 在线仍是发送和注入时的授权依赖，因此“零 Hub Relay”不等于离线自治。新完整链路的 fake Codex/真实 Codex 证据分别见 [status](architecture-v2-status.md)；fake queue 不证明模型实际消费。
