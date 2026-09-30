# Architecture v2 状态矩阵（v2.3目标）

## 当前剩余项目执行状态（2026-09-30）

当前源基线是 `dev` HEAD `f30892fcd79a27bfe5604575deaecebe52c5ec50` 加 dirty 工作树；M1/M2 的既有 PASS 仍归属各自旧 fingerprint。`5414d6edee44e2be1cad04d10181fd1a23ccd3bf0004fa3fb7bb66776448de83` 在[后端门禁](../.cicada-data/architecture-wide-accepted-20260930T121202Z/gates-summary.json)前后不变：1,307 Go PASS、11 SKIP、25 包 PASS、vet PASS、13 项 race PASS、八项 Python PASS、三套 disposable real-TCP Docker PASS。后续 `e13b3848…` 的[Go 门禁](../.cicada-data/architecture-wide-finalfix-20260930T123606Z/gates-summary.json)为 1,308 PASS、11 SKIP、25 包、vet 与八项 Python PASS，但该源码的真实 native gate FAIL；`434c4eb6…` 的[下一 native 重试](../.cicada-data/architecture-wide-nativefix-20260930T125600Z/gates-summary.json)也 FAIL。M3 cursor/显式未读、M4 精确委托、v40 双 Owner 新记录 Group board 有确定性后端覆盖。v41 原子 nested `group.create` 已实现并通过隔离 checkout 的 Store/Control 全包及定向 race，主仓 `c33f…` 冻结 Go/race/迁移门禁已 PASS。更新的 M5 durable native-outcome 测试也在同一有界门禁 PASS；旧 writer 串行化/epoch 审计不冒充该测试。M3 即时引用/Network Task offer、M5 完整两 Hub 产品互操作及跨 Owner 历史仍是后续工作。最终 [c33f 检查点](v01-group-panel-checkpoint-validation.md)另在同源前后通过 1,336 Go/11 SKIP/0 FAIL、25 包、vet、36 race、八项 Python、三套 Docker，并以独立 Chrome 151 loopback gate 和受控真实 Codex CLI 0.159.2 双逻辑 Node 同 Group ASK/REPLY gate PASS；后者不是 V68 双网络 namespace 或 unattended cold wake。逐项范围见[完成账本](completion-ledger.md)。

正在执行的剩余路线见[当前计划](architecture-v2-plan.md)。上述 Docker 只证明指定的真实 TCP Hub/Go 协议范围；其中 Group Spaces 使用合成 native session，不是模型消费。新版 CLI 0.159.2 首次因 stdio MCP helper 缺 `CODEX_HOME` FAIL；`e13b…` 在最终 route allowlist FAIL（之前 ASK/REPLY 子断言通过），`434c…` 因模型提供截短 synthetic Group ID 在首个 Join FAIL（该轮无 ASK/REPLY），均不是 native PASS。[Chrome 151 真实浏览器门禁](../.cicada-data/hub-web-panel-browser/20260930t131113z-251515-c3ac163f/result.json)在 `5414…` / Hub image `sha256:6a21824109c755cc47b345d0cd63b97c49b0d51306420c160ba4ab7b8aa9b475` 的 loopback fixture **PASS**，覆盖手动 pin、生产 Go WASM、加密 vault、设备加入、topology/status/canvas 与可见 Group；`UNCERTAIN` 写故障注入与公网 HTTPS **NOT_RUN**。最终 `c33f…` 浏览器另在 image `sha256:6940829857d0135fd21349a55a367dc530f4c3cf4c3282aa62c841729af3d123` 上独立 PASS，见[验证记录](v01-group-panel-checkpoint-validation.md)；其 `UNCERTAIN` 注入仍 NOT_RUN。当前 Android v1.5 和 public HTTPS 均 `NOT_RUN`；旧 `f30892f` Client APK4 证据不转移给当前 v1.5。v0.2.x 可选 OpenAI/dot/GPT-Live/ChatGPT plugin 方向仅在[路线文档](v02-openai-integration-roadmap.md)中规划，当前预定 v0.1.x 不增此类功能或依赖。

## 历史 M2 候选（2026-09-30，以下结果保持原归属）

> M2 起点 `dev` `7c4194155d6c0c342671299e447c907f0b1d94d6` 加未提交工作树。Hub schema v37 的同 Owner、单 Hub ACTIVE Group Journal/Discussion Store/Fabric Guard、Node HTTP、原 Thread MCP/Unix bridge、逐读者密封、Owner 单记录历史签名与重封装已接线；[M2 合同](group-spaces-m2-contract.md)记录准确入口与限额。聚焦两 Node `TestGroupSpacesMCPAcrossNodesWithLostCommitResponse` 在隔离 Go Docker 中 **PASS**：当前 MCP→受信 Unix Node→Hub Handler/Store→第二 Node 本地解密，含作者自读、丢 commit 响应后原字节重试且出站 crypto 序号不前进、伪造工具身份和只读写拒绝、Topic resolve/get/reopen CAS，以及撤读再授后的旧记录拒绝、离线 Owner 签单记录历史与重封装读取。`TestGroupSpaceCachePersistsLegalThirtyTwoReaderWireSize` 通过大于 2 MiB 密文 cache 写入/重开；32-reader/16KiB 合成案例的 snapshot 约 1.49 MB、commit JSON 2,116,357 B、16-page JSON 2,530,333 B，HTTP/cache 上限定为 4 MiB。全 Go/vet、聚焦 race、合同及三套独立 disposable real-TCP Docker 后端门禁均 PASS；这是有界 M2 后端验收，不代表模型、设备或公开部署验收。Client v1.4 管理 catalog/wire v1 未变，Android 内容、真实 native Runtime、双物理 Node、公网 HTTPS **NOT_RUN**。

> **M2 后端有界门禁 PASS（同一冻结 dirty 源码）。** `go test ./...` 共 25 包、1292 tests PASS、0 FAIL、11 SKIP；`go vet ./...` EXIT0；六包聚焦 race EXIT0；gofmt、Client v1.4 合同、八项 Python、shell 语法和 diff 检查均 EXIT0。M2、Client 与 Network M1 三套独立 disposable real-TCP Docker 门禁各 EXIT0，均使用相同 source fingerprint `76becd7a479dfd801427fc470c376517227f67b293392d4cd7e314f5fa5b6e7c`，测试前后不变。证据：[Go/vet](../.cicada-data/m2-20260930/accepted/go-gates.json)、[race](../.cicada-data/m2-20260930/accepted/race.json)、[本地检查](../.cicada-data/m2-20260930/accepted/local-checks.json)、[M2 Docker](../.cicada-data/m2-20260930/accepted/group-spaces-m2-docker/result.json)、[Client Docker](../.cicada-data/m2-20260930/accepted/client-docker/result.json)、[Network Docker](../.cicada-data/m2-20260930/accepted/network-m1-docker/result.json)。11 项 SKIP 是另行运行的 opt-in Docker/native，不单独计 PASS；真实 native Runtime、Android、双物理 Node、公网 HTTPS仍 NOT_RUN。

M2 本轮的分层测试、旧基线失败与定向诊断、隔离 Hub 容器镜像及未运行边界统一见 [Group Spaces M2 validation](group-spaces-m2-validation.md)；基线和当前 dirty candidate 不能互相归因。

> **当前 M1 后端矩阵 PASS（2026-09-28）；本轮止于 M1，不启动 M2。** Hub schema v36、Client `client-hub-v1.4`（wire v1、36 项操作）已接入 ACTIVE Owner Network 拓扑/同网建组和 Network Endpoint key manifest/grant/status；Node/Relay/MCP 的 Network-only 密封 SEND/ASK/REPLY 不要求伪 Group。旧 Group/Link 授权与新的 Network direct grant 各自独立；只有当前 Network 双端登记、精确 Node/native binding、公钥自签与各 Owner 同意及逐动作 grant 同时有效才能发送。capability 只报告 Hub 实现，实际授权由加密设备请求或受信 Node credential、Owner 签名和服务端 Guard 决定。冻结源码 `479386745593bf9dee679513cb2038cff08530abcc65fab1482736c4d837e3fe` 前后不变：全 Go 25 包、vet、16 个聚焦 race 用例、合同/八项 Python、默认 Client 与 Network 两套独立 disposable real-TCP Docker 门禁均 **PASS**；[Go 门禁](../.cicada-data/m1-final-20260928/accepted/go-gates.json)、[Client 结果](../.cicada-data/m1-final-20260928/accepted/client-docker/result.json)、[Network 结果](../.cicada-data/m1-final-20260928/accepted/network-docker/result.json)。结果归属 HEAD `733ca86` 加 dirty 工作树，不能只归因于 HEAD。真实 native Runtime、Android、双物理 Node、公网 HTTPS 分项 **NOT_RUN**；下方 PASS 均为各自旧候选的有界证据。

> **历史 2026-09-28 M1 ACTIVE 权限迁移有界检查点 PASS，整体 M1 当时仍未完成。** 在 v35 基础上，该轮将 Network/Group 当前授权推进旧 Relay、sealed Node、目录、Task、Artifact 与选定原生投递读写边界；映射批准推进 Group 授权版本，旧映射前签名密钥 Grant 必须由 Owner 在 Network 加入后重新签发。真实 HTTP 测试验证 Control 为 nil 时 ACTIVE 同组 sealed ASK→claim→授权→REPLY，以及 Network 撤权后 SEND/ASK 重试、新 SEND/ASK 和待决 REPLY 入队被拒；Network-only MCP 状态不能调用 Group 工具。当时全 Go `./...`、vet、聚焦 race、合同 check/export/verify、八项 Python、默认 Client 和独立 ACTIVE Network disposable real-TCP Docker 门禁均 **PASS**；[Go 门禁](../.cicada-data/checkpoint-next-20260928/go-gates.json)、[Client 结果](../.cicada-data/checkpoint-next-20260928/client-docker/result.json)、[Network 结果](../.cicada-data/checkpoint-next-20260928/network-docker/result.json)与[清理记录](../.cicada-data/checkpoint-next-20260928/cleanup.json)分别记录当时证据。源码为 HEAD `975ce8e` 加当时 dirty 工作树，source fingerprint `1738095ea36e47655808857ce1934a72241bab1d8bb860d62f24299964c38d00`，不可只归因于 HEAD；下方 `b0081a0` PASS 属于更早的有界基础检查点。
> 该历史检查点仍为 Client `client-hub-v1.3` 的 33 项操作、wire v1 与 Hub schema v35；ACTIVE `group.create` 当时缺 Network selector。当前 v1.4/v36 已补该能力，且有独立后端门禁，不能借用旧结果。该历史时点的 M1 仍为 **NOT_COMPLETE**；真实 native Runtime、Android、双物理机和公网 HTTPS 当时 **NOT_RUN**。

> **2026-09-27 bounded checkpoint PASS:** clean candidate `25013b5` passed full Go/vet, focused race, v1.3 contract/export checks and exact-image disposable TCP gates. The controlled three-Thread Android/native run passed one same-Thread read-only preview, one separate dispatch and both original recipient Thread receive/context assertions. Client's 10 selectors and final strict status passed; Core's scoped Hub ciphertext scan and Intake's independent read-only Hub audit passed; owned fixture/emulator cleanup exited `0`, with no owned containers or fixture directory remaining. See the [candidate record](client-hub-v13-25013b5-validation.md), [approval evidence note](monitor-broadcast-approval-review.md), [runbook](client-monitor-native-fixture.md), and [Client validation](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md).
> Scope limits: two logical Nodes shared one container. Full product-facing React Native consent UX, physical dual-Node/Android operation, public HTTPS and unattended cold wake remain **NOT_RUN/UNSUPPORTED**; one accepted review flow is not general prompt-injection protection. The `81d8f1f` denials remain historical. Group Journal/Discussion remain proposed targets under Architecture v2.3; the Group collaboration design is [proposed only](group-collaboration-spaces-design.md).
> **Earlier M1 foundation checkpoint:** bounded Network foundation **PASS** on clean source `b0081a0`, with the test-only stale schema-ledger expectation fix at `f9d3c7e`. Separate disposable real-TCP Network and default Client Docker gates, full vet, focused Network race, frozen contract and seven Python checks passed. The initial `go test ./...` exited `1` solely because an old migration assertion expected schema v34; every other package passed, and the full Store suite passed after the assertion-only fix. Exact identities and results are in the [M1 validation record](network-m1-validation.md).
> **At that earlier foundation checkpoint, M1 was NOT_COMPLETE.** Operation enqueue after revocation, all custom Node/legacy routes and historical reads, and a complete migration-ledger comparison remained outside that bounded proof. A Network-only Endpoint with no Group could not DM; a sealed Link could connect endpoints in different Groups when each had its own authorized Group in the same Network and bilateral Owner grants. Frozen Client v1.3 `group.create` lacked a Network selector and was rejected on an ACTIVE Hub; the passing default PREPARING Client gate did not prove ACTIVE topology compatibility. M1 native Runtime, Android, physical dual-Node and public HTTPS were **NOT_RUN**. The later v35 ACTIVE permission checkpoint closed selected entry-point gaps but still did not complete M1; neither earlier result proves the current v1.4/v36 candidate. See the [M1 contract](network-m1-contract.md) and [validation matrix](network-m1-validation.md).
> The dated sections below are historical snapshots and do not override the current candidate status or the bounded `25013b5` result.

## 2026-09-27 截至冻结前的候选状态快照：Monitor 同意候选、intake 限额与公平分页

Hub v34 在 Monitor 账本中增加 consent 元数据，并为待确认预览与 Node 通知
增加有界查询。新 intake 只统计尚未过期且状态为 `PREPARED`、`APPROVED` 或
`DISPATCH_AUTHORIZED` 的行：每 Owner/Device 最多 16 条、每 Owner 最多 64 条。
预览有效期仍为五分钟；设备撤销不会提前释放仍有效的行。超限返回同一个通用
backpressure 错误。精确 Prepare 重试先于 admission 检查，因此不会额外占槽。

通知列表每次最多检查 16 个 Owner 范围内的活动候选，按 `(expires_at, preview_id)`
用索引扫描，并用每 Node 持久游标轮转。SQL 候选仍需在 Go 中排除其他 Node 和终态
通知回执，并对候选重新执行当前完整 Guard；因此一页可能返回少于 16 条或为空，
空响应不证明没有后续待办。Node 必须保留周期性 reconciliation，SSE wake hint
合并或丢失时由后续轮询推进。游标在检查候选后事务性前进，包含拒绝/终态候选；
回卷包含当前游标位置，单条未确认记录在响应丢失后仍会再次出现。游标仅是调度
提示，不是 ACK、授权或跳过检查的依据。

Client `client-hub-v1.3` 现为候选目录：33 项操作、catalog SHA-256
`808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377`。新增
`monitor.broadcast_prepare/confirm/status/recover` 四项操作；用户授权仍由当前
加密设备会话与服务端 Guard 决定，操作目录只说明可用性。成员上的显式
`message.broadcast` 开关独立于 Monitor 角色。候选检查
`python3 scripts/client-contract.py check` 通过，七项
`scripts.test_client_contract` 与 `scripts.test_client_recovery_fault_proxy` 测试
通过，最新七项合同/恢复 Python 测试用时 1.692 秒；`TestClientMonitorBroadcastEncryptedHTTPLifecycle`
与 `TestRelayNodeMonitorBroadcast` 的定向 TCP HTTP 测试也通过。交叉审查发现的
Confirm 响应 projection/OpenAPI 不匹配和 inactive Group 拒绝缺口已修正。整仓
`go test -count=1 -timeout 15m ./... && go vet ./...` 在这两项 review 修正之前通过；
修正后，受影响的 Control/Server 全包测试、vet 及聚焦 race 复验均通过，Store 的
Monitor 并发/恢复聚焦 race 也通过。截至冻结前，最终干净 artifact 元数据与 disposable Docker
门禁仍待根任务确认。不要据此宣称
新 Android 集成、真实原生 Monitor 或公网 HTTPS 通过；
三者均为 **NOT_RUN**。旧 v1.2.1 Android 结果继续只归属于历史固定镜像。

本轮 limits 与迁移定向测试在 Go 1.27.1 Bookworm 中通过，包括精确重试和过期释放、
撤销设备仍占用 Owner 配额、旧记录跨页公平性/重启、单条游标记录重复可读，以及
v33→v34 数据保全。Store 的五项 Monitor 并发/恢复定向 race 测试通过。根任务发现
并已修正一个旧迁移 fixture 对最高版本 v33 的硬编码。上述两个 review 修正随后通过
受影响的 Control/Server 全包测试、vet 及聚焦 race 复验；截至冻结前仅等待干净 artifact
和最终 Docker 门禁。

## 2026-09-26 历史状态快照：Node Monitor 通知、执行与结果证据

以下为 2026-09-26 的记录；其中 `client-hub-v1.2.1` 与“未公开 Monitor RPC”
描述的是当日 v31–v33 快照，不是当前 v34 / v1.3 候选状态。

Hub v31–v33 与 Node/MCP 内部接线已完成：v32 保存原始签名登记 Grant 和通知回执，
v33 保存有界逐收件者结果。原 Monitor Session 的 `cicada_monitor_broadcast` 只接受
通知中的批准 ID；Node 验证本地 Owner 信任、Client 密文和固定快照，并在每名
收件者密封前重验 Endpoint、成员、Binding epoch 与密钥。

结果按 `FAILED → UNKNOWN → ACCEPTED` 单调前进。本地 `NODE_REPORTED` 与 Hub 验证的
远端 `RELAY_PERSISTED` 都只证明传输持久接受，不证明模型消费。Client 撤销或
批准过期不抹去事实报告，但仍要求原 Node 与有效的原 Monitor SessionBinding。
子消息已持久而 Hub 报告丢失时结果可保持 `PENDING`；只能在五分钟期限和原绑定
仍有效时用相同稳定 ID 显式重试，过期或换绑后不自动重发。

公共合同仍为 `client-hub-v1.2.1`、29 项操作、catalog SHA-256
`25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`。未公开
preview/confirm/status RPC 或 Monitor capability。Endpoint 原始 attestation 与
Owner proof 预览 DTO 和丢预览响应后的业务恢复状态尚未实现；新 Client 合同、
公开向量及 Monitor RPC 门禁因此未开放。Android/native Monitor 流程为 **NOT_RUN**。

独立 Client 双 Owner 合成 Endpoint 授权报告 PASS：实现
`680fac2bf12c431ac02804e5db168669cf12941f`、报告
`a4007a51b53a36b15ecc02cbf50bdac4f744ec56`，固定 Hub `967dbd8` / v1.2.1；
不含 Codex/native Thread 或 v33 广播，见
`../CICADA_CLIENT/docs/client-two-owner-v1.2.1-967dbd-validation.md`。

无新通知且 inbox 不存在时，不新建 Node inbox；已有常规 inbox 仍可为恢复持久工作
而打开。列表上限 16、Store 候选页 64、收件人上限 32、每批 8。期限索引和分页
不消除大量有效期内但被逐条 Guard 判为陈旧的候选所需总扫描 CPU。测试
`TestMachineMonitorNotificationEmptyListDoesNotCreateInbox` 覆盖的是不创建新库。

Docker Go 1.27.1 Bookworm `go test -count=1 -timeout 15m ./... && go vet ./...`、
合同检查与 7 项 Python 合同/恢复代理测试均退出 0；catalog 未变。聚焦 race 命令
见下文。源码含
`617be77`（v33）、`01a22df`（Node/MCP）等切片，不能把 dirty/组合验证只归因于
HEAD。干净源码 `f1b99c4` / fingerprint
`56b00612f335bc5cb7210f1434796208bd9b876ff842de349820f9ccff744055` 的隔离
Hub 门禁已 PASS：Hub 镜像 `sha256:acd2f956e86d499249bb9881df8edb601d6df6fb3359947f44d717ea0ddc1997`，
smoke 与 recovery 两项 TCP 测试通过，记录在
`.cicada-data/client-interop/monitor-20260926T233342Z/result.json`。Android、native
和公网 HTTPS 不在此门禁范围。空闲 Hub 的镜像另为
`sha256:351830afad94de2abec7a85d4fa90e4679d24e160a327a3e2394173184817e98`，来源同为
干净 `f1b99c4` / fingerprint
`56b00612f335bc5cb7210f1434796208bd9b876ff842de349820f9ccff744055`；测量脚本版本
为 `bd2f46d`。最终三次 RSS 为 25,907,200、25,972,736、25,972,736 字节
（约 24.71–24.77 MiB），cgroup 内存为 20,283,392、21,495,808、22,708,224 字节，
均低于 128 MiB 上限；容器限制为 0.5 CPU。PID 1 的 100 Hz CPU tick 为
30→30→31→31，即三段增量 0、10、0 ms；合计 7.660 秒短采样约为单核 0.13%，
10 ms 分辨率不足以代表长期闲置基线，且 cgroup CPU 仍含探针开销。最终记录：
`.cicada-data/footprint/20260926T233342Z/idle-hub-20260926T234235Z-de8694a7.json`。
较早独立测量保留于
`.cicada-data/footprint/20260926T233342Z/idle-hub-20260926T233446Z-1df3d407.json`；
该轮 RSS 为 26,955,776 字节，CPU 只读 cgroup 计数，故不与 PID 1 最终样本合并。
这些数字只描述一次性空闲 Hub，不涵盖 Node、模型、Android 或负载运行。

定向结果证据包括 `TestUserMonitorBroadcastV2OutcomeReportsAreExactAndMonotone`、
`TestUserMonitorBroadcastV2OutcomeRejectsMismatchesAtomically`、
`TestUserMonitorBroadcastV2OutcomeMigrationBackfillsV32Dispatch`；跨组件
`TestMonitorBroadcastApprovedClientPayloadPersistsLocalAndRemoteChildren` 与
`TestMonitorBroadcastLostOutcomeReceiptRetainsStableChildren` 通过 TCP Hub 测试服务、
Node bridge、Store 和 fake queue 验收，Control 未构造。local/remote 结果分别为
`NODE_REPORTED`/`RELAY_PERSISTED`，不表示模型消费。Android 真机、真实 native Monitor、
双物理 Node 和本轮公共 HTTPS 为 **NOT_RUN**。

`TestUserMonitorBroadcastV2OutcomeReportsAreIdempotentAcrossStoreHandles` 另以
`-count=10` 通过。额外的聚焦 race 验证命令为：
`go test -race -count=1 -timeout 5m ./internal/store ./cmd/cicada -run 'TestUserMonitorBroadcastV2OutcomeReportsAreIdempotentAcrossStoreHandles|TestMonitorBroadcastLostOutcomeReceipt|TestMachineMonitorNotificationRechecksClientGuard|TestMachineMonitorExpired'`，退出 0；其中 expiry 测试是
`TestMachineMonitorExpiredNoticeReceiptRemainsCorrelatedWithoutAuthorization`。

## 2026-09-26 Monitor 授权基础与广播投递校验（v31 历史快照）

本节只记录 v31 基础账本刚落地时的范围；后续 Node/MCP 接线、v32/v33 和当前
缺口以上一节为准。下文关于“Node 管理通知、Monitor MCP 未接通”的描述是当时
状态，不代表现在的实现。

本轮从干净 `dev` / `45206a2` 开始，分四个可独立审阅的提交：

| 提交 | 代码与实际边界 |
|---|---|
| `3196452` | Node 本地/远端广播子投递在密封与持久接受前，比较原快照和新授权的 Endpoint、成员、绑定 epoch、密钥与证明；拒绝静默换目标或换钥 |
| `29322f4` | Client→Monitor 独立 PQ 密封格式，绑定设备、epoch、批准 ID、Group、Monitor、正文/收件范围摘要与期限；含完整公开合成验签向量，无私钥 |
| `765d67b` | Hub schema v31 的设备绑定预览、密文确认、单操作派发授权账本；来源取自已经认证的 Client 请求记录，当前角色/设备/Node/绑定/成员/密钥与期限重新验证 |
| `d5aa124` | 退役旧 Federation 三个正文写方法及 HTTP/MCP 入口；HTTP 在读取正文前返回 410，历史查询和数据保留 |

各实现的定向测试已通过：`TestGroupBroadcastLocalChildRejectsStaleSnapshotBeforePersistence`、
`TestGroupBroadcastRemoteFenceChecksBothEndpoints`、
`TestMCPBroadcastLocalAndRemoteSealedFullChain`、`internal/e2ee` 的 Monitor 向量/
篡改测试、`TestUserMonitorBroadcastV2*` 与迁移测试，以及
`./internal/fabric ./internal/server ./cmd/cicada` 的退役入口回归。环境均为
Docker Go 1.27.1；协议、Store 和 fake Runtime 测试不证明真实模型消费。
新 Store 测试包含两个 Store 实例并发确认/授权、重启、v30→v31 数据保全、
撤销与过期重试、密文序号冲突和溢出拒绝。

在 v31 基础落地时，**V73 为 PARTIAL**：`DISPATCH_AUTHORIZED` 只是为同一个操作
预留执行权限，不是投递完成或模型消费；当时 Node 管理通知与 Monitor MCP 尚未
接通。后续 v32/v33 与当前 Node/MCP 范围见本文顶部；Client 新操作和
Android/真实 native Monitor 全链仍待验收。
Client 合同仍为 `client-hub-v1.2.1`；内部向量不在其既有协议包中，不能让
Client 据此调用不存在的操作。既有固定 `967dbd8` 镜像验收继续独立保留。

已通过原生任务工具启动用户指定的 Client Thread
`01a0cc3a-91d2-74f2-9f41-547c9b38fb0d`，执行
[双 Owner 独立验收任务](client-two-owner-acceptance-task.md)。该任务只修改
Client 仓库、使用独立一次性资源，不重跑付费 Codex 或改动常驻 Hub；收到
最终回报前不得将双 Owner Android 路径标为通过。

冻结代码回归中，历史 invite 迁移测试首次失败：预期账本停在 v30，与实际
新增的 v31 不符。`3a19968` 更新该断言，保留旧行保全/失败回滚检查后，
同一 Go 1.27.1 Bookworm 环境完整复跑 `go test -count=1 -timeout 15m ./... &&
go vet ./...` 退出 0。`go test -race -count=1 -timeout 5m ./internal/store -run
'TestUserMonitorBroadcastV2ConcurrentStore'` 退出 0。合同检查和七项 Python
合同/恢复代理测试退出 0；catalog 与 29 个公开操作均未改变。

`scripts/test-client-hub-interop.sh` 在修正该测试断言前的干净提交
`3d7f4cab283ad6ec3d8290012a31c420849dba52` 构建并运行，退出 0；后续差异只有
上述测试断言与工程文档，没有归因成新提交的镜像。Hub 本地镜像 ID 为
`sha256:8adfd753e15e148d450016f61a6b6dda31edc219a62c944d643b5fc738ab37d2`，
`dirty=false`，source fingerprint 为
`d148427fbb6d3a7b67a53590d8fd8d64f3db9410dceb9952b6e2b2089b1e21a9`。
`TestClientDockerHubSmoke` 和 `TestClientDockerHubRecoveryFixture` 均通过；
证据在 `.cicada-data/client-interop/20260926T021133Z-3494794/result.json` 与
同目录 `test.log`。这只证明实际 TCP Hub/Go 协议客户端，不含 Android、
真实 Codex、公网 HTTPS 或完整 Monitor 广播。一次性容器与镜像标签已清理。

## 2026-09-25 本轮冻结源码回归与故障边界

`dev` 的干净提交 `d88e09045846ca52c4cbbcfdd923f99311c21ec0` 上，
Go 1.27.1 Bookworm 容器执行 `go test -count=1 -timeout 15m ./... && go vet ./...`
退出 0；`python3 scripts/client-contract.py check` 与 7 项 Python 合同/恢复代理
测试也退出 0，合同仍为 `client-hub-v1.2.1`，catalog SHA-256 仍为
`25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`。
并发 Store 打开曾在 WAL 设置处收到 `SQLITE_BUSY`；初始化现在仅对这一类锁冲突
有界重试，原并发迁移测试 `-count=20` 与整仓复测均退出 0。没有 schema、密钥
或 wire 合同迁移。

同一干净提交构建的一次性 Hub 镜像
`sha256:d8d46d1474bc40dec50d6af4a1792f49b6c772222e6fc445ea3f2cb670d6aa98`
以 `dirty=false`、source fingerprint
`f8fae0d82b1d5d437f4da36fde336c95c0755e247cbb0cc90d7d8aef11911966`
通过 `scripts/test-client-hub-interop.sh`，两项真实 TCP Hub/Go 协议驱动测试均退出 0。
这项门禁不包含 Android、真实 Codex 或公网 HTTPS；独立 Client 仓库的固定镜像
Android 结果须单独归因。其一次性结果位于
`.cicada-data/client-interop/20260925T184254Z-3153232/result.json`。

`TestMachineSealedAskReconnectClaimsDurableOfflineMessage` 把 sealed Link ASK、
真实 TLS/TCP SSE 断流/新连接恢复与 Node 生产 claim/decrypt 接在同一测试：B 离线时
Hub 持久保留 OPEN 请求，重连收到 `ready` 后才入 Node inbox，重复 wake 只调用一次
fake Codex queue。普通与定向 `-race` 测试均退出 0，Hub 不见合成正文，Control
业务没有构造；回执停在 `CODEX_QUEUE_ACCEPTED`/`CONSUMPTION_UNCONFIRMED`，
不证明模型消费。Docker 双私有网桥的独立拓扑门禁和真实物理双机仍须分开报告。
`scripts/test-node-hub-topology.sh` 随后在同一干净提交上退出 0：两条私有
Docker bridge 的 Node 探针均可主动连同一个 Hub，Node 互不可直连且 Hub
不可拨入 Node；隔离 sealed fake Ask/Reply 和真实 TLS/SSE 重连子测试也通过。
该门禁使用不同的本地 Hub 镜像
`sha256:35b17d72d40d384055fd40c4238f6b5ab7d2aa3ce581fd47779df39c09446fe2`，
仍不等于同一次真实 Agent 双物理机 E2E。临时容器、网络与标签已清理。

同 Group 三真实 Thread 的 opt-in 广播测试已加入并执行三轮，但完整原生闭环
仍 **未通过**：前两轮分别停在测试夹具 outbox 路径与结构化 receive 解析，
第三轮干净 `c4eb006` 二进制在首个 Join 遇到 Codex 自动审批超时，未进入广播。
确定性的逐人 sealed 投递测试保持通过；没有把这些部分阶段拼接成两名真实
收件者都消费的结论。逐轮证据见[原生验收记录](architecture-v2-native-validation.md)。

Client 固定镜像联调指出原一次性 Group-key 夹具的 Node Join Unix socket 路径
过长。`client-group-key-fixture.sh` 现使用短 `/tmp/cgk.*` 真目录和短合成 Node ID；
脚本启动前检查计算出的 socket 路径长度。固定镜像 `start`/`stop` smoke 均退出
0，Node bootstrap 保持 `AWAITING_OWNER_CONFIRMATION`，本次路径长 65 字节，
临时 Hub、Owner 私钥与 Node 状态在 `stop` 后删除。这只是夹具可用性修复，
不代替 Android 正向 Group Grant 验收。

## 2026-09-25 Client 固定镜像验收回传

已读取 Client 仓库的 `docs/cicada-core-handoff.md`、
`docs/client-hub-v1.2.1-967dbd-validation.md` 与
`docs/client-group-key-v1.2.1-disposable-validation.md`，仅将它们作为独立仓库的
验收证据，不归因于当前 `dev` 工作树。Client 固定目标是干净源码
`967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a`、合同
`client-hub-v1.2.1`、catalog SHA-256
`25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`、
本地镜像 ID
`sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7`。
其 Android 模拟器加密会话、登记 201/RPC 200 响应丢失恢复、
`STILL_PROCESSING`/`OUTCOME_UNCERTAIN`/`RECOVERY_UNAVAILABLE` 三种恢复结果，
以及真实 Node→Codex 审批→`goal.result` 闭环均记录为 **PASS**。
修正后的 Kotlin Endpoint 证明/RFC3339Nano 向量测试亦 **PASS**。
早期管理闭环报告中的正向 `group.key_manifest/grant/status` 曾为 **NOT_RUN**；
Client 随后在提交 `b676668`（实现）与 `948a2fa`（验收记录）的独立模拟器
运行中，以同一固定 Hub 镜像、真实 Node 和原生 Codex leased Endpoint 完成
加密 Manifest、完整 Endpoint ML-DSA 验证、外部 Owner 签名、手机显式确认、
Grant 及 `group.key_status=CURRENT`，Android test 退出 0。
同一最终 APK 的租约到期 `STALE`、证明到期 `PROOF_EXPIRED` 与 Android 本地
篡改签名拒绝也通过；错误 Owner key 选择与不存在 Group/Endpoint 的拒绝有证据，
但**没有**第二个真实 Owner 的越权测试。最终 APK SHA-256 为
`cfe345272f2399cbed7cd76f47e25e3e6fc09ed94daadb1d6e1a6ba9106caff1`；
物理 Android 和公网 HTTPS 仍 **NOT_RUN**。该 Group 验收与较早
Goal/审批/结果闭环是两条不同运行，不相互替代。原一次性夹具见
[Client Group-key 临时环境](client-group-key-disposable-fixture.md)；其准备本身
仍不能算正向验收。
新增 `TestClientGroupEndpointKeyGrantEncryptedHTTPLifecycle` 使用真实临时 TCP
Hub、加密 Client RPC 和合成 Store Node/SessionBinding/Endpoint 验证
`group.key_manifest → group.key_grant → group.key_status`，覆盖有效 Grant 的
`CURRENT`、篡改与异 owner 拒绝、到期 `PROOF_EXPIRED`、撤销成员后的 `STALE`。
Go 1.27.1 Bookworm 的定向 `./internal/server` 测试退出 0。该测试没有真实
Node/Codex 或 Android，不替代固定镜像的正向手机联调。

Node 恢复审计确认的标记丢失窗口已收紧：`Restore` 在原子发布 Node 子树前，
在子树外的 `nodes/.recovery-pending/` 写入并同步私有隔离登记；Agent 在共享
维护锁内检查外置登记或原有 `recovery-pending.json` 任一存在即拒绝启动。
新测试验证删除子树内标记后仍拒绝联网、发布前失败清理本次登记、发布后
同步失败仍保留隔离。Go 1.27.1 Bookworm 的 Node backup/Agent 聚焦测试退出
0，无数据库 schema 变更。崩溃可能留下阻止启动的孤儿登记，这是安全侧
fail-closed；**尚无**经授权的 Hub 绑定、MCP outbox、原生 Session 和
crypto/replay 水位对账及安全解除隔离协议，完整设备恢复仍 **OPEN**。

## 2026-09-25 本切片增量与原生边界

Relay receipt 已按当前 attempt/inbox/binding epoch 加入状态更新 fencing：迟到的
旧 attempt 不能覆盖新 owner/claim 的 inbox 或游标，`ACK` 后的业务
`RESULT_ACCEPTED` 不使传输状态倒退。新增 `CODEX_QUEUE_ACCEPTED` 与
`NATIVE_THREAD_RESUMED` 两层审计回执，不把它们自动提升为模型消费确认；
没有 schema migration。Node 普通、Link sealed、同组跨 Node sealed 与本地 Group
队列在 `codex queue` 返回成功后记录 `CODEX_QUEUE_ACCEPTED`，不再直接上报
`RUNTIME_INJECTED`；`CONSUMPTION_UNCONFIRMED` 保留现有可读取状态，但并不证明
原生 Thread 已醒或模型已消费。queue 成功后、本地回执前的崩溃仅凭持久 journal
中的同一 attempt 成功证据对账；未确认的原生注入仍停在
`INJECTION_UNCERTAIN`。Codex 0.157.0 的隔离协议核验发现，MCP 子进程没有可用的
当前 Thread ID，`thread/resume` 也没有前台 owner/epoch 条件；因此生产无人值守
cold Thread resume 当前标为 **UNSUPPORTED**，不能把排队成功冒充唤醒。
证据与适用范围见[原生验收记录](architecture-v2-native-validation.md)。

明文 peer 路径复核：当前 MCP 的 `cicada_send`/`cicada_ask` 要求来源与目标
当前均具备 `local_peer_delivery=sealed_v1`，失去能力或 Node 桥不可用时拒绝；
同组跨 Node 与显式 Link 的公开发送入口只提交密文。旧
`POST /v2/fabric/send|ask|reply` 在读取正文前返回 410，`/v1/fabric/*`
已移除。仍有仅供内部/测试直接调用的 `Service.Send`/`Ask`，在双方缺少
能力键时可写旧明文表；生产 Go 调用点为零，受控历史读取仍保留。
它是待清理的隐式兼容债，不是当前 MCP 的静默降级，也不证明数据库中
历史明文已消失。现有降级、旧路由和 Store guard 定向回归通过。

Node 专用原生唤醒授权读接口要求当前凭据、attempt、inbox、Endpoint、
SessionBinding epoch/lease 与 Group join 一致，并在撤权、重加入及过期时拒绝；
它明确只支持 PLAINTEXT，不替代 sealed Link/grant 复核，也不返回正文、密钥或
任意 capabilities JSON。Codex app-server daemon/proxy 的版本与现有 socket
能力门禁已加入，真实 0.157.0 临时 daemon 的只读协议探针核对了字段；
该 adapter 还没有接入生产自动恢复路径。另修正 sealed claim 的单组旧投影限制：
同一 Endpoint 的次要 Group 当前 Join/成员授权可领取相应 sealed 消息，未 Join、
撤权和旧 epoch 仍拒绝；无 schema migration。

冻结后的整仓源码在 Go 1.27.1 Bookworm 容器中执行
`go test -count=1 -timeout 15m ./... && go vet ./...`，两者退出 0。
`python3 scripts/client-contract.py check` 仍返回 `client-hub-v1.2.1`、29 个
operation 和原 catalog 摘要；7 项 Python 合同/恢复代理测试通过。并行的另一次
Store 全包曾在迁移并发用例遇到 `SQLITE_BUSY`，随后冻结源码的整仓 Store 包
通过；该用例在没有并行整包运行时以 `-count=3` 连续通过。并行失败不计为
已根治的数据库问题。
聚焦 `go test -race -count=1 ./internal/store ./internal/nodeinbox -run
'Test(RelayNativeWakeAuthorization|RelaySealedV1Claim|CodexQueueAccepted)'`
也退出 0；未执行整仓 `-race ./...`。

`scripts/test-node-hub-topology.sh` 退出 0：一次性 Hub 与两个独立 Docker
bridge 的 Node 探针完成同一 Hub 出站 HTTP、Node 间双向 TCP 拒绝、Hub→Node
TCP 拒绝；隔离 `--network none` 的 sealed Ask/Reply 是进程内测试 Hub 与 fake
Codex queue。构建来源为 `ef47552c236d9ef3929825309aabc0c0e9669f9d`、
`dirty=true`、source fingerprint
`9a46466da6f91e100d103cdb726624d5fdf0eadc57608da0bb38a8cc1753a0f5`；
Hub 镜像 ID `sha256:243c0544c3cc8fb79901b515bd6c8ab120e877c3548f9aa8f039b024b3803ed9`，
test 镜像 ID `sha256:affde96dacf535d453671d3bbff54c15dc02fbcf3bccb20a6ee02ae9cc0f6f8a`。
临时容器、网络和标签已清理。此门禁不证明真实 Node 认证、真实 Codex、
双物理机或通用 egress ACL。

新增 Node SSE 断流切片：`TestMachineRelayReconnectClaimsDurableOfflineMessage`
通过真实 `runMachineRelayEventStream` 与 `processMachineFabricDeliveriesV2`，
连接 `server.NewFabricHandler` 和 SQLite Store。测试用 loopback TLS/TCP SSE，
先确认 ready 后流仍保持，再关闭真实连接并等待 Hub handler 的 request context
结束；Node 发起新的 TCP/HTTP 请求时，测试 Hub 暂停发送 ready。此时写入一条
synthetic Ask，核对 Hub Store 中仍有 OPEN request 和对应正文、fake Codex queue
尚未调用，然后放行重连，观察 ready 对账唤醒 Node 并执行一次 claim/fake queue
命令。相同幂等键重试再次发出 wake 后，fake queue 命令计数仍为一。

验证命令（容器只读挂载本机 Go 模块缓存；服务端与 Node 客户端在一个隔离
`--network none` 测试容器内通过真实 loopback TLS/TCP 通信）：

```sh
docker run --rm --network none -v "$PWD:/src" \
  -v /home/zyf/go/pkg/mod:/go/pkg/mod:ro -w /src/cicada-go \
  -e GOPROXY=off -e GOCACHE=/tmp/cicada-go-cache \
  golang:1.27.1-bookworm go test ./cmd/cicada \
  -run '^TestMachineRelayReconnectClaimsDurableOfflineMessage$' -count=1 -v
```

使用已缓存依赖的这次运行退出 0；以下定向 race 运行也退出 0：

```sh
docker run --rm --network none -v "$PWD:/src" \
  -v /home/zyf/go/pkg/mod:/go/pkg/mod:ro -w /src/cicada-go \
  -e GOPROXY=off -e GOCACHE=/tmp/cicada-go-race-cache \
  golang:1.27.1-bookworm go test -race ./cmd/cicada \
  -run '^TestMachineRelayReconnectClaimsDurableOfflineMessage$' -count=1 -v
```

首轮无模块缓存的 Docker 运行因 `GOPROXY=off` 退出 1；尝试允许拉取时，临时容器访问
`proxy.golang.org` 超时并退出 1。另一次代码断言错误地从 request 行读取正文，
退出 1；改为查对应 Relay message 后通过。整条拓扑脚本首次构建被
`build-hub-image.sh` 的源码 fingerprint 保护拒绝（build 期间共享 cicada-go
有改动，退出 1）；该次没有运行拓扑阶段或 Go 测试，属于构建快照变化，不是
产品验收失败。源码冻结后再次执行 `scripts/test-node-hub-topology.sh`，退出 0：
Hub 只发布在两条 Node 私有 Docker bridge gateway，Node A/B 都出站访问同一
Hub healthz、彼此不能 TCP 直连，Hub 容器也不能连到 Node probe listener；原有
sealed fake Ask/Reply 与新增 TLS/SSE reconnect Go 切片均通过。该 dirty 构建的
来源记录为 HEAD `8ca63f022b6e951ad7d7b561c58c1aa271631c3e`、`dirty=true`、
source fingerprint `287d4f98257a1a1095664fdccbc5e1e62a74b6fb1164899458159b7d0452bca0`；
Hub 镜像 `sha256:d32a76e70237d51d435be82e15a3b7e7c9f7034c3cfe2b5ec724a395d331206e`，
test 镜像 `sha256:ca91c9ed8f537c6d2c5bd8a8f767e26767d9e1989f525ade981e3f54ab7838ce`。
此处结果分别依赖 HEAD、dirty 标记、源码 fingerprint 和镜像 digest，不能仅归到
HEAD revision。脚本清理了临时 Hub/Node 容器、两个网络和两张测试镜像。

此切片走现有 legacy PLAINTEXT Ask/claim 路径，不验证 sealed/Hub-blind E2EE。
synthetic Node 授权及 fake Codex queue 不代表生产 enrollment、真实 Native
Runtime 或模型消费；Node 到 Hub 的独立 Docker TCP 探针也不代表 Agent 进程。
跨物理机、公网 HTTPS、真实 Codex、Android 和 native 消费结果均为 NOT_RUN。

现有 `scripts/test-client-hub-interop.sh` 在独立临时 StateDir/真实 TCP Hub
上也退出 0；`TestClientDockerHubSmoke` 与
`TestClientDockerHubRecoveryFixture` 均退出 0。脱敏结果在
`/tmp/cicada-client-interop-current.8pT8ai3u/result.json`。该次构建以
`5302207519481eb87fd6f723abc40f789698426c`、`dirty=true` 和同一 source
fingerprint 标识，Hub 镜像 ID 为
`sha256:df4886044802dc326682adcbfa5dc7652d193fd7a09c90846bb9652cb155dca1`；
Android、原生 Runtime 与公网 HTTPS 在此门禁中仍为 NOT_RUN。Client 仓库另在
干净的 `967dbd8` 固定 Hub 镜像上报告了 Android 模拟器管理闭环 PASS，
其结果不能归属于本次 dirty dev 构建；正向 Group key grant 仍待临时 leased
Endpoint 夹具与 Client 独立验收。

前两次真实 Codex 0.157.0 / `gpt-5.6-luna` 尝试均在 B 原 Thread 恢复后的
`cicada_join` 模型工具调用前失败；这些运行本身没有验收 Ask/Reply。之后，
`TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` 在同一物理主机的
两个逻辑 Node、两个 owner 和两条真实 Codex Thread 上通过，exit 0，
耗时 228.02 秒：A/B 原 native ID 保持，密封 Link Ask/Reply 完成，Hub 不见
正文且 Control business call 为 0。该测试由受控 driver 执行
`codex exec resume`，所以不证明无人值守 cold wake；双物理机、公网 HTTPS、
Android 正向 Group Grant 后续已在独立固定镜像验收通过。失败尝试保留为历史诊断，当前结果与完整
边界见[原生验收记录](architecture-v2-native-validation.md)。

## 2026-09-25 开发基线（`dev` / `967dbd8`）

开始本切片时工作树干净。使用完整仓库挂载、Go 1.27.1 Bookworm 容器和
本地只读 module cache 执行 `go test -count=1 -timeout 15m ./...`，全部包通过；
`go vet ./...` 退出码 0。`python3 scripts/client-contract.py check` 返回
`client-hub-v1.2.1`、29 个 operation、catalog SHA-256
`25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9`；
`python3 -m unittest scripts.test_client_contract scripts.test_client_recovery_fault_proxy`
运行 7 项并通过。Go 首轮仅挂载 `cicada-go/`，使依赖根目录 `docs/` 的
`internal/clientcontract` 测试失败；改为完整仓库挂载后全包通过，故该首轮
失败是测试环境错误，不作为代码缺陷或通过证据。上述基线尚不包含本切片的
代码改动；改后回归和原生/故障结果需另记。

## Client–Hub v1.2.1 Endpoint 证明签名合同勘误

Client v1.2 互操作审阅发现：wire 文档要求 EndpointKeyAttestation 的签名原文
省略 `signature`，但既有 Go 签发/验签实际包含末尾 `"signature":null`。
v1.2.1 修正合同并加入公开合成证明与独立签名测试；既有证明、Grant、密钥、
schema 和 replay 不重写。Go 1.27.1 Docker 的整仓 `go test -count=1 -timeout 15m ./...`、
`go vet ./...`、协议包检查及 4 项 Python 合同测试通过；
Android 独立 Kotlin 验签仍待 Client 仓库在新固定包上执行，不能计 PASS。
为 Android 固定镜像故障验收新增测试专用回环代理与 `/tmp` 下标记数据库
辅助程序；三个恢复分支的 Go HTTP 测试和代理截断测试已通过。正式 Hub
镜像没有故障 API。Android 三场景尚未运行，不能由这些测试替代。

## 2026-09-24 真实 Node→Hub→Codex 审批验收

隔离 Docker 中的真实 `cicada machine agent --once`、Hub HTTP Handler、
Codex CLI 0.156.1 (`gpt-5.6-luna`) 和加密合成 Client 协议驱动完成了一次
Goal→Worker→原生审批→Client 决议→原 turn 继续→Node result→加密
`goal.result` 闭环。受批准动作在隔离目录产生的文件内容得到校验；审批请求的
`threadId` 与 Worker 最终记录的原生 Thread ID 完全相同，attempt 为 1，
Worker `completed`、Intent `resolved`。复跑命令和脱敏结果见
[v1.2 验收记录](client-hub-v12-validation.md)。此测试的 Hub 是实际 HTTP
Handler，Node 是独立进程，Codex 是独立容器；Client 是加密协议测试驱动，
不是 Android，Hub/Node 也不是两台物理机。另一个独立原生探针证明了跨进程
`thread/resume` 和历史连续性；不能把两次测试合并为一次已有 Thread 的
跨机器恢复。Android 真机、公共 HTTPS 与双物理机仍未验收。

## 2026-09-24 远端 Codex 审批闭环与 Node Workspace 定位

Hub 的 Node Worker 审批桥在真实 Agent 二进制、真实 Hub HTTP Handler、
加密 Client RPC 与模拟 app-server 的端到端测试中连续三次通过：
Client 提交 Goal、Node 领取、app-server 请求审批、Client 决定、Node 回答
原生请求 ID、Node 提交结果、Client 读取 `goal.result`。Hub 与 Node 使用独立
Workspace 根目录；Node 以已授权的 `workspace_id` 在本地定位 Workspace，
不执行 Hub 的绝对路径。真实 Codex CLI 0.156.1 的隔离探针另行证明原生
命令审批、跨进程精确 `thread/resume` 以及会话历史连续性；该探针没有经过
Hub/Node/Android。两项证据不能合并宣称真实全链路已通过。

已接受远端审批后 Node 失联或 Hub 重启时，Worker 进入不可自动认领的
`outcome_uncertain` 并产生 `WorkerOutcomeUncertain` 事件，避免在结果未知时
自动再次执行已批准动作。原 Node 的当前授权与原 attempt 可提交迟到结果，
Hub 按同一 attempt 验收且拒绝重复结果；旧 pending 审批在 Hub 重启时取消。
其余原生注入、模型消费和业务结果仍需分层对账；
上述真实联合验收补上了 Codex 经 Hub 审批的隔离链路，双物理机和 Android
真机仍未验收。

## 2026-09-24 Node 子树离线备份与隔离恢复

Node Agent 现在持有单实例锁和生命周期共享维护锁；独立的 MCP Endpoint
密钥发布及 Owner key trust CLI 写入同样持共享锁。`cicada machine
backup/verify/restore` 以独占维护锁复制一个 Node 子树，检查 SQLite WAL、
完整性和文件 SHA-256，拒绝活动 Agent、特殊文件、损坏备份及非空恢复目标。
恢复会保留 Node 身份、Endpoint 私钥、账本和重放状态的字节，并写入
`recovery-pending.json`；Agent 在任何身份创建或联网前拒绝该状态。
Hub `migration backup` 已排除共用 StateDir 中的 `nodes/`，旧归档若含 Node
文件，自动 Verify/Restore 会拒绝，原归档不删除。

新增 `cicada machine recovery inspect --backup DIR --state-dir DIR` 作为隔离
状态的只读核查入口。该命令验证 marker 与 manifest 摘要、恢复树逐文件哈希和
SQLite integrity，并输出有界的本地 crypto/outbox/replay/inbox 状态计数；使用
immutable SQLite read-only 连接，不调用会修改 `INJECTING` 状态的
`nodeinbox.Open`。检查后 marker 和 Node 文件字节保持不变，`agent_may_start`
固定为 false。它无法查询 Hub binding/counter watermark，也不能验证 Node 子树
外 Codex Session 的所有权或模型是否消费注入；marker 不会被自动清除。CLI、损坏
拒绝、marker 缺失、状态不泄露和字节不变由定向合成测试覆盖，未执行真实恢复。

Go 1.27.1 Docker 的 `go test -count=1 ./...`、`go vet ./...` 通过；
`internal/nodebackup` 测试覆盖四个含 WAL 的数据库、真实 Node 密钥与
crypto-state 序号/重放字节、离线锁、损坏和额外 WAL 拒绝、只读校验及隔离恢复。
五个发布目标（Linux/macOS amd64/arm64、Windows amd64）编译及
`SHA256SUMS` 校验通过。使用构建的 Linux CLI 在临时合成 Node 状态上实际
执行 backup→verify→restore，四个 SQLite 行和身份/密钥/凭据文件哈希相同，
恢复标记存在；对该恢复目录启动 Agent 返回非零并在联网前拒绝。

这仍是 **Node 子树快照**：外部 MCP session/outbox 与 Codex 原生记录未纳入；
恢复后 binding epoch、outbox/replay 高水位及不确定原生注入的对账和解隔离
尚未实现。真实生产 Node、双物理机恢复、无人值守冷 Thread 唤醒均未验收。

## 2026-09-24 Client / Hub 恢复与结果读取增量（`dev` 已提交）

当前 Hub 契约为 `client-hub-v1.2`，Client-Control packet wire 保持 v1。Hub schema
增至 v29，新增逐请求的持久响应序号预留和密文恢复通知缓存；新请求在接受事务内
写入恢复标记，旧未完成请求不臆造序号。设备登记已接受的相同签名 Grant 可以在
HTTP 201 丢失后原样重试，撤销、变更 Grant/密钥/owner/Hub 仍拒绝。
`POST /v2/client/rpc/recover` 只认证和查询原签名密文，不再次调用管理业务；
完成者返回原密文，不确定者返回使用原预留序号的持久密文通知，旧无标记请求
返回 `RECOVERY_UNAVAILABLE`。这只是传输 pending 的恢复，不是业务成功证明。

Manager owner 的新 `goal.result` 加密 RPC 从本 owner 已接受的 `intent_id` 推导
Goal，核对 Goal owner，再返回有界 Worker 结果及不含路径/正文的 Artifact 元数据；
外部 owner 不能调用。`TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 使用
真实 Hub HTTP 与合成 Node 回报验证接口，仍未启动真实 Node Agent 或 Android。
Store、Handler 故障测试验证丢 201、Hub 重启、请求序号预留崩溃窗、密文通知
幂等、错误密文、撤销和迁移旧行保留。Docker Go 1.22 的
`go test -count=1 ./...`、`go vet ./...`、契约校验、4 项 Python 合同测试与
`git diff --check` 通过。一次性 `scripts/test-client-hub-interop.sh` 在独立
Docker Hub 真实 TCP 上通过登记精确重试、加密 RPC、完成请求恢复、Node 配对
和双 owner 隔离；脱敏证据为
`.cicada-data/client-interop/v12-20260924/result.json`，源码脏树指纹
`f59b37119531ee52e4e6c872ba67d63978f31474ca9c0106fe70740d2586985f`、
镜像 ID `sha256:b8d143cadb290e2b9ac0cb52a3302ebee2ef364add6f4265b755986ede3213b4`。
独立 Android pending-slot 恢复、真实 Node Agent/Codex、生产 HTTPS 仍为 NOT_RUN。
上游 Codex [#44491](https://github.com/openai/codex/issues/44491) 指出已卸载的
Thread 可能接受 `codex queue --thread` 却不启动模型，直到显式
`thread/resume`。本仓 Node 路径当前只有 queue，故“精确目标入队”已实现，
“无人值守冷 Thread 唤醒”仍未实现；既有真实 Thread 验收由受控驱动显式 resume，
不构成反证。后续须在原生会话所有权租约下接入官方 resume 和状态对账。

依赖与基础镜像复核见[上游技术审查](upstream-technology-review-2026-09.md)。
Go 1.27.1 Bookworm、离线已锁定模块执行 `go test -count=1 ./...`、
`go vet ./...` 均退出码 0；全 Go `gofmt -l` 无输出、`git diff --check`
通过。一次性 Hub 使用 Go 1.27.1/CIRCL 1.6.5/SQLite 1.59.0 与 Alpine
3.24 的真实 TCP 合同测试通过，脱敏证据在
`.cicada-data/client-interop/lts-stack-20260924/result.json`；该次源码指纹
`8571a8eac32aeb069370c42eef30621b2b2d8adf4236f1be4babf11766bd4081`，
镜像 ID `sha256:237fe368fb6b3f2bc45b9f8fd09ab38083843c30f2fef6a21c322dbe93adbdd3`。
Ubuntu 26.04 LTS 完整镜像已构建，官方 shell 安装 Codex CLI 0.156.1，
`cicada version` 退出 0；GitHub Actions 仅做 YAML 解析和上游 Node 24
runtime 元数据校对，未通过 GitHub CI 运行。CICADA 没有 Node.js 服务或
Node 22 固定项；Node.js 24 是当前 LTS，26 仍是 Current。
`scripts/build-release.sh 0.4.0-dev .cicada-data/release-lts-check` 在
Go 1.27.1 容器中完成 Linux amd64/arm64、macOS amd64/arm64、Windows
amd64 五个构建及 SHA256SUMS；容器验证使用 `GOFLAGS=-buildvcs=false`
跳过容器 UID 与工作树 owner 不一致造成的 VCS stamping 失败，未改全局
Git 配置。Node SSE 短流重连
的定向 `-race`、E2EE/Client wire 两包 `-race` 均退出 0。

下节为前一次 N1–N3 验收快照，其 `client-hub-v1.1` 摘要和镜像 ID 只认证
当时构建，不能认证当前 v1.2 工作树。

## 2026-09-24 Client / Hub 规范化验收

本轮在 `dev` 的干净基线 `7c0efc4df6209785df4fc4694792ff5c9163141a` 上，
完成 [联合开发规范](client-hub-development.md) N1–N3 的 CICADA 侧入口。
真实 dispatcher、角色 allowlist、公开及加密 capabilities 统一到嵌入 catalog，
契约修订为 `client-hub-v1.1`，wire 仍为 v1。新增轻量 Hub、源码标识、
确定性协议包、公开合成加密向量和普通 PR CI；未修改 CICADA_CLIENT。

| 验收 | 实际命令 / 测试 | 结果 |
|---|---|---|
| 回归基线与改后全仓 | Docker Go 1.22：`go test -count=1 ./...`、`go vet ./...`、`gofmt -l .` | 两次全仓测试与 vet 退出 0；改后无格式差异 |
| 契约一致性 | `TestCatalogIsVersionedCompleteAndPointsIntoWireContract`、`TestClientRPCDispatchCasesMatchCatalog`、capabilities/guest scope tests | PASS；catalog、OpenAPI enum、实际分发和权限集合一致 |
| 公开密码学向量 | `TestPublishedClientWireVectors` | PASS；请求/响应字节、AAD、绑定和篡改拒绝。未运行 Kotlin 实现 |
| 协议包 | `python3 scripts/client-contract.py check`；`python3 -m unittest discover -s scripts -p test_client_contract.py` | PASS；4 项覆盖确定性、摘要、缺文件和不安全归档 |
| 独立 Docker Hub | `CICADA_INTEROP_OUTPUT=.cicada-data/normalization/docker-interop-3 scripts/test-client-hub-interop.sh` | PASS，退出 0；`TestClientDockerHubSmoke` 确认真实 TCP 加密 RPC、精确重试、Node 配对及双 Owner 状态/拓扑隔离 |
| 开发启动脚本 | 独立临时状态、随机本机端口运行 `scripts/run-client-hub-dev.sh`，随后重复运行同名容器 | PASS；健康检查、精确 image ID、已有 token 收紧到 0600、拒绝替换现存容器 |
| 新 GitHub workflow | `.github/workflows/client-hub.yml` | 已编写，本地对应门禁通过；未推送，GitHub 执行 NOT_RUN |
| Android / 原生 Codex / 公网 HTTPS | 本切片未运行 | NOT_RUN；不能沿用旧版本结果认证本次构建 |

Docker PASS 原始脱敏结果位于
`.cicada-data/normalization/docker-interop-3/{result.json,test.log}`，全仓日志位于
`.cicada-data/normalization/go-regression.log`。测试发生在提交前，明确记录
`dirty=true`；源码输入摘要
`c0e6e51a3bcf3a711baa98e2408050b0f3681f6b1a0f58150d5315974132abdc`，
Hub image ID 为
`sha256:e192d637479ff3528ee4f756d058bd41559f5b0082993291c33bf5b729819ddd`，
catalog SHA-256 为
`f6f05783ddc00e51b92ebe050b5d8e6b9b185fae80d8fc6f04bc3143b6782374`。
前两次门禁尝试分别因镜像名大小写及脚本收尾期间的读取问题退出非零，保留
FAIL 记录；上表 PASS 对应修复并静止脚本后的第三次运行。临时容器、密钥和
数据库均已清理，原有开发 Hub/模拟器未被替换。没有付费模型调用。

本轮没有 DB、密钥或 replay 迁移；登记丢响应与 `UNCERTAIN` pending 恢复
仍待 N4。内层 RPC 仍部分使用文字形状引用，并非完整 JSON Schema。以下
Architecture v2 各阶段的 PARTIAL 结论不因工程门禁完善而改变。

## 2026-09-24 广播与真实跨 Node 原生验收增量

此前在 `dev` 落地的 Hub schema v28 增加不可变同 Group 收件人快照、Node-only 授权读取、Node 逐收件人 sealed 本地/跨 Node `SEND`、MCP `cicada_broadcast` 持久操作与显式重试。范围限同 owner 的一个精确 Group；发送者须同时有 `message.broadcast` 和 `message.send`，接收者须有 `message.receive`，最多 32 人、每批 8 人。Hub 不接收广播明文，快照不保存正文；每个接收者仍由现有单播 Guard 在写入和投递前复权。Store 快照、Hub HTTP 定向测试及 `TestMCPBroadcastLocalAndRemoteSealedFullChain` 已通过：两个逻辑 Node、真实 Store/Fabric、Node Unix 桥和 fake Codex queue 验证本地与跨 Node 两名收件人独立密文投递、Hub 不见正文、Control 业务未构造。fake queue 仍不能证明真实 Codex 广播消费。当前不能宣称真实原生广播、跨 owner 广播或用户经 Monitor 的可信广播已经完成。下文“广播未实现”的旧快照仅描述本增量之前的状态。

广播目前复用单播即时 queue 行为；尚无独立 Group 通知/预算策略，也未提供用户经 Monitor 发起的可信审批来源。`ACCEPTED` 只表示该收件人的本地或 Relay 持久接受，原生注入、模型消费和业务验收仍须分别观察。分批进度在 MCP outbox 持久化，失败或未知结果需要同一 operation 的显式重试；没有后台自动推进所有批次。

本段广播验收时的 Node 备份审计指出：`migration backup` 只锁 Hub 数据库，不能证明 Node 状态一致。后来已增加 Node 子树离线备份和维护锁；完整设备级恢复、Hub/Node 水位及原生注入对账仍未完成，见本文顶部和[实施计划](architecture-v2-plan.md)。

本增量在 Docker Go 1.22、离线依赖缓存下执行 `go test -count=1 ./...` 和 `go vet ./...`，均退出码 0。聚焦 `-race` 覆盖 MCP/Node 广播、Store 快照、scoped inbox 与 Hub snapshot HTTP，均退出码 0；没有运行全仓 `-race ./...`。`gofmt -l` 无输出，`git diff --check` 通过。上述 fake full-chain 的 Control 隔离由不构造 Control 业务对象且检查 Hub method/path 证明，仍非两个独立物理节点。

Node sealed `cicada_receive` 的新增可信元数据为 `kind`、`request_id`、`reply_to`、`sender_endpoint_id`，仍由当前 Endpoint/native Session/binding epoch/Group 的只读游标隔离。旧行仅在精确可信投递证据存在时补齐元数据，不能猜测旧行 Group。Node crypto DB 仍为 v5；当时 Hub schema 增至 v28。真实同 Node 双 Codex Thread Ask/Reply 的先前 PASS 不变。真实同组跨 Node opt-in `TestMCPSealedCrossNodeGroupAskReplyNative` 现在也 **PASS**：`gpt-5.6-luna`、两个独立逻辑 Node 状态目录、两个真实原生 Thread、一个测试 Hub，A Ask→B 原 Thread MCP Receive/Reply→A 原 Thread 恢复并保留上下文，退出码 0、171.22 秒；Hub 不见正文，Control 业务未构造或调用。精确 Session/Endpoint/request 证据见[原生验收记录](architecture-v2-native-validation.md)。两个 Node 仍同处一台 Docker 主机，受控驱动显式绑定/恢复 Session，不能算双物理机或无人值守唤醒验收。

## 2026-09-24 同 Group sealed Node 路径增量（本地 `dev`，尚未合入 `main`）

同 Node 路径新增 Node+Session 双凭据本地 Guard、候选公钥绑定检查、Node 专属密文消息/request 账本与 inbox、MCP `send/ask/reply` 的本机 sealed 分流、注入前复权、撤权终态及不确定注入停重试。此路径没有 Hub Relay 消息路由，但发送/注入前可向 Hub 查询 Guard/Directory，Control 业务不参与。当前又接通同 owner、同 Group、不同 Node 的 sealed SEND/ASK/REPLY：来源 Node 从同组目标取 Hub 返回的公开 key evidence，独立验签并加密；Node-only Hub Relay 持久化不透明密文、按 Node claim，并在领取/目标注入前复核当前 membership、binding 与 Grant；目标 Node 解密入本地 inbox 并投递精确原生 Session。Node 侧必须预先设置可信 `CICADA_HUB_ID`；缺失或不匹配会 fail closed，设备码绑定尚未自动下发此配置。Store 全包/定向测试、Hub HTTP 集成测试和同 Node fake full-chain 通过；当时的 Store/Hub/fake 测试本身不证明双物理 Node 或真实 Codex 消费；后续同组双逻辑 Node 原生测试已通过。

sealed-capable `cicada_receive` 现在经受信本机桥读取 Node inbox，而不是调用 Hub 的明文 `/v2/fabric/receive`。cursor 绑定 Endpoint、native Session、binding epoch 和 Group，并分别记录同 Node inbox 与跨 Node crypto inbox 的位置；返回 `messages`（`message_id`、明文 `body`、`state`、`sequence`、`created_at`）及 `next_cursor`，新增可信 `kind`、`request_id`、`reply_to`、`sender_endpoint_id` 结构化字段；旧行缺少可信映射时保持空值。读取只显示 runtime 已注入或消费状态未知的消息。`OpenReadOnly` 不建表、不做 crash recovery、不变更状态。未映射 Group 的旧行不向新 Group receive 暴露；Node Agent 已补齐显式 Link 入站 normal/recovery `Save` 的可信 GroupID 和最终注入前 exact-attempt recheck。历史无映射行保持隐藏，不根据 Endpoint 或 Link 猜 Group。只有当前 Session 没有 sealed-delivery 能力时，MCP 才保留旧 Hub receive；能力存在但值不支持时 fail closed。

安全复核发现：只看 MCP 缓存能力会让 sealed Endpoint 在缓存标志丢失时误走旧明文写路径。现在 MCP 发送前重新用当前 Session 读取 WhoAmI/Resolve，Fabric 和 Store 写事务同时检查源与目标 Endpoint 的当前 `local_peer_delivery` 能力；status/cancel 也先查当前能力，不能泄露本地 request ID 或取消理由到旧 Hub 路径。旧 Relay inbox 的单连接游标死锁已修复，历史列表改为分批读取正文，避免每条多一次 SQLite 查询。Node 本机交接删除一次重复 Guard 请求；原生明文 inbox 强制私有目录/数据库；精确路由复验由整组扫描改为按 Endpoint ID 查询。本轮进一步移除 MCP Join 的管理 bearer 回退、本机 sealed Reply 的重复探测和 `nodeinbox.RecordReceipt` 别名；历史数据读取、迁移表和跨时间边界的 Guard 仍保留。

官方 shell 安装器已把一次性 `cicada-codex:updated` Docker 镜像中的 CLI 更新至 `0.156.1`。提供方自动审批已由用户配置完成。修复 `cicada_receive` 后，真实 Codex 同 Node 测试 `TestMCPSealedSameNodeGroupAskReplyNative` 退出码 0：两个原生 Thread 完成 A Ask、B 在原 Thread 经 MCP Reply、A 在原 Thread 收到关联结果并保留上下文；Endpoint、request 与 native Session 证据见[原生验收记录](architecture-v2-native-validation.md)。Hub path whitelist 只记录 method/path 元数据，最终检查通过且不含 `/v2/fabric/receive`。测试仍显式绑定原生 ID 并由受控安全点触发 resume，不证明全局 MCP 自动发现、无人值守唤醒或跨 Node 原生连续性。

最后一次安全与清理改动后，Docker Go 1.22 的 `GOPROXY=off go test -count=1 ./... && GOPROXY=off go vet ./...` 退出码 0；`go test -race -count=1 ./cmd/cicada ./internal/store ./internal/nodeinbox -run 'Test(MCPSealedSameNode|MCPLocalGroup|LocalDeliveryAuthorization|OpenRequiresPrivateDirectory)'` 退出码 0。`gofmt -l` 全 Go 文件无输出、`git diff --check` 通过。这里的 `-race` 仅覆盖列出的切片，不是全仓 `-race ./...`。

该轮 Docker Go 1.22 的 `go test -count=1 ./...`、`go vet ./...`、全 Go 格式检查及 `git diff --check` 均通过。Store 全包及 same-Group sealed 定向测试、Hub HTTP 集成 `TestNodeSameGroupSealedHTTPRoutesAuthorizeOpaqueTrafficWithoutControl`、同 Node fake full-chain、两逻辑 Node same-Group fake full-chain 和 scoped `cicada_receive` 测试均通过；新增 inbox/本机收件全链的聚焦 `-race` 也通过。fake Codex queue 不证明模型真实消费；真实 Codex 同 Node 两 Thread 的受控 Ask/Reply 则已单独通过。当时双物理 Node、真实 native 广播、Node 一致点备份/恢复与 Android 独立互操作仍未通过验收；Node 子树离线备份后来已完成，但设备级恢复仍未完成，因此 v2-B 整体保持 **PARTIAL**。

快照日期：2026-09-24。`dev` 从 `main` 的 `f4fa7eb8d948ae09834be0b5ec2695205cba536f` 开发；目标规格为根目录 Architecture v2.1。以下阶段/逐项矩阵中的“当前”和 schema v30 均指这个历史快照；2026-09-26 的 Monitor 进度以本文顶部为准。本文区分历史 v2 实现证据与新的退出条件。旧版 MA→MB 演示通过不等于新跨组直达已实现。

状态约定：**A／完成** = 代码和针对性测试覆盖该限定范围；**B／部分** = 有实现但缺完整验收或只覆盖 fake/in-process/native 子集；**C／未完成** = 尚未实现或缺少验收证据；明确缺少外部条件才标 `BLOCKED`。该 2026-09-24 快照的 Hub schema v30、Node crypto DB v5；v27 grants 已被 Node-only same-Group sealed Relay route 消费，并经 Store、Hub HTTP 与两逻辑 Node/fake Codex 验证。v30 为 Node Worker 原生审批桥添加绑定的幂等持久记录；HTTP/Store 与模拟 app-server 的审批链路已验证。独立 Docker 中真实 Codex 0.156.1 的命令审批与跨进程精确 `thread/resume`、上下文延续通过，但真实 Node Agent→Hub→Android 联合验收仍缺；证据见 [v1.2 验收记录](client-hub-v12-validation.md)。此前 `-race ./internal/store` 曾停在既有备份校验测试并于默认 10 分钟超时，本轮 Store 包测试已通过。Client 独立仓库在固定 967dbd8 镜像上的 Android 模拟器管理、恢复与审批结果另有 PASS，不归属于这批 Go 改动；当前代码尚未与新 Android 镜像联合验收。完整 -race ./... 也未针对这批改动完成。

## 2026-09-24 历史基线：阶段结论

| 阶段 | 状态 | 已有事实 | 仍缺什么 |
|---|---|---|---|
| v2-A 身份、Group、显式 Join、统一 Guard | **B（相对 v2.1）** | Principal/Membership/Endpoint/SessionBinding、显式 Join、旧 API guard；v11 多组关系及同机双容器真实 Codex 多组 Ask/Reply；v12 版本化 Group 父子关系、防环、不继承授权；v26 增加由当前 Node owner 绑定推导的 guest Join 服务端入口和本机 Codex record/Unix socket 桥接。两个 owner 的真实 Codex Thread Join 与 sealed Link Ask/Reply 另有同机双逻辑 Node 验收，见 C-04。 | 桥接信任同 OS 用户；Android guest enrollment、双物理 Node 与嵌套 Group 面板编辑、完整跨用户 Guard 未完成或未验收。 |
| v2-B Relay、Node、原生异步恢复 | **B** | 持久 Relay/Node、精确 queue、Control-free test、同 Node sealed ASK/REPLY 的真实 Codex 原生 Thread 验收通过；同组跨 Node route 的 Store/Hub、两逻辑 Node/fake Codex full-chain 及两逻辑 Node/真实 Codex ASK/REPLY 通过。 | 同组跨 Node 已有两个逻辑 Node 的真实 Codex 验收；双物理机仍未验收；旧的未 sealed Session 组内 peer 路径仍可能走明文；无人值守前台安全仍缺。 |
| v2-C 通信图与跨组/跨用户 | **B（单收件人密文 SEND/ASK/REPLY）** | 旧版 GroupGateway/MA→MB 状态和真实演示保留为历史证据；v13–v27 建立 Link 提案、候选公钥、key-bound 双侧 Grant 和两个独立 owner 的邀请；显式 Link 有 fake 全链和两个 owner 的真实 Codex sealed Ask/Reply 验收，后者限同机两个逻辑 Node；同 Node sealed 路径也有真实 Codex Thread 闭环。v31–v33 已接入内部 Monitor 通知、批准 ID MCP 和逐收件者结果；独立 Client Group Grant 正向验收另有证据。 | 双物理机、无人值守 cold wake、真实 native Monitor 消费、Client Monitor RPC/Android 和双真实 Owner 的 Android 越权测试仍缺；邀请或 Grant 单独不建立消息路由。 |
| v2-D Shared Task/Lease | **B** | Shared Task claim/结果验收、ResourceLease 权威冲突键、结构化 handoff、副作用 ledger 与 scoped Artifact v6–v10 已实现并测试。 | GPU/workspace 资源仍 advisory；真实执行器强制 fencing/外部副作用对账不完整。 |
| v2-E 产品化/互操作 | **B** | Android↔Hub PQ 设备授权/RPC、状态快照、部分差异游标、持久异步 Intent、加密拓扑读写与设备撤销有服务端测试；Node 设备码配对后可用单独 Node 凭据执行同 owner 的 Worker 管理链路；Client 已在固定 `967dbd8` 镜像完成模拟器管理、故障恢复、审批结果与独立 Group Grant 闭环；仍保留只读 PWA 管理视图。 | 手机侧由独立仓库负责；完整状态推送、真机/公网及双真实 Owner 越权验收未完成。 |

## 2026-09-24 历史基线：逐项状态

| 编号 | 状态 | 证据 | 边界/下一步 |
|---|---|---|---|
| A-01 旧 v1 guard | **A** | `control/fabric.go` `legacyEndpointIdentity`/`requireLegacyEndpoint`；`store/fabric.go` legacy read/write filters；`TestLegacyFabricRejectsReadyV2EndpointsAndRelayMessages`、`TestLegacyFabricPeerRoutesAreRemoved`、`TestManagementEndpointReadProjectionReplacesLegacyPath`。 | 公开 `/v1/endpoints` 读写路由均已移除；内置面板使用 `/v2/management/endpoints` 只读投影。历史内部方法与表待迁移对账。 |
| A-02 四层身份 | **A** | `store/fabric_v2.go` 表/Store API；`TestFabricV2IdentityBindingAndFencing`。 | role binding 是管理面 CAS；Join 不自动授予 worker/monitor。 |
| A-03 显式 Join | **A（既有管家 owner）/ B（guest）** | `/v2/fabric/join`、`fabric.Service.Join`；MCP `cicada_join`；`TestCicadaMCPToolsRequireExplicitJoin`、`TestExplicitJoinIsIdempotentAndRotatesBindingCredential`。v26 的 `POST /v2/fabric/node/join` 用当前绑定的 Node bearer 推导 guest owner/Node，拒绝 body 伪造身份、异组和跨 Node 重绑；Node 本机桥接校验 Codex session record/workspace，Node 撤销后 guest Session token 失效。两个 owner 的真实 Codex Thread Join 与 sealed Link Ask/Reply 另有同机双逻辑 Node 验收，见 C-04。 | 同 UID 进程可伪造本机环境与记录；Hub 不独立证明真实 Codex Thread。Android guest enrollment、双物理 Node 和无人值守唤醒仍未验收。 |
| A-04 v2 actor/Group Directory | **A** | `Authenticate/Authorize/List/Resolve`；`TestDirectoryIsGroupScopedAndNeverGuesses`、`TestActorForgeryAndRevocationFailClosed`、server forged sender/group negative test。 | 旧 v1 仍独立存在，需继续维持所有入口回归。 |
| B-01 Relay durable state | **A** | `relay_v2_message_security`、`requests`、`outbox`、`inbox`、`delivery_attempts`、`receipts`、`consumer_cursors`；`relay_v2_test.go` 幂等、单 claim、cursor/restart、伪造 ACK。 | 独立网络 relay/吞吐/压力未测。 |
| B-02 cancel/expiry/late | **A** | `TestRelayV2ExpiryCancelAndLateReplyAreAtomic`；request events 保存 `LATE_RESULT`。 | native cancel/late business result 仍需真实 runtime 证据。 |
| B-03 Node receipt/fencing | **A** | `nodeinbox/inbox.go`、`node_owner_bindings_v2`；machine relay/server tests；Node token 必须获 owner Client 设备码确认并绑定精确 node，receipt 校验 endpoint/digest/attempt/epoch/lease 且禁止状态回退；Codex 子进程不继承管理/Node token。 | runtime 消费没有可验证 API；最终只能标 unknown。 |
| B-04 Control-free path | **A** | `internal/fabric` 无 Control 依赖；`TestFabricV2WorksWithoutControlBusinessService`、`TestControlBusinessDisabledPeerRPC`。 | 测试是同进程构造；没有独立服务宕机/宿主机隔离。 |
| B-05 native continuity/queue | **B** | 官方 `codex-cli 0.156.1`；既有 G1 的真实 MCP Join/Ask/Reply 与原生 context 连续；2026-09-24 `TestMCPSealedSameNodeGroupAskReplyNative` 验证同 Node sealed ASK/REPLY，两个逻辑 Node 的同组原生 ASK/REPLY 另有独立验收。 | 驱动显式绑定 Session ID 并调用 `exec resume`；不证明自动 MCP session discovery 或 unattended wake。双物理机仍未验收。 |
| C-01 GroupGateway records | **A** | `gateway_v2.go` 七类 `gateway_v2_*` 表；`gateway_v2_test.go` card/contract/mailbox/request/result、scope/deadline、digest、late/cancel。 | “A”只指同库状态/合同实现。 |
| C-02 representative owner epoch | **A** | `ClaimRepresentative/TakeoverRepresentative`；并发单 winner 和 stale owner 拒绝测试。 | 没有跨 Control owner lease transport。 |
| C-03 provenance/result | **A** | `TestGatewayV2ContractScopeDeadlineAndProvenance`、`TestMonitorMediatedCrossGroupCollaboration` 保留 producer principal/endpoint/group、evidence/provenance refs。 | 未验证真实外部 producer、签名证据或 Artifact 权限。 |
| C-04 新跨组/跨用户直连 | **B（单收件人密文 SEND/ASK/REPLY）** | 两个 owner 的提案及当前 key-bound Grant 经 Node 本地 Owner trust 再验证；显式 Link 的 MCP SEND/ASK/REPLY 经本地 Node 桥加密，Hub 只持久保存 `SEALED_V1`，目标 Node 在精确 attempt 授权下持久收件、复验并调用官方 `codex queue --thread`。Fake Codex 全链测试覆盖两个逻辑 Node；`TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` 又以真实 Codex Thread 验证双 owner sealed Ask/Reply、原 ID 保持、Hub 无正文及 Control business call 为 0。 | 原生 PASS 限同机两个逻辑 Node，driver 使用受控 `codex exec resume`；不证明 cold wake、双物理机或公网 HTTPS。Android 单 Owner Group Grant 已单独通过；跨 Owner 手机授权、完整广播和可选 Monitor 仍未验收。详见[原生验收记录](architecture-v2-native-validation.md)。 |
| D-01 Shared Task/Lease | **B** | `shared_task_v2.go`、`resource_lease_v2.go`、`shared_task_handoff_v2.go`、`shared_task_side_effect_v2.go` 与测试。 | 外部 GPU/workspace 强制 fencing、真实 SideEffect 执行对账未完成。 |
| E-01 产品化/互操作 | **B** | Hub v26 的 Client PQ 入口支持 owner 范围状态、Goal、Intent、审批、拓扑和 Node 管理。`client-hub-v1.3` 已公开 Monitor prepare/confirm/status/recover RPC；`25013b5` Node 增加只读验签/解密 preview，deterministic/disposable TCP gates 及受控 Android/native Monitor preview→dispatch→两 recipient receive 链通过。 | 当前验收仅两逻辑 Node/单容器。完整产品 React Native consent UX、双 Owner 手机越权、物理 Android/dual Node 和 public HTTPS 仍缺；其他状态推送、跨 Owner 操作按各自合同与验收边界判断。 |
| E-03 Client→Node Worker 闭环 | **B（隔离真实 Node/Codex）** | v23 的 owner 列不回填旧行；`TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 以 PQ Client RPC、Node 设备码、v2 Node heartbeat/jobs/claim、Workspace 快照 GET/POST 和 fenced result 跑通 Hub HTTP 链路。Store/Control 的撤销、并发 claim、旧 attempt、快照 CAS 和验证期间撤权测试通过；CLI 的 Node 快照收发与重定向拒绝定向 race 测试通过。真实 Node Agent、Codex CLI、Hub HTTP 与加密合成 Client 驱动的审批→结果闭环另以 `scripts/test-real-node-codex-approval.py` 通过，原生 Thread ID 一致。 | 原有 HTTP 集成测试本身不启动真实 Agent；新联合测试也未运行 Android、双物理机或公网 HTTPS，且不证明已有用户 Thread 的跨进程恢复。 |
| M-01 additive schema | **A（合成迁移测试）** | v14 增加 `endpoint_key_candidates_v2`，公开候选及其证明；定义为 additive，不更新旧 Endpoint、Contact、密钥、ratchet/replay 行。 | v14 合成旧库重跑/中断/并发打开和旧状态保留测试通过；真实生产库未演练。 |
| M-02 legacy pending | **A** | 旧 Endpoint 默认 `MIGRATION_PENDING_GROUP`；无明确映射不创建 Group；`TestFabricV2LegacyEndpointMigrationIsAdditiveAndRepeatable`。 | 需生产前显式 mapping/quarantine 操作和审计导出。 |
| M-03 backup/rollback | **B** | `cicada migration inventory/backup/verify/restore` 验证合成 Hub StateDir 的 Contact/session/replay；`cicada machine backup/verify/restore` 验证合成 Node 子树和隔离恢复。 | 真实生产 StateDir/Node 未演练；Node 私钥和 crypto-state 不在 Hub 备份中，外部 MCP/Codex 状态不在 Node 子树备份中。恢复旧计数后重新联网仍需显式 fencing/reconciliation。 |
| M-04 v14 key candidates / Node crypto-state | **B（SEND 已接入）** | Hub 按 Group 授权读取 `CANDIDATE`；MCP 从已 Join Session 发布 Node 本地公钥。Node DB v5 保存稳定私钥、序号、原样密文 outbox、入站密文与 replay，并以独立 Owner key trust 和双侧 v22 Grant 建立 scoped pin。显式 Link SEND 已调用本地 Seal/Open、重启后复用同一密文；目标 Node 的密文 inbox 与原生注入状态分层保存。Node 子树备份测试保留密钥及 crypto-state 字节。 | 入站持久化不证明模型消费；`INJECTION_UNCERTAIN` 和恢复后计数仍需原生/Hub 对账，真实生产恢复未验收。 |
| M-05 v15/v16/v22 owner approval | **B（单收件人密文路由已使用）** | v15 登记用户独立持有的 ML-KEM/ML-DSA 公钥；v16 旧合同 Grant 保留为不绑定 Endpoint key 的历史记录；v22 新表保存当前合同、两端原生绑定与公钥候选摘要的双侧签署，旧 v16 Grant 报 `LEGACY_KEY_UNBOUND`。v26 外部邀请可产生跨 owner 提案。邀请和单侧 Grant 不激活路由；双方当前 key-bound Grant 已用于显式 Link SEND/ASK/REPLY 的入队、领取与注入前 Guard，双 owner 的真实 Codex sealed Ask/Reply 也已验收。 | 原生验收限同机双逻辑 Node，未覆盖双物理 Node、Android 正向 Group Grant 或广播。外部邀请 token 不是两侧 Endpoint 密钥批准，管理 bearer 不能代替用户签署。 |
| M-06 v17 sealed Relay Store | **B（Node-auth SEND/ASK/REPLY 闭环）** | 独立 `relay_v2_message_payloads` BLOB/mode 迁移；Node 凭证保护的 `/sealed/send|ask|reply|claim`、请求状态/取消与精确 attempt 授权。ASK 的密文、request、outbox/inbox 同事务持久；REPLY 由原请求推导反向路由，迟到结果留密文终态且不自动唤醒。两端 Node 写入密文和恢复坐标后才报告 `NODE_RECEIVED`，注入前重查 Link/Grant/binding/Node owner；撤权和旧 attempt 拒绝，重复消息不二次 queue，原生结果不确定则停在 `INJECTION_UNCERTAIN`。 | 显式跨组单收件人有同机双逻辑 Node 的真实 Codex Ask/Reply 验收；双物理机与冷唤醒仍缺。旧同组 peer API 仍存明文，保护范围须明确区分。 |
| M-07 v18 Client 设备/重放 | **B（单 owner Hub）** | 持久 Hub ID、owner 签名设备 Grant、设备撤销/epoch、请求序号/operation ID、精确重试缓存与中断 UNCERTAIN；v18 迁移回滚/重跑及旧记录保留通过。 | 还缺双用户独立状态分区、首次远程可信引导、Android 设备码 UX 和完整备份/换机演练。 |
| E-02 Client PQ HTTP 入口 | **B（固定范围已验收）** | `internal/clientwire` 和 `/v2/client/{identity,devices/enroll,rpc}` 使用 ML-KEM/ML-DSA/AES-GCM，AAD 绑定 Hub/owner/device/epoch/sequence/operation/方向/密钥版本。v1.3 Monitor prepare/confirm/status/recover 在固定 `25013b5` Hub 上通过 Android strict status；具体 10 selectors、APK 与源 commit 见独立 [Client report](../../CICADA_CLIENT/docs/client-monitor-v13-25013b5-native-validation.md)。同一受控运行完成 preview→dispatch→两个原 Thread receive。 | 仅限本次候选和两个逻辑 Node/单 container；仍缺 full React Native consent UX、physical dual Node/Android 与 public HTTPS。其他跨 Owner、恢复和旧 API coverage 按各自条目判断。 |

离线公钥引导的可复现命令与边界见 [owner approval bootstrap](owner-approval-bootstrap.md)。

## V01–V73 验收快照

这里的 PASS 只代表表中写明的范围；`PARTIAL` 与 `NOT_RUN/BLOCKED` 不计入通过。

| ID | 状态 | 本轮证据或缺口 |
|---|---|---|
| V01 | PASS | 未 Join native session 不产生 Endpoint，Directory resolve 返回不可见。 |
| V02 | PASS | 同一 native session 重复 Join 保留 Endpoint/Principal，轮换 binding epoch/token。 |
| V03 | PASS | Join 仅创建 member；worker/monitor 需要 Control CAS role binding。 |
| V04 | PARTIAL | session discovery 会显式报错，但未构造真实多个候选 native session 的黑盒歧义测试。 |
| V05 | PASS | 同组授权成员可 list/resolve 必要 Network Card metadata。 |
| V06 | PARTIAL | 当前异组 Endpoint 不可枚举；新版显式连线的外部 Endpoint Card 尚未实现。 |
| V07 | PASS | 同名 Endpoint 返回 `AMBIGUOUS`，不猜测。 |
| V08 | PASS（服务层） | `LeaveGroup` 只撤销当前 Group，最后一组退出才 fence binding；`Leave` 原子撤销整个 Endpoint 的所有 Group；Principal Membership 撤销只在无剩余授权 Group 时 fence binding。 |
| V09 | PARTIAL | 新 Endpoint 不自动读取其他 Endpoint inbox，但历史明文授权策略未形成完整对象。 |
| V10 | PARTIAL | v11 Store 关系、MCP/HTTP/CLI 显式第二组 Join/切换/逐组 Leave、Directory/Relay group scope 测试，以及同机双容器真实原生多组 Ask/Reply，证明同 native ID/Endpoint 多组隔离；共享记忆 UI 提示未完成。 |
| V11 | PASS | MCP/HTTP Ask 持久返回 request_id，不等待模型结果。 |
| V12 | PASS（同机逻辑 Node） | G1 `rq_874bd0118f6ee40a` 的 Ask/Reply 均由模型 MCP 提交，queue/resume 保持原生 Session。 |
| V13 | PASS | 目标离线时 request/inbox 保持 queued，rejoin 只重绑安全的 READY 行。 |
| V14 | PASS | 同 sender scope、idempotency key、digest 返回原请求。 |
| V15 | PASS | 同 key 不同 digest 明确冲突且不覆盖。 |
| V16 | PASS | 错 endpoint/digest/attempt/binding/epoch/Node credential 的 ACK 被拒。 |
| V17 | PASS | reply 必须来自原 request receiver principal/endpoint/group。 |
| V18 | PASS | 非破坏 receive、opaque cursor 与重启测试保留未确认消息。 |
| V19 | PASS | 过期后的回复记录为 `LATE_RESULT`，不重开请求。 |
| V20 | PARTIAL | 有 cancel requested/cancelled/late 状态；native 实际停止和副作用确认未支持。 |
| V21 | NOT_RUN | Ask wait-cycle 检测/预算未实现。 |
| V22 | PARTIAL | Ask admission quota 已实现；Group 广播有固定 32 人上限和每批 8 人，但独立 wake 预算、限速与大规模 fan-out 压力验收尚未实现。 |
| V23 | PARTIAL | HTTP/MCP/`fabric v2` CLI 共用 Fabric Service；CLI 拒绝跨 API origin 和错误 native context 的缓存凭据。旧 `/v1/threads/*`、`/v1/fabric/*`、`/v1/endpoints` 全部 HTTP 路由及 `cicada endpoint` 命令已移除并有拒绝测试；历史表/内部迁移路径尚在。 |
| V24 | PARTIAL | inbox 按 receiver Endpoint 定址，其他成员不被自动唤醒；组内共享历史的授权读取语义仍待补齐。 |
| V25 | PASS | 真实 E2E 的 Node delivery 和 `thread.started` 都保持精确 A/B UUID。 |
| V26 | PASS | SessionBinding lease owner/epoch CAS 和 Node 单消费者测试只有一个有效 owner。 |
| V27 | PASS | credential rotation/takeover 后旧 epoch/token/receipt 被拒。 |
| V28 | PARTIAL | fake Node 崩溃窗口进入 `INJECTION_UNCERTAIN` 且不盲重投；未杀死真实 Codex 注入进程演练。 |
| V29 | PARTIAL | 只使用官方 queue，无 tmux/按键/Enter；真实用户同时前台输入未压测。 |
| V30 | PARTIAL | unsupported harness 和 queue failure 明确 FAILED；授权 handoff/lineage 尚未实现。 |
| V31 | PASS | `TestControlBusinessDisabledPeerRPC` 不构造 Control，组内 ask/reply 成功。 |
| V32 | PASS | 全量 Control/Goal/Worker/Approval 回归通过；未删除现有管理功能。 |
| V33 | PARTIAL | Store/Node inbox/journal restart 测试通过；未在真实双机链路逐窗口重启网络服务。 |
| V34 | NOT_RUN | Runtime provider 限流与有界退避验收未实现。 |
| V35 | PARTIAL | 无连线的 stable ID 异组直连被拒；当前双方 key-bound Grant 下的单收件人密文 SEND/ASK/REPLY 经一个 Hub 直达，撤权/超 scope 拒绝有定向测试。真实双 owner Link Ask/Reply 已由两个真实 Codex Thread 验收；双物理 Node 和无人值守 cold wake 仍缺。 |
| V36 | PARTIAL（真实 Codex、同机双逻辑 Node） | 密文 REQUEST 与关联的反向 REPLY 在 Hub Store 中独立持久；Node 凭据保护 HTTP Ask/Reply/status/cancel。MCP 通过受信本机桥绑定当前原生 Session；fake Codex 两逻辑 Node 全链测试通过，`TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` 也以两个 owner 的真实 Thread 完成 sealed Link request/reply，原 ID 保持、Hub 不见正文、Control business call 为 0。 | 原生测试使用受控 `codex exec resume`；双物理机和无人值守 cold wake 未验证。旧 MA→MB 演示不能代替新 G2。 |
| V37 | PASS | `ACCEPTED`、`IN_PROGRESS`、`RESULT_ACCEPTED`、`CLOSED` 分离。 |
| V38 | PARTIAL | 普通已授权单收件人 Link 路由不依赖 Monitor，两逻辑 Node/fake Codex 路径已测；明确要求 Monitor 审阅的离线等待策略未实现。 |
| V39 | PARTIAL | 旧代表 owner/epoch CAS 已测；新可选审阅 owner 尚未实现。 |
| V40 | PARTIAL | 旧结果保留 producer/evidence/provenance；新直达和广播来源未测。 |
| V41 | PARTIAL | 当前双端 key-bound Grant 的 Link SEND/ASK/REPLY 对动作、scope、期限、撤权和绑定在入队/领取/注入前重查；fake 两逻辑 Node 全链与真实双 owner Codex sealed Ask/Reply 均通过。2026-09-24 同 Node 同 Group sealed 路径是本地 Group 授权切片，不代表同 Node 跨 Group Link；尚缺双物理机和更广拒绝/恢复矩阵。 |
| V42 | PARTIAL | 既有 Contact revoke/E2EE 状态保留；v13 提案可按预期版本撤销，但跨用户已激活连线、广播待投递项与端点密钥撤销尚未实现。 |
| V43–V52 | PARTIAL | v7–v10 Shared Task/Lease/Handoff/SideEffect 与 v6 scoped Artifact 已有 Store/HTTP 测试；真实 GPU/workspace 执行器强制、外部副作用和完整恢复矩阵未通过。 |
| V53 | PASS | Actor 来自 Session credential；未知 sender/group/role 字段和错误 scheme 被拒。 |
| V54 | PARTIAL | peer body 不会创建 Approval，HTTP 严格字段拒绝伪造；缺专门的正文 prompt-injection 验收。 |
| V55 | PARTIAL | Federation 保留 actor/provenance；尚无 Guard 对真实恶意 Monitor 指令的执行入口演练。 |
| V56 | PARTIAL | membership revoke 阻止 Fabric read/write；跨组 Artifact/search/export 统一 guard 尚未实现。 |
| V57 | PARTIAL | 既有 Contact E2EE 重放/篡改测试通过且未降级；Endpoint context-bound ML-KEM/ML-DSA/AES-GCM、ML-DSA-65 attestation、v22/v27 Owner grants 与 Node 本地 Owner trust 已接入 Link 和 same-Group `SEALED_V1` SEND/ASK/REPLY。跨 Node Link/同组 Hub Relay 只存密文；同 Node 同组使用本地账本。双 owner sealed Link Ask/Reply 已有同机双逻辑 Node 的真实 Codex 验收；双物理机仍缺。旧或无 sealed-delivery capability 的 Session 仍有旧明文兼容边界；三 Thread native broadcast 的 opt-in 已运行但完整验收未通过，广播授权矩阵仍不完整。 |
| V58 | PARTIAL | 合成 Hub StateDir 的 backup/verify/restore 与 Contact/session/replay counter 对照通过；Node 子树离线备份/校验/隔离恢复保留 Endpoint 私钥、crypto-state sequence/outbox、入站密文和 replay，含四个 WAL 库与锁竞争测试。显式 Link SEND 已接入 Node 原生 queue，崩溃/重复/不确定注入有 fake Codex 测试。 | Node 私钥与 crypto-state 不在 Hub 备份；MCP/Codex 外部状态不在 Node 子树备份。真实生产设备恢复、rollback fencing 和恢复后计数对账未验收。 |
| V59 | PARTIAL | secret scan、token-only-hash、0600 token files、child env filtering 已验证；未覆盖生产 crash dump。 |
| V60 | PASS（事务测试） | 版本化迁移账本、中断回滚/重跑、并发打开与旧记录保留测试通过；真实掉电/备份恢复未验收。 |
| V61 | PARTIAL | READY v2 Endpoint/message 不能经旧 Directory/message/machine API 绕过；旧公开 `/v1/fabric/*`、Thread queue/message、Contact peer/federation ingress、Contact session 查询/轮换、`/v1/endpoints` 和管理 bearer `/v1/communication-links` HTTP 路由已退役。旧 Control→Contact Relay 发送器及未被服务入口调用的 Control peer 转发方法也已删除；内置面板已切到 `/v2/management/endpoints`，历史 Contact ratchet 方法与数据库仍待迁移对账。 |
| V62 | PARTIAL | 授权每次查权威 SQLite、无扩权 cache；未注入权威服务故障黑盒测试。 |
| V63 | PASS | 缺少双物理机/自主 MCP/迁移条件均明确标记，不计为通过。 |
| V64 | NOT_RUN | 未运行压力测试，也未声明真实多 Agent 容量。 |
| V65–V70 | PARTIAL | 同 Thread 多 Group 服务/HTTP/MCP scope、独立撤权和同机双容器原生 Ask/Reply 有证据；v12 Group 父子关系 API 防环/版本/不继承授权有测试。双 owner Link 与同 owner 同组跨 Node 的密文 ASK/REPLY fake full-chain 均通过。V67 同 Node 同 Group sealed 路径与 V69 双 owner 单 Hub sealed Link Ask/Reply 均已有真实 Codex Thread 验收；跨 owner 测试限同机两个逻辑 Node，并由 driver 受控 resume。V66 面板拖拽、V68 双物理 Node、cold wake 与完整多组/拒绝组合仍未验收。 |
| V71 | PARTIAL | 新增 `TestMachineSealedAskReconnectClaimsDurableOfflineMessage` 在一条 TLS/TCP SSE 链中验证 sealed Link ASK 离线持久化、新连接 ready、Node 生产 claim/decrypt/inbox、fake queue 去重和分层回执，普通及 `-race` 均通过。另有双私有网桥门禁证明两个 Node 只能出站到同一 Hub、彼此及 Hub→Node 不可拨入；该门禁和 SSE 测试仍是两个隔离子链。真实双物理机、真实 Codex 消费及 Node/Hub 逐窗口重启未验收。 |
| V72 | PARTIAL | 同 owner 同 Group 的 Agent-initiated 本地+跨 Node 逐人密文广播通过两个逻辑 Node/fake Codex full-chain。早期普通广播三 Thread 尝试因夹具/结果解析/自动审批失败的历史记录保留；当前通过的是 V73 用户经 Monitor 发起的限定链路，见本表 V73 和 `client-hub-v13-25013b5-validation.md`。不把 Monitor PASS 归因给普通 Agent 广播；物理双 Node、通知预算与各类故障恢复全链仍未验收。 |
| V73 | PASS（限定链路） | 固定候选 `25013b5` 的同一 original Monitor Thread 完成一次只读 preview、一次独立 dispatch；两原生 recipient Thread receive/context assertions 通过。Client 10 selectors/final strict status、Core scoped ciphertext scan、Intake Hub state audit 与 cleanup 均 PASS；Hub 记录一条原审批，两个 unique recipient outcomes：local `NODE_REPORTED`、remote `RELAY_PERSISTED`。派发授权和这些 outcome 不证明普遍模型正确性；物理双 Node、完整 RN 同意 UI、公网 HTTPS 未验收。详见 [bounded candidate report](client-hub-v13-25013b5-validation.md)。 |

## G1–G5 演示状态

| 演示 | 状态 | 证据边界 |
|---|---|---|
| G1 组内原生问答 | PASS（同 Node、两个真实 Thread） | 真实模型 MCP Join/Ask/Reply；另有两组 Membership 同 native ID/Endpoint 的第二组 Ask/Reply；2026-09-24 同 Node sealed Ask/Reply 也通过 `TestMCPSealedSameNodeGroupAskReplyNative`，A 恢复原上下文并收到 B 的结果。详见 native-validation。由测试驱动显式绑定 Session 和受控 resume，不是无人值守 Adopt/前台并发或双物理机验证。 |
| G2 多组/跨组直达 | PARTIAL（部分真实原生通过） | 新版显式 Link 与同组跨 Node 的单收件人 ASK/REPLY 均有逻辑 Node/fake Codex 证据，不经过 Monitor；同组跨 Node 与跨 owner Link Ask/Reply 均已有真实 Codex 验收，但均为同机逻辑 Node，跨 owner 测试由 driver 受控 resume。双物理机、无人值守 cold wake、完整多组场景和广播仍未验收。旧 MA→MB→B1 原生演示仍只作历史证据。 |
| G3 Control 隔离 | PARTIAL（密文单播已证明） | 新版跨 Node SEND/ASK/REPLY 与同 Node 同 Group ASK/REPLY 全链测试只构造 Store/Fabric/Node/MCP，不构造 Control 业务模块；跨 owner 原生测试也断言 Control business call 为 0。本机路径拒绝 Hub Relay 消息路由，但发送/注入前可调用 Hub Guard/Directory。旧 G1/G2 也在 `serve --fabric-only` 中成功；广播尚未覆盖。 |
| G4 重启/失联/重复 | PARTIAL | Store/Node fake fault、restart、duplicate、uncertain 窗口通过；真实逐窗口杀进程未跑。 |
| G5 权限/数据边界 | PARTIAL | unjoined、伪造身份、旧跨组拒绝、旧 API、撤权、错误 ACK 和 scoped Artifact 子集有测试；新连线/多组/广播/PQ 的拒绝矩阵未跑。 |

## 已实现表面

现有 v2 HTTP 路由在 `server/fabric_v2.go`、`server/relay_node_v2.go` 和 `server/relay_node_group_sealed_v2.go`：除既有 Fabric/Node API 外，Node-only `/v2/relay/nodes/{node_id}/group/sealed/{peer-key,send,ask,reply,claim,requests/*,deliveries/*/authorization}` 承载 same-Group 跨 Node 密文路径，并以 Node credential 鉴权。MCP `mcp.go` 只在 `cicada_join` 后使用 `CicadaSession`，支持 `cicada_use_group` 和 `cicada_leave_group`；选定的 `Cicada-Group-Scope` 仍由服务端校验双重 Membership。当前 MCP Join 只调用受信 Node 本机桥，不再把管理 bearer 作为回退；服务端仍保留独立的管理/Node Join 入口，模型提交的 `principal_id`、sender、role、approval 字段不作为身份依据。Link 的同 owner 提案/撤销经加密 Client `topology.apply` 完成；旧 `/v1/communication-links` HTTP 路由已删除。v14 `/v2/fabric/endpoint-keys` 登记当前绑定的候选公钥；Node-only Link/same-Group 授权证据查询供本地 Owner trust 复核。显式 Link 的 `cicada_send/ask/reply` 与同 owner、同 Group、异 Node 的 sealed peer API 均由本地 Node 桥从可信 Session 推导身份、目标和 request correlation；Hub 保存不透明密文并在入队/claim/注入前复查授权，不调用 Control。相同 Node 的 sealed `cicada_send/ask/reply` 走本机账本/inbox，不经 Hub Relay 消息路由，但发送/注入前仍可查询 Hub Guard/Directory。sealed `cicada_receive` 经 Node 本机桥，从两个 Node inbox 数据库只读合并当前 native Session/Group 的已注入消息；只有没有 sealed-delivery capability 的旧 Session 才保留 Hub receive fallback。旧无 sealed capability Session 的同组写路径仍可能保存明文；sealed Session 不静默降级。同 owner、同 Group 的 sealed `cicada_broadcast` 已有 fake full-chain；跨 owner 和用户经 Monitor 广播未实现。

旧版/未密封的 v2 Relay `Receive` 是带 opaque cursor 的查看；Node 的 claim/receipt 才改变投递 attempt。未密封 peer body 仍可保存在 `fabric_messages` 明文列；跨 Node Link/same-Group sealed payload 存在 `relay_v2_message_payloads` 密文 BLOB，同 Node 同 Group sealed payload 存在 Node-local crypto ledger/inbox。sealed `cicada_receive` 只查询 Node inbox 可见表，且读取只读，不执行消费确认或 crash recovery。不能把旧路径的明文事实推广到已密封消息，也不能把新密文路径推广到仍未 sealed-capable 的旧 Session 或尚未实现的广播。

## 运行证据边界

本段所列 Docker Go 1.22 定向 Store、Hub HTTP、fake full-chain、Node inbox/pagination 与整仓回归均按各自记录通过。真实 Codex `TestMCPSealedSameNodeGroupAskReplyNative` 修复版退出码 0，验证同一 Node 上两个原生 Thread 的 ASK/REPLY、原生 ID 与上下文连续性；它由测试驱动显式绑定 Session 并调用受控 `exec resume`。另有 2026-09-25 `TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative` 退出码 0、耗时 228.02 秒，在同机两个逻辑 Node、两个 owner 的真实 Thread 中完成 sealed Link Ask/Reply，A/B 原 ID 保持、Hub 不见正文且 Control business call 为 0。两项原生测试都不证明无人值守 cold wake 或双物理机。双物理机、真实 native broadcast 与完整设备级恢复仍未通过验收；Android 正向 Group Grant 已另行通过单 Owner 固定镜像验收，公网 HTTPS 仍未运行。Node 子树的离线备份/隔离恢复已由本文顶部证据覆盖，v2-B 整体保持 **PARTIAL**。完整过程与限制见[原生验收记录](architecture-v2-native-validation.md)。

Android Client v1 的目标与当前接口见 [Client↔Hub 契约](android-client-hub-contract.md) 及 [OpenAPI](client-hub-v1.openapi.yaml)。Hub 现有独立 Control PQ 公钥、owner 签名设备登记、加密 RPC、状态快照/部分差异游标、持久异步 Intent/进度、审批、设备列出/撤销、Node 设备码绑定/撤销与同 owner 拓扑读写；`TestClientV2OwnerGrantAndEncryptedSnapshotAcrossRestart` 在 HTTP Handler 中使用两端独立密钥完成设备授权、加密快照、Intent、设备和 Node 管理、拓扑修改、精确重试及重启缓存，伪造设备与旧 bearer 越权被拒。完整状态事件推送和跨用户 Thread 连线尚无完整可用接口，因此总体 capability 仍是 `partial`。`/v1` 管理 bearer 与旧 PWA 不满足 NIST PQ Client↔Control E2EE，不能作为 Android 正式版通道。独立 Android 仓库由另一开发者负责；本仓库不修改其文件。

## 2026-09-23 历史快照：当前增量与版本差异

- Client↔Hub 合同固定为 `/v2/client/capabilities`、`/identity`、`/devices/enroll` 和 `/rpc`；当前为管家 owner 公布 25 个加密 RPC operation，为外部 owner 公布 18 个受限 operation，包括本人归属的状态/差异与拓扑，但不含管家的 Goal、Intent 或 Approval。`link.list` 提供双方可续读、owner 作用域的提案元数据，`status_events=false`、`external_thread_links=false`。`goal.lifecycle` 仅对未领取远端队列任务提供带版本的暂停/恢复，不能声称停止了运行中的原生 Worker；`status.changes` 的审批和 Intent 状态元数据也只按归属显示，仍非完整推送。[最小互操作步骤](client-hub-interop-v1.md) 与 OpenAPI/线协议一致；独立 Android 互操作未运行。
- v23 后，`TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 经真实 PQ Client RPC 绑定 Node、提交定向 Goal、检查持久 Worker，再以同一 Node bearer 调用 v2 heartbeat/jobs/claim、精确 Workspace 快照下载/上传及 result。Node bearer 仍不能调用旧 `/v1/machines` 管理 API，旧 Control bearer 也不能调用 Node Relay。旧 ownerless 任务不自动迁移为可领取工作；测试没有执行真实 Codex 或验证原生唤醒。
- 截至 2026-09-23 显式 Link 跨 Node 切片，Hub 的 Node-only Link 证据读取只向当前连线一侧返回 SessionBinding/key 清单和双侧 v2 Owner 签名。Node 使用独立预置的 Owner 公钥/指纹验证后 pin；旧跨组 pin/read API fail closed。`SEALED_V1` SEND/ASK/REPLY 在入队、领取和目标注入前重查 Link/Grant/密钥/绑定，双方 Node 已接入本地解密、密文 inbox、恢复 journal、原生 queue 与分层回执。该历史切片只覆盖跨 Node 单收件人；同 Node 同 Group 本地 sealed 路径由后续 2026-09-24 增量另行验收。
- 未被调用的 Control peer 转发方法和旧 `/v1/communication-links` manager-bearer HTTP 入口已删除；同 owner Link 管理走加密 Client `topology.apply`，历史表及旧 Grant 仍保留。Hub schema 至 v26；Node crypto-state 增量至 v5，旧 pin 保留但不能自动获得跨组授权。

- `serve --fabric-only` 从已有 trust identity/数据库启动，不构造 Control；`machine agent --relay-only` 仅使用已签发的 Node credential 调用 v2 Relay。
- MCP Join 不再向模型返回 session token，缓存按 API origin、harness、native session 和 Node 隔离；恢复前校验服务端绑定，失效凭据不自动重入。CLI `fabric v2` 同样使用 Session 授权，无全局默认 token 文件。
- Node 注入包含由 Relay 提供的 request/source/receiver 信息，正文保持外部信任等级；queue 进程启动后的失败进入 `INJECTION_UNCERTAIN`，有进程故障与重启不重复注入测试。
- 版本化迁移已到 v26：v11 精确回填旧 Endpoint-Group 关系，v12 添加父组，v13 增加非路由连线提案，v14 增加 Endpoint 公钥候选，v15/v16 保存用户批准公钥与双侧 Link Grant，v17 隔离 Relay 密文 BLOB，v18 保存 Hub ID、Client 设备/重放/密文响应，v19 增加 Client Intent 异步接受/恢复，v20 增加 Node 设备码与 owner 绑定，v21 增加状态快照差异索引，v22 增加两端 Endpoint key 清单绑定的签署记录，v23 为新 Client/Goal/Node 工作记录 owner 而不回填旧行，v24 给 Goal 增加生命周期版本，v25 在迁移事务内保留旧状态差异记录和游标并扩展审批/Intent 类型约束，v26 增加一次性外部 Thread 邀请状态表。新迁移不回填、重写或轮换旧 Endpoint、Contact、私钥、ratchet/replay 状态。多组原生验收与合成 Hub StateDir backup/verify/restore 已运行；Node-local crypto-state 和密钥不在此 Hub 备份内。真实生产/Node 备份恢复及恢复后计数对账未运行。
- Endpoint attestation 的 ML-DSA-65 自签名覆盖 Endpoint/Principal/Node/SessionBinding ID+epoch；它只证明 key possession 与候选所声明的当前绑定。Join Session credential 的根授权仍来自配置管理 bearer；`CICADA_API_TOKEN` 未配置或 bearer 范围过宽时，它们都不能建立独立用户 bootstrap trust，候选不得视作 owner-approved 或 safe-to-encrypt。
- Node-local `CryptoState` API 存储 outbound sequence、原样密文和 inbound replay digest/sequence；本地 peer pin 按 Endpoint/Group/连线范围及独立核验指纹保存。Node DB schema v1/v2 增量升 v5；v3 起入站密文和 replay 新记录原子提交，v4/v5 扩展跨组 pin 清单与独立 Owner key trust，旧 replay-only 记录不可被误判为可恢复的收件。跨组 Seal/Open 已接入显式 Link SEND 的 Fabric transport 与 Node 原生注入，重试复用原样密文；普通 pin 不证明用户批准，跨组路径逐次重验双侧 v22 签署和独立 Owner trust。入站记录不能证明模型已消费，`INJECTION_UNCERTAIN` 仍需 Runtime 对账。
- 真实模型在旧架构下完成 G1 与旧 MA→MB→B1 G2。详细身份、请求和控制隔离证据见 [原生验收记录](architecture-v2-native-validation.md)；不能将其标为 v2.1 新 G2。
- 截至 2026-09-23 快照，Node 主动 SSE 事件流在 durable commit 后给目标 Node 无正文 wake hint；连通测试见 `TestRelayNodeOutboundEventStreamWakesAfterDurableAsk` 与 `TestMachineRelayEventStreamUsesOutboundNodeCredentialAndWakeHints`。当时同 Node 仍经过中心 Relay；2026-09-24 新同 Node 同 Group sealed 路径改为本地消息路由，不把这条旧 SSE 观察当作当前事实。
- 前一轮 Hub v26 工作树在 Docker Go 1.22 中通过 `go test -count=1 ./...` 与 `go vet ./...`；`TestExternalThreadInvite*`、`TestExternalClientDeviceCanOnlyUseFederatedOperations`、`TestEncryptedExternalThreadInvitationUsesTwoOwnerSessionsAndStaysNonRoutable`、`TestOwnerKeyLocalBootstrapRequiresExactOutOfBandKeyID` 和 Fabric owner/trust-domain Join 定向 `-race` 通过。`TestClientDockerHubSmoke` 用本轮镜像及隔离 StateDir 在真实 TCP 上通过，包含两个独立 owner 设备会话和 guest 管家状态拒绝。此前 v25 Goal 生命周期/状态差异的定向 race 仍是历史证据。完整 `-race ./...`、Android 客户端互操作、真实 guest Codex Join/跨用户路由和生产部署验收仍未运行。

本轮上述三包 `-race` 的统一进程退出码为 0；其余包的完整 race 验收仍未运行。

## 2026-09-23 显式 Link SEND 增量验证

- Docker Go 1.22：`go test -count=1 ./... && go vet ./...` 退出码 0。`go test -race -count=1 ./cmd/cicada ./internal/fabric -run 'Test(MCPSealedSendAcrossTwoLogicalNodesWithoutControlBusiness|MachineSealedReceive|LocalSealedSend|DirectoryIsGroupScopedAndNeverGuesses)'` 退出码 0；完整 `-race ./...` 未运行。
- `TestMCPSealedSendAcrossTwoLogicalNodesWithoutControlBusiness` 使用真实 Store/Fabric、源/目标两个独立 Node 状态目录、真实 Unix 本地桥和 fake Codex queue；MCP→Node Seal→Hub 原样密文→目标 Node Open→精确 `--thread` 与分层回执成功。测试未构造 Control 业务模块，也未使用真实远端机器或真实 Codex 模型。
- `TestMachineSealedReceive*` 覆盖注入前撤权、陈旧 attempt、重复投递、journal 与 inbox 之间的崩溃恢复、非零 native queue 退出后的 `INJECTION_UNCERTAIN` 不重投。`TestLocalSealedSend*` 覆盖伪造身份、错误原生 Thread、缺双侧授权、凭据分离及相同操作的原样密文重试；`TestDirectoryIsGroupScopedAndNeverGuesses` 验证只有本人 `whoami` 返回原生 Session ID。
- 截至本 2026-09-23 显式 Link SEND 增量快照，真实双用户原生 Codex ASK/REPLY、双物理 Node、同 Node 零 Hub Relay、广播、Node 一致点备份和 PQ-only Node↔Hub TLS 均未运行或未实现；这些是该快照的历史边界，不覆盖下文 2026-09-24 的同 Node fake queue 验收。

## 2026-09-24 密文 ASK/REPLY 增量

- `internal/nodekeys` 的 owner-granted Seal/Open 覆盖 `REQUEST` 和反向 `REPLY`，核验 Link 的 `ask+reply` 动作、scope、`request_id`、`reply_to`、签名身份和路由；重试使用 Node 本地原样密文。`internal/store` 在既有 v17 Relay 表中原子保存 ASK/REPLY 密文、请求状态、outbox/inbox、回执和限额，无新增 schema migration；原始通用 sealed enqueue 无法绕过请求关联。
- 当前 Node 凭据保护的 Hub HTTP 提供 `sealed/ask|reply|claim` 及请求 status/cancel；MCP 的显式 Link ASK/REPLY 经 owner-only Unix bridge，以当前真实 Codex Session 和 `CicadaSession` 重新校验身份。模型不能填写 sender、role、`reply_to` 或替换回复目标；Node 从原 Request 和当前签署清单派生。ASK 的默认期限由持久 MCP operation 创建时间和 Link 期限确定，重复提交不会改变期限；失败响应可按同一 operation 重试。status/cancel 也通过本机桥，不暴露 Node 凭据。
- 两端 Node 将密文先持久存入本机 crypto inbox，再解密到目标原生 Session 的受控队列；注入前重查当前 Link/Grant/binding/attempt，重复投递不二次 queue。已取消或超过截止时间的回复记录为 `LATE_RESULT`，保留密文而不自动唤醒原 Thread；原生模型消费仍不可确定。
- `TestMCPSealedAskReplyAcrossTwoLogicalNodesWithoutControlBusiness` 用两个 owner/Node、真实 Store/Fabric、Unix bridge、MCP、Hub HTTP 与 fake Codex 跑通 A→B ASK 和 B→A 关联 REPLY；双方 queue 参数保持原 native ID，Hub 未接收明文，未构造 Control 业务。定向 `-race` 通过。Store/Node/桥接定向测试覆盖错误 Node/会话/Link、动作缺失、scope/关联篡改、限额、取消与迟到、撤权、离线/重复和恢复。此处不构成真实 Codex 模型或双物理机验收。
- 截至该跨 Node 显式 Link ASK/REPLY 切片的历史快照，Group 广播、真实双用户原生 Codex 和 PQ-only Node↔Hub TLS 仍未实现或未验证；同 Node 本地路径当时未纳入该切片，后续由本文顶部的 2026-09-24 同 Node 增量以 fake queue 全链与故障测试覆盖。再后的 same-Group cross-Node sealed route 已接入代码与 Store/Hub 定向测试，状态见本文顶部；这条历史快照不代表当前 route 状态。真实 Codex 双端消费、广播仍未验收；完整 `-race ./...` 未运行。
