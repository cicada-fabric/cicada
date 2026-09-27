# Architecture v2.1 状态矩阵

快照日期：2026-09-23。`dev` 从 `main` 的 `f4fa7eb8d948ae09834be0b5ec2695205cba536f` 开发；目标规格为根目录 Architecture v2.1。本文区分历史 v2 实现证据与新的退出条件。旧版 MA→MB 演示通过不等于新跨组直达已实现。

状态约定：**A／完成** = 代码和针对性测试覆盖该限定范围；**B／部分** = 有实现但缺完整验收或只覆盖 fake/in-process/native 子集；**C／未完成** = 尚未实现或缺少验收证据；明确缺少外部条件才标 `BLOCKED`。当前 Hub schema v22、Node crypto DB v5。Docker Go 1.22 全包 `go test -count=1 ./...` 已通过；`go vet ./...`、独立容器 Hub TCP 冒烟和完整 `-race ./...` 需要在本轮全部改动落定后分别记录。

## 阶段结论

| 阶段 | 状态 | 已有事实 | 仍缺什么 |
|---|---|---|---|
| v2-A 身份、Group、显式 Join、统一 Guard | **B（相对 v2.1）** | Principal/Membership/Endpoint/SessionBinding、显式 Join、旧 API guard；v11 多组关系及同机双容器真实 Codex 多组 Ask/Reply；v12 版本化 Group 父子关系、防环、不继承授权。 | 嵌套 Group 的面板编辑、跨用户边界仍未实现。 |
| v2-B Relay、Node、原生异步恢复 | **B** | 持久 Relay/Node、精确 queue、Control-free test、同机双逻辑 Node 真实 MCP 闭环；Node 主动 SSE wake 已有针对性测试。 | 同 Node 仍经 Hub Relay；PQ 端点密文与双物理机、无人值守前台安全仍缺。 |
| v2-C 通信图与跨组/跨用户 | **C（新目标）** | 旧版 GroupGateway/MA→MB 状态和真实演示保留为历史证据；v13 有不可路由的同 owner CommunicationLink 提案/撤销；v14 提供 Group-scoped read 的 `CANDIDATE` 公钥记录；v15/v16 加入离线 owner key 和旧合同 Grant；v22 增加绑定两端候选公钥的签署清单及加密 Client RPC。 | 缺远程可信设备绑定与跨 owner 邀请、可信双端 Endpoint pin、激活 Guard、端点密文、直达 B1、双用户同一 Hub、可选 Monitor、Group 广播。已有 Grant 状态不建立消息路由。 |
| v2-D Shared Task/Lease | **B** | Shared Task claim/结果验收、ResourceLease 权威冲突键、结构化 handoff、副作用 ledger 与 scoped Artifact v6–v10 已实现并测试。 | GPU/workspace 资源仍 advisory；真实执行器强制 fencing/外部副作用对账不完整。 |
| v2-E 产品化/互操作 | **B** | Android↔Hub PQ 设备授权/RPC、状态快照、部分差异游标、持久异步 Intent、加密拓扑读写与设备撤销有服务端测试；Node 设备码配对、Relay owner 绑定及心跳已有服务端闭环；仍保留只读 PWA 管理视图。 | 手机侧由独立仓库负责；完整状态推送、Android 独立互操作和可信跨用户 Thread 连线未完成或验收。 |

## 逐项状态

| 编号 | 状态 | 证据 | 边界/下一步 |
|---|---|---|---|
| A-01 旧 v1 guard | **A** | `control/fabric.go` `legacyEndpointIdentity`/`requireLegacyEndpoint`；`store/fabric.go` legacy read/write filters；`TestLegacyFabricRejectsReadyV2EndpointsAndRelayMessages`、`TestLegacyFabricPeerRoutesAreRemoved`、`TestManagementEndpointReadProjectionReplacesLegacyPath`。 | 公开 `/v1/endpoints` 读写路由均已移除；内置面板使用 `/v2/management/endpoints` 只读投影。历史内部方法与表待迁移对账。 |
| A-02 四层身份 | **A** | `store/fabric_v2.go` 表/Store API；`TestFabricV2IdentityBindingAndFencing`。 | role binding 是管理面 CAS；Join 不自动授予 worker/monitor。 |
| A-03 显式 Join | **A** | `/v2/fabric/join`、`fabric.Service.Join`；MCP `cicada_join`；`TestCicadaMCPToolsRequireExplicitJoin`、`TestExplicitJoinIsIdempotentAndRotatesBindingCredential`。 | `ensureEndpoint` 明确返回 disabled；未 Join 不可调用其他 MCP 工具。 |
| A-04 v2 actor/Group Directory | **A** | `Authenticate/Authorize/List/Resolve`；`TestDirectoryIsGroupScopedAndNeverGuesses`、`TestActorForgeryAndRevocationFailClosed`、server forged sender/group negative test。 | 旧 v1 仍独立存在，需继续维持所有入口回归。 |
| B-01 Relay durable state | **A** | `relay_v2_message_security`、`requests`、`outbox`、`inbox`、`delivery_attempts`、`receipts`、`consumer_cursors`；`relay_v2_test.go` 幂等、单 claim、cursor/restart、伪造 ACK。 | 独立网络 relay/吞吐/压力未测。 |
| B-02 cancel/expiry/late | **A** | `TestRelayV2ExpiryCancelAndLateReplyAreAtomic`；request events 保存 `LATE_RESULT`。 | native cancel/late business result 仍需真实 runtime 证据。 |
| B-03 Node receipt/fencing | **A** | `nodeinbox/inbox.go`、`node_owner_bindings_v2`；machine relay/server tests；Node token 必须获 owner Client 设备码确认并绑定精确 node，receipt 校验 endpoint/digest/attempt/epoch/lease 且禁止状态回退；Codex 子进程不继承管理/Node token。 | runtime 消费没有可验证 API；最终只能标 unknown。 |
| B-04 Control-free path | **A** | `internal/fabric` 无 Control 依赖；`TestFabricV2WorksWithoutControlBusinessService`、`TestControlBusinessDisabledPeerRPC`。 | 测试是同进程构造；没有独立服务宕机/宿主机隔离。 |
| B-05 native continuity/queue | **B** | 官方 `codex-cli 0.155.1`；G1 A `01a0c984-26a2-7d72-9e69-d430b01d00c3` / `ep_0c39a68ac103d137`，B `01a0c984-5039-7911-96bd-60c4902755f3` / `ep_af7d820560560364`；真实模型 MCP Join/Ask/Reply 和两端原生 context 连续。 | 同一主机的两个逻辑 Node；尚不是新同 Node 零 Hub Relay 或双物理机。 |
| C-01 GroupGateway records | **A** | `gateway_v2.go` 七类 `gateway_v2_*` 表；`gateway_v2_test.go` card/contract/mailbox/request/result、scope/deadline、digest、late/cancel。 | “A”只指同库状态/合同实现。 |
| C-02 representative owner epoch | **A** | `ClaimRepresentative/TakeoverRepresentative`；并发单 winner 和 stale owner 拒绝测试。 | 没有跨 Control owner lease transport。 |
| C-03 provenance/result | **A** | `TestGatewayV2ContractScopeDeadlineAndProvenance`、`TestMonitorMediatedCrossGroupCollaboration` 保留 producer principal/endpoint/group、evidence/provenance refs。 | 未验证真实外部 producer、签名证据或 Artifact 权限。 |
| C-04 新跨组/跨用户直连 | **C** | 当前 `fabric/gateway.go` 仍使用旧同库代表路径；真实旧 G2 见 native-validation。v13 提案、v14 候选及 v22 密钥绑定 Grant 均不打开现有跨组明文 Ask 或新消息路由。 | 可信远程双端设备身份/pin、外部 Card、加密后的路由激活、双用户同 Hub、可选 Monitor 与广播无实现。 |
| D-01 Shared Task/Lease | **B** | `shared_task_v2.go`、`resource_lease_v2.go`、`shared_task_handoff_v2.go`、`shared_task_side_effect_v2.go` 与测试。 | 外部 GPU/workspace 强制 fencing、真实 SideEffect 执行对账未完成。 |
| E-01 产品化/互操作 | **B** | Hub v22 的 Client PQ 入口支持 owner 签署设备注册、状态快照/部分差异游标、持久异步 Intent/进度、审批、设备与 Node 绑定管理、Group/Endpoint/角色及同 owner 连线提案的拓扑读写；`GET /v2/client/capabilities` 仍逐项声明 `partial`。 | 完整状态推送、可路由双端连线、广播与跨用户流程仍缺；Android 真实接入尚未验收。 |
| M-01 additive schema | **A（合成迁移测试）** | v14 增加 `endpoint_key_candidates_v2`，公开候选及其证明；定义为 additive，不更新旧 Endpoint、Contact、密钥、ratchet/replay 行。 | v14 合成旧库重跑/中断/并发打开和旧状态保留测试通过；真实生产库未演练。 |
| M-02 legacy pending | **A** | 旧 Endpoint 默认 `MIGRATION_PENDING_GROUP`；无明确映射不创建 Group；`TestFabricV2LegacyEndpointMigrationIsAdditiveAndRepeatable`。 | 需生产前显式 mapping/quarantine 操作和审计导出。 |
| M-03 backup/rollback | **B** | `cicada migration inventory/backup/verify/restore` 与合成 Hub StateDir 保存 Contact/session/replay 数据的既有演练。 | 未对真实生产 StateDir 演练；Node 私钥和 `node-crypto-state.sqlite` 未包含在 Hub 备份中。恢复旧计数后是否可重新联网需显式 fencing/reconciliation，不能声称任意 rollback 安全。 |
| M-04 v14 key candidates / Node crypto-state | **B（部分接入）** | Hub 按 Group 授权读取 `CANDIDATE`；MCP 显式工具从已 Join 的原生 Session 发布 Node 本地公钥，核对绑定并拒绝密钥冲突。Node-local API 有持久序号、不可变密文 outbox、scoped pin；Node DB v5 保留入站密文与 replay 同事务保存，并新增跨组 pin 清单字段与独立 Owner key trust，旧 replay-only 行显式要求对账。新 `SealOutboundEndpointMessage` / `OpenInboundEndpointMessage` 将精确 pin、端点密封/解密与 Node 持久化组合，并在重启后复用原密文；定向 `-race` 通过。 | 跨组 pin 已能核验独立可信 Owner 公钥与双侧 v22 Grant；调用方仍需生产路由 Guard 和 native delivery；入站持久化不证明模型消费，也不解决 `INJECTION_UNCERTAIN`。Node 备份/回滚未实现。 |
| M-05 v15/v16/v22 owner approval | **B（密码学与本地状态）** | v15 登记用户独立持有的 ML-KEM/ML-DSA 公钥；v16 合同 Grant 保留为不绑定 Endpoint key 的历史记录；v22 新表独立保存对当前合同、两端原生绑定与两端公钥候选摘要的双侧签署，旧 v16 Grant 报 `LEGACY_KEY_UNBOUND`。Client 加密 RPC 提供清单读取、签署提交和状态读取。Grant 不激活路由。 | 单 owner Client 入口仍不提供跨用户可信邀请与双侧身份建立、外部 Endpoint 邀请或加密 Fabric 路由；跨 owner 提案仍拒绝。Hub 本地文件系统管理员是临时 owner-key bootstrap 的信任根，不能把管理 bearer 视为用户批准。 |
| M-06 v17 sealed Relay Store | **B（Store 边界）** | 独立 `relay_v2_message_payloads` BLOB/mode 迁移；单收件人 `send` 的专用 enqueue/get/claim、旧明文读接口隔离、幂等/ACK/重启/撤权测试；旧 Node 明文注入路径拒绝 `SEALED_V1`；Docker 全包测试与 vet 通过。 | 没有 Fabric/HTTP/MCP 入口、可信公钥 pin、Node 解密或原生密文 E2E；普通 peer 消息仍走明文。 |
| M-07 v18 Client 设备/重放 | **B（单 owner Hub）** | 持久 Hub ID、owner 签名设备 Grant、设备撤销/epoch、请求序号/operation ID、精确重试缓存与中断 UNCERTAIN；v18 迁移回滚/重跑及旧记录保留通过。 | 还缺双用户独立状态分区、首次远程可信引导、Android 设备码 UX 和完整备份/换机演练。 |
| E-02 Client PQ HTTP 入口 | **B（部分可调用）** | `internal/clientwire` 和 `/v2/client/{identity,devices/enroll,rpc}` 使用 ML-KEM/ML-DSA/AES-GCM，AAD 绑定 Hub/owner/device/epoch/sequence/operation/方向/密钥版本。v19 Intent 持久异步派发；v20 Node 设备码经 Client 加密确认；v21 owner-bound 部分状态差异游标。Handler 的伪造、重启、精确重试和管理动作测试通过。 | 尚缺独立 Android 互操作、完整状态推送、跨用户连线；`capabilities.status=partial`。 |

离线公钥引导的可复现命令与边界见 [owner approval bootstrap](owner-approval-bootstrap.md)。

## V01–V64 验收快照

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
| V22 | PARTIAL | Ask admission quota 已实现；Group 广播和 fan-out 压力/背压尚未实现。 |
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
| V35 | PARTIAL | 当前无连线的 stable ID 异组直连被拒；v13 提案也不能开通路由；授权后的直接连线尚未实现。 |
| V36 | NOT_RUN（新目标） | 旧同库 MA→MB 测试和真实旧 G2 不能替代 v2.1 直达路径或单 Hub 跨用户验收。 |
| V37 | PASS | `ACCEPTED`、`IN_PROGRESS`、`RESULT_ACCEPTED`、`CLOSED` 分离。 |
| V38 | PARTIAL | 旧代表 mailbox 离线排队已测；新普通连线不依赖 Monitor 的路径未实现。 |
| V39 | PARTIAL | 旧代表 owner/epoch CAS 已测；新可选审阅 owner 尚未实现。 |
| V40 | PARTIAL | 旧结果保留 producer/evidence/provenance；新直达和广播来源未测。 |
| V41 | PARTIAL | 旧合同 scope/deadline 已测；v13 连线提案保存动作、数据范围、期限、版本快照和摘要，但还不能授权通信。 |
| V42 | PARTIAL | 既有 Contact revoke/E2EE 状态保留；v13 提案可按预期版本撤销，但跨用户已激活连线、广播待投递项与端点密钥撤销尚未实现。 |
| V43–V52 | PARTIAL | v7–v10 Shared Task/Lease/Handoff/SideEffect 与 v6 scoped Artifact 已有 Store/HTTP 测试；真实 GPU/workspace 执行器强制、外部副作用和完整恢复矩阵未通过。 |
| V53 | PASS | Actor 来自 Session credential；未知 sender/group/role 字段和错误 scheme 被拒。 |
| V54 | PARTIAL | peer body 不会创建 Approval，HTTP 严格字段拒绝伪造；缺专门的正文 prompt-injection 验收。 |
| V55 | PARTIAL | Federation 保留 actor/provenance；尚无 Guard 对真实恶意 Monitor 指令的执行入口演练。 |
| V56 | PARTIAL | membership revoke 阻止 Fabric read/write；跨组 Artifact/search/export 统一 guard 尚未实现。 |
| V57 | PARTIAL | 既有 Contact E2EE 重放/篡改测试通过且未降级；Endpoint context-bound ML-KEM/ML-DSA/AES-GCM 封装、ML-DSA-65 attestation、v14 Group-scoped `CANDIDATE` registry 与 Node 本地 scoped pin API 已实现。Node-local seal/open API 按 pin 和调用方可信 route 完成加解密及持久化；v22 双侧密钥绑定 Grant 已接入 Node-local 独立可信 pin verifier，但尚未接入生产路由 Guard。尚无加密 Fabric route 或 native E2E，Hub 仍能看到普通 peer 明文。 |
| V58 | PARTIAL | 合成 Hub StateDir 的 backup/verify/restore 与 Contact/session/replay counter 对照通过；Node `CryptoState` API 持久化 sequence/outbox，并在 v3 起把新入站密文与 replay 原子保存；v5 新增独立 Owner key trust；旧 replay-only 行需对账。尚未接入 native delivery，也不在 Hub 备份。完整 Node private-key/crypto-state backup、rollback fencing 和恢复后计数对账未验收；Node crypto-state 定向测试和 `-race` 通过。 |
| V59 | PARTIAL | secret scan、token-only-hash、0600 token files、child env filtering 已验证；未覆盖生产 crash dump。 |
| V60 | PASS（事务测试） | 版本化迁移账本、中断回滚/重跑、并发打开与旧记录保留测试通过；真实掉电/备份恢复未验收。 |
| V61 | PARTIAL | READY v2 Endpoint/message 不能经旧 Directory/message/machine API 绕过；旧公开 `/v1/fabric/*`、Thread queue/message、Contact peer/federation ingress、Contact session 查询/轮换、`/v1/endpoints` 和管理 bearer `/v1/communication-links` HTTP 路由已退役。旧 Control→Contact Relay 发送器及未被服务入口调用的 Control peer 转发方法也已删除；内置面板已切到 `/v2/management/endpoints`，历史 Contact ratchet 方法与数据库仍待迁移对账。 |
| V62 | PARTIAL | 授权每次查权威 SQLite、无扩权 cache；未注入权威服务故障黑盒测试。 |
| V63 | PASS | 缺少双物理机/自主 MCP/迁移条件均明确标记，不计为通过。 |
| V64 | NOT_RUN | 未运行压力测试，也未声明真实多 Agent 容量。 |
| V65–V70 | PARTIAL | 同 Thread 多 Group 服务/HTTP/MCP scope、独立撤权和同机双容器原生 Ask/Reply 有证据；v12 Group 父子关系管理 API 防环/版本/不继承授权有测试。V66 的面板拖拽未做；同 Node 零 Hub Relay、双用户单 Hub、授权跨组 scope 解析未实现。 |
| V71 | PARTIAL | Node 主动 SSE ready/wake 和 durable claim HTTP 测试通过；Docker Hub/Node 断流/重连组合尚未跑。 |
| V72–V73 | NOT_RUN | Group Thread 广播、用户经 Monitor 广播、逐接收者加密与伪造用户批准负例均未实现。 |

## G1–G5 演示状态

| 演示 | 状态 | 证据边界 |
|---|---|---|
| G1 组内原生问答 | PASS（同机双容器） | 真实模型 MCP Join/Ask/Reply；另有两组 Membership 同 native ID/Endpoint 的第二组 Ask/Reply；A 恢复旧上下文并收到结果。详见 native-validation。不是无人值守 Adopt/前台并发验证。 |
| G2 多组/跨组直达 | NOT_RUN（新目标） | 旧 MA→MB→B1 原生 G2 在同机逻辑 Node 上 PASS，见 native-validation；不计入新版 direct-link G2。 |
| G3 Control 隔离 | PARTIAL（新目标） | 旧 G1/G2 在 `serve --fabric-only` 中成功、管理 API 503；新版直达/广播仍未实现。 |
| G4 重启/失联/重复 | PARTIAL | Store/Node fake fault、restart、duplicate、uncertain 窗口通过；真实逐窗口杀进程未跑。 |
| G5 权限/数据边界 | PARTIAL | unjoined、伪造身份、旧跨组拒绝、旧 API、撤权、错误 ACK 和 scoped Artifact 子集有测试；新连线/多组/广播/PQ 的拒绝矩阵未跑。 |

## 已实现表面

现有 v2 HTTP 路由在 `server/fabric_v2.go` 和 `server/relay_node_v2.go`：`join/whoami/members/find/heartbeat/leave/leave-group/send/ask/reply/receive/request status/cancel/representative claim/federate/federation result` 与 Node `events/heartbeat/claim/receipts`。MCP `mcp.go` 只在 `cicada_join` 后使用 `CicadaSession`，支持 `cicada_use_group` 和 `cicada_leave_group`；选定的 `Cicada-Group-Scope` 仍由服务端校验双重 Membership。Join enrollment 使用管理 bearer，模型提交的 `principal_id`、sender、role、approval 字段不作为身份依据。Link 的同 owner 提案/撤销经加密 Client `topology.apply` 完成；旧 `/v1/communication-links` HTTP 路由已删除。提案和双侧 Grant 都不参与 Fabric 路由。v14 新增 `/v2/fabric/endpoint-keys` POST 登记当前绑定的自签名公钥候选，以及 GET 读取对方候选；读取限于当前 Group 可解析的 Endpoint。已绑定 Node 可在 `/v2/relay/nodes/{node_id}/links/{link_id}/authorization` 领取双侧当前公钥签名证据，Hub 在单事务中重查凭据、owner、Link、两侧 Grant 和绑定，且核对所选 Hub；这只是独立 Node 信任校验的输入，不能激活密文路由。Group broadcast 与活动端点 PQ E2EE 仍无 API。

v2 Relay 的 `Receive` 是带 opaque cursor 的查看；Node 的 claim/receipt 才改变投递 attempt。正文仍由 `fabric_messages` 唯一保存，Relay/Gateway 状态行保存 digest、引用、路由和 provenance；本状态文档不记录 secret 或完整 payload。

## 运行证据边界

v22 的 Docker Go 1.22 全包 `go test -count=1 ./...`、`go vet ./...` 通过；本轮 v22 的 `TestClientDockerHubSmoke` 对一次性独立 Docker Hub 容器走真实 TCP，验证加密 Client 请求、精确重试、Node 设备码确认/心跳和部分状态游标。完整 `-race ./...` 与真实 Android 互操作本轮未运行；较早 v17 密文 Store 和 v16 `e2ee`/`store`/CLI 的定向 `-race` 不能替代。原生旧 G1/G2 在同一主机两个隔离逻辑 Node 中成功，Fabric-only server 未构造 Control，模型自主 MCP reply 与旧 MA/MB 工具调用有证据。Node crypto-state 不是加密持久 Fabric outbox/Hub mailbox 的端到端集成；离线 Link Grant 也不是可信远程设备批准或 Endpoint pin，尚无密文 Node 投递。双物理机、新同 Node 零中心 Relay、新直接跨组/跨用户、Group broadcast、Hub-blind PQ E2EE 均未通过。合成 Hub 备份恢复与 v2-D/只读 v2-E 子集已实现；不能写成完整 Node 或生产恢复。

Android Client v1 的目标与当前接口见 [Client↔Hub 契约](android-client-hub-contract.md) 及 [OpenAPI](client-hub-v1.openapi.yaml)。Hub 现有独立 Control PQ 公钥、owner 签名设备登记、加密 RPC、状态快照/部分差异游标、持久异步 Intent/进度、审批、设备列出/撤销、Node 设备码绑定/撤销与同 owner 拓扑读写；`TestClientV2OwnerGrantAndEncryptedSnapshotAcrossRestart` 在 HTTP Handler 中使用两端独立密钥完成设备授权、加密快照、Intent、设备和 Node 管理、拓扑修改、精确重试及重启缓存，伪造设备与旧 bearer 越权被拒。完整状态事件推送和跨用户 Thread 连线尚无完整可用接口，因此总体 capability 仍是 `partial`。`/v1` 管理 bearer 与旧 PWA 不满足 NIST PQ Client↔Control E2EE，不能作为 Android 正式版通道。独立 Android 仓库由另一开发者负责；本仓库不修改其文件。

## 2026-09-23 当前增量与版本差异

- Client↔Hub 合同固定为 `/v2/client/capabilities`、`/identity`、`/devices/enroll` 和 `/rpc`；当前公布 19 个已实现的加密 RPC operation，`status_events=false`、`external_thread_links=false`。新增 [最小互操作步骤](client-hub-interop-v1.md) 与 OpenAPI/线协议一致性核查；这仍是服务端部分合同，独立 Android 互操作未运行。
- `TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 经真实 PQ Client RPC 绑定 Node、提交定向 Goal、检查持久 Worker，再用单独的旧 Control bearer 轮询/领取。该测试明确证明 Node Relay bearer 不能调用旧 Worker API；Node 设备码绑定本身尚不能让 Node 领取 Worker 任务。旧 Worker API 当前没有 owner 归属列，必须先完成 owner 归属迁移与原子 Guard，才可统一为绑定 Node credential。测试没有执行 Codex 或验证原生唤醒。
- Hub 新增绑定 Node 专用的 Link 双侧公开授权证据读取；只对当前 Link 的一侧 Node 返回当前 SessionBinding/key 清单及两侧 v2 owner 签名。Node-local verifier 仅在独立预置的 Owner 公钥/指纹、完整合同和双侧签名均通过后持久 pin；旧跨组 pin/read API fail closed。调用者传入的旧 Bundle 本身不能证明 Hub 此刻仍授权，生产接入必须每次从认证的当前 Store/Node 路径读取并重验 Guard，或加入单调撤销证据。该证据与 pin 均不激活 `PROPOSED` Link，也没有跨组密文生产投递。
- 未被调用的 Control peer 转发方法和旧 `/v1/communication-links` manager-bearer HTTP 入口已删除；同 owner Link 管理走加密 Client `topology.apply`，历史表及旧 Grant 仍保留。Hub schema 不变；Node crypto-state 增量迁移至 v5，旧 pin 保留但不能自动获得跨组授权。

- `serve --fabric-only` 从已有 trust identity/数据库启动，不构造 Control；`machine agent --relay-only` 仅使用已签发的 Node credential 调用 v2 Relay。
- MCP Join 不再向模型返回 session token，缓存按 API origin、harness、native session 和 Node 隔离；恢复前校验服务端绑定，失效凭据不自动重入。CLI `fabric v2` 同样使用 Session 授权，无全局默认 token 文件。
- Node 注入包含由 Relay 提供的 request/source/receiver 信息，正文保持外部信任等级；queue 进程启动后的失败进入 `INJECTION_UNCERTAIN`，有进程故障与重启不重复注入测试。
- 版本化迁移已到 v22：v11 精确回填旧 Endpoint-Group 关系，v12 添加父组，v13 增加非路由连线提案，v14 增加 Endpoint 公钥候选，v15/v16 保存用户批准公钥与双侧 Link Grant，v17 隔离 Relay 密文 BLOB，v18 保存 Hub ID、Client 设备/重放/密文响应，v19 增加 Client Intent 异步接受/恢复，v20 增加 Node 设备码与 owner 绑定，v21 增加状态快照差异索引，v22 增加两端 Endpoint key 清单绑定的签署记录。新迁移不回填、重写或轮换旧 Endpoint、Contact、私钥、ratchet/replay 状态。多组原生验收与合成 Hub StateDir backup/verify/restore 已运行；Node-local crypto-state 和密钥不在此 Hub 备份内。真实生产/Node 备份恢复及恢复后计数对账未运行。
- Endpoint attestation 的 ML-DSA-65 自签名覆盖 Endpoint/Principal/Node/SessionBinding ID+epoch；它只证明 key possession 与候选所声明的当前绑定。Join Session credential 的根授权仍来自配置管理 bearer；`CICADA_API_TOKEN` 未配置或 bearer 范围过宽时，它们都不能建立独立用户 bootstrap trust，候选不得视作 owner-approved 或 safe-to-encrypt。
- Node-local `CryptoState` API 存储 outbound sequence、原样密文和 inbound replay digest/sequence；本地 peer pin 按 Endpoint/Group/连线范围及独立核验指纹保存。Node DB schema v1/v2 增量升 v5；v3 起入站密文和 replay 新记录原子提交，v4/v5 扩展跨组 pin 清单与独立 Owner key trust，旧 replay-only 记录不可被误判为可恢复的收件。Node-local seal/open 组合 API 以精确 pin 和调用方可信 route 加解密、先存密文再返回，并支持重启后复用原字节；确定性 operation ID 仅可留在 Node 内。普通 pin 不证明用户批准；新的跨组 pin 必须重验双侧 v22 签署和独立 Owner key trust，但也不赋予路由权。该 API 尚未接入 Fabric transport 和 native injection；入站记录不能证明模型已消费，不能取代 `INJECTION_UNCERTAIN` 对账。
- 真实模型在旧架构下完成 G1 与旧 MA→MB→B1 G2。详细身份、请求和控制隔离证据见 [原生验收记录](architecture-v2-native-validation.md)；不能将其标为 v2.1 新 G2。
- Node 主动 SSE 事件流在 durable commit 后给目标 Node 无正文 wake hint；连通测试见 `TestRelayNodeOutboundEventStreamWakesAfterDurableAsk` 与 `TestMachineRelayEventStreamUsesOutboundNodeCredentialAndWakeHints`。当前同 Node 仍经过中心 Relay，SSE 不使 Hub 失明。
- 此前 Hub v22、Node crypto DB v3 工作树的 `go test -count=1 ./...` 与 `go vet ./...` 在 Docker Go 1.22 中通过；本次 v22 的 `TestClientDockerHubSmoke` 在独立 Docker Hub 上通过；新增 key-bound Link/Hub→Node 定向 `-race` 通过，完整 race 尚未运行。完整 race、Android 客户端互操作和生产部署验收仍未运行。

本轮上述三包 `-race` 的统一进程退出码为 0；其余包的完整 race 验收仍未运行。
