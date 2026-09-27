# Architecture v2.1 当前事实审计

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
