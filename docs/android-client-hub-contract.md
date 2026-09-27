# Android Client ↔ Hub/Control 协作契约

状态：**部分服务端能力已实现；完整 Android↔Hub 契约尚未就绪，也没有独立 Android 互操作验收声明**。当前可调用接口、字段与加密字节规则见 [Client wire v1](client-hub-wire-v1.md)，精简调用顺序与最小请求见 [Android interop v1](client-hub-interop-v1.md)，OpenAPI 见 [draft](client-hub-v1.openapi.yaml)。客户端仓库为 `../CICADA_CLIENT`；本仓库的 `CICADA.md` 是架构依据。首版 Client **只开发 Android**。手机是 Client，Control/Directory/Relay/权威面板状态运行于 Hub，原生 Thread 与 Node Agent 运行于 Node；三种部署职责允许同机。

## 已有接口与能力协商

Hub 现有 `/v1/machines`、`/v1/workers`、`/v1/goals`、`/v1/groups`、`/v1/approvals`、Goal events SSE 等属于旧管理 API。这些接口使用传统管理 bearer，不满足新的 Client↔Control 后量子 E2EE 和设备身份要求；Android 正式版不得直接提交语音转写、审批、拓扑改动或敏感管理读取到它们。旧 `/v1/communication-links` manager-bearer HTTP 路由已退役并返回 `404`；Client Link 提案和撤销只能走加密 `topology.apply`。现有 Goal/Worker 状态可作为后端构建新只读投影的事实源，但不能将 `worker.status` 直接等同于 `goal.status` 或 Node 在线状态。旧 Control 没有完整的 Goal pause/resume 语义。

`GET /v2/client/capabilities` 是无身份的能力探测点，不包含私有状态。Control 模式目前返回 `status=partial`；Fabric-only 模式返回 `status=not_ready`。Android 必须逐项检查 capability 和 `available_rpc_operations`，不能因为旧 bearer API 或某个操作可用就把完整契约视为就绪。

能力端点合同名为 `android-hub-v1-draft`，而 `/v2/client/identity` 的 `contract` 是 `android-hub-v1`。Control 可用时，除 `status_events` 与 `external_thread_links` 外，当前能力旗标为 `true`；`available_rpc_operations` 列出 19 个已实现的加密操作。`status_events` 和 `external_thread_links` 始终为 `false`。HTTP 传输错误使用 `{"error":"..."}`；RPC 业务拒绝则仍是 HTTP 200 的加密响应 `{ok:false,error:"..."}`，其中 `error` 只是自由文本，目前没有稳定 machine-readable code。Android 不得将错误文本当协议枚举。

当前已实现的服务端路由：

| 路由 | 能力与限制 |
|---|---|
| `GET /v2/client/identity` | 返回持久 Hub ID、独立的 Control PQ 公钥和密钥版本。客户端必须通过独立可信渠道固定 Hub ID/公钥；仅下载此响应不构成信任。 |
| `POST /v2/nodes/device-code` | Node 本地生成并保管 bearer，仅提交摘要与 ID/名称；Hub 返回短码和 `/client/device` 相对验证路径。这个路径由独立 Android Client 实现交互，本仓库不托管授权页面。 |
| `POST /v2/client/devices/enroll` | 接受已在 Hub 本地登记的 owner ML-DSA 公钥签署的设备 Grant；绑定精确设备公钥指纹、Hub ID、owner、用途和期限。首次 owner 公钥仍需本地可信引导，**不是**手机点链接输入设备码的最终体验。 |
| `POST /v2/client/rpc` | ML-KEM-768 + ML-DSA-65 + AES-256-GCM 双向封装；Hub 从登记设备记录推导身份和 epoch，事务性序号/operation ID 重放拦截，响应密文缓存。提供 `status.snapshot/changes`、`topology.snapshot/apply`、`devices.list/revoke`、`nodes.preview/confirm/list/revoke`、`approvals.list/decide`、`intent.get/list/status/submit`、`link.key_manifest/key_grants/key_grant`。`intent.submit` 先持久接受并返回 Intent ID，响应缓存后异步派发。Link 密钥签署只记录同 owner 的密钥绑定同意，不激活消息路由。 |

`status.snapshot` 当前只支持**单 owner 独占 Control 数据库**，并显式返回 `scope_mode=single_owner_control_database`；旧 Goal/Worker/Machine 表没有 owner 列，不能把这个投影暴露为多租户安全视图。响应区分 Node、Endpoint/原生 Session、Worker、Goal、Group、Task 的状态和未知/过期标记，Node 有 owner 验证标志；不含 peer 正文、Worker prompt/log、凭据或私钥。`status.changes` 是可重启续读的 owner 绑定快照差异游标，明确标为 `partial`，不覆盖审批、Intent、Membership/Link 或读取间瞬态。`topology.apply` 复用对象版本/绑定 epoch，支持嵌套 Group、同一 Endpoint 多组、角色绑定及同 owner 连线提案/撤销；连线提案不可路由，也不代表双方批准。`link.key_*` 让端侧校验当前规范合同与两端公钥候选后签署同 owner Link；它没有可信 Node pin 或跨用户邀请。完整 `status_events` 推送和跨用户 Thread 连线仍未实现，capability 保持 `false`。

Node 的 Relay 通道是独立的出站 Node bearer 流程：Node 在本地保管凭据，只把摘要提交 device-code；Client 在加密 RPC 中预览和确认；Node 再以 `Authorization: CicadaNode ...` 保持 Relay SSE、领取持久投递并回传 receipts。Android 不代理该传输。目前投递正文仍走遗留明文路径。详见 [interop 的 Node 流程](client-hub-interop-v1.md#4-bind-a-node-then-use-its-outbound-relay-channel)。

Client 公钥、Owner Grant 和 RPC packet 的 JSON 形状由 `internal/e2ee/owner_device_grant.go` 与 `internal/clientwire/wire.go` 定义；`[]byte` 按 JSON base64 编码。`route` 中的 owner/device/操作名是经 PQ 签名与 AAD 绑定的元数据，但不直接作为授权来源；服务端仍独立查询当前设备、owner key 和 epoch。第一次请求序号为 1，后续逐一递增。相同 packet 的精确重试返回持久缓存的相同密文响应；处理中的精确重试不会改变首个执行者的状态，同序号不同密文或不同 operation ID 拒绝。Hub 重启把未完成的 RPC PROCESSING 标记为 UNCERTAIN，不盲目重做管理副作用。异步 Intent 独立保存 QUEUED/RUNNING/DONE/UNCERTAIN；重启后 QUEUED 可继续，RUNNING 先与终态 Intent 对账，否则标记 UNCERTAIN。Client 应通过新的已认证请求读取权威 Intent/Approval 状态。

## 两个仓库的代码边界

`CICADA` 只负责 Node/Hub 网络与已有 Control 的服务端边界；`CICADA_CLIENT` 独立发布 Android APK，并负责手机 UI、录音/STT、用户交互和端侧密钥。Cicada 的 Hub 须提供清晰、版本化、可由独立客户端调用的 wire contract、能力协商和服务端安全校验；不在本仓库实现 Android 组件、用户登录界面、语音流程或手机状态缓存。Android 不链接 Go 包、不直读 Hub 数据库、不持有 Hub 管理 bearer 或 Node credential。上表列出的 URL/操作是真实路由；后面未标已实现的逻辑操作仍是目标契约，需在双方实施前冻结为 OpenAPI/JSON Schema 和公开测试向量。

目标网络层必须分清两类流量：Endpoint↔Endpoint 的密文由 Directory/Relay/Node 投递，Control 不见 peer 正文；外部 Client 发给 Control 的管理内容经独立的、版本化的应用层 PQ 安全入口，到达 Control 后由它作为预定接收端解密。**当前普通 Fabric 消息仍有遗留明文路径，尚未完成 Hub-blind Endpoint E2EE。** Hub 已实现 Client 管理入口的服务端认证、重放检查和路由适配，但不在本仓库开发 Client 端会话或用户操作流程。当前服务端可信身份来源是 Hub 本地登记的 owner 公钥签署的设备 Grant；手机端如何保管私钥和完成首次可信引导属于独立 Client 仓库及后续端到端验收。旧管理 bearer 或模型自报的 owner/approval 不能替代 Grant。

Hub 预留的接口按依赖顺序为：公开能力探测；已认证的加密管理请求/响应封套；按权限过滤的权威状态快照和增量游标；持久异步 Control Intent 与进度查询；版本化的审批、Node 绑定和拓扑/连线操作。Node 自己只通过出站 HTTPS/SSE 连接 Hub Relay，不要求 Android 在线，也不依赖 Client 转发普通 Agent 消息。各项服务端能力须有真实安全和协议测试后才在 `/v2/client/capabilities` 中打开；`CICADA_CLIENT` 可以独立实现其调用方，而不改变 Node/Relay 的消息路径。

## 要预留的服务边界

以下是待双方冻结的**逻辑操作**，不是现有 URL。新增实现应落在 Hub 的 Client/Management 入口，经过同一 User 身份、授权和权威 Control 状态服务；不能让手机伪装 Endpoint/Node，不能把普通 Endpoint↔Endpoint 正文转进 Control。

| 操作 | 请求与结果最小语义 | 服务端边界 |
|---|---|---|
| `open_client_session` | Hub ID、Android 设备 ID/公钥、User 登录、短时 challenge、会话 epoch、能力版本 | 单设备可撤销；设备码绑定 Node 是另一种操作，不自动授予解密或 Worker 权限。 |
| `get_status_snapshot` / `subscribe_status` | 有作用域的 Node、Workspace、Thread/Endpoint、Worker、Monitor、Group、Goal/Task 摘要，版本/游标、来源、观测时间、在线和过期标记 | Control 汇总可见状态；Hub 权威变更后推送增量，断线按游标补读；按 User/Group 授权过滤。 |
| `submit_control_intent` / `intent_status` | 用户自然语言文本或结构化意图、可选目标 Node/Workspace/Agent/Group、幂等键、预期版本、审批策略；返回持久 `intent_id` 和各阶段状态 | Control 执行理解、规划、查询、创建/启动/暂停/继续/结束 Goal 等管理决策。`accepted` 不等于完成。Control 查询 Worker 可通过 Fabric；有 Monitor 的 Group 可查询受权 Monitor，无 Monitor 时用持久状态或受权成员，不能凭空发明代表。 |
| `apply_topology_change` | 版本化的 Group/Endpoint Membership/角色/连线操作、权限预览、幂等键 | 所有写入在 Hub 权威事务中执行；同 Thread 多 Group、嵌套 Group、双端连线权限、撤销都由服务端 Guard 校验。手机画布只是控制器，不是独立权威数据库。 |
| `request_external_thread_link` / `approve_link` | 对方受限 Endpoint Card、方向、动作/数据范围、期限、所选单一 Hub、两端独立批准及版本 | 双方 User 授权后才生效；缺任一方批准不能路由或枚举内部对象，Monitor 不能冒充 User。 |
| `list_approvals` / `decide_approval` | 具体对象、动作、影响、到期、来源、版本、真实 User 批准签名/会话证据 | Control 验证身份与范围；模型正文中的“已批准”不产生授权。 |

状态至少拆成 `node_connectivity`（connected/stale/offline）、`native_session`（known/joined/binding_lost/unknown）、`worker_execution`（queued/running/recovering/completed/failed 等）、`goal_lifecycle`（planned/running/paused/completed/failed/cancelled 等，只有后端真实支持时展示）、`last_observed_at`、`source` 和 `stale`。本地页面不能把“Node 离线”写成“Worker 已完成”，也不能从一个没有新事件的旧快照推断 Goal 已暂停。状态操作需要权威版本和可审计历史；`pause`、`resume`、`finish` 不能由手机只改标签实现。

## 手机语音与任务入口

Android 首版应提供显眼的应用内麦克风入口，并考虑系统快捷方式、小组件和安全的通知入口；不依赖常驻麦克风。文字输入始终可用。用户可选择安装和删除本地小型语音转文字模型；默认仅在手机端处理原始音频，向 Control 发送转写后的文本与用户确认的目标/上下文。若无本地模型，联网 STT 必须由用户明确选定服务并显示音频将交给谁；不得把第三方 STT 误称为“音频始终端到端只到 Hub”。未来鸿蒙 Agent/Skills 和更广泛 APP 操控不属于 Android v1，但 `submit_control_intent` 的能力/审批模型不应绑定为语音专用。

## Client↔Hub 的 NIST 后量子 E2EE 门槛

Android 到 Hub 的**应用层**管理内容必须由 Android 设备加密给 Hub 上的 Control 身份，且以双向认证、抗重放、设备撤销和密钥轮换保护；仅有 HTTPS/TLS 不算满足此要求。可选协议套件以 [NIST FIPS 203（ML-KEM）](https://csrc.nist.gov/pubs/fips/203/final)、[FIPS 204（ML-DSA）](https://csrc.nist.gov/pubs/fips/204/final) 和 [SP 800-38D（GCM）](https://csrc.nist.gov/pubs/sp/800/38/d/final) 为基础，具体参数、KDF、AAD、nonce、签名覆盖、密钥目录、防回滚及 Android 依赖必须经协议文档、测试向量和实现审查后固定。未达标时能力协商保持 `false`，敏感操作 fail closed；不可静默降级为明文旧 API。

这里的 E2EE **接收端是 Control**：Control 为理解语音转写、规划和管理任务必然解密指令；Hub 的反向代理、Relay 与非 Control 组件不应获取其明文和私钥。普通 Worker↔Worker 消息的接收端则是目标 Endpoint，Control/Hub Relay 都不能解密。这两个终点不能混写成“Hub 永远看不到任何用户内容”。状态快照中含敏感信息的字段也应经同一 Client↔Control 保护；通知 push 只发无正文提示，由手机安全会话取回详情。

手机私钥必须留在受保护的端侧存储；优先使用 Android Keystore 的真实受支持算法和硬件级别，并在设备上检测能力。[Android 官方 Keystore 文档](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec)记载 ML-DSA 支持受系统/API 与 KeyMint 硬件版本限制，不能假设所有 Android 手机都能把 ML-KEM/ML-DSA 私钥直接放入硬件 Keystore。若某设备需要软件 PQ 实现与 Keystore 包装密钥，应记录明文密钥在内存中的边界并做威胁评估；达不到既定安全等级时拒绝启用远程敏感操作。备份、换机、丢失、重放计数与多设备授权需要独立设计。所有应用层封套至少绑定 `hub_id`、`device_id`、`user_id`、`session_epoch`、`sequence`、`operation_id`、收件人公钥版本与内容类型；服务端先验签/验序/验权，再交给 Control。对语音文本、外部 Thread 邀请、审批和画布变更均使用相同安全入口与服务端 Guard。

## 验收与协作

Android AI 可先实现纯本地语音模型安装/删除、录音权限/可访问性、文字编辑、离线草稿和 UI 状态组件；真实 Hub 数据/写操作在能力 `false` 时显示待接入。核心 Go AI 实现 PQ Client 会话、状态投影、事件恢复、Control Intent 和双端连线后，两仓共用协议测试向量及拒绝/重放/换机/断线测试。不能用 mock、TLS、HTTP 200 或旧 bearer 页面宣布 Android↔Hub E2EE 已完成。
