# Android Client ↔ Hub/Control 协作契约

状态：**Hub v1.2 服务端能力已部分实现；Client 开发者报告当前固定在 v1.1（实现 `179e0ef`、文档 `b298fd8`），此前结果不能算作 v1.2 验收**。当前可调用接口、字段与加密字节规则见 [Client wire v1](client-hub-wire-v1.md)，精简调用顺序与最小请求见 [Android interop v1](client-hub-interop-v1.md)，OpenAPI 见 [draft](client-hub-v1.openapi.yaml)。客户端仓库为 `../CICADA_CLIENT`；本仓库的 `CICADA.md` 是架构依据。首版 Client **只开发 Android**。手机是 Client，Control/Directory/Relay/权威面板状态运行于 Hub，原生 Thread 与 Node Agent 运行于 Node；三种部署职责允许同机。

该 Android 证据对应未标注精确源码 revision 的 resident Hub，不能自动认证当前核心版本。两仓按 [联合开发规范](client-hub-development.md) 固定协议、构建来源和验收范围；operation 来源为 [catalog](../cicada-go/internal/clientcontract/catalog.json)。

## 已有接口与能力协商

Hub 现有 `/v1/machines`、`/v1/workers`、`/v1/goals`、`/v1/groups`、`/v1/approvals`、Goal events SSE 等属于旧管理 API。这些接口使用传统管理 bearer，不满足新的 Client↔Control 后量子 E2EE 和设备身份要求；Android 正式版不得直接提交语音转写、审批、拓扑改动或敏感管理读取到它们。旧 `/v1/communication-links` manager-bearer HTTP 路由已退役并返回 `404`；Client Link 提案和撤销只能走加密 `topology.apply`。现有 Goal/Worker 状态可作为后端构建新只读投影的事实源，但不能将 `worker.status` 直接等同于 `goal.status` 或 Node 在线状态。加密 `goal.lifecycle` 只支持未领取的远端队列任务暂停/恢复；正在运行的原生 Worker 尚无安全停止闭环。

`GET /v2/client/capabilities` 是无身份的能力探测点，不包含私有状态。Control 模式目前返回 `status=partial`；Fabric-only 模式返回 `status=not_ready`。`available_rpc_operations` 属于本 Hub 管家 owner，`external_rpc_operations` 属于经独立登记的外部 owner；设备登录后还必须调用加密的 `session.capabilities` 确认自己的权限。Android 不能因为旧 bearer API 或某个操作可用就把完整契约视为就绪。

能力端点合同名为 `android-hub-v1-draft`，而 `/v2/client/identity` 的 `contract` 是 `android-hub-v1`。Control 可用时，`external_client_sessions` 与 `external_link_invites` 为 `true`；`status_events` 和可路由的 `external_thread_links` 仍为 `false`。HTTP 传输错误使用 `{"error":"..."}`；RPC 业务拒绝则仍是 HTTP 200 的加密响应 `{ok:false,error:"..."}`，其中 `error` 只是自由文本，目前没有稳定 machine-readable code。Android 不得将错误文本当协议枚举。

当前已实现的服务端路由：

| 路由 | 能力与限制 |
|---|---|
| `GET /v2/client/identity` | 返回持久 Hub ID、独立的 Control PQ 公钥和密钥版本。客户端必须通过独立可信渠道固定 Hub ID/公钥；仅下载此响应不构成信任。 |
| `POST /v2/nodes/device-code` | Node 本地生成并保管 bearer，仅提交摘要与 ID/名称；Hub 返回短码和 `/client/device` 相对验证路径。这个路径由独立 Android Client 实现交互，本仓库不托管授权页面。 |
| `POST /v2/client/devices/enroll` | 接受已在 Hub 本地登记的 owner ML-DSA 公钥签署的设备 Grant；绑定精确设备公钥指纹、Hub ID、owner、用途和期限。首次 owner 公钥仍需本地可信引导，**不是**手机点链接输入设备码的最终体验。 |
| `POST /v2/client/rpc` | ML-KEM-768 + ML-DSA-65 + AES-256-GCM 双向封装；Hub 从登记设备记录推导身份和 epoch，事务性序号/operation ID 重放拦截，响应密文缓存。提供 `session.capabilities`、`status.snapshot/changes`、`goal.lifecycle/result`、`topology.snapshot/apply`、`devices.list/revoke`、`nodes.preview/confirm/list/revoke`、`approvals.list/decide`、`intent.get/list/status/submit`、`link.list`、`link.invite_create/preview/accept`、`link.key_manifest/key_grants/key_grant`、`group.key_manifest/key_grant/key_status`。`intent.submit` 先持久接受并返回 Intent ID，响应缓存后异步派发。外部 owner 可管理自己的设备/Node/Group/Endpoint 拓扑、Link 和 Group Endpoint key grant，但无权读取管家的状态、Goal、Intent 或 Approval；邀请接受只生成不可路由的 `PROPOSED` Link，双方可用 `link.list` 恢复提案 ID。 |
| `POST /v2/client/rpc/recover` | 原样提交此前持久保存的签名密文请求；Hub 只检查当前绑定和原密文摘要，不重新执行业务。完成者返回原密文响应；新 v29 不确定请求返回签名密文 `OUTCOME_UNCERTAIN` 通知；旧无响应序号预留的请求明确拒绝自动恢复。 |

### Group Endpoint key grant 加密 RPC

能力探测会在实现可用时返回 `group_endpoint_key_grants: true`，manager 与已登记 external owner 的加密 `session.capabilities` 均列出 `group.key_manifest`、`group.key_grant`、`group.key_status`。这三个操作只能通过已认证的 `POST /v2/client/rpc` 封套调用。RPC 的 owner 由当前加密设备 session 推导；请求不接受 `owner_id`、`user_approved` 或其他自报授权字段。Group 必须归该 owner 所有，Endpoint 也必须归同一 owner 所有并已加入该 Group；未加入、异 owner、失效绑定或失效 owner Node 都会被服务端拒绝。

`group.key_manifest` 请求正文为：

```json
{
  "group_id": "grp_...",
  "endpoint_id": "ep_...",
  "owner_key_id": "...",
  "issued_at": "2026-09-24T12:00:00Z",
  "expires_at": "2026-09-24T13:00:00Z"
}
```

时间必须是 UTC 的规范 RFC3339Nano 字符串；`issued_at` 不得晚于 Hub 当前时间，`expires_at` 必须晚于当前时间和 `issued_at`。成功响应的 `result` 是 `GroupEndpointKeyGrantManifest`，含 Hub/owner/Group/Endpoint/Node、Group 与 Membership revision、Endpoint join revision、当前 SessionBinding epoch、候选 Endpoint 公钥身份与指纹、完整 `candidate_attestation`（base64 的 Endpoint 自签证明）、`candidate_binding_digest`、`owner_key_id`、时间和 `digest`。客户端必须先按 [wire contract 的完整 Endpoint 证据规则](client-hub-wire-v1.md#complete-group-endpoint-key-evidence) 核对证明 SHA-256、ML-DSA-65 签名、公钥 ID/指纹、当前身份/绑定 epoch 与两个域分离摘要，再展示本次授权对象与候选公钥并签名。缺少原始证明字节时不能仅凭 Hub 返回的摘要批准。

owner 使用其 ML-DSA owner key 对该 manifest 明确批准。签名参数为：

```text
SignOwnerLinkKeyGrant(
  manifest.owner_id,
  "group-endpoint-key-grant:v1",
  manifest.digest,
  manifest.candidate_binding_digest,
  uint64(manifest.candidate_version),
  OwnerLinkGrantSideSource,
  parse(manifest.issued_at),
  parse(manifest.expires_at))
```

`group.key_grant` 请求为 `{ "group_id": "...", "endpoint_id": "...", "owner_key_id": "...", "signed_proof": "<base64>" }`；`signed_proof` 是上述 signer 返回的完整 JSON 字节，按 Client RPC 的 `[]byte` JSON 规则 base64 编码。Hub 根据设备 session 确定 signer 的 owner，重新读取当前 manifest 并验证 ML-DSA 签名、用途、候选绑定、版本和有效期，然后原子接受 nonce。普通 `link.key_grant` proof 的 Link ID/用途不同，不能跨协议用于 Group Endpoint 授权。

`group.key_status` 请求为 `{ "group_id": "...", "endpoint_id": "..." }`，成功的 `result` 是最新 `OwnerGroupEndpointKeyGrant` 记录，含原始 `manifest`、签名证明、接受时间和 `current_status`。状态以 Store 返回值为准：`CURRENT` 表示当前绑定仍有效，`STALE` 表示 Group/Membership/Endpoint/候选绑定已变化，`PROOF_EXPIRED` 表示证明过期，`OWNER_KEY_REVOKED` 表示 owner key 已撤销，`INVALID` 表示记录无法通过当前检查。查询也严格限制在当前 session owner 自己拥有的 Group 和 Endpoint 范围内。

`status.snapshot` 对本 Hub 管家返回 `scope_mode=single_owner_control_database`；外部 owner 返回 `scope_mode=owner_attributed_v2`，只投影本人绑定 Node、Group/Endpoint 和有明确 owner 的 Goal 及其 Worker。旧 ownerless Goal/Machine 行不进入外部视图，Worker 通过 Goal 归属过滤。响应区分 Node、Endpoint/原生 Session、Worker、Goal、Group、Task 的状态和未知/过期标记，Node 有 owner 验证标志；不含 peer 正文、Worker prompt/log、凭据或私钥。`status.changes` 是可重启续读的 owner 绑定快照差异游标，明确标为 `partial`；它包含同 owner 审批和 Client Intent 的有限状态元数据，不含其请求正文、结果或错误，也不覆盖 Membership/Link 或读取间瞬态。`topology.apply` 对各 owner 自己的对象复用版本/绑定 epoch，支持嵌套 Group、同一 Endpoint 多组、角色绑定及同 owner 连线提案；外部提案任何一侧均可撤销。`link.invite_*` 可用一次性 token 在两个已登记 owner 的已加入 Endpoint 间建立受限提案；`link.key_*` 可让 Link 两侧分别记录密钥绑定签名。仅有提案或签名不能产生一般 Fabric 路由；双侧当前授权下的 Node-only 密文 SEND/ASK/REPLY 是独立的传输切片，已在两个逻辑 Node/fake Codex 中通过，但真实原生跨用户连续性尚未验收。guest Join 有本机桥接但未做真实 Codex 验收，完整状态推送也未实现。

Node 的出站通道使用独立 Node bearer：Node 在本地保管凭据，只把摘要提交 device-code；Client 在加密 RPC 中预览和确认；Node 再以 `Authorization: CicadaNode ...` 保持 Relay SSE、领取持久 peer 投递并回传 receipts。新 Client Intent 派生的 Goal 记录认证 owner；绑定 Node 可用同一 Node bearer 心跳、领取自己 owner 的 Worker、上传/下载精确 attempt 的 Workspace 快照并回报结果，不需要全局 Control bearer。旧 ownerless Goal 不会自动归属给它。Android 不代理这些 Node 路由，也不持有 Node 凭据。新 peer 投递要求 Node 封装的密文；遗留 `/v2/fabric/send|ask|reply` 明文写入返回 410，历史 receive 只读。详见 [interop 的 Node 流程](client-hub-interop-v1.md#4-bind-a-node-then-use-its-outbound-relay-channel)。

Client 公钥、Owner Grant 和 RPC packet 的 JSON 形状由 `internal/e2ee/owner_device_grant.go` 与 `internal/clientwire/wire.go` 定义；`[]byte` 按 JSON base64 编码。`route` 中的 owner/device/操作名是经 PQ 签名与 AAD 绑定的元数据，但不直接作为授权来源；服务端仍独立查询当前设备、owner key 和 epoch。第一次请求序号为 1，后续逐一递增。相同 packet 的精确重试返回持久缓存的相同密文响应；处理中的精确重试不会改变首个执行者的状态，同序号不同密文或不同 operation ID 拒绝。Hub 重启把未完成的 RPC PROCESSING 标记为 UNCERTAIN，不盲目重做管理副作用。异步 Intent 独立保存 QUEUED/RUNNING/DONE/UNCERTAIN；重启后 QUEUED 可继续，RUNNING 先与终态 Intent 对账，否则标记 UNCERTAIN。Hub v1.2 已提供原包 `/v2/client/rpc/recover`：`COMPLETED` 原密文响应、v29 `OUTCOME_UNCERTAIN` 密文通知、处理中及旧不确定请求的 409。Android 端 pending-slot 安全退休和读取权威状态尚待在 v1.2 契约下验收，不能绕过序号检查发新动作。

## 两个仓库的代码边界

`CICADA` 只负责 Node/Hub 网络与已有 Control 的服务端边界；`CICADA_CLIENT` 独立发布 Android APK，并负责手机 UI、录音/STT、用户交互和端侧密钥。Cicada 的 Hub 须提供清晰、版本化、可由独立客户端调用的 wire contract、能力协商和服务端安全校验；不在本仓库实现 Android 组件、用户登录界面、语音流程或手机状态缓存。Android 不链接 Go 包、不直读 Hub 数据库、不持有 Hub 管理 bearer 或 Node credential。上表列出的 URL/操作是真实路由；后面未标已实现的逻辑操作仍是目标契约，需在双方实施前冻结为 OpenAPI/JSON Schema 和公开测试向量。

目标网络层必须分清两类流量：Endpoint↔Endpoint 的密文由 Directory/Relay/Node 投递，Control 不见 peer 正文；外部 Client 发给 Control 的管理内容经独立的、版本化的应用层 PQ 安全入口，到达 Control 后由它作为预定接收端解密。新 peer 写入只走 Node 封装的密文路径，旧明文写入已退役；原生跨用户会话连续性仍待实测。Hub 已实现 Client 管理入口的服务端认证、重放检查和路由适配，但不在本仓库开发 Client 端会话或用户操作流程。当前服务端可信身份来源是 Hub 本地登记的 owner 公钥签署的设备 Grant；手机端如何保管私钥和完成首次可信引导属于独立 Client 仓库及后续端到端验收。旧管理 bearer 或模型自报的 owner/approval 不能替代 Grant。

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
