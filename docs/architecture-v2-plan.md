# Architecture v2.1 实施计划

2026-09-23。目标以 [CICADA.md](../CICADA.md) 为准，现状与证据见 [audit](architecture-v2-audit.md)、[status](architecture-v2-status.md)。本计划不把旧 MA→MB 联邦路径改名当作新跨组能力，也不以新增 `Group` 字段代替身份/授权迁移。

## 目标与顺序

部署顶层固定为 **Node / Hub / Client**；协作参与者固定为 **User / Control / Worker / Monitor**（Monitor 可选）。Node 本机通信不经中心 Relay；跨 Node/跨用户通过双方都主动连接的**一个** Hub Relay。Hub 可以组合部署 Control、Directory、Relay 和面板，但普通 peer 明文与解密私钥不得进入 Hub。一个 Thread/Endpoint 可以加入多个可嵌套 Group；跨组/跨用户消息按显式、双端授权的 CommunicationLink 直达，不默认经 Monitor。组内广播是按固定成员快照的独立操作。

以下按依赖顺序逐步交付。每步都先补负面/故障测试，再把新入口向 MCP/HTTP/CLI 和面板开放；跨步状态不得用目标设计冒充当前能力。

### 1. 固定协议与数据迁移

1. 当前 v11 已新增 Endpoint-Group 多对多关系和精确回填，MCP/HTTP/CLI 的显式 Join/Leave/作用域及 Directory/Relay 授权已接入；同机双容器真实原生多组验收已通过。v12 增量实现了 Group parent 的版本化管理、防环和不继承权限。v13 增量保存不可路由的同 owner CommunicationLink 提案及版本化撤销。v14 只新增按 Group 可读的 `CANDIDATE` 公钥登记；MCP 已可从显式 Join 的当前原生 Session 发布其 Node 本地公钥候选。v15/v16 将用户独立持有的公钥经 Hub 本地离线信任流程登记，并保存 Link 两侧精确合同的 ML-DSA Grant；两端当前原生绑定/成员版本与 key 状态在读取时重查。v17 增加 Relay 密文 BLOB 与明文读路径隔离，仍未接入 Fabric/Node；v18 增加单 owner Client↔Control PQ 设备登记、重放保护、加密 RPC 与状态快照；v19 增加持久异步 Intent 与恢复；v20 增加 owner 确认的 Node 设备码绑定；v21 增加部分状态快照差异游标。v22 将当前合同、两端原生绑定和公钥候选组成可复核清单，并用 Client 加密 RPC 保存两侧密钥绑定签署；旧 v16 合同 Grant 仅为历史。加密 Client RPC 已接入设备、Node、同 owner 拓扑和密钥同意管理。旧 `/v1/fabric/*`、Thread queue/message、Contact peer ingress、SSH machine pair 和明文 token 下发已退役。这些增量仍无外部邀请、可信 Endpoint pin 或密文原生路由，不使连线提案可路由。下一步实现可信跨 owner 邀请与独立双用户批准、Node 独立可信 pin、端点密文投递和完整状态推送。保留旧 Endpoint ID、原生 Session、单 `group_id` 列为迁移投影；不自动把旧 Session 放入宽权限全局 Group。
2. 明确每条消息使用的来源 Group、目标 Group、link revision、双方 Principal/Endpoint 及可信 SessionBinding；若多条连线或 Group scope 均可匹配，返回歧义，不依赖模型猜测。父子 Group 关系不传递访问权。
3. 迁移前后用 `migration inventory/backup/verify/restore` 在合成 StateDir 检查旧 Goal、Contact、消息、Approval、密钥/重放计数；真实 StateDir 仅在用户授权的运行环境与维护窗口操作。旧 GroupGateway 请求保持只读可追溯，完成映射前不删除表。

退出条件：同一 native Session 重复 Join 两组仍是一个 Endpoint/SessionBinding；每组可独立退出/撤权；未 Join、伪造身份、旧接口绕过和越权枚举均拒绝；数据库中旧 ID/密钥/计数未丢。

### 2. 打通本地与单 Hub 传输

1. Node-local `CryptoState` 已有 durable sequence、精确密文 outbox；Node DB v3 对新收件将经认证的密文和 replay 同事务保存，旧 replay-only 行明确要求对账。v4/v5 扩展跨组 pin 的签署清单和独立 Owner key trust；Node 能核验双侧授权证据并持久 pin，但该 pin 不赋予消息路由权。仍须把发送端 outbox、目标 inbox 接入现有 Relay receipt/idempotency。同 Node 由可信本地适配器授权后使用真实 `codex queue --thread` 精确投递；可不经过常驻 Node 进程的转发，但必须持久、去重、保留注入不确定状态。持久收件不证明模型已消费；Node inbox 注入与 `INJECTION_UNCERTAIN` 崩溃对账仍是独立工作。
2. 跨 Node 复用现有 Node credential、durable Relay、出站 HTTPS/SSE wake；Node 不要求入站端口，Hub 不能主动拨 Node。每条消息绑定一个共同 Hub，不能串联 Home Hub。断流后恢复与低频对账兜底，不能用高频轮询替代长连接。
3. 维持 `RELAY_ACCEPTED/LOCAL_ACCEPTED`、`NODE_RECEIVED`、`RUNTIME_INJECTED`、消费未知、结果验收的分层语义；异常注入进入 `INJECTION_UNCERTAIN`，不盲重投高风险操作。保护用户前台输入，只用官方 queue/安全投递点。

本机离线授权不能沿用现有 MCP Session 缓存：它缺少双方 Membership/加入版本与目标绑定，且恢复过程仍需 Hub `whoami`。本机 Guard 需要从可信授权源在线获取短租期、签名的双 Endpoint/Group/Binding scope 快照，并在 outbox 接受与原生注入前检查签名、租期、允许动作、版本和 epoch；Node 私有状态持久化快照及撤销水位。离线时无法即时获知远端撤销，只能承诺租期内有界陈旧；到期或版本回退即拒绝。旧 `/v1/threads/queue` HTTP/CLI 入口已移除，不能充当该路径。

退出条件：同 Node A↔B 的真实 MCP Ask/Reply 不调用 Hub Relay；两个 Node 网络互不可达但共连 Hub 时在原生 A/B Session 中完成 Ask/Reply、两端 ID 不变；Control 规划/汇报禁用时仍成功。

### 3. 授权连线、可选 Monitor 与广播

本阶段可以先建立版本化合同和 Guard，但**新的跨组/跨用户/广播正文路径在第 4 步的端点密文闭环通过之前保持关闭**；不能为了证明连线路由而把新业务明文写入 Hub。

v13 已落下提案结构、范围快照、摘要和撤销，但管理 bearer 同时用于 Node enrollment，不能证明双方用户独立批准。v14 的候选公钥仍只是自证 `CANDIDATE`。v15/v16 的离线用户公钥与双侧签名 Grant 使合同批准可持久核验；v18 已有单 owner 的 Client↔Control PQ 设备入口，v22 已让同 owner 的两侧通过加密 Client RPC 分别提交**与两端 Endpoint 密钥绑定**的 Link Grant，并让旧 v16 Grant 明确保持历史。跨 owner 双用户仍无可信邀请、独立状态分区和两端批准。因此提案保持 `PROPOSED`，没有激活 API、跨组路由权或外部 Endpoint 发现权；下一步建立外部邀请/Card 与 Node 独立可信 pin，再让跨 owner 双方 Grant 和公钥 pin 绑定同一合同摘要。授权 Guard 应在每次路由与读取时检查当前 Membership/Join/Group/Binding 版本、期限、动作、数据范围和撤销状态。跨用户提案在邀请身份可信前保持拒绝。

密钥绑定按独立、版本化的 Owner Grant v2 完成：从权威 Link、两端当前 SessionBinding 和 Endpoint key candidate 构造确定性 manifest，覆盖双方 Endpoint/Group/Principal/Owner/Node、binding ID/epoch、候选版本、key ID、完整指纹和证明摘要。双方用户分别签同一 manifest 摘要与精确合同；旧 v1 Grant 保留只读历史，显式标为 `LEGACY_KEY_UNBOUND`，不可被自动升级成 pin 或路由权。Hub 在接收和投递事务中重算版本化范围；Node 从独立可信来源取得 owner 公钥后重验双方签名和候选证明，才在本地建立精确 pin。候选自签、公钥登记和管理 bearer 均不能单独产生信任。任何 binding、成员、候选、合同或 owner key 变化都使旧授权失效，须重新批准。先保留跨 owner 提案拒绝，直到可信外部邀请与独立双用户授权入口真实可用。

1. 将单 Group 的默认成员通信和跨 Group/跨用户 CommunicationLink 分开：后者必须验证双方用户/管理 Grant、scope、方向、期限、版本、可见范围和撤销。Monitor 只在用户授予观察/审阅/拟稿能力时参与，不作为必经传输跳点。旧 MA→MB 写路径在新路径稳定、迁移对账后退役。
2. 广播固定**一个 Group** 和一个事务时点的有效成员快照，排除发送者或包括发送者的规则显式设定。每个收件人独立后量子加密 envelope、Delivery、回执与失败；本机收件人走本地路径，远端收件人各自最多一个 Hub。父/子 Group 或同一 Thread 的其他 Group 不自动接收。
3. User 经 Monitor 发起广播必须留可信用户发起/批准记录；Monitor 的建议或模型文本不能伪造用户授权。给 fan-out、正文尺寸、wake 和队列设置限额/背压。

本阶段退出条件：双端授权、范围、期限、版本、撤销和未授权拒绝有持久合同与负例；跨组正向 Ask/Reply 和广播的真实投递须与第 4 步的端点密文一起验收。Monitor 缺席不得使无审阅要求的授权合同失效。

Hub 已提供绑定 Node 专用的 `GET /v2/relay/nodes/{node_id}/links/{link_id}/authorization`，只返回当前双方签署的公开证据；Node 必须使用独立预置信任的 Owner 公钥重验，且当前提案仍不可路由。下一步把它接入生产 Guard 和密文投递；不能把证据读取或本地 pin 视为跨组消息完成。

### 4. 实现 Hub 失明的 NIST PQ 端点保护

先实测加解密终点。当前 `fabric_messages.body` 明文和旧 Control Contact 明文路径不满足目标。新 Fabric 消息在端点本地受控边缘用 NIST 标准 ML-KEM、ML-DSA 与经过审查的对称 AEAD 完成密钥封装、签名和加密；具体参数套件、版本、身份绑定、抗重放、轮换与恢复流程须固定在协议文档并验算实现依赖。Hub 的 Control、Relay、Directory、数据库、反向代理仅见密文和必要路由元数据；浏览器 Client 若展示正文，须有清楚的本地密钥终点。不能用 TLS 代替端点 E2EE，也不能让 Hub 私钥解密后自称盲中继。

当前已有 `internal/e2ee/endpoint.go` 密文原语、绑定 Endpoint/Principal/Node/SessionBinding epoch 的 ML-DSA-65 自签名 attestation、v14 Hub 公钥候选登记/Group-scoped read、v15/v16 离线用户公钥与双侧合同签名，以及 `internal/nodekeys` 的本地稳定私钥和 durable crypto-state API。它们还未连成消息路径：Hub 仍保存明文，候选不可信、不 pin、不授权加密，Node 本地状态没有接入原生投递。接入顺序是：把离线用户引导升级为可信设备/PQ Client 会话，把现有 Node-local pin API 接到双方批准合同，并定义重新加入/迁移时的密钥恢复与轮换；把本地 durable outbox/inbox 接到消息发送和接收，在网络请求前分配 message/request ID 和序号并一次性 Seal；增加 Hub 仅保存原样密文、与旧 `body` 路径严格隔离的 payload/route；Node 重验收件授权及原生绑定后持久抗重放并于安全注入点解密。先运行单收件人 `send` 的 native E2E 和崩溃/重放/备份回滚测试，再扩展相关 Ask/Reply 与逐收件人广播，避免把现有明文 `mcp_outbox` 当作加密完成。Node crypto-state 与私钥尚未纳入 Hub backup；完整 Node 一致点备份、恢复与单调计数对账仍是退出条件。

退出条件：Hub 进程/数据库/日志/备份查不到普通 peer 明文和私钥；篡改、重放、错误收件人、撤权后发送均拒绝；旧 Contact 密钥/ratchet/replay 不重置且无静默明文降级。协议备选与现有缺口见 [PQ transport](architecture-v2-pq-transport.md)。

### 5. Android Client 契约、面板、设备绑定与 Docker 演示

Android 是首版手机 Client；Hub v18–v21 已实现经 NIST PQ 应用层保护的单 owner Client↔Control 设备入口、状态快照/部分差异游标、审批、持久异步 Intent、Node 设备码、版本化拓扑和不可路由连线提案。下一步补完整状态推送、可信双端连线及独立 Android 互操作验收。未就绪的单项能力在 `/v2/client/capabilities` 保持 `false`，不能让旧 bearer API 承载敏感 Android 操作。Control 对管理指令是预定解密端；普通 peer 消息仍要求 Hub Relay 失明。服务端按 Node/Worker/Goal 分层给出运行、暂停、完成、未知与时间来源，不凭推断伪造 Goal pause/resume。详见 [Android 契约](android-client-hub-contract.md)。

Hub→Node Worker 管理链路须再收敛凭据：当前 Node 设备码绑定只授权 Relay，旧 Worker job/claim/result API 使用单独的全局 Control bearer。先为由已认证 Client 接受的新 Intent 和 Goal 增量记录 owner，旧行保持 ownerless；新 Node job/claim/result 入口在同一事务内重验绑定凭据、owner、机器、Worker→Goal 归属与 attempt。旧 ownerless 任务不得按机器名推断 owner 或被新 Node bearer 领取。只有这一整条路径的跨 owner、撤权、并发与结果验收测试通过后，才能声称手机发起的任务可由已绑定 Node 单凭自己的凭据执行。

Hub 权威面板状态展示经验证 Node、Thread/Endpoint、可嵌套 Group、同一 Thread 的多组 Membership、可选 Monitor 和已授权通信连线；Android 只是其视图和操作入口，拖拽/连线每次都是有预期版本和权限预览的管理事务。Node 登录采用一次性设备码与用户在已认证 Android Client 上批准的绑定流程；Node 仍只主动出站，设备绑定不授予 peer 明文密钥。

Docker 演示至少有持续运行的 Hub、两个互不可直连的 Node、Alice/Bob 两个独立用户、A1/A2/MA/B1/MB/U、嵌套 Group 与多组 Thread。分别验证本机零 Hub、跨机一个 Hub、双用户双端授权、广播、断流/重启/重复/错误 ACK/撤权。容器测试只能证明隔离网络模拟；真实 Codex 原生连续性和双物理机/公网仍要单独记录。v2-D Task/Lease 与只读 v2-E 功能继续回归，不因拓扑改动而丢失。

## 每步共同的安全与验证门槛

MCP、HTTP、CLI 与后台重试进入同一 Guard/权威状态服务；sender/group/role/approval 只由可信绑定和管理授权推导。所有 Node/Hub 路径记录 message/request/link/endpoint/epoch/attempt 状态，不默认记录正文。保持 `go test -count=1 ./...`、`go vet ./...` 和相关集成/真实原生脚本绿色，单独汇报未运行或受阻项。用户未提交改动、历史凭据、真实密钥、生产部署与远端分支均不作为清理对象。
