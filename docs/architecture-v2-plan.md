# Architecture v2.1 实施计划

## 2026-09-25 收尾与下个安全门槛

当前 `dev` 在干净 `d88e090` 上通过整仓 Go 测试/vet、合同校验、一次性
Client–Hub TCP 联调与双私有网桥拓扑门禁。sealed Link ASK 的真实 TLS/SSE
断流恢复已与 Node 生产 claim/decrypt 接成一条 deterministic 测试，Runtime
仍是假队列。同 Group 三真实 Codex Thread 广播夹具已加入，但第三次独立
opt-in 在首个 Join 因 Codex 自动审批超时结束；V72 保持 PARTIAL，不能据前两轮
部分阶段宣布原生广播通过。详见[状态矩阵](architecture-v2-status.md)与
[原生验收记录](architecture-v2-native-validation.md)。

下一条可执行的工程切片应先取得受支持的 native Session ID 来源和前台所有权/
安全注入回执，或明确使用需用户在前台交接的模式；在缺少该协议前不实现
无人值守 cold resume。用户经 Monitor 广播需要独立的可信 Client 操作、
与正文/Group/Monitor/版本绑定的用户批准记录及 Guard，不能借用普通
`intent.submit` 或 Worker `approvals.decide` 伪造批准。该功能应作为新的
合同修订与 Client 仓库协同交付；保持现有 v1.2.1 固定镜像可复验，
不将它悄悄扩展成不受审的 Monitor 广播入口。

V73 的独立后续切片应按以下次序实施，完成前保持 **NOT_RUN**：

1. 固定新 Client 合同修订（外层 PQ wire framing 可保持 v1），至少提供
   `group.broadcast.preview`、`confirm`、`status`。预览绑定精确 Group、当前
   Monitor Endpoint/角色/SessionBinding、正文 SHA-256、收件者快照及期限。
   Client 本地显示并确认最终正文，将它密封给已验签的 Monitor Endpoint；
   Hub 的批准账本只保存摘要、路由和密封正文，不记录可读广播正文。
   `status` 供响应丢失、
   `OUTCOME_UNCERTAIN` 与逐收件者结果查询，不能因恢复通知重建一笔广播。
2. Control 在 owner/device-bound Client 会话中写入版本化用户发起与批准记录，
   并创建独立的 durable Monitor 管理请求。Monitor 角色不能仅凭普通
   `message.broadcast` 权限推断；管理请求离线排队、重放幂等，Node 领取和
   原生 queue 的不确定窗口按现有分层回执处理。
3. Monitor 原生 Thread 在当前 Session 下实际调用扩展的 MCP 广播，Node/Hub
   核验批准 ID、正文摘要、Group/收件快照、角色、binding epoch、期限与单次
   使用；Monitor Node 解开给自己的密封正文，然后复用现有逐人 sealed SEND。
   Sender 仍是 Monitor Endpoint，
   用户只作为可审计 origin/approver；Hub 不得冒用 Monitor Session。
4. 同仓完成 catalog/OpenAPI/wire 文档和拒绝测试，再让 Client 独立导入新包并
   做 Android 预览/确认/丢响应恢复测试。验收必须覆盖伪造批准、错组/错
   Monitor、撤权、成员变化、重复确认、离线 Monitor、单接收者失败和限额。
   现有 v1.2.1 固定镜像仍以旧合同单独复验，不将新增能力回填旧镜像。

## 2026-09-25 当前执行切片

本轮从干净的 `dev` / `967dbd8` 开始，不扩大 Client 协议或产品范围。先以既有
Codex 适配器、CIRCL、SQLite 账本与 Node 出站连接为基线，分别完成：

1. 两个独立 owner、两个逻辑 Node 的真实 Codex 原生 Ask/Reply 验收；逐端核对
   Join 前、注入后和 Reply 后的 native Thread ID，并记录 Hub 只见密文、
   Control 业务调用为零。测试驱动显式恢复与无人值守冷 Thread 唤醒分别记录，
   不把 `codex queue` 的成功退出当成后者通过。若模型或适配器能力不足，保留
   可复跑测试并明确阻塞。
2. 修复一个具体的 Node 重启/对账故障窗口，用确定性故障测试证明状态与重试
   语义，不把传输去重写成模型或外部副作用的 exactly-once。
3. 核对官方 Codex 与现有开源密码/存储组件的可复用能力，记录版本、许可证
   和不引入额外运行时的理由；据此确定冷 Thread 的显式 resume/安全点能力
   门槛；固定来源和取舍见[开源复用审查](architecture-v2-open-source-review.md)。
   再跑完整 Go、合同与隔离 Docker 回归。

每项只在有实际代码和测试证据后更新状态矩阵。当前片段不代表 v2-A/B/C
整体完成；双物理 Node、真实 Android 和公网 HTTPS 仍须分别验收。

本切片实际结果以[状态矩阵](architecture-v2-status.md)和
[原生验收记录](architecture-v2-native-validation.md)为准：Relay attempt fencing、
Codex queue 分层回执、次要 Group sealed claim 与一次性 Docker 出站拓扑门禁已
实现并通过确定性测试。跨 owner TestMCPSealedCrossOwnerCommunicationLinkAskReplyNative
现已在同机两个逻辑 Node、两个 owner 的真实 Codex Thread 上通过，A/B 原 ID 保持，
Hub 不见正文且 Control business call 为 0；早先两次未走到 B Join 的失败运行保留为
历史诊断，不再代表当前状态。测试 driver 使用受控 codex exec resume；
Codex 0.157.0 的 MCP ID 与前台 owner/epoch 协议门槛未满足，生产无人值守
cold Thread wake 暂标 **UNSUPPORTED**（证据见原生验收记录）。Client 在另一个仓库对干净的
`967dbd8` / `client-hub-v1.2.1` 固定镜像完成 Android 模拟器的管理链路验收；
随后用[可复跑夹具](client-group-key-disposable-fixture.md)、真实 Node/Codex leased
Endpoint 与最终 Android APK 完成独立 Group key 正向 Grant、`CURRENT`、`STALE`
和 `PROOF_EXPIRED` 验收，见独立仓库的固定镜像报告。该夹具准备本身不算验收；
它的 Node Join Unix socket 路径问题已在核心脚本中修正并通过启动/清理 smoke。
Client 的历史固定镜像验收不得替代当前 dev Go 代码或新 dirty 镜像的验收。

## 前一切片：两仓接口与联调规范化

此前按 [联合开发规范](client-hub-development.md)
的 N1→N2→N3 完成统一 operation catalog、可追溯轻量 Docker Hub、协议包、
公开合成 wire 向量与 CI。保持两个仓库独立，不修改 CICADA_CLIENT，也不
把该规范化切片描述为 Architecture v2 全部完成。

N4 的 Hub 设备登记精确重试、RPC 恢复查询与 `OUTCOME_UNCERTAIN` 故障窗
已实现并通过 Store/HTTP/一次性 Docker Hub 测试；Client 已在固定干净
`967dbd8` 镜像上通过 Android 模拟器的丢响应恢复和三类故障结果。
v1.2.1 校正 Endpoint attestation 的跨仓签名原文合同，
保留既有证明与 Grant，不重写密钥或计数。N5 的 Hub `goal.result` owner-scoped 结果读取已实现；
隔离 Hub HTTP、真实 Node Agent、真实 Codex 与加密合成 Client 协议驱动已完成
Worker→审批→结果闭环；Client 又在 Android 模拟器上对同一固定镜像完成
发起/批准/读取结果验收。下一步先验收
真实 Node/Codex 冷 Thread 唤醒与身份连续、Node 恢复后重新联网对账及双物理机
封闭路径；Client 真机、公网 HTTPS 和发布属于后续 N6。恢复必须保留设备
身份、旧结果、重放水位和授权，不盲目重试副作用。

2026-09-24 执行更新：同 Group 广播已从纯设计进入代码验证。当前切片先以 Hub v28 固定同 owner、同一精确 Group 的不可变成员快照，再由来源 Node 分批使用现有本地/跨 Node sealed `SEND`，每名收件人有独立密文、稳定子操作 ID 与进度记录；MCP 暴露 `cicada_broadcast`。此切片只允许当前加入且同时具备 `message.broadcast` 与 `message.send` 的 Agent 发起，目标须有 `message.receive`，上限 32 人、每批 8 人。`UNKNOWN` 需要显式 `cicada_operation_retry`，不会把传输持久接受误报为模型消费。后续仍需证明真实 native 广播、用户经 Monitor 的可信发起/批准、跨 owner 广播与 Node 恢复后对账。以下较早的“广播关闭”叙述记录的是本切片之前的状态；以本段和 [状态矩阵](architecture-v2-status.md) 的最新验收为准。

2026-09-24 复核。目标以 [CICADA.md](../CICADA.md) 为准，现状与证据见 [audit](architecture-v2-audit.md)、[status](architecture-v2-status.md)。本计划不把旧 MA→MB 联邦路径改名当作新跨组能力，也不以新增 `Group` 字段代替身份/授权迁移。

## 目标与顺序

部署顶层固定为 **Node / Hub / Client**；协作参与者固定为 **User / Control / Worker / Monitor**（Monitor 可选）。Node 本机通信不经中心 Relay；跨 Node/跨用户通过双方都主动连接的**一个** Hub Relay。Hub 可以组合部署 Control、Directory、Relay 和面板，但普通 peer 明文与解密私钥不得进入 Hub。一个 Thread/Endpoint 可以加入多个可嵌套 Group；跨组/跨用户消息按显式、双端授权的 CommunicationLink 直达，不默认经 Monitor。组内广播是按固定成员快照的独立操作。

以下按依赖顺序逐步交付。每步都先补负面/故障测试，再把新入口向 MCP/HTTP/CLI 和面板开放；跨步状态不得用目标设计冒充当前能力。

### 1. 固定协议与数据迁移

1. 当前 v11 已新增 Endpoint-Group 多对多关系和精确回填，MCP/HTTP/CLI 的显式 Join/Leave/作用域及 Directory/Relay 授权已接入；同机双容器真实原生多组验收已通过。v12 增量实现了 Group parent 的版本化管理、防环和不继承权限。v13 增量保存不可路由的同 owner CommunicationLink 提案及版本化撤销。v14 只新增按 Group 可读的 `CANDIDATE` 公钥登记；MCP 已可从显式 Join 的当前原生 Session 发布其 Node 本地公钥候选。v15/v16 将用户独立持有的公钥经 Hub 本地离线信任流程登记，并保存 Link 两侧精确合同的 ML-DSA Grant；两端当前原生绑定/成员版本与 key 状态在读取时重查。v17 最初只增加 Relay 密文 BLOB 与明文读路径隔离；v18 增加单 owner Client↔Control PQ 设备登记、重放保护、加密 RPC 与状态快照；v19 增加持久异步 Intent 与恢复；v20 增加 owner 确认的 Node 设备码绑定；v21 增加部分状态快照差异游标。v22 将当前合同、两端原生绑定和公钥候选组成可复核清单，并用 Client 加密 RPC 保存两侧密钥绑定签署；旧 v16 合同 Grant 仅为历史。v23 让 Client 新建的 Node/Goal/Intent 保留 owner 并收敛 Worker 领取凭据；v24 对远端未领取 Goal 提供真实的版本化暂停/恢复；v25 扩展状态差异游标的审批与 Intent 元数据。v26 为分别登记的两个 owner 提供一次性外部邀请、预览和接受，接受仅产生 `PROPOSED` Link；外部 Client 的设备/Node/邀请/本侧密钥同意操作与管家管理范围分离。v27 增量保存同 owner、当前 Group/Endpoint/SessionBinding/候选公钥的签名授权，并通过加密 Client RPC 提供授权预览/接受；本轮又接通 Node 独立验签、Hub Node-only 密文 SEND/ASK/REPLY/claim、注入前授权复查和同组跨 Node 路由。Store 全包、Hub HTTP 集成与两逻辑 Node/fake Codex same-Group full-chain 测试已通过。旧 `/v1/fabric/*`、Thread queue/message、Contact peer ingress、SSH machine pair 和明文 token 下发已退役。双 owner 显式 Link 与同 owner 同组均有逻辑 Node/fake Codex 覆盖；同 Node sealed 路径有 fake 全链/故障测试及一个 Node 上两真实 Thread 的 Codex Ask/Reply 验收。同组跨 Node 与跨 owner Link 的真实 Codex Ask/Reply 也已在同机两个逻辑 Node 上通过。双物理 Node、无人值守 cold wake 和 Node 一致点恢复后对账尚未验收。保留旧 Endpoint ID、原生 Session、单 `group_id` 列为迁移投影；不自动把旧 Session 放入宽权限全局 Group。
2. 明确每条消息使用的来源 Group、目标 Group、link revision、双方 Principal/Endpoint 及可信 SessionBinding；若多条连线或 Group scope 均可匹配，返回歧义，不依赖模型猜测。父子 Group 关系不传递访问权。
3. 迁移前后用 `migration inventory/backup/verify/restore` 在合成 StateDir 检查旧 Goal、Contact、消息、Approval、密钥/重放计数；真实 StateDir 仅在用户授权的运行环境与维护窗口操作。旧 GroupGateway 请求保持只读可追溯，完成映射前不删除表。

退出条件：同一 native Session 重复 Join 两组仍是一个 Endpoint/SessionBinding；每组可独立退出/撤权；未 Join、伪造身份、旧接口绕过和越权枚举均拒绝；数据库中旧 ID/密钥/计数未丢。

### 2. 打通本地与单 Hub 传输

1. Node-local `CryptoState` 已有 durable sequence、精确密文 outbox；Node DB v3 对新收件将经认证的密文和 replay 同事务保存，旧 replay-only 行明确要求对账。v4/v5 扩展跨组 pin 的签署清单和独立 Owner key trust；Node 能核验双侧授权证据并持久 pin，但该 pin 不赋予消息路由权。跨 Node 显式 Link 密文 SEND/ASK/REPLY 已把 outbox、Relay receipt、目标 crypto inbox 和原生 queue 接通。同 owner、同 Node、同 Group sealed SEND/ASK/REPLY 已由可信适配器写入独立持久账本和 inbox；fake Codex queue 的全链、撤权、Hub Guard 503/重启和不确定注入测试通过。该本机路径不调用 Hub Relay 消息路由或 Control 业务，但授权读仍可调用 Hub Guard/Directory；2026-09-24 真实 Codex 同 Node Ask/Reply、同组跨 Node native consumption 和 2026-09-25 双 owner sealed Link Ask/Reply 已分别在真实 Thread 中通过，后两项使用同机两个逻辑 Node。受控测试 driver 的原生恢复不证明 unattended wake，持久收件也不证明 Runtime 提供通用消费 ACK。
2. 跨 Node 复用现有 Node credential、durable Relay、出站 HTTPS/SSE wake；Node 不要求入站端口，Hub 不能主动拨 Node。每条消息绑定一个共同 Hub，不能串联 Home Hub。断流后恢复与低频对账兜底，不能用高频轮询替代长连接。
3. 维持 `RELAY_ACCEPTED/LOCAL_ACCEPTED`、`NODE_RECEIVED`、`RUNTIME_INJECTED`、消费未知、结果验收的分层语义；异常注入进入 `INJECTION_UNCERTAIN`，不盲重投高风险操作。保护用户前台输入，只用官方 queue/安全投递点。

同 Node、同 Group sealed 路径当前要求 **零 Hub Relay 消息路由**，允许发送和注入前向 Hub Guard/Directory 做在线授权读取；不构成 Hub 全离线工作。Node+Session Guard 才是本地权威校验，MCP Session 缓存本身不是 Guard。若以后要求 Hub 完全离线时仍可本机通信，则另需短租期、签名且版本化的双 Endpoint/Group/Binding 授权快照及撤销水位；离线期间只能承诺有界陈旧，不能声称即时撤权。旧 `/v1/threads/queue` HTTP/CLI 入口已移除，不能充当该路径。

退出条件：同 Node、同 Group 的真实 Codex A↔B MCP Ask/Reply 在零 Hub Relay 消息路由下完成，两端保持原生 Session ID；两个 Node 网络互不可达但共连 Hub 时在原生 A/B Session 中完成跨 Node Ask/Reply、两端 ID 不变；Control 规划/汇报禁用时仍成功。2026-09-24 同 Node 真实 Ask/Reply 已通过；同组跨 Node 和双 owner Link 的真实 Ask/Reply 也已在同机两个逻辑 Node 上通过，但 Docker 网络隔离下的真实原生验证、双物理机与独立 Control-disabled 黑盒仍待做。

### 3. 授权连线、可选 Monitor 与广播

版本化合同和 Guard 已让显式单收件人跨 owner SEND/ASK/REPLY 在端点密文闭环下开放，并通过同机两个逻辑 Node 的真实 Codex sealed Ask/Reply 验收；**跨 owner 广播和用户经 Monitor 的广播正文路径仍保持关闭**，直至逐收件人密文、授权、恢复和验收完成；不能为证明连线路由而把新业务明文写入 Hub。

v13 已落下提案结构、范围快照、摘要和撤销，但管理 bearer 不能证明双方用户独立批准。v14 的候选公钥仍只是自证 `CANDIDATE`。v15/v16 的离线用户公钥与双侧签名 Grant 使合同批准可持久核验；v22 已让 Link 两侧通过加密 Client RPC 分别提交**与两端 Endpoint 密钥绑定**的 Link Grant，并让旧 v16 Grant 明确保持历史。v26 允许分别登记的 owner 经各自加密 Client session 创建、预览和接受一次性邀请，但结果只是不可路由提案；邀请 token 的持有不能代替任何一侧对端点密钥的授权。受信 Node Join 桥、Node 独立可信 pin 与生产 Guard 已接入显式 Link SEND/ASK/REPLY；Guard 在入队、领取和注入前重查当前 Membership/Join/Group/Binding、期限、动作、数据范围和撤销状态。同 owner、同 Group 广播已经限定开放；跨 owner 广播和外部 Endpoint 枚举仍未开放。

密钥绑定按独立、版本化的 Owner Grant v2 完成：从权威 Link、两端当前 SessionBinding 和 Endpoint key candidate 构造确定性 manifest，覆盖双方 Endpoint/Group/Principal/Owner/Node、binding ID/epoch、候选版本、key ID、完整指纹和证明摘要。双方用户分别签同一 manifest 摘要与精确合同；旧 v1 Grant 保留只读历史，显式标为 `LEGACY_KEY_UNBOUND`，不可被自动升级成 pin 或路由权。v26 的外部邀请和两个独立 owner 的 Store 签署测试已证明提案/授权记录边界；普通跨 owner 提案入口仍拒绝，只有一次性邀请可建提案。Hub 在未来的生产路由事务中仍须重算版本化范围；Node 从独立可信来源取得 owner 公钥后重验双方签名和候选证明，才在本地建立精确 pin。候选自签、公钥登记和管理 bearer 均不能单独产生信任。任何 binding、成员、候选、合同或 owner key 变化都使旧授权失效，须重新批准。

1. 将单 Group 的默认成员通信和跨 Group/跨用户 CommunicationLink 分开：后者必须验证双方用户/管理 Grant、scope、方向、期限、版本、可见范围和撤销。Monitor 只在用户授予观察/审阅/拟稿能力时参与，不作为必经传输跳点。旧 MA→MB 写路径在新路径稳定、迁移对账后退役。
2. 广播固定**一个 Group** 和一个事务时点的有效成员快照，排除发送者或包括发送者的规则显式设定。每个收件人独立后量子加密 envelope、Delivery、回执与失败；本机收件人走本地路径，远端收件人各自最多一个 Hub。父/子 Group 或同一 Thread 的其他 Group 不自动接收。
3. User 经 Monitor 发起广播必须留可信用户发起/批准记录；Monitor 的建议或模型文本不能伪造用户授权。给 fan-out、正文尺寸、wake 和队列设置限额/背压。

本阶段退出条件：双端授权、范围、期限、版本、撤销和未授权拒绝有持久合同与负例；跨组正向 Ask/Reply 和广播的真实投递须与第 4 步的端点密文一起验收。Monitor 缺席不得使无审阅要求的授权合同失效。

Hub 已提供绑定 Node 专用的 `GET /v2/relay/nodes/{node_id}/links/{link_id}/authorization`，只返回当前双方签署的公开证据；Node 使用独立预置信任的 Owner 公钥重验。Node-only `sealed/send|ask|reply|claim`、请求 status/cancel 和精确 attempt 授权已建立跨 Node 密文单播的入队、领取和注入前 Guard。MCP 显式 Link SEND/ASK/REPLY 经本地 Node 桥的 durable outbox、Owner trust、Seal 与 Hub 接通；双方 Node 已把密文 claim、精确授权、本地 crypto inbox/恢复 journal、解密与原生队列串成闭环，并在 queue 前再次查权。两个逻辑 Node 加 fake Codex 的显式 Link 与同组跨 Node ASK/REPLY full-chain 测试已通过；同 Node 同 Group 路径不走 Hub Relay 消息路由，也已通过 fake queue 故障测试及真实 Codex 原生 Thread 验收。同组跨 Node 与跨 owner Link 的真实 Codex Ask/Reply 均已在同机两个逻辑 Node 上通过；跨 owner 证据还验证原 ID 保持、Hub 不见正文和 Control business call 为 0。受控 driver resume 不证明无人值守 cold wake，双物理机仍未验收。fake queue 只证明精确 queue 调用，不等同真实模型消费。

### 4. 实现 Hub 失明的 NIST PQ 端点保护

先实测加解密终点。当前 `fabric_messages.body` 明文和旧 Control Contact 明文路径不满足目标。新 Fabric 消息在端点本地受控边缘用 NIST 标准 ML-KEM、ML-DSA 与经过审查的对称 AEAD 完成密钥封装、签名和加密；具体参数套件、版本、身份绑定、抗重放、轮换与恢复流程须固定在协议文档并验算实现依赖。Hub 的 Control、Relay、Directory、数据库、反向代理仅见密文和必要路由元数据；浏览器 Client 若展示正文，须有清楚的本地密钥终点。不能用 TLS 代替端点 E2EE，也不能让 Hub 私钥解密后自称盲中继。

当前已有 `internal/e2ee/endpoint.go` 密文原语、绑定 Endpoint/Principal/Node/SessionBinding epoch 的 ML-DSA-65 自签名 attestation、v14 Hub 公钥候选登记/Group-scoped read、v22/v27 当前端点公钥授权，以及 `internal/nodekeys` 的本地稳定私钥、独立 Owner 公钥信任、scoped pin 和 durable crypto-state API。单收件人显式 Link SEND/ASK/REPLY 已接入 MCP、Node 和 Hub-blind Relay；同 Node 同 Group sealed SEND/ASK/REPLY 走本机持久 inbox；同 owner、同 Group、不同 Node 的密文 SEND/ASK/REPLY 现在也接入 Hub Node-only Relay 路由与两端 Node 加解密。sealed `cicada_receive` 读取当前 Session/Group 的 Node inbox，不走 Hub 明文 receive；当前返回另有来自可信投递的 kind、request_id、reply_to 与 sender_endpoint_id；旧行无证据时保持空值。旧或尚未 sealed-capable 的 Session 仍可走其旧明文路径，sealed Session 遇到不支持的操作则 fail closed。下一步按依赖顺序扩展：双物理 Node 跨 Node 连续性验收、真实 native 广播与 Node 恢复后的单调计数对账。Node crypto-state 与私钥尚未纳入 Hub backup，不能把 fake Codex 全链测试当成真实 native E2E。

退出条件：Hub 进程/数据库/日志/备份查不到普通 peer 明文和私钥；篡改、重放、错误收件人、撤权后发送均拒绝；旧 Contact 密钥/ratchet/replay 不重置且无静默明文降级。协议备选与现有缺口见 [PQ transport](architecture-v2-pq-transport.md)。

### 5. Android Client 契约、面板、设备绑定与 Docker 演示

Android 是首版手机 Client；Hub v18–v26 已实现经 NIST PQ 应用层保护的管家 owner 设备入口、状态快照/部分差异游标、审批、持久异步 Intent、Node 设备码、版本化拓扑、受限连线提案，以及仅限未领取远端队列任务的 Goal 暂停/恢复。v26 外部 owner 可独立登记设备并在受限加密会话内管理自己的设备/Node、邀请与本侧密钥同意，不读取管家 Goal/状态；本机 Node Join 桥接和单收件人密文 SEND/ASK/REPLY 已接入，两个 owner 的真实 Codex sealed Link Ask/Reply 另有同机双逻辑 Node 验收。下一步补完整状态推送、运行中 Worker 安全停止；固定镜像的 Android 模拟器管理闭环与独立 Group key 正向授权均已验收，真机和公网 HTTPS 仍未运行。未就绪的单项能力在 `/v2/client/capabilities` 保持 `false`，不能让旧 bearer API 承载敏感 Android 操作。Control 对管理指令是预定解密端；普通 peer 消息仍要求 Hub Relay 失明。服务端按 Node/Worker/Goal 分层给出运行、暂停、完成、未知与时间来源，不凭推断伪造 Goal pause/resume。详见 [Android 契约](android-client-hub-contract.md)。

Hub→Node Worker 管理链路已用 v23 收敛凭据：加密 Client session 接受的新 Intent/Goal 传播可信 owner，旧记录保持 ownerless；已确认 Node 以本地 `CicadaNode` bearer 心跳、领取同 owner 的 Worker、传输精确 attempt 的 Workspace 快照并提交结果。任务领取、快照关联和结果提交在 Store 事务中重验凭据、owner、机器、Goal/Worker 关系及 attempt；旧 ownerless 任务不按机器名推断 owner。HTTP 集成测试覆盖 Client 加密 Intent 到 Node 结果，CLI 测试覆盖同一路由的快照收发；隔离的真实 Node Agent/Codex 审批闭环另见 [v1.2 验收记录](client-hub-v12-validation.md)。固定镜像的 Android 模拟器互操作已有独立验收记录；真实远端物理 Node 和公网 HTTPS 仍待验收。

v26 已为 guest Node 增加受当前 Node owner 绑定限制的 `POST /v2/fabric/node/join` 服务端入口；撤销 Node owner 绑定后，其 guest Fabric Session token 随之失效。Node 本机受信 Join 桥已核对 Codex session 记录和 Workspace，再由 Node bearer 调用该入口；MCP/模型不持有 Node bearer。显式 Link SEND 还用当前 Session 凭据的 `whoami` 核对原生 Session ID、Endpoint 和 binding epoch，且 Directory 列表不公开别人的原生 ID。Node Join 桥对 guest 身份仍只核对本地记录与绑定；另有独立真实 Codex 测试验证两个 owner Thread 的 sealed Link Ask/Reply 连续性，但不覆盖 Android guest enrollment、双物理 Node 或无人值守唤醒。Hub 自身不能独立观察模型是否消费了消息。

Hub 权威面板状态展示经验证 Node、Thread/Endpoint、可嵌套 Group、同一 Thread 的多组 Membership、可选 Monitor 和已授权通信连线；Android 只是其视图和操作入口，拖拽/连线每次都是有预期版本和权限预览的管理事务。Node 登录采用一次性设备码与用户在已认证 Android Client 上批准的绑定流程；Node 仍只主动出站，设备绑定不授予 peer 明文密钥。

Docker 演示至少有持续运行的 Hub、两个互不可直连的 Node、Alice/Bob 两个独立用户、A1/A2/MA/B1/MB/U、嵌套 Group 与多组 Thread。分别验证本机零 Hub、跨机一个 Hub、双用户双端授权、广播、断流/重启/重复/错误 ACK/撤权。容器测试只能证明隔离网络模拟；真实 Codex 原生连续性和双物理机/公网仍要单独记录。v2-D Task/Lease 与只读 v2-E 功能继续回归，不因拓扑改动而丢失。

## 2026-09-24 起按序执行的下一切片（当时计划）

以下保留当时的待办快照；此后同 Node、同组跨 Node 和跨 owner Link 的真实
Codex Ask/Reply 均已通过，跨 owner 结果限定同机两个逻辑 Node 与受控 resume。
当前验收状态及未覆盖边界见上文和[原生验收记录](architecture-v2-native-validation.md)。

1. **跨 Node 密文 RPC 收尾（代码已连通）**：双 owner 显式 Link 与同 owner、同 Group 路径均经 MCP durable outbox、本机受信 Node 桥、端点加解密和一个 Hub Relay；Hub Store 原子保存 REQUEST/REPLY 状态与密文，Node claim/注入前复查当前授权，回复按原 request 关联。Hub 不调用 Control。Store 全包/定向测试、Node-only Hub HTTP 授权测试与当前同 Node fake full-chain 均通过；fake queue 不能证明真实模型消费或双物理机连通。跨 Node Group 运行要求 Node 上另行设置并钉住 `CICADA_HUB_ID`；设备码流程尚未自动写入此值。
2. **真实原生与隔离网络验收**：用现有官方 shell 安装的 Codex CLI 和两个相互不可直连、只出站连一个常驻 Hub 的 Node 容器，分别记录两个 owner 的原 Session ID、Endpoint ID、请求/回复 ID、Hub 中的密文模式及 Control 调用计数；有条件再上两台物理机。真实模型未运行时明确标 `NOT_RUN`。
3. **同 Node 同 Group sealed 单播原生验收**：Node+Session Guard 解析同 owner/同 Group/同 Node 的当前路由；MCP outbox 经本地 Unix socket 把 Endpoint 密文写入 Node SQLite request/message ledger；Node 在解密入 inbox 和原生 queue 前重新查权，撤权终止待投递行，不确定注入不盲重试。fake Codex ASK/REPLY、撤权、Guard 503/重启恢复和 `INJECTION_UNCERTAIN` 不重试测试通过；Hub Guard/Directory 仍可在线参与授权读取，但没有 Hub Relay 消息路由，也不构造 Control 业务。修复 `cicada_receive` 旧 Hub 路径后，`TestMCPSealedSameNodeGroupAskReplyNative` 在一个真实 Node 的两个原生 Thread 上由 gpt-5.5 完成 Join、ASK、B 原 Thread MCP Reply、A 原 Thread 收到结果与上下文断言，退出码 0；精确 ID 与命令见 native-validation。测试驱动从 `thread.started` 绑定 Session ID 并通过受控 `codex exec resume` 投递，不能证明全局 Codex MCP 自动发现或无人值守唤醒。下一步验同组跨 Node 真正 native 路径和双物理 Node；旧或未 sealed-capable Session 仍可能走历史明文路径，sealed Session 遇到不支持操作不降级。
4. **Group 广播与剩余可靠性**：在单播 E2EE/本机直达稳定后做固定成员快照、每收件人独立密文/Delivery、背压、用户经 Monitor 的可信批准来源；Node 子树离线备份已完成；下一步补设备级恢复与单调计数对账，并验收运行中 Worker fencing。

每步保持 Go 全包回归可运行；部分完成只标该切片，不能把 fake Codex、同机逻辑隔离或旧 MA→MB 演示冒充真实原生、双物理机或新版广播完成。

### 可靠性切片：Node 一致点备份已落地，重新联网对账仍待实现

当前 `migration backup` 只管理 Hub StateDir 的 SQLite/文件快照，不能替代 Node 备份。Node 的 `nodes/node-{id}` 下分散保存 `identity.json`、`relay.token`、`endpoint-keys/`、`node-crypto-state.sqlite`、远端 `inbox.sqlite`、本地 `local-messages.sqlite3`/`local-inbox.sqlite3` 和 `relay-journal.json`；MCP Session/outbox 与 Codex 原生 Session 记录还可能位于各自独立的状态目录。若只复制其中一个数据库，会破坏 outbox、重放计数、原生注入状态与密钥的对应关系。

本轮已给 Agent 建立单实例锁，并让 Agent 与两个独立的 Node 子树写入入口服从离线维护锁。`cicada machine backup/verify/restore` 在独占锁下对 Node 子树的 SQLite WAL 做 checkpoint，复制私钥、身份、账本和 inbox，生成无正文/私钥的摘要清单，并将校验过的副本原子发布到私有目录。恢复只写入新/空目标，并写入阻止 Agent 启动的 `recovery-pending.json`。Hub `migration backup` 现在明确跳过 `nodes/`，不能代替这套 Node 子树备份。

下一步是恢复后对账与安全重新联网：以 Hub 当前 Node 绑定、SessionBinding epoch、Node outbox/replay 水位、原生注入不确定项和可能仍运行的旧进程为依据，决定是否前滚、隔离或人工处置。Codex 原生 Session 与 MCP outbox 不在 Node 子目录时，必须在同一维护窗口单独纳入设备级恢复计划。当前没有自动化对账或生产 Node 恢复演练，不能把隔离副本称为完整 Node 恢复。
现在已在 Node 子树之外持久登记“此 Node 正在恢复”，Agent 启动时同时核对该登记与子树内 `recovery-pending.json`；误删子树内标记不会绕过启动门。崩溃可能留下孤儿登记并安全地阻止启动。下一步仍须建立 Hub 绑定、SessionBinding 和加密/重放水位对账后的受权解除隔离协议，不能仅靠删除标记。

## 每步共同的安全与验证门槛

MCP、HTTP、CLI 与后台重试进入同一 Guard/权威状态服务；sender/group/role/approval 只由可信绑定和管理授权推导。所有 Node/Hub 路径记录 message/request/link/endpoint/epoch/attempt 状态，不默认记录正文。保持 `go test -count=1 ./...`、`go vet ./...` 和相关集成/真实原生脚本绿色，单独汇报未运行或受阻项。用户未提交改动、历史凭据、真实密钥、生产部署与远端分支均不作为清理对象。
