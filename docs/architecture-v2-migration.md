# Architecture v2.3 数据与协议迁移

## 2026-09-27 M1 Network migration gate（有界基础门禁通过；整体未完成）

M1 从干净 Hub schema v34 之后做 additive migration，不改写旧 Endpoint、Principal、
Group、Thread、Message、Request、Receipt、Approval、Link/Contact、owner key、密钥、
ratchet 或 replay 计数。迁移须先经只读 inventory 与明确 Group→Network 映射，再 prepare、
逐项 approve，最后执行一次单向 activation；Git 回滚不恢复 SQLite 或外部计数。

schema v35 已在有界 M1 基础检查点实现；当前 Core 门槛为：

| 对象 | 目标语义 | 必须保留/拒绝 |
|---|---|---|
| Hub scope ledger（v35）`network_mode_v2` | 单行 mode 从 `PREPARING` 单向转至 `ACTIVE`。Prepare 阶段只记录候选；批准映射后，该 Group 立即收紧为 Network Guard。 | 不允许回到旧 mode；旧二进制未经验证不能连接已激活 schema。 |
| `network_group_mappings_v2` | 每个既有 Group 记录唯一映射候选、`PENDING`/`APPROVED` 状态、Group 版本及原因。Prepare 不修改 Group；Approve 以预期版本 CAS 校验父子 Group 属于同一 Network，并只允许给空 `groups.network_id` 赋值。映射一经写入不可静默变更。 | 缺失、多个候选、跨 Network 父子、已有授权会扩大的映射保留为 `PENDING`，不按 Owner 机械拆组或把所有 Group 并入大 Network。 |
| `groups.network_id` | 仅在显式批准后保存归属；Group 只属于一个 Network。 | 不通过 `network_id` 请求参数或同名 Group 推断权威归属。 |
| activation | 单一事务确认所有旧 Group 已有一致 APPROVED 映射，或保持 `network_id` 为空且有显式 pending quarantine，再将 Hub mode CAS 为 ACTIVE。 | 未确定归属的旧 Group 在激活后 fail closed；Network 新 API 自启用起严格 Guard，不依赖 Hub 总 mode。 |

当前只读 dry-run 给出 Group 映射状态、成员、Link、Group key grant 和 pending receipt 的有界计数，不输出消息正文、密钥、凭据或完整敏感 payload。源/目标 digest 与更完整的关系摘要仍属 M1 验收缺口，不能将现有报告称为完整迁移清单。Prepare/Approve/Activate 的重复调用须幂等或以明确版本冲突拒绝；备份与 schema ledger 要覆盖失败重试。先保全 pending 数据，不能删除已有请求来“清空迁移”。

`PREPARING` 期间尚未映射的旧 Group 仍属于 `LEGACY_UNSCOPED`，不能宣称已有 Network 隔离。某 Group 一旦显式 `APPROVED` 并写入不可变 `network_id`，它从那一刻起就在激活前应用严格 scope Guard；旧 Group Session 若没有当前 Network 注册必须拒绝。仍为 `PENDING` 的旧 Group 在激活前可保留原有旧路径，但不享有新租户隔离。Network-scoped API 从引入起始终严格 Guard。

Activation 将 Hub mode 单向切到 `ACTIVE`，所有仍未映射的 PENDING Group 此后 fail closed，旧 API 也必须从认证上下文取得并校验当前 Network scope。无法映射或不能在当前 Guard 下复验的操作拒绝。迁移保留 activation 前排队的 delivery/message/request/receipt 行和原 ID；后续新 Network grant 不会追溯授权这些旧操作的 claim、投递或历史读取。它们须经过逐项重验、显式重新授权、取消或隔离，不能自动续送；清理也不得删除原始审计数据。

有界基础检查点 `b0081a0` 的独立 Docker Client 与 Network suite 均通过；测试修正提交 `f9d3c7e` 仅把旧迁移测试的 ledger 预期从 v34 补至 v35，随后完整 Store 包复验通过。合成 v34→v35 测试比较了选定的 Client owner key、设备、nonce/replay、Monitor 批准密文、Group key grant、Principal、Group、Endpoint 和原生绑定表，确认 v35 不自动映射 Group 或创造 Network 成员，并能继续授权历史 Monitor 密文投递；它不证明所有历史 ledger 均已覆盖。无 Network enrollment revision 的旧排队消息及原 ID 被保留，在映射后缺少新 scope 证据时 fail closed。Client v1.3 `group.create` 没有 Network selector，ACTIVE Hub 拒绝缺少 Network 的新 Group 申请；默认 PREPARING Client gate 不证明 ACTIVE 兼容。完整证据与未完成矩阵见 [M1 验证](network-m1-validation.md)。任何真实 StateDir 迁移均需另行安排停写、一致备份与人工审核，本轮未执行。

## 2026-09-27 Hub v34：consent 元数据与 Monitor intake 限额

`v2.client.monitor_broadcast_intake_limits` 先补充现有
`user_monitor_broadcast_v2` 的 `consent_digest` 与 `preview_json`，再创建
`user_monitor_broadcast_v2_notice_cursors` 和三条 owner/device/status/expiry
索引。新 notice scan index 可按有效期与 preview ID 做有界 owner 范围分页；迁移
随后删除已被它替代的 `user_monitor_broadcast_v2_active_notice_idx`。既有 preview、
批准、设备、密文、recipient snapshot、结果与 replay 记录均保留，不重写授权事实。

Admission 对仍有效的 `PREPARED`、`APPROVED`、`DISPATCH_AUTHORIZED` 行实施
16 条/owner-device 与 64 条/owner 的容量检查。Prepare 精确重试先查到已有请求后
直接返回，不再占用槽位；只有记录过期才释放容量，设备撤销不删除未过期历史状态。
限制只作用于新 intake，不限制既有状态的查询/事实回执。候选扫描游标只记每个 Node
上次检查的有效期/preview 位置，不授予授权、不确认送达，也不丢弃旧 ledger。

迁移 apply 会调用相同 v34 中的 consent schema initializer，再创建限额 schema；版本
验证检查 cursor table、两个 consent 列以及三个必需索引。`TestUserMonitorBroadcastV2LimitsMigration34PreservesLedger`
从 v33 形态重开合成数据库，验证既有 PREPARED preview/snapshot 保留、列和索引出现、
旧通知索引移除。旧版本对 v33 ledger 上限的 fixture 已更新到 v34。整仓 Go tests/vet
通过后，Confirm response projection/OpenAPI 与 inactive Group 拒绝两项 review 修正
通过受影响的 Control/Server 全包测试、vet 及聚焦 race 复验；Store Monitor race 也
通过。只待干净 artifact 与最终 Docker 门禁。

Client `client-hub-v1.3` 操作目录已通过本地一致性检查，但最终协议包 manifest、干净
源码 commit 与 Hub image metadata 尚未冻结。本迁移说明不表示运行中的 Hub 已升级；
部署升级仍按 Hub/Node 分离备份流程操作，不对共享开发 Hub 做门禁或替换。

## 2026-09-26 Hub v33：逐收件者结果证据

`v2.client.monitor_broadcast_recipient_outcomes` 增量增加
`user_monitor_broadcast_v2_recipient_outcomes`，从原固定快照派生最多 32 个
稳定子操作/消息 ID。旧已预留派发的行仅补 `PENDING` 槽位，表示尚无合格结果
上报，不声称从未发送。迁移可重入且保留原批准、密文、设备与身份记录。

当前 Node + 原 Monitor SessionBinding 才能上报最多 8 项事实；过期/设备撤销
不抹去已经发生的投递，但旧绑定不能覆盖新 owner。`FAILED → UNKNOWN → ACCEPTED`
只单调前进，本地接受明确为 `NODE_REPORTED`，远端接受必须核对对应 Relay
密文记录才写 `RELAY_PERSISTED`。这些状态都不证明模型消费或业务结果通过。

`TestUserMonitorBroadcastV2OutcomeMigrationBackfillsV32Dispatch` 将一次性库降为
v32 状态再重开，验证 `DISPATCH_AUTHORIZED` 原行、快照、摘要、稳定 ID 与密文
均不变，新收件者行只为 `PENDING`。结果读取目前是内部 Node/Store 协议，未提供
给 Client 的 `status` RPC；Client 撤销后的 Node 事实报告也不等于原 Client 还能
读取状态。

报告丢失后使用同一个操作和子消息 ID 重试；若原批准或 SessionBinding 已
失效，禁止借对账重新发送。尚未收到有效报告的槽位仍不能汇报成功；超期后的
独立 Node 结果补报/恢复 UX 仍需后续接线。

## 2026-09-26 Hub v32：原登记证据与管理通知回执

`v2.client.monitor_broadcast_delivery_evidence` 增量增加
`client_device_enrollment_proofs_v2` 和
`user_monitor_broadcast_v2_notice_receipts`；不重建设备或密钥，不更改原 nonce
和 replay 状态。新设备登记事务保存准确签名 Grant、摘要、原登记时间。
旧设备只能通过与原 nonce 摘要完全匹配的原 Grant 重试补回证据；没有该文件时
旧 Client 操作仍可用，新增 Monitor 密文打开明确拒绝，不签发替代 Grant。

历史登记时间精确到秒：验签在该秒表示的时间区间与签名有效期交集中检查，
保留原始时间字符串；新登记使用纳秒时间格式。Hub 与 Node 共用同一时间精度
校验函数，不用当前时间替代历史登记，也不虚构更精确的时间。

通知回执区分 `NODE_ACCEPTED`、`QUEUE_ACCEPTED`、`INJECTION_UNCERTAIN` 和
`FAILED`。它们描述管理通知，允许在派发批准消费之前记录；不能用作广播
投递完成凭据。Node 凭据和当前原 SessionBinding/epoch 约束回执，撤销或
过期后的事实记录不重新授权发送。Node 的独立
`monitor-broadcast-inbox.sqlite` 复用已有持久注入日志与维护锁下的离线备份。

升级前仍须使用已有 Hub/Node 分离备份流程；这不是对运行中状态的热备份
支持。Client wire 和 `client-hub-v1.2.1` 的公开操作未改变。

## 2026-09-26 Hub v31：Monitor 广播授权基础

增量迁移 `v2.client.monitor_broadcast_authorization` 新建
`user_monitor_broadcast_v2`，关联现有设备请求与不可变广播快照，保存可信
设备来源、准确内容/接收范围摘要、短期限、密封正文及单次派发授权状态。
不改写历史 Endpoint、Session、Goal、Contact、Approval、密钥或重放计数。
签名验证成功不是授权，派发授权也不是原生消费回执。该内部基础尚无公开
Client 操作，合同仍为 `client-hub-v1.2.1`、外层 wire 仍为 v1。

升级前按现有一致点备份/验证流程保存 Hub StateDir；Node 子树和外部 MCP/
Codex 状态分别备份。不要删除迁移账本或回退密钥计数。v31 数据应向前修复；
旧二进制未验收读取新授权状态，不能直接复用已升级 StateDir 做降级。
旧 Federation 业务写入口退役不删除其请求、结果、消息和密钥历史；新通信
使用已授权 Endpoint 连线与 Node 密封路径。

## 2026-09-25 Relay/Node 语义修正（无 schema 迁移）

本切片没有提高 Hub 或 Node 数据库 schema 版本，也没有重写历史消息、Endpoint、
Group、Goal、Contact、Approval、密钥或 replay 计数。Relay 在既有
`relay_v2_receipts.layer` 文本列记录 `CODEX_QUEUE_ACCEPTED` 和未来可核实的
`NATIVE_THREAD_RESUMED` 审计层；旧回执原样保留。新 Node 代码只把
`codex queue` 的成功视为队列接受，保留原有本地
`CONSUMPTION_UNCONFIRMED` 行的读取方式，不据此推断模型消费。旧数据中的
`RUNTIME_INJECTED` 是当时实现写出的历史记录，迁移不会倒推或伪造新的
原生唤醒证明。

sealed claim 现在依据 Endpoint 的精确目标 Group Join 和 Principal Membership，
不再要求目标 Group 等于 `SessionBinding.group_id` 的首次 Join 投影；Endpoint ID、
native Session、binding epoch 与已有消息/密文均不变。原生唤醒授权新读接口
仅准许 PLAINTEXT 当前 attempt；sealed Link 继续使用其专用双边授权接口。
升级时保持原 StateDir 与 Node 私有账本，先按既有流程一致点备份；不要删除或
重建数据以获得这些代码语义修正。

## Client–Hub v1.2.1 Endpoint 证明合同勘误

v1 EndpointKeyAttestation 的 Go 签发和验证自实现起均使用域分离字节加完整
有序 compact JSON，并在末尾包含 `"signature":null`。旧 v1.2 wire 文档误写
为省略 signature；v1.2.1 只修正跨仓合同与公开合成向量，不改变实际签名算法、
证明原始字节或数据库 schema。现有 Endpoint key candidate 的证明摘要、
owner Group/Link Grant、Node pin、Contact、私钥和 replay 计数保持原样。
Client 必须按新固定包独立验证完整证明后才签新 Grant；旧固定合同的
“省略 signature”实现不得被当作兼容验签路径。无需执行数据迁移或轮换密钥。

## 2026-09-24 远端 Node Worker 审批增量

Hub schema v30 `v2.node.worker_approval_bridge` 在既有 `approvals` 表增量添加
`source_node_id`、`worker_attempt`、`request_id` 和 `request_hash`，并为非空
Node 请求建立唯一幂等索引。旧 Approval 行保持原 ID、正文、决定和状态；新列
使用空 Node、零 attempt 的兼容默认值，不把旧本地审批伪装成远端请求。
Node 必须以当前设备绑定凭据、Goal owner 和 Worker attempt 创建/领取审批；
相同请求 ID 与内容恢复原记录，内容变化返回冲突。旧 attempt、终态 Worker、
撤权或失效 owner key 不能获得新的决定；pending 项在任务入结果、重新领取
或撤销时取消。迁移不触碰 Endpoint、Contact、Group 密钥和 replay 计数。
旧库升级及上述状态转换由 `TestRemoteWorkerApprovalMigrationPreservesLegacyApproval`
与 `TestBoundNodeWorkerApproval*` 覆盖；真实 Codex 审批 turn 仍需独立验收。

## 2026-09-24 Hub Client 恢复增量

Hub schema v29 `v2.client.request_recovery` 增量创建
`client_device_request_recovery_v2`，每个新接受的 Client 请求在同一事务内获得
恢复标记。正常响应先在事务中把单调响应序号预留给原请求，再进行加密；若进程
在预留后、缓存前崩溃，恢复使用原序号。`UNCERTAIN/FAILED` 的恢复通知密文
先缓存后发送，重复请求返回相同密文。v18–v28 历史请求不回填标记：未知序号
不可安全猜测，旧不确定请求明确返回 `RECOVERY_UNAVAILABLE`。迁移不删除
Client 设备、owner key、Grant nonce、请求、密文响应、Goal、Contact 或其他
密钥/replay 行。升级前须备份并验证 Hub StateDir；Node 私钥和账本另做一致点备份。

本增量同时把跨仓 catalog 修订到 `client-hub-v1.2`，packet wire 仍为 v1，
新增 `/v2/client/rpc/recover` 与 manager-only `goal.result`。旧 Client 可以继续
已实现操作；要解除 UNCERTAIN pending，必须按新契约实现并验证 Android 逻辑。
下节 v1.1/v28 描述前次构建的历史快照。

## 2026-09-24 Client 契约与构建来源整理

这是 2026-09-24 的历史版本候选快照（当时为 `0.4.0-dev`）；Client packet wire 仍为 **v1**，新增
`contract_revision=client-hub-v1.1` 与 `catalog_sha256` 元数据。摘要只覆盖
嵌入的 catalog 原始字节，不替代完整协议包各文件摘要。外层新增字段与原有
operation 名称兼容；角色目录改为单一来源，不扩大 owner 或资源权限。
旧 Client 可以继续其已验证的操作子集，新增 Group key 操作需独立实现验签。

前次构建的 Hub schema 为 **v28**、Node crypto DB 为 **v5**；该历史快照没有数据迁移、算法
切换、身份重建、密钥轮换或 replay 重置。协议向量中的私钥明确为公开合成
测试材料，禁止用于初始化任何真实部署。轻量 `docker/Dockerfile.hub` 不含
Codex 或模型配置；真实 Node/模型验收继续使用原有相应运行环境。

开发启动脚本不会自动替换已有同名容器；一次性互操作脚本另建独立状态并在
结束后清理。现有部署升级仍需明确安排停机与一致点备份，不得通过删除 state
目录达到“干净安装”。登记丢响应与不确定 RPC 的恢复语义尚未升级，详见
[联合开发规范](client-hub-development.md)。

2026-09-24 增量：Hub schema **v29** 新增 Client 请求恢复映射，在接受新请求时原子预留响应序号和密文恢复通知；历史请求不回填。此前 v28 新增的同 Group 广播快照仍保持不可变，只包含当前授权的 Endpoint、绑定版本与公开 key 证据，不保存广播正文；来源须同时具备 `message.broadcast` 和 `message.send`，每个目标须具备 `message.receive`，且所有目标同 owner、同一精确 Group。重复 `broadcast_id` 返回原快照，不重新枚举成员；最多 32 名接收者，不自动包含发送者，也不向父组、子组或该 Thread 的其他 Group 扩散。既有 Endpoint、Contact、Goal、Approval、消息、密钥及重放计数不回填或重置。Node 本地收件库新增可信 `kind/request_id/reply_to/sender_endpoint_id` 元数据列；旧行仅在有精确匹配的可信投递证据时补齐，不能据此推断旧行所属 Group。广播迁移与回滚测试见 `TestSameGroupBroadcastV2*`、`TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable`。

2026-09-24。当前 Hub 版本化迁移推进到 **v30**，并保留只读 inventory、显式 backup/verify/restore。v11 建立 Endpoint-Group 多对多关系及旧 READY 记录回填；v12 添加不继承权限的 Group 父子关系；v13 保存不可路由的 CommunicationLink 提案；v14 增加 Endpoint 公钥候选；v15/v16 增加用户批准公钥与 Link Grant；v17 新增 Relay 密文 payload 表；v18 新增 Hub Client 设备与请求重放；v19 新增异步 Client Intent；v20 新增 Node 设备码及 owner 绑定；v21 新增 owner 作用域状态差异游标；v22 新增双端公钥绑定的 Link Grant；v23 为 Client Intent、Goal 和机器增加显式 owner 列以收敛 Node Worker 路由；v24 为 Goal 增加生命周期版本；v25 在事务内扩展 Client 状态差异表的允许类型并保留原记录及游标；v26 增加一次性外部 Thread 邀请状态；v27 增加同 owner Group 范围内的 Endpoint 公钥签署记录，并由新增 Node-only Relay 路由执行当前授权复查；v28 固定同组广播收件快照；v29 增加新 Client 请求的密文响应恢复映射；v30 增量保存 Node Worker 审批幂等键与 attempt。v14–v30 不回填、改写或轮换旧 Endpoint、Contact、私钥、ratchet 或 replay 状态；既有业务记录和旧 keys 保持原样。显式第二组 Join、逐组 Leave、作用域授权及同机双容器真实原生多组 Ask/Reply 已验证，但旧 MA→MB 退役或明文 Fabric 消息的整体迁移**尚未**完成。不要用删除表、重建原生 Thread、重置 Contact/密钥/ratchet/replay 状态来达成新架构。

## 当前已实现的账本

2026-09-24 的 Node 单播新增 Node 专属 `local-messages.sqlite3` 与 `local-inbox.sqlite3`，由 `internal/nodelocal` 和 `internal/nodeinbox` 管理。前者只存 Endpoint 密文、不可变路由快照、异步 ASK/REPLY 相关性、截止时间与本机 handoff/撤权终态；后者在 Node 受控环境内保存解密正文和分层原生注入状态。`nodelocal` 新库使用 schema v2；已有 v1 本地账本在单个事务内增量加撤权终态列和索引，保留原 ASK 密文/请求行，版本只在成功后推进，未来版本拒绝打开；合成 v1 文件升级测试已通过。`nodeinbox` 以 `CREATE TABLE IF NOT EXISTS` 增加 Group 映射表和注入可见序列表/触发器，不重写投递正文或状态；旧已注入记录仅获得稳定读取序号，因没有可信 Group 映射而不会出现在 Group-scoped `cicada_receive` 中。新保存的记录只有写入可信 Group 映射后才可按当前 Endpoint/native Session/binding epoch/Group 查询；未完成原生注入的记录不展示。MCP 使用 `OpenReadOnly` 读取，不初始化 schema、不执行启动恢复或状态转换，所以读取不会释放 claim 或改写 `INJECTION_UNCERTAIN`。Node Agent 已为显式 Link normal/recovery `Save` 补入受当前授权派生的 GroupID，并覆盖最终注入前 exact-attempt 复查；node inbox 与同组跨 Node fake full-chain 定向测试通过。历史无可信 Group 映射记录仍不可见，不按旧 Link 或 Endpoint 猜归属。以上 Node 表不修改 Hub schema，也不回填、删除旧 Relay/Contact/Goal/Approval/密钥/replay 行。旧同组明文消息留在原历史路径；仅无 sealed-delivery 能力的旧 Session 保留 Hub receive/旧写路径，sealed-capable Session 不静默降级。`nodeinbox.Open` 拒绝非私有目录并将现有数据库收紧到 `0600`；升级前若 Node inbox 目录曾由旧部署创建为 `0755`，需先确认归属并将目录改为 `0700`，不删除数据库，WAL/SHM 同置于私有目录。Node 子树 backup/verify/restore 见下文；Hub `migration backup` 跳过整个 `nodes/`，历史 Hub archive 若含 Node 文件会被新 Verify/Restore 拒绝自动处理，需隔离后人工迁移。Node 备份只包含 `nodes/node-{id}/`，不包含位于子树外的 MCP session/outbox 状态或 Codex 原生记录，因此只是 Node 子树快照。恢复旧 Node 文件时先隔离联网、对账 binding epoch、密文 outbox/replay 序号和未确认原生注入，再决定前滚或手工处置，不能直接重放。

2026-09-24 的密文 REQUEST/REPLY 基础沿用 v17 `relay_v2_message_payloads` 和既有 `relay_v2_requests`、inbox/outbox/receipt 表；不新增 schema、不回填历史消息。Node-only sealed Ask/Reply/status/cancel 入口有当前 Node 绑定鉴权；MCP 原生会话闭环仍在验收，不能把该入口当成已完成的用户路径。旧明文 Request 继续按原 payload mode 读取；新密文 Request 只能走专用 sealed 状态读取与当前 Link 授权，不能从旧 Fabric 明文读 API 取出。

`internal/store/migrations_v2.go` 的 `schema_migrations_v2` 在 SQLite `BEGIN IMMEDIATE`/savepoint 下记录版本、checksum、状态、尝试次数、旧数据计数和校验摘要。版本依次为：

| 版本 | ID | 数据范围 |
|---|---|---|
| v1 | `v2.fabric.identity` | Principal、Group、Membership、SessionBinding 及旧 Endpoint 绑定列 |
| v2 | `v2.node.credentials` | Node credential digest |
| v3 | `v2.relay.delivery` | Relay request/outbox/inbox/attempt/receipt/cursor |
| v4 | `v2.gateway.federation` | 旧代表合同、邮箱、请求和结果 |
| v5 | `v2.relay.admission` | Ask admission 和 retry policy |
| v6 | `v2.artifact.scoped_access` | Artifact 版本引用与窄范围读取授权 |
| v7 | `v2.task.shared_responsibility` | Shared Task、依赖、原子 claim、结果/验收 |
| v8 | `v2.resource.authority` | 跨 Group 物理资源冲突身份、Lease、quarantine |
| v9 | `v2.task.handoff` | epoch-fenced 结构化 handoff |
| v10 | `v2.task.side_effect_ledger` | 副作用意图及对账事件 |
| v11 | `v2.fabric.endpoint_group_membership` | 独立 Endpoint-Group 加入关系；只回填旧 READY 且有明确 Principal Membership 的 Endpoint |
| v12 | `v2.group.hierarchy` | Group 父组列与索引；原有 Group 均保持顶层，不自动继承授权 |
| v13 | `v2.collaboration.link_proposals` | 新建 `communication_links_v2`；只允许 `PROPOSED`/`REVOKED`，不回填旧代表合同，不赋予 Fabric 路由权 |
| v14 | `v2.fabric.endpoint_key_candidates` | 新建 `endpoint_key_candidates_v2`；仅保存当前 Endpoint/Principal/Node/SessionBinding epoch 的自签名公开 key candidate，状态固定为 `CANDIDATE`，不 pin、不激活、不授予路由权 |
| v15–v16 | `v2.collaboration.owner_approval_keys` / `v2.collaboration.link_owner_grants` | 本地可信 owner 公钥与两侧 Link Grant；尚未赋予新端点路由权 |
| v17 | `v2.relay.sealed_payloads` | 新增密文 payload mode/BLOB；历史明文行保持原样 |
| v18 | `v2.client.device_identity_and_replay` | 持久 Hub ID、Client 设备授权/撤销、重放序号和密文响应缓存 |
| v19 | `v2.client.control_intents` | 持久 Client Intent 输入、QUEUED/RUNNING/DONE/UNCERTAIN 状态和重启对账；旧 Intent 行不自动归入新队列 |
| v20 | `v2.node.owner_device_code_bindings` | 短期一次性 Node 设备码摘要、owner/Hub/Client 设备与凭据版本绑定；Node bearer 明文只留本地，旧未绑定 Node token 不能访问 v2 Relay |
| v21 | `v2.client.status_change_feed` | owner-local 状态投影差异、持久序号与游标；只覆盖 Node/Endpoint/Worker/Goal/Group/Task，不复制旧任意事件正文 |
| v22 | `v2.collaboration.key_bound_owner_grants` | 当前 Link、两端原生绑定与 Endpoint 公钥候选的摘要由 Hub 计算；两侧 owner 分别签名并持久保存。v16 无公钥绑定的 Grant 只保留历史，不自动升级，也不激活路由 |
| v23 | `v2.node.owner_scoped_worker_jobs` | 给 `machines`、`goals`、`client_control_intents_v2` 增量增加 `owner_id`，旧行默认为空且不猜测归属；只让当前加密 Client session 派生的新工作通过 owner/Node/attempt 守卫进入 Node-scoped job API |
| v24 | `v2.client.goal_lifecycle` | 给 `goals` 增量增加 `lifecycle_version`，旧 Goal 默认版本 1 且状态原样保留；只允许 owner 对尚未领取的远端队列工作做版本化 pause/resume |
| v25 | `v2.client.status_approval_intent_deltas` | 在迁移事务内重建两张 status projection 表的实体类型约束，保留原行和 owner-local 游标；新增审批与 Intent 的有限元数据差异，不复制请求正文或结果 |
| v26 | `v2.collaboration.external_thread_invites` | 新建一次性跨 owner 邀请状态表；仅存 token 摘要、授权范围、当前来源绑定与消费状态。接受只建 `PROPOSED` Link，不改旧权限和消息表 |
| v27 | `v2.collaboration.group_endpoint_key_grants` | 新建 `group_endpoint_key_grants_v2`，只保存 owner 签署的同组 Endpoint 当前公钥/原生绑定清单、nonce 和期限；读取时重算 Node owner、Group、Membership、Join、Binding、候选和 owner key 状态。Node-only same-Group sealed Relay route 已消费该证据并逐次复查；旧消息、密钥及重放计数不回填或重置 |
| v28 | `v2.fabric.group_broadcast_snapshots` | 新建不可变的同 Group 广播快照和有序收件人表；只保存授权/绑定/公开 key 证据与摘要，不保存正文；不回填旧广播或旧成员。 |
| v29 | `v2.client.request_recovery` | 新建请求→预留响应序号/密文恢复通知映射；新请求接受时原子写标记，历史请求不回填。设备/Grant/nonce、旧请求及响应密文保持原样。 |
| v30 | `v2.node.worker_approval_bridge` | 在 `approvals` 增加 Node ID、Worker attempt、幂等请求 ID 与内容摘要；旧审批行保持原状。Node 只可对当前 owner 绑定且正在运行的同一 attempt 创建/领取决定。 |

`TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable`、`TestV2MigrationFailureRollsBackSchemaAndResumes` 和 `TestV2MigrationsConcurrentOpenSerializesLedger` 覆盖旧库升级、重复打开、注入失败及并发打开。版本账本保证 schema 操作可重试，不代表对象级映射、真实断电或生产恢复已验收。

Node-local `node-crypto-state.sqlite` 使用独立 schema 版本；本轮从 v3 增量升级至 v5。v4 为旧 pin 增加 `link_version`、清单摘要及合同/双侧 Grant 期限列，旧行默认 `link_version=0`，不能凭历史 pin 获得跨组授权。v5 增加 `node_crypto_owner_key_trust`，只保存经独立预期公钥与指纹核对的 Owner 公开身份、版本和终态撤销记录。升级不重置 Node 私钥、outbox、inbox 或 replay；v3→v5 的旧 pin 保留测试和定向 race 测试已通过。Hub v24 只给 Goal 加版本列；Hub v25 需要复制现有 status projection 行以调整 CHECK 约束，但不更改身份、消息或密钥表。

Hub 新增只读的 Node 凭据绑定证据查询：在同一个数据库事务中校验当前 Node credential/owner 绑定、Link 双端 scope、当前 SessionBinding、公钥候选及两侧 v2 签名 Grant，只向该 Link 一侧的 Node 输出公开清单和签名。Node 仍必须在本地独立验证 Owner key trust、合同/清单和两个签名；`PROPOSED` 证据不是路由许可。旧管理 bearer `/v1/communication-links` HTTP 路由已退役；同 owner Link 提案和撤销改走 Client 加密 `topology.apply`。旧 Link、Grant 和历史消息保留。

## v2.1 需要新增的迁移

以下列出 v11–v30 已新增的数据关系及仍需新增的目标 schema；其余概念名不是已存在的表名，实际命名以 migration 和测试固定：

1. **Endpoint-Group Membership**：v11 已建关系表、旧 READY 精确回填、Store/Service/MCP/HTTP 显式第二组 Join 和逐组 Leave；Directory/Relay/Node claim 按选定 Group scope 验证并隔离邮箱。保留 `endpoint_id`、`principal_id`、`binding_id`、native Session ID 与原消息引用；`fabric_endpoints.group_id` 和 SessionBinding 的 `group_id` 仍是旧主组投影。没有明确归属的旧 Endpoint 保持 `MIGRATION_PENDING_GROUP`，不自动加入全局组。同机双容器原生多组已通过；迁移断电与跨用户边界仍需单独验收。
2. **Group nesting**：v12 已添加 `groups.parent_group_id`，管理 API `PATCH /v1/groups/{id}/parent` 要求 `expected_version`；拒绝循环、跨 owner/trust domain 和过期版本。父子边仅用于组织/管理视图，不继承发现、密钥、消息或 Artifact 权限；旧 Group ID 保留。可视化拖拽尚未实现。
3. **CommunicationLink 与双方 Grant**：v13 保存同一 owner 下、两端有效加入各自 Group 的连线提案，记录 Endpoint、Principal、Group、owner、Node、动作、数据范围、方向、期限、所选 Hub、Membership/Join/Group 版本快照、合同摘要及版本化撤销。跨 Node 提案要求指定一个 Hub；同 Node 提案不得指定 Hub。v26 增加一次性外部邀请的跨 owner 提案；两侧各由自己的 Client 设备会话读取当前 key-bound 清单并提交 Grant。数据库状态仍只有 `PROPOSED`/`REVOKED`；单个管理 bearer、邀请 token 或仅一侧 Grant 均不能授权传输。现有生产 Guard 开放两个 owner、不同 Node、指定 Hub 的单收件人密文 SEND/ASK/REPLY，入队、领取和注入前均重查当前双侧证明。旧 MA→MB 合同不自动转为直连，保留原历史；同 Node Link 和广播仍未接通。
4. **Broadcast**：固定 Group/成员快照、不可变操作 ID、每个收件人独立 envelope/Delivery/receipt 和 retry 状态；同一 Endpoint 在多个 Group 时按固定 Group scope 去重，不传播到其他组。旧单收件人消息 ID/请求相关性原样保留。
5. **端点密文与密钥元数据**：v14 增加公开 key candidate 表/API；ML-DSA-65 自签名绑定 Endpoint、Principal、Node 和 SessionBinding ID/epoch。候选自签及 Join Session credential 不证明 owner 批准；v22 将当前两端候选 key、原生绑定和合同组成双侧签名清单。Node-local 独立 Owner key trust、清单验证和 scoped pin 已接入显式 Link SEND；MCP 经 Node 桥先写持久密文 outbox，再由 Hub 仅持久保存 `SEALED_V1` BLOB，目标 Node 将入站密文与 replay 原子保存，保留恢复坐标并在原生注入前复验。旧 replay-only 行不能当成可恢复收件，`INJECTION_UNCERTAIN` 不自动重投。旧 Contact/peer ratchet、sequence、信任记录原样保留；旧同组明文路径需明确标示保护范围，禁止跨组密文失败时静默降级。

`internal/e2ee/endpoint.go`、Endpoint attestation、v14 Hub candidate registry 与 `internal/nodekeys.CryptoState` 已经通过单收件人 Link SEND 接上用户签署 Grant、生产 Guard、Hub-blind transport 与 Node native queue。Hub 的 `migration backup/restore` 不包含 Node-local Endpoint 私钥，也不包含 `node-crypto-state.sqlite` 的 sequence/outbox/replay/inbox 数据；不得声称完整 Node 备份或恢复。v14–v17 Hub migrations 只增加迁移账本、候选、公钥、Grant 和 Relay payload 表，不改写旧业务表或旧 keys。Node DB v5 同时保存新入站记录的 replay 与原样密文，v1/v2 旧 replay-only 行继续显式要求对账。该 SEND 切片已有两个逻辑 Node/fake Codex 全链测试；Node 子树离线备份/隔离恢复已实现；上线真实 Endpoint 前仍需把外部 MCP/Codex 状态纳入设备级备份、完成恢复后单调计数对账，防止私钥/计数回滚造成身份或 nonce 错误。真实生产 Node 备份/恢复和双物理机原生验收未运行。

v15 新建 `owner_approval_keys_v2`，只存经 Hub 本地可信操作核对的用户公钥及版本化撤销状态；v16 新建 `communication_link_grants_v2`，保存精确合同两侧分别签署的证明、nonce 和接受时间。它们均为增量表，不回填旧提案为已批准，也不接入现有明文跨组消息路由。用户私钥由可信 Client 保管，不能放入 Hub 备份；本地 CLI 只是 Android 设备认证与 PQ 应用会话建立前的开发/恢复引导。若恢复旧 Hub 数据库导致公钥撤销或 Grant 状态回退，必须先隔离并对账，不能自动宣称安全重新联网。两个新迁移的中断回滚、重跑、旧数据计数对照与真实备份恢复分别记录，不能用 Git 历史替代。

v22 单独新建 `communication_link_key_grants_v2`，不覆盖 v16 原始签名和 nonce。新清单在同一个事务内由当前 Link、完整规范合同、两端 SessionBinding lease/epoch 与 Endpoint 公钥候选构成；各侧 owner 对同一清单摘要分别签名。v16 签名在新状态查询里显示为 `LEGACY_KEY_UNBOUND`，不能转成可信 Node pin。Hub 数据备份需要同时保留 v16/v22 历史与撤销后的 owner key 行；恢复旧备份后必须隔离、对账版本/密钥/计数，不能自动开放路由。v26 的两个独立 owner 合成测试证明外部提案双方可分别签署且不能代签；Node 已能独立验证公开证据，当前单收件人 `SEALED_V1` SEND/ASK/REPLY 可依此路由。

每个新版本独立可重复运行并做 legacy count/digest、FK/integrity、旧 ID/关系和密钥状态对照。迁移可先创建新结构和只读映射，再切流量，最后退役旧写入口；**Git 历史不是数据备份**。旧 GroupGateway 表和历史请求可保留只读/导出，在新直达路径完成验收和对账后才删除旧运行 API。

## 已实现的备份工具与操作边界

CLI 提供：

```bash
cicada migration inventory --state-dir PATH
cicada migration backup --state-dir PATH --output NEW_BACKUP_DIR
cicada migration verify --backup BACKUP_DIR
cicada migration restore --backup BACKUP_DIR --state-dir NEW_EMPTY_STATE_DIR
```

这些 Hub 命令要求显式路径。Hub 备份排除 `nodes/`；带 Node 文件的旧归档会被当前 Verify/Restore 拒绝，不会删除归档或自动忽略其中数据。需先隔离并人工迁移到 Node 专属备份流程。`TestStateBackupRestorePreservesSQLiteIdentityAndReplayState` 与 `TestMigrationBackupCommandOutputBackupVerifyRestore` 对**合成 StateDir** 验证 Hub 数据完整性；尚无真实生产 StateDir 演练。

Node 子树有单独的离线命令：

```bash
cicada machine backup --id NODE_ID --state-dir PATH --output NEW_BACKUP_DIR
cicada machine verify --backup BACKUP_DIR
cicada machine restore --backup BACKUP_DIR --state-dir PATH
```

Backup 和 Restore 获取位于 `nodes/.locks` 的非阻塞独占维护锁；Agent 与直接 Node 写入者持有共享锁时，命令 fail-fast 并且不会发布输出。锁覆盖整个 Node 子树复制；对其中发现的 SQLite 数据库逐一执行 WAL 截断 checkpoint，持有 `BEGIN EXCLUSIVE` 到所有文件复制和源哈希复核完成。任何未 checkpoint 的 WAL、rollback journal、其他 socket、symlink、特殊文件、校验失败或已有输出目录都会使操作失败。Checkpoint 后的空 WAL 和可重建 SHM 不进入 payload，而在 manifest 中列明；根目录的陈旧 `join.sock` 也只在独占锁下跳过并列入 manifest。备份目录与文件分别使用 `0700` 和 `0600`，manifest 只存 Node ID、相对路径、大小、SHA-256 与 SQLite 完整性元数据，不存文件内容、密钥或凭据。MCP session/outbox 状态和 Codex 原生记录位于 Node 子树之外，明确不属于该命令边界。

Restore 只允许同一 Node ID 的目标子树不存在或为空；发布前先在 `nodes/.recovery-pending/` 写入并同步外置私有隔离登记，再原子发布带 `recovery-pending.json` 的副本。Node Agent 在维护锁内看到任一隔离信号都会拒绝启动；误删子树内标记不能直接放行。发布前失败会清掉本次登记，发布可能已提交时保留登记；崩溃可能留下需未来受权对账处理的孤儿登记。该命令建立的是隔离的 Node 子树副本，不代表完成了原生会话恢复或外部状态对账；重新联网前须按 Node binding epoch、密文 outbox/replay 序号以及未确认注入/副作用逐项 reconciliation，不能直接重放或恢复旧计数。`TestNodeBackupWALRestoreQuarantineAndManifestPrivacy`、`TestNodeBackupRejectsLiveAgentAndDirectWriter`、`TestNodeBackupCorruptionAndExtraWALRefuseRestore` 覆盖合成 Node 树与 WAL、锁竞争、私有 manifest、损坏拒绝及隔离恢复；尚无真实生产 Node 或物理设备恢复演练。

`cicada machine recovery inspect --backup BACKUP_DIR --state-dir PATH` 只做恢复前检查：持有同一独占维护锁，核对 marker 中的 manifest 摘要、恢复文件清单/哈希及 SQLite 完整性，并以 immutable read-only 连接给出本地序号、outbox/replay 与 inbox 状态的有限计数。它不打开会在启动时恢复状态的 `nodeinbox.Open`，不启动 Agent、不连 Hub、不改数据库或 marker，且始终报告仍处于 quarantine。Hub 对旧 binding epoch 的接受情况、服务端/对端 crypto counter 高水位、Node 子树外的 MCP 会话/队列、Codex 原生 Session 所有权及模型是否消费消息都无法由该离线副本证明；不得依据 inspect 输出自行清除 marker 或启动恢复的 Node。缺少/损坏 marker、文件或 manifest 声明的数据库会 fail closed。`TestRecoveryInspectIsReadOnlyAndReportsUncertainty`、`TestRecoveryInspectRejectsRestoredTreeCorruption` 与 `TestRecoveryInspectRejectsMissingMarker` 覆盖合成状态；它们不构成生产恢复授权或原生会话连续性证明。

备份恢复不是随意回滚：签发新凭据、递增 binding/owner epoch、推进 E2EE counter 或触发原生/外部副作用后，恢复旧状态可能重用计数或失去对外部事实的认知。此时须隔离联网，验证密钥与计数的新旧序关系，对未确认注入/副作用做 fencing 和 reconciliation，然后前滚。不能删除 SQLite 行或重置信任让测试变绿。

## 验收状态

| 项目 | 当前状态 |
|---|---|
| v1–v13 additive schema、ledger、重复运行与并发打开测试 | 已实现并测试；v11 精确回填、v12 父子关系、v13 提案中断回滚/重跑及旧记录保留另有专项测试 |
| v14 Hub key-candidate additive migration | 只新增候选表；合成旧库中断/重跑和旧状态保留测试通过，真实生产库未演练 |
| v15 Hub owner approval key migration | 只新增独立用户公钥表；合成旧库中断回滚/重跑、撤销不可静默恢复和旧状态保留测试通过 |
| v16 Hub bilateral Link Grant migration | 只新增双侧签名证明表；合成旧库中断回滚/重跑、成员与原生 binding epoch 失效测试通过；旧提案仍不可路由 |
| v17 Hub sealed Relay payload migration | 只新增独立 mode/BLOB 表；旧消息保持明文标记或兼容读取，专用 `SEALED_V1` 与旧读取隔离。两个逻辑 Node/fake Codex 的正向单收件人 SEND 已接入本地 Seal/Open、原生 queue 参数与分层回执；真实 Codex/双物理机待验收。 |
| v18 Hub Client 设备与请求迁移 | 新增持久 Hub ID、设备公钥/owner Grant nonce、会话 epoch 与序号、operation ID/密文 digest/状态及密文响应 BLOB；不保存 Client 私钥或请求明文。失败回滚/重试、旧状态不丢与 Hub ID 重启稳定测试通过。新的 Control PQ 私钥位于 `StateDir/e2ee/client-control-identity.json`，须和 SQLite 一起备份；丢失时旧 Client 无法信任新密钥。 |
| v19 Hub Client Intent 迁移 | 新增 `client_control_intents_v2`，接受记录与普通 Intent 同事务创建；输入仅供 Control 执行，通用 JSON 不泄露原文。重启只恢复 QUEUED，RUNNING 与普通 Intent 终态对账后标 DONE，否则标 UNCERTAIN；合成旧库保真、并发 Claim 和定向 race 测试通过。 |
| v20 Node 设备码绑定 | 新增 `node_device_binding_requests_v2` 与 `node_owner_bindings_v2`；Hub 只存短码/Node bearer 摘要，Client 经 PQ RPC 预览、确认、列出和撤销；旧未绑定 Node token 不再认证 v2 Relay。合成迁移中断/重跑、并发单次确认及撤销测试通过；真实远端 Node 与 Android 配对待验收。 |
| v21 Client 状态差异游标 | 新增 `client_status_state_v2`、`client_status_streams_v2`、`client_status_change_events_v2`；owner-local 序号和重启续读测试通过。此为快照差异，不是完整事件推送，轮询间瞬态仍不可见。 |
| v23 Client→Node 工作归属 | `machines`、`goals`、`client_control_intents_v2` 增加默认空值的 `owner_id` 与索引。旧记录不自动归属；已认证 Client session 接受的新 Intent 才传播 owner。当前绑定 Node 的 bearer、owner、机器、Worker→Goal、attempt 在任务领取、快照关联和结果入库时重验；新 Node API 不把旧 ownerless 任务按机器 ID 偷偷领走。合成迁移、撤权、并发与 HTTP 链路测试结果见状态文档。 |
| v24 Client Goal 生命周期 | `goals.lifecycle_version` 旧行默认 1；已认证 owner 的远端队列任务可版本化暂停/恢复，Node 领取的旧/新入口均检查 paused。正在运行的 Worker 不被假报暂停。 |
| v25 Client 审批/Intent 差异 | 迁移事务内调整状态差异表的实体类型约束并逐行保留旧投影/事件；审批和 Intent 仅生成有限状态元数据，未覆盖轮询间瞬态或完整推送。 |
| v26 外部 Thread 邀请 | 增量新增 `external_thread_invites_v2`；只保存 256-bit 一次性 token 的 SHA-256 摘要、来源当前成员与绑定版本、Hub、范围、期限和消费状态。接受在一个事务内重验两端 owner/Group/成员/SessionBinding/Hub，仅产生 `PROPOSED` Link。迁移中断回滚、重跑和旧身份/消息/密钥/重放记录保留已有合成测试；真实生产库演练未运行。旧 Link 不回填邀请或自动开放跨 owner 路由。 |
| v27 同组 Endpoint 公钥授权与 Relay | 增量新增 `group_endpoint_key_grants_v2`；同一 owner 对当前 Group/Endpoint/Node/SessionBinding 与候选公钥的规范清单签 ML-DSA，Hub 保存签名与 nonce。Node 独立验证签署并 pin 后，Node-only Hub route 提供 peer-key、SEND/ASK/REPLY、claim、status/cancel 和精确 delivery authorization；Store 的全包/定向测试及 Hub HTTP 授权集成测试通过。仍未证明两个物理 Node、真实跨 Node Codex 消费或重启后的生产恢复。 |
| v28 同组广播快照与本机收件元数据 | 增量新增不可变的 `group_broadcast_v2_snapshots` 和 `group_broadcast_v2_snapshot_recipients`；来源必须同时具有 broadcast/send 权限，收件人只限同 owner、当前精确 Group 的 receive 成员。Node 本地 inbox 增加可信 kind/correlation/sender 元数据，不重写旧消息正文。Store 迁移/回滚、Hub HTTP 与两个逻辑 Node/fake Codex full-chain 通过；真实 native 广播及生产恢复未验证。 |
| 旧 Endpoint pending、READY 隔离旧 v1 API | 已实现并测试 |
| 合成 Hub StateDir inventory/backup/verify/restore | 已实现并测试；`nodes/` 被排除，含 Node 文件的旧归档自动 Verify/Restore 拒绝 |
| 合成 Node-subtree backup/verify/quarantined restore | 已实现并测试：锁竞争拒绝、SQLite WAL checkpoint/保留、私有 metadata manifest、损坏及未登记 WAL 拒绝、空目标隔离恢复 |
| 真实生产 StateDir 备份/恢复与重新联网对账 | 未运行 |
| 多 Group Endpoint 关系与作用域服务接入 | v11 additive schema、Store/Service/HTTP/MCP 定向测试和同机双容器真实原生多组通过 |
| Group 嵌套管理边界 | v12 additive schema、版本化管理 API 与防环/不继承 Fabric 权限测试通过；面板拖拽未实现 |
| 连线、广播、端点密文及 Android↔Control PQ 迁移 | v13–v29 先后加入提案、公钥候选、旧/新 Grant、独立 Client↔Control PQ、Node 设备码、外部邀请和同组广播快照；两个 owner 的显式 Link 与同 owner 同 Group 跨 Node 单收件人 SEND/ASK/REPLY 均接入 Hub 密文 Relay。同 Node 单播零 Hub Relay；sealed `cicada_receive` 读本地 scoped inbox。同 owner 同 Group 广播的 fake 全链已通过；真实 native 广播、用户经 Monitor 广播和双物理机验收仍缺。 |
| Node-local crypto-state 与完整备份/回滚 | sequence/outbox/replay 已接入显式 Link SEND；Node 子树离线备份/验证/隔离恢复已实现，但子树外的 MCP session/outbox/Codex 记录、真实 native crash recovery 与恢复后计数对账未完成，不能称为完整 Node 恢复。 |
| 旧 MA→MB 写路径退役且历史记录完整映射 | 未实现 |
