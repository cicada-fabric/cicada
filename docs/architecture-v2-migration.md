# Architecture v2.1 数据与协议迁移

2026-09-23。当前代码增量把 additive migration 定义推进到 **v22**，并保留只读 inventory、显式 backup/verify/restore。v11 建立 Endpoint-Group 多对多关系及旧 READY 记录回填；v12 添加不继承权限的 Group 父子关系；v13 保存不可路由的 CommunicationLink 提案；v14 增加 Endpoint 公钥候选；v15/v16 增加用户批准公钥与 Link Grant；v17 新增 Relay 密文 payload 表；v18 新增 Hub Client 设备与请求重放；v19 新增异步 Client Intent；v20 新增 Node 设备码及 owner 绑定；v21 新增 owner 作用域状态差异游标；v22 新增双端公钥绑定的 Link Grant。v14–v22 不回填、改写或轮换旧 Endpoint、Contact、私钥、ratchet 或 replay 状态；既有业务记录和旧 keys 保持原样。显式第二组 Join、逐组 Leave、作用域授权及同机双容器真实原生多组 Ask/Reply 已验证，但旧 MA→MB 退役或明文 Fabric 消息的整体迁移**尚未**完成。不要用删除表、重建原生 Thread、重置 Contact/密钥/ratchet/replay 状态来达成新架构。

## 当前已实现的账本

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

`TestV2MigrationsUpgradeLegacyStateAndRemainRepeatable`、`TestV2MigrationFailureRollsBackSchemaAndResumes` 和 `TestV2MigrationsConcurrentOpenSerializesLedger` 覆盖旧库升级、重复打开、注入失败及并发打开。版本账本保证 schema 操作可重试，不代表对象级映射、真实断电或生产恢复已验收。

Node-local `node-crypto-state.sqlite` 使用独立 schema 版本；本轮从 v3 增量升级至 v5。v4 为旧 pin 增加 `link_version`、清单摘要及合同/双侧 Grant 期限列，旧行默认 `link_version=0`，不能凭历史 pin 获得跨组授权。v5 增加 `node_crypto_owner_key_trust`，只保存经独立预期公钥与指纹核对的 Owner 公开身份、版本和终态撤销记录。升级不重置 Node 私钥、outbox、inbox 或 replay；v3→v5 的旧 pin 保留测试和定向 race 测试已通过。Hub schema 仍是 v22，本轮没有改写 Hub 旧表。

Hub 新增只读的 Node 凭据绑定证据查询：在同一个数据库事务中校验当前 Node credential/owner 绑定、Link 双端 scope、当前 SessionBinding、公钥候选及两侧 v2 签名 Grant，只向该 Link 一侧的 Node 输出公开清单和签名。Node 仍必须在本地独立验证 Owner key trust、合同/清单和两个签名；`PROPOSED` 证据不是路由许可。旧管理 bearer `/v1/communication-links` HTTP 路由已退役；同 owner Link 提案和撤销改走 Client 加密 `topology.apply`。旧 Link、Grant 和历史消息保留。

## v2.1 需要新增的迁移

以下列出 v11–v22 已新增的数据关系及仍需新增的目标 schema；其余概念名不是已存在的表名，实际命名以 migration 和测试固定：

1. **Endpoint-Group Membership**：v11 已建关系表、旧 READY 精确回填、Store/Service/MCP/HTTP 显式第二组 Join 和逐组 Leave；Directory/Relay/Node claim 按选定 Group scope 验证并隔离邮箱。保留 `endpoint_id`、`principal_id`、`binding_id`、native Session ID 与原消息引用；`fabric_endpoints.group_id` 和 SessionBinding 的 `group_id` 仍是旧主组投影。没有明确归属的旧 Endpoint 保持 `MIGRATION_PENDING_GROUP`，不自动加入全局组。同机双容器原生多组已通过；迁移断电与跨用户边界仍需单独验收。
2. **Group nesting**：v12 已添加 `groups.parent_group_id`，管理 API `PATCH /v1/groups/{id}/parent` 要求 `expected_version`；拒绝循环、跨 owner/trust domain 和过期版本。父子边仅用于组织/管理视图，不继承发现、密钥、消息或 Artifact 权限；旧 Group ID 保留。可视化拖拽尚未实现。
3. **CommunicationLink 与双方 Grant**：v13 保存同一 owner 下、两端都仍有效加入各自 Group 的连线提案，记录来源/目标 Endpoint、Principal、Group、owner、Node、动作、数据范围、方向、期限、所选 Hub、Membership/Join/Group 版本快照、合同摘要及版本化撤销。跨 Node 提案要求指定一个 Hub；同 Node 提案不得指定 Hub。这些字段只是约束草案：当前管理 bearer 也用于 Node enrollment，不能证明独立用户的批准。因此数据库状态只有 `PROPOSED`/`REVOKED`，没有激活或路由入口；跨 owner 提案也拒绝，直到有可信外部邀请/Card 和双方授权。旧 MA→MB 合同不自动转为直连，保留原历史。未来仍需增加双方可信 Grant、版本重验、激活/撤权对已排队消息的处理和端点密文。
4. **Broadcast**：固定 Group/成员快照、不可变操作 ID、每个收件人独立 envelope/Delivery/receipt 和 retry 状态；同一 Endpoint 在多个 Group 时按固定 Group scope 去重，不传播到其他组。旧单收件人消息 ID/请求相关性原样保留。
5. **端点密文与密钥元数据**：v14 已增加公开 key candidate 表/API；ML-DSA-65 自签名绑定 Endpoint、Principal、Node 和 SessionBinding ID/epoch。候选只有当前 Group 的成员可读；自签名及 Join Session credential 不能证明 owner 批准，也不能解决 `CICADA_API_TOKEN` 未配置或范围过宽的 bootstrap trust，因此候选不是可信 pin 或 safe-to-encrypt key，仍不参与路由。v15/v16 已有离线用户公钥及旧合同 Grant，v22 增加当前两端候选 key 与原生绑定的双侧签名；Node-local 双边 pin 证据核验已实现，但尚未建立远程可信设备绑定、生产路由 Guard、端点密文 route 与本地 outbox/inbox 传输集成；新路径不能沿用 `fabric_messages.body` 明文。Node-local `CryptoState` API 能持久分配 sequence、保留精确密文 outbox；独立 Node DB schema v1→v2 添加精确作用域的公钥 pin 表，v2→v3 添加原子提交入站密文与 replay 的 inbox 表。旧 replay-only 行保留但需显式对账，不能当成可恢复的收件或模型消费。Node API 可在独立 owner key trust 前提下验证 v22 双侧签署并建立非路由 pin，但仍没有接入生产路由权或 native message delivery/injection，亦不处理注入后的不确定崩溃。旧 Contact/peer ratchet、sequence、信任记录原样保留并审计其真实加解密终点。迁移期间禁止静默明文降级。

`internal/e2ee/endpoint.go`、Endpoint attestation、v14 Hub candidate registry 与 `internal/nodekeys.CryptoState` 已有独立 API；`internal/nodekeys/endpoint_messages.go` 进一步将精确 pin、seal/open 与持久 outbox/inbox/replay 组合成 Node-local API，但未连接用户签署 Grant、Guard、Hub-blind transport 或 native delivery。Hub 的 `migration backup/restore` 不包含 Node-local endpoint private identity，也不包含 `node-crypto-state.sqlite` 的 sequence/outbox/replay/inbox 数据；不得声称完整 Node 备份或恢复。v14–v17 Hub migrations 只增加迁移账本条目与候选、公钥、Grant、Relay payload 表，不改写旧业务表或旧 keys。Node DB v5 对新入站记录继续同时保存 replay 与原样密文，v1/v2 旧 replay-only 行继续保留并返回显式恢复错误。启用端点密文前必须增加 Node 侧一致点备份、恢复和单调计数对账，并证明不会因丢失/回滚本地密钥与计数而静默生成新身份、复用序号或错误重放。v14–v17 Hub 迁移和 Node DB v5 定向测试通过；真实 Node 备份/恢复未验收。

v15 新建 `owner_approval_keys_v2`，只存经 Hub 本地可信操作核对的用户公钥及版本化撤销状态；v16 新建 `communication_link_grants_v2`，保存精确合同两侧分别签署的证明、nonce 和接受时间。它们均为增量表，不回填旧提案为已批准，也不接入现有明文跨组消息路由。用户私钥由可信 Client 保管，不能放入 Hub 备份；本地 CLI 只是 Android 设备认证与 PQ 应用会话建立前的开发/恢复引导。若恢复旧 Hub 数据库导致公钥撤销或 Grant 状态回退，必须先隔离并对账，不能自动宣称安全重新联网。两个新迁移的中断回滚、重跑、旧数据计数对照与真实备份恢复分别记录，不能用 Git 历史替代。

v22 单独新建 `communication_link_key_grants_v2`，不覆盖 v16 原始签名和 nonce。新清单在同一个事务内由当前 Link、完整规范合同、两端 SessionBinding lease/epoch 与 Endpoint 公钥候选构成；owner 对清单摘要签名。v16 签名在新状态查询里显示为 `LEGACY_KEY_UNBOUND`，不能转成可信 Node pin。Hub 数据备份需要同时保留 v16/v22 历史与撤销后的 owner key 行；恢复旧备份后必须隔离、对账版本/密钥/计数，不能自动开放路由。当前 v22 签名仍只记录同 owner Link 双侧同意；Node 已能独立验证公开证据并建立非路由 pin，尚无密文投递或跨 owner 路由。

每个新版本独立可重复运行并做 legacy count/digest、FK/integrity、旧 ID/关系和密钥状态对照。迁移可先创建新结构和只读映射，再切流量，最后退役旧写入口；**Git 历史不是数据备份**。旧 GroupGateway 表和历史请求可保留只读/导出，在新直达路径完成验收和对账后才删除旧运行 API。

## 已实现的备份工具与操作边界

CLI 提供：

```bash
cicada migration inventory --state-dir PATH
cicada migration backup --state-dir PATH --output NEW_BACKUP_DIR
cicada migration verify --backup BACKUP_DIR
cicada migration restore --backup BACKUP_DIR --state-dir NEW_EMPTY_STATE_DIR
```

这些命令要求显式路径。`TestStateBackupRestorePreservesSQLiteIdentityAndReplayState` 与 `TestMigrationBackupCommandOutputBackupVerifyRestore` 对**合成 StateDir** 验证旧身份、Contact/peer session/replay 与 SQLite 完整性。尚无真实生产 StateDir 演练。执行真实迁移前需停止写入、先 backup/verify、在副本运行 inventory 和升级，再按旧 ID、Goal、Approval、消息、Contact key/ratchet/replay、Artifact 引用与原生绑定逐项对账；只在维护窗口切换。

备份恢复不是随意回滚：签发新凭据、递增 binding/owner epoch、推进 E2EE counter 或触发原生/外部副作用后，恢复旧状态可能重用计数或失去对外部事实的认知。此时须隔离联网，验证密钥与计数的新旧序关系，对未确认注入/副作用做 fencing 和 reconciliation，然后前滚。不能删除 SQLite 行或重置信任让测试变绿。

## 验收状态

| 项目 | 当前状态 |
|---|---|
| v1–v13 additive schema、ledger、重复运行与并发打开测试 | 已实现并测试；v11 精确回填、v12 父子关系、v13 提案中断回滚/重跑及旧记录保留另有专项测试 |
| v14 Hub key-candidate additive migration | 只新增候选表；合成旧库中断/重跑和旧状态保留测试通过，真实生产库未演练 |
| v15 Hub owner approval key migration | 只新增独立用户公钥表；合成旧库中断回滚/重跑、撤销不可静默恢复和旧状态保留测试通过 |
| v16 Hub bilateral Link Grant migration | 只新增双侧签名证明表；合成旧库中断回滚/重跑、成员与原生 binding epoch 失效测试通过；旧提案仍不可路由 |
| v17 Hub sealed Relay payload migration | 只新增独立 mode/BLOB 表；旧消息保持明文标记或兼容读取，专用 `SEALED_V1` 存取与旧读取隔离、ACK/重启/撤权测试通过；尚未接入真实 Node 加解密投递 |
| v18 Hub Client 设备与请求迁移 | 新增持久 Hub ID、设备公钥/owner Grant nonce、会话 epoch 与序号、operation ID/密文 digest/状态及密文响应 BLOB；不保存 Client 私钥或请求明文。失败回滚/重试、旧状态不丢与 Hub ID 重启稳定测试通过。新的 Control PQ 私钥位于 `StateDir/e2ee/client-control-identity.json`，须和 SQLite 一起备份；丢失时旧 Client 无法信任新密钥。 |
| v19 Hub Client Intent 迁移 | 新增 `client_control_intents_v2`，接受记录与普通 Intent 同事务创建；输入仅供 Control 执行，通用 JSON 不泄露原文。重启只恢复 QUEUED，RUNNING 与普通 Intent 终态对账后标 DONE，否则标 UNCERTAIN；合成旧库保真、并发 Claim 和定向 race 测试通过。 |
| v20 Node 设备码绑定 | 新增 `node_device_binding_requests_v2` 与 `node_owner_bindings_v2`；Hub 只存短码/Node bearer 摘要，Client 经 PQ RPC 预览、确认、列出和撤销；旧未绑定 Node token 不再认证 v2 Relay。合成迁移中断/重跑、并发单次确认及撤销测试通过；真实远端 Node 与 Android 配对待验收。 |
| v21 Client 状态差异游标 | 新增 `client_status_state_v2`、`client_status_streams_v2`、`client_status_change_events_v2`；owner-local 序号和重启续读测试通过。此为快照差异，不是完整事件推送，轮询间瞬态仍不可见。 |
| 旧 Endpoint pending、READY 隔离旧 v1 API | 已实现并测试 |
| 合成 StateDir inventory/backup/verify/restore | 已实现并测试 |
| 真实生产 StateDir 备份/恢复与重新联网对账 | 未运行 |
| 多 Group Endpoint 关系与作用域服务接入 | v11 additive schema、Store/Service/HTTP/MCP 定向测试和同机双容器真实原生多组通过 |
| Group 嵌套管理边界 | v12 additive schema、版本化管理 API 与防环/不继承 Fabric 权限测试通过；面板拖拽未实现 |
| 连线、广播、端点密文及 Android↔Control PQ 迁移 | v13 有不可路由的同 owner 连线提案/撤销；v14 有按 Group 可读的不可路由候选；v15/v16 有离线用户公钥及旧合同 Grant，v22 有密钥绑定签名记录；v18–v21 加入独立 Client↔Control PQ 入口、Node 设备码绑定与部分状态游标，但仍无可信双端 Endpoint pin、跨用户提案、广播或端点密文消息路径 |
| Node-local crypto-state 与完整备份/回滚 | sequence/outbox/replay API 处于消息路径集成中；Node 私钥和 crypto-state 不在 Hub 备份，完整 Node 备份、native crash recovery 与恢复后计数对账未实现 |
| 旧 MA→MB 写路径退役且历史记录完整映射 | 未实现 |
