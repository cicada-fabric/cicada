# v0.2.x Agent 协作：Network 黄页、本地通讯录与主动组织

**状态：PLANNED / 设计提案；2026-10-10。** 本轮只完善规划，不实现 v0.2.x 功能，不运行模型或 Docker，不改独立 Client，不发布软件版本或修改 wire。v0.1.x 的 x 是补丁占位，当前软件标识 `0.1.0-dev` 与 Architecture v2.3 分属不同维度。本文不是软件版本、wire 或合同升级，也不表示 v0.1.x 完成。入口为 [v0.2.x 路线](v02-openai-integration-roadmap.md)，面向社区的导航为 [docs/README.md](README.md)，规范为 [CICADA.md](../CICADA.md)，工程证据须按各自实际源码和运行范围读取。

## 1. 目标与决定边界

此次规划三件相互配合的事：Hub 维护每个 Network 的完整黄页；Node daemon 为每个已 Join Thread 维护与它相关的小通讯录；每个 Agent 可主动联络同组 Worker、直属 Monitor、跨组专家和更远的已授权 Thread，Monitor 可主动规划组织、协作与再分组。复用现有 Task list、Journal、Discussion 持续迭代，不建立平行协作系统。

“完整黄页”指该 Network 的权威目录集合完整、字段有来源和更新版本；每个调用者看到的是当前授权投影。只有具备覆盖范围完整管理授权的管理员可查完整管理视图；普通 Agent 绝不默认拿到全表或 server/path。它不意味着所有成员看见所有条目，或所有字段对全网公开。简介是人工维护、Control 总结、还是二者组合，**尚未决定**；本文不默认允许模型读取全部历史来生成简介。

物理部署仍只有 Hub、Node、Client，逻辑参与者仍只有 User、Control、Worker、Monitor。Network 是租户/授权范围；NetworkAdmin 是有限 grant；Monitor 可选，Group 可在同 Network 嵌套，同一 Thread 可参加多个 Network/Group，父子关系不继承权限。独立 Client 的实现仍由其仓库负责。

## 2. 当前可复用证据与目标增量

本次只读检查在 `dev` / HEAD `d01b8fd` 的已有 dirty 工作树上进行；HEAD 不是该工作树全部内容的来源身份。以下定位证明代码/契约存在，不证明本轮测试或 native 验收通过。

| 范围 | 仓库证据 | 本提案仍要补齐什么 |
|---|---|---|
| Network Join、目录认证、解析 | [fabric/network.go](../cicada-go/internal/fabric/network.go)：`JoinNetworkForNodeCredential`、`AuthenticateForNetwork`、`ListNetwork`、`ResolveNetwork` | 丰富但逐字段受权的 profile、增量目录同步；现有卡片不能直接扩成全字段公开 |
| Owner 管理目录 | [client_network_endpoint_directory_v2.go](../cicada-go/internal/store/client_network_endpoint_directory_v2.go)：`ListClientOwnerNetworkEndpointCards` | 当前 DTO 刻意只含 Network/Endpoint/alias/presence，排除 Node、workspace、Group；新字段必须单独设计合同与 ACL |
| 目录与消息权限 | [Group 目录权限](group-directory-permission.md)、[Network 设计](agent-networks-design.md) | 保持 `directory.read`（Group）与 `directory.discover`（Network）实际差异；不得把名字统一后误授消息权限 |
| MCP 查找、通信、Task、协作空间 | [mcp.go](../cicada-go/cmd/cicada/mcp.go)、[mcp_spaces.go](../cicada-go/cmd/cicada/mcp_spaces.go) | `cicada_inspect` 当前是 find 兼容别名；独立丰富 inspect/profile/localcontacts 是拟议增量 |
| Task 竞争与依赖 | [shared_task_v2.go](../cicada-go/internal/store/shared_task_v2.go)：`ClaimSharedTaskForActor`、依赖检查、结果提交/验收 | 将工作分工和文件权属纳入已授权 Task 上下文，保持数据库原子 claim/版本/epoch |
| Task 正文隐私 | [Task peer privacy contract](task-peer-privacy-contract.md)、[mcp_task_privacy.go](../cicada-go/cmd/cicada/mcp_task_privacy.go) | peer 元数据、密封定义/结果及独立 Artifact ACL 保持原边界；不为新简介复制 Task 私有正文 |
| Monitor 提议与委托 | [fabric/delegated_regroup.go](../cicada-go/internal/fabric/delegated_regroup.go)、[store/delegated_regroup_v2.go](../cicada-go/internal/store/delegated_regroup_v2.go) | 复用 proposal 与受委托 CAS；既有入口不是任意移人、迁移 native writer、分享历史的万能授权 |
| Journal、Discussion、同步 | [M2 合同](group-spaces-m2-contract.md)、[原协作空间设计](group-collaboration-spaces-design.md) | 复用密封记录、游标、限额和来源；旧设计中的 M3/M4 状态措辞是历史规划，须核对实际代码与证据 |

后台 `20261010T063155Z-5b6d7a3e12` 的 supervisor 已报告 `source_unchanged=true`、overall `UNKNOWN`，六条 cleanup 门禁 `UNKNOWN`。这是既有运行状态引用，本文件不重跑或补造结果，不能据此写 v0.1.x 已完成。Android、真实 native Runtime、物理设备与公网 HTTPS 结果始终分开记录。

## 3. Hub 上的 Network 黄页

### 3.1 管理职责与数据源

Control 在当前 User/Owner/Network 的精确管理权限内维护黄页：处理受权登记、可发布字段、过期状态、简介候选与更正。NetworkAdmin 只能在其 Network grant 内操作，不能替 Thread owner Join 或读取原生历史。条目来源是显式 Join 后的受信 Endpoint/SessionBinding、已登记 Node/Workspace 元数据、获准 Group 加入关系及受控 profile 发布，而非扫描账号下所有 Thread。

黄页权威状态属于 Hub 的 Directory/State，确定性 Guard 负责发布与查询。Control 的模型停机、规划失败或总结延迟，不能阻塞已有合法 find/send/ask/reply；简介过期可以标记未知，稳定 ID 和已授权路由仍可解析。目录管理调用与普通 peer 业务分离，后者不得调用 Control 理解/规划/汇总 handler。

### 3.2 拟议条目与逐字段可见性

| 字段 | 含义和维护来源 | 默认暴露边界 |
|---|---|---|
| `hub_id, network_id, endpoint_id` | scope 内稳定地址与权威来源 | 只对获准发现者返回；不发布跨 Hub 全局 Thread ID |
| `name / alias` | Thread/Endpoint 的 Network scoped 名称 | 可变标签；多个匹配必须拒绝歧义 |
| `server` | 所在服务器的受控标签及必要关联 | 默认脱敏别名；真实主机/IP/账号须字段级授权，不作为 transport 许可 |
| `workspace` | 已登记工作空间标签 | 默认获准标签；绝对路径、仓库私密信息须额外授权；发现不授文件读取 |
| `groups` | 当前 Network 的多 Group 引用列表 | 仅返回调用者有权知道的 Group；隐藏项不泄露名称、数量或父子关系 |
| `summary` | 目的、专长、当前可公开工作简介 | 只使用获准发布的最少资料；维护机制待决定 |
| `capabilities` | 声明及可选证据时间/引用 | 表示可用性，绝不是 caller grant 或正确性证明 |
| `availability, observed_at` | presence/binding 的新鲜度 | 明确未知/过期；不等于原生运行、模型已读或任务完成 |
| `profile_revision, policy_revision, expires_at` | 更新、投影与缓存校验依据 | 版本不能成为授权 token；内部 grant/key 不进入 profile |
| `summary_provenance` | 人工/Control 候选、来源范围、更新时间 | 可见来源同样过滤；不泄露隐藏 Task、记录标题或完整历史 |

Hub 是用户选择发布的目录元数据的可见方，包括选定简介。这个发布信任边界与 peer 正文 E2EE 分开：Hub 不解密普通 peer、Journal、Discussion 或 Task 密封正文。不能承诺“黄页简介对 Hub 也不可见”，同时又要求它在 Hub 建索引。秘密、凭据、完整原生历史、未分享 Task/Evidence 正文不得汇总进简介。简介如经外部模型总结，须有独立的明文处理授权与预算，不默认为该模型提供整个目录。

简介候选采用来源范围、版本、更新时间和受权发布动作。人工纠错不能静默改写历史证据；Control 生成文本只是声明，不能把“专家”“用户已授权”等字眼写成权限事实。自动发布权、人工确认频率和退回规则保持开放。

### 3.3 查询与消息权限独立

先按可信 caller 和当前 Hub/Network 验证可发现范围，再过滤条目和每个字段，最后解析别名。字段缺失不通过错误或排序侧信道泄露私有对象。只有所选范围内唯一匹配才返回稳定地址；同名目标返回歧义，未知和无权目标对普通调用者可统一拒绝。

find/inspect 成功不授予 send/ask、广播、Task claim、Artifact read 或角色权限。已存在同 Network direct-message grant 可支持跨组直达，不强制虚构共同 Group 或经过两个 Monitor；没有该 grant 时，按实际 Group policy/精确 Link 检查，不把“同 Network”当准许。跨用户仍须双方独立授权；跨 Network 需双方 scope/policy 和共同权威 Hub，跨 Hub 不做 Hub-to-Hub 转发。

## 4. Node daemon 的每 Thread 小通讯录

### 4.1 范围与隔离

daemon 为每个已 Join 原生 Thread 维护本地相关联系人投影：有权发现的同组成员、所绑定的直属 Monitor、显式 Link 或 Network grant 允许的跨组专家（发现本身须单独 narrow directory grant，消息权另查），以及当前任务/近期问答中仍有权访问的更远 Endpoint。直属只是受权 RoleBinding/关系，不推出任意父级 Monitor 可读全部内容。手工收藏只影响优先级，不能引入隐藏条目或制造授权。

本地存储键包含本地真实 Thread 关联、Hub、Network、来源 Group/Link、目标 scoped Endpoint、字段投影版本和更新时间；跨 Hub 凭据、授权/重放水位独立。共用一个 Node SQLite 文件可以使用受信本地身份和查询隔离，不要求每 Thread 独立数据库或进程。不得以一个 OS 用户/Node 超级凭据让模型填写任意 sender。Node 本地可关联同一 Thread 的多个注册，但不向全网公开关联映射。

通讯录还可有本地关系对象（关联任务、联系人选择/收藏及受权联系原因）和私有注释，但它们与 Hub 目录缓存分开存储/投影。最小远端身份键为 `(hub_id, network_id, endpoint_id)`；关系另绑定当前真实 Thread 与明确 Group/Link。私有注释不自动上传 Hub、对 peer 发布或进入简介，亦不成为权限或事实；其保留、导出和删除单独控制。

### 4.2 更新、失效与离线行为

按需查 Hub 后缓存有界结果；利用现有出站长连接的合并版本/失效提示更新。hint 只含 scope、对象/目录版本、变更类型，无正文、完整目录或秘密字段。断线重连先重新校验成员和授权水位，再分页补同步；游标过旧时有界重新获取当前投影，不能根据旧缓存复活已撤销字段。删除/撤权用受控 tombstone/失效事件清理本地卡片、索引和推荐引用，取消/封禁无剩余授权的 pending 请求并重验未读密文领取/注入，漏掉事件仍有到期刷新和操作 Guard 兜底。

通讯录是缓存，不是 grant。发送前、Relay 接受/领取、Node 注入以及 Task/Artifact 操作再次检查当前 scope、membership、Link、binding epoch 和期限；无法确认权威授权时 fail closed 或只按明确且有限的授权 lease 处理契约允许的动作。离线可以显示“历史缓存/不可确认”，不能用历史地址发起越权行动或延长 lease。撤权不能删除已经进入原生上下文的明文，也不承诺分区期间瞬时全局撤销。

## 5. 主动通信与迭代协作

Agent 在已有权限/预算内选择何时协作：先查小通讯录，必要时有界查 Network 黄页，固定唯一 scope 地址，发异步 Ask 或 Send，然后继续独立工作。接收方通过原始绑定读取并回复，结果返回发起方原 Thread。Idle、失败、超时和收到结果是不同事件；只在策略允许时唤醒，presence 不等于模型运行，idle/final answer 不等于 Task 已验收。

| 对象 | 用途 | 持续迭代规则 |
|---|---|---|
| Message / Ask / Reply | 及时问答、发现与进度通知 | 保持来源、request/message ID、期限与分层回执；不自动复制到长期共享历史 |
| Task list | 责任、依赖、原子 claim、handoff、验收 | 未满足依赖不可 claim；并发只一有效 owner，旧 epoch 不覆盖新结果 |
| Journal | 少量重要进展、发现、决定和更正 | 新记录关联更正，不保存全部原生对话；记录声明不创造 Approval |
| Discussion | 一个问题的主题、回复和争议 | resolved/reopened 仅为主题状态；共识和多数票不是事实验收 |
| Artifact / Evidence | 可复现成果与支持/反证 | 不可变版本和独立 ACL；引用不授整个 workspace 读取 |

Monitor 可从已获准 Task/Journal/Discussion 和事件识别重复劳动、阻塞、协作循环或知识冲突，主动给同组 Worker 提建议，联系已授权专家，规划依赖和文件权属，提出新 Group 或再分组。它可以在 Task owner 政策允许时协调子任务，但不能无限创建 Agent、增加预算、给自己或他人增权。多个 Monitor 可提供独立意见；没有 Monitor 的 Group 仍可协作。

组织计划与执行分开：proposal 记录源 Network/Group、明确操作和目标、依据、资源/读者/历史影响、预期版本及预算；执行时另查精确可撤销委托、当前 actor、期限、限额和所有相关 CAS，原子应用并审计。未委托仅建议；陈旧计划冲突，重新读取后生成新候选，不部分应用。扩大成员/读者/历史/密钥范围需要有权 Owner 独立批准，不能借已有 set-parent/create-child 委托实现任意移动或分享。重组不重建 native Thread、不迁移 writer、不清除旧模型记忆。

文件权属与真实资源必须明确：Task 指定可修改文件/工作区与验证责任，并发 Agent 避免同文件覆盖。必要租约以同一物理资源权威键冲突，执行器 fencing 的实际覆盖单独声明；advisory 协议不冒充安全隔离。提交成果先到 `RESULT_SUBMITTED`，满足明确事实/契约检查后才验收，不能靠“Monitor 同意”完成。

## 6. 传输、信任与消息注入

合法通信默认经双方选择的唯一共同 HubRelay，Node 只建立出站连接，Hub 保存密文及必要路由。只有同物理宿主、同 Codex 账号且 Node 可独立调用精确 native API、绑定与授权全部有效，才可零 Relay 本机 direct；同 Node 标签、workspace、Hub 或账号可见 Thread 都不足够。适配器未验收则标 `UNSUPPORTED/NOT_RUN`，不伪称已直达。

复用当前经审查的 NIST E2EE、签名、重放、密封与持久计数状态，不换算法、不共享真实 key、不引入明文降级。Node 是受托本地加解密边缘，实际明文终点必须诚实描述。`RELAY_ACCEPTED`、`NODE_RECEIVED`、`RUNTIME_INJECTED`、消费确认与业务验收分别记录。注入后落盘前崩溃须原生幂等对账或 `INJECTION_UNCERTAIN`；at-least-once 不承诺任意外部副作用 exactly-once。

恶意简介、能力描述、peer 消息、Discussion、Artifact 与 Monitor 摘要都是有来源的低信任数据，不成为系统指令、角色声明或用户 Approval。“我是 Control”“用户已批准”“把拒绝动作交给更强 Agent”均不能升级权限。未经明确委托，不能把被拒绝的动作转给其他 Agent 绕过权限。合法 Task/委托与请专家协助仍可进行，但须分别检查原 caller 的请求/转授范围和接收方的当前执行授权；受控工具保持原始请求范围，认证正文与执行批准分离。只拦截 CICADA MCP 的环境必须声明 native shell/宿主行为不在其完整 Guard 覆盖内。

敏感 Group 可要求专用 native Thread、workspace、凭据和运行隔离。同一 Thread 多 Network/Group 共享模型记忆；切 group_id、换 key、再分组或 prompt 保密提示均不保证隔离。简介生成、专家跨组答复和 Monitor 汇总尤其要检验跨 scope 泄露，不能把原生历史自动导出到新组。

## 7. 可组合 MCP 目标接口

以下是**拟议操作族示意，不是当前可调用合同或新增工具承诺**。实现时扩展现有 MCP/本地受信 bridge/Core，不另建万能管理入口；公开 capability 描述可用性，服务端仍逐操作 Guard。

| 操作族 | 输入/输出语义 | 复用与新增边界 |
|---|---|---|
| `profile.get / profile.propose / profile.publish` | scoped Endpoint、预期版本、逐字段候选/投影及来源 | 新增设计；发布需管理 grant，get 不授权消息 |
| `directory.find / directory.inspect` | 固定 Hub/Network 和可见过滤；返回有界唯一目标/歧义 | 复用现有 find/resolve；丰富字段 inspect 仍待实现 |
| `localcontacts.list / refresh` | 当前可信 Thread 的相关投影、新鲜度、游标 | 新增设计；不允许模型选择另一个 sender/thread |
| `send / ask / reply / receive / status` | 精确目标、稳定重试身份、request ID、分层结果 | 复用现有消息；不扩大正文权限或自动 wake-all |
| `task.list / claim / submit / accept` | 依赖、revision、owner epoch、密封定义/结果引用 | 复用原子 Task 和 peer privacy；验收与自报分离 |
| `journal.append / list / get`、`discussion.topic / reply / state` | 当前 Group 密封记录与有界游标 | 复用既有实现合同；订阅提示不推正文 |
| `monitor.topology.propose / apply_delegated` | 明确影响、proposal/delegation ID、相关版本 | 复用受委托 CAS；没有委托不执行，不扩大读者或迁移上下文 |

每族错误区分未 Join、歧义、无权/不存在、陈旧版本/绑定、不可达、限额、权限未知与注入不确定。业务对象稳定 ID 与幂等作用域必须带 Hub/Network/actor/operation；每次读取包括摘要、搜索、导出、localcontacts 与引用解析都重验 ACL。合同修订、wire、软件版本、schema、Git revision 和 image digest 分开记录。

## 8. Claude Code 组织形式参考

调研日期 **2026-10-10**；仅参考官方公开组织/协作形式，不接入 Claude harness，不复制实现、产品限制或权限模型。

| 官方事实（当日页面） | CICADA 借鉴 | 我们的推论/取舍 |
|---|---|---|
| Agent teams 使用独立上下文、共享依赖任务、竞争 claim、peer 通信、自动结果/idle 通知；文档建议避免文件冲突。功能仍实验性；其 mailbox 是本地 JSON。 | 独立工作上下文、共享责任、及时 peer 结果、明确文件权属。 | 用当前 SQLite 原子 claim、密封持久消息与受权 hints，独立 native Thread 并不自动带来多组上下文隔离。[Agent teams](https://code.claude.com/docs/en/agent-teams) |
| Agent teams 可区分计划与实施；当日文档写 lead session 自动发放计划批准。其固定 lead、每 Session 一个 team、禁止 nested teams 是产品限制。 | 保留 plan/proposal 与执行分离。 | 自动计划批准不等于 CICADA Owner Approval；保留多 Group、嵌套及可选 Monitor，不移植固定 lead 限制。[Agent teams](https://code.claude.com/docs/en/agent-teams) |
| Cross-session messaging 区分来源与用户指令，按接收 Session 权限处理；可以发现/发送、在安全调用边界交付、订阅部分本地 idle 通知，并对同名目标消歧。 | 主动发现、异步通信、来源标签、有限事件通知。 | 跨用户授权、Hub scope、可靠持久性与本机 direct 条件由 CICADA 自行验收；通信从不算批准。[Cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging) |
| Subagents 文档描述独立 context、受限工具/权限、将结果返回调用者。 | 最少上下文、有限工具与明确结果。 | 这不证明 CICADA 已支持 Claude 的原生恢复/注入，也不限制 CICADA 所有协作必须是父子任务。[Subagents](https://code.claude.com/docs/en/sub-agents) |

事实仅支持以上公开说明，不能外推为内部 scheduler、分布式安全、NIST peer E2EE 或我们的容量证据。Task 事实验收、双端 Owner 授权和跨 Network 数据防泄露是 CICADA 规范约束，不归因于 Claude 文档。OpenAI dot/GPT-Live/plugin 既有调研事实、原官方来源和接入设想保留于入口；本轮不重新核实或扩大声明，也不启动多 harness 接入。

## 9. 依赖顺序与验收出口

| 次序 | 可 review 切片及前置依赖 | 出口要求（均未由本文执行） |
|---|---|---|
| C0 | 固定源码/dirty fingerprint，审计当前 Directory/Guard/Task/Monitor/密封合同 | 明确复用和缺口、历史结果归属；v0.1.x UNKNOWN 门禁不能偷换成 PASS |
| C1 | Network profile 字段模型、来源与发布 ACL；依赖显式 Join/身份/目录 Guard | 迁移保留 ID/key/history，字段投影与目录/消息权限独立，禁用 Control 推理可正常查找/通信 |
| C2 | per-Thread localcontacts、索引、版本/失效/重连；依赖 C1 | 多 Thread/Network/Hub 隔离、有界缓存、撤权与漏 hint 后拒绝陈旧授权 |
| C3 | 主动协作上下文与异步结果；依赖 C2 和现有 Task/Journal/Discussion | 同组/直属 Monitor/跨组专家/远端真实 Thread 闭环；回到原 Session，无强制双 Monitor |
| C4 | Monitor 组织提案、精确委托与 CAS；依赖当前委托、C3 事实/预算 | 未委托只建议、跨 scope/自授/扩权拒绝；有效小范围修改原子且可审计 |
| C5 | 可组合接口与可选 UI 互操作；依赖固定版本合同、C1–C4 | Hub/Node 确定性与 disposable 加密 interop；独立 Client 另行实施，native/Android/物理机/公网分别验收 |

C1–C4 先用已有 SQLite 与 Go 包实现，保留现有会话、Task 与审计来源。旧宽字段视图只可做经过 Guard 的兼容投影；权限缩小时不能因“兼容”公开所有字段。不清理历史数据来绕开迁移，不为文档阶段创建部署。

## 10. 验收矩阵与复杂负载

以下全为 **PLANNED / NOT_RUN（本轮）**；历史证据按原报告查看，不汇总为本提案 PASS。

| ID | 场景 | 必须观察的结果/证据 |
|---|---|---|
| A01 | 未 Join、别名重复、伪造 caller/thread、跨 Network 同名 | 未 Join 不进黄页；权限过滤后仍多解则歧义；可信绑定不能模型自填 |
| A02 | 可 discover 无 send、可 send 无私有 Group read | 目录成功仍拒绝消息/历史；合法通信不泄露目标私有 Group |
| A03 | server/workspace/Group 字段不同受众 | profile/find/inspect/search/导出/缓存全部一致过滤，无隐藏数量泄露 |
| A04 | Control 模型禁用、简介过期 | Directory/State/Guard 可用时已有合法通信成立；调用计数/失败 stub 证明未进 Control peer 业务 |
| A05 | 同 Thread 多 Group/Network/Hub，多个 Thread 共 daemon | 注册、缓存、凭据、游标/重放隔离；唯一串行 native writer，原 Session ID 连续 |
| A06 | 同组 Worker、直属 Monitor、跨组专家、更远 Thread 主动 Ask/Reply | 有效既有 grant 下直达；无 grant 拒绝；Monitor 离线不阻断无审阅要求路线 |
| A07 | 跨用户/跨 Network、无共同 Hub、本机 native API 不可用 | 双方授权逐项验证；不同权威 Hub 拒绝；local 条件不足默认唯一 Relay或报能力缺口 |
| A08 | 联系人被撤销、Node 离线、漏失效 hint、过期游标、恢复旧缓存 | 联网检查点拒绝；离线 fail closed/有限 lease，不延长缓存授权；重连有界补同步 |
| A09 | Relay 已接受后撤权、注入前撤权、旧 binding epoch、注入崩溃窗口 | 排队重验；旧 epoch 拒绝；原生对账或 INJECTION_UNCERTAIN，回执不等于完成 |
| A10 | 简介/消息含假系统角色、批准、命令、终端转义、恶意链接 | 保留低信任来源；不提权、不执行正文命令、不洗成 Owner Approval；审计不复制秘密 |
| A11 | 恶意请求经 Monitor 总结/另一 Agent 转发 | 原始请求 scope 保留，拒绝动作不能借 delegate 绕过；扩大读者需独立批准 |
| A12 | 同时 claim、未满足依赖、旧 owner 迟到结果、冲突证据 | 单 winner；blocked 清楚；旧 epoch 不覆盖；提交与事实验收分开 |
| A13 | Monitor 自授权/委托到期/陈旧版本/并发重组/父子循环 | 未授权无写入；合法 CAS 一次应用、审计完整；不复制 key/history或 writer |
| A14 | 同 Thread 共享敏感 native 记忆、简介或答复试图泄露秘密 | UI/Join 明示风险，专用 Thread policy 生效，简介只含获准资料；不声称 prompt 保密可消除记忆 |
| A15 | 密封正文和 Task 隐私、错误读者、篡改/重放、Hub 数据扫描 | 沿用现有 NIST 格式；Hub 无正文/裸明文哈希索引，无密钥降级；Artifact 单独 ACL |
| A16 | Journal 更正、Discussion 结案、Idle/final answer 通知 | 来源/版本保留；不制造 Task COMPLETED 或 Approval；无 wake-all |

负载采用合成资料，逐步组合小/大 Network、稀疏/密集 Group、嵌套、多组复用、热点同名、跨组 Ask、广播扇出、并发 claim、profile 高频更新、撤权风暴、SQLite 写竞争、多个 Hub 重连和慢消费者。特意测缓存命中/未命中、分页末尾和权限过滤成本，证明不每次扫描完整目录或给每模型塞全网 prompt；大组全员广播仍可能 O(N²)，不得宣称 Group 自动消除。

可先用 **设计预算候选**：目录页最多 64 条、简介最多 1 KiB、每 Thread 热缓存最多 128 条、单 Node 最多 16 次并发目录刷新、重连每批最多 64 条失效处理。数字不是既有合同、全局默认或实测性能，须在 C1/C2 确认，并受单 Node 总存储/并发上限约束。Journal/Discussion 继续用当前合同限额，不能用这些候选覆盖它。预算还覆盖 Ask hop/deadline、每任务消息数、广播接收数、醒来次数、模型 Token/费用和人工通知；超额返回明确背压与恢复条件，不开启每 Thread 常驻模型轮询。

记录查询计划/索引命中、扫描行数、页/字节量、缓存大小与新鲜度、p50/p95/p99 分层延迟、SQLite busy/锁等待、撤权后拒绝次数、hint 合并率、模型 wake/Token、队列/重试/丢失和峰值资源。测试报告固定源码 fingerprint、工具/Runtime版本、硬件、数据库设置、对象分布、密文大小、采样范围与故障位置。任何性能数字须来自真实记录，transport 替身负载不证明多模型自治能力。

实现时每切片须运行相关确定性拒绝/并发/恢复测试和一次性 Hub 加密 Docker interop gate，不能使用共享开发 Hub。Android、真实原生 Runtime、物理设备、公网 HTTPS 和清理分别提供状态与精确证据，skip/UNKNOWN 不算 pass。本轮仅文档链接、事实、格式检查。

## 11. 轻量实现取舍与开放问题

采用当前 Go 核心、SQLite scoped 索引、keyset/有界分页、版本增量、事件失效、有界 per-Thread 缓存和预算；复用现有 outbox/inbox、出站长连接、Task/Journal/Discussion、委托与 Guard。不给每 Thread 新建常驻模型循环，不引入消息队列、向量数据库、全网正文索引或协调两仓库的新基础设施。

以下未决定项在进入对应切片前须明确：

- 简介由人、Control 还是混合维护；自动发布的精确授权、确认、更新频率和模型预算。
- server/workspace 使用什么脱敏标签，哪些受众能看完整字段，简介最小来源及可公开证据格式。
- per-Thread 相关联系人选择、固定收藏、热缓存淘汰、Node 总上限和离线有限 lease 的精确动作集合。
- 增量目录 revision/游标/tombstone 的契约、保留期与落后重建规则，避免现有最佳努力分页被误称一致快照。
- 丰富 inspect/profile 的 MCP 命名与合同修订；不抢占现有兼容别名语义。
- Monitor 哪些拓扑动作可提前委托；新动作如何保证原子版本检查并独立处理成员/读者扩张。
- 本机 direct native API 可用性与 Runtime版本矩阵；真实 Android/native/物理机/HTTPS 验收条件。

这些开放问题不改变已经确定的 Join、双端授权、盲 Relay、当前 NIST E2EE、唯一 native writer、低信任数据和用户主权边界，也不意味着本轮等待用户批准才能完成文档。
