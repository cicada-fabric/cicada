请在当前 CICADA 仓库上执行一次重大架构升级。

仓库根目录新版 CICADA.md 是本轮已经采纳的目标架构：
Architecture v2.1 — User-Defined Collaboration Graph & Single-Relay Transport。

请完整阅读该文档，尤其是设计不变量、原生会话与失败语义、迁移方案、
V01–V73 验收矩阵、G1–G5 演示路径和 v2-A 至 v2-E 的阶段划分。
如果根目录也有 CICADA_PROMPT.md，请完整读取并执行其中要求。

这是一项真实工程任务：修改现有代码、迁移、测试和工程文档。
不要只返回设计或计划，不要只增加 Group struct，不要另起一个项目。

一、先确认真实起点，然后继续实现

检查当前 HEAD、分支、工作树和已有本地修改。
阅读适用的仓库指令文件、CHANGELOG.md、DEVELOPMENT.md、相关 docs、
构建文件、数据库迁移和现有测试。

核查当前 Go 核心、MCP/插件、Endpoint、Directory、Relay、原生 Codex、
Goal/Idea、Worker/Monitor、审批、Contact、加密和恢复能力的真实实现。

不要仅凭 README 宣称某项能力已经完成；记录实际文件、函数和测试证据。
不要假设目录、接口或命令存在，先查实际代码。

建立并持续更新：
- docs/architecture-v2-audit.md
- docs/architecture-v2-plan.md
- docs/architecture-v2-status.md
- docs/architecture-v2-migration.md

审计和计划完成后继续修改真实代码，不要停下来只交计划。

二、必须保留的架构边界

顶层抽象先固定为两个视图：物理部署只有 Node（原生 Thread 所在执行节点）、Hub（公共中枢）和 Client（用户入口）三类职责；逻辑协作参与者只有 User、Control、Worker、Monitor 四类，其中 Monitor 可选。它们不要求各占一台机器或一个进程。Thread/Endpoint/Group 是对象，Directory/Relay/Guard 是组件职责，不能和顶层部署或参与者混成一层。

1. Control 是面向用户的管家。
   它继续管理 Idea/Goal、Group 拓扑、机器、Workspace、角色、
   生命周期、预算、审批和汇报。
   但普通 Agent 通信不得调用它的意图、规划或汇总业务。

2. Group 是持久、可嵌套的一等协作域。一个真实 Thread/Endpoint 可以同时加入多个 Group，保持原生 Session 与 Endpoint ID 不变；父子关系不自动继承授权。组内 Agent 通过 MCP 自主通信和广播。跨组、跨用户由双方明确授权的 Endpoint 连线直达，未经连线授权默认拒绝。旧版双 Monitor 必经工作流须退役，不作为新路径的兼容要求。

3. Monitor 是可选的观察者、专家、reviewer 或获授权的代表，不是默认消息转发站，也不能代替用户批准操作。用户可通过 Monitor 发起一个 Group 广播；必须分别记录可信用户发起/批准与 Monitor 实际发送身份。GroupGateway 如仍用于可选审阅，只能执行明确策略，不能偷偷插入普通 peer 传输链。
   Guard 在真实服务和执行入口落实安全规则，不能只靠模型遵守提示词。

4. 分离 Principal、Endpoint、Membership 和 SessionBinding。
   保留现有 Endpoint ID、原生 Session 和历史关系。
   同一 Principal、同一真实 Thread/Endpoint 可以参加多个 Group；Principal Membership 与 Endpoint-Group 关系分开，SessionBinding 不随切组重建。共享的模型记忆不能靠切换 group_id 清除，敏感 Group 可要求专用 Thread。

5. 保留显式 Join。
   安装集成不等于加入网络；未 Join Session 不可见、不可路由。
   Join 幂等，不自动授予 Worker/Monitor 角色。
   用户已有 Thread 可以后加入，不强迫重新创建会话。

6. 调用者身份必须来自可信连接和 Session 绑定。
   不接受模型填写的 sender、group、role 或“用户已批准”作为授权证明。
   MCP、HTTP、CLI 必须进入同一个授权和核心状态服务。

7. 公网部署单个 Cicada Hub，可同机运行 Control、Directory、Relay 与面板，但职责独立。同 Node 两 Thread 经本地受控适配器与原生 `queue` 通信，不走中心 Relay；跨 Node/跨用户两端 Node 只主动连接双方选定的一个 Hub，消息最多经过一个 Relay，Hub 不需要也不应拨入 Node。Hub 上任何进程都不得持有普通 peer 消息解密材料。当前明文 Fabric/旧 Contact 路径必须标为迁移缺口。

8. Client 第一版仅开发 Android，且由独立仓库 `~/CICADA_CLIENT` 中的另一开发者负责；本任务不得修改该仓库。核心 Hub/Control 需预留安全契约：按 Node/Worker/Goal 分层状态与增量、语音转写/文字 Control Intent、Hub 权威面板事务、双端授权的外部 Thread 连线。Android 可选安装本地小模型做语音转文字；无本地模型的联网 STT 须另行明确第三方边界。Android↔Control 的用户指令与管理数据必须使用 NIST 标准的应用层后量子 E2EE，不能以 TLS/旧 bearer 降级；Control 是管理指令的解密端，普通 peer 的解密端则是目标 Endpoint。未实现的能力应经版本化发现明确报未就绪，不开放假接口。

三、本轮优先完成 v2-A → v2-B → v2-C

v2-A：Group、身份与统一权限
- 梳理并解除 Fabric 对 Control 推理业务的依赖。
- 增量实现 Principal、Group、Membership、版本化绑定与 Group 授权。
- 对旧 Endpoint、角色和请求做可恢复迁移。
- 不把所有旧 Session 自动放进一个宽权限全局 Group。
- 未 Join、伪造身份、异组枚举、歧义目标和旧接口绕过必须有拒绝测试。

v2-B：真实原生 Thread 的异步组内协作
- 扩展现有 MCP/插件，不建立平行实现。
- 完善 join/leave/whoami/find/send/ask/reply/receive、
  请求状态与取消等语义。
- Ask 持久接受后返回 request_id，不无限阻塞工具调用。
- 实现或修正 outbox/inbox、相关回复、分层回执、游标、
  离线队列、去重、超时、取消和迟到结果。
- 使用可靠的 native Session 身份和会话所有权租约。
- 回复必须回到正确的原始 Thread。
- 用户前台输入必须受到保护；使用原生队列或安全投递点。
- 不能通过任意 tmux 输入、发送 Enter 或执行消息内 slash command
  冒充可靠原生集成。
- 原生恢复不支持时明确报告限制或授权 handoff，不创建同名新会话冒充成功。

v2-C：多组成员、显式通信图和可选 Monitor
- 同一真实 Thread 加入多个 Group，Join/Leave 各自幂等、撤销独立。
- 组可嵌套但不自动继承消息、制品、密钥和成员授权。
- 持久 CommunicationLink 具备双方授权、方向、动作、范围、期限、版本和撤销；授权后 Endpoint 跨组直达，未授权默认拒绝。
- 同 Group Thread 广播与用户经 Monitor 广播均需成员快照、逐接收者密文/Delivery、背压和可审计来源；不自动广播到父子 Group。
- Monitor 是可选审阅者；离线只阻塞明确要求其审阅的请求。
- 保留真正生产者和 Evidence 引用；接受请求不等于任务完成。
- 旧 MA→MB→B1 运行路径退役前完成数据保全和迁移，不为兼容延续强制转发。

基础闭环稳定后，继续按 v2-D 推进 Shared Task Graph、原子 Claim、
结果验收、handoff 和资源 Lease。
会话所有权、已有权限与加密保护属于基础要求，不能以 v2-D 为由后置。

四、可靠性必须处理真实故障窗口

不要把 at-least-once 传输说成任意动作 exactly-once。

必须区分：
- 本机 inbox 或唯一 Hub Relay 已持久接受；
- Node 已保存消息；
- 原生 Runtime 已确定注入；
- 模型消费是否可确认；
- 业务结果是否通过验收。

原生注入成功、适配器记录成功前崩溃时：
使用 Runtime 原生幂等能力对账，或进入 INJECTION_UNCERTAIN。
不能盲目重投高风险操作并宣称只执行一次。

会话与任务的旧 epoch 不得覆盖新 owner 的状态。
资源 Lease 到期不代表旧进程停止；真实资源需要执行器强制、
停止确认或隔离对账。
同一物理资源在不同 Group 中必须使用同一权威冲突身份。

五、按真实闭环验收

至少准备：
一个 Docker 常驻 Hub（Control、Directory、Relay、面板可同机）。
Group A：A1、A2，可选 Monitor MA；嵌套 Child Group，A1 同时加入 A 和 Child。
Group B：B1，可选 Monitor MB；由另一用户拥有。
一个未 Join 的原生 Session U。
至少两个互相不能直连、但都能主动连接 Hub 的隔离 Node 环境，并覆盖同一 Node 内两 Thread。
可单独禁用的 Control 规划/汇报业务。
仍运行的 Directory、Relay、Authorization 和 State。

完成并记录：
1. A1 与 A2 经 MCP 在原始 native Session 中完成 Ask/Reply；同 Node 路径 Hub Relay 业务调用为零。
2. A1 沿双方授权连线直达 B1 原生会话，收到有来源的结果；跨 Node/跨用户只经过一个 Hub Relay，双方 Node 仅出站。
3. 无连线时 A1→B1 拒绝；授权、撤销、限 scope 及两个用户的可见性边界均可验证。
4. A1 的同一真实 Thread 加入两个 Group、再退出其中一个，Endpoint/native Session ID 不变，权限不混淆。
5. Group 嵌套与同组广播、用户经 Monitor 广播通过 Docker 组合验证；父子 Group 不自动继承消息，伪造用户批准失败。
6. 禁用 Control 业务后，合法 peer 协作仍可进行，
   且用调用计数、失败 stub 或依赖断言证明未调用管理逻辑。
7. Relay/Node 重启、离线排队、重复消息、错误 ACK、
   陈旧绑定、并发消费者和注入崩溃窗口得到正确处理。
8. 未 Join、身份伪造、越权 Artifact、成员撤销、
   旧 API 绕过和伪造用户 Approval 均被阻止。
9. 旧身份、Goal、Contact、消息、审批、密钥和重放计数迁移不丢失。

fake harness 可以验证协议、并发和故障，但不能证明真实原生唤醒。
缺少凭据、Runtime 或远端环境时，准确标记 BLOCKED/SKIPPED，
继续完成可执行的实现与测试；不能把未运行项目计为通过。
不要伪造线程 ID、测试输出、退出码或性能数据。

六、保留与安全约束

保留现有 Go 核心和有效产品能力，不做无关语言重写。
保留现有加密、联系人、密钥、会话链和重放状态。
不要重置密钥、切换算法、重新信任联系人或静默明文降级。

先确认实际加解密终点：
Control API 接触过明文的路径，不能声称 Control 从未看到明文。

不要删除用户未提交改动，不做破坏性 Git 清理，不自动推送、
发布 release、修改生产部署、购买资源、轮换真实密钥或修改全局 CLI 配置。

不为了借鉴其他项目就引入 NATS、Kafka、Redis、Kubernetes 或整套新运行时。
确需新增依赖时，记录需求、取舍、固定版本、许可证与测试。

七、最终交付

交付真实改动和证据：
- 修改了哪些文件、服务边界和迁移。
- v2-A/B/C 分别完成、部分完成或受阻的情况。
- 实际运行的构建、测试、演示命令与结果。
- 原生 Session 连续性和跨组路径证据。
- 旧路径退役、升级、备份、恢复与安全限制。
- 目前可复现的使用步骤。
- 尚未完成或验证的路径及下一条可执行任务。

文档、代码、单元测试、集成测试、真实原生验收和故障验收分别报告。
不要用“整体基本完成”掩盖缺口。

现在开始：建立本地事实和回归基线，然后连续推进真实实现。
