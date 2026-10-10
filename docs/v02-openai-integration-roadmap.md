# v0.2.x OpenAI 接入路线（规划，未实现）

本文只记录 **v0.2.x 以后**的可选接入方向。当前预定的 v0.1.x 不因此增加 OpenAI、dot、GPT-Live、ChatGPT plugin 功能或依赖，也不改变 [CICADA.md](../CICADA.md) 的身份、授权、密码与部署不变量。以下是基于公开接口的架构推断，不是 CICADA 互操作验收或产品可用承诺。

## v0.2.x 协作底座入口（2026-10-10 增量规划）

新增 [Agent 协作设计：Network 黄页、本地通讯录与主动组织](v02-agent-collaboration-design.md)：Control 在受权范围维护 Hub 上完整但逐字段可见的 Network 黄页；Node daemon 为每个已 Join Thread 保存相关小通讯录；Agent 主动联系同组 Worker、直属 Monitor、跨组专家及更远的已授权 Thread，Monitor 以 proposal/精确委托 CAS 规划与调整协作，并复用 Task list、Journal、Discussion 持续迭代。简介由人工还是 Control 总结尚未决定。

上述都是 `PLANNED`，目录查询与消息授权分离，缓存不代表授权；Control 黄页管理不进入 peer 消息业务路径。新设计提供实际仓库定位、Claude 官方组织形式调研、依赖顺序、验收矩阵、轻量存储预算与未定项，不改 v0.1.x 合同或密码算法。当前后台门禁 overall `UNKNOWN`，不能以该规划宣称 v0.1.x 完成。

以下 OpenAI 接入段落保留既有 2026-10-10 调研事实及其原官方来源归属；本次新增设计不重新核实或扩大这些产品声明。用户接入设想与已记录公开事实继续分开，具体账号、客户端、插件许可和接口在实现前须复核。本轮新增外部调研只参考 Claude Code 组织形式，不启动多 harness 接入，见新设计的来源与取舍。

## CICADA 保留的能力边界

CICADA 的差异化是连接稳定的原生 Thread，而非绑定某个模型入口：私有 Network/Group、不同用户之间逐方授权的后量子 peer 密封通信、持久化的 Journal/Discussion/Task/回执，以及断线后按原身份和权限恢复协作。独立 Client 继续掌握用户身份与签署；Node 的未来适配接口应容纳多个 native harness，具体支持范围仍以各自验收为准。OpenAI 接入只是其中一类可替换入口，不能取代 Client、Node、Hub 或其他 harness。

Control 是可插拔、受信但受限的 Manager 角色。未来可以让 dot 经最小授权 MCP 管理适配器提出或查看其有权处理的 Control 工作；插件工具的存在、模型文本里的“用户已批准”、dot 的一次调用或云账号登录，都不构成 CICADA Owner/Client 签名、设备会话、精确 grant、版本 CAS 或当前 Guard 的替代。管理请求仍需 CICADA 自身认证、限定 Hub/Network/Group/动作、预览与可恢复的批准路径。Relay、Guard 和持久状态继续由 CICADA 作为权威；模型服务不持有 peer/Group 的路由授权账本，也不能自行升级身份。ChatGPT 插件可由 MCP server 提供工具，并可选择附带 MCP Apps UI；是否以及如何暴露给 dot，须按当时受支持的插件、账号权限和运行环境单独验证。官方资料仅说 dot 可用受支持、已安装且启用的插件，**没有保证任意自定义 MCP 会自动供 dot 使用或无需专门批准**。[dot 的应用连接](https://learn.chatgpt.com/docs/dots/computers-and-apps)、[ChatGPT plugin/MCP quickstart](https://developers.openai.com/plugins/build/app-quickstart)

## Dots mobile：公开事实与 CICADA 设计推断

**公开事实（2026-10-10 查阅）：** 官方 2026 年 10 月 5–9 日更新说明，用户可以在 ChatGPT 手机 app 创建和个性化 dot、连接插件，并选择默认打开 dot 会话；dot 可以继续已有 Codex Thread 或新建任务，也可以读取和修改 ChatGPT Work automations。当前 Dots 总览同样列出手机创建，mobile web 仍不支持。[日期明确的发布说明](https://learn.chatgpt.com/docs/whats-new/dots-october-9-2026)、[Dots 总览](https://learn.chatgpt.com/docs/dots)

公开文档更新不同步：本次查阅的 getting-started 页面仍要求先在桌面创建、手机支持取决于更新。本路线优先采用上述日期明确的发布说明，不把旧措辞当作当前手机创建限制；具体账号和客户端是否获得功能仍需验证。以上产品页面没有提供可直接接入 CICADA 的 Dots dispatch API 或内部任务选择算法。[仍有旧措辞的 setup 页面](https://learn.chatgpt.com/docs/dots/getting-started)

**CICADA 设计推断，尚未实现或验收：**

- 同一任务可续用已确认的 native Session；独立任务或需分开敏感上下文的工作使用新 Session。fork 可能保留原上下文，不保证秘密或权限隔离。
- resume 前由受信适配器核对 harness、真实 Session ID、Hub/Endpoint/当前绑定和授权；不能以名字相同、dot 记忆或模型自报 ID 冒充原会话。
- dot 的续任务/新任务选择与 CICADA 的 Owner 批准独立。新 Session 不继承额外 grant，已有批准也不能扩大到新动作或新目标。
- 暂停应分别停止新任务提交、队列准入和运行中工作；还需区分授权撤销与执行器停止证明。暂停一个入口不等于所有子进程已经停止。
- 手机可以作为用户交互入口，不能替代独立 Client 的身份、签名和恢复边界。发给 dot 或外部模型的内容进入其明文处理边界，不属于 CICADA peer E2EE 的盲 Hub 保证。

## 可选语音入口与明文责任

v0.2.x 可评估云端 GPT-Live WebRTC 语音适配器。它应是用户明确选择的 Client/Control 入口，保持本地 STT、离线文本和隐私优先选项；云端会话须有可见的费用/时长预算、主动停止、连接失效和停止后的权限收口。官方 WebRTC 文档描述浏览器音频轨道、事件数据通道，以及由受信应用服务器发起会话；这只证明存在可研究的集成方式，不证明 CICADA 已接通或取得特定账号能力。[GPT-Live WebRTC 文档](https://developers.openai.com/api/docs/guides/voice-webrtc)

任何外部模型都会看到调用方实际授予它处理的明文。CICADA 的后量子端到端加密只覆盖其已定义的 Client/Node peer 或 Board 密封边界；不能把第三方模型推理、云语音传输或第三方语音记录描述为 provider-blind，也不能宣称 NIST E2EE 覆盖整个第三方语音链路。未来接线时须显式列出发往模型服务的内容、保存范围与用户可撤销的访问。官方已记录 ChatGPT 手机 app 的 dot 创建与交互，移动网页仍不支持；这些产品能力不是 v0.1.x CICADA 移动 Client 的替代交付。[dot 渠道说明](https://learn.chatgpt.com/docs/dots/channels)

## 进入实现前的判定

单独确定受支持的产品入口、账号/插件许可、最小 MCP 工具与动作范围、用户批准及撤权体验、语音预算/停止语义、明文流向和断线恢复；再做隔离的权限拒绝与真实服务互操作验收。未完成这些检查前，本路线保持 `PLANNED`，不进入 v0.1.x 能力目录、合同或验收矩阵的 PASS 项。
