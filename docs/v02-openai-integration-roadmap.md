# v0.2.x OpenAI 接入路线（规划，未实现）

本文只记录 **v0.2.x 以后**的可选接入方向。当前预定的 v0.1.x 不因此增加 OpenAI、dot、GPT-Live、ChatGPT plugin 功能或依赖，也不改变 [CICADA.md](../CICADA.md) 的身份、授权、密码与部署不变量。以下是基于公开接口的架构推断，不是 CICADA 互操作验收或产品可用承诺。

## CICADA 保留的能力边界

CICADA 的差异化是连接稳定的原生 Thread，而非绑定某个模型入口：私有 Network/Group、不同用户之间逐方授权的后量子 peer 密封通信、持久化的 Journal/Discussion/Task/回执，以及断线后按原身份和权限恢复协作。独立 Client 继续掌握用户身份与签署；Node 的未来适配接口应容纳多个 native harness，具体支持范围仍以各自验收为准。OpenAI 接入只是其中一类可替换入口，不能取代 Client、Node、Hub 或其他 harness。

Control 是可插拔、受信但受限的 Manager 角色。未来可以让 dot 经最小授权 MCP 管理适配器提出或查看其有权处理的 Control 工作；插件工具的存在、模型文本里的“用户已批准”、dot 的一次调用或云账号登录，都不构成 CICADA Owner/Client 签名、设备会话、精确 grant、版本 CAS 或当前 Guard 的替代。管理请求仍需 CICADA 自身认证、限定 Hub/Network/Group/动作、预览与可恢复的批准路径。Relay、Guard 和持久状态继续由 CICADA 作为权威；模型服务不持有 peer/Group 的路由授权账本，也不能自行升级身份。ChatGPT 插件可由 MCP server 提供工具，并可选择附带 MCP Apps UI；是否以及如何暴露给 dot，须按当时受支持的插件、账号权限和运行环境单独验证。官方资料仅说 dot 可用受支持、已安装且启用的插件，**没有保证任意自定义 MCP 会自动供 dot 使用或无需专门批准**。[dot 的应用连接](https://learn.chatgpt.com/docs/dots/computers-and-apps)、[ChatGPT plugin/MCP quickstart](https://developers.openai.com/plugins/build/app-quickstart)

## 可选语音入口与明文责任

v0.2.x 可评估云端 GPT-Live WebRTC 语音适配器。它应是用户明确选择的 Client/Control 入口，保持本地 STT、离线文本和隐私优先选项；云端会话须有可见的费用/时长预算、主动停止、连接失效和停止后的权限收口。官方 WebRTC 文档描述浏览器音频轨道、事件数据通道，以及由受信应用服务器发起会话；这只证明存在可研究的集成方式，不证明 CICADA 已接通或取得特定账号能力。[GPT-Live WebRTC 文档](https://developers.openai.com/api/docs/guides/voice-webrtc)

任何外部模型都会看到调用方实际授予它处理的明文。CICADA 的后量子端到端加密只覆盖其已定义的 Client/Node peer 或 Board 密封边界；不能把第三方模型推理、云语音传输或第三方语音记录描述为 provider-blind，也不能宣称 NIST E2EE 覆盖整个第三方语音链路。未来接线时须显式列出发往模型服务的内容、保存范围与用户可撤销的访问。dot 的 ChatGPT 移动使用仍取决于官方所说的支持更新，移动网页不支持；因此它不是 v0.1.x 移动 Client 的替代交付路径。[dot 渠道说明](https://learn.chatgpt.com/docs/dots/channels)

## 进入实现前的判定

单独确定受支持的产品入口、账号/插件许可、最小 MCP 工具与动作范围、用户批准及撤权体验、语音预算/停止语义、明文流向和断线恢复；再做隔离的权限拒绝与真实服务互操作验收。未完成这些检查前，本路线保持 `PLANNED`，不进入 v0.1.x 能力目录、合同或验收矩阵的 PASS 项。
