# 给 Android Client 开发者的下一阶段任务

只修改 `~/CICADA_CLIENT`，保留已有实现；不修改 CICADA 核心。当前 Client
`836d422` 已有真实 Hub RPC、状态与管理 UI、本地 STT 和双 Owner Link
提案，不要重复开发这些基线，也不要将提案视为已开通跨用户通信。

先读 CICADA 的 `docs/client-hub-development.md`、`docs/client-hub-handoff.md`
和导出的协议包。以 `catalog.json`、OpenAPI、wire 文档为同一修订的契约，
固定 Hub commit、镜像 ID/digest、`contract_revision`、`catalog_sha256` 与
Client commit/APK 摘要。不要只测试未知 revision 的常驻 Hub。开发实例与
一次性测试实例使用不同名称、端口、状态和测试身份。
Client 构建工具链请单独核对上游支持范围并固定受支持的 LTS；截至
2026-09-24，Node.js 24 为 LTS，26 仍为 Current。CICADA 仓库不配置
Client 的 Node.js，也不修改 `~/CICADA_CLIENT`。

按序执行：

1. 用 Kotlin 读取协议包公开合成 vectors，验证双向解密、AAD、签名和篡改/
   错误绑定拒绝；测试密钥绝不进入正式设备初始化。Go 自测不能替代 Kotlin。
2. 加密 `session.capabilities` 与本机操作实现求交。新增 Group key operations
   不自动变成手机功能；尚未实现的签署验证继续关闭。独立可信 Hub 公钥
   pin 与 Owner Grant 保持必需，未知字段不得自动提供权限。
3. 使用 `client-hub-v1.2` 的 Hub 恢复协议：登记 HTTP 201 丢失时原样重发
   已签名的登记请求；RPC 响应丢失时将原始加密 REQUEST 包发送到
   `/v2/client/rpc/recover`。校验原 operation ID、签名和下一响应序号；
   `OUTCOME_UNCERTAIN` 只结束传输 pending，业务仍须显式标为不确定并查询
   权威状态。`STILL_PROCESSING` 保留 pending，`RECOVERY_UNAVAILABLE` 停止并
   提示人工对账。不能猜 epoch、重置 counter 或新建同义动作绕过不确定性。
4. 用确定版本的 Docker Hub 验证从 Android Intent 到 Node Worker 的结果
   回传：先查询 `intent.status`，再以原 `intent_id` 调用 `goal.result` 读取
   bounded summary 和 Artifact 引用；真实审批另行验收。区分协议替身测试和
   真实 Codex。队列暂停不冒充运行中停止。
5. 补充真机录音、前后台/进程终止恢复、公网 HTTPS 与签名 Release APK 验收。

`external_thread_links=false` 时只展示邀请/提案，`status_events=false` 时
使用 partial changes 加定期快照。`link.key_grant` 需要完整 canonical
contract、双方 Endpoint attestation 与当前绑定验证，不能只加一个同意按钮。
手机不持有 Hub/Node bearer，不读 Hub SQLite，不调用旧 `/v1` 管理 API。

交付按“实现、平台测试、Docker 联调、真实任务、真机/生产”分别记录。
缺少环境标 `NOT_RUN/BLOCKED`；证据保存合成标识与结果，不保存真实密钥、
完整 Grant、敏感输入或邀请 token。用户不需要承担两仓之间的接口信息搬运。
