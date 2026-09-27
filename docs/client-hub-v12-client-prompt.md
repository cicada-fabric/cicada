# 给 CICADA_CLIENT 开发者：固定并验收 Client–Hub v1.2

请只修改 `CICADA_CLIENT` 仓库；不要在 Client 仓库复制 Hub 授权业务、读取 Hub
SQLite，或把 Node bearer/管理 bearer 放进 Android。当前 Client 起点由开发者报告为
`client-hub-v1.1`，实现提交 `179e0ef`、文档提交 `b298fd8`。这些结果不能直接
算作 v1.2 验收。

先从 Hub 维护者提供的交付记录固定四个值：CICADA 完整 commit、协议包
SHA-256、`catalog_sha256`、完整 Docker image ID。校验协议包 manifest 的
`source_dirty=false`、`source_revision` 与 commit 一致、逐文件摘要正确，并
独立核对 image 元数据的 source revision/catalog 摘要。不要只固定可变 tag。
以包内的 `docs/client-hub-wire-v1.md`、OpenAPI、公开合成密码学向量和
`docs/client-hub-v12-validation.md` 为实施与验收依据。

按下面顺序开发和记录 PASS/FAIL/BLOCKED/SKIPPED：

1. 更新 Kotlin packet/签名/封装解析并重跑**独立 Kotlin 向量**。将未知
   `available_rpc_operations` 安全忽略；向 Hub 发送 `session.capabilities`，
   比较运行时 revision/catalog SHA，而非以文档或 tag 猜版本。
2. 持久化原始签名密文请求、`operation_id`、请求序号、预期响应序号和 pending
   状态。设备登记 HTTP 201 丢失后原样重发**相同** Grant/身份；RPC 响应丢失
   或重启后将**原包**提交 `/v2/client/rpc/recover`。分别实测 `COMPLETED`
   原密文响应、处理中 409 `STILL_PROCESSING`、v29 崩溃后已签名密文
   `OUTCOME_UNCERTAIN`、旧无预留响应序号 409 `RECOVERY_UNAVAILABLE`、错包和
   已撤销设备拒绝。`OUTCOME_UNCERTAIN` 只退休传输 pending，业务状态保持
   “待核实”；任何 409 都不通过新 operation 重放副作用，也不猜测或重置序号。
3. 在同一 owner 会话验证 `intent.submit`→`intent.status`→`goal.result`；请求
   `goal.result` 使用 `intent_id`，展示 Goal/Worker 终态、摘要及不含正文的
   Artifact 引用。Intent DONE 不能等同 Worker/Goal 成功。跨 owner 结果、
   非 Goal Intent、未完成 Goal 必须按合同处理。
4. `group.key_manifest` 的 `candidate_attestation` 是完整 Endpoint 自签
   JSON 的 base64，不是已验证布尔值。先核对其原始字节 SHA-256 与
   `candidate_proof_digest`，用完整 ML-DSA-65 公钥验证域分离签名，比较
   Endpoint/Principal/Node/SessionBinding ID 与 epoch、完整公钥、key ID、
   指纹、Membership/Group/Join revision、binding digest、manifest digest
   和当前 owner 意图；全部通过后才允许 owner key 签 `group.key_grant`。
   缺证明、签名错误、绑定过期或版本变化必须拒绝并重新预览。
5. 用固定 image 在独立 Docker Hub 上跑真实 TCP/重启/丢响应测试，再跑
   Android 模拟器和真机验收。保留脱敏日志、测试命令、退出码、Hub/Client
   commit、包 SHA、catalog SHA、image ID、APK SHA。不得把 Go 或 v1.1
   结果冒充 Kotlin/Android v1.2 通过。

Hub 的 `goal.result`、恢复路由与远端 Node Codex 审批桥已提供，见包内
`docs/client-hub-v12-validation.md`。Client 直接使用现有加密
`approvals.list/decide`，不持有 Node 凭据，也无需另设计权限模型。Hub 侧已用
真实 Node Agent、真实 Codex 和加密合成 Client 协议驱动通过隔离的
Worker→审批→结果闭环；这不是 Android 验收。请在固定版本的隔离环境中
另外记录真实 Worker 等待、**手机**批准、同一原生 turn 继续、
`goal.result` 返回的证据；未运行的层级明确标为 NOT_RUN 或 BLOCKED。

请在 Client 仓库提交实现和验收记录，不推送、不合并 CICADA 仓库；将固定
版本和各层测试结果回传 Hub 维护者，供后续联合验收。
