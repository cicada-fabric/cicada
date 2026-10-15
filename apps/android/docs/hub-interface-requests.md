# Client ↔ Hub v1.1 接口缺口

以下请求基于 `fb0f07a` / `client-hub-v1.1` 的实际路由与合成测试。Client 只调用公开 `/v2/client/*`，不读取 Hub 数据库，也不在手机保存 Hub 或 Node bearer。字段名与恢复流程由核心确定；本文不把建议当成已实现合同。

## N4：设备登记响应丢失

现行 `POST /v2/client/devices/enroll` 接收 `owner_id, owner_key_id, device_id, device_public_identity, owner_device_grant`。成功时返回 HTTP 201 和 `owner_id, device_id, session_epoch, device_key_version, state=ACTIVE`。若 Hub 已提交但 201 丢失，同一请求再次提交会与其他登记失败一样得到 HTTP 403 `{"error":"owner-authorized device enrollment failed"}`；没有登记结果查询或恢复路由。

**请求核心：**定义绑定原 Owner Grant、设备公钥、Hub 和一次性 nonce 的安全恢复交换。已提交、未提交、已撤销、过期和 Owner key 失效应有可区分的稳定结果；已提交时只能返回原 `session_epoch` / `device_key_version`，不得创建第二台设备或重用 Grant 授权新设备。请更新 wire、OpenAPI 和响应丢失及 Hub 重启测试。

**复现：**在隔离 Docker Hub 以受支持的本地 `owner-key register` 登记合成 Owner 公钥；生成新设备身份和精确 Grant。代理只转发首次登记，确认上游 201 后丢弃下游响应。Client 应保持 `enrolled=false`，持久 `enrollmentRecoveryRequired=true` 并关闭远程操作。测试 harness 原样再次提交，现行 Hub 返回上述 403。Client 现在本地拒绝再次登记、换设备身份和改信任根；这只是保守冻结，尚不能恢复。

## N4：加密 RPC 的 HTTP 409 / UNCERTAIN

`POST /v2/client/rpc` 的原始签名密文包、`sequence` 和 `operation_id` 在发送前持久化。已完成操作原包逐字节重发可得到缓存的相同加密响应。当前 HTTP 409 可能表示 replay/device guard、仍在处理、Hub 重启后的 `UNCERTAIN`、session changed 或 completion uncertain，但响应只有不稳定的 `{"error":"..."}`，没有对账、终态或安全退休协议。

**请求核心：**为原包提供经过设备认证且与原 `hub_id/owner_id/device_id/session_epoch/sequence/operation_id/packet digest` 绑定的权威结果。明确缓存响应恢复、仍在处理、确定未执行、`UNCERTAIN`、撤权和跨重启行为；只有在可证明安全时才能退休 pending 并继续单调计数，不能重新执行不确定动作。请提供稳定机器可读状态、wire/OpenAPI 定义和故障注入测试。Client 在合同前对首次 409 持久设置 `recoveryBlocked`，保留原包和计数，禁止重发、新 RPC、换 Hub 或换密钥。

**复现：**正常登记后发送有效 `sequence=1, operation_id=X` 包；再以相同序号重新 Seal 有效但随机密文不同的包，现行 Hub 返回 409 replay guard。Android `realHubReplayConflictFreezesAnIsolatedAndroidSession` 已在当前 Docker Hub 上用隔离状态复现此分支，验证原包与计数跨 `ClientHubSession` 重建保持不变，新 RPC 和原包重试被阻止。另在 durable accept 后、响应缓存前故障停止 Hub，重启同一隔离状态，再发原包应进入 `UNCERTAIN` 409 且不可重执行。现有 Store 测试覆盖状态转换；HTTP handler 的该故障注入与真正的 `UNCERTAIN` Android 恢复仍需核心协议。

## Group Endpoint 密钥签署的取证材料

`group.key_manifest` 当前只返回 `candidate_proof_digest` 和公钥身份，不返回完整 Endpoint self-attestation。完整 proof 只能从需要 Node Session 凭据的 `/v2/fabric/endpoint-keys/{endpoint}` 取得；Android 不应借用 Node bearer。Client 无法独立核对 Endpoint 对当前 `endpoint_id/principal_id/node_id/binding_id/binding_epoch/public_identity` 的 ML-DSA 签名，因此 `group.key_manifest/grant/status` 的 Client 调用入口均保持关闭。

**请求核心：**经加密的 Client manifest 结果提供与 digest 绑定的完整公开 Endpoint proof 和必要的当前绑定证据，或定义等效且无需 Node bearer 的取证接口。更新 canonical 合同、catalog 修订与测试向量后，Client 才能验证完整 manifest 与 Endpoint proof，再显示 Owner 签署按钮。服务端已有 Guard 不替代手机的独立验证。

**复现：**Node 使用 `/v2/fabric/endpoint-keys` 登记真实 attestation；获授权 Client 请求 `group.key_manifest`，结果只有 proof digest/public identity。手机无 Node 凭据，无法取得 proof bytes 进行本地验签。

## N5：真实 Worker 与审批闭环

核心 `TestClientIntentQueuesWorkForOwnerBoundMachineAgent` 使用 `httptest` 和人工 Node claim/result；它不启动 Agent，也不产生实际审批。旧 Android `queuedGoalLifecycleAgainstDockerHub` 只验了排队 Goal 和 pause/resume。两者都不能充当当前 Hub 的真实 Codex 闭环证据。

**请求核心：**提供一个隔离、无外部副作用、稳定触发待审批记录的任务和真实测试 Node Agent 运行方法，使 Android `intent.submit → Hub queued Worker → Node claim/执行 → approvals.list/decide → Node result → 加密 intent.status/status.snapshot` 可重跑。Node bearer 只留 Node。模拟 HTTP、真实 Codex、真机和公网 HTTPS 结果须分别记录。
