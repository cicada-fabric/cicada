# Client ↔ 固定 Hub v1.2 联合验收记录

**日期：**2026-09-25

**Client 实现提交：**`3c2d8e14457d10aaf9b88bbe56215e2c10ff856a`（`dev/react-native`）

**范围：**仅在本仓库更新 Client、协议快照和测试驱动；真实 Hub、Node 与 Codex 均使用一次性隔离状态。未修改 CICADA 工作树、Hub 数据库文件或常驻开发 Hub；未推送或合并。

## 固定对象与独立核验

| 对象 | 固定值及结果 |
|---|---|
| Hub 源码 | `41beaf0fa57e8279ad993fa4ce070a33515851ba`；协议 manifest 的 `source_dirty=false`。 |
| 协议包 | `../CICADA/.cicada-data/contracts/client-hub-e42cdca3d9f2b8719179476e2e7e87a2a9793c8c5b2a8352331928f882d18d5d.tar.gz`；SHA-256 `e42cdca3d9f2b8719179476e2e7e87a2a9793c8c5b2a8352331928f882d18d5d`。已导入 [`contracts/client-hub-v1.2-41beaf0/`](../contracts/client-hub-v1.2-41beaf0/manifest.json)。 |
| 合同 | `client-hub-v1.2`；catalog 原始字节 SHA-256 `613084ee67f75d27762ddaf59ec2e5b33ebea7383cbfcf455a50b472e756c66a`。 |
| Hub 镜像 | 完整 image ID `sha256:528dc6817a35a37c1c028dce85243afb3a7e42b4b04ed9410bd68046ef7d67e8`。OCI revision、catalog 和 dirty 标签与包一致；没有仅凭可变 tag 作判断。 |
| 实际运行时 | 一次性容器 `cicada-client-hub-v12-41beaf0`，宿主机仅 `127.0.0.1:8794`；Android 35 模拟器通过 `10.0.2.2:8794`。加密 `session.capabilities` 返回 manager、上述合同与 catalog；公开能力的 `status_events=false`、`external_thread_links=false`。 |
| Docker 与状态 | Docker Root `/gpu1-share/data/docker-root`；测试状态、Owner/Node 密钥和原始日志在 `/gpu1-share/data/cicada-client/hub-v1.2-41beaf0/`，目录及证据文件权限分别为 `0700`、`0600`。隔离 Hub 使用测试专用身份与全新数据库，Owner 公钥仅通过正式 `owner-key register` 命令登记。 |
| Android 包 | debug APK SHA-256 `65eff9c51f4c0b9416b36b1d96fac458ac6980f06fd9798e93350c8b60251d19`；AndroidTest APK SHA-256 `f6fd23ef9a64a054fdf6b19cced0de4b6a202e1eea5312e5a283f95b66b2b847`。二者均非发布包。 |

固定提交的 `scripts/client-contract.py verify <协议包>`、本仓库 `python3 scripts/check-client-contract.py`、tar 原始 SHA-256、manifest 的 12 个文件及 catalog 校验均 exit 0。CICADA 工作树在验收期间前进，故复核使用 `git show 41beaf0...:scripts/client-contract.py` 取出的**固定提交脚本**；当前核心 HEAD 的导出文件清单已不同，不能拿它检验旧固定包。镜像校验、固定脚本输出及运行时 Android 加密能力结果见仓库外 `fixed-target-summary.json`、`pinned-contract-verify.log` 和 `manager-correct-encrypted-capabilities.log`。

## 结果矩阵

Android 测试命令在 `cicada-client-interop-emulator` 容器中使用 `/opt/android-sdk/platform-tools/adb -s <serial> shell am instrument -w -e class <class#method> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner`。ADB 进程本身可能在 JUnit 失败时返回 0，因此下表的 PASS 同时要求日志出现对应 `OK (N tests)` 且没有 `FAILURES`。完整参数中的测试 Grant、设备公钥、短码和 marker 仅位于 Git 外权限受限的证据目录；表内不记录这些原文。

| 项目 | 结果、命令与退出码 | 脱敏证据 |
|---|---|---|
| 固定包、镜像、运行时能力 | **PASS**。固定提交的 `client-contract.py verify`、`python3 scripts/check-client-contract.py`、`docker image inspect <完整 image ID>` 均 exit 0；模拟器 `ClientHubInteropTest#enrollAndRead` 验证加密 `session.capabilities` 为 manager、v1.2 和固定 catalog，JUnit `OK (1 test)`、ADB exit 0。 | `fixed-target-summary.json`、`pinned-contract-verify.log`、`manager-correct-encrypted-capabilities.log`。 |
| Kotlin 密码学向量与本地恢复锁 | **PASS**。最终测试 APK 的 `ClientWirePublicVectorTest` → `OK (5 tests)`，`ClientHubRecoveryLockTest` → `OK (3 tests)`，ADB exit 0；独立核对双向解密、签名、AAD、route/sequence 和篡改拒绝。 | `final-kotlin-vectors.log`、`final-recovery-lock.log`。 |
| 登记 HTTP 201 丢失 | **PASS**。故障代理 `--drop-path /v2/client/devices/enroll` 记录上游 `201` 后丢弃首次下游响应；模拟器 `emulator-5554` 的 `lostEnrollment201ReplaysPersistedGrantAfterSessionReconstruction` 用同一持久 Grant 跨会话重建恢复，`OK (1 test)`、ADB exit 0。 | `loss-repeat/lost-enroll-201-repeat.log`、`loss-repeat/proxy-enroll-201.log`（上游 `201` 后丢弃）。 |
| 加密 RPC HTTP 200 丢失 | **PASS**。故障代理 `--drop-path /v2/client/rpc --drop-operation status.snapshot` 记录上游 `200` 后丢弃首次下游响应；同一模拟器的 `lostRpc200RecoversSameEncryptedResponseWithoutNewOperation` 用原签名包 `/v2/client/rpc/recover` 恢复，序号与 operation ID 未变，`OK (1 test)`、ADB exit 0。 | `loss/lost-rpc-200.log`、`loss/proxy-rpc-200.log`（上游 `200` 后丢弃）。 |
| 真实 Android → Hub → Node Agent → Codex → Android 审批 → 结果 | **PASS**。`emulator-5592` 经加密 `nodes.preview/confirm` 绑定新 Node；`submitBoundedRealCodexGoal`、`approveOriginalRealCodexTurnAndReadResult` 各 `OK (1 test)`、ADB exit 0。固定镜像中提取的真实 `cicada machine agent --once` 运行 exit 0；Codex CLI `0.156.1` 使用 `gpt-5.6-luna`，模型凭据只读挂载于一次性 Codex 容器。Android 对一个原生 command approval 经加密 `approvals.list/decide` 作 `accept`；Node 同一 Worker attempt 1 的认证结果 HTTP 200，`completed`，目标文件内容精确匹配。Android 从 `intent.status` 读到 `DONE`，从 `goal.result(intent_id)` 分别读到 Intent `resolved`、Goal `completed`、Worker `completed` 和有界 Artifact 数组。 | `native-e2e-summary.json`、`android-native-4-submit.log`、`android-native-4-approve-result.log`、`node-result.jsonl` 中与该 Worker 摘要对应的一行。 |
| 原生会话连续性 | **PASS**。Android 所见审批 `request.threadId` 的 SHA-256 与 Node 通过认证结果路由回报的 `thread_id` SHA-256 完全相同：`19210c2299eb4669d06f4ee0542363e80bf2410f700b0369c43ce438e3a6180d`。结果记录的 Worker SHA-256 为 `514008e3065504b44190a2fdbf07c031fa591a37b87c2b3b79e6f4fc04b81163`，attempt 为 1。Node 与原生 Codex turn 在审批前后保持运行，没有另建 Worker 或 Thread。 | `native-e2e-summary.json`；脱敏 Intent/Goal/Worker 前缀分别为 `intent_16178`、`goal_2137706`、`worker_eca97`。 |
| 管理授权及禁用密钥签署 | **PASS**。最终测试 APK 的 `managerReadAndRejectionMatrixAgainstDockerHub` → `OK (1 test)`、ADB exit 0；读取状态、拓扑、Node、Approval、设备和 Intent，Guard 拒绝无效写入，Android 本地 allowlist 拒绝 `group.key_manifest/grant/status` 和 `link.key_*`。 | `final-manager-matrix.log`。 |
| 全新模拟器 UI 与信任拒绝 | **PASS**。`CICADA_EMULATOR_VECTOR_CHECK=1 CICADA_EMULATOR_SECURITY_CHECK=1 CICADA_EMULATOR_HUB_BASE_URL=http://10.0.2.2:8794 ./scripts/docker-emulator-check.sh` exit 0；五页及输入面板、错误 Hub pin/Grant 拒绝、五项 Kotlin 向量。 | `fresh-ui-smoke.log`。 |
| 中断后原包恢复 | **PASS（测试辅助路径）**。测试期间故意停止轮询后，Android 保留 pending 原包；`recoverInterruptedReadOnlyApprovalPoll` 经 `/recover` 取回已接受响应；另一次只读查询收到 409 `RECOVERY_REJECTED` 后，测试明确调用 `retryPendingExact` 发送同一原包。两次均 `OK (1 test)`、ADB exit 0。此结果不代替下列三种故障注入。 | `android-recover-interrupted-poll.log`、`android-recover-rejected-exact-retry.log`。 |
| `STILL_PROCESSING`、重启后签名密文 `OUTCOME_UNCERTAIN`、旧请求 `RECOVERY_UNAVAILABLE` | **NOT_RUN**。当前固定运行镜像没有安全、确定、可复跑的隔离故障驱动；不能通过读写 Hub 数据库或生产故障开关制造 PASS。Client 保留 pending 密文、计数和阻断策略。所需入口见[核心接口请求](hub-interface-requests-v12.md)。 | 无运行镜像 Android 故障证据。 |
| `group.key_grant` | **BLOCKED**。固定包的 Endpoint attestation 合同排除 `signature`，固定 Go 签名原文包含 `"signature":null`；未收到统一签名字节、完整公开向量与新固定交付前，Client 不验收 `group.key_manifest`、不签 owner proof。 | [核心接口请求](hub-interface-requests-v12.md)。 |
| Android 真机 | **NOT_RUN**。本轮仅有 Android 模拟器，无物理设备验收。 | 无。 |
| 公网 HTTPS | **NOT_RUN**。本轮只有回环 Hub 和模拟器宿主机映射；没有公网证书、延迟与设备网络验证。 | 无。 |

测试前期的隔离运行未达到验收门槛，已留在隔离状态中作为失败记录：第一次是一次性包装脚本的 Python 转义错误，后续两轮是测试代理未读取 Node Workspace 上传的 HTTP chunked 请求体。代理出现 `Bad request syntax ('800')` 后按标准分块格式读取并转发，请求复测为 `POST` 404、随后 `GET /healthz` 200；用全新 Node、Codex 状态与审批目标完成上表的正式通过轮次。未把失败轮次的受控文件写入当作 Goal 成功，也未将旧队列中的 Worker 算进通过结果。

## 安全与交付边界

Client 只持有设备私钥、固定的 Hub 公钥和加密 Client 会话；Node bearer 留在 Node 私有状态，Hub 管理 bearer 与模型凭据均未进入 Android、Git 或 APK。模型凭据文件位于 Git 外，权限为 `0600`，只读挂载到一次性 Codex 容器。测试代理只用于回环隔离联调，不记录请求包、Grant、审批正文或 bearer；对 Node 回报只保存 Worker 与 Thread SHA-256、attempt、状态和 Hub HTTP 状态。原始测试输出留在 Git 外权限受限目录，不随此报告提交。

`status_events=false` 时 Client 继续使用 partial changes 加快照对账；`external_thread_links=false` 时只展示跨用户连接提案。这里的 Client↔Control 后量子应用层加密不证明普通 peer 正文对 Hub 盲化。debug APK 的模拟器 HTTP 端口仅在 `BuildConfig.DEBUG` 下开放；发布构建要求 HTTPS。隔离测试完成后已停止并移除一次性 Hub 与故障代理，未触碰常驻开发 Hub。
