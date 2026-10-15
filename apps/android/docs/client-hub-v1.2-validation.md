# Android Client ↔ 固定 Hub `client-hub-v1.2` 验收（2026-09-24）

## 固定对象与证据边界

| 对象 | 本轮固定值 |
|---|---|
| Client 分支 / 实现提交 | `dev/react-native` / `befff5f97052fc3db684ab5bee716f5fe53e7e3d`；起点 `b298fd82f68a94b2f6586a07ab10cda4bcd84cc8` |
| Hub 源码 | `01d51ece186a7ec53dc2a83b77e05085f939bd28`；协议包 manifest 的 `source_dirty=false` |
| 协议包 | SHA-256 `628910647ecca9cf1b6d72a2872e22f6b0158b421a92b6349331a1bfdb640151`；已原样导入 `contracts/client-hub-v1.2/` |
| 合同 | `client-hub-v1.2`；catalog SHA-256 `613084ee67f75d27762ddaf59ec2e5b33ebea7383cbfcf455a50b472e756c66a` |
| 运行镜像 | `cicada:client-hub-v1.2-01d51ec`，实际完整 image ID `sha256:e31b4c5dc6fceb27932fbc4e5a43afac425b6ef0647a3c7f25788ff52b31585b`；OCI 标签的源提交、catalog 和 dirty 标志均匹配 |
| 隔离 Hub | `cicada-client-hub-v1-2`，回环 `127.0.0.1:8789`；manager 测试实例 `cicada-client-hub-v1-2-manager`，回环 `:8792`，两者完整 image ID 相同 |
| 开发数据 | Docker Root `/gpu1-share/data/docker-root`；隔离状态与脱敏测试日志在 `/gpu1-share/data/cicada-client/hub-v1.2/`，不进 Git/APK |
| 最终 debug APK | `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`，SHA-256 `1079c6a7bd000851aa0cedb45cd65a59913f87cd31bf3fd496df998ba3e181dd`；不是签名发布包 |
| 最终 AndroidTest APK | `android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`，SHA-256 `69fc711b6030fd5b429c8cd88c6dded9ac0a2ff6f6204075137f465d74baea30` |

`python3 scripts/check-client-contract.py` 与核心 `client-contract.py verify` 对协议包逐文件、manifest、完整源提交和 catalog 原始字节校验均 exit 0。运行中的两个 Hub 的**加密** `session.capabilities` 分别返回 `client-hub-v1.2` 和上述 catalog 摘要，Android 外部 owner 与 manager owner 的独立登记读取均 exit 0。可变 image tag 与公开 `/capabilities` 均未单独作为认证依据。v1.1 测试及 APK 摘要不用于本轮验收。

## 本轮实测矩阵

Android 命令统一为容器内的 `adb -s emulator-5592 shell am instrument -w -e class ai.cicada.client.<类名>#<方法名> ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner`，工具路径 `/opt/android-sdk/platform-tools/adb`。敏感 Owner 密钥、Grant、Node 测试 bearer、原密文及模型权重只在 Git 外的隔离数据目录和 Android 私有存储。下列日志只写脱敏文件名，不在仓库附带原始身份材料。

| 项目 | 执行结果与原始证据 | 证明范围 |
|---|---|---|
| 独立 Kotlin 向量 | 最终 APK 的 `ClientWirePublicVectorTest` → `OK (5 tests)`，ADB exit 0；`android-interop/final-kotlin-vectors.log` | 用 Kotlin 独立打开公开双向密文，核对签名、AAD、route/sequence；篡改签名、路由或 GCM tag 被拒绝。 |
| 本机持久锁 | 最终 APK 的 `ClientHubRecoveryLockTest` → `OK (3 tests)`，ADB exit 0；`android-interop/final-recovery-lock.log` | 旧无完整序号的 pending 与旧无原始字节的登记尝试跨重建保持冻结；签名不确定结果在快照对账前禁止新写入。 |
| 201 响应丢失 | 故障代理先让固定 Hub 持久接受，再丢弃首次 201；`lostEnrollment201ReplaysPersistedGrantAfterSessionReconstruction` → `OK (1 test)`，exit 0；`android-interop/lost-enroll-201.log` | 同一 Grant 请求字节跨 `ClientHubSession` 重建原样重发，Hub 返回同一设备 epoch/key version。 |
| 200 RPC 响应丢失 | 故障代理丢弃首次 `status.snapshot` 成功响应；`lostRpc200RecoversSameEncryptedResponseWithoutNewOperation` → `OK (1 test)`，exit 0；`android-interop/lost-rpc-200.log` | Android 保留原签名包与预期响应序号，经 `/v2/client/rpc/recover` 完成，不新建 operation。另用固定 Hub 对原包重复 `/recover` 比对返回密文字节一致。 |
| 未到达 Hub | 临时模拟器 iptables 阻断测试代理；`offlineLeavesExactPending` 与 `unacceptedOfflineRequestRequiresExplicitExactRetry` 均 `OK (1 test)`，exit 0；相应 `android-interop/*.log` | `/recover` 的 409 `RECOVERY_REJECTED` 后，只在明确选择时将同一原包送 `/rpc`，不生成新计数。测试后已移除阻断规则。 |
| 错包、重放、撤权 | 固定 Hub 原包被篡改时 HTTP 403；`realHubReplayConflictFreezesAnIsolatedAndroidSession` 和 `revokeDisposablePeerDeviceWithVersionGuard` 各 `OK (1 test)`，exit 0；`android-interop/replay409.log`、`device-revoke.log` | 错密文/签名、旧序号新包、撤销后的设备调用均拒绝；Android 的孤立 replay 会话被冻结。 |
| 外部 Owner | `currentV12ExternalReadsUseEncryptedCapabilitiesAndKeepKeyRpcDisabled` → `OK (1 test)`；`android-interop/external-read.log` | 加密能力返回 external，状态可读；Group/Link Key RPC 保持本地禁用。 |
| Manager 只读与 Guard | 最终 APK 的 `managerReadAndRejectionMatrixAgainstDockerHub` → `OK (1 test)`，ADB exit 0；`android-interop/final-manager-matrix.log` | 加密状态、拓扑、Node、Approval、设备和 Intent 列表；无效审批决定被 Guard 拒绝。未用合成审批伪装真实 Worker 请求。 |
| 排队 Goal | Android `confirmDisposableNodeForQueuedGoal`、`queuedGoalLifecycleAgainstDockerHub` → 各 `OK (1 test)`；`android-interop/manager-node-confirm.log`、`manager-goal-submit-retry.log` | Android Intent→Hub→排队 Goal/Worker，`intent.status` 与 `goal.result(intent_id)` 独立读取，远端排队 pause/resume 使用版本校验。首次运行因测试 Node 未心跳失败；补充 Node 认证心跳后复跑通过。 |
| Worker 结果 | 测试 Node 仅通过 Node 认证的 HTTP 协议领取并回报一次合成结果；`completedGoalResultIsIndependentOfIntentDone` → `OK (1 test)`；`android-interop/goal-result-completed-protocol-fixture.log` | Intent `DONE` 与 Worker `COMPLETED`、Goal 终态及有限 Artifact 引用分开显示。Node 是协议 fixture，**不是实际 Codex**。 |
| UI / 信任拒绝 | 最终 APK 的 `CICADA_EMULATOR_VECTOR_CHECK=1 CICADA_EMULATOR_SECURITY_CHECK=1 CICADA_EMULATOR_HUB_BASE_URL=http://10.0.2.2:8789 ./scripts/docker-emulator-check.sh` → exit 0；`android-interop/final-fresh-ui-smoke.log` | 新 Android 35 模拟器五页、输入面板、错误 pin/无效 Grant 拒绝和五项 Kotlin 向量。 |
| Android 本地 STT | `SpeechInferenceTest` → `OK (4 tests)`、12.226 s；`android-interop/stt-inference-restored.log` | App 私有目录中已验证权重的 Vosk 中英、Paraformer 中文、SenseVoice Small INT8 对公开 WAV 的 JNI 推理。首次运行因模拟器清数据移除了权重而失败；恢复已核验权重后复测通过。非麦克风或真机性能。 |
| 固定提交 Go 故障测试 | Git 外的固定 commit 归档，Go 1.27.1 Docker：`go test -count=1 ./internal/store -run 'TestClientRecovery|TestGroupEndpointKeyGrant'` 和 `go test -count=1 ./internal/server -run 'TestClientRPCRecovery|TestClientIntentQueuesWorkForOwnerBoundMachineAgent|TestClientGroupEndpointKeyGrant'` → 均 exit 0；`go-store-tests.log`、`go-server-tests.log` | Store/HTTP 合成故障覆盖 `STILL_PROCESSING`、`OUTCOME_UNCERTAIN`、`RECOVERY_UNAVAILABLE` 等服务端语义；**不是固定运行镜像上的 Android 故障注入**。`TestClientDockerHubSmoke` 因使用旧 `/v1` bearer 和本地 DB 未用于 Client 验收。 |

## 未通过的验收门槛

- **Group Key Grant BLOCKED：**固定包的 Endpoint attestation 签名原文明确排除 `signature`，固定 Go 实现实际签入 `"signature":null`。不能独立验证全部候选证据，`group.key_manifest/grant/status` 保持 Android 原生 allowlist 外；Hub 只给出的摘要不能成为 owner 签名依据。请求、预期、复现步骤见[接口请求](hub-interface-requests-v12.md)。
- **固定镜像 Android 的三种恢复故障 NOT_RUN：**`STILL_PROCESSING`、Hub 重启后签名密文 `OUTCOME_UNCERTAIN`、旧 schema `RECOVERY_UNAVAILABLE` 由固定提交的 Go 测试覆盖，但运行镜像缺安全的确定性故障入口。Client 已实现状态处理、持久证据和禁止重复执行；需固定镜像独立验收，见[接口请求](hub-interface-requests-v12.md)。
- **真实远端 Node Codex Worker→审批→继续原任务 BLOCKED：**`approvals.list/decide` 已接入并测业务拒绝；后端远端原生审批桥尚未完成。合成 Node result 和人工审批记录不能替代。
- **Android 真机、真机麦克风性能、公网 HTTPS、签名发布 APK NOT_RUN。** 当前 ADB 只有模拟器。本地 debug HTTP 限制在模拟器；生产配置要求 HTTPS。`status_events=false` 隐藏推送，`external_thread_links=false` 只展示连接提案；普通 peer 正文不宣称 Hub 盲化。

## 最终构建记录

`./scripts/docker-build.sh` 和 `./scripts/docker-build-android-test.sh` 均 exit 0；Docker 中执行 `tsc --noEmit --noUnusedLocals --noUnusedParameters` 与 `npm run lint -- --quiet` 均 exit 0；`python3 scripts/check-client-contract.py`、`git diff --check` 均 exit 0。最终 APK SHA-256 见上表。最终 Android 35 模拟器安装此 APK/Test APK 后，Kotlin 公开向量 `OK (5 tests)`、恢复锁 `OK (3 tests)`、manager 加密能力及 Guard `OK (1 test)`、全新 UI/信任 smoke exit 0。上述 Git 外测试材料属于隔离开发环境，不能推入远端仓库。

Client 实现提交：`befff5f97052fc3db684ab5bee716f5fe53e7e3d`。本报告将作为后续纯文档提交；APK 对应的实现源码不受该文档提交影响。
