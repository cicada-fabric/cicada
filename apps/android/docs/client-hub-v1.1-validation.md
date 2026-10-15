# Android Client ↔ Hub `client-hub-v1.1` 验收（2026-09-24）

## 版本与可复核对象

| 对象 | 实际值 |
|---|---|
| Client 分支 / 本轮实现提交 | `dev/react-native` / `179e0efb148b3f9da55a93e2630d3a4955abb5d4` |
| 核心源码 | `fb0f07a2330084b9402eb72878388bd1866bee10`，构建元数据 `source_dirty=false` |
| 合同 | `client-hub-v1.1`，catalog SHA-256 `f6f05783ddc00e51b92ebe050b5d8e6b9b185fae80d8fc6f04bc3143b6782374` |
| 原始协议包 | SHA-256 `a6655205f0145ba1aa81aa968229fbcd1c6bfe052ab3e6364d7a32278d3f8cad`；核心 `client-contract.py verify` 和本仓库 `scripts/check-client-contract.py` 均通过 |
| 本轮真实测试 Hub | `cicada-client-hub-v1-1`，Docker image ID `sha256:928763068ac72d9a27ba883a7212fb5dda875127a125b8d45ae0bd2805ab8c44`，本地回环 `127.0.0.1:8788`，构建证明见 `/gpu1-share/data/cicada-client/hub-v1.1/build.json` |
| Client 构建镜像 | Node `24.21.0` Active LTS、npm `12.1.0`、Gradle `9.4.1`、Temurin JDK `25.0.4.1` LTS；Docker image ID `sha256:375c6fb48e660b100f61b56fdefd9ab7ae6df2198823452da1cf78e4f62ba65d` |
| 最终 Android debug APK | `/gpu1-share/data/cicada-client/build-output/cicada-client-debug.apk`，SHA-256 `80d10e09443d163382bf0b98ee024948f77c1af132a5adc073465dddf96b01fd` |
| 最终 AndroidTest APK | `android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`，SHA-256 `68c5fd418b9f1c8eba26e99664866832a6a366a88f7ad7a72799fd5453b3554a` |

Docker Root 为 `/gpu1-share/data/docker-root`，开发缓存和原始测试输出位于 `/gpu1-share/data/cicada-client`。Hub 镜像由核心 `./scripts/run-client-hub-dev.sh` 基于上述干净提交启动。另一个旧容器 `cicada-client-hub-dev` 的镜像缺当前合同来源证明，本页不使用其 Android 结果作为 v1.1 验收。合成 Owner 私钥、Grant、测试包和模型权重只存放在 Git 外数据目录；本轮构建的 App debug APK 已检查，不含公开测试向量、私钥或 bearer。签名发布 APK 尚未构建。

下表中 `.../文件名` 的完整目录前缀是 `/gpu1-share/data/cicada-client/hub-v1.1/android-interop/`。

## 分层结果

| 层级 | 执行与结果 | 本项证明的范围 |
|---|---|---|
| 协议包完整性 | `python3 scripts/check-client-contract.py` → `PASS`，exit 0；原始 tar 的核心验证也通过 | 导入的 7 个文件大小、SHA-256、源提交和 catalog 一致。 |
| Kotlin 公开向量 | JDK 25 重编译测试 APK 的 `ClientWirePublicVectorTest` → `OK (5 tests)`，ADB exit 0；输出 `/gpu1-share/data/cicada-client/hub-v1.1/android-interop/wire-vectors-jdk25.log` | Android Kotlin 独立解密两个方向的公开包，核对 canonical AAD、ML-DSA 签名、路由绑定；改动 epoch/operation、签名或有效重签后的 GCM tag 均拒绝。 |
| Android N4 本地锁 | JDK 25 重编译测试 APK 的 `ClientHubRecoveryLockTest` → `OK (2 tests)`；输出 `.../n4-lock-jdk25.log` | 合成的登记不确定和 RPC 409 状态经重建后仍阻止重登、换身份、改 Hub、重发或新 RPC，原包与计数不变。它不是 Hub 的恢复协议。 |
| UI / 信任拒绝 | `CICADA_EMULATOR_VECTOR_CHECK=1 CICADA_EMULATOR_SECURITY_CHECK=1 CICADA_EMULATOR_HUB_BASE_URL=http://10.0.2.2:8788 ./scripts/docker-emulator-check.sh` → exit 0；五页与输入面板通过、错误 Hub pin/无效 Grant `OK (1 test)`、向量 `OK (5 tests)`；原始日志 `.../fresh-jdk25-final.log` | 新 Android 35 x86_64 模拟器启动；候选身份不能自动固定，错误 pin 和无效 Grant 在登记前被拒绝。 |
| 真实 Docker Hub Android 加密互操作 | 先前同一 v1.1 Hub 的 `enrollAndRead` → `OK (1 test)`，真实 Owner Grant/201/encrypted capabilities/snapshot/changes。JDK 25 重编译 APK 覆盖安装后 `currentV11ExternalReadsUseEncryptedCapabilitiesAndKeepKeyRpcDisabled` → `OK (1 test)`，日志 `.../current-hub-read-jdk25.log`；同一代码上的 Link 提案、设备列表/自撤销 Guard、非法 RPC 也各 `OK (1 test)`。 | 最终 APK 的加密能力校验、`owner_attributed_v2` 快照、partial changes、仅提案 Link、设备列表/自撤销拒绝和非法 RPC 本地拒绝。当前测试 Owner 是 `external`，不声称有 Manager 写权限。 |
| 真实 Hub HTTP 409 | JDK 25 重编译测试 APK 的 `realHubReplayConflictFreezesAnIsolatedAndroidSession` → `OK (1 test)`；日志 `.../replay409-jdk25.log` | 从真实已登记设备复制加密本机状态到隔离上下文，以旧 sequence 新密文触发当前 Hub replay guard 的 HTTP 409；Client 持久保留原包，跨实例停止恢复与新 RPC；真实 App 会话计数不变。没有模拟 `UNCERTAIN` 终态。 |
| 断线与 Activity 重启 | JDK 25 APK 对当前 Hub `:8788` 执行 `scripts/interop/run-activity-recovery.sh`，阻断 TCP、写入原包、重启 Activity、恢复联网和权威快照 → exit 0；离线/恢复各 `OK (1 test)`；日志 `.../recovery-jdk25-final.log` | 普通传输失败时精确重发原密文，响应认证后对账；这不等于 409/UNCERTAIN 的安全恢复。 |
| 撤权 | 同一 v1.1 Hub 上可丢弃设备的 Android `revokeDisposablePeerDeviceWithVersionGuard` → `OK (1 test)`；陈旧版本加密业务拒绝、按当前版本撤销后列表为 REVOKED，随后该设备的新密文 RPC 返回 HTTP 403。最终 APK 的自撤销 Guard 测试再次通过。 | 设备撤权及 Guard 的模拟器/Hub 协议路径；没有生产设备撤权。 |
| 真实推理 | JDK 25 重编译 APK 的 `SpeechInferenceTest` → `OK (4 tests)`，12.215 s；SenseVoice、Paraformer、Vosk 中文/英文识别已校验公开 WAV；日志 `.../stt-four-models-jdk25.log`。 | Android x86_64 JNI 与当前 Gson/JNA/AAR 组合可运行；样本来自文件，非真机麦克风。下载、校验、中断和 UI 安装路径见 [STT 记录](stt-validation.md)的前一阶段模拟器结果。 |
| Go 协议模拟 | 从核心 `fb0f07a` 的 Git 外干净克隆执行 `./scripts/test-client-hub-interop.sh` → exit 0、`status=PASS`、`level=real_tcp_hub_go_protocol_client`，证据 `/gpu1-share/data/cicada-client/hub-v1.1/protocol-smoke-pinned/result.json`。该测试自身重建的 Hub image ID 为 `sha256:98021d94f815cb63617c2be7a00b3c0a54f8b7d3bdbf26377dd8c17605eb9e4e`。 | 真实 TCP Hub 的 Go 协议 Client、原包重放、Node code/heartbeat 和 Owner 状态隔离。它的 `android/native_runtime/public_https` 字段均为 `NOT_RUN`，不能借此声称真实 Codex。 |
| 构建与依赖 | Temurin JDK 25 强制重跑 `:app:assembleDebug :app:assembleDebugAndroidTest --rerun-tasks` → exit 0，116 tasks executed，日志 `/gpu1-share/data/cicada-client/jdk25-trial/gradle-rerun.log`；正式 `./scripts/docker-build.sh`、`./scripts/docker-build-android-test.sh` 均 exit 0，日志 `.../docker-build-jdk25-final.log`、`.../docker-build-android-test-jdk25-final.log`；`tsc --noEmit --noUnusedLocals --noUnusedParameters`、`npm run lint -- --quiet`、`git diff --check` → exit 0；官方 npm registry 上完整及生产依赖 `npm audit` 各 0 项已知告警。`:app:processReleaseMainManifest` → exit 0，合并结果含 `allowBackup=false`、`usesCleartextTraffic=false`，日志 `.../release-manifest-jdk25-final.log`。 | 固定锁文件可构建且静态检查通过；npm audit 不覆盖 Gradle/AAR 或未知漏洞。Debug APK 未当作签名发布产物。 |

Android 嵌套业务 RPC 采用 ML-KEM-768 + ML-DSA-65 + AES-256-GCM；debug HTTP 只允许模拟器 `10.0.2.2:8787/8788`，发布配置要求 HTTPS。手机的业务正文终点是 Control，因此这里的 E2EE 是 **Client↔Control** 链路，不是普通 peer 正文对 Hub 盲化的证明。HTTP 200、Intent 分发 `DONE`、Node 接收都不等于 Worker 模型消费或 Goal 完成。

## 未通过 / 未运行

- **N4 安全恢复未完成：**核心 v1.1 对登记 201 响应丢失没有受认证结果查询；RPC 409/`UNCERTAIN` 没有可证明安全的原包终态对账。Client 保留原 Grant 摘要、设备身份、pending 密文和计数并冻结操作。真实 409 replay guard 已测；Hub durable accept 后重启导致 `UNCERTAIN` 的 Android 安全恢复 **NOT_RUN**，因为合同未定义。具体请求和复现见 [接口缺口](hub-interface-requests.md)。
- **Group/Link Key 签署关闭：**v1.1 `group.key_manifest` 没有向 Client 提供完整 Endpoint self-attestation proof，Android 无 Node bearer。`link.key_*` 与 `group.key_*` 即使被 Hub 广告，也未纳入原生 RPC allowlist。`external_thread_links=false` 只展示提案，`status_events=false` 不显示实时事件。
- **N5 真实闭环 NOT_RUN：**当前 Hub 镜像没有已启动的真实 Node Codex Worker，现有核心 Go 测试用人工 claim/result 且不产生真实 Approval。本轮没有把模拟协议结果写成 Android Intent→真实 Worker→审批→结果的完成证据。
- **Android 真机、真机麦克风性能、生产公网 HTTPS 与签名发布 APK NOT_RUN。** 这些结果必须另列，不能由模拟器或本地回环 HTTP 推断。
