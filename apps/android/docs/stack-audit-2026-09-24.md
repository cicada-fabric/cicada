# Client 技术栈核对（2026-09-24）

本轮按上游正式发布、Android 可构建性和既有协议向量核对版本。`package-lock.json` 固定 npm 依赖；Gradle、Android AAR 和模型下载均使用明确版本或摘要。升级版本必须重新运行 Docker 构建、Android 协议向量和本地 STT 回归，不能只看 GitHub 的 Latest 标签。

| 组件 | 当前选择 | 核对与取舍 |
|---|---|---|
| React Native / React | `0.87.1` / `19.3.0` | [RN releases](https://github.com/facebook/react-native/releases) 中 0.87.1 是正式稳定版；0.88 为 RC。React 19.3.0 满足 RN 0.87.1 的 `^19.2.3` peer 范围。保留现有 Android UI 和跨平台 TypeScript 业务层。未来原生鸿蒙 UI 需用 ArkUI/ArkTS 实现，复用 wire 合同和产品流程。 |
| TypeScript | `6.0.3` | [TypeScript releases](https://github.com/microsoft/TypeScript/releases) 已有 7.0.2，但当前 RN ESLint 依赖链的 [typescript-eslint TS 7 支持](https://github.com/typescript-eslint/typescript-eslint/issues/12518) 尚未完成；当前 6.0.3 可通过类型检查。 |
| UI 辅助与格式工具 | `react-native-safe-area-context 5.10.0`、`Prettier 3.9.9`、`ESLint 8.57.1` | 前两项升到正式稳定版。RN 0.87.1 虽允许 ESLint 9，但其间接依赖 `eslint-plugin-ft-flow@2.0.3` 只接受 ESLint 8，实际锁定 ESLint 9 会出现 peer 冲突，因此保留最新的 ESLint 8 patch，并把该插件显式固定以适应 npm 12 的依赖布局。Babel 8 不在 RN Babel preset 的 `@babel/core ^7.25.2` 范围，所以保留 Babel 7.29.7。 |
| Android 构建 | Gradle `9.4.1`、AGP 由 RN 插件解析为 `9.2.1`、Temurin JDK `25.0.4.1` LTS、SDK 37 | [Gradle Java 兼容表](https://docs.gradle.org/current/userguide/compatibility.html)支持 JDK 25；[Temurin 25.0.4.1](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.4.1%2B1)以 SHA-256 固定并从 Git 外缓存进入 Docker 镜像。Android Gradle Plugin 9.2 仍以 JDK 17 为最低和默认基线，因此本轮另用 JDK 25 强制重跑 116 个 Gradle task，结果 `BUILD SUCCESSFUL`；模拟器协议、UI 和 STT 回归见 [v1.1 验收](client-hub-v1.1-validation.md)。[AGP 9.4](https://developer.android.com/build/releases/agp-9-4-0-release-notes) 与更新 Gradle 已发布，但升级需与 RN Gradle 插件联动验证。 |
| Node / npm 构建镜像 | Node `24.21.0-bookworm-slim`、npm `12.1.0` | [Node Release Working Group](https://github.com/nodejs/Release) 将 24.x 标为 Active LTS；[24.21.0](https://github.com/nodejs/node/releases/tag/v24.21.0) 是该线最新正式版。26.10.0 虽是更新的 Current 正式版，尚非 LTS；按用户最新要求选最新 LTS。npm [12.1.0](https://github.com/npm/cli/releases/tag/v12.1.0) 是最新正式版，其 Node engines 接受 24.21.0。两者只在 Docker 构建时使用。 |
| PQ 与 AEAD | Bouncy Castle `bcprov-jdk18on:1.86`、Android JCA AES-256-GCM | [BC 1.86 发布说明](https://github.com/bcgit/bc-java/discussions/2449)含安全修复。Client 仅组合官方 ML-KEM-768、ML-DSA-65 实现和 JCA；没有自写算法。设备 PQ 私钥由 Android Keystore AES 密钥包裹，但 PQ 运算仍在应用进程内完成，不声称硬件 PQ 密钥。 |
| Android JSON | Gson `2.14.0` | [Gson 发布页](https://github.com/google/gson/releases)的正式稳定版；本轮从 2.13.2 更新。安全相关字段另作类型、值和协议摘要校验，不把解析成功当成授权。 |
| Android 仪表测试 | AndroidX Test runner `1.7.0`、ext:junit `1.3.0` | [AndroidX Test 官方发布页](https://developer.android.com/jetpack/androidx/releases/test)列出的最新稳定版；本轮从 1.6.2/1.2.1 更新。 |
| Vosk JNI 依赖 | JNA `5.19.1@aar` | [JNA 5.19.1 变更](https://github.com/java-native-access/jna/blob/master/CHANGES.md)修复旧 Android 版本兼容问题；本轮从 5.18.1 更新。Vosk Android `0.3.75` 保持 Maven 固定版本。 |
| 端侧 STT | sherpa-onnx `1.13.8`、Vosk Android `0.3.75` | [sherpa-onnx 官方 release](https://github.com/k2-fsa/sherpa-onnx/releases/tag/v1.13.8)提供预编译 Android AAR，下载脚本校验 SHA-256。模型权重按需下载和校验，不放入 APK；现有中文/英文模型实测记录见 [STT 验证](stt-validation.md)。 |

Android 生态仍需使用 Java 字节码/互操作库，例如 Gson、JNA 和 Bouncy Castle；这不表示将 UI 改写为 Java。高频 UI 用 React Native/Hermes，设备密钥与 STT 适配层用 Kotlin，底层推理通过现成原生库执行。`npm audit` 的生产与完整依赖审计以及 Android 安装运行结果见 [v1.1 验收](client-hub-v1.1-validation.md)。
