# 手机 Client 技术选型（2026-09-23）

## 决定

当前以 **TypeScript + React Native 0.87.1** 开发手机 UI，**先交付 Android**，保留 iOS 工程入口。Android 原生安全通道用 Kotlin；既有语音/模型模块仍含 Java 与 Kotlin。Java 和 Kotlin 同在 Android Runtime 运行，已有 Java 模块不会单独造成语音模型或 PQ 算法的性能瓶颈；新安全代码统一用 Kotlin。共享代码中的状态模型、授权语义和请求契约不得依赖 React Native 组件。

现存 Java 文件负责 Vosk 的 Android 回调、模型目录、下载与 SHA-256 校验；Vosk 和 sherpa-onnx 的主要推理在其本机库中运行，Kotlin 安全通道也调用 Android/加密库。Java 文件不是新功能默认语言。将已实测的桥接层仅为统一语法改写，既不能提高推理速度，也会带来录音、下载和模型切换回归风险；后续触及这些模块时可逐步迁到 Kotlin，并以真机 STT 测试确认行为。性能优化应先测模型大小、推理后端、线程数、内存和录音延迟。

未来鸿蒙版必须是**原生鸿蒙应用**：使用鸿蒙平台的 ArkUI/ArkTS 界面和设备能力；当前阶段不使用 Ark 开发。React Native 的 TSX 页面不能当作鸿蒙原生页面直接编译。到那时需重写页面和平台适配，但可沿用同一产品流程、稳定 ID、字段语义、测试样例与协议契约；纯 TypeScript 逻辑也需逐项检验 ArkTS 兼容性，不能承诺直接复制可运行。

## 选择依据

- React Native 官方支持 Android、iOS，共享页面与交互可先覆盖这两个平台；[官方版本表](https://reactnative.dev/versions) 和 [0.87 发布说明](https://reactnative.dev/blog/2026/08/11/react-native-0.87) 是本版的版本依据。
- 原生鸿蒙的主要应用语言/界面框架是 [ArkTS/ArkUI](https://developer.huawei.com/consumer/en/harmonyos/develop/)。TypeScript 与 ArkTS 的类型和语法思路接近，适合将非 UI 的状态模型和契约逐项迁移；React Native API、第三方模块与 TSX UI 仍须重写/适配。
- Kotlin 适合 Android，也可通过 [Kotlin Multiplatform](https://www.jetbrains.com/kotlin-ecosystem/) 共享 Android/iOS 逻辑；它不解决未来原生鸿蒙 UI 的迁移。Swift/SwiftUI 则主要服务 [Apple 平台](https://developer.apple.com/documentation/technologyoverviews/swiftui)。
- [Android 官方 Kotlin 说明](https://developer.android.com/kotlin/learn)指出 Kotlin 可直接调用 Java 库，二者都编译为 JVM 字节码；本工程的 Java 桥接层可与 Kotlin 渐进共存。性能是否有差异应对具体模型和设备测量，不能从源文件扩展名推断。
- Flutter 与 React Native 都是广泛使用的跨平台方案；不存在一个覆盖所有国家、年份、开发方式的“全球最常用”单一统计。Flutter 的鸿蒙移植运行方式与用户要求的原生鸿蒙交付不同。本选型按明确的 Android 优先、iOS 后续、原生鸿蒙后续路径作出。

## 代码边界

| 层 | 当前实现 | 未来迁移 |
|---|---|---|
| 状态与请求语义 | `src/domain` TypeScript；固定 ID、状态来源和观察时间 | 与鸿蒙端共享契约和样例，必要时移植为 ArkTS |
| 页面与导航 | `App.tsx` React Native | iOS 可复用并适配；鸿蒙用 ArkUI 重新实现 |
| 录音和离线模型 | `src/platform/speech.ts` 接口；Android Java/Kotlin 的 sherpa-onnx 与 Vosk 模块 | iOS、鸿蒙分别实现本机适配；端侧音频不进 Hub |
| Hub 安全通道 | `src/platform/clientHub.ts` 薄适配 + Android Kotlin Client-Control v1 密码学、Keystore 和会话；已对真实开发 Hub 做互操作测试 | iOS、原生鸿蒙分别实现同一版本化 wire 契约，密钥存入各自安全边界 |

当前 Docker/Linux 可编译 Android，不能在这里声称 iOS 已通过 Xcode 构建或鸿蒙原生端已实现。模型性能仍须 Android 真机验收。
