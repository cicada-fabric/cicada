# 端侧模型选择与目录规则（2026-09-23）

## 产品结论

不存在适用于所有手机、语言、口音和任务的「社区公认第一」。当前中文语音入口优先实测 **SenseVoice Small INT8** 和 **Paraformer 中文小模型 INT8**；Vosk 中文轻量版保留作低下载量选项，但已有公开中文样本上出现明显错词，不能默认认定其中文质量足够。若允许约 GB 级下载，**Qwen3-ASR-0.6B** 是下一阶段语音识别候选；它尚未通过本 App 的 Android 推理适配和手机资源验收。未来文字/图像端侧能力另评估 **Qwen3.5-2B**，不会把它误称为语音识别模型。

模型中心按 `模型 ID + 固定版本 + 推理引擎 + 能力` 管理。一个用户可安装多个模型，切换当前语音模型；权重始终由用户选择下载，不打进 APK。目录中每个**可下载**模型必须同时具备 Android 可调用的解码器、具体文件清单、固定来源版本、大小和 SHA-256；从 Hugging Face 找到权重不意味着 App 能运行它。今后模型可达 GB 级，下载还需进一步加进度、续传、空间预检和低内存设备适配，不能仅放大文件上限。

## 当前目录

| 模型 | 下载量 | 语言与能力 | 当前判断 |
|---|---:|---|---|
| [SenseVoice Small INT8](https://k2-fsa.github.io/sherpa/onnx/sense-voice/index.html) | 239 MB 模型 + 0.3 MB tokens | 普通话、粤语、英语、日语、韩语；模型还支持语言识别、情绪和声音事件识别 | 用 sherpa-onnx 在 Android 实现离线转写；其他能力暂不开放。权重采用 [FunASR 模型协议](https://github.com/modelscope/FunASR/blob/main/MODEL_LICENSE)，不可写成 Apache 2.0。 |
| [Paraformer 中文小模型 INT8](https://k2-fsa.github.io/sherpa/onnx/pretrained_models/offline-paraformer/paraformer-models.html#csukuangfj-sherpa-onnx-paraformer-zh-small-2024-03-09-chinese-english) | 81.8 MB 模型 + 75 KB tokens | 中文、英语；上游示例还包含部分方言 | 用 sherpa-onnx 在 Android 实现离线转写。模型由第三方转换，许可须按[具体来源](https://huggingface.co/csukuangfj/sherpa-onnx-paraformer-zh-small-2024-03-09)核对，不推断为运行时软件的许可证。 |
| [Vosk 中文轻量 0.22](https://alphacephei.com/vosk/models) | 43.9 MB ZIP | 中文转写 | 低下载量可选；官方在列出的中文测试集上报告 17.15%–38.29% 错误率，本项目公开音频 A 的结果明显不可靠。 |
| [Vosk English Small 0.15](https://alphacephei.com/vosk/models) | 41.2 MB ZIP | 英语转写 | 供英语场景选择；中文场景不应选用。 |

前三款中文模型均需同一批公开中文音频和 Android 端侧运行比较；模型卡的基准数据来自各自不同的测试条件，不能横向当成我们的手机成绩。[sherpa-onnx 1.13.8 Android AAR](https://github.com/k2-fsa/sherpa-onnx/releases/tag/v1.13.8) 按固定 SHA-256 在构建时取得，权重在 App 中逐文件校验后存到私有目录。Android AAR 提供 x86_64/arm64 等 ABI；这不等于真机耗时已测得。

## 下一阶段候选

| 模型 | 适合的用途 | 接入门槛 |
|---|---|---|
| [Qwen3-ASR-0.6B](https://huggingface.co/Qwen/Qwen3-ASR-0.6B) | 中文/方言优先的较大 ASR；上游称覆盖 30 种语言及 22 种中文方言 | 官方量化 GGUF 示例为约 [805 MB 权重 + 214 MB 音频投影](https://huggingface.co/ggml-org/Qwen3-ASR-0.6B-GGUF/tree/main)；要集成 Android 音频推理运行时、测 RAM/延迟/准确率和电量后才开放。 |
| [Fun-ASR-Nano-2512](https://huggingface.co/FunAudioLLM/Fun-ASR-Nano-2512) | 中国团队的较大语音识别候选 | 原始仓库约 2 GB；需确认适配的量化格式、移动运行时与端侧测量。 |
| [Qwen3.5-2B](https://huggingface.co/Qwen/Qwen3.5-2B) | 将来的本地文字与图像理解 | 它是图文模型，不能代替 ASR；需要独立的推理适配、权限边界和设备控制设计。 |
| [MiniCPM-o 4.5](https://huggingface.co/openbmb/MiniCPM-o-4_5) | 将来的语音、视觉和对话一体化高配设备试验 | 上游标为约 9B 参数、原始仓库约 20 GB；当前不是普通 Android 手机的默认选择，需压缩版本和设备实测。 |

未来端侧模型可以辅助输入和设备交互，但它不能自行获得 CICADA 的 Hub 管理权限、批准其他用户连接或向 Worker 注入原生 Session。语音转成文字后仍是可编辑草稿；用户确认后，只有已登记且获得加密 `session.capabilities` 授权的设备才可通过 Client-Control v1 向 Hub 提交文字。原始音频仍不上传。
