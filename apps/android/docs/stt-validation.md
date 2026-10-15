# 离线语音转文字实测（2026-09-24）

## 模型与环境

- Android App 模型中心支持分别下载、选择、删除四个固定版本：SenseVoice Small INT8（239.5 MB）、Paraformer 中文小模型 INT8（81.9 MB）、[Vosk 中文轻量 0.22](https://alphacephei.com/vosk/models)（43.9 MB ZIP）与 Vosk English Small 0.15（41.2 MB ZIP）。权重不内置 APK；下载逐文件核对大小与 SHA-256 后放入 App 私有目录。模型来源、语言和许可见 [模型选择](model-selection.md)。
- Android 运行时使用 sherpa-onnx 1.13.8 AAR、`vosk-android:0.3.75`、JNA `5.19.1`。安装需联网；本地识别不上传音频。
- Docker x86_64 测试使用 `cicada-client-stt:dev`（Python 3.11 / Vosk 0.3.45）和 `cicada-client-sherpa-stt:dev`（Python 3.11 / sherpa-onnx 1.13.8），统一输入为 16 kHz、单声道、16 bit PCM。Docker 数据根目录 `/gpu1-share/data/docker-root`；权重、公开样本与构建缓存位于 `/gpu1-share/data/cicada-client`，未加入 Git。
- Android 模拟器是 API 35 x86_64 / KVM、320×640。以下将 Docker CPU、模拟器、真机分别列出；**没有 Android 真机录音或性能成绩**。

**v1.1 最终依赖回归：**在 Node 24.21.0/npm 12.1.0 构建、Gson 2.14.0/JNA 5.19.1 的最终 debug APK 上，`SpeechInferenceTest` 四项 Android x86_64 JNI 推理全部通过（`OK (4 tests)`，11.851 s）。原始输出位于 `/gpu1-share/data/cicada-client/hub-v1.1/android-interop/stt-four-models-node24-final.log`；APK SHA-256 与当前 Hub 分层证据见 [v1.1 验收](client-hub-v1.1-validation.md)。以下早期逐项下载/安装结果保留原始测试背景，未把真机或公网标为通过。

## 样本、命令和结果

样本 A 来自 [sherpa-onnx 中文 Paraformer 示例](https://k2-fsa.github.io/sherpa/onnx/pretrained_models/offline-paraformer/paraformer-models.html) 的 [公开 WAV](https://k2-fsa.github.io/sherpa/_static/sherpa-onnx-paraformer-zh-int8-2025-10-07/1.wav)，SHA-256 `4affd509d1ebb95052b50079f4aea3734e05eefc57a018a26618043744e572c9`。示例给出的参考句是「来，哥哥再给你唱首歌。好儿，哎呦，把伴奏给我放起来，放就放嘛，还要躲人家钩子。」。

样本 B 来自 [sherpa-onnx Paraformer 公开测试音频](https://huggingface.co/csukuangfj/sherpa-onnx-paraformer-zh-2023-03-28/tree/main/test_wavs) 的 `0.wav`，SHA-256 `1a6bf94091d9c35e11aea5d494d05e3287b8f5c767f6de3bfd796d91b637500c`。此处没有经人工校对的参考文字。

样本 C 是 [Vosk 官方示例 `test.wav`](https://github.com/alphacep/vosk-api/blob/master/python/example/test.wav)，265,914 bytes、16 kHz 单声道 PCM16，SHA-256 `dcfea5712c43a43ba7ae8083afb39d36993e5a69c46e88b68aaa72b65cb615bb`。Android Vosk 英文 JNI 测试只断言转写包含 `one zero zero zero one`，不把宿主 Docker 的整句输出写成 Android 的实际整句结果。

| 模型 / 样本 | 命令 | 退出码 | 音频 / 加载 / 解码 | 峰值 RSS | 转写 |
|---|---|---:|---|---:|---|
| SenseVoice / A | `./scripts/test-sherpa-docker.sh` | 0 | 7.808 / 1.559 / 0.600 s；RTF 0.077 | 372,892 KiB | `来哥哥再给你唱首歌。好，哎呦把伴奏给我放起来，放着放嘛，还要躲人家钩子。` |
| SenseVoice / B | 同上 | 0 | 5.615 / 1.616 / 0.444 s；RTF 0.079 | 482,608 KiB | `对我做了介绍啊，那么我想说的是呢，大家如果对我的研究感兴趣呢。` |
| Paraformer / A | 同上 | 0 | 7.808 / 1.636 / 0.216 s；RTF 0.028 | 196,364 KiB | `来哥哥再给你唱首歌好哎呦把伴奏给我放起来放就放嘛还要躲人家钩子` |
| Paraformer / B | 同上 | 0 | 5.615 / 1.638 / 0.142 s；RTF 0.025 | 213,048 KiB | `对我做了介绍啊那么我想说的是呢大家如果对我的研究感兴趣呢嗯` |
| Vosk 中文 / A | `./scripts/test-stt-docker.sh` | 0 | 7.808 / 0.384 / 4.691 s；RTF 0.601 | 232,488 KiB | `哎 搞 个 再 给 你 藏 过 着 而 有 八百 字 高 房价 烦 都 烦 吗 还有 都 应该 听 着` |
| Vosk 中文 / B | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/workspace:ro" -v /gpu1-share/data/cicada-client:/data:ro cicada-client-stt:dev python scripts/test_stt.py --model /data/models/vosk-model-small-cn-0.22 --wav /data/test-data/zh-0.wav` | 0 | 5.615 / 0.408 / 4.400 s；RTF 0.784 | 220,604 KiB | `对 我 做 了 介绍 按 吗 我 想说 的 是 呢 大家 如果 对 我 的 研究 感兴趣 呢` |

公开样本 A 上 SenseVoice 和 Paraformer 都能还原主要句子，Vosk 中文错词明显；SenseVoice 在这两条样本中还生成了标点。B 没有经人工校对的参考文本。两段音频不足以推断总体准确率、方言质量或手机麦克风效果。因此 UI 将转写视为**可编辑草稿**；用户确认后，只有具备已验证加密 Hub 会话和 `intent.submit` 授权时才能发送文字。下表语音测试仍不构成真机麦克风验收。

下载模型与样本的命令（仅需首次运行；全部写入 `/gpu1-share/data/cicada-client`）：

```bash
mkdir -p /gpu1-share/data/cicada-client/{models,test-data}
curl -fL https://alphacephei.com/vosk/models/vosk-model-small-cn-0.22.zip \
  -o /gpu1-share/data/cicada-client/models/vosk-model-small-cn-0.22.zip
curl -fL https://k2-fsa.github.io/sherpa/_static/sherpa-onnx-paraformer-zh-int8-2025-10-07/1.wav \
  -o /gpu1-share/data/cicada-client/test-data/zh-groundtruth.wav
./scripts/test-stt-docker.sh
```

两个测试脚本在推理前校验下载文件的 SHA-256。模型转写结果可能随运行硬件略有变化，但转写不应为空。

## Android 验证

| 项目 | 命令 | 退出码 / 结果 |
|---|---|---|
| 编译 APK | `./scripts/docker-build.sh`；`./scripts/docker-build-android-test.sh` | 0；生成调试 APK 和同签名的测试 APK |
| 模拟器界面 | `CICADA_EMULATOR_PROXY=http://127.0.0.1:7890 ./scripts/docker-emulator-check.sh` | 0；首页概览、节点、工作、管理、设置、文字/语音面板均打开，截图存于 `/gpu1-share/data/cicada-client/build-output/` |
| 模拟器实际推理 | 先将已校验的公开样本 B 和两套模型文件复制到 App 私有目录；`adb shell am instrument -w -e class ai.cicada.client.SpeechInferenceTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` | `OK (2 tests)`；SenseVoice 和 Paraformer 的 Android JNI 推理均识别出「研究」 |
| 模拟器 Vosk 中文推理 | 校验 Vosk 中文 ZIP 的 SHA-256 后，将模型和公开样本 B 放入 App 私有目录；`adb shell am instrument -w -e class ai.cicada.client.SpeechInferenceTest#voskChineseRecognizesPublicChineseSample ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` | 构建退出码 0；instrument 退出码 0 且 `OK (1 test)`，5.372 s；Android Vosk JNI 转写含「研究」 |
| 模拟器 Vosk 英文推理 | `SpeechInferenceTest#voskEnglishRecognizesPublicEnglishSample`，使用已校验的英文模型与公开 WAV | 前期 AndroidTest APK 上 instrument 退出码 0、`OK (1 test)`，2.595 s；转写包含测试短语 `one zero zero zero one` |
| 模拟器下载并安装 | 模拟器与 Docker 用 host 网络，Android 系统代理 `10.0.2.2:7890`；`adb shell am instrument -w -e class ai.cicada.client.ModelDownloadTest ai.cicada.client.test/androidx.test.runner.AndroidJUnitRunner` | 分项运行均 `OK (1 test)`；Paraformer 81.9 MB 和 Vosk 中文 43.9 MB 经 HTTPS 下载、大小与 SHA-256 校验，Vosk 完成 ZIP 解压，两者都能设为当前模型 |
| 模拟器 Vosk 英文与 SenseVoice 安装 | `SttAcceptanceTest#englishVoskModelDownloadsAndCanBeSelected`、`#senseVoiceDownloadsVerifiesAndCanBeSelected` | 前期 AndroidTest APK 上分别 `OK (1 test)`、退出码 0，19.172 s / 47.837 s；真实下载 41.2 MB Vosk ZIP 和 SenseVoice 两资产约 239.5 MB，校验大小/SHA-256，解压或保存后可选择。SenseVoice 已下载的模型上重跑中文 JNI 推理 `OK (1 test)`、退出码 0，2.538 s |
| 下载中断、删除与录音权限 | `SttAcceptanceTest#interruptedEnglishInstallLeavesNoPartialFiles`、`#removingSelectedEnglishModelClearsSelection`、`#startListeningRejectsMissingMicrophonePermission`、`#grantedVoskRecordingCanBeStoppedWithoutProducingText` | 各项均 `OK (1 test)`、退出码 0；下载进度出现后切断模拟器网络，失败后无已安装目录、staging 或缓存残片；删除所选模型清除选择；拒权返回 `MIC_PERMISSION`；授权后能进入本机聆听并停止，静默模拟器无文本 |
| 模型界面操作 | 模拟器 UI 手动点击 Paraformer 的删除确认、下载并安装、选择按钮，查看 UI 层级与私有目录 | 删除后显示「未安装」，重新下载后显示「已安装」，切换后显示「当前使用」；按钮实际调用 Android 安装器和选择状态 |
| 真机麦克风、低内存与性能 | 需要 Android 真机 | 未执行 |
| Hub 集成 / 端到端加密 | 见 [Android ↔ Hub 互操作记录](client-hub-interop-results.md) | 开发 Docker Hub 与 Android 模拟器通过；不等于普通 peer 的盲 Hub E2EE 或生产公网验收 |

本次 Vosk Android 测试先用 `sha256sum /gpu1-share/data/cicada-client/models/vosk-model-small-cn-0.22.zip` 核对目录中固定的 `3af8b0e7e0f835ae9d414ce5df580237a3cfb08d586c9fbbb0f7ff29ad5b14ba`，再经 `docker cp`、`adb push`、`adb shell run-as ai.cicada.client unzip` 将权重放进 `files/models/vosk-model-small-cn-0.22`，并将公开样本 B 复制为 `files/public-zh-0.wav`。`./scripts/docker-build-android-test.sh` 退出码 0；安装同签名测试 APK 后单独运行 `SpeechInferenceTest#voskChineseRecognizesPublicChineseSample`，输出 `OK (1 test)`。测试直接走 APK 内 Vosk Android JNI 解码器，使用与 UI 识别器相同的模型目录；测试音频来自文件，未使用麦克风。

注意：`adb shell am instrument` 即使报告 `FAILURES` 也可能返回进程退出码 0，必须检查输出中的 `OK (n tests)`。首次仅设置模拟器 `-http-proxy` 时出现 `connection closed`；同时把 Android 系统代理设为 `10.0.2.2:7890` 后下载通过。7890 是本开发机的代理端口，发布 APK 并不依赖该代理。Android 推理测试使用预置的公开模型文件验证 JNI 路径；下载测试单独验证 App 安装器，两项不能等同于真机录音验收。

SenseVoice 模型目录原先的 `tokens.txt` SHA-256 常量被截断成 53 位，因此新下载必然校验失败。本轮对六个公开模型资产的本地 SHA-256 与目录值逐一核对，修正了 SenseVoice 常量；`SttAcceptanceTest#catalogAssetsHaveCompleteHttpsPins` 检查 HTTPS、正数大小和完整 64 位摘要。SenseVoice 与 Vosk 英文现在均已通过 Android 模拟器实际下载、选择和 JNI 推理。下载中断测试首次写法因 App 没有 `ACCESS_NETWORK_STATE` 权限而在测试读取网络状态时失败；移除该测试依赖后，使用实际网络中断和安装器回调复测通过。所有语音样本来自文件或模拟器静默麦克风；**四个模型仍没有 Android 真机麦克风质量、内存、耗电或热表现验收**。

最终 APK 的模拟器 UI 检查还验证：未点击语音入口时不进入录音；点击后才请求 `RECORD_AUDIO`，拒绝授权仍能在输入框键入文字。授权后可手动开始/停止本机聆听，草稿不会自动发往 Hub；未登录时发送按钮保持“远程发送未启用”。测试容器没有麦克风设备或音频 socket，不能把这一检查当作真实麦克风识别成绩。公开 WAV 已从模拟器 App 私有目录清除，模型保留供后续手测；下载残片和 staging 均已清理。
