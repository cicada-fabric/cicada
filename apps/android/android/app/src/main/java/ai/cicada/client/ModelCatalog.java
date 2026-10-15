package ai.cicada.client;

import java.util.Arrays;
import java.util.List;

/** Reviewed, pinned model artifacts. Adding a card here requires a working decoder. */
final class ModelCatalog {
    static final class Asset {
        final String name;
        final String url;
        final String sha256;
        final long bytes;

        Asset(String name, String url, String sha256, long bytes) {
            this.name = name;
            this.url = url;
            this.sha256 = sha256;
            this.bytes = bytes;
        }
    }

    static final class ModelSpec {
        final String id;
        final String name;
        final String engine;
        final String languages;
        final String capabilities;
        final String source;
        final String license;
        final String licenseUrl;
        final List<Asset> assets;

        ModelSpec(String id, String name, String engine, String languages,
                  String capabilities, String source, String license, String licenseUrl,
                  Asset... assets) {
            this.id = id;
            this.name = name;
            this.engine = engine;
            this.languages = languages;
            this.capabilities = capabilities;
            this.source = source;
            this.license = license;
            this.licenseUrl = licenseUrl;
            this.assets = Arrays.asList(assets);
        }

        long downloadBytes() {
            long sum = 0;
            for (Asset asset : assets) sum += asset.bytes;
            return sum;
        }
    }

    private static final String PARA_BASE =
            "https://huggingface.co/csukuangfj/sherpa-onnx-paraformer-zh-small-2024-03-09/resolve/63ddc3cd0f2810b68289a7b3876e62ef5d53d6df/";
    private static final String SENSE_BASE =
            "https://huggingface.co/csukuangfj/sherpa-onnx-sense-voice-zh-en-ja-ko-yue-2024-07-17/resolve/2365baeacb507f821a0c8120fcee3d484dba7a07/";

    static final List<ModelSpec> ALL = Arrays.asList(
            new ModelSpec("sherpa-sensevoice-small-int8", "SenseVoice Small INT8",
                    "sensevoice", "中文 · 粤语 · English · 日本語 · 한국어",
                    "语音转文字 · 语言识别；其他音频能力待验证",
                    "FunAudioLLM / sherpa-onnx", "FunASR 模型协议",
                    "https://github.com/modelscope/FunASR/blob/main/MODEL_LICENSE",
                    new Asset("model.int8.onnx", SENSE_BASE + "model.int8.onnx",
                            "c71f0ce00bec95b07744e116345e33d8cbbe08cef896382cf907bf4b51a2cd51", 239233841),
                    new Asset("tokens.txt", SENSE_BASE + "tokens.txt",
                            "f449eb28dc567533d7fa59be34e2abca8784f771850c78a47fb731a31429a1dc", 315894)),
            new ModelSpec("sherpa-paraformer-zh-small", "Paraformer 中文小模型 INT8",
                    "paraformer", "中文 · English", "语音转文字",
                    "FunASR 派生 / sherpa-onnx", "原模型条款请见来源",
                    "https://huggingface.co/csukuangfj/sherpa-onnx-paraformer-zh-small-2024-03-09",
                    new Asset("model.int8.onnx", PARA_BASE + "model.int8.onnx",
                            "3ef6c19369b912f7caf3cef8e545c5ccd1a33d9d7ec792a46668dc41c4b229ec", 81828675),
                    new Asset("tokens.txt", PARA_BASE + "tokens.txt",
                            "4b2d964e18b9cf139b473003b6698fb2ed9a2a5ec55b93daa677b28f578897aa", 75352)),
            new ModelSpec("vosk-model-small-cn-0.22", "Vosk 中文轻量模型 0.22",
                    "vosk", "中文", "语音转文字",
                    "Alpha Cephei / Vosk", "Apache 2.0",
                    "https://alphacephei.com/vosk/models",
                    new Asset("model.zip", "https://alphacephei.com/vosk/models/vosk-model-small-cn-0.22.zip",
                            "3af8b0e7e0f835ae9d414ce5df580237a3cfb08d586c9fbbb0f7ff29ad5b14ba", 43898754)),
            new ModelSpec("vosk-model-small-en-us-0.15", "Vosk English Small 0.15",
                    "vosk", "English", "语音转文字",
                    "Alpha Cephei / Vosk", "Apache 2.0",
                    "https://alphacephei.com/vosk/models",
                    new Asset("model.zip", "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip",
                            "30f26242c4eb449f948e42cb302dd7a686cb29a3423a8367f99ff41780942498", 41205931))
    );

    static ModelSpec get(String id) {
        for (ModelSpec spec : ALL) if (spec.id.equals(id)) return spec;
        return null;
    }
}
