package ai.cicada.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.k2fsa.sherpa.onnx.OfflineModelConfig
import com.k2fsa.sherpa.onnx.OfflineParaformerModelConfig
import com.k2fsa.sherpa.onnx.OfflineRecognizer
import com.k2fsa.sherpa.onnx.OfflineRecognizerConfig
import com.k2fsa.sherpa.onnx.OfflineSenseVoiceModelConfig
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.vosk.Model
import org.vosk.Recognizer
import java.io.File

/** Runs real Sherpa ONNX and Vosk inference on public 16 kHz PCM samples. */
@RunWith(AndroidJUnit4::class)
class SpeechInferenceTest {
    @Test fun senseVoiceRecognizesPublicChineseSample() {
        val result = decode("sherpa-sensevoice-small-int8", true)
        assertTrue("SenseVoice output should contain a known public-sample word: $result",
            result.contains("研究"))
    }

    @Test fun paraformerRecognizesPublicChineseSample() {
        val result = decode("sherpa-paraformer-zh-small", false)
        assertTrue("Paraformer output should contain a known public-sample word: $result",
            result.contains("研究"))
    }

    @Test fun voskChineseRecognizesPublicChineseSample() {
        val text = voskRecognizesSample("vosk-model-small-cn-0.22", "public-zh-0.wav")
        assertTrue("Vosk output should contain a known public-sample word: $text",
            text.contains("研究"))
    }

    @Test fun voskEnglishRecognizesPublicEnglishSample() {
        val text = voskRecognizesSample("vosk-model-small-en-us-0.15", "public-en-test.wav")
        assertTrue("Vosk output should contain a known public-sample phrase: $text",
            text.contains("one zero zero zero one"))
    }

    private fun voskRecognizesSample(modelId: String, sampleName: String): String {
        val files = InstrumentationRegistry.getInstrumentation().targetContext.filesDir
        val modelDir = File(files, "models/$modelId")
        assertTrue(File(modelDir, "am/final.mdl").isFile)
        val sample = publicSample(sampleName)
        val text = StringBuilder()
        Model(modelDir.path).use { model ->
            Recognizer(model, sample.sampleRate.toFloat()).use { recognizer ->
                val buffer = ByteArray(8192)
                var offset = 0
                while (offset < sample.pcm16.size) {
                    val count = minOf(buffer.size, sample.pcm16.size - offset)
                    sample.pcm16.copyInto(buffer, 0, offset, offset + count)
                    if (recognizer.acceptWaveForm(buffer, count)) {
                        appendVoskText(text, recognizer.result)
                    }
                    offset += count
                }
                appendVoskText(text, recognizer.finalResult)
            }
        }
        return text.toString().trim()
    }

    private fun appendVoskText(output: StringBuilder, result: String) {
        val text = JSONObject(result).optString("text").trim()
        if (text.isNotEmpty()) {
            if (output.isNotEmpty()) output.append(' ')
            output.append(text)
        }
    }

    private fun decode(id: String, senseVoice: Boolean): String {
        val files = InstrumentationRegistry.getInstrumentation().targetContext.filesDir
        val modelDir = File(files, "models/$id")
        val model = File(modelDir, "model.int8.onnx")
        val tokens = File(modelDir, "tokens.txt")
        assertTrue(model.isFile && tokens.isFile)
        val config = OfflineModelConfig(
            senseVoice = if (senseVoice) OfflineSenseVoiceModelConfig(model = model.path)
                else OfflineSenseVoiceModelConfig(),
            paraformer = if (senseVoice) OfflineParaformerModelConfig()
                else OfflineParaformerModelConfig(model = model.path),
            tokens = tokens.path,
            numThreads = 2,
        )
        val recognizer = OfflineRecognizer(config = OfflineRecognizerConfig(modelConfig = config))
        val stream = recognizer.createStream()
        try {
            val sample = publicSample("public-zh-0.wav")
            stream.acceptWaveform(sample.floatSamples, sample.sampleRate)
            recognizer.decode(stream)
            return recognizer.getResult(stream).text.trim()
        } finally {
            stream.release()
            recognizer.release()
        }
    }

    private fun publicSample(name: String): AudioSample = synchronized(sampleCache) {
        sampleCache.getOrPut(name) {
            val files = InstrumentationRegistry.getInstrumentation().targetContext.filesDir
            val (pcm16, sampleRate) = readPcm16(File(files, name))
            AudioSample(pcm16, sampleRate)
        }
    }

    private fun readPcm16(file: File): Pair<ByteArray, Int> {
        val wav = file.readBytes()
        require(String(wav, 0, 4) == "RIFF" && String(wav, 8, 4) == "WAVE")
        fun u16(offset: Int) = (wav[offset].toInt() and 0xff) or
            ((wav[offset + 1].toInt() and 0xff) shl 8)
        fun u32(offset: Int) = u16(offset) or (u16(offset + 2) shl 16)
        require(u16(22) == 1 && u16(34) == 16)
        val sampleRate = u32(24)
        var offset = 12
        while (offset + 8 < wav.size && String(wav, offset, 4) != "data") {
            offset += 8 + u32(offset + 4)
        }
        require(offset + 8 < wav.size)
        val count = u32(offset + 4) / 2
        val start = offset + 8
        require(start + count * 2 <= wav.size)
        return wav.copyOfRange(start, start + count * 2) to sampleRate
    }

    private data class AudioSample(val pcm16: ByteArray, val sampleRate: Int) {
        val floatSamples: FloatArray by lazy(LazyThreadSafetyMode.NONE) {
            FloatArray(pcm16.size / 2) { index ->
                val value = (pcm16[index * 2].toInt() and 0xff) or
                    (pcm16[index * 2 + 1].toInt() shl 8)
                value.toShort() / 32768f
            }
        }
    }

    private companion object {
        val sampleCache = mutableMapOf<String, AudioSample>()
    }
}
