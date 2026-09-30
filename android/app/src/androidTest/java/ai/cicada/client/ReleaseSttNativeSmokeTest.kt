package ai.cicada.client

import android.content.pm.ApplicationInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.k2fsa.sherpa.onnx.OfflineModelConfig
import com.k2fsa.sherpa.onnx.OfflineParaformerModelConfig
import com.k2fsa.sherpa.onnx.OfflineRecognizer
import com.k2fsa.sherpa.onnx.OfflineRecognizerConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest
import java.util.Locale

/** Release packaging smoke using public files staged outside the APK in app-specific storage. */
@RunWith(AndroidJUnit4::class)
class ReleaseSttNativeSmokeTest {
    @Test
    fun paraformerRecognizesPinnedPublicSampleAndVoskNativeBindingIsAvailable() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(
            "Smoke must run against a nondebuggable Release target",
            0,
            context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE,
        )
        val fixtureRoot = checkNotNull(context.getExternalFilesDir("packaging-fixture")) {
            "App-specific external fixture directory is unavailable"
        }.canonicalFile

        val model = fixtureFile(fixtureRoot, "stt_model_path")
        val tokens = fixtureFile(fixtureRoot, "stt_tokens_path")
        val wavFile = fixtureFile(fixtureRoot, "stt_sample_path")

        val spec = checkNotNull(ModelCatalog.get("sherpa-paraformer-zh-small"))
        assertEquals("paraformer", spec.engine)
        val modelAsset = spec.assets.single { it.name == "model.int8.onnx" }
        val tokensAsset = spec.assets.single { it.name == "tokens.txt" }
        assertEquals(PARAFORMER_SHA256, modelAsset.sha256)
        assertEquals(PARAFORMER_BYTES, modelAsset.bytes)
        assertEquals(PARAFORMER_TOKENS_SHA256, tokensAsset.sha256)
        assertEquals(PARAFORMER_TOKENS_BYTES, tokensAsset.bytes)
        assertPinnedFile(model, PARAFORMER_SHA256, PARAFORMER_BYTES)
        assertPinnedFile(tokens, PARAFORMER_TOKENS_SHA256, PARAFORMER_TOKENS_BYTES)

        // Resolve through the target APK classloader and invoke Vosk's JNA-registered native API.
        invokeVoskNativeLogLevel(context.classLoader)

        val audio = readPcm16Wav(wavFile)
        val config = OfflineModelConfig(
            paraformer = OfflineParaformerModelConfig(model = model.absolutePath),
            tokens = tokens.absolutePath,
            numThreads = 2,
        )
        val recognizer = OfflineRecognizer(config = OfflineRecognizerConfig(modelConfig = config))
        val transcript = try {
            val stream = recognizer.createStream()
            try {
                stream.acceptWaveform(audio, SAMPLE_RATE)
                recognizer.decode(stream)
                recognizer.getResult(stream).text.trim()
            } finally {
                stream.release()
            }
        } finally {
            recognizer.release()
        }

        assertTrue("Pinned public audio must produce nonempty transcription", transcript.isNotEmpty())
        assertTrue("Pinned public audio must include the documented recognition token",
            transcript.contains("研究"))
    }

    private fun fixtureFile(root: File, argumentName: String): File {
        val relative = InstrumentationRegistry.getArguments().getString(argumentName)
            ?: throw AssertionError("Missing instrumentation argument: $argumentName")
        require(relative.isNotBlank() && !File(relative).isAbsolute) {
            "Fixture path must be relative to app-specific external storage"
        }
        val file = File(root, relative).canonicalFile
        require(file.path.startsWith(root.path + File.separator)) {
            "Fixture path must stay beneath app-specific external storage"
        }
        return file
    }

    private fun assertPinnedFile(file: File, expectedSha256: String, expectedBytes: Long) {
        assertTrue("Pinned public fixture file is missing", file.isFile)
        assertEquals("Pinned public fixture size", expectedBytes, file.length())
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        assertEquals("Pinned public fixture SHA-256", expectedSha256, hex(digest.digest()))
    }

    private fun invokeVoskNativeLogLevel(classLoader: ClassLoader) {
        val logLevelClass = Class.forName("org.vosk.LogLevel", true, classLoader)
        val warnings = checkNotNull(logLevelClass.enumConstants?.singleOrNull {
            (it as? Enum<*>)?.name == "WARNINGS"
        }) { "Vosk WARNINGS log level is unavailable in the target APK" }
        val libVoskClass = Class.forName("org.vosk.LibVosk", true, classLoader)
        libVoskClass.getMethod("setLogLevel", logLevelClass).invoke(null, warnings)
    }

    private fun readPcm16Wav(file: File): FloatArray {
        val wav = file.readBytes()
        require(wav.size == PUBLIC_SAMPLE_BYTES.toInt()) { "Pinned public WAV size is invalid" }
        require(hex(MessageDigest.getInstance("SHA-256").digest(wav)) == PUBLIC_SAMPLE_SHA256) {
            "Pinned public WAV SHA-256 is invalid"
        }
        require(wav.size in 44..MAX_WAV_BYTES) { "Public WAV size is outside the smoke-test bound" }
        require(ascii(wav, 0, 4) == "RIFF" && ascii(wav, 8, 4) == "WAVE") {
            "Public fixture is not a RIFF/WAVE file"
        }
        require(u32(wav, 4) + 8L == wav.size.toLong()) { "Public WAV RIFF length is invalid" }

        var format: Int? = null
        var channels: Int? = null
        var sampleRate: Long? = null
        var bitsPerSample: Int? = null
        var pcm: ByteArray? = null
        var offset = 12
        while (offset <= wav.size - 8) {
            val chunkSize = u32(wav, offset + 4)
            val dataStart = offset + 8
            require(chunkSize <= (wav.size - dataStart).toLong()) { "Public WAV chunk exceeds file bounds" }
            when (ascii(wav, offset, 4)) {
                "fmt " -> {
                    require(chunkSize >= 16) { "Public WAV format chunk is truncated" }
                    format = u16(wav, dataStart)
                    channels = u16(wav, dataStart + 2)
                    sampleRate = u32(wav, dataStart + 4)
                    bitsPerSample = u16(wav, dataStart + 14)
                }
                "data" -> pcm = wav.copyOfRange(dataStart, dataStart + chunkSize.toInt())
            }
            val next = dataStart.toLong() + chunkSize + (chunkSize and 1L)
            require(next <= wav.size.toLong()) { "Public WAV chunk padding exceeds file bounds" }
            offset = next.toInt()
        }

        require(format == 1 && channels == 1 && sampleRate == SAMPLE_RATE.toLong() && bitsPerSample == 16) {
            "Public WAV must be 16 kHz mono PCM16"
        }
        val samples = checkNotNull(pcm) { "Public WAV has no data chunk" }
        require(samples.isNotEmpty() && samples.size % 2 == 0) { "Public WAV PCM data is invalid" }
        return FloatArray(samples.size / 2) { index ->
            val value = (samples[index * 2].toInt() and 0xff) or (samples[index * 2 + 1].toInt() shl 8)
            value.toShort() / 32768.0f
        }
    }

    private fun ascii(bytes: ByteArray, offset: Int, count: Int): String =
        String(bytes, offset, count, Charsets.US_ASCII)

    private fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun u32(bytes: ByteArray, offset: Int): Long =
        u16(bytes, offset).toLong() or (u16(bytes, offset + 2).toLong() shl 16)

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(Locale.ROOT, it) }

    private companion object {
        const val SAMPLE_RATE = 16_000
        const val MAX_WAV_BYTES = 300_000
        const val PARAFORMER_SHA256 = "3ef6c19369b912f7caf3cef8e545c5ccd1a33d9d7ec792a46668dc41c4b229ec"
        const val PARAFORMER_BYTES = 81_828_675L
        const val PARAFORMER_TOKENS_SHA256 = "4b2d964e18b9cf139b473003b6698fb2ed9a2a5ec55b93daa677b28f578897aa"
        const val PARAFORMER_TOKENS_BYTES = 75_352L
        const val PUBLIC_SAMPLE_SHA256 = "1a6bf94091d9c35e11aea5d494d05e3287b8f5c767f6de3bfd796d91b637500c"
        const val PUBLIC_SAMPLE_BYTES = 179_712L
    }
}
