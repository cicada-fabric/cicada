package ai.cicada.client

import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Handler
import android.os.Looper
import com.k2fsa.sherpa.onnx.OfflineModelConfig
import com.k2fsa.sherpa.onnx.OfflineParaformerModelConfig
import com.k2fsa.sherpa.onnx.OfflineRecognizer
import com.k2fsa.sherpa.onnx.OfflineRecognizerConfig
import com.k2fsa.sherpa.onnx.OfflineSenseVoiceModelConfig
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.concurrent.thread

/** Offline ONNX decoding after a short recording; audio is never written to disk. */
internal class SherpaOfflineStt(private val spec: ModelCatalog.ModelSpec) : SttSession {
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var stopRequested = false
    @Volatile private var closed = false
    @Volatile private var recorder: AudioRecord? = null

    override fun start(modelDir: File, listener: SttSession.Listener) {
        thread(name = "cicada-sherpa-stt") {
            var recognizer: OfflineRecognizer? = null
            var audioRecord: AudioRecord? = null
            try {
                status(listener, "正在加载 ${spec.name}…")
                val model = File(modelDir, "model.int8.onnx").absolutePath
                val tokens = File(modelDir, "tokens.txt").absolutePath
                val modelConfig = if (spec.engine == "sensevoice") {
                    OfflineModelConfig(
                        senseVoice = OfflineSenseVoiceModelConfig(model = model),
                        tokens = tokens,
                        numThreads = 2,
                    )
                } else {
                    OfflineModelConfig(
                        paraformer = OfflineParaformerModelConfig(model = model),
                        tokens = tokens,
                        numThreads = 2,
                    )
                }
                recognizer = OfflineRecognizer(config = OfflineRecognizerConfig(modelConfig = modelConfig))
                if (stopRequested || closed) return@thread
                val minBuffer = AudioRecord.getMinBufferSize(
                    SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
                require(minBuffer > 0) { "麦克风格式不可用" }
                audioRecord = AudioRecord(
                    MediaRecorder.AudioSource.MIC, SAMPLE_RATE,
                    AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
                    maxOf(minBuffer * 2, 8192),
                )
                require(audioRecord.state == AudioRecord.STATE_INITIALIZED) { "麦克风无法初始化" }
                recorder = audioRecord
                audioRecord.startRecording()
                status(listener, "正在本机录音 · 点按停止后识别（最多 30 秒）")
                val audio = ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                while (!stopRequested && !closed && audio.size() < MAX_AUDIO_BYTES) {
                    val count = audioRecord.read(chunk, 0, chunk.size)
                    if (count < 0) throw IllegalStateException("录音中断")
                    if (count > 0) audio.write(chunk, 0, count)
                }
                if (audioRecord.recordingState == AudioRecord.RECORDSTATE_RECORDING) audioRecord.stop()
                audioRecord.release()
                audioRecord = null
                recorder = null
                if (!closed && audio.size() > 0) {
                    status(listener, "正在本机转写…")
                    val pcm = audio.toByteArray()
                    val samples = FloatArray(pcm.size / 2) { index ->
                        val low = pcm[index * 2].toInt() and 0xff
                        val high = pcm[index * 2 + 1].toInt()
                        ((high shl 8) or low).toShort() / 32768.0f
                    }
                    val stream = recognizer.createStream()
                    try {
                        stream.acceptWaveform(samples, SAMPLE_RATE)
                        recognizer.decode(stream)
                        val text = recognizer.getResult(stream).text.trim()
                        if (!closed && text.isNotEmpty()) main.post {
                            if (!closed) listener.onText(text, false)
                        }
                    } finally {
                        stream.release()
                    }
                }
            } catch (error: Exception) {
                status(listener, "本地转写失败：${error.message ?: "未知错误"}")
            } finally {
                try {
                    if (audioRecord?.recordingState == AudioRecord.RECORDSTATE_RECORDING) audioRecord.stop()
                    audioRecord?.release()
                } catch (_: Exception) { }
                recorder = null
                recognizer?.release()
                main.post { listener.onStopped() }
            }
        }
    }

    override fun stop() {
        stopRequested = true
        // AudioRecord.read uses small bounded chunks and exits after the next chunk.
    }

    override fun close() {
        closed = true
        stopRequested = true
    }

    private fun status(listener: SttSession.Listener, message: String) {
        main.post { if (!closed) listener.onStatus(message) }
    }

    private companion object {
        const val SAMPLE_RATE = 16000
        const val MAX_AUDIO_BYTES = SAMPLE_RATE * 2 * 30
    }
}
