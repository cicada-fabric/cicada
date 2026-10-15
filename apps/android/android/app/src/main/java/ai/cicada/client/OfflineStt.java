package ai.cicada.client;

import android.os.Handler;
import android.os.Looper;

import org.json.JSONObject;
import org.vosk.Model;
import org.vosk.Recognizer;
import org.vosk.android.RecognitionListener;
import org.vosk.android.SpeechService;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Microphone audio stays on the device; only recognized text reaches the composer. */
final class OfflineStt implements SttSession {

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private Model model;
    private SpeechService service;
    private volatile boolean closed;
    private volatile boolean stopped;

    @Override public void start(File modelDir, Listener listener) {
        worker.execute(() -> {
            if (closed || stopped) return;
            try {
                main.post(() -> listener.onStatus("正在加载本地模型…"));
                if (model == null) model = new Model(modelDir.getAbsolutePath());
                if (closed || stopped) return;
                Recognizer recognizer = new Recognizer(model, 16000.0f);
                main.post(() -> {
                    if (closed || stopped) {
                        recognizer.close();
                        return;
                    }
                    try {
                        service = new SpeechService(recognizer, 16000.0f);
                        service.startListening(new RecognitionListener() {
                            @Override public void onPartialResult(String hypothesis) {
                                emit(hypothesis, true, listener);
                            }
                            @Override public void onResult(String hypothesis) {
                                emit(hypothesis, false, listener);
                            }
                            @Override public void onFinalResult(String hypothesis) {
                                emit(hypothesis, false, listener);
                                listener.onStopped();
                            }
                            @Override public void onError(Exception error) {
                                listener.onStatus("转写失败，请重试或直接输入文字");
                                listener.onStopped();
                            }
                            @Override public void onTimeout() {
                                listener.onStopped();
                            }
                        });
                        listener.onStatus("正在离线聆听 · 点按停止");
                    } catch (Exception error) {
                        if (service != null) {
                            service.shutdown();
                            service = null;
                        } else recognizer.close();
                        listener.onStatus("无法启动麦克风：" + error.getMessage());
                        listener.onStopped();
                    }
                });
            } catch (Exception error) {
                main.post(() -> {
                    listener.onStatus("本地模型无法加载，请重新安装");
                    listener.onStopped();
                });
            }
        });
    }

    @Override public void stop() {
        stopped = true;
        if (service != null) service.stop();
    }

    @Override public void close() {
        closed = true;
        stopped = true;
        if (service != null) {
            service.stop();
            service.shutdown();
            service = null;
        }
        worker.execute(() -> {
            if (model != null) {
                model.close();
                model = null;
            }
        });
    }

    private void emit(String hypothesis, boolean partial, Listener listener) {
        try {
            String text = new JSONObject(hypothesis).optString(partial ? "partial" : "text", "").trim();
            if (!text.isEmpty()) main.post(() -> {
                if (!closed) listener.onText(text, partial);
            });
        } catch (Exception ignored) {
            // Malformed partial recognition is ignored; it is never logged or uploaded.
        }
    }
}
