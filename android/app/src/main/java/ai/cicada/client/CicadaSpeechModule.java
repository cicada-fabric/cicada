package ai.cicada.client;

import android.Manifest;
import android.content.pm.PackageManager;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

/** Android-only device adapter. App screens and request semantics live in TypeScript. */
public final class CicadaSpeechModule extends ReactContextBaseJavaModule {
    private final ReactApplicationContext context;
    private final ModelManager models;
    private SttSession stt;

    CicadaSpeechModule(ReactApplicationContext context) {
        super(context);
        this.context = context;
        this.models = new ModelManager(context);
    }

    @NonNull @Override public String getName() {
        return "CicadaSpeech";
    }

    @ReactMethod public void getModels(Promise promise) {
        WritableArray result = Arguments.createArray();
        ModelCatalog.ModelSpec selected = models.selected();
        for (ModelCatalog.ModelSpec spec : ModelCatalog.ALL) {
            WritableMap item = Arguments.createMap();
            item.putString("id", spec.id);
            item.putString("name", spec.name);
            item.putString("engine", spec.engine);
            item.putString("languages", spec.languages);
            item.putString("capabilities", spec.capabilities);
            item.putString("source", spec.source);
            item.putString("license", spec.license);
            item.putString("licenseUrl", spec.licenseUrl);
            item.putDouble("downloadBytes", spec.downloadBytes());
            item.putBoolean("installed", models.isInstalled(spec));
            item.putBoolean("selected", selected != null && selected.id.equals(spec.id));
            result.pushMap(item);
        }
        promise.resolve(result);
    }

    @ReactMethod public void installModel(String id, Promise promise) {
        models.install(id, new ModelManager.Callback() {
            @Override public void onProgress(String message) {
                emitStatus(message);
            }
            @Override public void onFinished(boolean ok, String message) {
                if (ok) promise.resolve(message);
                else promise.reject("MODEL_INSTALL_FAILED", message);
            }
        });
    }

    @ReactMethod public void removeModel(String id, Promise promise) {
        closeStt();
        models.remove(id, (ok, message) -> {
            if (ok) promise.resolve(message);
            else promise.reject("MODEL_REMOVE_FAILED", message);
        });
    }

    @ReactMethod public void selectModel(String id, Promise promise) {
        closeStt();
        if (models.select(id)) promise.resolve(null);
        else promise.reject("MODEL_SELECT_FAILED", "模型未安装或不可用");
    }

    @ReactMethod public void startListening(String sessionId, Promise promise) {
        if (sessionId == null || sessionId.isEmpty() || sessionId.length() > 256) {
            promise.reject("INVALID_SPEECH_SESSION", "A local recording session is required");
            return;
        }
        ModelCatalog.ModelSpec selected = models.selected();
        if (selected == null) {
            promise.reject("MODEL_NOT_SELECTED", "请先安装并选择本地语音模型");
            return;
        }
        if (context.checkSelfPermission(Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
            promise.reject("MIC_PERMISSION", "尚未获得麦克风权限");
            return;
        }
        closeStt();
        stt = "vosk".equals(selected.engine) ? new OfflineStt() : new SherpaOfflineStt(selected);
        stt.start(models.modelDir(selected), new SttSession.Listener() {
            @Override public void onStatus(String status) {
                WritableMap event = Arguments.createMap();
                event.putString("message", status);
                event.putString("sessionId", sessionId);
                emit("CicadaSpeechStatus", event);
            }
            @Override public void onText(String text, boolean partial) {
                WritableMap event = Arguments.createMap();
                event.putString("text", text);
                event.putBoolean("partial", partial);
                event.putString("sessionId", sessionId);
                emit("CicadaSpeechResult", event);
            }
            @Override public void onStopped() {
                WritableMap event = Arguments.createMap();
                event.putString("sessionId", sessionId);
                emit("CicadaSpeechStopped", event);
            }
        });
        promise.resolve(null);
    }

    @ReactMethod public void stopListening(Promise promise) {
        if (stt != null) stt.stop();
        promise.resolve(null);
    }

    @ReactMethod public void addListener(String eventName) {}
    @ReactMethod public void removeListeners(int count) {}

    @Override public void invalidate() {
        closeStt();
        super.invalidate();
    }

    private void closeStt() {
        if (stt != null) {
            stt.close();
            stt = null;
        }
    }

    private void emitStatus(String status) {
        WritableMap event = Arguments.createMap();
        event.putString("message", status);
        emit("CicadaSpeechStatus", event);
    }

    private void emit(String name, WritableMap data) {
        if (context.hasActiveReactInstance()) {
            context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                    .emit(name, data);
        }
    }
}
