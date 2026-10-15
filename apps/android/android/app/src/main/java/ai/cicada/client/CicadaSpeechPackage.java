package ai.cicada.client;

import androidx.annotation.NonNull;

import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;

import java.util.Collections;
import java.util.List;

public final class CicadaSpeechPackage implements ReactPackage {
    @NonNull @Override public List<NativeModule> createNativeModules(@NonNull ReactApplicationContext context) {
        return Collections.singletonList(new CicadaSpeechModule(context));
    }

    @NonNull @Override public List<ViewManager> createViewManagers(@NonNull ReactApplicationContext context) {
        return Collections.emptyList();
    }
}
