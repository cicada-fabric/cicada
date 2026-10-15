package ai.cicada.client;

import java.io.File;

interface SttSession {
    interface Listener {
        void onStatus(String status);
        void onText(String text, boolean partial);
        void onStopped();
    }

    void start(File modelDir, Listener listener);
    void stop();
    void close();
}
