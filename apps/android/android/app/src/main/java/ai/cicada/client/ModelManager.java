package ai.cicada.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Installs pinned model artifacts to separate app-private directories. */
final class ModelManager {
    private static final long MAX_UNPACKED_BYTES = 200L * 1024 * 1024;
    private static final String PREFS = "cicada.model.selection";
    private static final String SELECTED = "selected";
    private final Context context;
    private final Handler main;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    interface Callback {
        default void onProgress(String message) {}
        void onFinished(boolean ok, String message);
    }

    ModelManager(Context context) {
        this.context = context.getApplicationContext();
        this.main = new Handler(Looper.getMainLooper());
    }

    File modelDir(ModelCatalog.ModelSpec spec) {
        return new File(new File(context.getFilesDir(), "models"), spec.id);
    }

    boolean isInstalled(ModelCatalog.ModelSpec spec) {
        File root = modelDir(spec);
        if (!new File(root, ".verified").isFile()) return false;
        if ("vosk".equals(spec.engine)) {
            return new File(root, "am/final.mdl").isFile()
                    && new File(root, "graph/HCLr.fst").isFile();
        }
        for (ModelCatalog.Asset asset : spec.assets) {
            if (!new File(root, asset.name).isFile()) return false;
        }
        return true;
    }

    ModelCatalog.ModelSpec selected() {
        String id = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(SELECTED, null);
        ModelCatalog.ModelSpec spec = id == null ? null : ModelCatalog.get(id);
        return spec != null && isInstalled(spec) ? spec : null;
    }

    boolean select(String id) {
        ModelCatalog.ModelSpec spec = ModelCatalog.get(id);
        if (spec == null || !isInstalled(spec)) return false;
        SharedPreferences.Editor editor = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit();
        return editor.putString(SELECTED, id).commit();
    }

    void install(String id, Callback callback) {
        ModelCatalog.ModelSpec spec = ModelCatalog.get(id);
        if (spec == null) {
            finish(callback, false, "未知模型");
            return;
        }
        executor.execute(() -> {
            File parent = modelDir(spec).getParentFile();
            File staging = new File(parent, spec.id + ".staging");
            File archive = new File(context.getCacheDir(), spec.id + ".download");
            try {
                if (isInstalled(spec)) {
                    finish(callback, true, "模型已安装");
                    return;
                }
                if (!parent.exists() && !parent.mkdirs()) throw new IOException("无法创建模型目录");
                deleteRecursively(staging);
                if (!staging.mkdirs()) throw new IOException("无法创建临时目录");
                for (int index = 0; index < spec.assets.size(); index++) {
                    ModelCatalog.Asset asset = spec.assets.get(index);
                    progress(callback, "下载 " + (index + 1) + "/" + spec.assets.size()
                            + " · " + asset.name);
                    download(asset, archive, callback);
                    if ("vosk".equals(spec.engine)) {
                        progress(callback, "已校验 · 正在解压");
                        unpackVosk(spec, archive, staging);
                    } else {
                        File target = new File(staging, asset.name);
                        if (!archive.renameTo(target)) throw new IOException("模型文件保存失败");
                    }
                }
                if ("vosk".equals(spec.engine) &&
                        (!new File(staging, "am/final.mdl").isFile()
                                || !new File(staging, "graph/HCLr.fst").isFile())) {
                    throw new IOException("模型文件不完整");
                }
                try (FileOutputStream marker = new FileOutputStream(new File(staging, ".verified"))) {
                    marker.write(spec.id.getBytes(StandardCharsets.US_ASCII));
                }
                deleteRecursively(modelDir(spec));
                if (!staging.renameTo(modelDir(spec))) throw new IOException("安装模型失败");
                if (selected() == null) select(spec.id);
                finish(callback, true, spec.name + " 已安装");
            } catch (Exception error) {
                deleteRecursively(staging);
                finish(callback, false, "安装失败：" + safeMessage(error));
            } finally {
                if (archive.exists()) archive.delete();
            }
        });
    }

    void remove(String id, Callback callback) {
        ModelCatalog.ModelSpec spec = ModelCatalog.get(id);
        if (spec == null) {
            finish(callback, false, "未知模型");
            return;
        }
        executor.execute(() -> {
            deleteRecursively(modelDir(spec));
            boolean removed = !modelDir(spec).exists();
            if (removed) {
                SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                if (id.equals(prefs.getString(SELECTED, null))) prefs.edit().remove(SELECTED).commit();
            }
            finish(callback, removed, removed ? "本地模型已删除" : "删除失败");
        });
    }

    private void download(ModelCatalog.Asset asset, File target, Callback callback)
            throws IOException, NoSuchAlgorithmException {
        URL url = new URL(asset.url);
        if (!"https".equals(url.getProtocol())) throw new IOException("模型地址必须使用 HTTPS");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(20_000);
        connection.setReadTimeout(45_000);
        connection.setInstanceFollowRedirects(true);
        try {
            if (connection.getResponseCode() != 200) throw new IOException("模型服务返回 " + connection.getResponseCode());
            if (!"https".equals(connection.getURL().getProtocol())) throw new IOException("模型下载发生不安全跳转");
            long declared = connection.getContentLengthLong();
            if (declared > 0 && declared != asset.bytes) throw new IOException("模型大小与目录不符");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = connection.getInputStream();
                 FileOutputStream output = new FileOutputStream(target)) {
                byte[] buffer = new byte[64 * 1024];
                long total = 0;
                long nextReport = 4L * 1024 * 1024;
                int count;
                while ((count = input.read(buffer)) != -1) {
                    total += count;
                    if (total > asset.bytes) throw new IOException("模型文件超出预期大小");
                    digest.update(buffer, 0, count);
                    output.write(buffer, 0, count);
                    if (total >= nextReport) {
                        progress(callback, "下载 " + asset.name + " · "
                                + (total * 100 / asset.bytes) + "%");
                        nextReport = total + 4L * 1024 * 1024;
                    }
                }
                if (total != asset.bytes) throw new IOException("模型下载不完整");
            }
            if (!asset.sha256.equals(hex(digest.digest()))) throw new IOException("模型 SHA-256 校验失败");
        } finally {
            connection.disconnect();
            if (target.exists() && target.length() != asset.bytes) target.delete();
        }
    }

    private static void unpackVosk(ModelCatalog.ModelSpec spec, File archive, File staging)
            throws IOException {
        long unpacked = 0;
        int entries = 0;
        String prefix = spec.id + "/";
        String root = staging.getCanonicalPath() + File.separator;
        try (ZipInputStream zip = new ZipInputStream(new FileInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > 150 || !entry.getName().startsWith(prefix))
                    throw new IOException("模型压缩包格式错误");
                String relative = entry.getName().substring(prefix.length());
                if (relative.isEmpty()) continue;
                File output = new File(staging, relative);
                if (!output.getCanonicalPath().startsWith(root)) throw new IOException("模型路径无效");
                if (entry.isDirectory()) {
                    if (!output.isDirectory() && !output.mkdirs()) throw new IOException("无法创建模型目录");
                    continue;
                }
                File folder = output.getParentFile();
                if (!folder.isDirectory() && !folder.mkdirs()) throw new IOException("无法创建模型目录");
                try (FileOutputStream file = new FileOutputStream(output)) {
                    byte[] buffer = new byte[64 * 1024];
                    int count;
                    while ((count = zip.read(buffer)) != -1) {
                        unpacked += count;
                        if (unpacked > MAX_UNPACKED_BYTES) throw new IOException("模型解压超出限制");
                        file.write(buffer, 0, count);
                    }
                }
                zip.closeEntry();
            }
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) value.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        return value.toString();
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) for (File child : children) deleteRecursively(child);
        }
        if (file.exists()) file.delete();
    }

    private void progress(Callback callback, String value) {
        main.post(() -> callback.onProgress(value));
    }

    private void finish(Callback callback, boolean ok, String value) {
        main.post(() -> callback.onFinished(ok, value));
    }

    private static String safeMessage(Exception error) {
        String value = error.getMessage();
        return value == null ? "未知错误" : value;
    }
}
