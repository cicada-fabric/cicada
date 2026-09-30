package ai.cicada.client

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContext
import com.cicadaclient.MainActivity
import com.cicadaclient.MainApplication
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Exercises model installation, microphone permission checks, and Vosk recording lifecycle. */
@RunWith(AndroidJUnit4::class)
class SttAcceptanceTest {
    @Test fun catalogAssetsHaveCompleteHttpsPins() {
        assertTrue("Model catalog is empty", ModelCatalog.ALL.isNotEmpty())
        for (spec in ModelCatalog.ALL) {
            for (asset in spec.assets) {
                val name = "${spec.id}/${asset.name}"
                assertTrue("$name must use HTTPS", asset.url.startsWith("https://"))
                assertTrue("$name must have a positive size", asset.bytes > 0)
                assertTrue(
                    "$name needs a full SHA-256 pin",
                    asset.sha256.matches(Regex("[a-f0-9]{64}")),
                )
            }
        }
    }

    @Test fun englishVoskModelDownloadsAndCanBeSelected() {
        val manager = modelManager()
        val spec = englishModel()
        assertInstall(manager, spec.id)
        assertTrue(File(manager.modelDir(spec), "am/final.mdl").isFile)
        assertTrue(File(manager.modelDir(spec), "graph/HCLr.fst").isFile)
        assertTrue(manager.select(spec.id))
        assertEquals(spec.id, manager.selected()?.id)
    }

    @Test fun senseVoiceDownloadsVerifiesAndCanBeSelected() {
        val manager = modelManager()
        val spec = requireNotNull(ModelCatalog.get("sherpa-sensevoice-small-int8"))
        assertInstall(manager, spec.id)
        assertTrue(File(manager.modelDir(spec), "model.int8.onnx").isFile)
        assertTrue(File(manager.modelDir(spec), "tokens.txt").isFile)
        assertTrue(manager.select(spec.id))
        assertEquals(spec.id, manager.selected()?.id)
    }

    @Test fun interruptedEnglishInstallLeavesNoPartialFiles() {
        val manager = modelManager()
        val spec = englishModel()
        removeModel(manager, spec.id)

        val done = CountDownLatch(1)
        val success = AtomicReference<Boolean>()
        val detail = AtomicReference("installer callback not received")
        val interruptionTriggered = AtomicReference(false)
        val interruptionError = AtomicReference<String>()
        manager.install(spec.id, object : ModelManager.Callback {
            override fun onProgress(message: String) {
                if (message.contains("%") && interruptionTriggered.compareAndSet(false, true)) {
                    try {
                        setGuestNetworkEnabled(false)
                    } catch (error: Exception) {
                        interruptionError.set(error.message ?: error.javaClass.simpleName)
                    }
                }
            }

            override fun onFinished(ok: Boolean, message: String) {
                success.set(ok)
                detail.set(message)
                done.countDown()
            }
        })

        try {
            assertTrue("Installer timed out: ${detail.get()}", done.await(90, TimeUnit.SECONDS))
            assertTrue("No mid-download progress was interrupted", interruptionTriggered.get())
            assertNull("Could not disable guest networking: ${interruptionError.get()}",
                interruptionError.get())
            assertFalse(detail.get(), success.get())
            assertFalse(manager.isInstalled(spec))
            assertFalse(File(manager.modelDir(spec).parentFile, "${spec.id}.staging").exists())
            assertFalse(File(targetContext().cacheDir, "${spec.id}.download").exists())
        } finally {
            setGuestNetworkEnabled(true)
        }
    }

    @Test fun removingSelectedEnglishModelClearsSelection() {
        val manager = modelManager()
        val spec = englishModel()
        assertInstall(manager, spec.id)
        assertTrue(manager.select(spec.id))
        assertEquals(spec.id, manager.selected()?.id)

        removeModel(manager, spec.id)

        assertFalse(manager.isInstalled(spec))
        assertNull(manager.selected())
    }

    @Test fun startListeningRejectsMissingMicrophonePermission() {
        val context = targetContext()
        val manager = modelManager()
        val model = englishModel()
        assertInstall(manager, model.id)
        assertTrue(manager.select(model.id))
        assertEquals(
            PackageManager.PERMISSION_DENIED,
            context.checkSelfPermission(Manifest.permission.RECORD_AUDIO),
        )

        val rejectedCode = AtomicReference<String>()
        val promise = Proxy.newProxyInstance(
            Promise::class.java.classLoader,
            arrayOf(Promise::class.java),
        ) { _, method, args ->
            if (method.name == "reject") rejectedCode.set(args?.firstOrNull() as? String)
            null
        } as Promise

        speechModule().startListening("permission-test-recording", promise)

        assertEquals("MIC_PERMISSION", rejectedCode.get())
    }

    @Test fun grantedVoskRecordingCanBeStoppedWithoutProducingText() {
        val context = targetContext()
        val manager = modelManager()
        val spec = englishModel()
        assertInstall(manager, spec.id)
        assertTrue(manager.select(spec.id))
        assertEquals(
            PackageManager.PERMISSION_GRANTED,
            context.checkSelfPermission(Manifest.permission.RECORD_AUDIO),
        )

        val listening = CountDownLatch(1)
        val stopped = CountDownLatch(1)
        val lastStatus = AtomicReference("no status received")
        val recognizedText = AtomicReference<String>()
        val session = OfflineStt()
        try {
            session.start(manager.modelDir(spec), object : SttSession.Listener {
                override fun onStatus(status: String) {
                    lastStatus.set(status)
                    if (status.contains("离线聆听")) listening.countDown()
                }

                override fun onText(text: String, partial: Boolean) {
                    recognizedText.set(text)
                }

                override fun onStopped() {
                    stopped.countDown()
                }
            })

            assertTrue(
                "Vosk did not start microphone capture: ${lastStatus.get()}",
                listening.await(45, TimeUnit.SECONDS))
            session.stop()
            assertTrue(
                "Stopping capture did not finish: ${lastStatus.get()}",
                stopped.await(10, TimeUnit.SECONDS))
            assertNull("Silent emulator input must not produce text", recognizedText.get())
        } finally {
            session.close()
        }
    }

    private fun targetContext() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun setGuestNetworkEnabled(enabled: Boolean) {
        val commands = if (enabled) {
            listOf(
                "cmd wifi set-wifi-enabled enabled",
                "svc data enable",
                "cmd connectivity airplane-mode disable",
            )
        } else {
            listOf(
                "cmd connectivity airplane-mode enable",
                "cmd wifi set-wifi-enabled disabled",
                "svc data disable",
            )
        }
        for (command in commands) {
            val descriptor = InstrumentationRegistry.getInstrumentation().uiAutomation
                .executeShellCommand(command)
            ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
        }
    }

    private fun modelManager() = ModelManager(targetContext())

    private fun englishModel() = requireNotNull(ModelCatalog.get("vosk-model-small-en-us-0.15"))

    private fun speechModule(): CicadaSpeechModule {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = targetContext()
        instrumentation.startActivitySync(
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        val app = context.applicationContext as MainApplication
        var reactContext: ReactContext? = app.reactHost.currentReactContext
        val deadline = SystemClock.elapsedRealtime() + 20_000
        while (reactContext == null && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(100)
            reactContext = app.reactHost.currentReactContext
        }
        assertTrue("React Native did not initialize", reactContext != null)
        val applicationContext = reactContext as? ReactApplicationContext
        assertTrue("React Native context is not an application context", applicationContext != null)
        return CicadaSpeechPackage().createNativeModules(requireNotNull(applicationContext))
            .filterIsInstance<CicadaSpeechModule>()
            .single()
    }

    private fun assertInstall(manager: ModelManager, id: String) {
        val done = CountDownLatch(1)
        val success = AtomicReference<Boolean>()
        val detail = AtomicReference("installer callback not received")
        manager.install(id, object : ModelManager.Callback {
            override fun onFinished(ok: Boolean, message: String) {
                success.set(ok)
                detail.set(message)
                done.countDown()
            }
        })
        assertTrue("Installer timed out: ${detail.get()}", done.await(180, TimeUnit.SECONDS))
        assertTrue(detail.get(), success.get())
        val spec = requireNotNull(ModelCatalog.get(id))
        assertTrue(manager.isInstalled(spec))
    }

    private fun removeModel(manager: ModelManager, id: String) {
        val done = CountDownLatch(1)
        val success = AtomicReference<Boolean>()
        val detail = AtomicReference("removal callback not received")
        manager.remove(id, object : ModelManager.Callback {
            override fun onFinished(ok: Boolean, message: String) {
                success.set(ok)
                detail.set(message)
                done.countDown()
            }
        })
        assertTrue("Removal timed out: ${detail.get()}", done.await(30, TimeUnit.SECONDS))
        assertTrue(detail.get(), success.get())
    }
}
