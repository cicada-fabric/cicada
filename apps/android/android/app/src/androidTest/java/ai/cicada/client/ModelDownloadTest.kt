package ai.cicada.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Exercises the same verified installer used by the UI, with the emulator's network proxy. */
@RunWith(AndroidJUnit4::class)
class ModelDownloadTest {
    @Test fun downloadsVerifiesAndSelectsParaformer() {
        installAndSelect("sherpa-paraformer-zh-small")
    }

    @Test fun downloadsUnpacksAndSelectsVoskChinese() {
        installAndSelect("vosk-model-small-cn-0.22")
    }

    private fun installAndSelect(id: String) {
        val manager = ModelManager(InstrumentationRegistry.getInstrumentation().targetContext)
        val spec = ModelCatalog.get(id)
        val done = CountDownLatch(1)
        var success = false
        var detail = "callback not received"
        manager.install(spec.id, object : ModelManager.Callback {
            override fun onFinished(ok: Boolean, message: String) {
                success = ok
                detail = message
                done.countDown()
            }
        })
        assertTrue("Installer timed out", done.await(180, TimeUnit.SECONDS))
        assertTrue(detail, success)
        assertTrue(manager.isInstalled(spec))
        assertTrue(manager.select(spec.id))
        assertEquals(spec.id, manager.selected()?.id)
    }
}
