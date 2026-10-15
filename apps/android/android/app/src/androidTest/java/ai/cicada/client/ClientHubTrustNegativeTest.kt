package ai.cicada.client

import ai.cicada.client.hub.ClientHubSession
import ai.cicada.client.hub.ClientWireCrypto
import ai.cicada.client.hub.HubSessionException
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.util.UUID

/** A fresh emulator proves trust and Grant failures leave no usable Client session. */
@RunWith(AndroidJUnit4::class)
class ClientHubTrustNegativeTest {
    @Test fun candidateWrongPinsAndInvalidGrantNeverEnroll() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val baseUrl = InstrumentationRegistry.getArguments().getString("hub_base_url")
            ?: error("hub_base_url is required")
        val session = ClientHubSession(context)
        assertFalse("Use a disposable unregistered emulator", session.getStatus().get("pinned").asBoolean)

        val candidate = session.fetchHubMetadata(baseUrl)
        assertFalse(candidate.get("trusted").asBoolean)
        assertFalse("Candidate metadata must not become a trust pin",
            session.getStatus().get("pinned").asBoolean)
        val identity = candidate.getAsJsonObject("identity")
        val hubId = identity.get("hub_id").asString
        val control = identity.getAsJsonObject("control_public_identity")
        session.createDeviceIdentity()

        fun attemptEnrollment() {
            session.enroll(
                "negative-test-owner", control.get("id").asString, control.toString(),
                "negative-test-device-${UUID.randomUUID()}",
                Base64.encodeToString("{}".toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP),
            )
        }

        session.pinHub(baseUrl, "$hubId-wrong", control.toString())
        expectCode("HUB_IDENTITY_MISMATCH") { attemptEnrollment() }

        val differentControl = ClientWireCrypto.Identity.generate().publicIdentity.toJson()
        session.pinHub(baseUrl, hubId, differentControl)
        expectCode("HUB_IDENTITY_MISMATCH") { attemptEnrollment() }

        // The real key here is test input only; no first-use trust is promoted in the app.
        session.pinHub(baseUrl, hubId, control.toString())
        expectCode("INVALID_OWNER_GRANT") { attemptEnrollment() }
        val status: JsonObject = session.getStatus()
        assertFalse(status.get("enrolled").asBoolean)
        assertFalse(status.get("sessionCapabilitiesReady").asBoolean)
        assertFalse(status.get("remoteEnabled").asBoolean)
        assertFalse(status.has("pendingOperationId"))
        assertFalse(status.has("nextSequence"))
    }

    private fun expectCode(expected: String, action: () -> Unit) {
        try {
            action()
            fail("Expected $expected")
        } catch (error: HubSessionException) {
            assertEquals(expected, error.errorCode)
        }
    }
}
