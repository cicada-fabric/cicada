package ai.cicada.client.hub

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/** Public synthetic identities only. This is local validation, not live Node acceptance. */
@RunWith(AndroidJUnit4::class)
class NodeControlKeyBindingVerifierTest {
    @Test
    fun publicIdentitiesMatchIndependentNodewireFingerprintBytes() {
        val fixture = binding()
        assertEquals(NODE_FINGERPRINT, NodeControlKeyBindingVerifier.fingerprint(
            ClientWireCrypto.PublicIdentity.parse(fixture.getAsJsonObject("node_public_identity"))))
        assertEquals(HUB_FINGERPRINT, NodeControlKeyBindingVerifier.fingerprint(
            ClientWireCrypto.PublicIdentity.parse(fixture.getAsJsonObject("hub_public_identity"))))
        verify(fixture)
    }

    @Test
    fun wrongOwnerHubDeviceKeyOrStateFailsClosed() {
        for (field in listOf("hub_id", "owner_id", "client_device_id", "approved_owner_device_id",
                             "owner_key_id", "approved_owner_key_id", "state")) {
            reject(binding().apply { addProperty(field, "wrong") })
        }
    }

    @Test
    fun incompleteKeysSubstitutionFingerprintTamperingAndClientFingerprintAreRejected() {
        for (side in listOf("node", "hub")) {
            reject(binding().apply { remove("${side}_public_identity") })
            reject(binding().apply { getAsJsonObject("${side}_public_identity").remove("kem_public") })
            reject(binding().apply { getAsJsonObject("${side}_public_identity").addProperty("id", "pq1-wrong") })
            reject(binding().apply { getAsJsonObject("${side}_public_identity").addProperty("private_key", "denied") })
            reject(binding().apply { addProperty("${side}_key_id", "pq1-wrong") })
            reject(binding().apply { addProperty("${side}_key_fingerprint", "0".repeat(64)) })
            reject(binding().apply { addProperty("${side}_key_fingerprint",
                ClientWireCrypto.PublicIdentity.parse(getAsJsonObject("${side}_public_identity")).fingerprint()) })
        }
    }

    private fun binding(): JsonObject {
        val fixture = InstrumentationRegistry.getInstrumentation().context.assets
            .open("client-control-v1.json").use { JsonParser.parseString(String(it.readBytes(), Charsets.UTF_8)).asJsonObject }
        return JsonObject().apply {
            addProperty("hub_id", "hub-public-test")
            addProperty("owner_id", "owner-public-test")
            addProperty("client_device_id", "phone-public-test")
            addProperty("approved_owner_device_id", "phone-public-test")
            addProperty("owner_key_id", "owner-key-public-test")
            addProperty("approved_owner_key_id", "owner-key-public-test")
            addProperty("state", "ACTIVE")
            for ((side, name) in listOf("node" to "device_TEST_ONLY", "hub" to "hub_TEST_ONLY")) {
                val identity = fixture.getAsJsonObject(name).getAsJsonObject("public").deepCopy()
                add("${side}_public_identity", identity)
                addProperty("${side}_key_id", identity.get("id").asString)
                addProperty("${side}_key_fingerprint", if (side == "node") NODE_FINGERPRINT else HUB_FINGERPRINT)
            }
        }
    }

    private fun verify(value: JsonObject) = NodeControlKeyBindingVerifier.verify(value,
        "hub-public-test", "owner-public-test", "phone-public-test", "owner-key-public-test")

    private fun reject(value: JsonObject) {
        try { verify(value); fail("Tampered public binding must be rejected") }
        catch (_: IllegalArgumentException) { /* Expected local refusal. */ }
    }

    companion object {
        // Independently computed from public fixture bytes using Python hashlib, not the verifier.
        private const val NODE_FINGERPRINT = "dcbffc16220cf2e09717793060a3ca294fb5f57e707c5f8a35b1e9970b0e554f"
        private const val HUB_FINGERPRINT = "1bbffec42a95d1217d2d93ce78f3712022f8926feb29196d064c25bdd2c7ccd9"
    }
}
