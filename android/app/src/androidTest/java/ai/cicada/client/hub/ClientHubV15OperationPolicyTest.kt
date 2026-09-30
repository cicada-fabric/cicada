package ai.cicada.client.hub

import android.content.Context
import android.content.ContextWrapper
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Synthetic local policy tests. They do not certify real Hub consent or delegation execution. */
@RunWith(AndroidJUnit4::class)
class ClientHubV15OperationPolicyTest {
    private data class Sandbox(
        val session: ClientHubSession,
        val stateFile: File,
        val wrappedKeyFile: File,
        val initialState: JsonObject,
    )

    @Test
    fun newConsentOperationsAreRejectedBeforeStoredStateOrDeviceKeys() = sandbox(false) { box ->
        // A corrupt existing file proves rejection precedes even parsing persisted state.
        box.stateFile.writeText("not-json-synthetic-state")
        val original = box.stateFile.readBytes()
        for (operation in NEW_CONSENT_OPERATIONS) {
            expectCode("CLIENT_CONSENT_FLOW_UNAVAILABLE") { box.session.rpc(operation, JsonObject()) }
            assertArrayEquals(original, box.stateFile.readBytes())
            assertFalse(box.wrappedKeyFile.exists())
        }
        expectCode("UNSUPPORTED_RPC_OPERATION") { box.session.rpc(UNKNOWN_OPERATION, JsonObject()) }
        assertArrayEquals(original, box.stateFile.readBytes())
        assertFalse(box.wrappedKeyFile.exists())
    }

    @Test
    fun authenticatedV15CapabilitiesExposeOnlyImplementedOperations() = sandbox { box ->
        ClientWireCrypto.Identity.generate().use { control ->
            for (role in listOf("manager", "external")) {
                box.stateFile.writeText(box.initialState.toString())
                acceptSyntheticCapabilities(box, control, role)
                val status = box.session.getStatus()
                assertTrue(status.get("sessionCapabilitiesReady").asBoolean)
                assertEquals(role, status.get("role").asString)
                assertEquals(IMPLEMENTED_SAMPLE.toSet(), status.getAsJsonArray("allowedOperations").map { it.asString }.toSet())
                val persisted = JsonParser.parseString(box.stateFile.readText()).asJsonObject
                assertEquals(IMPLEMENTED_SAMPLE.toSet(), persisted.getAsJsonArray("allowedOperations").map { it.asString }.toSet())
                assertEquals(12L, persisted.get("nextSequence").asLong)
                assertEquals(10L, persisted.get("lastResponseSequence").asLong)
                assertFalse(persisted.has("pending"))
                for (operation in NEW_CONSENT_OPERATIONS) {
                    assertUnchanged(box, "CLIENT_CONSENT_FLOW_UNAVAILABLE") { box.session.rpc(operation, JsonObject()) }
                }
                // Existing dedicated consent paths remain guarded after the contract upgrade.
                assertUnchanged(box, "VERIFIED_GROUP_FLOW_REQUIRED") { box.session.rpc("group.key_manifest", JsonObject()) }
                assertUnchanged(box, "VERIFIED_NETWORK_FLOW_REQUIRED") { box.session.rpc("network.key_manifest", JsonObject()) }
                assertUnchanged(box, "VERIFIED_MONITOR_FLOW_REQUIRED") { box.session.rpc("monitor.broadcast_recover", JsonObject()) }
            }
        }
    }

    @Test
    fun persistedCapabilitiesCannotBypassPolicyOrReplaceOriginalPending() = sandbox { box ->
        val pending = JsonObject().apply {
            addProperty("operation", "intent.submit")
            addProperty("operationId", "synthetic-original-operation")
            addProperty("sequence", 10)
            addProperty("expectedResponseSequence", 10)
            addProperty("packetJson", "EXACT_SYNTHETIC_ORIGINAL_PACKET")
        }
        box.stateFile.writeText(box.initialState.deepCopy().apply {
            add("allowedOperations", advertisement())
            add("pending", pending)
        }.toString())
        assertEquals(IMPLEMENTED_SAMPLE.toSet(), box.session.getStatus().getAsJsonArray("allowedOperations").map { it.asString }.toSet())
        for (operation in NEW_CONSENT_OPERATIONS) {
            assertUnchanged(box, "CLIENT_CONSENT_FLOW_UNAVAILABLE") { box.session.rpc(operation, JsonObject(), "replacement-attempt") }
        }
        assertUnchanged(box, "UNSUPPORTED_RPC_OPERATION") { box.session.rpc(UNKNOWN_OPERATION, JsonObject()) }
        val persisted = JsonParser.parseString(box.stateFile.readText()).asJsonObject
        assertEquals(pending, persisted.getAsJsonObject("pending"))
        assertEquals(11L, persisted.get("nextSequence").asLong)
        assertEquals(9L, persisted.get("lastResponseSequence").asLong)
    }

    @Test
    fun historicalCapabilitiesCannotAuthorizeExistingOperationsAfterUpgrade() = sandbox { box ->
        box.stateFile.writeText(box.initialState.deepCopy().apply {
            addProperty("validatedContractRevision", "client-hub-v1.4")
            addProperty("validatedCatalogSha256", "7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54")
            add("allowedOperations", advertisement().apply { add("intent.submit") })
        }.toString())
        val status = box.session.getStatus()
        assertFalse(status.get("sessionCapabilitiesReady").asBoolean)
        assertFalse(status.has("role"))
        assertEquals(0, status.getAsJsonArray("allowedOperations").size())
        assertUnchanged(box, "SESSION_CAPABILITIES_REQUIRED") { box.session.rpc("intent.submit", JsonObject()) }
        assertUnchanged(box, "CLIENT_CONSENT_FLOW_UNAVAILABLE") { box.session.rpc("topology.regroup_proposal", JsonObject()) }
    }

    /** Signed/encrypted test-side capability response, consumed by the production state machine. */
    private fun acceptSyntheticCapabilities(box: Sandbox, control: ClientWireCrypto.Identity, role: String) {
        val state = JsonParser.parseString(box.stateFile.readText()).asJsonObject
        val device = invokePrivate(box.session, "loadDeviceIdentity") as ClientWireCrypto.Identity
        device.use {
            val request = ClientWireCrypto.Route().apply {
                direction = "REQUEST"
                hubId = "synthetic-v15-policy-hub"
                ownerId = "synthetic-v15-policy-owner"
                deviceId = "synthetic-v15-policy-device"
                sessionEpoch = 1
                sequence = 11
                operation = "session.capabilities"
                operationId = "synthetic-v15-capabilities-$role"
                senderKeyId = device.publicIdentity.id
                senderKeyVersion = 1
                receiverKeyId = control.publicIdentity.id
                receiverKeyVersion = 1
            }
            state.getAsJsonObject("pin").addProperty("controlPublicIdentityJson", control.publicIdentity.toJson())
            state.addProperty("nextSequence", 12)
            state.add("pending", JsonObject().apply {
                addProperty("operation", request.operation)
                addProperty("operationId", request.operationId)
                addProperty("sequence", request.sequence)
                addProperty("expectedResponseSequence", 10)
                addProperty("packetJson", ClientWireCrypto.sealRequest(device, control.publicIdentity, request, "{}"))
            })
            box.stateFile.writeText(state.toString())
            val response = ClientWireCrypto.Route.parse(JsonParser.parseString(request.toJson()).asJsonObject).apply {
                direction = "RESPONSE"
                sequence = 10
                senderKeyId = control.publicIdentity.id
                receiverKeyId = device.publicIdentity.id
            }
            val body = JsonObject().apply {
                addProperty("request_id", "synthetic-v15-request-$role")
                addProperty("operation_id", request.operationId)
                addProperty("ok", true)
                add("result", JsonObject().apply {
                    addProperty("owner_id", request.ownerId)
                    addProperty("role", role)
                    addProperty("contract_revision", "client-hub-v1.5")
                    addProperty("catalog_sha256", "a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68")
                    add("available_rpc_operations", advertisement())
                })
            }
            val aad = ("cicada/client-control/packet/v1\u0000" + response.toJson()).toByteArray(StandardCharsets.UTF_8)
            val envelope = ClientWireCrypto.sealRawEnvelope(control, device.publicIdentity, 10,
                aad, body.toString().toByteArray(StandardCharsets.UTF_8))
            val packet = JsonObject().apply {
                add("route", JsonParser.parseString(response.toJson()))
                addProperty("envelope", Base64.encodeToString(envelope.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP))
            }
            invokePrivate(box.session, "finishResponse", invokePrivate(box.session, "readState"), device,
                control.publicIdentity, request, packet.toString(), true)
        }
    }

    private fun advertisement(): JsonArray = JsonArray().apply {
        (IMPLEMENTED_SAMPLE + NEW_CONSENT_OPERATIONS + listOf("link.key_manifest", "link.key_grant",
            "link.key_grants", UNKNOWN_OPERATION)).forEach(::add)
    }

    private fun invokePrivate(session: ClientHubSession, name: String, vararg args: Any?): Any? = try {
        ClientHubSession::class.java.declaredMethods.single { it.name == name }.apply { isAccessible = true }.invoke(session, *args)
    } catch (error: InvocationTargetException) { throw error.targetException }

    private fun assertUnchanged(box: Sandbox, code: String, action: () -> Unit) {
        val stateBytes = box.stateFile.readBytes()
        val keyBytes = box.wrappedKeyFile.readBytes()
        expectCode(code, action)
        assertArrayEquals(stateBytes, box.stateFile.readBytes())
        assertArrayEquals(keyBytes, box.wrappedKeyFile.readBytes())
    }

    private fun expectCode(code: String, action: () -> Unit) {
        try { action(); fail("Expected $code") }
        catch (error: HubSessionException) { assertEquals(code, error.errorCode) }
    }

    private fun sandbox(prepared: Boolean = true, action: (Sandbox) -> Unit) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(target.cacheDir, "v15-operation-policy-${UUID.randomUUID()}").apply { check(mkdirs()) }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getNoBackupFilesDir(): File = root
        }
        val profileId = UUID.randomUUID().toString()
        val session = ClientHubSession(context, profileId)
        val directory = ClientHubSession.profileDirectory(context, profileId)
        val fixture = InstrumentationRegistry.getInstrumentation().context.assets.open("network-direct-key-consent-v1.json")
            .use { JsonParser.parseString(it.reader().readText()).asJsonObject }
        val initial = JsonObject().apply {
            addProperty("nextSequence", 11)
            addProperty("lastResponseSequence", 9)
            addProperty("role", "manager")
            addProperty("sessionCapabilitiesReady", true)
            addProperty("validatedContractRevision", "client-hub-v1.5")
            addProperty("validatedCatalogSha256", "a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68")
            add("allowedOperations", advertisement())
            add("pin", JsonObject().apply {
                addProperty("baseUrl", "https://127.0.0.1:1")
                addProperty("hubId", "synthetic-v15-policy-hub")
                addProperty("controlPublicIdentityJson", fixture.getAsJsonObject("receiver_public_identity").toString())
            })
            add("enrollment", JsonObject().apply {
                addProperty("ownerId", "synthetic-v15-policy-owner")
                addProperty("deviceId", "synthetic-v15-policy-device")
                addProperty("sessionEpoch", 1)
                addProperty("deviceKeyVersion", 1)
                addProperty("state", "ACTIVE")
            })
        }
        val box = Sandbox(session, File(directory, "session-state.json"), File(directory, "device-key.wrap.json"), initial)
        try {
            if (prepared) { session.createDeviceIdentity(); box.stateFile.writeText(initial.toString()) }
            action(box)
        } finally {
            box.stateFile.writeText("{}")
            session.deleteProfileState()
            root.deleteRecursively()
        }
    }

    companion object {
        private const val UNKNOWN_OPERATION = "future.unverified_consent"
        private val IMPLEMENTED_SAMPLE = listOf("session.capabilities", "status.snapshot", "group.key_manifest",
            "network.key_manifest", "monitor.broadcast_recover")
        // Exact newly delivered v1.5 catalog identifiers, independent of the implementation set.
        private val NEW_CONSENT_OPERATIONS = listOf(
            "space.foreign_member_admit", "space.foreign_member_revoke", "space.foreign_endpoint_join",
            "space.key_manifest_v2", "space.key_consent_v2", "space.key_admission_v2", "space.key_status_v2",
            "topology.delegation_issue", "topology.delegation_revoke", "topology.regroup_proposal",
        )
    }
}
