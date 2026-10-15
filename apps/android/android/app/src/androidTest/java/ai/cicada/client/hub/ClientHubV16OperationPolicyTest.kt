package ai.cicada.client.hub

import android.content.Context
import android.content.ContextWrapper
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.stream.JsonWriter
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.StringWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.net.URLStreamHandler
import java.net.URLStreamHandlerFactory
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Synthetic local policy tests. They do not certify real Hub consent or delegation execution. */
@RunWith(AndroidJUnit4::class)
class ClientHubV16OperationPolicyTest {
    private data class Sandbox(
        val session: ClientHubSession,
        val stateFile: File,
        val wrappedKeyFile: File,
        val initialState: JsonObject,
        val devicePublicIdentity: JsonObject?,
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
        expectCode("VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED") {
            box.session.rpc("link.review_policy_status", JsonObject().apply { addProperty("link_id", "synthetic-link") })
        }
        assertArrayEquals(original, box.stateFile.readBytes())
        assertFalse(box.wrappedKeyFile.exists())
        expectCode("UNSUPPORTED_RPC_OPERATION") { box.session.rpc(UNKNOWN_OPERATION, JsonObject()) }
        assertArrayEquals(original, box.stateFile.readBytes())
        assertFalse(box.wrappedKeyFile.exists())
    }

    @Test
    fun authenticatedV16CapabilitiesExposeOnlyImplementedOperations() = sandbox { box ->
        ClientWireCrypto.Identity.generate().use { control ->
            val deviceJson = box.devicePublicIdentity
                ?: throw AssertionError("Public Client identity was not created")
            val device = ClientWireCrypto.PublicIdentity.parse(deviceJson)
            val initial = box.initialState.deepCopy().apply {
                addProperty("sessionCapabilitiesReady", false)
                add("role", null)
                add("allowedOperations", JsonArray())
                getAsJsonObject("pin").addProperty("controlPublicIdentityJson", control.publicIdentity.toJson())
            }
            for (role in listOf("manager", "external")) {
                box.stateFile.writeText(initial.toString())
                val before = box.session.getStatus()
                assertFalse(before.get("sessionCapabilitiesReady").asBoolean)
                assertFalse(before.has("role"))
                assertEquals(0, before.getAsJsonArray("allowedOperations").size())

                val operationId = "synthetic-v16-capabilities-$role"
                val responder = SyntheticCapabilitiesResponder(
                    control,
                    device,
                    role,
                    operationId,
                    advertisement(),
                )
                SyntheticHttpsTransport.install(responder)
                val response = try {
                    box.session.rpc("session.capabilities", JsonObject(), operationId)
                } finally {
                    SyntheticHttpsTransport.clear(responder)
                }
                assertTrue(response.get("ok").asBoolean)
                assertEquals(operationId, response.get("operationId").asString)
                assertEquals(1, responder.requestCount)

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
        assertUnchanged(box, "VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED") {
            box.session.rpc("link.review_policy_status", JsonObject().apply { addProperty("link_id", "replacement") }, "replacement-attempt")
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
        assertUnchanged(box, "VERIFIED_REGROUP_FLOW_REQUIRED") { box.session.rpc("topology.regroup_proposal", JsonObject()) }
    }

    @Test
    fun linkReviewStatusUsesFreshOwnerListAndRecoversTheExactOriginalPacket() = sandbox { box ->
        ClientWireCrypto.Identity.generate().use { control ->
            val deviceJson = box.devicePublicIdentity ?: throw AssertionError("Public Client identity was not created")
            val device = ClientWireCrypto.PublicIdentity.parse(deviceJson)
            val initial = box.initialState.deepCopy().apply {
                add("pin", getAsJsonObject("pin").deepCopy().apply {
                    addProperty("controlPublicIdentityJson", control.publicIdentity.toJson())
                })
            }
            box.stateFile.writeText(initial.toString())
            val responder = SyntheticLinkStatusResponder(control, device, loseFirstStatusResponse = true)
            SyntheticHttpsTransport.install(responder)
            try {
                expectCode("NETWORK_ERROR") { box.session.linkReviewPolicyStatus("synthetic-link", 4L) }
                val pendingState = JsonParser.parseString(box.stateFile.readText()).asJsonObject
                val pending = pendingState.getAsJsonObject("pending")
                val originalPacket = pending.get("packetJson").asString
                assertEquals("link.review_policy_status", pending.get("operation").asString)
                val savedContext = pendingState.getAsJsonObject("linkReviewStatusReadContext")
                assertEquals("synthetic-link", savedContext.get("link_id").asString)
                assertEquals(4L, savedContext.get("link_version").asLong)
                assertEquals("SOURCE", savedContext.get("my_side").asString)
                assertEquals(pending.get("operationId").asString, savedContext.get("operation_id").asString)
                assertEquals(pending.get("sequence").asLong, savedContext.get("sequence").asLong)
                assertEquals(13L, pendingState.get("nextSequence").asLong)
                assertEquals(10L, pendingState.get("lastResponseSequence").asLong)

                val recovered = box.session.recoverPending()
                assertTrue(recovered.get("ok").asBoolean)
                assertEquals("synthetic-link", recovered.getAsJsonObject("result").get("link_id").asString)
                assertEquals(1, responder.recoveryCount)
                assertEquals(originalPacket, responder.recoveredOriginalPacket)
                val recoveredState = JsonParser.parseString(box.stateFile.readText()).asJsonObject
                assertFalse(recoveredState.has("pending"))
                assertFalse(recoveredState.has("linkReviewStatusReadContext"))
                assertEquals(13L, recoveredState.get("nextSequence").asLong)
                assertEquals(11L, recoveredState.get("lastResponseSequence").asLong)

                val directDto = box.session.linkReviewPolicyStatus("synthetic-link", 4L)
                assertEquals("synthetic-link", directDto.get("link_id").asString)
                assertEquals(4L, directDto.get("link_version").asLong)
                assertEquals(0L, directDto.get("policy_version").asLong)
                assertEquals(listOf("link.list", "link.review_policy_status", "link.list", "link.review_policy_status"), responder.rpcOperations)
                assertEquals(15L, JsonParser.parseString(box.stateFile.readText()).asJsonObject.get("nextSequence").asLong)
            } finally {
                SyntheticHttpsTransport.clear(responder)
            }
        }
    }

    @Test
    fun linkReviewStatusRejectsStaleListVersionBeforeIssuingStatusRpc() = sandbox { box ->
        ClientWireCrypto.Identity.generate().use { control ->
            val deviceJson = box.devicePublicIdentity ?: throw AssertionError("Public Client identity was not created")
            val device = ClientWireCrypto.PublicIdentity.parse(deviceJson)
            val initial = box.initialState.deepCopy().apply {
                add("pin", getAsJsonObject("pin").deepCopy().apply {
                    addProperty("controlPublicIdentityJson", control.publicIdentity.toJson())
                })
            }
            box.stateFile.writeText(initial.toString())
            val responder = SyntheticLinkStatusResponder(control, device, linkVersion = 5L)
            SyntheticHttpsTransport.install(responder)
            try {
                expectCode("LINK_REVIEW_LINK_STALE") { box.session.linkReviewPolicyStatus("synthetic-link", 4L) }
                assertEquals(listOf("link.list"), responder.rpcOperations)
                val after = JsonParser.parseString(box.stateFile.readText()).asJsonObject
                assertFalse(after.has("pending"))
                assertFalse(after.has("linkReviewStatusReadContext"))
                assertEquals(12L, after.get("nextSequence").asLong)
                assertEquals(10L, after.get("lastResponseSequence").asLong)
            } finally {
                SyntheticHttpsTransport.clear(responder)
            }
        }
    }

    /** One-shot in-memory Control response for the public encrypted RPC path. */
    private interface SyntheticResponder {
        fun respond(url: URL, method: String, requestBytes: ByteArray): ByteArray
    }

    private class SyntheticCapabilitiesResponder(
        private val control: ClientWireCrypto.Identity,
        private val device: ClientWireCrypto.PublicIdentity,
        private val role: String,
        private val operationId: String,
        private val operations: JsonArray,
    ) : SyntheticResponder {
        var requestCount: Int = 0
            private set

        override fun respond(url: URL, method: String, requestBytes: ByteArray): ByteArray {
            if (url.protocol != "https" || url.host != SYNTHETIC_HOST || url.port != SYNTHETIC_PORT ||
                url.path != SYNTHETIC_RPC_PATH || url.query != null || url.ref != null || url.userInfo != null ||
                method != "POST" || requestBytes.isEmpty()
            ) {
                throw IOException("Synthetic policy transport rejected the request")
            }
            requestCount += 1
            if (requestCount != 1) throw IOException("Synthetic policy transport accepts one RPC")

            val packet = JsonParser.parseString(String(requestBytes, StandardCharsets.UTF_8)).asJsonObject
            val requestRouteJson = packet.getAsJsonObject("route")
            val requestRoute = ClientWireCrypto.Route.parse(requestRouteJson)
            if (requestRoute.toJson() != requestRouteJson.toString() ||
                requestRouteJson.get("version").asInt != 1 ||
                requestRouteJson.get("direction").asString != "REQUEST" ||
                requestRouteJson.get("hub_id").asString != SYNTHETIC_HUB_ID ||
                requestRouteJson.get("owner_id").asString != SYNTHETIC_OWNER_ID ||
                requestRouteJson.get("device_id").asString != SYNTHETIC_DEVICE_ID ||
                requestRouteJson.get("session_epoch").asLong != 1L ||
                requestRouteJson.get("sequence").asLong != REQUEST_SEQUENCE ||
                requestRouteJson.get("operation").asString != "session.capabilities" ||
                requestRouteJson.get("operation_id").asString != operationId ||
                requestRouteJson.get("sender_key_id").asString != device.id ||
                requestRouteJson.get("sender_key_version").asLong != 1L ||
                requestRouteJson.get("receiver_key_id").asString != control.publicIdentity.id ||
                requestRouteJson.get("receiver_key_version").asLong != 1L
            ) {
                throw IOException("Synthetic policy transport rejected the RPC route")
            }

            val requestEnvelopeText = String(
                Base64.decode(packet.get("envelope").asString, Base64.NO_WRAP),
                StandardCharsets.UTF_8,
            )
            val requestEnvelope = JsonParser.parseString(requestEnvelopeText).asJsonObject
            if (requestEnvelope.get("version").asInt != 1 ||
                requestEnvelope.get("sequence").asLong != REQUEST_SEQUENCE ||
                requestEnvelope.get("sender_id").asString != device.id ||
                requestEnvelope.get("sender_signing_public").asString !=
                Base64.encodeToString(device.signingPublic, Base64.NO_WRAP)
            ) {
                throw IOException("Synthetic policy transport rejected the signed request header")
            }
            val signature = Base64.decode(requestEnvelope.get("signature").asString, Base64.NO_WRAP)
            if (!ClientWireCrypto.verify(device, canonicalUnsignedEnvelope(requestEnvelope), signature)) {
                throw IOException("Synthetic policy transport rejected the request signature")
            }

            val responseRouteJson = JsonObject().apply {
                addProperty("version", requestRouteJson.get("version").asLong)
                addProperty("direction", "RESPONSE")
                addProperty("hub_id", requestRouteJson.get("hub_id").asString)
                addProperty("owner_id", requestRouteJson.get("owner_id").asString)
                addProperty("device_id", requestRouteJson.get("device_id").asString)
                addProperty("session_epoch", requestRouteJson.get("session_epoch").asLong)
                // The fixture's stored lastResponseSequence is 9, so the next Hub response is 10.
                addProperty("sequence", RESPONSE_SEQUENCE)
                addProperty("operation_id", requestRouteJson.get("operation_id").asString)
                addProperty("operation", requestRouteJson.get("operation").asString)
                addProperty("sender_key_id", control.publicIdentity.id)
                addProperty("sender_key_version", requestRouteJson.get("receiver_key_version").asLong)
                addProperty("receiver_key_id", requestRouteJson.get("sender_key_id").asString)
                addProperty("receiver_key_version", requestRouteJson.get("sender_key_version").asLong)
            }
            val responseRouteText = ClientWireCrypto.Route.parse(responseRouteJson).toJson()
            val responseBody = JsonObject().apply {
                addProperty("request_id", "synthetic-v16-request-$role")
                addProperty("operation_id", operationId)
                addProperty("ok", true)
                add("result", JsonObject().apply {
                    addProperty("owner_id", SYNTHETIC_OWNER_ID)
                    addProperty("role", role)
                    addProperty("contract_revision", "client-hub-v1.6.1")
                    addProperty("catalog_sha256", CATALOG_SHA256)
                    add("available_rpc_operations", operations)
                })
            }
            val aad = (PACKET_DOMAIN + responseRouteText).toByteArray(StandardCharsets.UTF_8)
            val responseEnvelope = ClientWireCrypto.sealRawEnvelope(
                control,
                device,
                RESPONSE_SEQUENCE,
                aad,
                responseBody.toString().toByteArray(StandardCharsets.UTF_8),
            )
            val responsePacket = JsonObject().apply {
                add("route", JsonParser.parseString(responseRouteText))
                addProperty(
                    "envelope",
                    Base64.encodeToString(responseEnvelope.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP),
                )
            }
            return responsePacket.toString().toByteArray(StandardCharsets.UTF_8)
        }

        private fun canonicalUnsignedEnvelope(value: JsonObject): ByteArray {
            val output = StringWriter()
            val writer = JsonWriter(output)
            writer.setSerializeNulls(true)
            writer.beginObject()
                .name("version").value(value.get("version").asLong)
                .name("algorithm").value(value.get("algorithm").asString)
                .name("sequence").value(value.get("sequence").asLong)
                .name("kem_ciphertext").value(value.get("kem_ciphertext").asString)
                .name("nonce").value(value.get("nonce").asString)
                .name("ciphertext").value(value.get("ciphertext").asString)
                .name("sender_id").value(value.get("sender_id").asString)
                .name("sender_signing_public").value(value.get("sender_signing_public").asString)
                .name("signature").nullValue()
                .endObject()
            writer.close()
            return output.toString().toByteArray(StandardCharsets.UTF_8)
        }
    }

    /** Synthetic encrypted link.list/status endpoint used to exercise saved-scope recovery. */
    private class SyntheticLinkStatusResponder(
        private val control: ClientWireCrypto.Identity,
        private val device: ClientWireCrypto.PublicIdentity,
        private val linkVersion: Long = 4L,
        private val loseFirstStatusResponse: Boolean = false,
    ) : SyntheticResponder {
        val rpcOperations = mutableListOf<String>()
        var recoveryCount = 0
            private set
        var recoveredOriginalPacket: String? = null
            private set
        private var lostStatusPacket: String? = null
        private var cachedStatusResponse: String? = null
        private var didLoseStatusResponse = false

        override fun respond(url: URL, method: String, requestBytes: ByteArray): ByteArray {
            if (url.protocol != "https" || url.host != SYNTHETIC_HOST || url.port != SYNTHETIC_PORT ||
                url.path !in setOf(SYNTHETIC_RPC_PATH, SYNTHETIC_RPC_RECOVER_PATH) || url.query != null ||
                url.ref != null || url.userInfo != null || method != "POST" || requestBytes.isEmpty()) {
                throw IOException("Synthetic Link status transport rejected the request")
            }
            val packetText = String(requestBytes, StandardCharsets.UTF_8)
            val packet = JsonParser.parseString(packetText).asJsonObject
            val requestRouteJson = packet.getAsJsonObject("route")
            val requestRoute = ClientWireCrypto.Route.parse(requestRouteJson)
            if (requestRoute.toJson() != requestRouteJson.toString() || requestRoute.hubId != SYNTHETIC_HUB_ID ||
                requestRoute.ownerId != SYNTHETIC_OWNER_ID || requestRoute.deviceId != SYNTHETIC_DEVICE_ID ||
                requestRoute.sessionEpoch != 1L || requestRoute.operation !in setOf("link.list", "link.review_policy_status")) {
                throw IOException("Synthetic Link status transport rejected the encrypted route")
            }
            if (url.path == SYNTHETIC_RPC_RECOVER_PATH) {
                recoveryCount += 1
                if (recoveryCount != 1 || packetText != lostStatusPacket) {
                    throw IOException("Synthetic recovery did not receive the exact original status packet")
                }
                recoveredOriginalPacket = packetText
                return cachedStatusResponse?.toByteArray(StandardCharsets.UTF_8)
                    ?: throw IOException("Synthetic cached status response is missing")
            }

            val expectedOperation = when (rpcOperations.size) {
                0, 2 -> "link.list"
                1, 3 -> "link.review_policy_status"
                else -> throw IOException("Synthetic Link status transport received an unexpected RPC")
            }
            if (requestRoute.operation != expectedOperation || requestRoute.sequence != 11L + rpcOperations.size) {
                throw IOException("Synthetic Link status transport received an unexpected operation sequence")
            }
            rpcOperations += requestRoute.operation
            val result = if (requestRoute.operation == "link.list") linkListResult() else defaultStatusResult()
            val response = responsePacket(requestRouteJson, requestRoute.sequence - 1L, requestRoute.operationId, result)
            if (requestRoute.operation == "link.review_policy_status" && loseFirstStatusResponse && !didLoseStatusResponse) {
                didLoseStatusResponse = true
                lostStatusPacket = packetText
                cachedStatusResponse = response
                throw IOException("Synthetic lost Link status response")
            }
            return response.toByteArray(StandardCharsets.UTF_8)
        }

        private fun linkListResult(): JsonObject = JsonObject().apply {
            add("links", JsonArray().apply {
                add(JsonObject().apply {
                    add("link", JsonObject().apply {
                        addProperty("link_id", "synthetic-link")
                        addProperty("source_endpoint_id", "source-endpoint")
                        addProperty("source_group_id", "source-group")
                        addProperty("target_endpoint_id", "target-endpoint")
                        addProperty("target_group_id", "target-group")
                        addProperty("direction", "forward")
                        add("actions", JsonArray().apply { add("ask") })
                        add("data_scopes", JsonArray().apply { add("metadata") })
                        addProperty("expires_at", "2030-01-01T00:00:00Z")
                        addProperty("state", "ACCEPTED")
                        addProperty("version", linkVersion)
                    })
                    addProperty("my_side", "SOURCE")
                })
            })
            addProperty("cursor", "")
            addProperty("has_more", false)
        }

        private fun defaultStatusResult(): JsonObject = JsonObject().apply {
            addProperty("link_id", "synthetic-link")
            addProperty("link_version", linkVersion)
            addProperty("policy_version", 0)
            addProperty("policy_digest", "")
            add("policy", JsonObject().apply {
                addProperty("mode", "NONE")
                add("reviewers", JsonArray())
                addProperty("max_failovers", 0)
                addProperty("reviewer_lease_seconds", 0)
                addProperty("max_review_age_seconds", 0)
            })
            addProperty("current", true)
            add("accepted_sides", JsonArray())
        }

        private fun responsePacket(requestRouteJson: JsonObject, responseSequence: Long,
                                   operationId: String, result: JsonObject): String {
            val responseRouteJson = JsonObject().apply {
                addProperty("version", requestRouteJson.get("version").asLong)
                addProperty("direction", "RESPONSE")
                addProperty("hub_id", requestRouteJson.get("hub_id").asString)
                addProperty("owner_id", requestRouteJson.get("owner_id").asString)
                addProperty("device_id", requestRouteJson.get("device_id").asString)
                addProperty("session_epoch", requestRouteJson.get("session_epoch").asLong)
                addProperty("sequence", responseSequence)
                addProperty("operation_id", operationId)
                addProperty("operation", requestRouteJson.get("operation").asString)
                addProperty("sender_key_id", control.publicIdentity.id)
                addProperty("sender_key_version", requestRouteJson.get("receiver_key_version").asLong)
                addProperty("receiver_key_id", requestRouteJson.get("sender_key_id").asString)
                addProperty("receiver_key_version", requestRouteJson.get("sender_key_version").asLong)
            }
            val responseRouteText = ClientWireCrypto.Route.parse(responseRouteJson).toJson()
            val responseBody = JsonObject().apply {
                addProperty("request_id", "synthetic-link-status-$responseSequence")
                addProperty("operation_id", operationId)
                addProperty("ok", true)
                add("result", result)
            }
            val aad = (PACKET_DOMAIN + responseRouteText).toByteArray(StandardCharsets.UTF_8)
            val envelope = ClientWireCrypto.sealRawEnvelope(
                control, device, responseSequence, aad, responseBody.toString().toByteArray(StandardCharsets.UTF_8),
            )
            return JsonObject().apply {
                add("route", JsonParser.parseString(responseRouteText))
                addProperty("envelope", Base64.encodeToString(envelope.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP))
            }.toString()
        }
    }

    /**
     * This process-lifetime URL factory only serves the exact synthetic RPC route.
     * It has no socket/TLS fallback, and the active private-key responder is cleared after use.
     */
    private object SyntheticHttpsTransport {
        @Volatile private var active: SyntheticResponder? = null
        private var installed = false

        @Synchronized
        fun install(responder: SyntheticResponder) {
            if (active != null) throw IllegalStateException("A synthetic RPC responder is already active")
            if (!installed) {
                URL.setURLStreamHandlerFactory(object : URLStreamHandlerFactory {
                    override fun createURLStreamHandler(protocol: String): URLStreamHandler? {
                        if (protocol != "https") return null
                        return object : URLStreamHandler() {
                            override fun openConnection(url: URL): URLConnection {
                                if (url.host != SYNTHETIC_HOST || url.port != SYNTHETIC_PORT ||
                                    url.path !in setOf(SYNTHETIC_RPC_PATH, SYNTHETIC_RPC_RECOVER_PATH) || url.query != null ||
                                    url.ref != null || url.userInfo != null
                                ) {
                                    throw IOException("Synthetic policy transport rejected the HTTPS target")
                                }
                                return SyntheticHttpsConnection(url)
                            }
                        }
                    }
                })
                installed = true
            }
            active = responder
        }

        @Synchronized
        fun clear(responder: SyntheticResponder) {
            if (active !== responder) throw IllegalStateException("Synthetic RPC responder ownership changed")
            active = null
        }

        fun exchange(url: URL, method: String, requestBytes: ByteArray): ByteArray {
            val responder = active ?: throw IOException("No synthetic HTTPS responder is active")
            return responder.respond(url, method, requestBytes)
        }
    }

    private class SyntheticHttpsConnection(url: URL) : HttpURLConnection(url) {
        private val requestBytes = ByteArrayOutputStream()
        private var responseBytes: ByteArray? = null

        override fun connect() {
            connected = true
        }

        override fun disconnect() {
            connected = false
        }

        override fun usingProxy(): Boolean = false

        override fun getOutputStream(): java.io.OutputStream {
            if (requestMethod != "POST") throw IOException("Synthetic policy transport rejects non-POST requests")
            connect()
            return requestBytes
        }

        override fun getResponseCode(): Int {
            if (responseBytes == null) {
                val request = requestBytes.toByteArray()
                requestBytes.reset()
                responseBytes = SyntheticHttpsTransport.exchange(url, requestMethod, request)
            }
            return HTTP_OK
        }

        override fun getInputStream(): java.io.InputStream {
            getResponseCode()
            val bytes = responseBytes
            if (bytes == null) throw IOException("Synthetic policy response was not created")
            return ByteArrayInputStream(bytes)
        }
    }

    private fun advertisement(): JsonArray = JsonArray().apply {
        (IMPLEMENTED_SAMPLE + NEW_CONSENT_OPERATIONS + listOf("link.key_manifest", "link.key_grant",
            "link.key_grants", UNKNOWN_OPERATION)).forEach(::add)
    }

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
        val root = File(target.cacheDir, "v16-operation-policy-${UUID.randomUUID()}").apply { check(mkdirs()) }
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
            addProperty("validatedContractRevision", "client-hub-v1.6.1")
            addProperty("validatedCatalogSha256", CATALOG_SHA256)
            add("allowedOperations", advertisement())
            add("pin", JsonObject().apply {
                addProperty("baseUrl", "https://127.0.0.1:1")
                addProperty("hubId", SYNTHETIC_HUB_ID)
                addProperty("controlPublicIdentityJson", fixture.getAsJsonObject("receiver_public_identity").toString())
            })
            add("enrollment", JsonObject().apply {
                addProperty("ownerId", SYNTHETIC_OWNER_ID)
                addProperty("deviceId", SYNTHETIC_DEVICE_ID)
                addProperty("sessionEpoch", 1)
                addProperty("deviceKeyVersion", 1)
                addProperty("state", "ACTIVE")
            })
        }
        val devicePublicIdentity = if (prepared) {
            session.createDeviceIdentity().getAsJsonObject("devicePublicIdentity")
        } else null
        val box = Sandbox(
            session,
            File(directory, "session-state.json"),
            File(directory, "device-key.wrap.json"),
            initial,
            devicePublicIdentity,
        )
        try {
            if (prepared) box.stateFile.writeText(initial.toString())
            action(box)
        } finally {
            box.stateFile.writeText("{}")
            session.deleteProfileState()
            root.deleteRecursively()
        }
    }

    companion object {
        private const val UNKNOWN_OPERATION = "future.unverified_consent"
        private const val SYNTHETIC_HUB_ID = "synthetic-v16-policy-hub"
        private const val SYNTHETIC_OWNER_ID = "synthetic-v16-policy-owner"
        private const val SYNTHETIC_DEVICE_ID = "synthetic-v16-policy-device"
        private const val SYNTHETIC_HOST = "127.0.0.1"
        private const val SYNTHETIC_PORT = 1
        private const val SYNTHETIC_RPC_PATH = "/v2/client/rpc"
        private const val SYNTHETIC_RPC_RECOVER_PATH = "/v2/client/rpc/recover"
        private const val PACKET_DOMAIN = "cicada/client-control/packet/v1\u0000"
        private const val CATALOG_SHA256 = "6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b"
        private const val REQUEST_SEQUENCE = 11L
        private const val RESPONSE_SEQUENCE = 10L
        private val IMPLEMENTED_SAMPLE = listOf("session.capabilities", "status.snapshot", "link.list", "group.key_manifest",
            "network.key_manifest", "monitor.broadcast_recover", "network.directory",
            "topology.endpoint_admission_preview", "topology.regroup_proposal",
            "topology.delegation_issue", "topology.delegation_revoke", "link.review_policy_status")
        // Exact v1.5/v1.6.1 deferred consent and proof routes, independent of the implementation set.
        private val NEW_CONSENT_OPERATIONS = listOf(
            "space.foreign_member_admit", "space.foreign_member_revoke", "space.foreign_endpoint_join",
            "space.key_manifest_v2", "space.key_consent_v2", "space.key_admission_v2", "space.key_status_v2",
            "space.foreign_endpoint_preview", "network.collaboration_key_manifest",
            "network.collaboration_key_grant", "network.collaboration_key_status",
            "link.review_policy_preview", "link.review_policy_grant",
        )
    }
}
