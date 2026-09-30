package ai.cicada.client.hub

import android.content.Context
import android.content.ContextWrapper
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonNull
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

/** Local guard tests with public synthetic identities; no Hub or external signer is started. */
@RunWith(AndroidJUnit4::class)
class NetworkSessionGuardTest {
    private data class Sandbox(
        val context: Context,
        val session: ClientHubSession,
        val stateFile: File,
        val wrappedKeyFile: File,
        val initialState: JsonObject,
        val ownerKeyId: String,
    )

    @Test
    fun genericNetworkKeyRpcCannotBypassVerificationBeforeAnyPinOrDeviceKey() = sandbox(false) { box ->
        val stateExists = box.stateFile.exists()
        val keyExists = box.wrappedKeyFile.exists()
        for (operation in listOf("network.key_manifest", "network.key_grant", "network.key_status")) {
            expectCode("VERIFIED_NETWORK_FLOW_REQUIRED") {
                box.session.rpc(operation, JsonObject().apply {
                    addProperty("network_id", NETWORK)
                    addProperty("endpoint_id", ENDPOINT)
                })
            }
        }
        assertFalse(stateExists)
        assertFalse(keyExists)
        assertFalse(box.stateFile.exists())
        assertFalse(box.wrappedKeyFile.exists())
        assertFalse(box.session.getStatus().has("nextSequence"))
    }

    @Test
    fun missingOrDifferentNetworkSelectionRefusesAllDedicatedCallsWithoutWrites() = sandbox { box ->
        val missing = box.initialState.deepCopy().apply { remove("activeNetworkId") }
        save(box, missing)
        assertRefusedUnchanged(box, "NETWORK_SELECTION_REQUIRED") { allDedicatedCalls(box) }
        save(box, box.initialState.deepCopy().apply { addProperty("activeNetworkId", "other-network") })
        assertRefusedUnchanged(box, "NETWORK_SELECTION_REQUIRED") { allDedicatedCalls(box) }
    }

    @Test
    fun missingOrDifferentOwnerTrustKeyRefusesConsentBeforeMetadataOrRpc() = sandbox { box ->
        save(box, box.initialState.deepCopy().apply { remove("ownerApprovalPublicIdentityJson") })
        assertRefusedUnchanged(box, "OWNER_PUBLIC_KEY_REQUIRED") { allDedicatedCalls(box) }
        save(box, box.initialState)
        assertRefusedUnchanged(box, "OWNER_KEY_ID_MISMATCH") { ownerKey ->
            consentCalls(box, "$ownerKey-wrong")
        }
    }

    @Test
    fun missingCurrentEncryptedCapabilitiesAndHistoricalCatalogCannotAuthorizeConsent() = sandbox { box ->
        save(box, box.initialState.deepCopy().apply { addProperty("sessionCapabilitiesReady", false) })
        assertRefusedUnchanged(box, "SESSION_CAPABILITIES_REQUIRED") { allDedicatedCalls(box) }
        save(box, box.initialState.deepCopy().apply {
            addProperty("validatedContractRevision", "client-hub-v1.3")
            addProperty("validatedCatalogSha256", "808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377")
        })
        assertRefusedUnchanged(box, "SESSION_CAPABILITIES_REQUIRED") { allDedicatedCalls(box) }
        save(box, box.initialState.deepCopy().apply { addProperty("role", "self-asserted-admin") })
        assertRefusedUnchanged(box, "SESSION_CAPABILITIES_REQUIRED") { allDedicatedCalls(box) }
    }

    @Test
    fun encryptedOperationAllowlistRefusesGrantForBothAuthenticatedOwnerRoles() = sandbox { box ->
        for (role in listOf("manager", "external")) {
            save(box, box.initialState.deepCopy().apply {
                addProperty("role", role)
                add("allowedOperations", JsonArray().apply {
                    add("session.capabilities")
                    add("topology.snapshot")
                    add("network.key_manifest")
                })
            })
            assertRefusedUnchanged(box, "RPC_OPERATION_NOT_AUTHORIZED") { ownerKey ->
                listOf { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) }
            }
        }
    }

    @Test
    fun originalPendingCiphertextBlocksNetworkFlowWithoutReplacingItsIdsOrCounters() = sandbox { box ->
        save(box, box.initialState.deepCopy().apply {
            add("pending", JsonObject().apply {
                addProperty("operation", "network.key_grant")
                addProperty("operationId", "original-network-operation")
                addProperty("sequence", 11)
                addProperty("expectedResponseSequence", 4)
                addProperty("packetJson", "EXACT_SYNTHETIC_ORIGINAL_SIGNED_CIPHERTEXT")
            })
        })
        assertRefusedUnchanged(box, "PENDING_RECOVERY_REQUIRED") { allDedicatedCalls(box) }
        val status = box.session.getStatus()
        assertEquals("original-network-operation", status.get("pendingOperationId").asString)
        assertEquals(12L, status.get("nextSequence").asLong)
    }

    @Test
    fun uncertainBusinessOutcomeRefusesNewNetworkGrantBeforeMetadataOrResequencing() = sandbox { box ->
        save(box, box.initialState.deepCopy().apply {
            addProperty("uncertainNeedsReconciliation", true)
            addProperty("outcomeUncertainOperationId", "original-uncertain-network-operation")
        })
        assertRefusedUnchanged(box, "BUSINESS_RECONCILIATION_REQUIRED") { ownerKey ->
            listOf { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) }
        }
        val status = box.session.getStatus()
        assertEquals("original-uncertain-network-operation", status.get("outcomeUncertainOperationId").asString)
        assertEquals(12L, status.get("nextSequence").asLong)

        // This is a local synthetic protocol regression, not real Hub fault acceptance.
        save(box, box.initialState)
        ClientWireCrypto.Identity.generate().use { control ->
            val original = acceptSyntheticResponse(box, control, "network.key_grant", "synthetic-first-grant", true)
            assertEquals(original, readStoredState(box).getAsJsonObject("networkGrantUncertainPending"))
            acceptSyntheticResponse(box, control, "status.snapshot", "synthetic-general-snapshot", false)
            assertFalse(readStoredState(box).get("uncertainNeedsReconciliation").asBoolean)
            assertRefusedUnchanged(box, "NETWORK_GRANT_RECONCILIATION_REQUIRED") { ownerKey ->
                listOf { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) }
            }

            acceptSyntheticResponse(box, control, "network.key_status", "synthetic-uncertain-read", true)
            assertEquals("synthetic-uncertain-read", readStoredState(box).getAsJsonObject("retiredPending")
                .get("operationId").asString)
            acceptSyntheticResponse(box, control, "status.snapshot", "synthetic-second-snapshot", false)
            assertEquals(original, readStoredState(box).getAsJsonObject("networkGrantUncertainPending"))
            val restarted = ClientHubSession(box.context, box.session.profileId)
            val restartedStatus = restarted.getStatus()
            assertTrue(restartedStatus.get("networkGrantReconciliationRequired").asBoolean)
            assertEquals("synthetic-first-grant", restartedStatus.get("networkGrantUncertainOperationId").asString)
            assertFalse(restartedStatus.toString().contains(original.get("packetJson").asString))
            assertFalse(restartedStatus.toString().contains("packetJson"))
            assertRefusedUnchanged(box, "NETWORK_GRANT_RECONCILIATION_REQUIRED") { ownerKey ->
                listOf(
                    { restarted.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) },
                    { restarted.startNewDeviceEnrollment() },
                    { restarted.recoverEnrollment() },
                    { restarted.enroll("owner", ownerKey, "{}", "device", PUBLIC_OPAQUE_PROOF) },
                    { restarted.pinHub("https://127.0.0.1:2", "synthetic-network-guard-hub", control.publicIdentity.toJson()) },
                    { restarted.deleteProfileState() },
                )
            }

            // A surviving legacy retired grant is conservatively fenced, including AUTH_RESET.
            save(box, readStoredState(box).apply {
                remove("networkGrantUncertainPending")
                add("retiredPending", original.deepCopy())
                addProperty("sessionError", "AUTH_RESET")
                addProperty("uncertainNeedsReconciliation", false)
            })
            assertRefusedUnchanged(box, "NETWORK_GRANT_RECONCILIATION_REQUIRED") { ownerKey ->
                listOf { restarted.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) }
            }
            acceptSyntheticResponse(box, control, "status.snapshot", "synthetic-migration-snapshot", false)
            assertEquals(original, readStoredState(box).getAsJsonObject("networkGrantUncertainPending"))

            // Missing/null fields in old state carry no fence; a malformed non-null fence is refused.
            for (explicitNull in listOf(false, true)) {
                save(box, box.initialState.deepCopy().apply {
                    if (explicitNull) add("networkGrantUncertainPending", JsonNull.INSTANCE)
                })
                assertFalse(restarted.getStatus().get("networkGrantReconciliationRequired").asBoolean)
                acceptSyntheticResponse(box, control, "status.snapshot", "synthetic-no-fence-$explicitNull", false)
                assertFalse(restarted.getStatus().get("networkGrantReconciliationRequired").asBoolean)
            }
            save(box, box.initialState.deepCopy().apply { add("networkGrantUncertainPending", JsonObject()) })
            assertRefusedUnchanged(box, "SESSION_STORAGE_INVALID") { ownerKey ->
                listOf(
                    { restarted.getStatus() },
                    { restarted.startNewDeviceEnrollment() },
                    { restarted.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) },
                )
            }
        }
    }

    @Test
    fun malformedReviewedDigestAndUnboundedProofRefuseBeforeAnyFreshManifestRead() = sandbox { box ->
        assertRefusedUnchanged(box, "NETWORK_CONSENT_MISMATCH") { ownerKey ->
            listOf { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, "unreviewed", PUBLIC_OPAQUE_PROOF) }
        }
        assertRefusedUnchanged(box, "NETWORK_OWNER_PROOF_INVALID") { ownerKey ->
            listOf(
                { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, "invalid-base64") },
                { box.session.previewNetworkKeyGrant(NETWORK, ENDPOINT, ownerKey, DIGEST, "A".repeat(43_696)) },
            )
        }
    }

    private fun allDedicatedCalls(box: Sandbox): List<() -> Unit> = consentCalls(box, box.ownerKeyId) +
        listOf { box.session.networkKeyStatus(NETWORK, ENDPOINT) }

    private fun consentCalls(box: Sandbox, ownerKey: String): List<() -> Unit> = listOf(
        { box.session.previewNetworkKey(NETWORK, ENDPOINT, ownerKey) },
        { box.session.previewNetworkKeyGrant(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) },
        { box.session.grantNetworkKey(NETWORK, ENDPOINT, ownerKey, DIGEST, PUBLIC_OPAQUE_PROOF) },
    )

    private fun assertRefusedUnchanged(box: Sandbox, expected: String,
                                      calls: (String) -> List<() -> Unit>) {
        val stateBytes = box.stateFile.readBytes()
        val keyBytes = box.wrappedKeyFile.readBytes()
        calls(box.ownerKeyId).forEach { action ->
            expectCode(expected, action)
            assertArrayEquals(stateBytes, box.stateFile.readBytes())
            assertArrayEquals(keyBytes, box.wrappedKeyFile.readBytes())
        }
    }

    private fun save(box: Sandbox, state: JsonObject) { box.stateFile.writeText(state.toString()) }

    private fun readStoredState(box: Sandbox): JsonObject = JsonParser.parseString(box.stateFile.readText()).asJsonObject

    /** Feed authenticated synthetic packets into the production response path, without HTTP. */
    private fun acceptSyntheticResponse(box: Sandbox, control: ClientWireCrypto.Identity,
                                        operation: String, operationId: String, uncertain: Boolean): JsonObject {
        val state = readStoredState(box)
        val device = invokePrivate(box.session, "loadDeviceIdentity") as ClientWireCrypto.Identity
        device.use {
            val request = ClientWireCrypto.Route().apply {
                direction = "REQUEST"
                hubId = state.getAsJsonObject("pin").get("hubId").asString
                ownerId = state.getAsJsonObject("enrollment").get("ownerId").asString
                deviceId = state.getAsJsonObject("enrollment").get("deviceId").asString
                sessionEpoch = 1
                sequence = state.get("nextSequence").asLong
                this.operation = operation
                this.operationId = operationId
                senderKeyId = device.publicIdentity.id
                senderKeyVersion = 1
                receiverKeyId = control.publicIdentity.id
                receiverKeyVersion = 1
            }
            val responseSequence = state.get("lastResponseSequence").asLong + 1
            val pending = JsonObject().apply {
                addProperty("operation", operation)
                addProperty("operationId", operationId)
                addProperty("sequence", request.sequence)
                addProperty("expectedResponseSequence", responseSequence)
                addProperty("packetJson", ClientWireCrypto.sealRequest(device, control.publicIdentity, request, "{}"))
            }
            state.add("pending", pending)
            state.addProperty("nextSequence", request.sequence + 1)
            state.getAsJsonObject("pin").addProperty("controlPublicIdentityJson", control.publicIdentity.toJson())
            save(box, state)
            val response = ClientWireCrypto.Route.parse(JsonParser.parseString(request.toJson()).asJsonObject).apply {
                direction = "RESPONSE"
                sequence = responseSequence
                senderKeyId = control.publicIdentity.id
                receiverKeyId = device.publicIdentity.id
            }
            val body = JsonObject().apply {
                addProperty("request_id", "synthetic-request-$operationId")
                addProperty("operation_id", operationId)
                addProperty("ok", !uncertain)
                if (uncertain) {
                    addProperty("error_code", "OUTCOME_UNCERTAIN")
                    addProperty("error", "Synthetic in-process response")
                    add("recovery", JsonObject().apply {
                        addProperty("state", "UNCERTAIN")
                        addProperty("request_sequence", request.sequence)
                    })
                } else add("result", JsonObject().apply { addProperty("synthetic_only", true) })
            }
            val aad = ("cicada/client-control/packet/v1\u0000" + response.toJson()).toByteArray(StandardCharsets.UTF_8)
            val envelope = ClientWireCrypto.sealRawEnvelope(control, device.publicIdentity, responseSequence,
                aad, body.toString().toByteArray(StandardCharsets.UTF_8))
            val packet = JsonObject().apply {
                add("route", JsonParser.parseString(response.toJson()))
                addProperty("envelope", Base64.encodeToString(envelope.toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP))
            }
            invokePrivate(box.session, "finishResponse", invokePrivate(box.session, "readState"), device,
                control.publicIdentity, request, packet.toString(), true)
            return pending.deepCopy()
        }
    }

    private fun invokePrivate(session: ClientHubSession, name: String, vararg args: Any?): Any? = try {
        ClientHubSession::class.java.declaredMethods.single { it.name == name }.apply { isAccessible = true }
            .invoke(session, *args)
    } catch (error: InvocationTargetException) { throw error.targetException }

    private fun sandbox(prepared: Boolean = true, action: (Sandbox) -> Unit) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(target.cacheDir, "network-session-guards-${UUID.randomUUID()}").apply { check(mkdirs()) }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getNoBackupFilesDir(): File = root
        }
        val profileId = UUID.randomUUID().toString()
        val session = ClientHubSession(context, profileId)
        val directory = ClientHubSession.profileDirectory(context, profileId)
        val fixture = InstrumentationRegistry.getInstrumentation().context.assets
            .open("network-direct-key-consent-v1.json").use { JsonParser.parseString(it.reader().readText()).asJsonObject }
        val owner = fixture.getAsJsonObject("owner_public_identity")
        val initial = JsonObject().apply {
            addProperty("activeNetworkId", NETWORK)
            addProperty("ownerApprovalPublicIdentityJson", owner.toString())
            addProperty("nextSequence", 12)
            addProperty("lastResponseSequence", 3)
            addProperty("role", "manager")
            addProperty("sessionCapabilitiesReady", true)
            addProperty("validatedContractRevision", "client-hub-v1.5")
            addProperty("validatedCatalogSha256", "a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68")
            add("allowedOperations", JsonArray().apply {
                listOf("session.capabilities", "topology.snapshot", "network.key_manifest",
                    "network.key_grant", "network.key_status").forEach(::add)
            })
            add("pin", JsonObject().apply {
                addProperty("baseUrl", "https://127.0.0.1:1")
                addProperty("hubId", "synthetic-network-guard-hub")
                addProperty("controlPublicIdentityJson", fixture.getAsJsonObject("receiver_public_identity").toString())
            })
            add("enrollment", JsonObject().apply {
                addProperty("ownerId", "synthetic-network-guard-owner")
                addProperty("deviceId", "synthetic-network-guard-device")
                addProperty("sessionEpoch", 1)
                addProperty("deviceKeyVersion", 1)
                addProperty("state", "ACTIVE")
            })
        }
        val box = Sandbox(context, session, File(directory, "session-state.json"),
            File(directory, "device-key.wrap.json"), initial, owner.get("id").asString)
        try {
            if (prepared) { session.createDeviceIdentity(); save(box, initial) }
            action(box)
        } finally {
            box.stateFile.writeText("{}")
            session.deleteProfileState()
            root.deleteRecursively()
        }
    }

    private fun expectCode(expected: String, action: () -> Unit) {
        try { action(); fail("Expected $expected") }
        catch (error: HubSessionException) { assertEquals(expected, error.errorCode) }
    }

    companion object {
        private const val NETWORK = "synthetic-selected-network"
        private const val ENDPOINT = "synthetic-selected-endpoint"
        private val DIGEST = "a".repeat(64)
        // Public opaque bytes exercise local authorization guards, not proof acceptance.
        private val PUBLIC_OPAQUE_PROOF = Base64.encodeToString("{}".toByteArray(), Base64.NO_WRAP)
    }
}
