package ai.cicada.client

import ai.cicada.client.hub.ClientHubSession
import ai.cicada.client.hub.HubSessionException
import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

/** Against the separately running Docker Hub, using the APK's actual Kotlin session code. */
@RunWith(AndroidJUnit4::class)
class ClientHubInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val session get() = ClientHubSession(instrumentation.targetContext)
    private val arguments get() = InstrumentationRegistry.getArguments()

    private fun argument(name: String): String = arguments.getString(name)
        ?: error("Instrumentation argument $name is required")

    private fun decoded(name: String): String = String(
        Base64.decode(argument(name), Base64.NO_WRAP), StandardCharsets.UTF_8,
    )

    private fun publish(name: String, value: String) {
        instrumentation.sendStatus(0, Bundle().apply { putString(name, value) })
    }

    @Test fun linkProposalReadAndUnauthorizedSourceAreEncryptedBusinessResults() {
        val before = session.getStatus()
        assertTrue("Enrolled manager session is required", before.get("remoteEnabled").asBoolean)
        val capabilities = session.rpc("session.capabilities", JsonObject())
        assertTrue(capabilities.get("ok").asBoolean)
        val operations = capabilities.getAsJsonObject("result")
            .getAsJsonArray("available_rpc_operations").map { it.asString }
        assertTrue(operations.contains("link.list"))
        assertTrue(operations.contains("link.invite_create"))
        val listed = session.rpc("link.list", JsonObject().apply { addProperty("limit", 50) })
        assertTrue(listed.get("ok").asBoolean)
        assertTrue(listed.getAsJsonObject("result").get("links").isJsonArray)
        val badPreview = session.rpc("link.invite_preview", JsonObject().apply {
            addProperty("token", "invalid-test-token")
        })
        assertFalse("Invalid bearer must be rejected inside the encrypted result",
            badPreview.get("ok").asBoolean)
        val badSource = session.rpc("link.invite_create", JsonObject().apply {
            addProperty("source_endpoint_id", "ep_not_owned_by_android_test")
            addProperty("source_group_id", "gr_not_owned_by_android_test")
            addProperty("hub_id", before.get("hubId").asString)
            add("actions", JsonParser.parseString("[\"ask\",\"reply\"]"))
            add("data_scopes", JsonParser.parseString("[\"benchmark.public_result\"]"))
            addProperty("expires_at", java.time.Instant.now().plusSeconds(1800).toString())
        })
        assertFalse("A non-owned source must not create an invitation",
            badSource.get("ok").asBoolean)
    }

    @Test fun currentV13ExternalReadsUseEncryptedCapabilitiesAndGuardKeyRpc() {
        val before = session.getStatus()
        assertTrue(before.get("remoteEnabled").asBoolean)
        val cap = session.rpc("session.capabilities", JsonObject())
        assertTrue(cap.get("ok").asBoolean)
        val result = cap.getAsJsonObject("result")
        assertEquals("external", result.get("role").asString)
        assertEquals("client-hub-v1.3", result.get("contract_revision").asString)
        assertEquals("808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377",
            result.get("catalog_sha256").asString)

        val allowed = session.getStatus().getAsJsonArray("allowedOperations").map { it.asString }
        assertTrue(allowed.contains("status.snapshot"))
        assertTrue(allowed.contains("status.changes"))
        for (operation in listOf("link.key_manifest", "link.key_grants", "link.key_grant")) {
            assertFalse("Unverified key operation is not callable: $operation", allowed.contains(operation))
            try {
                session.rpc(operation, JsonObject())
                fail("Unverified key operation reached the Hub: $operation")
            } catch (error: HubSessionException) {
                assertEquals("UNSUPPORTED_RPC_OPERATION", error.errorCode)
            }
        }
        assertTrue(allowed.contains("group.key_manifest"))
        assertTrue(allowed.contains("group.key_grant"))
        assertTrue(allowed.contains("group.key_status"))
        for (operation in listOf("group.key_manifest", "group.key_grant", "group.key_status")) {
            try {
                session.rpc(operation, JsonObject())
                fail("Raw Group key operation bypassed the verified flow: $operation")
            } catch (error: HubSessionException) {
                assertEquals("VERIFIED_GROUP_FLOW_REQUIRED", error.errorCode)
            }
        }

        val snapshot = session.rpc("status.snapshot", JsonObject())
        assertTrue(snapshot.get("ok").asBoolean)
        assertEquals("owner_attributed_v2", snapshot.getAsJsonObject("result")
            .get("scope_mode").asString)
        val changes = session.rpc("status.changes", JsonObject().apply {
            addProperty("limit", 50)
        })
        assertTrue(changes.get("ok").asBoolean)
        assertEquals("partial", changes.getAsJsonObject("result")
            .get("completeness").asString)
        assertFalse(session.getStatus().has("pendingOperationId"))
    }

    @Test fun realHubReplayConflictFreezesAnIsolatedAndroidSession() {
        val target = instrumentation.targetContext
        val liveDir = File(target.noBackupFilesDir, "client-hub")
        val liveState = JsonParser.parseString(
            File(liveDir, "session-state.json").readText(StandardCharsets.UTF_8),
        ).asJsonObject
        val replaySequence = liveState.get("lastResponseSequence").asLong
        assertTrue("A prior authenticated RPC is required", replaySequence > 0)
        assertFalse("Do not clone an unresolved live RPC", liveState.has("pending"))
        assertTrue(liveState.get("sessionCapabilitiesReady").asBoolean)

        // Clone only encrypted Android private storage into an isolated test context.
        // Reusing an older sequence with a newly sealed packet must hit the real
        // Hub replay guard; the enrolled app's own counters remain untouched.
        val root = File(target.cacheDir, "client-hub-replay-${UUID.randomUUID()}")
        val cloneDir = File(root, "client-hub")
        assertTrue(cloneDir.mkdirs())
        try {
            liveState.addProperty("nextSequence", replaySequence)
            File(cloneDir, "session-state.json").writeText(
                liveState.toString(), StandardCharsets.UTF_8,
            )
            File(liveDir, "device-key.wrap.json").copyTo(
                File(cloneDir, "device-key.wrap.json"),
            )
            val context = object : ContextWrapper(target) {
                override fun getApplicationContext(): Context = this
                override fun getNoBackupFilesDir(): File = root
            }
            val isolated = ClientHubSession(context)
            try {
                isolated.rpc("status.snapshot", JsonObject(), "android-replay-${UUID.randomUUID()}")
                fail("Real Hub accepted a new ciphertext using an old sequence")
            } catch (error: HubSessionException) {
                assertEquals("HTTP_409", error.errorCode)
            }
            val blocked = isolated.getStatus()
            assertTrue(blocked.get("recoveryBlocked").asBoolean)
            assertFalse(blocked.get("remoteEnabled").asBoolean)
            assertEquals(replaySequence + 1, blocked.get("nextSequence").asLong)
            val pendingId = blocked.get("pendingOperationId").asString
            val packet = JsonParser.parseString(File(cloneDir, "session-state.json")
                .readText(StandardCharsets.UTF_8)).asJsonObject
                .getAsJsonObject("pending").get("packetJson").asString

            val restored = ClientHubSession(context)
            assertEquals(pendingId, restored.getStatus().get("pendingOperationId").asString)
            for ((expected, action) in listOf<Pair<String, () -> Unit>>(
                "HTTP_409_RECOVERY_REJECTED" to { restored.recoverPending() },
                "PENDING_RECOVERY_REQUIRED" to {
                    restored.rpc("status.snapshot", JsonObject())
                },
            )) {
                try {
                    action()
                    fail("Blocked operation unexpectedly proceeded")
                } catch (error: HubSessionException) {
                    assertEquals(expected, error.errorCode)
                }
            }
            val after = JsonParser.parseString(File(cloneDir, "session-state.json")
                .readText(StandardCharsets.UTF_8)).asJsonObject
            assertEquals(packet, after.getAsJsonObject("pending").get("packetJson").asString)
            assertEquals(replaySequence + 1, after.get("nextSequence").asLong)
            assertFalse(session.getStatus().has("pendingOperationId"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun managerReadAndRejectionMatrixAgainstDockerHub() {
        val before = session.getStatus()
        assertTrue("Enrolled manager session is required", before.get("remoteEnabled").asBoolean)
        val caps = session.rpc("session.capabilities", JsonObject())
        assertTrue(caps.get("ok").asBoolean)
        assertEquals("manager", caps.getAsJsonObject("result").get("role").asString)

        val snapshot = session.rpc("status.snapshot", JsonObject())
        assertTrue(snapshot.get("ok").asBoolean)
        assertEquals("single_owner_control_database",
            snapshot.getAsJsonObject("result").get("scope_mode").asString)
        val changes = session.rpc("status.changes", JsonObject().apply {
            addProperty("limit", 50)
        })
        assertTrue(changes.get("ok").asBoolean)
        assertEquals("partial", changes.getAsJsonObject("result")
            .get("completeness").asString)
        assertTrue(session.rpc("topology.snapshot", JsonObject())
            .getAsJsonObject("result").get("groups").isJsonArray)
        assertTrue(session.rpc("nodes.list", JsonObject())
            .get("result").isJsonArray)
        assertTrue(session.rpc("approvals.list", JsonObject().apply {
            addProperty("pending_only", true)
        }).get("result").isJsonArray)
        assertTrue(session.rpc("devices.list", JsonObject())
            .get("result").isJsonArray)
        assertTrue(session.rpc("intent.list", JsonObject())
            .get("result").isJsonArray)

        fun rejected(operation: String, body: JsonObject) {
            val response = session.rpc(operation, body)
            assertFalse("$operation must be rejected as a decrypted business result",
                response.get("ok").asBoolean)
            assertTrue("The rejection must retain a readable reason", response.has("error"))
        }
        rejected("nodes.preview", JsonObject().apply {
            addProperty("user_code", "INVALID-CODE")
        })
        rejected("approvals.decide", JsonObject().apply {
            addProperty("approval_id", "missing-approval-android-matrix")
            addProperty("decision", "accept")
        })
        rejected("topology.apply", JsonObject().apply {
            addProperty("kind", "group.set_parent")
            add("set_parent", JsonObject().apply {
                addProperty("group_id", "gr_missing_android_matrix")
                addProperty("expected_group_version", 1)
            })
        })
        rejected("intent.get", JsonObject().apply {
            addProperty("intent_id", "missing-intent-android-matrix")
        })
        for (operation in listOf("link.key_manifest", "link.key_grants", "link.key_grant")) {
            try {
                session.rpc(operation, JsonObject())
                fail("Unverified key operation must remain disabled: $operation")
            } catch (error: HubSessionException) {
                assertEquals("UNSUPPORTED_RPC_OPERATION", error.errorCode)
            }
        }
        try {
            session.rpc("group.key_grant", JsonObject())
            fail("Raw Group key grant bypassed owner proof verification")
        } catch (error: HubSessionException) {
            assertEquals("VERIFIED_GROUP_FLOW_REQUIRED", error.errorCode)
        }
        rejected("link.invite_accept", JsonObject().apply {
            addProperty("token", "invalid-test-token")
            addProperty("target_endpoint_id", "ep_missing_android_matrix")
            addProperty("target_group_id", "gr_missing_android_matrix")
        })
    }

    @Test fun insecureTransportAndUnknownRpcAreRejectedBeforeNetwork() {
        val before = session.getStatus()
        assertTrue(before.get("remoteEnabled").asBoolean)
        listOf("http://example.com", "http://10.0.2.2:8791").forEach { url ->
            try {
                session.fetchHubMetadata(url)
                fail("Debug build accepted an unapproved HTTP Hub URL")
            } catch (error: HubSessionException) {
                assertEquals("INSECURE_HUB_URL", error.errorCode)
            }
        }
        try {
            session.rpc("legacy.status", JsonObject())
            fail("Client sent an RPC outside the encrypted v2 contract")
        } catch (error: HubSessionException) {
            assertEquals("UNSUPPORTED_RPC_OPERATION", error.errorCode)
        }
        val after = session.getStatus()
        assertEquals(before.get("hubId"), after.get("hubId"))
        assertEquals(before.get("deviceId"), after.get("deviceId"))
        assertEquals(before.get("nextSequence"), after.get("nextSequence"))
        assertFalse(after.has("pendingOperationId"))
    }

    @Test fun prepareDevice() {
        val result = session.createDeviceIdentity()
        val publicIdentity = result.getAsJsonObject("devicePublicIdentity")
        assertTrue(publicIdentity.get("id").asString.startsWith("pq1-"))
        publish("device_public_identity_base64", Base64.encodeToString(
            publicIdentity.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP,
        ))
    }

    @Test fun enrollAndRead() {
        val trustedHub = JsonParser.parseString(decoded("trusted_hub_identity_base64")).asJsonObject
        val ownerPublic = decoded("owner_public_identity_base64")
        val baseUrl = arguments.getString("hub_base_url") ?: "http://10.0.2.2:8787"
        val expectedRole = arguments.getString("expected_role") ?: "manager"
        val expectedScopeMode = arguments.getString("expected_scope_mode") ?: "single_owner_control_database"
        val pin = session.pinHub(
            baseUrl,
            trustedHub.get("hub_id").asString,
            trustedHub.getAsJsonObject("control_public_identity").toString(),
        )
        assertTrue(pin.get("pinned").asBoolean)
        val enrolled = session.enroll(
            argument("owner_id"),
            argument("owner_key_id"),
            ownerPublic,
            argument("device_id"),
            argument("owner_device_grant_base64"),
        )
        assertEquals("ACTIVE", enrolled.get("state").asString)
        val cap = session.rpc("session.capabilities", JsonObject(), "android-capabilities-1")
        assertTrue(cap.get("ok").asBoolean)
        assertEquals(expectedRole, cap.getAsJsonObject("result").get("role").asString)
        assertEquals("client-hub-v1.3", cap.getAsJsonObject("result").get("contract_revision").asString)
        assertEquals("808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377",
            cap.getAsJsonObject("result").get("catalog_sha256").asString)
        val snapshot = session.rpc("status.snapshot", JsonObject(), "android-snapshot-2")
        assertTrue(snapshot.get("ok").asBoolean)
        assertEquals(expectedScopeMode,
            snapshot.getAsJsonObject("result").get("scope_mode").asString)
        val changes = session.rpc("status.changes", JsonObject().apply { addProperty("limit", 100) },
            "android-changes-3")
        assertTrue(changes.get("ok").asBoolean)
        assertEquals("partial", changes.getAsJsonObject("result").get("completeness").asString)
        val status = session.getStatus()
        assertTrue(status.get("sessionCapabilitiesReady").asBoolean)
        assertTrue(status.get("remoteEnabled").asBoolean)
        assertFalse(status.has("pendingOperationId"))
    }

    @Test fun lostEnrollment201ReplaysPersistedGrantAfterSessionReconstruction() {
        val trustedHub = JsonParser.parseString(decoded("trusted_hub_identity_base64")).asJsonObject
        val baseUrl = argument("hub_base_url")
        session.pinHub(baseUrl, trustedHub.get("hub_id").asString,
            trustedHub.getAsJsonObject("control_public_identity").toString())
        try {
            session.enroll(argument("owner_id"), argument("owner_key_id"),
                decoded("owner_public_identity_base64"), argument("device_id"),
                argument("owner_device_grant_base64"))
            fail("Fault proxy did not discard the accepted HTTP 201 response")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        val waiting = session.getStatus()
        assertTrue(waiting.get("enrollmentRecoveryRequired").asBoolean)
        assertFalse(waiting.get("enrolled").asBoolean)
        val resumed = ClientHubSession(instrumentation.targetContext)
        val recovered = resumed.recoverEnrollment()
        assertEquals("ACTIVE", recovered.get("state").asString)
        assertEquals(1L, recovered.get("sessionEpoch").asLong)
        assertEquals(1L, recovered.get("deviceKeyVersion").asLong)
        val cap = resumed.rpc("session.capabilities", JsonObject())
        assertTrue(cap.get("ok").asBoolean)
        assertEquals("client-hub-v1.3", cap.getAsJsonObject("result")
            .get("contract_revision").asString)
        assertEquals("808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377",
            cap.getAsJsonObject("result").get("catalog_sha256").asString)
        assertFalse(resumed.getStatus().get("enrollmentRecoveryRequired").asBoolean)
    }

    @Test fun lostRpc200RecoversSameEncryptedResponseWithoutNewOperation() {
        val initial = session.getStatus()
        assertTrue(initial.get("remoteEnabled").asBoolean)
        val operationId = "android-v12-lost-response-${UUID.randomUUID()}"
        try {
            session.rpc("status.snapshot", JsonObject(), operationId)
            fail("Fault proxy did not discard the accepted encrypted RPC response")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        val waiting = session.getStatus()
        assertEquals(operationId, waiting.get("pendingOperationId").asString)
        val beforeSequence = waiting.get("nextSequence").asLong
        val resumed = ClientHubSession(instrumentation.targetContext)
        val recovered = resumed.recoverPending()
        assertTrue(recovered.get("ok").asBoolean)
        assertEquals(operationId, recovered.get("operationId").asString)
        assertEquals(beforeSequence, resumed.getStatus().get("nextSequence").asLong)
        assertFalse(resumed.getStatus().has("pendingOperationId"))
    }

    private fun pendingSnapshot(): JsonObject = JsonParser.parseString(File(
        instrumentation.targetContext.noBackupFilesDir, "client-hub/session-state.json",
    ).readText(StandardCharsets.UTF_8)).asJsonObject.getAsJsonObject("pending")

    @Test fun switchEnrolledSessionToIsolatedFaultProxy() {
        val trusted = JsonParser.parseString(decoded("trusted_hub_identity_base64")).asJsonObject
        val before = session.getStatus()
        assertTrue(before.get("remoteEnabled").asBoolean)
        val pin = session.pinHub(argument("fault_proxy_base_url"),
            trusted.get("hub_id").asString,
            trusted.getAsJsonObject("control_public_identity").toString())
        assertTrue(pin.get("pinned").asBoolean)
        val after = session.getStatus()
        assertEquals(before.get("ownerId"), after.get("ownerId"))
        assertEquals(before.get("nextSequence"), after.get("nextSequence"))
        assertTrue(after.get("remoteEnabled").asBoolean)
    }

    @Test fun faultProxyPersistsOneExactSnapshotPacket() {
        val before = session.getStatus()
        assertTrue(before.get("remoteEnabled").asBoolean)
        val sequence = before.get("nextSequence").asLong
        val operationId = "android-v121-fault-${UUID.randomUUID()}"
        try {
            session.rpc("status.snapshot", JsonObject(), operationId)
            fail("The isolated fault proxy did not discard the response")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        val status = session.getStatus()
        val pending = pendingSnapshot()
        assertEquals(operationId, status.get("pendingOperationId").asString)
        assertEquals(operationId, pending.get("operationId").asString)
        assertEquals(sequence, pending.get("sequence").asLong)
        assertEquals(sequence + 1, status.get("nextSequence").asLong)
        assertTrue(pending.get("packetJson").asString.isNotBlank())
        try {
            session.rpc("status.snapshot", JsonObject())
            fail("New operation was accepted while original ciphertext is pending")
        } catch (error: HubSessionException) {
            assertEquals("PENDING_RECOVERY_REQUIRED", error.errorCode)
        }
        publish("pending_operation_id", operationId)
        publish("pending_request_sequence", sequence.toString())
        publish("pending_packet_sha256", MessageDigest.getInstance("SHA-256")
            .digest(pending.get("packetJson").asString.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) })
    }

    @Test fun faultProxyRecoverStillProcessingKeepsExactPending() {
        val before = session.getStatus()
        val pending = pendingSnapshot().toString()
        try {
            ClientHubSession(instrumentation.targetContext).recoverPending()
            fail("Expected the pinned Hub's 409 STILL_PROCESSING")
        } catch (error: HubSessionException) {
            assertEquals("STILL_PROCESSING", error.errorCode)
        }
        val after = session.getStatus()
        assertEquals(before.get("pendingOperationId"), after.get("pendingOperationId"))
        assertEquals(before.get("nextSequence"), after.get("nextSequence"))
        assertEquals(pending, pendingSnapshot().toString())
        assertEquals("STILL_PROCESSING", after.get("sessionError").asString)
    }

    @Test fun faultProxyRecoverUncertainReconcilesWithoutSecondWrite() {
        val before = session.getStatus()
        val pendingId = before.get("pendingOperationId").asString
        val next = before.get("nextSequence").asLong
        val recovered = ClientHubSession(instrumentation.targetContext).recoverPending()
        assertFalse(recovered.get("ok").asBoolean)
        assertEquals("OUTCOME_UNCERTAIN", recovered.get("errorCode").asString)
        assertEquals(pendingId, recovered.get("operationId").asString)
        val uncertain = session.getStatus()
        assertFalse(uncertain.has("pendingOperationId"))
        assertEquals(next, uncertain.get("nextSequence").asLong)
        assertTrue(uncertain.get("uncertainNeedsReconciliation").asBoolean)
        try {
            session.rpc("intent.submit", JsonObject())
            fail("A second business operation was allowed before authoritative reconciliation")
        } catch (error: HubSessionException) {
            assertEquals("BUSINESS_RECONCILIATION_REQUIRED", error.errorCode)
        }
        assertTrue(session.rpc("status.snapshot", JsonObject()).get("ok").asBoolean)
        assertFalse(session.getStatus().get("uncertainNeedsReconciliation").asBoolean)
    }

    @Test fun faultProxyRecoverUnavailableFencesOriginalPacket() {
        val before = session.getStatus()
        val pending = pendingSnapshot().toString()
        try {
            ClientHubSession(instrumentation.targetContext).recoverPending()
            fail("Expected 409 RECOVERY_UNAVAILABLE for the legacy isolated request")
        } catch (error: HubSessionException) {
            assertEquals("RECOVERY_UNAVAILABLE", error.errorCode)
        }
        val after = session.getStatus()
        assertEquals(before.get("pendingOperationId"), after.get("pendingOperationId"))
        assertEquals(before.get("nextSequence"), after.get("nextSequence"))
        assertEquals(pending, pendingSnapshot().toString())
        assertTrue(after.get("recoveryBlocked").asBoolean)
        try {
            session.rpc("status.snapshot", JsonObject())
            fail("Another operation was allowed despite unavailable recovery")
        } catch (error: HubSessionException) {
            assertEquals("PENDING_RECOVERY_REQUIRED", error.errorCode)
        }
    }

    @Test fun offlineLeavesExactPending() {
        val operationId = "android-offline-" + java.util.UUID.randomUUID()
        try {
            session.rpc("status.snapshot", JsonObject(), operationId)
            fail("Paused Hub unexpectedly accepted the request")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        val status = session.getStatus()
        assertEquals(operationId, status.get("pendingOperationId").asString)
    }

    @Test fun unacceptedOfflineRequestRequiresExplicitExactRetry() {
        val before = session.getStatus()
        val operationId = before.get("pendingOperationId").asString
        assertTrue(operationId.startsWith("android-offline-"))
        try {
            session.recoverPending()
            fail("Recovery route dispatched an unaccepted request")
        } catch (error: HubSessionException) {
            assertEquals("HTTP_409_RECOVERY_REJECTED", error.errorCode)
        }
        assertEquals(operationId, session.getStatus().get("pendingOperationId").asString)
        assertEquals("RECOVERY_REJECTED", session.getStatus().get("sessionError").asString)
        val retried = session.retryPendingExact()
        assertTrue(retried.get("ok").asBoolean)
        assertEquals(operationId, retried.get("operationId").asString)
        assertFalse(session.getStatus().has("pendingOperationId"))
    }

    @Test fun sessionIsRecoveredAfterActivityRestart() {
        val status = session.getStatus()
        assertFalse("Activity startup must clear only a verified pending response",
            status.has("pendingOperationId"))
        assertTrue(status.get("remoteEnabled").asBoolean)
        assertEquals(arguments.getString("expected_role") ?: "manager", status.get("role").asString)
    }

    @Test fun revokedDeviceIsFenced() {
        try {
            session.rpc("status.snapshot", JsonObject(), "android-revoked-5")
            fail("Revoked device unexpectedly retained RPC access")
        } catch (error: HubSessionException) {
            assertEquals("HTTP_403", error.errorCode)
        }
        assertFalse(session.getStatus().get("remoteEnabled").asBoolean)
    }

    @Test fun explicitNewDeviceAfterRevocation() {
        val oldId = session.createDeviceIdentity()
            .getAsJsonObject("devicePublicIdentity").get("id").asString
        val fresh = session.startNewDeviceEnrollment()
        val newId = fresh.getAsJsonObject("devicePublicIdentity").get("id").asString
        assertNotEquals(oldId, newId)
        assertTrue(fresh.get("previousDeviceMayRemainOnHub").asBoolean)
        val status = session.getStatus()
        assertFalse(status.get("enrolled").asBoolean)
        assertFalse(status.get("remoteEnabled").asBoolean)
        publish("new_device_public_identity_base64", Base64.encodeToString(
            fresh.getAsJsonObject("devicePublicIdentity").toString()
                .toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP,
        ))
    }

    @Test fun managerOperationsAgainstHub() {
        val trustedHub = JsonParser.parseString(decoded("trusted_hub_identity_base64")).asJsonObject
        session.pinHub(arguments.getString("hub_base_url") ?: "http://10.0.2.2:8789", trustedHub.get("hub_id").asString,
            trustedHub.getAsJsonObject("control_public_identity").toString())
        assertEquals("ACTIVE", session.enroll(
            argument("owner_id"), argument("owner_key_id"),
            decoded("owner_public_identity_base64"), argument("device_id"),
            argument("owner_device_grant_base64"),
        ).get("state").asString)
        val capabilities = session.rpc("session.capabilities", JsonObject(), "android-manager-caps")
        assertTrue(capabilities.get("ok").asBoolean)
        assertEquals("manager", capabilities.getAsJsonObject("result").get("role").asString)

        assertTrue(session.rpc("topology.snapshot", JsonObject()).get("ok").asBoolean)
        val groupName = "android-interop-" + System.currentTimeMillis()
        val create = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("name", groupName) })
            })
        })
        assertTrue(create.get("ok").asBoolean)
        val groupId = create.getAsJsonObject("result").getAsJsonObject("group")
            .get("group_id").asString
        val conflict = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.set_parent")
            add("set_parent", JsonObject().apply {
                addProperty("group_id", groupId)
                addProperty("expected_group_version", 999)
            })
        })
        assertFalse("Version conflict must be a decrypted business rejection",
            conflict.get("ok").asBoolean)
        assertTrue(session.rpc("topology.snapshot", JsonObject()).get("ok").asBoolean)

        val preview = session.rpc("nodes.preview", JsonObject().apply {
            addProperty("user_code", argument("node_user_code"))
        })
        assertTrue(preview.get("ok").asBoolean)
        val binding = session.rpc("nodes.confirm", JsonObject().apply {
            addProperty("user_code", argument("node_user_code"))
        })
        assertTrue(binding.get("ok").asBoolean)
        assertTrue(session.rpc("nodes.list", JsonObject()).get("ok").asBoolean)
        val node = binding.getAsJsonObject("result")
        val revoked = session.rpc("nodes.revoke", JsonObject().apply {
            addProperty("binding_id", node.get("id").asString)
            addProperty("expected_version", node.get("version").asLong)
        })
        assertTrue(revoked.get("ok").asBoolean)

        assertTrue(session.rpc("approvals.list", JsonObject().apply {
            addProperty("pending_only", true)
        }).get("ok").asBoolean)
        val approvalRejected = session.rpc("approvals.decide", JsonObject().apply {
            addProperty("approval_id", "nonexistent-interop-approval")
            addProperty("decision", "accept")
        })
        assertFalse(approvalRejected.get("ok").asBoolean)

        val intent = session.rpc("intent.submit", JsonObject().apply {
            addProperty("text", "请概述当前已登记节点的状态")
        })
        assertTrue(intent.get("ok").asBoolean)
        val intentId = intent.getAsJsonObject("result").get("id").asString
        val intentStatus = session.rpc("intent.status", JsonObject().apply {
            addProperty("intent_id", intentId)
        })
        assertTrue(intentStatus.get("ok").asBoolean)
        assertTrue(intentStatus.getAsJsonObject("result").has("intent"))
        assertTrue(session.rpc("status.snapshot", JsonObject()).get("ok").asBoolean)
    }

    @Test fun intentHistorySurvivesClientReload() {
        val before = session.getStatus()
        assertTrue("A previously enrolled manager device is required", before.get("remoteEnabled").asBoolean)
        assertEquals("manager", before.get("role").asString)
        val marker = "Android history interop " + System.currentTimeMillis()
        // An unsupported kind produces needs_input without creating a Goal or modifying a workspace.
        val submitted = session.rpc("intent.submit", JsonObject().apply {
            addProperty("text", marker)
            addProperty("kind", "interop_unsupported_kind")
        })
        assertTrue(submitted.get("ok").asBoolean)
        val intentId = submitted.getAsJsonObject("result").get("id").asString

        val reloaded = ClientHubSession(instrumentation.targetContext)
        assertTrue(reloaded.rpc("session.capabilities", JsonObject()).get("ok").asBoolean)
        val listed = reloaded.rpc("intent.list", JsonObject())
        assertTrue(listed.get("ok").asBoolean)
        val history = listed.getAsJsonArray("result")
        assertTrue(history.any { item -> item.asJsonObject.get("id").asString == intentId &&
            item.asJsonObject.get("text").asString == marker })
        val detail = reloaded.rpc("intent.get", JsonObject().apply {
            addProperty("intent_id", intentId)
        })
        assertTrue(detail.get("ok").asBoolean)
        assertEquals(intentId, detail.getAsJsonObject("result").get("id").asString)
        val progress = reloaded.rpc("intent.status", JsonObject().apply {
            addProperty("intent_id", intentId)
        })
        assertTrue(progress.get("ok").asBoolean)
        assertEquals(intentId, progress.getAsJsonObject("result")
            .getAsJsonObject("intent").get("id").asString)
        assertTrue(progress.getAsJsonObject("result").has("job"))
    }

    @Test fun clientDeviceListAndSelfRevokeGuard() {
        val before = session.getStatus()
        assertTrue("A previously enrolled manager device is required", before.get("remoteEnabled").asBoolean)
        assertTrue(session.rpc("session.capabilities", JsonObject()).get("ok").asBoolean)
        val ownId = before.get("deviceId").asString
        val listed = session.rpc("devices.list", JsonObject())
        assertTrue(listed.get("ok").asBoolean)
        val own = listed.getAsJsonArray("result").firstOrNull { item ->
            item.asJsonObject.get("device_id").asString == ownId
        }?.asJsonObject ?: error("Current device missing from owner-scoped devices.list")
        assertEquals("ACTIVE", own.get("state").asString)

        val rejected = session.rpc("devices.revoke", JsonObject().apply {
            addProperty("device_id", ownId)
            addProperty("expected_version", own.get("version").asLong)
        })
        assertFalse("Server must reject self-revoke inside the encrypted RPC", rejected.get("ok").asBoolean)
        val after = session.rpc("devices.list", JsonObject())
        assertTrue(after.get("ok").asBoolean)
        assertTrue(after.getAsJsonArray("result").any { item ->
            item.asJsonObject.get("device_id").asString == ownId &&
                item.asJsonObject.get("state").asString == "ACTIVE"
        })
    }

    @Test fun revokeDisposablePeerDeviceWithVersionGuard() {
        val targetId = argument("disposable_device_id")
        require(targetId.startsWith("client-disposable-"))
        val ownId = session.getStatus().get("deviceId").asString
        assertNotEquals(ownId, targetId)
        assertTrue(session.rpc("session.capabilities", JsonObject()).get("ok").asBoolean)
        fun targetVersion(): Long {
            val listed = session.rpc("devices.list", JsonObject())
            assertTrue(listed.get("ok").asBoolean)
            val target = listed.getAsJsonArray("result").firstOrNull { item ->
                item.asJsonObject.get("device_id").asString == targetId
            }?.asJsonObject ?: error("Disposable target absent from owner-scoped list")
            assertEquals("ACTIVE", target.get("state").asString)
            return target.get("version").asLong
        }
        val version = targetVersion()
        val stale = session.rpc("devices.revoke", JsonObject().apply {
            addProperty("device_id", targetId)
            addProperty("expected_version", version + 1000)
        })
        assertFalse("Stale version must be a sealed business rejection", stale.get("ok").asBoolean)
        assertEquals(version, targetVersion())

        val revoked = session.rpc("devices.revoke", JsonObject().apply {
            addProperty("device_id", targetId)
            addProperty("expected_version", version)
        })
        assertTrue(revoked.get("ok").asBoolean)
        val device = revoked.getAsJsonObject("result")
        assertEquals("REVOKED", device.get("state").asString)
        assertEquals(version + 1, device.get("version").asLong)
        val finalList = session.rpc("devices.list", JsonObject())
        assertTrue(finalList.get("ok").asBoolean)
        assertTrue(finalList.getAsJsonArray("result").any { item ->
            item.asJsonObject.get("device_id").asString == targetId &&
                item.asJsonObject.get("state").asString == "REVOKED"
        })
    }

    @Test fun confirmDisposableNodeForQueuedGoal() {
        val nodeId = argument("disposable_node_id")
        require(nodeId.startsWith("client-test-node-"))
        val code = argument("node_user_code")
        assertTrue(session.rpc("session.capabilities", JsonObject()).get("ok").asBoolean)
        val preview = session.rpc("nodes.preview", JsonObject().apply {
            addProperty("user_code", code)
        })
        assertTrue(preview.get("ok").asBoolean)
        assertEquals(nodeId, preview.getAsJsonObject("result").get("node_id").asString)
        val confirmed = session.rpc("nodes.confirm", JsonObject().apply {
            addProperty("user_code", code)
        })
        assertTrue(confirmed.get("ok").asBoolean)
        assertEquals(nodeId, confirmed.getAsJsonObject("result").get("node_id").asString)
    }

    @Test fun queuedGoalLifecycleAgainstDockerHub() {
        val nodeId = argument("disposable_node_id")
        require(nodeId.startsWith("client-test-node-"))
        val capabilities = session.rpc("session.capabilities", JsonObject())
        assertTrue(capabilities.get("ok").asBoolean)
        assertEquals("manager", capabilities.getAsJsonObject("result").get("role").asString)
        val marker = "Android queued lifecycle " + System.currentTimeMillis()
        val accepted = session.rpc("intent.submit", JsonObject().apply {
            addProperty("text", marker)
            addProperty("kind", "goal")
            add("goal", JsonObject().apply {
                addProperty("objective", marker)
                addProperty("success_criteria", "Return a short completion summary")
                addProperty("constraints", "Do not modify files or contact external services")
                addProperty("machine_id", nodeId)
                addProperty("harness", "codex")
            })
        })
        assertTrue(accepted.get("ok").asBoolean)
        val intentId = accepted.getAsJsonObject("result").get("id").asString
        var goalId: String? = null
        for (attempt in 0 until 50) {
            val progress = session.rpc("intent.status", JsonObject().apply {
                addProperty("intent_id", intentId)
            })
            assertTrue(progress.get("ok").asBoolean)
            val intent = progress.getAsJsonObject("result").getAsJsonObject("intent")
            val result = intent.get("result")
            if (intent.get("status").asString == "resolved" &&
                result != null && result.isJsonObject && result.asJsonObject.has("goal_id")) {
                goalId = result.asJsonObject.get("goal_id").asString
                break
            }
            Thread.sleep(100)
        }
        val id = goalId ?: error("Intent did not resolve to a remote queued Goal")
        val boundedResult = session.rpc("goal.result", JsonObject().apply {
            addProperty("intent_id", intentId)
        })
        assertTrue(boundedResult.get("ok").asBoolean)
        val resultBody = boundedResult.getAsJsonObject("result")
        assertEquals(intentId, resultBody.get("intent_id").asString)
        assertEquals(id, resultBody.get("goal_id").asString)
        assertEquals("queued", resultBody.getAsJsonArray("workers").first().asJsonObject
            .get("status").asString)
        assertTrue(resultBody.get("artifacts").isJsonArray)
        fun goalSnapshot(): JsonObject {
            val snapshot = session.rpc("status.snapshot", JsonObject())
            assertTrue(snapshot.get("ok").asBoolean)
            val body = snapshot.getAsJsonObject("result")
            val goal = body.getAsJsonArray("goals").firstOrNull { item ->
                item.asJsonObject.get("goal_id").asString == id
            }?.asJsonObject ?: error("Goal missing from owner snapshot")
            assertEquals(nodeId, goal.get("node_id").asString)
            val workers = body.getAsJsonArray("workers")
            assertTrue(workers.any { item ->
                item.asJsonObject.get("goal_id")?.asString == id &&
                    item.asJsonObject.getAsJsonObject("worker_execution")
                        .get("state").asString == "queued"
            })
            return goal
        }
        val initial = goalSnapshot()
        assertEquals("queued", initial.getAsJsonObject("goal_lifecycle").get("state").asString)
        val version = initial.get("lifecycle_version").asLong
        val paused = session.rpc("goal.lifecycle", JsonObject().apply {
            addProperty("goal_id", id); addProperty("action", "pause")
            addProperty("expected_version", version)
        })
        assertTrue(paused.get("ok").asBoolean)
        assertEquals("paused", paused.getAsJsonObject("result").get("status").asString)
        assertEquals(version + 1, paused.getAsJsonObject("result")
            .get("lifecycle_version").asLong)
        assertEquals("paused", goalSnapshot().getAsJsonObject("goal_lifecycle")
            .get("state").asString)
        val stale = session.rpc("goal.lifecycle", JsonObject().apply {
            addProperty("goal_id", id); addProperty("action", "resume")
            addProperty("expected_version", version)
        })
        assertFalse(stale.get("ok").asBoolean)
        val resumed = session.rpc("goal.lifecycle", JsonObject().apply {
            addProperty("goal_id", id); addProperty("action", "resume")
            addProperty("expected_version", version + 1)
        })
        assertTrue(resumed.get("ok").asBoolean)
        assertEquals("queued", resumed.getAsJsonObject("result").get("status").asString)
        val finalPause = session.rpc("goal.lifecycle", JsonObject().apply {
            addProperty("goal_id", id); addProperty("action", "pause")
            addProperty("expected_version", version + 2)
        })
        assertTrue(finalPause.get("ok").asBoolean)
        assertEquals("paused", goalSnapshot().getAsJsonObject("goal_lifecycle")
            .get("state").asString)
    }

    @Test fun submitGoalForNodeResultInterop() {
        val nodeId = argument("disposable_node_id")
        require(nodeId.startsWith("client-test-node-"))
        val marker = "Android v1.2 bounded result " + System.currentTimeMillis()
        val accepted = session.rpc("intent.submit", JsonObject().apply {
            addProperty("text", marker)
            addProperty("kind", "goal")
            add("goal", JsonObject().apply {
                addProperty("objective", marker)
                addProperty("success_criteria", "Return a short completion summary")
                addProperty("constraints", "Do not modify files or contact external services")
                addProperty("machine_id", nodeId)
                addProperty("harness", "codex")
            })
        })
        assertTrue(accepted.get("ok").asBoolean)
        val intentId = accepted.getAsJsonObject("result").get("id").asString
        var workerId: String? = null
        for (attempt in 0 until 50) {
            val progress = session.rpc("intent.status", JsonObject().apply { addProperty("intent_id", intentId) })
            assertTrue(progress.get("ok").asBoolean)
            val body = session.rpc("goal.result", JsonObject().apply { addProperty("intent_id", intentId) })
            assertTrue(body.get("ok").asBoolean)
            val result = body.getAsJsonObject("result")
            if (result.has("goal_id") && result.getAsJsonArray("workers").size() > 0) {
                val worker = result.getAsJsonArray("workers").first().asJsonObject
                assertEquals("queued", worker.get("status").asString)
                workerId = worker.get("worker_id").asString
                break
            }
            Thread.sleep(100)
        }
        assertNotNull("Goal/Worker did not become queued", workerId)
        publish("interop_intent_id", intentId)
        publish("interop_worker_id", workerId!!)
    }

    @Test fun completedGoalResultIsIndependentOfIntentDone() {
        val intentId = argument("interop_intent_id")
        val workerId = argument("interop_worker_id")
        val progress = session.rpc("intent.status", JsonObject().apply { addProperty("intent_id", intentId) })
        assertTrue(progress.get("ok").asBoolean)
        assertEquals("DONE", progress.getAsJsonObject("result").getAsJsonObject("job")
            .get("state").asString)
        val bounded = session.rpc("goal.result", JsonObject().apply { addProperty("intent_id", intentId) })
        assertTrue(bounded.get("ok").asBoolean)
        val result = bounded.getAsJsonObject("result")
        assertEquals(intentId, result.get("intent_id").asString)
        val worker = result.getAsJsonArray("workers").firstOrNull { item ->
            item.asJsonObject.get("worker_id").asString == workerId
        }?.asJsonObject ?: error("Worker missing from bounded goal.result")
        assertEquals("completed", worker.get("status").asString)
        assertEquals("Node protocol fixture completed a bounded task", worker.get("summary").asString)
        assertTrue(result.get("artifacts").isJsonArray)
    }

    /** The Node Agent and Codex run separately; every user decision here is a real encrypted Android RPC. */
    @Test fun submitBoundedRealCodexGoal() {
        val nodeId = argument("native_node_id")
        val marker = argument("native_marker")
        require(nodeId.startsWith("client-test-node-") && marker.matches(Regex("CICADA_NATIVE_[A-F0-9]{16,32}")))
        val caps = session.rpc("session.capabilities", JsonObject())
        assertTrue(caps.get("ok").asBoolean)
        val capability = caps.getAsJsonObject("result")
        assertEquals("manager", capability.get("role").asString)
        val allowed = capability.getAsJsonArray("available_rpc_operations").map { it.asString }
        assertTrue(allowed.containsAll(listOf("intent.submit", "intent.status", "goal.result",
            "approvals.list", "approvals.decide")))
        val objective = "Run exactly one Codex command: printf '%s' '$marker' > " +
            "/approval-target/result.txt. This isolated target is outside the workspace, so " +
            "request normal approval. Do not inspect the workspace, run verification commands, " +
            "or contact external services. After the command succeeds, reply with the marker alone."
        val accepted = session.rpc("intent.submit", JsonObject().apply {
            addProperty("text", objective)
            addProperty("kind", "goal")
            add("goal", JsonObject().apply {
                addProperty("objective", objective)
                addProperty("success_criteria", "The isolated marker file matches exactly")
                addProperty("constraints", "Only write the specified isolated test file after explicit approval")
                addProperty("machine_id", nodeId)
                addProperty("harness", "codex")
            })
        })
        assertTrue(accepted.get("ok").asBoolean)
        val intentId = accepted.getAsJsonObject("result").get("id").asString
        repeat(60) {
            val progress = session.rpc("intent.status", JsonObject().apply { addProperty("intent_id", intentId) })
            assertTrue(progress.get("ok").asBoolean)
            val bounded = session.rpc("goal.result", JsonObject().apply { addProperty("intent_id", intentId) })
            assertTrue(bounded.get("ok").asBoolean)
            val result = bounded.getAsJsonObject("result")
            val workers = result.getAsJsonArray("workers")
            if (result.has("goal_id") && workers.size() == 1) {
                val worker = workers.first().asJsonObject
                assertEquals("queued", worker.get("status").asString)
                publish("native_intent_id", intentId)
                publish("native_goal_id", result.get("goal_id").asString)
                publish("native_worker_id", worker.get("worker_id").asString)
                return
            }
            Thread.sleep(150)
        }
        fail("Android Intent did not resolve to one queued Node Worker")
    }

    @Test fun recoverInterruptedReadOnlyApprovalPoll() {
        val before = session.getStatus()
        assertTrue("Interrupted Android polling must retain its exact packet",
            before.has("pendingOperationId"))
        val state = JsonParser.parseString(File(instrumentation.targetContext.noBackupFilesDir,
            "client-hub/session-state.json").readText(StandardCharsets.UTF_8)).asJsonObject
        assertEquals("approvals.list", state.getAsJsonObject("pending").get("operation").asString)
        val recovered = session.recoverPending()
        assertTrue(recovered.get("ok").asBoolean)
        assertFalse(session.getStatus().has("pendingOperationId"))
    }

    @Test fun recoverInterruptedReadOnlyNativeQuery() {
        val before = session.getStatus()
        assertTrue("Interrupted Android query must retain its exact packet",
            before.has("pendingOperationId"))
        val state = JsonParser.parseString(File(instrumentation.targetContext.noBackupFilesDir,
            "client-hub/session-state.json").readText(StandardCharsets.UTF_8)).asJsonObject
        assertTrue(state.getAsJsonObject("pending").get("operation").asString in
            setOf("approvals.list", "intent.status", "goal.result"))
        val recovered = try {
            session.recoverPending()
        } catch (error: HubSessionException) {
            if (error.errorCode != "HTTP_409_RECOVERY_REJECTED") throw error
            // The interrupted operation is one of the read-only queries above.
            // This is an explicit test decision to send its exact saved packet.
            session.retryPendingExact()
        }
        assertTrue(recovered.get("ok").asBoolean)
        assertFalse(session.getStatus().has("pendingOperationId"))
    }

    @Test fun approveOriginalRealCodexTurnAndReadResult() {
        val intentId = argument("native_intent_id")
        val goalId = argument("native_goal_id")
        val workerId = argument("native_worker_id")
        val marker = argument("native_marker")
        require(marker.matches(Regex("CICADA_NATIVE_[A-F0-9]{16,32}")))
        var nativeThreadId: String? = null
        val decided = mutableSetOf<String>()
        val deadline = System.currentTimeMillis() + 420_000L
        while (System.currentTimeMillis() < deadline) {
            val listed = session.rpc("approvals.list", JsonObject().apply { addProperty("pending_only", true) })
            assertTrue(listed.get("ok").asBoolean)
            for (item in listed.getAsJsonArray("result")) {
                val approval = item.asJsonObject
                if (approval.get("goal_id").asString != goalId ||
                    approval.get("worker_id").asString != workerId ||
                    approval.get("status").asString != "pending") continue
                val approvalId = approval.get("id").asString
                if (approvalId in decided) continue
                assertTrue("Too many native approvals", decided.size < 6)
                assertEquals(1, approval.get("attempt").asInt)
                assertTrue(approval.get("method").asString in setOf(
                    "item/commandExecution/requestApproval", "item/fileChange/requestApproval"))
                val request = approval.getAsJsonObject("request")
                val threadId = request.get("threadId")?.asString ?: error("Native approval omitted threadId")
                assertTrue(threadId.isNotBlank())
                if (nativeThreadId == null) nativeThreadId = threadId
                assertEquals("Native approval changed Thread", nativeThreadId, threadId)
                val requestText = request.toString()
                assertTrue("Approval is outside the bounded target", requestText.contains("/approval-target/result.txt"))
                val exactReadback = approval.get("method").asString ==
                    "item/commandExecution/requestApproval" && request.get("command")?.asString ==
                    "/bin/bash -lc 'wc -c /approval-target/result.txt && od -An -tx1c /approval-target/result.txt'"
                assertTrue("Approval is neither the exact write nor the bounded readback",
                    requestText.contains(marker) || exactReadback)
                val decision = session.rpc("approvals.decide", JsonObject().apply {
                    addProperty("approval_id", approvalId)
                    addProperty("decision", "accept")
                })
                assertTrue(decision.get("ok").asBoolean)
                assertEquals(approvalId, decision.getAsJsonObject("result").get("id").asString)
                assertEquals("accept", decision.getAsJsonObject("result").get("decision").asString)
                decided.add(approvalId)
            }
            if (decided.isNotEmpty()) {
                val progress = session.rpc("intent.status", JsonObject().apply { addProperty("intent_id", intentId) })
                assertTrue(progress.get("ok").asBoolean)
                val bounded = session.rpc("goal.result", JsonObject().apply { addProperty("intent_id", intentId) })
                assertTrue(bounded.get("ok").asBoolean)
                val result = bounded.getAsJsonObject("result")
                val worker = result.getAsJsonArray("workers").firstOrNull { entry ->
                    entry.asJsonObject.get("worker_id").asString == workerId
                }?.asJsonObject
                if (worker != null && worker.get("status").asString == "completed") {
                    assertEquals("DONE", progress.getAsJsonObject("result").getAsJsonObject("job")
                        .get("state").asString)
                    assertEquals("resolved", result.get("intent_status").asString)
                    assertEquals(goalId, result.get("goal_id").asString)
                    assertEquals("completed", result.get("goal_status").asString)
                    assertEquals(1, worker.get("attempt").asInt)
                    assertTrue(worker.get("summary").asString.isNotBlank())
                    assertTrue(result.get("artifacts").isJsonArray)
                    val all = session.rpc("approvals.list", JsonObject().apply {
                        addProperty("pending_only", false)
                    })
                    assertTrue(all.get("ok").asBoolean)
                    val acceptedApprovals = all.getAsJsonArray("result").map { it.asJsonObject }
                        .filter { it.get("goal_id").asString == goalId &&
                            it.get("worker_id").asString == workerId }
                    assertTrue("No accepted approval belongs to this Worker", acceptedApprovals.isNotEmpty())
                    acceptedApprovals.forEach { approved ->
                        assertEquals(1, approved.get("attempt").asInt)
                        assertEquals("accept", approved.get("decision").asString)
                        assertEquals(nativeThreadId,
                            approved.getAsJsonObject("request").get("threadId").asString)
                    }
                    val digest = MessageDigest.getInstance("SHA-256")
                        .digest(nativeThreadId!!.toByteArray(StandardCharsets.UTF_8))
                        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
                    publish("native_thread_sha256", digest)
                    publish("native_approval_count", acceptedApprovals.size.toString())
                    publish("native_worker_attempt", worker.get("attempt").asString)
                    publish("native_worker_status", worker.get("status").asString)
                    publish("native_goal_status", result.get("goal_status").asString)
                    publish("native_intent_status", result.get("intent_status").asString)
                    return
                }
                assertFalse("Worker ended before the original turn completed", worker != null &&
                    worker.get("status").asString in setOf("failed", "cancelled", "outcome_uncertain"))
            }
            Thread.sleep(1_000)
        }
        fail("Real Codex approval or final Worker result did not arrive before the deadline")
    }

    @Test fun revokeDisposableNodeAfterQueuedGoal() {
        val nodeId = argument("disposable_node_id")
        require(nodeId.startsWith("client-test-node-"))
        assertTrue(session.rpc("session.capabilities", JsonObject()).get("ok").asBoolean)
        val listed = session.rpc("nodes.list", JsonObject())
        assertTrue(listed.get("ok").asBoolean)
        val binding = listed.getAsJsonArray("result").firstOrNull { item ->
            item.asJsonObject.get("node_id").asString == nodeId &&
                item.asJsonObject.get("state").asString == "ACTIVE"
        }?.asJsonObject ?: error("Disposable Node binding absent")
        val revoked = session.rpc("nodes.revoke", JsonObject().apply {
            addProperty("binding_id", binding.get("id").asString)
            addProperty("expected_version", binding.get("version").asLong)
        })
        assertTrue(revoked.get("ok").asBoolean)
        assertEquals("REVOKED", revoked.getAsJsonObject("result").get("state").asString)
    }
}
