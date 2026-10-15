package ai.cicada.client.hub

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.cicadaclient.MainActivity
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Staged Android operations against the separately owned, fixed v1.3 Docker Hub. */
@RunWith(AndroidJUnit4::class)
class MonitorHubInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val session get() = ClientHubSession(target)
    private val runId: String get() = InstrumentationRegistry.getArguments().getString("run_id")
        ?.takeIf { it.matches(Regex("monitor-v13-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe Monitor run_id is required")
    private val directory get() = File(target.noBackupFilesDir, "monitor-v13/$runId")

    private fun text(source: JsonObject, name: String): String = source.get(name)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing public fixture field: $name")

    private fun read(name: String): JsonObject = JsonParser.parseString(File(directory, name).readText()).asJsonObject
    private fun fixture(): JsonObject = read("fixture.json").also {
        assertEquals("cicada.client-monitor-fixture.v1", text(it, "schema"))
    }

    private fun save(name: String, value: JsonObject) {
        assertTrue(directory.isDirectory || directory.mkdirs())
        File(directory, name).writeText(value.toString())
    }

    private fun mark(name: String, value: String) {
        instrumentation.sendStatus(0, Bundle().apply { putString(name, value) })
    }

    private fun rpc(operation: String, body: JsonObject = JsonObject()): JsonObject {
        val response = session.rpc(operation, body)
        assertTrue("Encrypted $operation was rejected", response.get("ok").asBoolean)
        return response.getAsJsonObject("result")
    }

    @Test fun prepareDevice() {
        assertFalse("A fresh emulator identity is required", session.getStatus().get("enrolled").asBoolean)
        val result = session.createDeviceIdentity()
        save("device-public.json", result.getAsJsonObject("devicePublicIdentity"))
        mark("monitor_device_public_ready", "true")
    }

    @Test fun enrollOwnerAndCheckCapabilities() {
        val cfg = fixture()
        val hub = cfg.getAsJsonObject("hub_identity")
        val owner = cfg.getAsJsonObject("owner")
        session.pinHub(text(cfg, "hub_base_url"), text(hub, "hub_id"),
            hub.getAsJsonObject("control_public_identity").toString())
        session.enroll(text(owner, "owner_id"), text(owner, "owner_key_id"),
            owner.getAsJsonObject("owner_public_identity").toString(), text(owner, "device_id"),
            text(owner, "owner_device_grant_base64"))
        assertFixedCapabilities(cfg)
    }

    @Test fun readFixedCapabilitiesAfterAppUpdate() = assertFixedCapabilities(fixture())

    private fun assertFixedCapabilities(cfg: JsonObject) {
        val owner = cfg.getAsJsonObject("owner")
        val capabilities = rpc("session.capabilities")
        assertEquals(text(owner, "owner_id"), text(capabilities, "owner_id"))
        assertEquals("external", text(capabilities, "role"))
        assertEquals("client-hub-v1.3", text(capabilities, "contract_revision"))
        assertEquals("808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377",
            text(capabilities, "catalog_sha256"))
        val allowed = capabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        assertTrue(allowed.containsAll(listOf("monitor.broadcast_prepare", "monitor.broadcast_confirm",
            "monitor.broadcast_status", "monitor.broadcast_recover", "topology.apply")))
        val public = session.fetchHubMetadata(text(cfg, "hub_base_url")).getAsJsonObject("capabilities")
        assertFalse(public.get("external_thread_links").asBoolean)
        assertFalse(public.get("status_events").asBoolean)
        mark("monitor_encrypted_v13_capabilities_verified", "true")
    }

    @Test fun confirmPendingNodes() {
        val cfg = fixture()
        val codeFile = File(directory, "node-codes.json")
        val codes = read("node-codes.json")
        assertTrue("Remove private code staging immediately after reading", codeFile.delete())
        for (entry in cfg.getAsJsonArray("nodes")) {
            val node = entry.asJsonObject
            val code = text(codes, text(node, "label"))
            val preview = rpc("nodes.preview", JsonObject().apply { addProperty("user_code", code) })
            assertEquals(text(node, "node_id"), text(preview, "node_id"))
            assertTrue(confirm("Confirm Node", "Bind the displayed disposable Node to this Owner?\n\n" +
                "Node: ${text(preview, "node_id")}\nName: ${text(preview, "node_name")}", "Confirm Node"))
            val accepted = rpc("nodes.confirm", JsonObject().apply { addProperty("user_code", code) })
            assertEquals(text(node, "node_id"), text(accepted, "node_id"))
        }
        mark("monitor_nodes_confirmed", "true")
    }

    @Test fun createOrReconcileGroup() {
        val groupName = "Android Monitor $runId"
        val snapshot = rpc("topology.snapshot")
        val existing = snapshot.getAsJsonArray("groups").map { it.asJsonObject }
            .singleOrNull { text(it, "name") == groupName }
        val group = existing ?: run {
            assertTrue(confirm("Create Group", "Create this Owner's disposable Group?\n\n$groupName", "Create Group"))
            rpc("topology.apply", JsonObject().apply {
                addProperty("kind", "group.create")
                add("create_group", JsonObject().apply {
                    add("group", JsonObject().apply { addProperty("name", groupName) })
                })
            }).getAsJsonObject("group")
        }
        save("setup.json", JsonObject().apply {
            addProperty("group_id", text(group, "group_id"))
            addProperty("group_name", groupName)
        })
        mark("monitor_group_ready", "true")
    }

    private fun monitorMembership(groupId: String, endpointId: String): JsonObject {
        val topology = rpc("topology.snapshot")
        val endpoint = topology.getAsJsonArray("endpoints").map { it.asJsonObject }
            .single { text(it, "endpoint_id") == endpointId }
        return topology.getAsJsonArray("memberships").map { it.asJsonObject }.single {
            text(it, "group_id") == groupId && text(it, "principal_id") == text(endpoint, "principal_id")
        }
    }

    /** The role itself must leave the explicit broadcast permission disabled. */
    @Test fun assignMonitorRoleAndEnableBroadcastPermission() {
        val cfg = fixture()
        val group = text(cfg, "group_id")
        val monitor = text(cfg, "monitor_endpoint_id")
        val before = monitorMembership(group, monitor)
        assertFalse("Fresh membership unexpectedly has broadcast permission", before.get("broadcast_permission_enabled").asBoolean)
        rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "membership.bind_role")
            add("bind_role", JsonObject().apply {
                addProperty("group_id", group)
                addProperty("membership_id", text(before, "membership_id"))
                addProperty("role", "monitor")
                addProperty("expected_membership_version", before.get("version").asLong)
            })
        })
        val roleOnly = monitorMembership(group, monitor)
        assertFalse("Monitor role must not imply broadcast permission", roleOnly.get("broadcast_permission_enabled").asBoolean)
        val denied = session.monitorBroadcastPrepare(group, monitor, BODY)
        assertFalse("Role alone must not authorize a broadcast", denied.get("ok").asBoolean)
        assertEquals("user-through-Monitor broadcast is not currently authorized", text(denied, "error"))
        assertTrue(confirm("Allow Monitor broadcast", "Allow message.broadcast for only this Group membership?\n\n" +
            "Group: $group\nMonitor: $monitor\nMembership: ${text(roleOnly, "membership_id")}", "Allow broadcast"))
        rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "membership.set_broadcast_permission")
            add("set_broadcast_permission", JsonObject().apply {
                addProperty("group_id", group)
                addProperty("membership_id", text(roleOnly, "membership_id"))
                addProperty("enabled", true)
                addProperty("expected_membership_version", roleOnly.get("version").asLong)
            })
        })
        val after = monitorMembership(group, monitor)
        assertTrue(after.get("broadcast_permission_enabled").asBoolean)
        assertTrue(after.get("version").asLong > roleOnly.get("version").asLong)
        mark("monitor_permission_authoritatively_enabled", "true")
    }

    @Test fun exportEndpointManifests() {
        val cfg = fixture()
        val ownerKey = text(cfg.getAsJsonObject("owner"), "owner_key_id")
        val manifests = JsonObject()
        for (entry in cfg.getAsJsonArray("endpoints")) {
            val endpoint = entry.asJsonObject
            val response = session.previewGroupKey(text(cfg, "group_id"), text(endpoint, "endpoint_id"), ownerKey)
            assertTrue(response.get("verified").asBoolean)
            manifests.add(text(endpoint, "label"), response.getAsJsonObject("result"))
        }
        save("manifests.json", manifests)
        mark("monitor_endpoint_manifests_verified", "true")
    }

    @Test fun grantEndpointKeysAndReadCurrent() {
        val cfg = fixture()
        val manifests = read("manifests.json")
        val groupId = text(cfg, "group_id")
        val key = text(cfg.getAsJsonObject("owner"), "owner_key_id")
        for (entry in cfg.getAsJsonArray("endpoints")) {
            val endpoint = entry.asJsonObject
            val label = text(endpoint, "label")
            val id = text(endpoint, "endpoint_id")
            val manifest = manifests.getAsJsonObject(label)
            val digest = text(manifest, "digest")
            val proof = text(endpoint, "owner_signed_proof_base64")
            val verified = session.previewGroupKeyGrant(groupId, id, key, digest, proof)
            assertTrue(verified.get("verified").asBoolean)
            assertTrue(confirm("Approve Endpoint key", "Approve this independently verified external Owner proof?\n\n" +
                "Endpoint: $id\nGroup: $groupId\nManifest: $digest", "Approve key"))
            assertTrue(session.grantGroupKey(groupId, id, key, digest, proof).get("ok").asBoolean)
            val result = session.groupKeyStatus(groupId, id)
            assertTrue(result.get("ok").asBoolean)
            assertEquals("CURRENT", text(result.getAsJsonObject("result"), "current_status"))
        }
        mark("monitor_group_endpoint_keys_current", "true")
    }

    @Test fun prepareExactTextAndReviewRoster() {
        val cfg = fixture()
        val prepared = session.monitorBroadcastPrepare(text(cfg, "group_id"),
            text(cfg, "monitor_endpoint_id"), BODY)
        verifyPrepared(cfg, prepared)
        save("prepared.json", prepared)
        mark("monitor_exact_text_preview_verified", "true")
    }

    /** Diagnose public proof rejection without exporting the device key or any plaintext draft. */
    @Test fun verifyOriginalPendingPrepareEvidence() {
        val cfg = fixture()
        val state = privateSessionState()
        val pending = state.getAsJsonObject("pending")
        assertEquals("monitor.broadcast_prepare", text(pending, "operation"))
        val packet = text(pending, "packetJson")
        val route = ClientWireCrypto.Route.parse(JsonParser.parseString(packet).asJsonObject.getAsJsonObject("route"))
        val connection = URL(text(cfg, "hub_base_url") + "/v2/client/rpc/recover").openConnection() as HttpURLConnection
        val response = try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.connectTimeout = 5000
            connection.readTimeout = 15000
            connection.doOutput = true
            connection.outputStream.use { it.write(packet.toByteArray(StandardCharsets.UTF_8)) }
            assertEquals(200, connection.responseCode)
            connection.inputStream.bufferedReader().use { it.readText() }
        } finally { connection.disconnect() }
        val method = ClientHubSession::class.java.getDeclaredMethod("loadDeviceIdentity").apply { isAccessible = true }
        (method.invoke(session) as ClientWireCrypto.Identity).use { device ->
            val hub = ClientWireCrypto.PublicIdentity.parse(cfg.getAsJsonObject("hub_identity").getAsJsonObject("control_public_identity"))
            val opened = ClientWireCrypto.openResponse(device, hub, route, response)
            assertTrue(opened.body.get("ok").asBoolean)
            val owner = cfg.getAsJsonObject("owner")
            MonitorBroadcastCrypto.verifyPrepare(opened.body.getAsJsonObject("result"),
                MonitorBroadcastCrypto.TrustedPrepare(text(cfg.getAsJsonObject("hub_identity"), "hub_id"),
                    text(owner, "owner_id"), text(cfg, "group_id"), text(cfg, "monitor_endpoint_id"),
                    digest(BODY.toByteArray(StandardCharsets.UTF_8))),
                ClientWireCrypto.PublicIdentity.parse(owner.getAsJsonObject("owner_public_identity")))
        }
    }

    @Test fun recoverOriginalPrepareAfterPreviewExpiry() {
        val before = privateSessionState()
        val pending = before.getAsJsonObject("pending")
        assertEquals("monitor.broadcast_prepare", text(pending, "operation"))
        val operationId = text(pending, "operationId")
        val recovered = session.monitorBroadcastRecover(operationId)
        assertEquals(operationId, text(recovered, "operationId"))
        assertTrue(recovered.get("verified").asBoolean)
        assertFalse("Run only after the original preview has expired", recovered.get("canConfirm").asBoolean)
        assertEquals(before.get("nextSequence"), privateSessionState().get("nextSequence"))
        assertFalse(session.getStatus().has("pendingOperationId"))
        val metadata = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { text(it, "operationId") == operationId }
        assertEquals("EXPIRED", text(metadata, "state"))
        assertFalse("An expired Prepare is not a Confirm attempt", metadata.get("confirmAttempted").asBoolean)
        try {
            session.monitorBroadcastConfirm(text(recovered, "previewId"), BODY, text(recovered, "consentDigest"))
            fail("An expired preview must never be signed")
        } catch (error: HubSessionException) {
            assertEquals("MONITOR_PREVIEW_NOT_CONFIRMABLE", error.errorCode)
        }
        val status = session.monitorBroadcastStatus(text(recovered, "previewId"))
        assertTrue(status.get("ok").asBoolean)
        assertEquals(text(recovered, "previewId"), text(status.getAsJsonObject("result"), "preview_id"))
        mark("monitor_late_prepare_consumed_read_only_without_replacement", "true")
    }

    @Test fun recoverExpiredStatusWithOriginalPacket() {
        val before = privateSessionState()
        val pending = before.getAsJsonObject("pending")
        assertEquals("monitor.broadcast_status", text(pending, "operation"))
        val recovered = session.recoverPending()
        assertTrue(recovered.get("ok").asBoolean)
        assertEquals(text(pending, "operationId"), text(recovered, "operationId"))
        assertEquals(before.get("nextSequence"), privateSessionState().get("nextSequence"))
        assertFalse(session.getStatus().has("pendingOperationId"))
        val result = recovered.getAsJsonObject("result")
        assertEquals("PREPARED", text(result, "approval_status"))
        assertEquals(0, result.getAsJsonArray("recipients").size())
        val record = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { it.get("previewId")?.asString == text(result, "preview_id") }
        assertEquals("EXPIRED", text(record, "state"))
        assertFalse(record.get("confirmAttempted").asBoolean)
        mark("monitor_expired_original_status_consumed_without_fabricated_outcomes", "true")
    }

    @Test fun confirmReviewedEnvelopeAndReadStatus() {
        val cfg = fixture()
        val prepared = read("prepared.json")
        verifyPrepared(cfg, prepared)
        val cards = prepared.getAsJsonArray("recipients").map { it.asJsonObject }
        assertTrue(confirm("Approve Monitor broadcast", "Send exactly this text through the verified Monitor?\n\n" +
            BODY + "\nGroup: ${text(prepared, "groupId")}\nMonitor: ${text(prepared, "monitorEndpointId")}\n" +
            "Recipients:\n" + cards.joinToString("\n") { text(it, "endpointId") }, "Approve broadcast"))
        val response = session.monitorBroadcastConfirm(text(prepared, "previewId"), BODY,
            text(prepared, "consentDigest"))
        assertTrue("Encrypted Monitor confirmation was rejected", response.get("ok").asBoolean)
        assertTrue(text(response.getAsJsonObject("result"), "status") in setOf("APPROVED", "DISPATCH_AUTHORIZED"))
        assertOneConfirmationOnly(prepared)
        val status = session.monitorBroadcastStatus(text(prepared, "previewId"))
        verifyStatus(prepared, status)
        record("positive", JsonObject().apply {
            addProperty("result", "PASS")
            addProperty("body_sha256", digest(BODY.toByteArray(StandardCharsets.UTF_8)))
            add("status", status.getAsJsonObject("result"))
            addProperty("native_consumption_claimed", false)
        })
    }

    /** Read final status after native dispatch; this selector never prepares or confirms. */
    @Test fun readNativeDispatchStatus() {
        val cfg = fixture()
        val prepared = read("prepared.json")
        val operationId = text(prepared, "operationId")
        val beforeState = privateSessionState()
        assertFalse("No encrypted request may be pending before the read-only status RPC",
            beforeState.has("pending"))
        val beforeOperation = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { text(it, "operationId") == operationId }
        assertTrue(beforeOperation.get("confirmAttempted").asBoolean)
        assertTrue(beforeOperation.get("confirmStatusReconciled").asBoolean)
        assertTrue(text(beforeOperation, "confirmOperationId").isNotBlank())
        assertTrue(beforeOperation.get("confirmSequence").asLong > 0L)
        assertEquals(text(prepared, "previewId"), text(beforeOperation, "previewId"))
        assertEquals(text(prepared, "broadcastId"), text(beforeOperation, "broadcastId"))

        val response = session.monitorBroadcastStatus(text(prepared, "previewId"))
        assertTrue("Encrypted final Monitor status was rejected", response.get("ok").asBoolean)
        val result = response.getAsJsonObject("result")
        verifyStatus(prepared, response)
        assertEquals("DISPATCH_AUTHORIZED", text(result, "approval_status"))

        val configured = cfg.getAsJsonArray("endpoints").map { it.asJsonObject }
            .associateBy { text(it, "label") }
        val localEndpoint = text(configured.getValue("recipient-a"), "endpoint_id")
        val remoteEndpoint = text(configured.getValue("recipient-b"), "endpoint_id")
        val preparedOrder = prepared.getAsJsonArray("recipients").map { text(it.asJsonObject, "endpointId") }
        assertEquals(2, preparedOrder.size)
        assertEquals(setOf(localEndpoint, remoteEndpoint), preparedOrder.toSet())
        val recipients = result.getAsJsonArray("recipients").map { it.asJsonObject }
        assertEquals(2, recipients.size)
        recipients.forEachIndexed { ordinal, recipient ->
            assertEquals(ordinal, recipient.get("ordinal").asInt)
            val endpointId = text(recipient, "endpoint_id")
            assertEquals(preparedOrder[ordinal], endpointId)
            assertEquals("ACCEPTED", text(recipient, "state"))
            val expectedEvidence = when (endpointId) {
                localEndpoint -> "NODE_REPORTED"
                remoteEndpoint -> "RELAY_PERSISTED"
                else -> error("Status returned an endpoint outside the consent roster")
            }
            assertEquals(expectedEvidence, text(recipient, "evidence"))
        }

        val afterState = privateSessionState()
        assertEquals(beforeState.get("nextSequence").asLong + 1L, afterState.get("nextSequence").asLong)
        assertFalse("Read-only status must leave no pending request", session.getStatus().has("pendingOperationId"))
        val afterOperation = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { text(it, "operationId") == operationId }
        for (field in listOf("operationId", "previewId", "broadcastId", "groupId", "monitorEndpointId",
                "bodySha256", "snapshotDigest", "consentDigest", "expiresAt", "grantExpiresAt",
                "confirmOperationId")) {
            assertEquals("Monitor metadata changed after status read: $field", beforeOperation.get(field), afterOperation.get(field))
        }
        assertEquals(beforeOperation.get("confirmSequence"), afterOperation.get("confirmSequence"))
        assertEquals(beforeOperation.get("recipientEndpointIds"), afterOperation.get("recipientEndpointIds"))
        assertTrue(afterOperation.get("confirmAttempted").asBoolean)
        assertTrue(afterOperation.get("confirmStatusReconciled").asBoolean)
        record("native_status", JsonObject().apply {
            addProperty("result", "PASS")
            add("status", result)
            addProperty("native_consumption_claimed", false)
        })
        mark("monitor_native_dispatch_status_verified", "true")
    }

    /** Read actual status after native review; this does not submit or recover a write. */
    @Test fun readOriginalBroadcastStatus() {
        val prepared = read("prepared.json")
        val operationId = text(prepared, "operationId")
        val beforeState = privateSessionState()
        assertFalse("No encrypted request may be pending before the read-only status RPC",
            beforeState.has("pending"))
        val beforeOperation = beforeState.getAsJsonArray("monitorOperations")
            .map { it.asJsonObject }.single { text(it, "operationId") == operationId }
        assertEquals(text(prepared, "previewId"), text(beforeOperation, "previewId"))
        assertTrue(beforeOperation.get("confirmAttempted").asBoolean)
        assertTrue(beforeOperation.get("confirmStatusReconciled").asBoolean)
        assertTrue(text(beforeOperation, "confirmOperationId").isNotBlank())
        assertTrue(beforeOperation.get("confirmSequence").asLong > 0L)
        assertTrue(text(beforeOperation, "sealedPayload").isNotBlank())

        val response = session.monitorBroadcastStatus(text(prepared, "previewId"))
        assertTrue("Encrypted Monitor status read was rejected", response.get("ok").asBoolean)
        val result = response.getAsJsonObject("result")
        verifyStatus(prepared, response)

        val afterState = privateSessionState()
        assertEquals(beforeState.get("nextSequence").asLong + 1L, afterState.get("nextSequence").asLong)
        assertFalse("Read-only status must leave no pending request", afterState.has("pending"))
        assertFalse(session.getStatus().has("pendingOperationId"))
        val afterOperation = afterState.getAsJsonArray("monitorOperations")
            .map { it.asJsonObject }.single { text(it, "operationId") == operationId }
        for (field in listOf("operationId", "previewId", "broadcastId", "groupId", "monitorEndpointId",
                "bodySha256", "snapshotDigest", "consentDigest", "expiresAt", "grantExpiresAt",
                "confirmOperationId", "confirmSequence", "sealedPayload", "recipientEndpointIds")) {
            assertEquals("Original Monitor operation changed after status read: $field",
                beforeOperation.get(field), afterOperation.get(field))
        }
        assertTrue(afterOperation.get("confirmAttempted").asBoolean)
        assertTrue(afterOperation.get("confirmStatusReconciled").asBoolean)
        record("native_observed_status", JsonObject().apply {
            addProperty("result", "PASS")
            add("status", result.deepCopy())
            addProperty("native_consumption_claimed", false)
        })
        mark("monitor_observed_approval_status", text(result, "approval_status"))
        mark("monitor_observed_recipient_count", result.getAsJsonArray("recipients").size().toString())
    }

    /** The external loopback proxy must discard this Prepare response after Hub HTTP 200. */
    @Test fun prepareResponseLossKeepsOriginalPacket() {
        val cfg = fixture()
        var lost = false
        try {
            session.monitorBroadcastPrepare(text(cfg, "group_id"), text(cfg, "monitor_endpoint_id"), BODY)
        } catch (_: Exception) {
            lost = true
        }
        assertTrue("Test requires a dropped response, not a successful Prepare", lost)
        val pending = privateSessionState().getAsJsonObject("pending")
        assertEquals("monitor.broadcast_prepare", text(pending, "operation"))
        val packet = text(pending, "packetJson")
        val route = JsonParser.parseString(packet).asJsonObject.getAsJsonObject("route")
        assertEquals(text(pending, "operationId"), text(route, "operation_id"))
        save("prepared.json", JsonObject().apply {
            addProperty("originalOperationId", text(pending, "operationId"))
            addProperty("originalPacketSha256", digest(packet.toByteArray(StandardCharsets.UTF_8)))
            addProperty("originalSequence", route.get("sequence").asLong)
        })
        mark("monitor_lost_prepare_original_packet_retained", "true")
    }

    @Test fun recoverLostPrepareWithoutAnotherOperation() {
        val saved = read("prepared.json")
        val originalId = text(saved, "originalOperationId")
        val pending = privateSessionState().getAsJsonObject("pending")
        assertEquals(originalId, text(pending, "operationId"))
        assertEquals(text(saved, "originalPacketSha256"), digest(text(pending, "packetJson").toByteArray(StandardCharsets.UTF_8)))
        val restoredSession = ClientHubSession(target)
        val prepared = restoredSession.monitorBroadcastRecover(originalId)
        verifyPrepared(fixture(), prepared)
        assertEquals(originalId, text(prepared, "operationId"))
        assertFalse(restoredSession.getStatus().has("pendingOperationId"))
        val after = privateSessionState()
        assertEquals(saved.get("originalSequence").asLong + 1, after.get("nextSequence").asLong)
        save("prepared.json", prepared)
        record("lost_prepare", JsonObject().apply {
            addProperty("result", "PASS")
            addProperty("original_operation_sha256", digest(originalId.toByteArray(StandardCharsets.UTF_8)))
            addProperty("original_packet_sha256", text(saved, "originalPacketSha256"))
            addProperty("original_sequence", saved.get("originalSequence").asLong)
            addProperty("replacement_prepare_created", false)
        })
    }

    /** Offline-before-send recovery may explicitly retry only the retained original packet. */
    @Test fun explicitlyRetryUnreceivedPrepareThenLoseItsResponse() {
        val saved = read("prepared.json")
        val originalSequence = privateSessionState().get("nextSequence").asLong
        try {
            session.recoverPending()
            fail("This fixture requires the Hub to report that it never accepted the request")
        } catch (error: HubSessionException) {
            assertEquals("HTTP_409_RECOVERY_REJECTED", error.errorCode)
        }
        assertTrue(confirm("Retry original encrypted request", "Hub did not accept the saved Prepare. Retry only its original signed ciphertext once?", "Retry original"))
        try {
            session.retryPendingExact()
            fail("The loopback proxy must lose the accepted Prepare response")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        val after = privateSessionState()
        val pending = after.getAsJsonObject("pending")
        assertEquals(originalSequence, after.get("nextSequence").asLong)
        assertEquals(text(saved, "originalOperationId"), text(pending, "operationId"))
        assertEquals(text(saved, "originalPacketSha256"), digest(text(pending, "packetJson").toByteArray(StandardCharsets.UTF_8)))
        mark("monitor_unreceived_prepare_retried_with_original_ciphertext_only", "true")
    }

    /** The proxy must now discard Confirm only; the same verified preview is used. */
    @Test fun confirmResponseLossKeepsOriginalSealedEnvelope() {
        val prepared = read("prepared.json")
        verifyPrepared(fixture(), prepared)
        assertTrue(confirm("Approve Monitor broadcast", "Approve this exact verified preview once?\n\n" +
            BODY + "\nPreview: ${text(prepared, "previewId")}\nRecipients:\n" +
            prepared.getAsJsonArray("recipients").joinToString("\n") { text(it.asJsonObject, "endpointId") }, "Approve broadcast"))
        var lost = false
        try {
            session.monitorBroadcastConfirm(text(prepared, "previewId"), BODY, text(prepared, "consentDigest"))
        } catch (_: Exception) { lost = true }
        assertTrue("Test requires a lost Confirm response", lost)
        val pending = privateSessionState().getAsJsonObject("pending")
        assertEquals("monitor.broadcast_confirm", text(pending, "operation"))
        prepared.addProperty("confirmPacketSha256", digest(text(pending, "packetJson").toByteArray(StandardCharsets.UTF_8)))
        prepared.addProperty("confirmOperationId", text(pending, "operationId"))
        save("prepared.json", prepared)
        mark("monitor_lost_confirm_exact_packet_retained", "true")
    }

    @Test fun recoverLostConfirmAndReadOriginalStatus() {
        val prepared = read("prepared.json")
        val pending = privateSessionState().getAsJsonObject("pending")
        assertEquals(text(prepared, "confirmOperationId"), text(pending, "operationId"))
        assertEquals(text(prepared, "confirmPacketSha256"), digest(text(pending, "packetJson").toByteArray(StandardCharsets.UTF_8)))
        val recovered = ClientHubSession(target).recoverPending()
        assertTrue(recovered.get("ok").asBoolean)
        assertEquals(text(prepared, "previewId"), text(recovered.getAsJsonObject("result"), "preview_id"))
        assertOneConfirmationOnly(prepared)
        val status = session.monitorBroadcastStatus(text(prepared, "previewId"))
        verifyStatus(prepared, status)
        record("lost_confirm", JsonObject().apply {
            addProperty("result", "PASS")
            addProperty("original_operation_sha256", digest(text(prepared, "confirmOperationId").toByteArray(StandardCharsets.UTF_8)))
            addProperty("original_packet_sha256", text(prepared, "confirmPacketSha256"))
            addProperty("replacement_confirmation_created", false)
            add("status", status.getAsJsonObject("result"))
        })
    }

    private fun assertOneConfirmationOnly(prepared: JsonObject) {
        val before = privateSessionState().get("nextSequence").asLong
        try {
            ClientHubSession(target).monitorBroadcastConfirm(text(prepared, "previewId"), BODY,
                text(prepared, "consentDigest"))
            fail("A second confirmation must not be sealed or submitted")
        } catch (error: HubSessionException) {
            assertEquals("MONITOR_CONFIRM_RECOVERY_REQUIRED", error.errorCode)
        }
        assertEquals(before, privateSessionState().get("nextSequence").asLong)
    }

    @Test fun rejectChangedTextAndUnknownPreviewBeforeSending() {
        val cfg = fixture()
        val prepared = session.monitorBroadcastPrepare(text(cfg, "group_id"), text(cfg, "monitor_endpoint_id"), BODY)
        verifyPrepared(cfg, prepared)
        save("negative-preview.json", prepared)
        val sequence = privateSessionState().get("nextSequence").asLong
        for ((preview, body, expected) in listOf(
            Triple(text(prepared, "previewId"), BODY.trim(), "MONITOR_BODY_CHANGED"),
            Triple("preview-not-owned-by-this-device", BODY, "UNKNOWN_MONITOR_PREVIEW"),
        )) {
            try {
                session.monitorBroadcastConfirm(preview, body, text(prepared, "consentDigest"))
                fail("Unreviewed text or a foreign preview must be rejected")
            } catch (error: HubSessionException) {
                assertEquals(expected, error.errorCode)
            }
        }
        assertEquals(sequence, privateSessionState().get("nextSequence").asLong)
        mark("monitor_changed_text_and_unknown_preview_rejected_locally", "true")
    }

    @Test fun capacityReturnsOneBoundedRejectionWithoutRetry() {
        val cfg = fixture()
        var busy = false
        for (index in 0..16) {
            val sequence = privateSessionState().get("nextSequence").asLong
            val response = session.monitorBroadcastPrepare(text(cfg, "group_id"),
                text(cfg, "monitor_endpoint_id"), BODY + "Capacity fixture $index")
            assertEquals("A Prepare call must not silently create another operation", sequence + 1,
                privateSessionState().get("nextSequence").asLong)
            if (response.get("ok")?.asBoolean == false) {
                assertEquals("user-through-Monitor broadcast intake is temporarily busy", text(response, "error"))
                busy = true
                break
            }
            assertTrue(response.get("verified").asBoolean)
        }
        assertTrue("Fixed per-device admission bound was not observed", busy)
        assertFalse(session.getStatus().has("pendingOperationId"))
        mark("monitor_capacity_rejected_without_automatic_retry", "true")
    }

    /** Run before the saved preview expires; changing the permission invalidates its evidence. */
    @Test fun rejectStalePreviewAfterBroadcastPermissionRevoked() {
        val prepared = read("negative-preview.json")
        val membership = monitorMembership(text(prepared, "groupId"), text(prepared, "monitorEndpointId"))
        assertTrue(confirm("Revoke Monitor broadcast", "Revoke message.broadcast for only this membership?\n\n" +
            text(membership, "membership_id"), "Revoke broadcast"))
        rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "membership.set_broadcast_permission")
            add("set_broadcast_permission", JsonObject().apply {
                addProperty("group_id", text(prepared, "groupId"))
                addProperty("membership_id", text(membership, "membership_id"))
                addProperty("enabled", false)
                addProperty("expected_membership_version", membership.get("version").asLong)
            })
        })
        assertFalse(monitorMembership(text(prepared, "groupId"), text(prepared, "monitorEndpointId"))
            .get("broadcast_permission_enabled").asBoolean)
        try {
            session.monitorBroadcastConfirm(text(prepared, "previewId"), BODY, text(prepared, "consentDigest"))
            fail("Changed permission must invalidate the preview before sealing")
        } catch (error: HubSessionException) {
            assertEquals("MONITOR_PREVIEW_REFRESH_FAILED", error.errorCode)
        }
        val metadata = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { text(it, "operationId") == text(prepared, "operationId") }
        assertFalse(metadata.get("confirmAttempted").asBoolean)
        assertFalse(metadata.has("confirmOperationId"))
        mark("monitor_stale_preview_rejected_without_confirmation", "true")
    }

    /** Reconcile an earlier Hub-rejected Confirm without retrying that confirmation. */
    @Test fun reconcileRejectedConfirmationWithAuthoritativeStatus() {
        val preview = read("negative-preview.json")
        val before = privateSessionState().get("nextSequence").asLong
        val status = session.monitorBroadcastStatus(text(preview, "previewId"))
        assertTrue(status.get("ok").asBoolean)
        assertEquals(text(preview, "previewId"), text(status.getAsJsonObject("result"), "preview_id"))
        val operation = session.monitorBroadcastOperations().getAsJsonArray("operations")
            .map { it.asJsonObject }.single { text(it, "operationId") == text(preview, "operationId") }
        assertTrue(operation.get("confirmAttempted").asBoolean)
        assertTrue(operation.get("confirmStatusReconciled").asBoolean)
        assertEquals(before + 1, privateSessionState().get("nextSequence").asLong)
        assertOneConfirmationOnly(preview)
        mark("monitor_rejected_confirmation_status_reconciled_without_resubmission", "true")
    }

    private fun verifyPrepared(cfg: JsonObject, value: JsonObject) {
        assertTrue("Monitor preview must independently verify", value.get("verified").asBoolean)
        assertTrue(value.get("canConfirm").asBoolean)
        assertEquals("PREPARED", text(value, "status"))
        assertEquals(text(cfg, "group_id"), text(value, "groupId"))
        assertEquals(text(cfg, "monitor_endpoint_id"), text(value, "monitorEndpointId"))
        assertEquals(digest(BODY.toByteArray(StandardCharsets.UTF_8)), text(value, "bodySha256"))
        val actual = value.getAsJsonArray("recipients").map { it.asJsonObject }
        val expected = cfg.getAsJsonArray("endpoints").map { text(it.asJsonObject, "endpoint_id") }
            .filter { it != text(cfg, "monitor_endpoint_id") }.sorted()
        assertEquals(expected, actual.map { text(it, "endpointId") })
        assertTrue(actual.size <= 32)
        for (card in actual + value.getAsJsonObject("source")) {
            assertEquals(text(cfg.getAsJsonObject("owner"), "owner_id"), text(card, "ownerId"))
            assertTrue(card.get("membershipRevision").asLong > 0)
            assertTrue(card.get("bindingEpoch").asLong > 0)
        }
        assertFalse(value.toString().contains("native_session_id"))
        assertFalse(value.toString().contains("workspace"))
    }

    private fun verifyStatus(prepared: JsonObject, response: JsonObject) {
        assertTrue(response.get("ok").asBoolean)
        val result = response.getAsJsonObject("result")
        assertEquals(text(prepared, "previewId"), text(result, "preview_id"))
        assertEquals(text(prepared, "broadcastId"), text(result, "broadcast_id"))
        assertEquals(text(prepared, "groupId"), text(result, "group_id"))
        assertTrue(text(result, "approval_status") in setOf("APPROVED", "DISPATCH_AUTHORIZED"))
        val recipients = result.getAsJsonArray("recipients")
        val expectedCount = prepared.getAsJsonArray("recipients").size()
        if (text(result, "approval_status") == "DISPATCH_AUTHORIZED") assertEquals(expectedCount, recipients.size())
        else assertTrue(recipients.size() <= expectedCount)
        val seen = mutableSetOf<Int>()
        recipients.forEach { entry ->
            val recipient = entry.asJsonObject
            val index = recipient.get("ordinal").asInt
            assertTrue(index in 0 until expectedCount && seen.add(index))
            assertEquals(text(prepared.getAsJsonArray("recipients")[index].asJsonObject, "endpointId"), text(recipient, "endpoint_id"))
            assertTrue(text(recipient, "state") in setOf("PENDING", "FAILED", "UNKNOWN", "ACCEPTED"))
        }
    }

    private fun privateSessionState(): JsonObject = JsonParser.parseString(
        File(target.noBackupFilesDir, "client-hub/session-state.json").readText(),
    ).asJsonObject

    private fun record(stage: String, evidence: JsonObject) {
        val current = if (File(directory, "result.json").exists()) read("result.json") else JsonObject()
        current.add(stage, evidence)
        save("result.json", current)
    }

    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun confirm(title: String, details: String, label: String): Boolean {
        val activity = instrumentation.startActivitySync(Intent(target, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        })
        val latch = CountDownLatch(1)
        val accepted = AtomicBoolean(false)
        var dialog: AlertDialog? = null
        instrumentation.runOnMainSync {
            dialog = AlertDialog.Builder(activity).setTitle(title).setMessage(details)
                .setPositiveButton(label) { _, _ -> accepted.set(true); latch.countDown() }
                .setNegativeButton("Cancel") { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }.show()
        }
        mark("confirmation_ready", title)
        return try {
            assertTrue("Explicit Android confirmation timed out", latch.await(180, TimeUnit.SECONDS))
            accepted.get()
        } finally {
            instrumentation.runOnMainSync { dialog?.dismiss(); activity.finish() }
        }
    }

    companion object {
        // Public synthetic input intentionally exercises exact UTF-8 and trailing whitespace.
        private const val BODY = "Monitor acceptance: 中文与 emoji 🙂\nKeep exact trailing spaces.  \n"
    }
}
