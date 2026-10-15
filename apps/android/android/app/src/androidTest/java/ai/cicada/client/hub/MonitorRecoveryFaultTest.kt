package ai.cicada.client.hub

import android.os.Bundle
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

/**
 * Android recovery-layer checks against the disposable fixed-v1.3 fault proxy.
 * The proxy seeds a request ledger but does not dispatch Monitor business work.
 */
@RunWith(AndroidJUnit4::class)
class MonitorRecoveryFaultTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val session get() = ClientHubSession(target)
    private val arguments get() = InstrumentationRegistry.getArguments()
    private val runId get() = arguments.getString("run_id")
        ?.takeIf { it.matches(Regex("monitor-v13-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe Monitor run_id is required")
    private val scenario get() = arguments.getString("scenario")
        ?.takeIf { it in setOf("processing", "uncertain", "legacy") }
        ?: error("A recovery scenario argument is required")
    private val directory get() = File(target.noBackupFilesDir, "monitor-v13/$runId")

    private fun fixture(): JsonObject = JsonParser.parseString(
        File(directory, "fixture.json").readText(StandardCharsets.UTF_8),
    ).asJsonObject.also {
        assertEquals("cicada.client-monitor-fixture.v1", string(it, "schema"))
        assertTrue(string(it.getAsJsonObject("owner"), "owner_id").isNotBlank())
        assertTrue(string(it.getAsJsonObject("hub_identity"), "hub_id").isNotBlank())
    }

    private fun string(source: JsonObject, field: String): String = source.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing fixture or persisted field: $field")

    private fun assertSameText(label: String, expected: String, actual: String) {
        assertTrue(label, expected == actual)
    }

    private fun privateSessionState(): JsonObject = JsonParser.parseString(
        File(target.noBackupFilesDir, "client-hub/session-state.json")
            .readText(StandardCharsets.UTF_8),
    ).asJsonObject

    private fun pending(state: JsonObject = privateSessionState()): JsonObject =
        state.getAsJsonObject("pending")
            ?: error("Expected the original encrypted Monitor Prepare to remain pending")

    private fun operation(operationId: String): JsonObject = session.monitorBroadcastOperations()
        .getAsJsonArray("operations").map { it.asJsonObject }
        .single { string(it, "operationId") == operationId }

    private fun digest(value: String): String = digest(value.toByteArray(StandardCharsets.UTF_8))

    private fun digest(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun mark(name: String, value: String) {
        instrumentation.sendStatus(0, Bundle().apply { putString(name, value) })
    }

    private fun faultGroupId(): String = "synthetic-fault-group-$scenario-$runId"
    private fun faultMonitorId(): String = "synthetic-fault-monitor-$scenario-$runId"

    private fun assertExpectedScenario(expected: String) {
        assertEquals("The isolated core fixture and Android selector must agree", expected, scenario)
        val cfg = fixture()
        val status = session.getStatus()
        assertTrue("A fresh enrolled v1.3 external Owner session is required", status.get("enrolled").asBoolean)
        assertTrue(status.get("pinned").asBoolean)
        assertTrue(status.get("sessionCapabilitiesReady").asBoolean)
        assertEquals(string(cfg.getAsJsonObject("hub_identity"), "hub_id"), string(status, "hubId"))
        assertEquals(string(cfg.getAsJsonObject("owner"), "owner_id"), string(status, "ownerId"))
        assertEquals("external", string(status, "role"))
        val state = privateSessionState()
        assertEquals("client-hub-v1.3", string(state, "validatedContractRevision"))
        assertEquals("808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377",
            string(state, "validatedCatalogSha256"))
    }

    /** Run once per disposable scenario after device enrollment and capabilities setup. */
    @Test fun capturePrepareFaultPendingPacket() {
        assertExpectedScenario(scenario)
        val statusBefore = session.getStatus()
        assertTrue("Each fault scenario starts from a reconciled session", statusBefore.get("remoteEnabled").asBoolean)
        assertFalse("Each fault scenario needs a fresh Android session", statusBefore.has("pendingOperationId"))
        assertTrue(session.monitorBroadcastOperations().getAsJsonArray("operations").isEmpty())
        val requestSequence = statusBefore.get("nextSequence").asLong
        val lastResponseSequence = privateSessionState().get("lastResponseSequence").asLong
        val operationId = "monitor-fault-$scenario-${java.util.UUID.randomUUID()}"
        var lost = false
        try {
            // The fixed test proxy consumes this sealed request into its disposable
            // recovery ledger and deliberately drops the HTTP response before the
            // fixed Hub can dispatch monitor.broadcast_prepare business logic.
            session.monitorBroadcastPrepare(faultGroupId(), faultMonitorId(), TEST_BODY, operationId)
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
            lost = true
        }
        assertTrue("The fixed fault proxy must drop the accepted request response", lost)

        val after = session.getStatus()
        val state = privateSessionState()
        val original = pending(state)
        val packetJson = string(original, "packetJson")
        val route = ClientWireCrypto.Route.parse(
            JsonParser.parseString(packetJson).asJsonObject.getAsJsonObject("route"),
        )
        assertEquals("monitor.broadcast_prepare", string(original, "operation"))
        assertSameText("Original operation identifier changed", operationId, string(original, "operationId"))
        assertSameText("Signed route operation identifier changed", operationId, route.operationId)
        assertEquals("monitor.broadcast_prepare", route.operation)
        assertEquals(requestSequence, original.get("sequence").asLong)
        assertEquals(requestSequence, route.sequence)
        assertEquals(lastResponseSequence + 1, original.get("expectedResponseSequence").asLong)
        assertEquals(requestSequence + 1, after.get("nextSequence").asLong)
        assertEquals(lastResponseSequence, state.get("lastResponseSequence").asLong)
        assertSameText("Session pending operation identifier changed", operationId, string(after, "pendingOperationId"))
        assertEquals("monitor.broadcast_prepare", string(after, "pendingOperation"))

        val metadata = operation(operationId)
        assertEquals("PREPARE_PENDING", string(metadata, "state"))
        assertSameText("Durable Group selector changed", faultGroupId(), string(metadata, "groupId"))
        assertSameText("Durable Monitor selector changed", faultMonitorId(), string(metadata, "monitorEndpointId"))
        assertFalse(metadata.get("confirmAttempted").asBoolean)
        assertFalse(metadata.has("previewId"))
        try {
            session.monitorBroadcastPrepare(faultGroupId(), faultMonitorId(), TEST_BODY)
            fail("A second Prepare must be blocked while the original packet is pending")
        } catch (error: HubSessionException) {
            assertEquals("PENDING_RECOVERY_REQUIRED", error.errorCode)
        }
        val stillPending = pending()
        assertSameText("Exact original ciphertext changed", packetJson, string(stillPending, "packetJson"))
        assertEquals(requestSequence + 1, session.getStatus().get("nextSequence").asLong)

        mark("monitor_prepare_fault_original_operation_sha256", digest(operationId))
        mark("monitor_prepare_fault_original_packet_sha256", digest(packetJson))
        mark("monitor_prepare_fault_request_sequence", requestSequence.toString())
        mark("monitor_prepare_fault_expected_response_sequence", original.get("expectedResponseSequence").asString)
        mark("monitor_prepare_fault_business_dispatch_claimed", "false")
    }

    @Test fun recoverStillProcessing() {
        assertExpectedScenario("processing")
        val before = assertOriginalPreparePending()
        val statusBefore = session.getStatus()
        val nextSequence = statusBefore.get("nextSequence").asLong
        try {
            session.recoverPending()
            fail("Expected the isolated Hub's HTTP 409 STILL_PROCESSING")
        } catch (error: HubSessionException) {
            assertEquals("STILL_PROCESSING", error.errorCode)
        }
        assertExactPendingRetained(before, nextSequence)
        assertEquals("STILL_PROCESSING", string(session.getStatus(), "sessionError"))
        assertBlockedNewPrepare("PENDING_RECOVERY_REQUIRED", before, nextSequence)
        mark("monitor_prepare_recovery_processing", "STILL_PROCESSING")
        mark("monitor_prepare_recovery_original_packet_retained", "true")
        mark("monitor_prepare_recovery_business_dispatch_claimed", "false")
    }

    @Test fun recoverUnavailable() {
        assertExpectedScenario("legacy")
        val before = assertOriginalPreparePending()
        val statusBefore = session.getStatus()
        val nextSequence = statusBefore.get("nextSequence").asLong
        try {
            session.recoverPending()
            fail("Expected HTTP 409 RECOVERY_UNAVAILABLE for the isolated legacy request")
        } catch (error: HubSessionException) {
            assertEquals("RECOVERY_UNAVAILABLE", error.errorCode)
        }
        val after = assertExactPendingRetained(before, nextSequence)
        assertTrue(after.get("recoveryBlocked").asBoolean)
        assertEquals("RECOVERY_UNAVAILABLE", string(after, "sessionError"))
        assertBlockedNewPrepare("PENDING_RECOVERY_REQUIRED", before, nextSequence)
        mark("monitor_prepare_recovery_legacy", "RECOVERY_UNAVAILABLE")
        mark("monitor_prepare_recovery_original_packet_retained", "true")
        mark("monitor_prepare_recovery_business_dispatch_claimed", "false")
    }

    @Test fun recoverSignedUncertain() {
        assertExpectedScenario("uncertain")
        val before = assertOriginalPreparePending()
        val statusBefore = session.getStatus()
        val operationId = string(before, "operationId")
        val packetJson = string(before, "packetJson")
        val requestSequence = before.get("sequence").asLong
        val responseSequence = before.get("expectedResponseSequence").asLong
        val nextSequence = statusBefore.get("nextSequence").asLong

        val recovered = session.recoverPending()
        assertFalse(recovered.get("ok").asBoolean)
        assertEquals("OUTCOME_UNCERTAIN", string(recovered, "errorCode"))
        assertSameText("Recovered operation identifier changed", operationId, string(recovered, "operationId"))
        val afterRecovery = privateSessionState()
        assertFalse("Only a verified signed uncertain response retires transport pending", afterRecovery.has("pending"))
        assertEquals(nextSequence, afterRecovery.get("nextSequence").asLong)
        assertEquals(responseSequence, afterRecovery.get("lastResponseSequence").asLong)
        assertTrue(afterRecovery.get("uncertainNeedsReconciliation").asBoolean)
        assertSameText("Uncertain operation identifier changed", operationId,
            string(afterRecovery, "outcomeUncertainOperationId"))
        val retired = afterRecovery.getAsJsonObject("retiredPending")
            ?: error("The exact original Prepare evidence must remain retired-pending")
        assertEquals("monitor.broadcast_prepare", string(retired, "operation"))
        assertSameText("Retired operation identifier changed", operationId, string(retired, "operationId"))
        assertEquals(requestSequence, retired.get("sequence").asLong)
        assertEquals(responseSequence, retired.get("expectedResponseSequence").asLong)
        assertSameText("Retired exact ciphertext changed", packetJson, string(retired, "packetJson"))
        assertEquals("PREPARE_UNCERTAIN", string(operation(operationId), "state"))

        try {
            session.recoverPending()
            fail("A signed uncertain response consumes its reserved response sequence exactly once")
        } catch (error: HubSessionException) {
            assertEquals("NO_PENDING_REQUEST", error.errorCode)
        }
        val afterDuplicateRecovery = privateSessionState()
        assertEquals(nextSequence, afterDuplicateRecovery.get("nextSequence").asLong)
        assertEquals(responseSequence, afterDuplicateRecovery.get("lastResponseSequence").asLong)
        assertSameText("Retired exact ciphertext changed after duplicate recovery", packetJson,
            string(afterDuplicateRecovery.getAsJsonObject("retiredPending"), "packetJson"))

        val beforeReads = session.getStatus().get("nextSequence").asLong
        try {
            session.monitorBroadcastPrepare(faultGroupId(), faultMonitorId(), TEST_BODY)
            fail("A new Monitor Prepare must be blocked before authoritative read-only reconciliation")
        } catch (error: HubSessionException) {
            assertEquals("BUSINESS_RECONCILIATION_REQUIRED", error.errorCode)
        }
        assertEquals(beforeReads, session.getStatus().get("nextSequence").asLong)

        // The fixture never ran the Monitor business handler, so a Monitor-level
        // broadcast_recover lookup would be outside this test's contract. Only the
        // generic authenticated status snapshot is a valid read-only reconciliation.
        val statusRead = session.rpc("status.snapshot", JsonObject())
        assertTrue("A read-only authenticated status snapshot is allowed after uncertainty", statusRead.get("ok").asBoolean)
        val afterRead = privateSessionState()
        assertFalse(afterRead.get("uncertainNeedsReconciliation").asBoolean)
        assertEquals("PREPARE_UNCERTAIN", string(operation(operationId), "state"))
        assertFalse(operation(operationId).has("previewId"))
        assertSameText("Retired exact ciphertext changed after status read", packetJson,
            string(afterRead.getAsJsonObject("retiredPending"), "packetJson"))

        val afterReadSequence = session.getStatus().get("nextSequence").asLong
        try {
            session.monitorBroadcastPrepare(faultGroupId(), faultMonitorId(), TEST_BODY)
            fail("A status snapshot must not clear unresolved Monitor Prepare metadata")
        } catch (error: HubSessionException) {
            assertEquals("MONITOR_PREPARE_RECOVERY_REQUIRED", error.errorCode)
        }
        assertEquals(afterReadSequence, session.getStatus().get("nextSequence").asLong)
        mark("monitor_prepare_recovery_uncertain", "OUTCOME_UNCERTAIN")
        mark("monitor_prepare_recovery_original_packet_retained", "true")
        mark("monitor_prepare_recovery_monitor_metadata_retained", "PREPARE_UNCERTAIN")
        mark("monitor_prepare_recovery_authoritative_monitor_preview_claimed", "false")
        mark("monitor_prepare_recovery_business_dispatch_claimed", "false")
    }

    private fun assertOriginalPreparePending(): JsonObject {
        val state = privateSessionState()
        val original = pending(state)
        assertEquals("monitor.broadcast_prepare", string(original, "operation"))
        val route = ClientWireCrypto.Route.parse(
            JsonParser.parseString(string(original, "packetJson")).asJsonObject.getAsJsonObject("route"),
        )
        assertEquals("monitor.broadcast_prepare", route.operation)
        assertSameText("Signed route operation identifier changed", string(original, "operationId"), route.operationId)
        assertEquals(original.get("sequence").asLong, route.sequence)
        assertSameText("Session pending operation identifier changed", string(original, "operationId"),
            string(session.getStatus(), "pendingOperationId"))
        assertEquals("PREPARE_PENDING", string(operation(string(original, "operationId")), "state"))
        return original.deepCopy()
    }

    private fun assertExactPendingRetained(before: JsonObject, nextSequence: Long): JsonObject {
        val afterState = privateSessionState()
        val after = pending(afterState)
        assertSameText("Original operation identifier changed", string(before, "operationId"), string(after, "operationId"))
        assertEquals(string(before, "operation"), string(after, "operation"))
        assertEquals(before.get("sequence").asLong, after.get("sequence").asLong)
        assertEquals(before.get("expectedResponseSequence").asLong, after.get("expectedResponseSequence").asLong)
        assertSameText("Exact original ciphertext changed", string(before, "packetJson"), string(after, "packetJson"))
        assertEquals(nextSequence, afterState.get("nextSequence").asLong)
        assertSameText("Session pending operation identifier changed", string(before, "operationId"),
            string(session.getStatus(), "pendingOperationId"))
        return session.getStatus()
    }

    private fun assertBlockedNewPrepare(expectedCode: String, before: JsonObject, nextSequence: Long) {
        try {
            session.monitorBroadcastPrepare(faultGroupId(), faultMonitorId(), TEST_BODY)
            fail("A new Monitor Prepare must not replace an unresolved original packet")
        } catch (error: HubSessionException) {
            assertEquals(expectedCode, error.errorCode)
        }
        assertExactPendingRetained(before, nextSequence)
    }

    companion object {
        /** Synthetic only; the test proxy ledger never reaches Monitor dispatch. */
        private const val TEST_BODY = "Monitor recovery protocol fault fixture; no business dispatch."
    }
}
