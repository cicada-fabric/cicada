package ai.cicada.client.hub

import android.util.AtomicFile
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

/** Real v1.6.1 recovery responses from a disposable Core-owned recovery ledger. */
@RunWith(AndroidJUnit4::class)
class ClientHubV16RecoveryFaultTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v16-deterministic-v161-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A bounded v1.6.1 run ID is required")
    private val scenario get() = args.getString("scenario")
        ?.takeIf { it in SCENARIOS }
        ?: error("An isolated v1.6.1 recovery scenario is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v16/$runId")
    private val packetFile get() = File(directory, "recovery-original.packet.private.json")

    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing bounded recovery field: $key")

    private fun scope(): HubProfileStore.Scope {
        val active = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(active, "profileId"), active.get("selectionGeneration").asLong)
    }

    private fun state(scope: HubProfileStore.Scope): JsonObject = read(
        File(ClientHubSession.profileDirectory(target, scope.profileId), "session-state.json"),
    )

    private fun read(file: File): JsonObject = try {
        require(file.length() in 1..MAX_STATE_BYTES.toLong())
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) {
        error("Could not read bounded private recovery state")
    }

    private fun readReceipt(name: String): JsonObject = read(File(directory, name))

    private fun save(name: String, value: JsonObject) {
        require(directory.isDirectory || directory.mkdirs())
        val base = File(directory, name)
        check(!base.exists()) { "Recovery evidence already exists for this isolated run" }
        val file = AtomicFile(base)
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            error("Bounded recovery evidence write failed")
        }
        check(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true))
        check(file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true))
    }

    private fun savePacket(packet: String) {
        check(!packetFile.exists()) { "A recovery packet already exists for this isolated run" }
        val file = AtomicFile(packetFile)
        val output = file.startWrite()
        try {
            output.write(packet.toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            error("Encrypted recovery packet could not be staged privately")
        }
        check(packetFile.setReadable(false, false) && packetFile.setReadable(true, true))
        check(packetFile.setWritable(false, false) && packetFile.setWritable(true, true))
    }

    private fun hash(value: String): String = digest(value.toByteArray(StandardCharsets.UTF_8))

    private fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun requireEnrolledV16(scope: HubProfileStore.Scope, session: ClientHubSession) {
        val stored = state(scope)
        assertEquals(CONTRACT, text(stored, "validatedContractRevision"))
        assertEquals(CATALOG, text(stored, "validatedCatalogSha256"))
        assertTrue(session.getStatus().get("enrolled").asBoolean)
        assertTrue(session.getStatus().get("sessionCapabilitiesReady").asBoolean)
    }

    private fun verifyCapturedPacket(scope: HubProfileStore.Scope, captured: JsonObject): JsonObject {
        val pending = state(scope).getAsJsonObject("pending")
            ?: throw AssertionError("Original encrypted request is not pending")
        val packet = text(pending, "packetJson")
        val route = ClientWireCrypto.Route.parse(
            JsonParser.parseString(packet).asJsonObject.getAsJsonObject("route"),
        )
        assertEquals("status.snapshot", text(pending, "operation"))
        assertEquals(text(captured, "operation_id_sha256"), hash(text(pending, "operationId")))
        assertEquals(text(pending, "operationId"), route.operationId)
        assertEquals(text(pending, "operation"), route.operation)
        assertEquals(pending.get("sequence").asLong, route.sequence)
        assertEquals(text(captured, "packet_sha256"), hash(packet))
        assertEquals(pending.get("sequence").asLong, captured.get("request_sequence").asLong)
        assertEquals(pending.get("expectedResponseSequence").asLong,
            captured.get("expected_response_sequence").asLong)
        assertTrue(packetFile.isFile)
        val staged = packetFile.readBytes()
        assertTrue(staged.size in 1..MAX_PACKET_BYTES)
        assertEquals(staged.size, captured.get("packet_bytes").asInt)
        assertEquals(text(captured, "packet_sha256"), digest(staged))
        assertArrayEquals(packet.toByteArray(StandardCharsets.UTF_8), staged)
        return pending.deepCopy()
    }

    @Test fun prepareRecoveryFault() {
        val scope = scope()
        val status = profiles.getStatus(scope)
        assertTrue(!status.has("pendingOperationId") || status.get("pendingOperationId").isJsonNull ||
            status.get("pendingOperationId").asString.isEmpty())
        assertFalse(status.get("enrollmentRecoveryRequired").asBoolean)
        profiles.withActiveScope(scope) { session -> requireEnrolledV16(scope, session) }
        val stored = state(scope)
        assertFalse(stored.has("pending"))
        assertFalse(stored.get("recoveryBlocked")?.asBoolean == true)
        assertFalse(stored.get("uncertainNeedsReconciliation")?.asBoolean == true)
        assertFalse(packetFile.exists())
        for (name in listOf("recovery-preparation.redacted.json", "recovery-packet.redacted.json",
            "recovery-result.redacted.json")) {
            assertFalse("Stale recovery evidence exists", File(directory, name).exists())
        }
        val hubId = text(status, "hubId")
        val ownerId = text(status, "ownerId")
        val deviceId = text(status, "deviceId")
        save("recovery-preparation.redacted.json", JsonObject().apply {
            addProperty("schema", "cicada.client-v161-recovery-preparation.v1")
            addProperty("result", "PASS")
            addProperty("run_id", runId)
            addProperty("scenario", scenario)
            addProperty("contract_revision", CONTRACT)
            addProperty("catalog_sha256", CATALOG)
            addProperty("hub_id_sha256", hash(hubId))
            addProperty("owner_id_sha256", hash(ownerId))
            addProperty("device_id_sha256", hash(deviceId))
            addProperty("session_epoch", status.get("sessionEpoch").asLong)
            addProperty("next_sequence", status.get("nextSequence").asLong)
            addProperty("last_response_sequence", stored.get("lastResponseSequence").asLong)
            addProperty("enrolled", true)
            addProperty("session_capabilities_ready", true)
            addProperty("pending", false)
        })
    }

    @Test fun captureOriginalPacket() {
        val scope = scope()
        val prepared = readReceipt("recovery-preparation.redacted.json")
        assertEquals("PASS", text(prepared, "result"))
        assertEquals(runId, text(prepared, "run_id"))
        assertEquals(scenario, text(prepared, "scenario"))
        profiles.withActiveScope(scope) { session ->
            requireEnrolledV16(scope, session)
            val before = state(scope)
            assertFalse(before.has("pending"))
            assertEquals(prepared.get("next_sequence").asLong, before.get("nextSequence").asLong)
            assertEquals(prepared.get("last_response_sequence").asLong,
                before.get("lastResponseSequence").asLong)

            try {
                session.rpc("status.snapshot", JsonObject())
                fail("A request without the owned recovery carrier unexpectedly received a response")
            } catch (error: HubSessionException) {
                assertEquals("NETWORK_ERROR", error.errorCode)
            }

            val after = state(scope)
            val pending = after.getAsJsonObject("pending")
                ?: throw AssertionError("The exact encrypted request was not persisted")
            val packet = text(pending, "packetJson")
            assertTrue(packet.toByteArray(StandardCharsets.UTF_8).size in 1..MAX_PACKET_BYTES)
            val route = ClientWireCrypto.Route.parse(
                JsonParser.parseString(packet).asJsonObject.getAsJsonObject("route"),
            )
            assertEquals("status.snapshot", text(pending, "operation"))
            assertEquals(text(pending, "operationId"), route.operationId)
            assertEquals(text(pending, "operation"), route.operation)
            assertEquals(text(prepared, "hub_id_sha256"), hash(route.hubId))
            assertEquals(text(prepared, "owner_id_sha256"), hash(route.ownerId))
            assertEquals(text(prepared, "device_id_sha256"), hash(route.deviceId))
            assertEquals(prepared.get("session_epoch").asLong, route.sessionEpoch)
            assertEquals(before.get("nextSequence").asLong, route.sequence)
            assertEquals(route.sequence, pending.get("sequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + 1,
                pending.get("expectedResponseSequence").asLong)
            assertEquals(route.sequence + 1, after.get("nextSequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong, after.get("lastResponseSequence").asLong)
            savePacket(packet)
            save("recovery-packet.redacted.json", JsonObject().apply {
                addProperty("schema", "cicada.client-v161-recovery-packet.v1")
                addProperty("result", "PASS")
                addProperty("run_id", runId)
                addProperty("scenario", scenario)
                addProperty("contract_revision", CONTRACT)
                addProperty("catalog_sha256", CATALOG)
                addProperty("operation", "status.snapshot")
                addProperty("operation_id_sha256", hash(text(pending, "operationId")))
                addProperty("packet_sha256", hash(packet))
                addProperty("packet_bytes", packet.toByteArray(StandardCharsets.UTF_8).size)
                addProperty("request_sequence", route.sequence)
                addProperty("expected_response_sequence", pending.get("expectedResponseSequence").asLong)
                addProperty("next_sequence", after.get("nextSequence").asLong)
                addProperty("last_response_sequence", after.get("lastResponseSequence").asLong)
                addProperty("pending", true)
                addProperty("original_packet_persisted_before_network_io", true)
            })
        }
    }

    @Test fun recoverAndVerify() {
        val scope = scope()
        val captured = readReceipt("recovery-packet.redacted.json")
        assertEquals("PASS", text(captured, "result"))
        assertEquals(runId, text(captured, "run_id"))
        assertEquals(scenario, text(captured, "scenario"))
        profiles.withActiveScope(scope) { session ->
            requireEnrolledV16(scope, session)
            val original = verifyCapturedPacket(scope, captured)
            val before = state(scope)
            val beforeNext = before.get("nextSequence").asLong
            val expectedResponseSequence = original.get("expectedResponseSequence").asLong
            var recoveryCode = ""
            var followupSnapshot = false

            when (scenario) {
                "processing" -> {
                    expect("STILL_PROCESSING") { session.recoverPending() }
                    recoveryCode = "STILL_PROCESSING"
                    val after = state(scope)
                    assertTrue("Original pending request changed after HTTP 409", original == after.getAsJsonObject("pending"))
                    assertEquals(beforeNext, after.get("nextSequence").asLong)
                    assertEquals(before.get("lastResponseSequence").asLong, after.get("lastResponseSequence").asLong)
                    assertEquals("STILL_PROCESSING", text(session.getStatus(), "sessionError"))
                    expect("PENDING_RECOVERY_REQUIRED") { session.rpc("status.snapshot", JsonObject()) }
                    expect("PENDING_RECOVERY_REQUIRED") { session.rpc("topology.apply", JsonObject()) }
                    assertTrue(original == state(scope).getAsJsonObject("pending"))
                    assertEquals(beforeNext, state(scope).get("nextSequence").asLong)
                }
                "legacy" -> {
                    expect("RECOVERY_UNAVAILABLE") { session.recoverPending() }
                    recoveryCode = "RECOVERY_UNAVAILABLE"
                    val after = state(scope)
                    assertTrue("Original pending request changed after HTTP 409", original == after.getAsJsonObject("pending"))
                    assertEquals(beforeNext, after.get("nextSequence").asLong)
                    assertEquals(before.get("lastResponseSequence").asLong, after.get("lastResponseSequence").asLong)
                    assertTrue(session.getStatus().get("recoveryBlocked").asBoolean)
                    assertEquals("RECOVERY_UNAVAILABLE", text(session.getStatus(), "sessionError"))
                    expect("PENDING_RECOVERY_REQUIRED") { session.rpc("topology.apply", JsonObject()) }
                    assertTrue(original == state(scope).getAsJsonObject("pending"))
                    assertEquals(beforeNext, state(scope).get("nextSequence").asLong)
                }
                "uncertain" -> {
                    val result = session.recoverPending()
                    assertFalse("Uncertain outcome must not claim business success", result.get("ok").asBoolean)
                    assertEquals("OUTCOME_UNCERTAIN", text(result, "errorCode"))
                    assertEquals(text(original, "operationId"), text(result, "operationId"))
                    recoveryCode = "OUTCOME_UNCERTAIN"
                    val afterRecovery = state(scope)
                    assertFalse(afterRecovery.has("pending"))
                    assertEquals(original, afterRecovery.getAsJsonObject("retiredPending"))
                    assertEquals(beforeNext, afterRecovery.get("nextSequence").asLong)
                    assertEquals(expectedResponseSequence, afterRecovery.get("lastResponseSequence").asLong)
                    assertTrue(afterRecovery.get("uncertainNeedsReconciliation").asBoolean)
                    expect("BUSINESS_RECONCILIATION_REQUIRED") { session.rpc("topology.apply", JsonObject()) }
                    assertEquals(beforeNext, state(scope).get("nextSequence").asLong)
                    val authority = session.rpc("status.snapshot", JsonObject())
                    assertTrue(authority.get("ok").asBoolean)
                    val reconciled = state(scope)
                    assertFalse(reconciled.get("uncertainNeedsReconciliation").asBoolean)
                    assertEquals(original, reconciled.getAsJsonObject("retiredPending"))
                    assertEquals(beforeNext + 1, reconciled.get("nextSequence").asLong)
                    assertEquals(expectedResponseSequence + 1, reconciled.get("lastResponseSequence").asLong)
                    followupSnapshot = true
                }
            }

            val finalState = state(scope)
            val pending = finalState.getAsJsonObject("pending")
            if (scenario == "uncertain") assertNull(pending) else assertEquals(original, pending)
            check(packetFile.delete())
            save("recovery-result.redacted.json", JsonObject().apply {
                addProperty("schema", "cicada.client-v161-recovery-result.v1")
                addProperty("result", "PASS")
                addProperty("run_id", runId)
                addProperty("scenario", scenario)
                addProperty("contract_revision", CONTRACT)
                addProperty("catalog_sha256", CATALOG)
                addProperty("operation", "status.snapshot")
                addProperty("operation_id_sha256", text(captured, "operation_id_sha256"))
                addProperty("packet_sha256", text(captured, "packet_sha256"))
                addProperty("request_sequence", captured.get("request_sequence").asLong)
                addProperty("expected_response_sequence", expectedResponseSequence)
                addProperty("recovery_code", recoveryCode)
                addProperty("expected_http_status", if (scenario == "uncertain") 200 else 409)
                addProperty("pending_after_recovery", scenario != "uncertain")
                addProperty("retired_original_packet_preserved", scenario == "uncertain")
                addProperty("authoritative_followup_snapshot", followupSnapshot)
                addProperty("business_write_or_native_dispatch_claimed", false)
                addProperty("on_device_packet_copy_removed", true)
                addProperty("next_sequence_after_followup", finalState.get("nextSequence").asLong)
                addProperty("last_response_sequence_after_followup", finalState.get("lastResponseSequence").asLong)
            })
        }
    }

    private fun expect(code: String, action: () -> Unit) {
        try {
            action()
            fail("Expected recovery refusal: $code")
        } catch (error: HubSessionException) {
            assertEquals(code, error.errorCode)
        }
    }

    companion object {
        private const val CONTRACT = "client-hub-v1.6.1"
        private const val CATALOG = "6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b"
        private const val MAX_STATE_BYTES = 4 * 1024 * 1024
        private const val MAX_PACKET_BYTES = 256 * 1024
        private val SCENARIOS = setOf("processing", "uncertain", "legacy")
    }
}
