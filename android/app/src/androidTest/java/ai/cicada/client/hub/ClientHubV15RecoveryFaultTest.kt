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
import java.lang.reflect.InvocationTargetException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Real Android transport checks; Core exclusively owns each disposable fault ledger. */
@RunWith(AndroidJUnit4::class)
class ClientHubV15RecoveryFaultTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v15-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe v15 run_id is required")
    private val scenario get() = args.getString("scenario")
        ?.takeIf { it in setOf("enrollment", "completed", "processing", "uncertain", "legacy") }
        ?: error("An explicit isolated recovery scenario is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v15/$runId")

    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing bounded test field: $key")

    private fun scope(): HubProfileStore.Scope {
        val current = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(current, "profileId"), current.get("selectionGeneration").asLong)
    }

    private fun state(scope: HubProfileStore.Scope): JsonObject = read(
        File(ClientHubSession.profileDirectory(target, scope.profileId), "session-state.json"),
    )

    private fun read(file: File): JsonObject = try {
        require(file.length() in 1..MAX_BYTES.toLong())
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) {
        error("Could not parse bounded private test state")
    }

    private fun save(name: String, value: JsonObject) {
        check(directory.isDirectory || directory.mkdirs())
        val file = AtomicFile(File(directory, name))
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            error("Could not save bounded recovery evidence")
        }
        check(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true))
        check(file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true))
    }

    private fun hash(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun expect(code: String, action: () -> Unit) {
        try { action(); fail("Expected $code") }
        catch (error: HubSessionException) { assertEquals(code, error.errorCode) }
    }

    private fun requireEnrolled(scope: HubProfileStore.Scope, session: ClientHubSession) {
        val stored = state(scope)
        assertEquals("client-hub-v1.5", text(stored, "validatedContractRevision"))
        assertEquals(CATALOG, text(stored, "validatedCatalogSha256"))
        assertTrue(session.getStatus().get("enrolled").asBoolean)
        assertTrue(session.getStatus().get("sessionCapabilitiesReady").asBoolean)
    }

    @Test fun captureEnrollmentResponseLoss() {
        assertEquals("enrollment", scenario)
        val scope = scope()
        val fixture = read(File(directory, "devfixture.json"))
        assertEquals("cicada.client-v15-fixture.v1", text(fixture, "schema"))
        assertTrue("Consume private staging before HTTP", File(directory, "devfixture.json").delete())
        profiles.withActiveScope(scope) { session ->
            assertFalse(session.getStatus().get("enrolled").asBoolean)
            session.pinHub(text(fixture, "base_url"), text(fixture, "hub_id"),
                fixture.getAsJsonObject("control_public_identity").toString())
            expect("NETWORK_ERROR") {
                session.enroll(text(fixture, "owner_id"), text(fixture, "owner_key_id"),
                    fixture.getAsJsonObject("owner_public_identity").toString(),
                    text(fixture, "device_id"), text(fixture, "owner_device_grant"))
            }
            val original = state(scope).getAsJsonObject("enrollmentAttempt")
            val exactRequest = text(original, "requestJson")
            assertTrue(session.getStatus().get("enrollmentRecoveryRequired").asBoolean)
            expect("ENROLLMENT_RECOVERY_REQUIRED") {
                session.enroll("unused", "unused", "{}", "unused", "unused")
            }
            assertTrue("A second enrollment must preserve the original request",
                exactRequest == text(state(scope).getAsJsonObject("enrollmentAttempt"), "requestJson"))
            save("enrollment-loss.redacted.json", JsonObject().apply {
                addProperty("status", "PASS")
                addProperty("request_sha256", hash(exactRequest))
                addProperty("grant_sha256", text(original, "grantSha256"))
                addProperty("profile_id_sha256", hash(scope.profileId))
                addProperty("pending_enrollment", true)
                addProperty("replacement_refused", true)
            })
        }
    }

    @Test fun recoverExactEnrollment() {
        assertEquals("enrollment", scenario)
        val scope = scope()
        val recorded = read(File(directory, "enrollment-loss.redacted.json"))
        profiles.withActiveScope(scope) { session ->
            val original = state(scope).getAsJsonObject("enrollmentAttempt")
            assertEquals(text(recorded, "request_sha256"), hash(text(original, "requestJson")))
            assertEquals(text(recorded, "grant_sha256"), text(original, "grantSha256"))
            session.recoverEnrollment()
            assertTrue(session.getStatus().get("enrolled").asBoolean)
            assertFalse(session.getStatus().get("enrollmentRecoveryRequired").asBoolean)
            assertFalse(state(scope).has("enrollmentAttempt"))
            assertEquals(1L, session.getStatus().get("nextSequence").asLong)
            val caps = session.rpc("session.capabilities", JsonObject())
            assertTrue(caps.get("ok").asBoolean)
            requireEnrolled(scope, session)
            save("enrollment-recovery.redacted.json", recorded.deepCopy().apply {
                addProperty("pending_enrollment", false)
                addProperty("next_sequence", session.getStatus().get("nextSequence").asLong)
                addProperty("encrypted_capabilities_verified", true)
            })
        }
    }

    @Test fun captureRpcResponseLoss() {
        assertTrue(scenario != "enrollment")
        val scope = scope()
        profiles.withActiveScope(scope) { session ->
            requireEnrolled(scope, session)
            val before = state(scope)
            assertFalse(before.has("pending"))
            val sequence = before.get("nextSequence").asLong
            expect("NETWORK_ERROR") { session.rpc("status.snapshot", JsonObject()) }
            val after = state(scope)
            val original = after.getAsJsonObject("pending")
            val route = ClientWireCrypto.Route.parse(JsonParser.parseString(text(original, "packetJson"))
                .asJsonObject.getAsJsonObject("route"))
            assertEquals("status.snapshot", text(original, "operation"))
            assertTrue(text(original, "operationId") == route.operationId)
            assertEquals(sequence, route.sequence)
            assertEquals(sequence, original.get("sequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + 1,
                original.get("expectedResponseSequence").asLong)
            assertEquals(sequence + 1, after.get("nextSequence").asLong)
            assertPendingUnchanged(scope, session, original, sequence + 1)
            save("rpc-loss.redacted.json", pendingEvidence(original).apply {
                addProperty("status", "PASS")
                addProperty("scenario", scenario)
                addProperty("next_sequence", sequence + 1)
                addProperty("pending", true)
                addProperty("business_write_or_native_dispatch_claimed", false)
            })
        }
    }

    private fun assertPendingUnchanged(scope: HubProfileStore.Scope, session: ClientHubSession,
                                       original: JsonObject, next: Long) {
        assertTrue("Exact original pending packet must survive", original == state(scope).getAsJsonObject("pending"))
        assertEquals(next, session.getStatus().get("nextSequence").asLong)
        expect("PENDING_RECOVERY_REQUIRED") { session.rpc("status.snapshot", JsonObject()) }
        expect("PENDING_RECOVERY_REQUIRED") { session.rpc("topology.apply", JsonObject()) }
        assertTrue("A new operation must not replace the original ciphertext",
            original == state(scope).getAsJsonObject("pending"))
    }

    @Test fun recoverStillProcessing() = recoverConflict("processing", "STILL_PROCESSING")
    @Test fun recoverUnavailable() = recoverConflict("legacy", "RECOVERY_UNAVAILABLE")

    private fun recoverConflict(expectedScenario: String, code: String) {
        assertEquals(expectedScenario, scenario)
        val scope = scope()
        profiles.withActiveScope(scope) { session ->
            requireEnrolled(scope, session)
            val original = state(scope).getAsJsonObject("pending").deepCopy()
            val next = session.getStatus().get("nextSequence").asLong
            expect(code) { session.recoverPending() }
            assertPendingUnchanged(scope, session, original, next)
            assertEquals(code, text(session.getStatus(), "sessionError"))
            if (code == "RECOVERY_UNAVAILABLE") assertTrue(session.getStatus().get("recoveryBlocked").asBoolean)
            save("rpc-recovery.redacted.json", pendingEvidence(original).apply {
                addProperty("status", "PASS"); addProperty("scenario", scenario)
                addProperty("recovery_code", code); addProperty("next_sequence", next)
                addProperty("pending", true); addProperty("original_packet_retained", true)
            })
        }
    }

    @Test fun recoverCompleted() {
        assertEquals("completed", scenario)
        val scope = scope()
        profiles.withActiveScope(scope) { session ->
            requireEnrolled(scope, session)
            val before = state(scope)
            val original = before.getAsJsonObject("pending").deepCopy()
            // A read-only test capture, using the exact production HTTP adapter and original
            // packet, records only hashes. Production recoverPending still authenticates it.
            val raw = invokePrivate(session, "httpJsonRaw", text(before.getAsJsonObject("pin"), "baseUrl"),
                "/v2/client/rpc/recover", text(original, "packetJson"), MAX_BYTES) as String
            val packet = JsonParser.parseString(raw).asJsonObject
            val recovered = session.recoverPending()
            assertTrue(recovered.get("ok").asBoolean)
            assertTrue(text(original, "operationId") == text(recovered, "operationId"))
            val after = state(scope)
            assertFalse(after.has("pending"))
            assertEquals(before.get("nextSequence").asLong, after.get("nextSequence").asLong)
            assertEquals(original.get("expectedResponseSequence").asLong, after.get("lastResponseSequence").asLong)
            expect("NO_PENDING_REQUEST") { session.recoverPending() }
            save("rpc-recovery.redacted.json", pendingEvidence(original).apply {
                addProperty("status", "PASS"); addProperty("scenario", scenario)
                addProperty("recovery_response_sha256", hash(raw))
                addProperty("recovery_envelope_sha256", hash(text(packet, "envelope")))
                addProperty("pending", false); addProperty("next_sequence", after.get("nextSequence").asLong)
                addProperty("transport_authentication_verified", true)
                addProperty("original_http_response_comparison", "Requires independent proxy hash comparison")
            })
        }
    }

    @Test fun recoverSignedUncertain() {
        assertEquals("uncertain", scenario)
        val scope = scope()
        profiles.withActiveScope(scope) { session ->
            requireEnrolled(scope, session)
            val original = state(scope).getAsJsonObject("pending").deepCopy()
            val next = session.getStatus().get("nextSequence").asLong
            val result = session.recoverPending()
            assertFalse(result.get("ok").asBoolean)
            assertEquals("OUTCOME_UNCERTAIN", text(result, "errorCode"))
            assertTrue(text(original, "operationId") == text(result, "operationId"))
            val after = state(scope)
            assertFalse(after.has("pending"))
            assertTrue(original == after.getAsJsonObject("retiredPending"))
            assertEquals(next, after.get("nextSequence").asLong)
            assertEquals(original.get("expectedResponseSequence").asLong, after.get("lastResponseSequence").asLong)
            assertTrue(after.get("uncertainNeedsReconciliation").asBoolean)
            expect("BUSINESS_RECONCILIATION_REQUIRED") { session.rpc("topology.apply", JsonObject()) }
            assertEquals(next, state(scope).get("nextSequence").asLong)
            val authority = session.rpc("status.snapshot", JsonObject())
            assertTrue(authority.get("ok").asBoolean)
            assertFalse(state(scope).get("uncertainNeedsReconciliation").asBoolean)
            assertTrue(original == state(scope).getAsJsonObject("retiredPending"))
            save("rpc-recovery.redacted.json", pendingEvidence(original).apply {
                addProperty("status", "PASS"); addProperty("scenario", scenario)
                addProperty("recovery_code", "OUTCOME_UNCERTAIN"); addProperty("pending", false)
                addProperty("next_sequence", session.getStatus().get("nextSequence").asLong)
                addProperty("retired_original_packet_preserved", true)
                addProperty("authoritative_read_reconciled", true)
                addProperty("network_grant_business_reconciliation_claimed", false)
                addProperty("business_write_or_native_dispatch_claimed", false)
            })
        }
    }

    private fun pendingEvidence(original: JsonObject): JsonObject = JsonObject().apply {
        addProperty("operation_id_sha256", hash(text(original, "operationId")))
        addProperty("packet_sha256", hash(text(original, "packetJson")))
        addProperty("operation", text(original, "operation"))
        addProperty("request_sequence", original.get("sequence").asLong)
        addProperty("expected_response_sequence", original.get("expectedResponseSequence").asLong)
        addProperty("contract_revision", "client-hub-v1.5")
        addProperty("catalog_sha256", CATALOG)
    }

    private fun invokePrivate(session: ClientHubSession, name: String, vararg arguments: Any?): Any? = try {
        ClientHubSession::class.java.declaredMethods.single { it.name == name }.apply { isAccessible = true }
            .invoke(session, *arguments)
    } catch (error: InvocationTargetException) { throw error.targetException }

    companion object {
        private const val CATALOG = "a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68"
        private const val MAX_BYTES = 4 * 1024 * 1024
    }
}
