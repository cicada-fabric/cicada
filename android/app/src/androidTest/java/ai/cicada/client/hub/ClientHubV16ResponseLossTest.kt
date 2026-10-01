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

/** Response-loss recovery against the isolated v1.6.1 public Hub fixture. */
@RunWith(AndroidJUnit4::class)
class ClientHubV16ResponseLossTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v16-deterministic-v161-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A bounded v1.6.1 run_id is required")
    private val scenario get() = args.getString("scenario")
        ?.takeIf { it in setOf("enrollment", "completed") }
        ?: error("An isolated response-loss scenario is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v16/$runId")
    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: error("Missing bounded fixture field")
    private fun scope(): HubProfileStore.Scope {
        val active = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(active, "profileId"), active.get("selectionGeneration").asLong)
    }
    private fun state(scope: HubProfileStore.Scope): JsonObject =
        read(File(ClientHubSession.profileDirectory(target, scope.profileId), "session-state.json"))
    private fun read(file: File): JsonObject = try {
        require(file.length() in 1..MAX_BYTES.toLong())
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) { error("Could not read bounded private Client state") }
    private fun save(name: String, value: JsonObject) {
        check(directory.isDirectory || directory.mkdirs())
        val file = AtomicFile(File(directory, name))
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync(); file.finishWrite(output)
        } catch (_: Exception) { file.failWrite(output); error("Could not save redacted response-loss evidence") }
        check(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true))
        check(file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true))
    }
    private fun hash(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun expect(code: String, action: () -> Unit) { try { action(); fail("Expected recovery refusal") }
        catch (error: HubSessionException) { assertEquals(code, error.errorCode) } }
    private fun enrolled(scope: HubProfileStore.Scope, session: ClientHubSession) {
        val stored = state(scope)
        assertEquals("client-hub-v1.6.1", text(stored, "validatedContractRevision"))
        assertEquals(CATALOG, text(stored, "validatedCatalogSha256"))
        assertTrue(session.getStatus().get("enrolled").asBoolean)
        assertTrue(session.getStatus().get("sessionCapabilitiesReady").asBoolean)
    }
    @Test fun captureEnrollmentResponseLoss() {
        assertEquals("enrollment", scenario)
        val scope = scope()
        val fixtureFile = File(directory, "devfixture.json")
        val fixture = read(fixtureFile)
        assertEquals("cicada.client-v16-fixture.v1", text(fixture, "schema"))
        val publicSetup = fixture.deepCopy().apply { remove("owner_device_grant") }
        assertFalse(publicSetup.has("owner_device_grant"))
        save("setup-public.json", publicSetup)
        assertTrue("Consume private staging before network access", fixtureFile.delete())
        profiles.withActiveScope(scope) { session ->
            assertFalse(session.getStatus().get("enrolled").asBoolean)
            session.pinHub(text(fixture, "base_url"), text(fixture, "hub_id"),
                fixture.getAsJsonObject("control_public_identity").toString())
            expect("NETWORK_ERROR") {
                session.enroll(text(fixture, "owner_id"), text(fixture, "owner_key_id"),
                    fixture.getAsJsonObject("owner_public_identity").toString(),
                    text(fixture, "device_id"), text(fixture, "owner_device_grant"))
            }
            val attempt = state(scope).getAsJsonObject("enrollmentAttempt")
            val exactRequest = text(attempt, "requestJson")
            val grantHash = text(attempt, "grantSha256")
            assertTrue(session.getStatus().get("enrollmentRecoveryRequired").asBoolean)
            expect("ENROLLMENT_RECOVERY_REQUIRED") {
                session.enroll("unused", "unused", "{}", "unused", "unused")
            }
            val preserved = state(scope).getAsJsonObject("enrollmentAttempt")
            val storedRequest = text(preserved, "requestJson")
            assertTrue("Original enrollment bytes changed", exactRequest == storedRequest)
            assertEquals(hash(exactRequest), hash(storedRequest))
            assertEquals(grantHash, text(preserved, "grantSha256"))
            save("enrollment-loss.redacted.json", JsonObject().apply {
                addProperty("status", "PASS"); addProperty("contract_revision", "client-hub-v1.6.1")
                addProperty("catalog_sha256", CATALOG); addProperty("request_sha256", hash(exactRequest))
                addProperty("grant_sha256", grantHash); addProperty("profile_id_sha256", hash(scope.profileId))
                addProperty("pending_enrollment", true); addProperty("replacement_refused", true)
            })
        }
    }
    @Test fun recoverExactEnrollment() {
        assertEquals("enrollment", scenario)
        val scope = scope()
        val evidence = read(File(directory, "enrollment-loss.redacted.json"))
        profiles.withActiveScope(scope) { session ->
            val attempt = state(scope).getAsJsonObject("enrollmentAttempt")
            assertEquals(text(evidence, "request_sha256"), hash(text(attempt, "requestJson")))
            assertEquals(text(evidence, "grant_sha256"), text(attempt, "grantSha256"))
            session.recoverEnrollment()
            assertTrue(session.getStatus().get("enrolled").asBoolean)
            assertFalse(session.getStatus().get("enrollmentRecoveryRequired").asBoolean)
            assertFalse(state(scope).has("enrollmentAttempt"))
            assertEquals(1L, session.getStatus().get("nextSequence").asLong)
            val capabilities = session.rpc("session.capabilities", JsonObject())
            assertTrue(capabilities.get("ok").asBoolean)
            assertEquals("client-hub-v1.6.1", text(capabilities.getAsJsonObject("result"), "contract_revision"))
            assertEquals(CATALOG, text(capabilities.getAsJsonObject("result"), "catalog_sha256"))
            assertEquals(hash(text(read(File(directory, "setup-public.json")), "owner_id")),
                hash(text(capabilities.getAsJsonObject("result"), "owner_id")))
            enrolled(scope, session)
            save("enrollment-recovery.redacted.json", evidence.deepCopy().apply {
                addProperty("pending_enrollment", false)
                addProperty("next_sequence", session.getStatus().get("nextSequence").asLong)
                addProperty("encrypted_capabilities_verified", true)
            })
        }
    }
    @Test fun captureRpcResponseLoss() {
        assertEquals("completed", scenario)
        val scope = scope()
        profiles.withActiveScope(scope) { session ->
            enrolled(scope, session)
            val before = state(scope)
            assertFalse(before.has("pending"))
            val sequence = before.get("nextSequence").asLong
            expect("NETWORK_ERROR") { session.rpc("status.snapshot", JsonObject()) }
            val after = state(scope)
            val pending = after.getAsJsonObject("pending")
            val route = ClientWireCrypto.Route.parse(JsonParser.parseString(text(pending, "packetJson"))
                .asJsonObject.getAsJsonObject("route"))
            assertEquals("status.snapshot", text(pending, "operation"))
            assertEquals(hash(text(pending, "operationId")), hash(route.operationId))
            assertEquals(sequence, route.sequence)
            assertEquals(sequence, pending.get("sequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + 1,
                pending.get("expectedResponseSequence").asLong)
            assertEquals(sequence + 1, after.get("nextSequence").asLong)
            val exactPacket = text(pending, "packetJson")
            val operationId = text(pending, "operationId")
            expect("PENDING_RECOVERY_REQUIRED") { session.rpc("status.snapshot", JsonObject()) }
            val stillPending = state(scope).getAsJsonObject("pending")
            assertEquals(hash(exactPacket), hash(text(stillPending, "packetJson")))
            assertEquals(hash(operationId), hash(text(stillPending, "operationId")))
            save("rpc-loss.redacted.json", JsonObject().apply {
                addProperty("status", "PASS"); addProperty("contract_revision", "client-hub-v1.6.1")
                addProperty("catalog_sha256", CATALOG); addProperty("operation", "status.snapshot")
                addProperty("operation_id_sha256", hash(operationId)); addProperty("packet_sha256", hash(exactPacket))
                addProperty("request_sequence", sequence); addProperty("expected_response_sequence",
                    pending.get("expectedResponseSequence").asLong)
                addProperty("next_sequence", sequence + 1); addProperty("pending", true)
                addProperty("replacement_refused", true)
            })
        }
    }
    @Test fun recoverCompleted() {
        assertEquals("completed", scenario)
        val scope = scope()
        val evidence = read(File(directory, "rpc-loss.redacted.json"))
        profiles.withActiveScope(scope) { session ->
            enrolled(scope, session)
            val before = state(scope)
            val original = before.getAsJsonObject("pending").deepCopy()
            val originalPacket = text(original, "packetJson")
            val beforeNext = before.get("nextSequence").asLong
            assertEquals(text(evidence, "packet_sha256"), hash(originalPacket))
            assertEquals(text(evidence, "operation_id_sha256"), hash(text(original, "operationId")))
            assertEquals("status.snapshot", text(original, "operation"))
            assertEquals(beforeNext, original.get("sequence").asLong + 1)
            val recovered = session.recoverPending()
            assertTrue(recovered.get("ok").asBoolean)
            assertEquals(hash(text(original, "operationId")), hash(text(recovered, "operationId")))
            val after = state(scope)
            assertFalse(after.has("pending"))
            assertEquals(beforeNext, after.get("nextSequence").asLong)
            assertEquals(original.get("expectedResponseSequence").asLong,
                after.get("lastResponseSequence").asLong)
            assertFalse(session.getStatus().has("pendingOperationId"))
            save("rpc-recovery.redacted.json", evidence.deepCopy().apply {
                addProperty("pending", false); addProperty("next_sequence", after.get("nextSequence").asLong)
                addProperty("transport_signature_and_decryption_verified", true)
                addProperty("original_packet_retained_until_recovery", true)
            })
        }
    }
    companion object {
        private const val CATALOG = "6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b"
        private const val MAX_BYTES = 4 * 1024 * 1024
    }
}
