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
import java.security.MessageDigest

/** Real encrypted reads against a fresh, independently pinned v1.6 disposable fixture. */
@RunWith(AndroidJUnit4::class)
class ClientHubV16InteropTest {
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v16-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A bounded v16 run ID is required")
    private val deviceId get() = "phone-$runId"
    private val directory get() = File(target.noBackupFilesDir, "network-v16/$runId")
    private fun hash(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun text(value: JsonObject, field: String): String = value.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing bounded fixture field")
    private fun scope(): HubProfileStore.Scope {
        val selected = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(selected, "profileId"), selected.get("selectionGeneration").asLong)
    }
    private fun save(name: String, value: JsonObject) {
        require(directory.isDirectory || directory.mkdirs())
        val file = AtomicFile(File(directory, name))
        val stream = file.startWrite()
        try { stream.write(value.toString().toByteArray(Charsets.UTF_8)); stream.fd.sync(); file.finishWrite(stream) }
        catch (_: Exception) { file.failWrite(stream); error("Bounded evidence write failed") }
        require(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true))
        require(file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true))
    }
    private fun read(name: String): JsonObject = try {
        val file = File(directory, name); require(file.length() in 1..256 * 1024)
        JsonParser.parseString(file.readText(Charsets.UTF_8)).asJsonObject
    } catch (_: Exception) { error("Bounded fixture parsing failed") }
    private fun rpc(scope: HubProfileStore.Scope, operation: String, body: JsonObject = JsonObject()): JsonObject =
        profiles.withActiveScope(scope) { session ->
            val packet = session.rpc(operation, body)
            assertTrue("Encrypted operation refused", packet.get("ok")?.asBoolean == true)
            packet.getAsJsonObject("result") ?: error("Typed operation result missing")
        }
    @Test fun prepareDevice() {
        val scope = scope(); val before = profiles.getStatus(scope)
        assertFalse(before.get("enrolled").asBoolean)
        assertFalse(before.get("enrollmentRecoveryRequired").asBoolean)
        assertFalse(before.has("pendingOperationId"))
        val identity = profiles.withActiveScope(scope) { it.createDeviceIdentity().getAsJsonObject("devicePublicIdentity") }
        save("device-public.json", JsonObject().apply {
            addProperty("schema", "cicada.client-network-device.v1")
            addProperty("device_id", deviceId); addProperty("profile_id", scope.profileId)
            add("device_public_identity", identity)
        })
    }
    @Test fun enrollAndVerifyDirectory() {
        val scope = scope(); val prepared = read("device-public.json"); val fixture = read("devfixture.json")
        assertEquals("cicada.client-v16-fixture.v1", text(fixture, "schema"))
        assertEquals(deviceId, text(prepared, "device_id"))
        assertEquals(scope.profileId, text(prepared, "profile_id"))
        // Product persists the original signed enrollment before dispatch, including response-loss recovery.
        assertTrue(File(directory, "devfixture.json").delete())
        val public = profiles.withActiveScope(scope) { session ->
            session.pinHub(text(fixture, "base_url"), text(fixture, "hub_id"),
                fixture.getAsJsonObject("control_public_identity").toString())
            session.enroll(text(fixture, "owner_id"), text(fixture, "owner_key_id"),
                fixture.getAsJsonObject("owner_public_identity").toString(), deviceId,
                text(fixture, "owner_device_grant"))
            session.fetchHubMetadata(text(fixture, "base_url")).getAsJsonObject("capabilities")
        }
        verifyDirectory(scope, fixture, public)
    }
    @Test fun verifyRecoveredEnrollmentDirectory() {
        val scope = scope()
        val before = profiles.getStatus(scope)
        assertTrue(before.get("enrolled").asBoolean)
        assertFalse(before.get("enrollmentRecoveryRequired").asBoolean)
        val fixture = read("setup-public.json")
        assertEquals(text(fixture, "owner_id"), text(before, "ownerId"))
        assertEquals(text(fixture, "hub_id"), text(before, "hubId"))
        val public = profiles.withActiveScope(scope) {
            it.fetchHubMetadata(text(fixture, "base_url")).getAsJsonObject("capabilities")
        }
        verifyDirectory(scope, fixture, public)
    }
    private fun verifyDirectory(initialScope: HubProfileStore.Scope, fixture: JsonObject, public: JsonObject) {
        var scope = initialScope
        assertEquals("client-hub-v1.6", text(public, "contract_revision"))
        assertEquals(CATALOG, text(public, "catalog_sha256"))
        assertFalse(public.get("external_thread_links").asBoolean)
        assertFalse(public.get("status_events").asBoolean)
        assertEquals(55, public.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet().size)
        val caps = rpc(scope, "session.capabilities")
        assertEquals("client-hub-v1.6", text(caps, "contract_revision"))
        assertEquals(CATALOG, text(caps, "catalog_sha256"))
        assertEquals(text(fixture, "owner_id"), text(caps, "owner_id"))
        val topology = rpc(scope, "topology.snapshot")
        assertEquals(text(fixture, "owner_id"), text(topology, "owner_principal_id"))
        assertTrue(topology.getAsJsonArray("networks").any {
            val card = it.asJsonObject
            text(card, "network_id") == text(fixture, "network_id") && text(card, "state") == "ACTIVE"
        })
        profiles.setActiveNetwork(text(fixture, "network_id"), scope)
        scope = scope()
        val before = profiles.getStatus(scope)
        val allowed = before.getAsJsonArray("allowedOperations").map { it.asString }.toSet()
        assertEquals(if (text(caps, "role") == "external") 27 else 35, allowed.size)
        val sequence = before.get("nextSequence").asLong
        val directoryResult = rpc(scope, "network.directory", JsonObject().apply {
            addProperty("network_id", text(fixture, "network_id")); addProperty("limit", 64)
        })
        assertEquals(text(fixture, "network_id"), text(directoryResult, "network_id"))
        val cards = directoryResult.getAsJsonArray("endpoints")
        assertTrue(cards.size() <= 64)
        cards.forEach { element ->
            val card = element.asJsonObject
            assertEquals(setOf("network_id", "endpoint_id", "alias", "presence"), card.keySet())
            assertEquals(text(fixture, "network_id"), text(card, "network_id"))
        }
        try {
            profiles.withActiveScope(scope) { session -> session.rpc("network.directory", JsonObject().apply {
                addProperty("network_id", text(fixture, "foreign_network_id")); addProperty("limit", 64)
            }) }
            error("Unselected foreign Network reached transport")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_SELECTION_REQUIRED", error.errorCode)
        }
        val after = profiles.getStatus(scope)
        assertEquals(sequence + 3, after.get("nextSequence").asLong)
        assertFalse(after.has("pendingOperationId"))
        save("directory.redacted.json", JsonObject().apply {
            addProperty("result", "PASS"); addProperty("contract_revision", "client-hub-v1.6")
            addProperty("catalog_sha256", CATALOG); addProperty("owner_id_sha256", hash(text(caps, "owner_id")))
            addProperty("network_id_sha256", hash(text(fixture, "network_id")))
            addProperty("role", text(caps, "role")); addProperty("allowed_operations", allowed.size)
            addProperty("public_catalog_operations", 55); addProperty("directory_cards", cards.size())
            addProperty("foreign_network_refused_before_transport", true); addProperty("pending", false)
            addProperty("next_sequence", after.get("nextSequence").asLong)
            addProperty("native_endpoint_authority", "NOT_RUN")
        })
    }
    companion object {
        private const val CATALOG = "1ef2723f2a33d055c9bbfcab922a1084a7a5bda3c32c34b5be520c2db9c5389c"
    }
}
