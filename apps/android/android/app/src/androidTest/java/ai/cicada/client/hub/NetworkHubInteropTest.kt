package ai.cicada.client.hub

import android.os.Bundle
import android.util.AtomicFile
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/** Phased native Android Client acceptance against an independently pinned disposable ACTIVE Hub. */
@RunWith(AndroidJUnit4::class)
class NetworkHubInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val profiles get() = HubProfileStore(target)
    private val arguments get() = InstrumentationRegistry.getArguments()
    private val runId: String get() = arguments.getString("run_id")
        ?.takeIf { it.matches(Regex("v14-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe v14 run_id is required")
    private val deviceId: String get() = (arguments.getString("device_id") ?: "phone-v14-$runId")
        .takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,160}")) }
        ?: error("A safe device_id is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v14/$runId")

    private fun text(source: JsonObject, field: String): String = source.get(field)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing test adapter field: $field")

    private fun equalIdentity(label: String, expected: String, actual: String) =
        assertTrue("$label differs from the independently supplied scope", expected == actual)

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun activeScope(store: HubProfileStore = profiles): HubProfileStore.Scope {
        val scope = store.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(scope, "profileId"), scope.get("selectionGeneration").asLong)
    }

    private fun save(name: String, value: JsonObject) {
        assertTrue("Private test directory is unavailable", directory.isDirectory || directory.mkdirs())
        val file = AtomicFile(File(directory, name))
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output)
            error("Could not persist bounded test evidence")
        }
        assertTrue(file.baseFile.setReadable(false, false))
        assertTrue(file.baseFile.setReadable(true, true))
        assertTrue(file.baseFile.setWritable(false, false))
        assertTrue(file.baseFile.setWritable(true, true))
    }

    private fun read(name: String): JsonObject = try {
        val file = File(directory, name)
        require(file.length() in 1..MAX_TEST_FILE_BYTES)
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) {
        // Parsing errors must never include a private staged Grant or full fixture in test output.
        error("Cannot parse bounded test adapter file: $name")
    }

    private fun rpc(scope: HubProfileStore.Scope, operation: String,
                    body: JsonObject = JsonObject()): JsonObject = profiles.withActiveScope(scope) { session ->
        val response = session.rpc(operation, body)
        assertTrue("Encrypted $operation was rejected", response.get("ok")?.asBoolean == true)
        response.getAsJsonObject("result")
            ?: error("Encrypted $operation did not return its typed result")
    }

    private fun assertCapabilities(capabilities: JsonObject, ownerId: String) {
        equalIdentity("Authenticated Owner", ownerId, text(capabilities, "owner_id"))
        assertEquals(CONTRACT_REVISION, text(capabilities, "contract_revision"))
        assertEquals(CATALOG_SHA256, text(capabilities, "catalog_sha256"))
        assertTrue("An Owner device role is required", text(capabilities, "role") in setOf("manager", "external"))
        assertTrue("Recovery support is required", capabilities.get("rpc_recovery")?.asBoolean == true)
        val operations = capabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        assertTrue("Encrypted session omitted required operations", operations.containsAll(REQUIRED_OPERATIONS))
    }

    private fun assertTopology(snapshot: JsonObject, ownerId: String, networkId: String): JsonObject {
        assertEquals(2, snapshot.get("contract_version").asInt)
        equalIdentity("Topology Owner", ownerId, text(snapshot, "owner_principal_id"))
        assertEquals("best_effort", text(snapshot, "read_consistency"))
        val networks = snapshot.getAsJsonArray("networks")
        assertTrue("Network projection exceeded its contract bound", networks.size() <= 100)
        assertTrue("Network cutoff must be explicit", snapshot.get("networks_truncated").asJsonPrimitive.isBoolean)
        assertTrue("Enrollment cutoff must be explicit", snapshot.get("network_endpoints_truncated").asJsonPrimitive.isBoolean)
        val selected = networks.map { it.asJsonObject }.filter { text(it, "network_id") == networkId }
        assertEquals("Exactly one explicit Network must be visible", 1, selected.size)
        return selected.single().also {
            assertEquals("ACTIVE", text(it, "state"))
            assertTrue("Disposable Owner must own its selected Network", it.get("can_create_group").asBoolean)
            assertTrue("Network version must be positive", it.get("version").asLong > 0)
        }
    }

    private fun evidence(phase: String, scope: HubProfileStore.Scope): JsonObject = JsonObject().apply {
        addProperty("schema", "cicada.client-network-android-evidence.v1")
        addProperty("phase", phase)
        addProperty("status", "PASS")
        addProperty("contract_revision", CONTRACT_REVISION)
        addProperty("catalog_sha256", CATALOG_SHA256)
        addProperty("profile_id_sha256", digest(scope.profileId))
        addProperty("selection_generation", scope.selectionGeneration)
    }

    private fun mark(phase: String) = instrumentation.sendStatus(0, Bundle().apply {
        putString("network_v14_$phase", "true")
    })

    @Test fun prepareDevice() {
        val scope = activeScope()
        val status = profiles.getStatus(scope)
        assertFalse("Use a new un-enrolled active profile", status.get("enrolled").asBoolean)
        assertFalse("An unresolved enrollment cannot be replaced", status.get("enrollmentRecoveryRequired").asBoolean)
        assertFalse("An unresolved original request cannot be replaced", status.has("pendingOperationId"))
        assertTrue("A fresh profile must be independent of legacy state", scope.profileId != "legacy")
        val public = profiles.withActiveScope(scope) { it.createDeviceIdentity().getAsJsonObject("devicePublicIdentity") }
        val envelope = JsonObject().apply {
            addProperty("schema", "cicada.client-network-device.v1")
            addProperty("device_id", deviceId)
            add("device_public_identity", public)
            addProperty("profile_id", scope.profileId)
        }
        if (File(directory, "device-public.json").exists()) {
            val previous = read("device-public.json")
            equalIdentity("Prepared device identity", text(previous.getAsJsonObject("device_public_identity"), "id"), text(public, "id"))
            equalIdentity("Prepared profile", text(previous, "profile_id"), scope.profileId)
            equalIdentity("Prepared device ID", text(previous, "device_id"), deviceId)
        }
        save("device-public.json", envelope)
        save("prepare-device.redacted.json", evidence("prepareDevice", scope).apply {
            addProperty("device_id_sha256", digest(deviceId))
            addProperty("device_public_identity_sha256", digest(public.toString()))
            addProperty("existing_keys_preserved", true)
            addProperty("enrolled", false)
        })
        mark("device_public_ready")
    }

    @Test fun enrollAndVerifyActiveTopology() {
        val scope = activeScope()
        val prepared = read("device-public.json")
        assertEquals("cicada.client-network-device.v1", text(prepared, "schema"))
        equalIdentity("Prepared profile", text(prepared, "profile_id"), scope.profileId)
        val fixture = read("devfixture.json")
        assertEquals("cicada.client-network-fixture.v1", text(fixture, "schema"))
        // The signed enrollment attempt is durably retained by the product recovery path if HTTP fails.
        assertTrue("Consume private staging before enrollment", File(directory, "devfixture.json").delete())
        equalIdentity("Prepared device ID", text(prepared, "device_id"), text(fixture, "device_id"))
        val ownerId = text(fixture, "owner_id")
        val networkId = text(fixture, "network_id")
        val hubId = text(fixture, "hub_id")
        val base = text(fixture, "base_url")
        val publicCapabilities = profiles.withActiveScope(scope) { session ->
            session.pinHub(base, hubId, fixture.getAsJsonObject("control_public_identity").toString())
            val devicePublic = session.createDeviceIdentity().getAsJsonObject("devicePublicIdentity")
            equalIdentity("Original device key", text(prepared.getAsJsonObject("device_public_identity"), "id"), text(devicePublic, "id"))
            session.enroll(ownerId, text(fixture, "owner_key_id"),
                fixture.getAsJsonObject("owner_public_identity").toString(), text(fixture, "device_id"),
                text(fixture, "owner_device_grant"))
            session.fetchHubMetadata(base).getAsJsonObject("capabilities")
        }
        assertEquals(CONTRACT_REVISION, text(publicCapabilities, "contract_revision"))
        assertEquals(CATALOG_SHA256, text(publicCapabilities, "catalog_sha256"))
        assertTrue(publicCapabilities.get("client_control_pq_e2ee").asBoolean)
        assertTrue(publicCapabilities.get("authenticated_client_session").asBoolean)
        assertFalse(publicCapabilities.get("external_thread_links").asBoolean)
        assertFalse(publicCapabilities.get("status_events").asBoolean)
        val capabilities = rpc(scope, "session.capabilities")
        assertCapabilities(capabilities, ownerId)
        val publicList = if (text(capabilities, "role") == "external") "external_rpc_operations" else "available_rpc_operations"
        assertTrue("Public role catalog omitted operations", publicCapabilities.getAsJsonArray(publicList)
            .map { it.asString }.toSet().containsAll(REQUIRED_OPERATIONS))
        val topology = rpc(scope, "topology.snapshot")
        assertTopology(topology, ownerId, networkId)
        val selection = profiles.setActiveNetwork(networkId, scope)
        val selected = selection.getAsJsonObject("activeScope")
        val newScope = HubProfileStore.Scope(text(selected, "profileId"), selected.get("selectionGeneration").asLong)
        equalIdentity("Network selection profile", scope.profileId, newScope.profileId)
        assertEquals(scope.selectionGeneration + 1, newScope.selectionGeneration)
        try {
            profiles.withActiveScope(scope) { it.getStatus() }
            error("The previous selection generation must be fenced")
        } catch (error: HubSessionException) {
            assertEquals("PROFILE_SELECTION_CHANGED", error.errorCode)
        }
        val reopened = HubProfileStore(target)
        assertTrue("Selected scope must survive a new Store instance", newScope == activeScope(reopened))
        val status = reopened.getStatus(newScope)
        equalIdentity("Persisted explicit Network", networkId, text(status, "activeNetworkId"))
        equalIdentity("Pinned Hub", hubId, text(status, "hubId"))
        equalIdentity("Enrolled Owner", ownerId, text(status, "ownerId"))
        equalIdentity("Enrolled device", text(fixture, "device_id"), text(status, "deviceId"))
        assertTrue(status.get("sessionCapabilitiesReady").asBoolean)
        assertFalse(status.has("pendingOperationId"))
        assertEquals("Three encrypted reads reserve exactly three request sequences", 4L, status.get("nextSequence").asLong)
        save("enroll-topology.redacted.json", evidence("enrollAndVerifyActiveTopology", newScope).apply {
            addProperty("hub_id_sha256", digest(hubId))
            addProperty("owner_id_sha256", digest(ownerId))
            addProperty("device_id_sha256", digest(text(fixture, "device_id")))
            addProperty("network_id_sha256", digest(networkId))
            addProperty("network_count", topology.getAsJsonArray("networks").size())
            addProperty("networks_truncated", topology.get("networks_truncated").asBoolean)
            addProperty("network_endpoints_truncated", topology.get("network_endpoints_truncated").asBoolean)
            addProperty("encrypted_catalog_verified", true)
            addProperty("explicit_network_selection_persisted", true)
            addProperty("old_scope_rejected", true)
            addProperty("private_staging_consumed", true)
            addProperty("next_sequence", status.get("nextSequence").asLong)
            addProperty("pending", false)
        })
        mark("encrypted_active_topology_verified")
    }

    @Test fun createGroupWithinSelectedNetwork() {
        val scope = activeScope()
        val setup = read("enroll-topology.redacted.json")
        equalIdentity("Original profile", text(setup, "profile_id_sha256"), digest(scope.profileId))
        assertEquals(setup.get("selection_generation").asLong, scope.selectionGeneration)
        val before = profiles.getStatus(scope)
        assertTrue("The encrypted session must already be authorized", before.get("remoteEnabled").asBoolean)
        assertFalse("Recover the original pending request first", before.has("pendingOperationId"))
        val networkId = text(before, "activeNetworkId")
        val ownerId = text(before, "ownerId")
        equalIdentity("Original selected Network", text(setup, "network_id_sha256"), digest(networkId))
        equalIdentity("Original Owner", text(setup, "owner_id_sha256"), digest(ownerId))
        equalIdentity("Original Hub", text(setup, "hub_id_sha256"), digest(text(before, "hubId")))
        val startingSequence = before.get("nextSequence").asLong
        val topologyBefore = rpc(scope, "topology.snapshot")
        assertTopology(topologyBefore, ownerId, networkId)
        val name = "Android Network $runId"
        assertFalse("A completed creation must not be repeated as a new operation", topologyBefore.getAsJsonArray("groups")
            .any { text(it.asJsonObject, "name") == name })
        val changed = rpc(scope, "topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("network_id", networkId); addProperty("name", name) })
            })
        })
        assertEquals(2, changed.get("contract_version").asInt)
        assertEquals("group.create", text(changed, "action"))
        assertTrue(changed.get("changed").asBoolean)
        val group = changed.getAsJsonObject("group")
        equalIdentity("Created Group Network", networkId, text(group, "network_id"))
        val groupId = text(group, "group_id")
        val topologyAfter = rpc(scope, "topology.snapshot")
        assertTopology(topologyAfter, ownerId, networkId)
        val authoritative = topologyAfter.getAsJsonArray("groups").map { it.asJsonObject }
            .filter { text(it, "group_id") == groupId }
        assertEquals("Created Group must be uniquely visible in authoritative state", 1, authoritative.size)
        equalIdentity("Authoritative Group Network", networkId, text(authoritative.single(), "network_id"))
        assertTrue("Authoritative Group name differs", text(authoritative.single(), "name") == name)
        val after = profiles.getStatus(scope)
        assertEquals(startingSequence + 3, after.get("nextSequence").asLong)
        assertFalse(after.has("pendingOperationId"))
        save("create-group.redacted.json", evidence("createGroupWithinSelectedNetwork", scope).apply {
            addProperty("network_id_sha256", digest(networkId))
            addProperty("group_id_sha256", digest(groupId))
            addProperty("group_network_authoritatively_verified", true)
            addProperty("groups_before", topologyBefore.getAsJsonArray("groups").size())
            addProperty("groups_after", topologyAfter.getAsJsonArray("groups").size())
            addProperty("starting_sequence", startingSequence)
            addProperty("next_sequence", after.get("nextSequence").asLong)
            addProperty("encrypted_rpc_count", 3)
            addProperty("pending", false)
        })
        mark("selected_network_group_verified")
    }

    companion object {
        private const val CONTRACT_REVISION = "client-hub-v1.4"
        private const val CATALOG_SHA256 = "7a9e42094083d68b34e979aa5898140e862027777962650c8a4b18a323314d54"
        private const val MAX_TEST_FILE_BYTES = 256 * 1024L
        private val REQUIRED_OPERATIONS = setOf("session.capabilities", "topology.snapshot", "topology.apply",
            "network.key_manifest", "network.key_grant", "network.key_status")
    }
}
