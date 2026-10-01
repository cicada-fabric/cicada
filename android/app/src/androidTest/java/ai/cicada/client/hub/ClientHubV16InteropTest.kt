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

/** Real encrypted reads against a fresh, independently pinned v1.6.1 disposable fixture. */
@RunWith(AndroidJUnit4::class)
class ClientHubV16InteropTest {
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v16-deterministic-v161-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A bounded v1.6.1 run ID is required")
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
        assertEquals("client-hub-v1.6.1", text(public, "contract_revision"))
        assertEquals(CATALOG, text(public, "catalog_sha256"))
        assertFalse(public.get("external_thread_links").asBoolean)
        assertFalse(public.get("status_events").asBoolean)
        assertEquals(55, public.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet().size)
        val caps = rpc(scope, "session.capabilities")
        assertEquals("client-hub-v1.6.1", text(caps, "contract_revision"))
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
        assertTrue("Product review scope must expose the authenticated enrollment epoch",
            before.get("sessionEpoch").asLong > 0L)
        val allowed = before.getAsJsonArray("allowedOperations").map { it.asString }.toSet()
        assertEquals(if (text(caps, "role") == "external") 30 else 38, allowed.size)
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
            addProperty("result", "PASS"); addProperty("contract_revision", "client-hub-v1.6.1")
            addProperty("catalog_sha256", CATALOG); addProperty("owner_id_sha256", hash(text(caps, "owner_id")))
            addProperty("network_id_sha256", hash(text(fixture, "network_id")))
            addProperty("role", text(caps, "role")); addProperty("allowed_operations", allowed.size)
            addProperty("public_catalog_operations", 55); addProperty("directory_cards", cards.size())
            addProperty("foreign_network_refused_before_transport", true); addProperty("pending", false)
            addProperty("next_sequence", after.get("nextSequence").asLong)
            addProperty("native_endpoint_authority", "NOT_RUN")
        })
    }

    /** Create two same-Owner Groups for a later Core native Endpoint fixture. */
    @Test fun createMonitorFixtureGroups() {
        val scope = scope()
        val status = profiles.getStatus(scope)
        assertTrue("The encrypted session must already be authorized", status.get("remoteEnabled").asBoolean)
        assertFalse("Recover the original pending request first", status.has("pendingOperationId"))
        val ownerId = text(status, "ownerId")
        val hubId = text(status, "hubId")
        val networkId = text(status, "activeNetworkId")
        val fixtureFile = File(directory, "fixture-groups.private.json")

        fun verifySavedFixture(saved: JsonObject) {
            assertEquals(setOf("schema", "run_id", "hub_id", "owner_id", "network_id", "network_version",
                "groups", "device_public_identity_ref"), saved.keySet())
            assertEquals("cicada.client-v161-monitor-groups.v1", text(saved, "schema"))
            assertEquals(runId, text(saved, "run_id"))
            assertEquals(hubId, text(saved, "hub_id"))
            assertEquals(ownerId, text(saved, "owner_id"))
            assertEquals(networkId, text(saved, "network_id"))
            assertTrue(saved.get("network_version").asLong > 0L)
            val refs = saved.getAsJsonArray("groups")
            assertEquals(2, refs.size())
            assertEquals(setOf("monitor_source", "admission_target"), refs.map {
                val ref = it.asJsonObject
                assertEquals(setOf("label", "group_id", "version"), ref.keySet())
                text(ref, "label")
            }.toSet())
            assertEquals(2, refs.map { text(it.asJsonObject, "group_id") }.toSet().size)
            refs.forEach { item ->
                val ref = item.asJsonObject
                assertTrue(ref.get("version").asLong > 0L)
            }
            val deviceRef = saved.getAsJsonObject("device_public_identity_ref")
            assertEquals(setOf("device_id", "device_key_id", "manifest_sha256"), deviceRef.keySet())
            assertEquals(deviceId, text(deviceRef, "device_id"))
            assertTrue(text(deviceRef, "device_key_id").matches(Regex("[A-Za-z0-9_-]{1,256}")))
            assertTrue(text(deviceRef, "manifest_sha256").matches(Regex("[0-9a-f]{64}")))

            val snapshot = rpc(scope, "topology.snapshot")
            assertEquals(ownerId, text(snapshot, "owner_principal_id"))
            val networks = snapshot.getAsJsonArray("networks").map { it.asJsonObject }
                .filter { text(it, "network_id") == networkId }
            assertEquals(1, networks.size)
            assertEquals("ACTIVE", text(networks.single(), "state"))
            val groups = snapshot.getAsJsonArray("groups").map { it.asJsonObject }
            refs.forEach { item ->
                val ref = item.asJsonObject
                val found = groups.filter { text(it, "group_id") == text(ref, "group_id") }
                assertEquals(1, found.size)
                assertEquals("ACTIVE", text(found.single(), "state"))
                assertEquals(networkId, text(found.single(), "network_id"))
                assertEquals(ref.get("version").asLong, found.single().get("version").asLong)
            }
            val prepared = read("device-public.json")
            assertEquals(hash(prepared.toString()), text(deviceRef, "manifest_sha256"))
        }

        if (fixtureFile.exists()) {
            // A retry must verify the prior result without issuing either create again.
            verifySavedFixture(read("fixture-groups.private.json"))
            return
        }

        val prepared = read("device-public.json")
        assertEquals("cicada.client-network-device.v1", text(prepared, "schema"))
        assertEquals(deviceId, text(prepared, "device_id"))
        assertEquals(scope.profileId, text(prepared, "profile_id"))
        val identity = prepared.getAsJsonObject("device_public_identity")
        assertEquals(setOf("id", "kem_public", "signing_public"), identity.keySet())
        val deviceKeyId = text(identity, "id")
        val manifestHash = hash(prepared.toString())

        val suffix = hash(runId).take(12)
        val groupNames = listOf("v16-fixture-$suffix-monitor", "v16-fixture-$suffix-target")
        var snapshot = rpc(scope, "topology.snapshot")
        assertEquals(ownerId, text(snapshot, "owner_principal_id"))
        fun currentNetwork(value: JsonObject): JsonObject {
            val matches = value.getAsJsonArray("networks").map { it.asJsonObject }
                .filter { text(it, "network_id") == networkId }
            assertEquals(1, matches.size)
            val network = matches.single()
            assertEquals("ACTIVE", text(network, "state"))
            assertTrue(network.get("can_create_group").asBoolean)
            assertTrue(network.get("version").asLong > 0L)
            return network
        }
        currentNetwork(snapshot)
        val existingNames = snapshot.getAsJsonArray("groups").map { it.asJsonObject }
            .map { text(it, "name") }.toSet()
        assertTrue("A prior partial fixture must be reconciled before retry", groupNames.none { it in existingNames })

        val created = groupNames.map { name ->
            // group.create has no expected-version field in the v1.6.1 wire contract;
            // capture and recheck the current ACTIVE Network before each exact scoped action.
            snapshot = rpc(scope, "topology.snapshot")
            currentNetwork(snapshot)
            assertEquals(ownerId, text(snapshot, "owner_principal_id"))
            assertFalse(snapshot.getAsJsonArray("groups").map { it.asJsonObject }
                .any { text(it, "name") == name })
            val result = rpc(scope, "topology.apply", JsonObject().apply {
                addProperty("kind", "group.create")
                add("create_group", JsonObject().apply {
                    add("group", JsonObject().apply {
                        addProperty("network_id", networkId)
                        addProperty("name", name)
                    })
                })
            })
            assertEquals(2, result.get("contract_version").asInt)
            assertEquals("group.create", text(result, "action"))
            assertTrue(result.get("changed").asBoolean)
            val group = result.getAsJsonObject("group")
            assertEquals(networkId, text(group, "network_id"))
            assertEquals(name, text(group, "name"))
            assertTrue(group.get("version").asLong > 0L)
            group
        }

        snapshot = rpc(scope, "topology.snapshot")
        assertEquals(ownerId, text(snapshot, "owner_principal_id"))
        val network = currentNetwork(snapshot)
        val authoritativeGroups = snapshot.getAsJsonArray("groups").map { it.asJsonObject }
        val refs = created.mapIndexed { index, result ->
            val id = text(result, "group_id")
            val version = result.get("version").asLong
            val matches = authoritativeGroups.filter { text(it, "group_id") == id }
            assertEquals(1, matches.size)
            val authoritative = matches.single()
            assertEquals("ACTIVE", text(authoritative, "state"))
            assertEquals(networkId, text(authoritative, "network_id"))
            assertEquals(groupNames[index], text(authoritative, "name"))
            assertEquals(version, authoritative.get("version").asLong)
            JsonObject().apply {
                addProperty("label", if (index == 0) "monitor_source" else "admission_target")
                addProperty("group_id", id)
                addProperty("version", version)
            }
        }
        val output = JsonObject().apply {
            addProperty("schema", "cicada.client-v161-monitor-groups.v1")
            addProperty("run_id", runId)
            addProperty("hub_id", hubId)
            addProperty("owner_id", ownerId)
            addProperty("network_id", networkId)
            addProperty("network_version", network.get("version").asLong)
            add("groups", com.google.gson.JsonArray().apply { refs.forEach { add(it) } })
            add("device_public_identity_ref", JsonObject().apply {
                addProperty("device_id", deviceId)
                addProperty("device_key_id", deviceKeyId)
                addProperty("manifest_sha256", manifestHash)
            })
        }
        save("fixture-groups.private.json", output)
        verifySavedFixture(output)
    }

    /** Validate a Core-supplied public Endpoint ID, then make only bounded encrypted reads. */
    @Test fun verifyEndpointPreviewFromPublicFixture() {
        val scope = scope()
        val status = profiles.getStatus(scope)
        assertTrue(status.get("remoteEnabled").asBoolean)
        assertFalse(status.has("pendingOperationId"))
        val ownerId = text(status, "ownerId")
        val hubId = text(status, "hubId")
        val networkId = text(status, "activeNetworkId")
        assertTrue(File(directory, "endpoint-preview-fixture.json").length() in 1..4096)
        val fixture = read("endpoint-preview-fixture.json")
        assertEquals(setOf("hub_id", "owner_id", "network_id", "group_id", "endpoint_id"), fixture.keySet())
        assertEquals(hubId, text(fixture, "hub_id"))
        assertEquals(ownerId, text(fixture, "owner_id"))
        assertEquals(networkId, text(fixture, "network_id"))
        listOf("hub_id", "owner_id", "network_id", "group_id", "endpoint_id").forEach {
            assertTrue("Invalid public fixture selector", text(fixture, it).matches(Regex("[A-Za-z0-9_-]{1,256}")))
        }

        val groupFixture = read("fixture-groups.private.json")
        assertEquals(setOf("schema", "run_id", "hub_id", "owner_id", "network_id", "network_version",
            "groups", "device_public_identity_ref"), groupFixture.keySet())
        assertEquals("cicada.client-v161-monitor-groups.v1", text(groupFixture, "schema"))
        assertEquals(runId, text(groupFixture, "run_id"))
        assertEquals(hubId, text(groupFixture, "hub_id"))
        assertEquals(ownerId, text(groupFixture, "owner_id"))
        assertEquals(networkId, text(groupFixture, "network_id"))
        assertTrue(groupFixture.get("network_version").asLong > 0L)
        val groupRefs = groupFixture.getAsJsonArray("groups").map { it.asJsonObject }
        assertEquals(2, groupRefs.size)
        groupRefs.forEach { ref -> assertEquals(setOf("label", "group_id", "version"), ref.keySet()) }
        val deviceRef = groupFixture.getAsJsonObject("device_public_identity_ref")
        assertEquals(setOf("device_id", "device_key_id", "manifest_sha256"), deviceRef.keySet())
        assertEquals(deviceId, text(deviceRef, "device_id"))
        assertEquals(hash(read("device-public.json").toString()), text(deviceRef, "manifest_sha256"))
        val targetRef = groupRefs.single { text(it, "group_id") == text(fixture, "group_id") }
        assertEquals("admission_target", text(targetRef, "label"))

        val snapshot = rpc(scope, "topology.snapshot")
        assertEquals(ownerId, text(snapshot, "owner_principal_id"))
        val networks = snapshot.getAsJsonArray("networks").map { it.asJsonObject }
            .filter { text(it, "network_id") == networkId }
        assertEquals(1, networks.size)
        assertEquals("ACTIVE", text(networks.single(), "state"))
        assertTrue(networks.single().get("version").asLong > 0L)
        val groups = snapshot.getAsJsonArray("groups").map { it.asJsonObject }
            .filter { text(it, "group_id") == text(fixture, "group_id") }
        assertEquals(1, groups.size)
        val group = groups.single()
        assertEquals("ACTIVE", text(group, "state"))
        assertEquals(networkId, text(group, "network_id"))
        assertTrue(group.get("version").asLong > 0L)
        assertEquals(targetRef.get("version").asLong, group.get("version").asLong)

        val endpoints = snapshot.getAsJsonArray("endpoints").map { it.asJsonObject }
            .filter { text(it, "endpoint_id") == text(fixture, "endpoint_id") }
        assertEquals(1, endpoints.size)
        val endpoint = endpoints.single()
        assertTrue(endpoint.getAsJsonArray("network_ids").map { it.asString }.contains(networkId))
        assertTrue(text(endpoint, "principal_id").isNotBlank())
        // Endpoint principal_id is an Endpoint authority identity; never compare it to Owner Human ID.
        val sourceGroupId = text(groupRefs.single { text(it, "label") == "monitor_source" }, "group_id")
        assertTrue(endpoint.getAsJsonArray("group_ids").map { it.asString }.contains(sourceGroupId))
        assertFalse("Target Group must not already contain the Endpoint", endpoint.getAsJsonArray("group_ids")
            .map { it.asString }.contains(text(fixture, "group_id")))
        val bindingStatus = text(endpoint, "binding_status")
        assertTrue("Current Network enrollment must expose its active native binding",
            text(endpoint, "binding_id").isNotBlank() && endpoint.get("binding_epoch").asLong > 0L &&
                bindingStatus in setOf("active", "leased", "online", "ready", "acquired"))

        val directoryResult = rpc(scope, "network.directory", JsonObject().apply {
            addProperty("network_id", networkId); addProperty("limit", 64)
        })
        val cards = directoryResult.getAsJsonArray("endpoints")
        assertTrue(cards.size() <= 64)
        assertTrue("Directory card is only a reference; topology remains the authority", cards.any { item ->
            val card = item.asJsonObject
            assertEquals(setOf("network_id", "endpoint_id", "alias", "presence"), card.keySet())
            text(card, "network_id") == networkId && text(card, "endpoint_id") == text(fixture, "endpoint_id")
        })

        val preview = rpc(scope, "topology.endpoint_admission_preview", JsonObject().apply {
            addProperty("network_id", networkId)
            addProperty("group_id", text(fixture, "group_id"))
            addProperty("endpoint_id", text(fixture, "endpoint_id"))
        })
        assertEquals(ownerId, text(preview, "owner_principal_id"))
        assertEquals(networkId, text(preview, "network_id"))
        assertEquals(text(fixture, "group_id"), text(preview, "group_id"))
        assertEquals(text(fixture, "endpoint_id"), text(preview, "endpoint_id"))
        assertEquals(networks.single().get("version").asLong, preview.get("network_version").asLong)
        assertEquals(group.get("version").asLong, preview.get("group_version").asLong)
        assertEquals(text(endpoint, "principal_id"), text(preview, "endpoint_principal_id"))
        // Group SessionBinding and NetworkDirectNativeBinding are different
        // authority records. Their IDs/epochs are not required to be equal.
        assertTrue(text(preview, "native_binding_id").isNotBlank())
        assertEquals(false, preview.get("history_included").asBoolean)
        assertEquals(false, preview.get("key_grant_created").asBoolean)
        assertEquals(true, preview.get("existing_thread_memory_retained").asBoolean)
        assertEquals(listOf("member"), preview.getAsJsonArray("admission_roles").map { it.asString })
        assertEquals(0, preview.getAsJsonArray("admission_grants").size())
        assertTrue(preview.get("network_membership_revision").asLong > 0L)
        assertTrue(preview.get("endpoint_network_revision").asLong > 0L)
        assertTrue(preview.get("network_access_epoch").asLong > 0L)
        assertTrue(preview.get("native_binding_epoch").asLong > 0L)

        save("endpoint-preview.redacted.json", JsonObject().apply {
            addProperty("result", "PASS")
            addProperty("owner_id_sha256", hash(ownerId))
            addProperty("network_id_sha256", hash(networkId))
            addProperty("group_id_sha256", hash(text(fixture, "group_id")))
            addProperty("endpoint_id_sha256", hash(text(fixture, "endpoint_id")))
            addProperty("network_version", preview.get("network_version").asLong)
            addProperty("group_version", preview.get("group_version").asLong)
            addProperty("directory_reference_present", true)
            addProperty("history_included", false)
            addProperty("key_grant_created", false)
            addProperty("admission_performed", false)
            addProperty("pending", profiles.getStatus(scope).has("pendingOperationId"))
        })
    }
    companion object {
        private const val CATALOG = "6748449ea6116164a5f3bcd49992bef7c13d6c03e5232a1f050ae0a97377394b"
    }
}
