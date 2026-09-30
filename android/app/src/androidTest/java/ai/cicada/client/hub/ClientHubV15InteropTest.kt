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

/** Phased v1.5 Android acceptance; requires a fresh independently pinned disposable Hub. */
@RunWith(AndroidJUnit4::class)
class ClientHubV15InteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val profiles get() = HubProfileStore(target)
    private val arguments get() = InstrumentationRegistry.getArguments()
    private val runId: String get() = arguments.getString("run_id")
        ?.takeIf { it.matches(Regex("v15-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A safe v15 run_id is required")
    private val deviceId: String get() = (arguments.getString("device_id") ?: "phone-v15-$runId")
        .takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,160}")) }
        ?: error("A safe device_id is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v15/$runId")

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

    private fun assertDeferredConsentRefused(scope: HubProfileStore.Scope, expected: Set<String>) = profiles.withActiveScope(scope) { session ->
        val before = session.getStatus()
        val allowed = before.getAsJsonArray("allowedOperations").map { it.asString }.toSet()
        assertTrue("Local authorization must exactly match the pinned role and implemented operations", allowed == expected)
        assertTrue("Unsupported consent operations must not become locally authorized",
            allowed.intersect(DEFERRED_OPERATIONS).isEmpty())
        val nextSequence = before.get("nextSequence").asLong
        DEFERRED_OPERATIONS.forEach { operation ->
            try {
                session.rpc(operation, JsonObject())
                error("A gated consent operation reached transport")
            } catch (error: HubSessionException) {
                assertEquals("CLIENT_CONSENT_FLOW_UNAVAILABLE", error.errorCode)
            }
            val after = session.getStatus()
            assertEquals("Local consent rejection must not reserve a new sequence", nextSequence,
                after.get("nextSequence").asLong)
            assertFalse("Local rejection must not create pending ciphertext", after.has("pendingOperationId"))
        }
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
        putString("network_v15_$phase", "true")
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
        assertEquals("cicada.client-v15-fixture.v1", text(fixture, "schema"))
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
        verifyActiveTopology(scope, ownerId, networkId, hubId, text(fixture, "device_id"),
            publicCapabilities, "enrollAndVerifyActiveTopology")
    }

    /** Fresh authorized reads after exact enrollment recovery; never repeats registration. */
    @Test fun verifyActiveTopologyAfterRecoveredEnrollment() {
        val scope = activeScope()
        val recovered = read("enrollment-recovery.redacted.json")
        assertEquals("PASS", text(recovered, "status"))
        assertFalse(recovered.get("pending_enrollment").asBoolean)
        val fixture = read("topology-fixture.json")
        assertEquals("cicada.client-v15-topology-fixture.v1", text(fixture, "schema"))
        val status = profiles.getStatus(scope)
        assertTrue(status.get("enrolled").asBoolean)
        assertFalse(status.has("pendingOperationId"))
        equalIdentity("Recovered Hub", text(fixture, "hub_id"), text(status, "hubId"))
        equalIdentity("Recovered Owner", text(fixture, "owner_id"), text(status, "ownerId"))
        equalIdentity("Recovered device", text(fixture, "device_id"), text(status, "deviceId"))
        val publicCapabilities = profiles.withActiveScope(scope) { session ->
            session.fetchHubMetadata(text(status, "baseUrl")).getAsJsonObject("capabilities")
        }
        verifyActiveTopology(scope, text(status, "ownerId"), text(fixture, "network_id"),
            text(status, "hubId"), text(status, "deviceId"), publicCapabilities,
            "verifyActiveTopologyAfterRecoveredEnrollment")
    }

    private fun verifyActiveTopology(scope: HubProfileStore.Scope, ownerId: String,
                                     networkId: String, hubId: String, deviceId: String,
                                     publicCapabilities: JsonObject, phase: String) {
        val startingSequence = profiles.getStatus(scope).get("nextSequence").asLong
        assertEquals(CONTRACT_REVISION, text(publicCapabilities, "contract_revision"))
        assertEquals(CATALOG_SHA256, text(publicCapabilities, "catalog_sha256"))
        assertTrue(publicCapabilities.get("client_control_pq_e2ee").asBoolean)
        assertTrue(publicCapabilities.get("authenticated_client_session").asBoolean)
        assertFalse(publicCapabilities.get("external_thread_links").asBoolean)
        assertFalse(publicCapabilities.get("status_events").asBoolean)
        val advertised = publicCapabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        assertEquals("The fixed public v1.5 catalog must have 46 distinct operations", 46, advertised.size)
        assertTrue("The catalog omitted the new consent operations", advertised.containsAll(DEFERRED_OPERATIONS))
        val capabilities = rpc(scope, "session.capabilities")
        assertCapabilities(capabilities, ownerId)
        val publicList = if (text(capabilities, "role") == "external") "external_rpc_operations" else "available_rpc_operations"
        val publicRole = publicCapabilities.getAsJsonArray(publicList).map { it.asString }.toSet()
        val authenticated = capabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        val expected = IMPLEMENTED_OPERATIONS.intersect(publicRole).intersect(authenticated)
        assertEquals(if (text(capabilities, "role") == "external") 25 else 33, expected.size)
        assertDeferredConsentRefused(scope, expected)
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
        equalIdentity("Enrolled device", deviceId, text(status, "deviceId"))
        assertTrue(status.get("sessionCapabilitiesReady").asBoolean)
        assertFalse(status.has("pendingOperationId"))
        assertEquals("Three encrypted reads reserve exactly three request sequences", startingSequence + 3, status.get("nextSequence").asLong)
        save("enroll-topology.redacted.json", evidence(phase, newScope).apply {
            addProperty("hub_id_sha256", digest(hubId))
            addProperty("owner_id_sha256", digest(ownerId))
            addProperty("device_id_sha256", digest(deviceId))
            addProperty("network_id_sha256", digest(networkId))
            addProperty("network_count", topology.getAsJsonArray("networks").size())
            addProperty("networks_truncated", topology.get("networks_truncated").asBoolean)
            addProperty("network_endpoints_truncated", topology.get("network_endpoints_truncated").asBoolean)
            addProperty("encrypted_catalog_verified", true)
            addProperty("public_catalog_operations", 46)
            addProperty("client_supported_operations", expected.size)
            addProperty("deferred_consent_operations_refused_before_transport", 10)
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

    /** Requires Core's explicit second-Owner fixture, rather than a nonexistent random ID. */
    @Test fun rejectCrossOwnerGroupCreation() {
        val scope = activeScope()
        val supplied = read("permission-network.json")
        assertEquals("cicada.client-v15-permission.v1", text(supplied, "schema"))
        val forbiddenNetwork = text(supplied, "forbidden_network_id")
        assertTrue("Core must identify a real cross-Owner permission fixture",
            supplied.get("cross_owner_network_verified").asBoolean)
        val before = profiles.getStatus(scope)
        val ownerId = text(before, "ownerId")
        equalIdentity("Permission fixture Owner", text(supplied, "owner_id"), ownerId)
        assertTrue("The forbidden Network must differ from the selected authorized scope",
            forbiddenNetwork != text(before, "activeNetworkId"))
        val topology = rpc(scope, "topology.snapshot")
        assertFalse("Foreign Network must not be authorized in this Owner projection",
            topology.getAsJsonArray("networks").any {
                text(it.asJsonObject, "network_id") == forbiddenNetwork
            })
        val sequence = profiles.getStatus(scope).get("nextSequence").asLong
        val name = "Denied Android Group $runId"
        val refused = profiles.withActiveScope(scope) { session ->
            session.rpc("topology.apply", JsonObject().apply {
                addProperty("kind", "group.create")
                add("create_group", JsonObject().apply {
                    add("group", JsonObject().apply {
                        addProperty("network_id", forbiddenNetwork); addProperty("name", name)
                    })
                })
            })
        }
        assertFalse("The authenticated Hub must refuse this cross-Owner operation", refused.get("ok").asBoolean)
        // Ordinary business denial has a free-text error, not a stable wire error code.
        assertTrue("The authenticated denial must contain an error", text(refused, "error").isNotBlank())
        assertFalse("A denial must not supply a successful Group result", refused.has("result"))
        assertEquals(sequence + 1, profiles.getStatus(scope).get("nextSequence").asLong)
        assertFalse(profiles.getStatus(scope).has("pendingOperationId"))
        val authority = rpc(scope, "topology.snapshot")
        assertFalse("A denial cannot appear as successful creation in the current Owner projection",
            authority.getAsJsonArray("groups").any { text(it.asJsonObject, "name") == name })
        assertEquals("The Owner Group projection must remain unchanged",
            topology.getAsJsonArray("groups"), authority.getAsJsonArray("groups"))
        save("permission-denial.redacted.json", evidence("rejectCrossOwnerGroupCreation", scope).apply {
            addProperty("forbidden_network_id_sha256", digest(forbiddenNetwork))
            addProperty("stable_business_error_code", false)
            addProperty("encrypted_hub_denial_verified", true)
            addProperty("current_owner_projection_unchanged", true)
            addProperty("foreign_owner_state_read_claimed", false)
            addProperty("pending", false)
            addProperty("next_sequence", profiles.getStatus(scope).get("nextSequence").asLong)
        })
    }

    companion object {
        private const val CONTRACT_REVISION = "client-hub-v1.5"
        private const val CATALOG_SHA256 = "a6c108afae4823c2551ca1a07f203c751c69359afa05d4c6559daaad255d3e68"
        private val IMPLEMENTED_OPERATIONS = setOf(
            "session.capabilities", "status.snapshot", "status.changes", "goal.lifecycle",
            "topology.snapshot", "topology.apply", "devices.list", "devices.revoke",
            "nodes.preview", "nodes.confirm", "nodes.list", "nodes.revoke",
            "approvals.list", "approvals.decide", "goal.result", "intent.get", "intent.status",
            "intent.list", "intent.submit", "link.list", "link.invite_create", "link.invite_preview",
            "link.invite_accept", "group.key_manifest", "group.key_grant", "group.key_status",
            "network.key_manifest", "network.key_grant", "network.key_status",
            "monitor.broadcast_prepare", "monitor.broadcast_confirm", "monitor.broadcast_status",
            "monitor.broadcast_recover",
        )
        private val DEFERRED_OPERATIONS = setOf(
            "space.foreign_member_admit", "space.foreign_member_revoke", "space.foreign_endpoint_join",
            "space.key_manifest_v2", "space.key_consent_v2", "space.key_admission_v2", "space.key_status_v2",
            "topology.delegation_issue", "topology.delegation_revoke", "topology.regroup_proposal",
        )
        private const val MAX_TEST_FILE_BYTES = 256 * 1024L
        private val REQUIRED_OPERATIONS = setOf("session.capabilities", "topology.snapshot", "topology.apply",
            "network.key_manifest", "network.key_grant", "network.key_status")
    }
}
