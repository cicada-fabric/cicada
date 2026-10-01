package ai.cicada.client.hub

import android.content.Context
import android.content.ContextWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Synthetic local validation only. No Hub, Monitor, native Thread or delegation executes. */
@RunWith(AndroidJUnit4::class)
class RegroupDelegationValidationTest {
    private val now = Instant.parse("2026-10-01T12:00:00Z")

    @Test
    fun exactOwnerScopeAcceptsDistinctAgentPrincipal() {
        val result = checked(proposal())
        assertEquals("agent-a", result.get("principal_id").asString)
        assertEquals("owner-a", result.get("owner_id").asString)
        RegroupDelegationValidation.currentIssue(result, topology(), now)
        val rolesOnlyMonitor = topology().apply {
            getAsJsonArray("memberships")[0].asJsonObject.addProperty("role", "")
        }
        RegroupDelegationValidation.currentIssue(result, rolesOnlyMonitor, now)
        RegroupDelegationValidation.issueExpiry(result, "2026-10-01T12:20:00Z", now)
    }

    @Test
    fun createChildCanUseTheSameSourceAndTargetGroup() {
        val value = proposal().apply { getAsJsonObject("input").apply {
            addProperty("action", "CREATE_CHILD")
            addProperty("target_group_id", "source-a")
            addProperty("expected_target_version", 2)
            addProperty("new_group_name", "Child group")
        } }
        checked(value)
        RegroupDelegationValidation.currentIssue(value, topology(), now)
        rejects { checked(value.deepCopy().apply { getAsJsonObject("input").addProperty("action", "SET_PARENT") }) }
    }

    @Test
    fun foreignOwnerHubNetworkAndExtraFieldsAreRejected() {
        for (field in listOf("hub_id", "owner_id", "proposal_id", "principal_id")) {
            rejects { checked(proposal().apply { addProperty(field, "foreign") }) }
        }
        rejects { checked(proposal().apply { getAsJsonObject("input").addProperty("network_id", "foreign") }) }
        rejects { checked(proposal().apply { addProperty("node_bearer", "SYNTHETIC_FORBIDDEN_FIELD") }) }
        rejects { checked(proposal().apply { addProperty("binding_epoch", 9_007_199_254_740_992L) }) }
    }

    @Test
    fun staleGroupBindingExpiryAndExistingDelegationPreventIssue() {
        for (changed in listOf(
            topology().apply { getAsJsonArray("groups")[0].asJsonObject.addProperty("version", 3) },
            topology().apply { getAsJsonArray("endpoints")[0].asJsonObject.addProperty("binding_epoch", 8) },
            topology().apply { getAsJsonArray("endpoints")[0].asJsonObject.addProperty("binding_status", "revoked") },
        )) rejects { RegroupDelegationValidation.currentIssue(proposal(), changed, now) }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), topology(), now.plusSeconds(7200)) }
        rejects { RegroupDelegationValidation.issueExpiry(proposal(), "2026-10-01T13:01:00Z", now) }
        rejects { RegroupDelegationValidation.issueExpiry(proposal(), "2026-10-01T11:59:00Z", now) }
        rejects { RegroupDelegationValidation.currentIssue(proposal().apply { add("delegation", delegation()) }, topology(), now) }

        val missingTarget = topology().apply { getAsJsonArray("memberships").remove(1) }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), missingTarget, now) }

        val groupsOnlyIsNotMembership = topology().apply {
            getAsJsonArray("memberships").remove(1)
            assertTrue(getAsJsonArray("endpoints")[0].asJsonObject.getAsJsonArray("group_ids")
                .any { it.asString == "target-a" })
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), groupsOnlyIsNotMembership, now) }

        val wrongEndpointPrincipal = topology().apply {
            getAsJsonArray("endpoints")[0].asJsonObject.addProperty("principal_id", "agent-other")
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), wrongEndpointPrincipal, now) }

        val inactiveTarget = topology().apply {
            getAsJsonArray("memberships")[1].asJsonObject.addProperty("status", "revoked")
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), inactiveTarget, now) }

        val invalidTargetVersion = topology().apply {
            getAsJsonArray("memberships")[1].asJsonObject.addProperty("version", 0)
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), invalidTargetVersion, now) }

        val duplicateTarget = topology().apply {
            getAsJsonArray("memberships").add(getAsJsonArray("memberships")[1].deepCopy())
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), duplicateTarget, now) }

        val sourceWithoutMonitorRole = topology().apply {
            getAsJsonArray("memberships")[0].asJsonObject.apply {
                addProperty("role", "member")
                add("roles", JsonParser.parseString("[]").asJsonArray)
            }
        }
        rejects { RegroupDelegationValidation.currentIssue(proposal(), sourceWithoutMonitorRole, now) }
    }

    @Test
    fun delegationRejectsWrongScopeUsesAndCASShape() {
        RegroupDelegationValidation.delegation(delegation(), proposal())
        for (field in listOf("proposal_id", "hub_id", "owner_id", "network_id", "source_group_id", "target_group_id")) {
            rejects { RegroupDelegationValidation.delegation(delegation().apply { addProperty(field, "foreign") }, proposal()) }
        }
        rejects { RegroupDelegationValidation.delegation(delegation().apply { addProperty("max_uses", 2) }, proposal()) }
        rejects { RegroupDelegationValidation.delegation(delegation().apply { addProperty("use_count", 1) }, proposal()) }
        rejects { RegroupDelegationValidation.delegation(delegation().apply { addProperty("version", 0) }, proposal()) }
    }

    @Test
    fun genericBridgeAndUnconfirmedWritesRejectBeforeStoredState() = sandbox { session, file ->
        file.writeText("CORRUPT_SYNTHETIC_STATE")
        val original = file.readBytes()
        for (operation in listOf("topology.regroup_proposal", "topology.delegation_issue", "topology.delegation_revoke")) {
            code("VERIFIED_REGROUP_FLOW_REQUIRED") { session.rpc(operation, JsonObject()) }
        }
        code("EXPLICIT_CONFIRMATION_REQUIRED") { session.issueRegroupDelegation("review", "expiry", false, 1) }
        code("EXPLICIT_CONFIRMATION_REQUIRED") { session.revokeRegroupDelegation("review", "delegation", 1, false, 1) }
        assertArrayEquals(original, file.readBytes())
        assertFalse(File(file.parentFile, "device-key.wrap.json").exists())
    }

    @Test
    fun durableUncertainFenceSurvivesRestartAndGenericReconciliationFlags() = sandbox { session, file ->
        val context = JsonObject().apply {
            addProperty("operation", "topology.delegation_issue")
            for (key in listOf("proposal_id", "hub_id", "owner_id")) add(key, proposal().get(key))
            add("input", proposal().getAsJsonObject("input"))
            add("request", JsonObject().apply { addProperty("proposal_id", "proposal-a"); addProperty("expires_at", "2026-10-01T12:20:00Z"); addProperty("max_uses", 1) })
        }
        val fence = JsonObject().apply {
            addProperty("operation", "topology.delegation_issue")
            addProperty("operationId", "synthetic-original-operation")
            addProperty("sequence", 8)
            addProperty("expectedResponseSequence", 8)
            addProperty("packetJson", "EXACT_SYNTHETIC_ORIGINAL_CIPHERTEXT")
        }
        file.writeText(JsonObject().apply {
            addProperty("nextSequence", 9); addProperty("lastResponseSequence", 8)
            addProperty("uncertainNeedsReconciliation", false)
            add("regroupUncertainPending", fence); add("regroupWriteContext", context)
        }.toString())
        val original = file.readBytes()
        val status = session.getStatus()
        assertTrue(status.get("regroupReconciliationRequired").asBoolean)
        assertEquals("synthetic-original-operation", status.get("regroupUncertainOperationId").asString)
        code("REGROUP_RECONCILIATION_REQUIRED") { session.startNewDeviceEnrollment() }
        code("REGROUP_RECONCILIATION_REQUIRED") { session.ensureProfileRemovable() }
        code("REGROUP_RECONCILIATION_REQUIRED") { session.issueRegroupDelegation("new-review", "expiry", true, 1) }
        code("REGROUP_RECONCILIATION_REQUIRED") { session.revokeRegroupDelegation("new-review", "delegation", 1, true, 1) }
        assertArrayEquals(original, file.readBytes())
    }

    @Test
    fun foregroundInvalidationNeverWaitsForNetworkProcessLock() {
        val acquired = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = Thread {
            ClientHubSession.PROCESS_LOCK.lock()
            try { acquired.countDown(); release.await(5, TimeUnit.SECONDS) }
            finally { ClientHubSession.PROCESS_LOCK.unlock() }
        }
        holder.start()
        try {
            assertTrue(acquired.await(2, TimeUnit.SECONDS))
            val returned = CountDownLatch(1)
            val callback = Thread { ClientHubSession.clearRegroupReviews(); returned.countDown() }
            callback.start()
            assertTrue("Lifecycle callback must not wait for RPC IO", returned.await(1, TimeUnit.SECONDS))
            callback.join(1000)
        } finally { release.countDown(); holder.join(2000) }
    }

    private fun checked(value: JsonObject) = RegroupDelegationValidation.proposal(value, topology(),
        "hub-a", "owner-a", "network-a", "proposal-a")

    private fun proposal() = json("""{"proposal_id":"proposal-a","hub_id":"hub-a","owner_id":"owner-a",
        "endpoint_id":"endpoint-a","principal_id":"agent-a","binding_id":"binding-a","binding_epoch":7,
        "input":{"operation_id":"monitor-operation","network_id":"network-a","source_group_id":"source-a",
        "target_group_id":"target-a","action":"SET_PARENT","expected_source_version":2,"expected_target_version":4},
        "state":"PROPOSED","created_at":"2026-10-01T11:00:00Z","expires_at":"2026-10-01T13:00:00Z"}""")

    private fun topology() = json("""{"contract_version":2,"owner_principal_id":"owner-a","read_consistency":"best_effort",
        "networks":[{"network_id":"network-a","state":"ACTIVE","version":1,"can_create_group":true}],
        "groups":[{"group_id":"source-a","network_id":"network-a","state":"ACTIVE","version":2},
        {"group_id":"target-a","network_id":"network-a","state":"ACTIVE","version":4}],
        "memberships":[{"membership_id":"source-member-a","principal_id":"agent-a","group_id":"source-a",
        "role":"monitor","roles":["monitor"],"broadcast_permission_enabled":false,"status":"active","version":2},
        {"membership_id":"target-member-a","principal_id":"agent-a","group_id":"target-a",
        "role":"member","broadcast_permission_enabled":false,"status":"active","version":1}],
        "endpoints":[{"endpoint_id":"endpoint-a","principal_id":"agent-a","group_ids":["source-a","target-a"],
        "binding_id":"binding-a","binding_epoch":7,"binding_status":"active"}]}""")

    private fun delegation() = json("""{"delegation_id":"delegation-a","proposal_id":"proposal-a","hub_id":"hub-a",
        "owner_id":"owner-a","network_id":"network-a","source_group_id":"source-a","target_group_id":"target-a",
        "action":"SET_PARENT","expected_source_version":2,"expected_target_version":4,"expires_at":"2026-10-01T12:20:00Z",
        "max_uses":1,"use_count":0,"state":"ACTIVE","version":1,"created_at":"2026-10-01T12:00:00Z"}""")

    private fun json(value: String) = JsonParser.parseString(value).asJsonObject
    private fun rejects(action: () -> Unit) { try { action(); fail("Invalid scope accepted") } catch (_: IllegalArgumentException) {} }
    private fun code(expected: String, action: () -> Unit) {
        try { action(); fail("Expected local refusal") } catch (error: HubSessionException) { assertEquals(expected, error.errorCode) }
    }

    private fun sandbox(action: (ClientHubSession, File) -> Unit) {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(base.cacheDir, "regroup-local-${UUID.randomUUID()}").apply { mkdirs() }
        val context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getNoBackupFilesDir(): File = root
        }
        val session = ClientHubSession(context, UUID.randomUUID().toString())
        val file = File(ClientHubSession.profileDirectory(context, session.profileId), "session-state.json")
        try { action(session, file) }
        finally { file.writeText("{}"); session.deleteProfileState(); root.deleteRecursively() }
    }
}
