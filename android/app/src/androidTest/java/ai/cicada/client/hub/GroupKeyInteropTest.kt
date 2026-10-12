package ai.cicada.client.hub

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.cicadaclient.MainActivity
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Encrypted Group-key integration steps. The Hub, owner signer, and Node stay outside the APK. */
@RunWith(AndroidJUnit4::class)
class GroupKeyInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val session get() = ClientHubSession(instrumentation.targetContext)
    private val arguments get() = InstrumentationRegistry.getArguments()

    private fun argument(name: String): String = arguments.getString(name)
        ?: error("Instrumentation argument $name is required")

    private fun publish(name: String, value: String) {
        instrumentation.sendStatus(0, Bundle().apply { putString(name, value) })
    }

    /** Confirms the pending Node, then creates a fresh Group through encrypted RPC. */
    @Test fun confirmPendingNodeAndCreateGroup() {
        val code = argument("node_user_code")
        val preview = session.rpc("nodes.preview", JsonObject().apply {
            addProperty("user_code", code)
        })
        assertTrue("Encrypted Node preview was rejected", preview.get("ok").asBoolean)
        val node = preview.getAsJsonObject("result")
        val nodeId = node.get("node_id").asString
        val nodeName = node.get("node_name").asString
        val candidateDigest = node.get("candidate_digest").asString
        val candidateVersion = node.get("candidate_version").asLong
        assertTrue(nodeId.isNotBlank())
        assertTrue(nodeName.isNotBlank())
        assertTrue(candidateDigest.matches(Regex("[0-9a-f]{64}")))
        assertTrue(candidateVersion > 0)

        publish("group_key_node_confirmation_required", "true")
        publish("group_key_pending_node_id", nodeId)
        publish("group_key_pending_node_name", nodeName)
        publish("group_key_pending_node_expires_at", node.get("expires_at").asString)
        assertTrue("Operator did not confirm the displayed Node", confirmOnDevice(
            title = "Confirm Node binding",
            action = "Bind this Node to the current owner and Android device?",
            details = listOf(
                "Node ID: $nodeId",
                "Node name: $nodeName",
                "Expires at: ${node.get("expires_at").asString}",
            ),
            positiveLabel = "Confirm Node",
        ))

        val confirmed = session.rpc("nodes.confirm", JsonObject().apply {
            addProperty("user_code", code)
            addProperty("candidate_digest", candidateDigest)
            addProperty("candidate_version", candidateVersion)
        })
        assertTrue("Encrypted Node confirmation was rejected", confirmed.get("ok").asBoolean)
        val binding = confirmed.getAsJsonObject("result")
        assertEquals(nodeId, binding.get("node_id").asString)
        publish("group_key_node_binding_id", binding.get("owner_binding_id").asString)
        publish("group_key_node_state", binding.get("state").asString)

        val groupName = arguments.getString("group_name")
            ?: "Disposable Android Group ${UUID.randomUUID()}"
        assertTrue("Operator did not confirm Group creation", confirmOnDevice(
            title = "Create Group",
            action = "Create this owner-scoped Group for the key-grant validation?",
            details = listOf("Group name: $groupName", "Owner Node: $nodeName ($nodeId)"),
            positiveLabel = "Create Group",
        ))
        val created = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("name", groupName) })
            })
        })
        assertTrue("Encrypted Group creation was rejected", created.get("ok").asBoolean)
        val group = created.getAsJsonObject("result").getAsJsonObject("group")
        val groupId = group.get("group_id").asString
        assertTrue(groupId.isNotBlank())
        publish("group_key_created_group_id", groupId)
        publish("group_key_created_group_name", group.get("name").asString)
    }

    /** Reconciles a Group after a test-runner interruption without repeating Node confirmation. */
    @Test fun findOrCreateFixtureGroup() {
        val name = argument("group_name")
        val snapshot = session.rpc("topology.snapshot", JsonObject())
        assertTrue("Encrypted topology snapshot was rejected", snapshot.get("ok").asBoolean)
        val existing = snapshot.getAsJsonObject("result").getAsJsonArray("groups")
            .map { it.asJsonObject }
            .firstOrNull { it.get("name")?.asString == name }
        if (existing != null) {
            publish("group_key_created_group_id", existing.get("group_id").asString)
            publish("group_key_group_reconciled", "true")
            return
        }
        assertTrue("Operator did not confirm Group creation", confirmOnDevice(
            title = "Create Group",
            action = "Create this owner-scoped Group for the key-grant validation?",
            details = listOf("Group name: $name"),
            positiveLabel = "Create Group",
        ))
        val created = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("name", name) })
            })
        })
        assertTrue("Encrypted Group creation was rejected", created.get("ok").asBoolean)
        publish("group_key_created_group_id", created.getAsJsonObject("result")
            .getAsJsonObject("group").get("group_id").asString)
        publish("group_key_group_reconciled", "false")
    }

    /** Reads the full verified manifest but publishes only public signing/review fields. */
    @Test fun manifestPreview() {
        val result = session.previewGroupKey(
            argument("group_id"), argument("endpoint_id"), argument("owner_key_id"),
        )
        assertTrue("Encrypted group.key_manifest was rejected", result.get("ok").asBoolean)
        assertTrue("Client did not verify the full Endpoint attestation and manifest", result.get("verified").asBoolean)
        val manifest = result.getAsJsonObject("result")
        assertEquals(argument("group_id"), manifest.get("group_id").asString)
        assertEquals(argument("endpoint_id"), manifest.get("endpoint_id").asString)
        assertEquals(argument("owner_key_id"), manifest.get("owner_key_id").asString)
        assertTrue(manifest.get("candidate_attestation").asString.isNotEmpty())

        // The external signer needs only these public claims. Never emit the
        // candidate proof bytes, owner proof, or any private key material.
        for (field in listOf(
            "owner_id", "group_id", "endpoint_id", "node_id", "binding_id",
            "operation", "binding_epoch", "candidate_version", "candidate_key_id",
            "candidate_fingerprint", "candidate_binding_digest", "digest",
            "issued_at", "expires_at",
        )) {
            publish("group_key_manifest_$field", manifest.get(field).asString)
        }
        publish("group_key_manifest_base64", Base64.encodeToString(
            manifest.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP,
        ))
    }

    /**
     * Verifies an externally signed proof, presents its exact current manifest
     * in a real Android dialog, and grants only after an operator taps Approve.
     */
    @Test fun grantCurrentProofAndReadStatus() {
        val groupId = argument("group_id")
        val endpointId = argument("endpoint_id")
        val ownerKeyId = argument("owner_key_id")
        val expectedDigest = argument("expected_digest")
        val signedProof = argument("signed_proof_base64")
        val reviewed = session.previewGroupKeyGrant(
            groupId, endpointId, ownerKeyId, expectedDigest, signedProof,
        )
        assertTrue("Client did not verify the imported proof's manifest", reviewed.get("verified").asBoolean)
        val manifest = reviewed.getAsJsonObject("result")
        assertEquals(groupId, manifest.get("group_id").asString)
        assertEquals(endpointId, manifest.get("endpoint_id").asString)
        assertEquals(expectedDigest, manifest.get("digest").asString)

        publish("group_key_grant_confirmation_required", "true")
        publish("group_key_approval_manifest_digest", expectedDigest)
        assertTrue("Operator did not approve the exact displayed Group grant", confirmOnDevice(
            title = "Approve Group Endpoint key grant",
            action = "Grant this owner key consent for the verified Endpoint candidate?",
            details = listOf(
                "Group ID: ${manifest.get("group_id").asString}",
                "Endpoint ID: ${manifest.get("endpoint_id").asString}",
                "Node ID: ${manifest.get("node_id").asString}",
                "Binding ID: ${manifest.get("binding_id").asString}",
                "Binding epoch: ${manifest.get("binding_epoch").asString}",
                "Candidate key: ${manifest.get("candidate_key_id").asString}",
                "Candidate fingerprint: ${manifest.get("candidate_fingerprint").asString}",
                "Manifest digest: ${manifest.get("digest").asString}",
            ),
            positiveLabel = "Approve key grant",
        ))
        publish("group_key_grant_confirmation_accepted", "true")

        val grant = session.grantGroupKey(groupId, endpointId, ownerKeyId,
            expectedDigest, signedProof)
        assertTrue("Encrypted group.key_grant was rejected", grant.get("ok").asBoolean)
        val status = session.groupKeyStatus(groupId, endpointId)
        assertTrue("Encrypted group.key_status was rejected", status.get("ok").asBoolean)
        val currentStatus = status.getAsJsonObject("result").get("current_status").asString
        assertEquals("CURRENT", currentStatus)
        publish("group_key_grant_status", currentStatus)
        publish("group_key_grant_manifest_digest", expectedDigest)
    }

    /** Tampering with the imported signature is rejected locally before group.key_grant. */
    @Test fun rejectInvalidGroupProof() {
        val proofBytes = Base64.decode(argument("signed_proof_base64"), Base64.NO_WRAP)
        val proof = JsonParser.parseString(String(proofBytes, StandardCharsets.UTF_8)).asJsonObject
        val signature = Base64.decode(proof.get("signature").asString, Base64.NO_WRAP)
        assertTrue(signature.isNotEmpty())
        signature[0] = (signature[0].toInt() xor 1).toByte()
        proof.addProperty("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
        val invalidProof = Base64.encodeToString(
            proof.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP,
        )
        try {
            session.previewGroupKeyGrant(argument("group_id"), argument("endpoint_id"),
                argument("owner_key_id"), argument("expected_digest"), invalidProof)
            fail("Tampered Group owner signature passed local verification")
        } catch (error: HubSessionException) {
            assertEquals("GROUP_OWNER_PROOF_INVALID", error.errorCode)
        }
        assertFalse(session.getStatus().has("pendingOperationId"))
        publish("group_key_invalid_proof_rejected_before_grant", "true")
    }

    /** Wrong key selection is fenced locally; foreign Group/Endpoint reads are sealed rejections. */
    @Test fun rejectWrongOwnerKeyAndEndpointScope() {
        val groupId = argument("group_id")
        val endpointId = argument("endpoint_id")
        val before = session.getStatus().get("nextSequence").asLong
        try {
            session.previewGroupKey(groupId, endpointId,
                "pq1-00000000000000000000000000000000")
            fail("Untrusted owner key selection reached Group manifest flow")
        } catch (error: HubSessionException) {
            assertEquals("OWNER_KEY_ID_MISMATCH", error.errorCode)
        }
        assertEquals(before, session.getStatus().get("nextSequence").asLong)

        val wrongEndpoint = session.groupKeyStatus(groupId,
            "ep_missing_disposable_group_key_scope")
        assertFalse("Wrong Endpoint unexpectedly read a Group key grant",
            wrongEndpoint.get("ok").asBoolean)
        val wrongGroup = session.groupKeyStatus(
            "gr_missing_disposable_other_owner_scope", endpointId)
        assertFalse("Unowned Group unexpectedly read a Group key grant",
            wrongGroup.get("ok").asBoolean)
        assertFalse(session.getStatus().has("pendingOperationId"))
        publish("group_key_wrong_scope_rejected", "true")
    }

    /** Reads Hub authority after an external membership/binding/expiry change. */
    @Test fun readGroupStatusExpectation() {
        val status = session.groupKeyStatus(argument("group_id"), argument("endpoint_id"))
        assertTrue("Encrypted group.key_status was rejected", status.get("ok").asBoolean)
        val actual = status.getAsJsonObject("result").get("current_status").asString
        assertEquals(argument("expected_current_status"), actual)
        publish("group_key_expected_status", actual)
        publish("group_key_status_group_id", argument("group_id"))
        publish("group_key_status_endpoint_id", argument("endpoint_id"))
    }

    /** Policy boundary test: reverse-loopback HTTP requires debug + emulator + high port. */
    @Test fun loopbackHttpRequiresDebugEmulatorAndValidPort() {
        assertTrue(ClientHubSession.isDebugHttpHubAllowed("127.0.0.1", 49152, true, true))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("127.0.0.1", 49152, true, false))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("127.0.0.1", 49152, false, true))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("127.0.0.1", 80, true, true))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("localhost", 49152, true, true))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("0.0.0.0", 49152, true, true))
        assertFalse(ClientHubSession.isDebugHttpHubAllowed("10.0.2.2", 49152, true, true))
        assertTrue(ClientHubSession.isDebugHttpHubAllowed("10.0.2.2", 8787, true, false))
    }

    private fun confirmOnDevice(title: String, action: String, details: List<String>,
                                positiveLabel: String): Boolean {
        val activity = instrumentation.startActivitySync(
            Intent(instrumentation.targetContext, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            },
        )
        val latch = CountDownLatch(1)
        val accepted = AtomicBoolean(false)
        val dialogHolder = arrayOfNulls<AlertDialog>(1)
        instrumentation.runOnMainSync {
            dialogHolder[0] = AlertDialog.Builder(activity)
                .setTitle(title)
                .setMessage(action + "\n\n" + details.joinToString("\n"))
                .setPositiveButton(positiveLabel) { _, _ ->
                    accepted.set(true)
                    latch.countDown()
                }
                .setNegativeButton("Cancel") { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .create()
                .also { it.show() }
        }
        publish("confirmation_ready", "true")
        publish("confirmation_title", title)
        val timeout = arguments.getString("approval_timeout_ms")?.toLongOrNull()
            ?.coerceIn(1_000L, 600_000L) ?: 180_000L
        return try {
            assertTrue("Timed out waiting for an explicit on-device confirmation",
                latch.await(timeout, TimeUnit.MILLISECONDS))
            accepted.get()
        } finally {
            instrumentation.runOnMainSync {
                dialogHolder[0]?.dismiss()
                activity.finish()
            }
        }
    }
}
