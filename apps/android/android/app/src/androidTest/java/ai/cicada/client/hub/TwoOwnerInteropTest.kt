package ai.cicada.client.hub

import android.app.AlertDialog
import android.content.Context
import android.content.ContextWrapper
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
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Two synthetic external Owners against a disposable fixed-contract Hub.
 * Context roots isolate journals and PQ identities but share the app UID and Keystore wrapping
 * alias. This verifies protocol authorization, not OS-level key isolation.
 */
@RunWith(AndroidJUnit4::class)
class TwoOwnerInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext
    private val arguments get() = InstrumentationRegistry.getArguments()

    private fun publish(name: String, value: String) {
        instrumentation.sendStatus(0, Bundle().apply { putString(name, value) })
    }

    private fun runId(): String = arguments.getString("run_id")
        ?.takeIf { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9_-]{0,95}")) }
        ?: error("A safe run_id instrumentation argument is required")

    private fun runRoot(): File = File(target.noBackupFilesDir,
        "cicada-two-owner/${runId()}")

    private fun contextFor(label: String): OwnerContext = OwnerContext(
        target, File(runRoot(), label),
    )

    private fun sessionFor(label: String): ClientHubSession = ClientHubSession(contextFor(label))

    private fun fixture(): JsonObject {
        val file = File(runRoot(), "fixture.json")
        assertTrue("Public two-owner fixture is missing", file.isFile)
        val value = parseJson(file)
        assertEquals("cicada.client-two-owner-acceptance.v1", string(value, "schema"))
        return value
    }

    private fun owner(fixture: JsonObject, name: String): JsonObject =
        fixture.getAsJsonObject("owners")?.getAsJsonObject(name)
            ?: error("Public fixture omits Owner $name")

    private fun publicDeviceIdentities(): JsonObject {
        val file = File(runRoot(), "device-publics.json")
        assertTrue("Generated public device identities are missing", file.isFile)
        val value = parseJson(file)
        assertEquals("cicada.client-two-owner-device-publics.v1", string(value, "schema"))
        return value
    }

    private fun publicManifest(name: String): JsonObject {
        val file = File(runRoot(), "manifests.json")
        assertTrue("Verified public Group manifests are missing", file.isFile)
        val root = parseJson(file)
        assertEquals("cicada.client-two-owner-manifests.v1", string(root, "schema"))
        return root.getAsJsonObject(name)
    }

    private fun readResult(): JsonObject {
        val file = File(runRoot(), "result.json")
        return if (file.isFile) parseJson(file) else JsonObject()
    }

    private fun writeResult(stage: String, result: JsonObject) {
        val root = readResult()
        root.add(stage, result)
        writeJson(File(runRoot(), "result.json"), root)
    }

    /** Makes three distinct PQ identities; private bytes stay Keystore-wrapped in isolated roots. */
    @Test fun prepareTwoOwnerDeviceKeys() {
        val root = runRoot()
        assertTrue("Could not create private test root", root.exists() || root.mkdirs())
        val identities = JsonObject()
        for (label in listOf("A", "A_admin", "B")) {
            val context = contextFor(label)
            val wrappedKey = File(File(context.noBackupFilesDir, "client-hub"), "device-key.wrap.json")
            assertFalse("Run ID already has a generated device identity", wrappedKey.exists())
            val result = ClientHubSession(context).createDeviceIdentity()
            identities.add(label, result.getAsJsonObject("devicePublicIdentity"))
        }
        val ids = listOf("A", "A_admin", "B").map {
            string(identities.getAsJsonObject(it), "id")
        }
        assertEquals("Each isolated device needs its own PQ public identity", ids.size, ids.toSet().size)
        identities.addProperty("schema", "cicada.client-two-owner-device-publics.v1")
        writeJson(File(root, "device-publics.json"), identities)
        publish("two_owner_device_keys_prepared", "true")
    }

    /** Enroll A, A-admin and B, then approve each Node binding and create each real Group. */
    @Test fun enrollConfirmAndCreateOwnerGroups() {
        val fixture = fixture()
        val publicIds = publicDeviceIdentities()
        val privateFile = File(runRoot(), "private-fixture.json")
        assertTrue("Private one-time Node code file is missing", privateFile.isFile)
        val privateFixture = parseJson(privateFile)
        assertEquals("cicada.client-two-owner-private-fixture.v1", string(privateFixture, "schema"))
        val codes = privateFixture.getAsJsonObject("node_user_codes")
        val codeA = string(codes, "A")
        val codeB = string(codes, "B")
        assertTrue("Could not remove one-time Node codes from app-private staging", privateFile.delete())

        val a = owner(fixture, "A")
        val b = owner(fixture, "B")
        val admin = sessionFor("A_admin")
        val primaryA = sessionFor("A")
        val primaryB = sessionFor("B")

        enrollAndCheckCapabilities(fixture, a, admin, "A_admin",
            string(a, "admin_device_id"), string(a, "admin_owner_device_grant_base64"),
            publicIds.getAsJsonObject("A_admin"))
        enrollAndCheckCapabilities(fixture, a, primaryA, "A",
            string(a, "device_id"), string(a, "owner_device_grant_base64"),
            publicIds.getAsJsonObject("A"))
        enrollAndCheckCapabilities(fixture, b, primaryB, "B",
            string(b, "device_id"), string(b, "owner_device_grant_base64"),
            publicIds.getAsJsonObject("B"))

        val groupA = confirmNodeAndCreateGroup(primaryA, codeA, "A", string(a, "node_id"))
        val groupB = confirmNodeAndCreateGroup(primaryB, codeB, "B", string(b, "node_id"))
        val groups = JsonObject().apply {
            add("A", JsonObject().apply {
                addProperty("group_id", groupA.groupId)
                addProperty("node_id", groupA.nodeId)
                addProperty("group_name", groupA.groupName)
            })
            add("B", JsonObject().apply {
                addProperty("group_id", groupB.groupId)
                addProperty("node_id", groupB.nodeId)
                addProperty("group_name", groupB.groupName)
            })
            addProperty("schema", "cicada.client-two-owner-groups.v1")
        }
        assertNotEquals("Owner Groups must be distinct", groupA.groupId, groupB.groupId)
        writeJson(File(runRoot(), "groups.json"), groups)
        writeResult("enrollment_and_groups", JsonObject().apply {
            addProperty("owner_a_capabilities_match", true)
            addProperty("owner_a_admin_capabilities_match", true)
            addProperty("owner_b_capabilities_match", true)
            addProperty("owner_groups_are_distinct", true)
            addProperty("node_codes_removed_after_read", true)
        })
        publish("two_owner_groups_created", "true")
        publish("two_owner_group_a_id", groupA.groupId)
        publish("two_owner_group_b_id", groupB.groupId)
    }

    /** Reads each owner's exact live manifest through the product verifier for external signing. */
    @Test fun exportOwnerGroupManifests() {
        val fixture = fixture()
        val a = owner(fixture, "A")
        val b = owner(fixture, "B")
        val manifestA = ownVerifiedManifest(sessionFor("A"), a)
        val manifestB = ownVerifiedManifest(sessionFor("B"), b)
        assertNotEquals("Owners must not share a Group manifest", string(manifestA, "digest"), string(manifestB, "digest"))
        val root = JsonObject().apply {
            add("A", manifestA)
            add("B", manifestB)
            addProperty("schema", "cicada.client-two-owner-manifests.v1")
        }
        writeJson(File(runRoot(), "manifests.json"), root)
        writeResult("manifest_export", JsonObject().apply {
            addProperty("owner_a_manifest_verified", true)
            addProperty("owner_b_manifest_verified", true)
        })
        publish("two_owner_manifests_exported", "true")
        publish("two_owner_a_manifest_digest", string(manifestA, "digest"))
        publish("two_owner_b_manifest_digest", string(manifestB, "digest"))
    }

    /** Exercises local fences, independently sealed cross-owner requests, device revoke and recovery. */
    @Test fun twoOwnerOwnershipAndRevocationMatrix() {
        val fixture = fixture()
        val a = owner(fixture, "A")
        val b = owner(fixture, "B")
        val manifestA = publicManifest("A")
        val manifestB = publicManifest("B")
        val groupA = string(a, "group_id")
        val endpointA = string(a, "endpoint_id")
        val groupB = string(b, "group_id")
        val endpointB = string(b, "endpoint_id")
        requireForeignIds(a, b)
        assertEquals(groupA, string(manifestA, "group_id"))
        assertEquals(endpointA, string(manifestA, "endpoint_id"))
        assertEquals(groupB, string(manifestB, "group_id"))
        assertEquals(endpointB, string(manifestB, "endpoint_id"))

        val proofA = string(a, "owner_proof_base64")
        val proofB = string(b, "owner_proof_base64")
        val sessionA = sessionFor("A")
        val sessionAdminA = sessionFor("A_admin")
        val sessionB = sessionFor("B")

        val ownStatusA = approveOwnGrantAndReadStatus(sessionA, a, manifestA, proofA, "A")
        val ownStatusB = approveOwnGrantAndReadStatus(sessionB, b, manifestB, proofB, "B")
        assertEquals("CURRENT", ownStatusA.first)
        assertEquals("CURRENT", ownStatusB.first)

        val aBeforeLocal = sequenceSnapshot("A")
        val bBeforeLocal = sequenceSnapshot("B")
        val aLocalClassifications = rejectForeignCallsLocally(sessionA, a, b, manifestB, proofB)
        val bLocalClassifications = rejectForeignCallsLocally(sessionB, b, a, manifestA, proofA)
        assertSequenceUnchanged(aBeforeLocal, sequenceSnapshot("A"))
        assertSequenceUnchanged(bBeforeLocal, sequenceSnapshot("B"))

        // The independent sender uses the same enrolled PQ device identity and wire contract,
        // while bypassing only the product's local owner-key/proof guard for these negative cases.
        val aBeforeWire = sequenceSnapshot("A")
        val bBeforeAProbe = sequenceSnapshot("B")
        val aWireResult = JsonObject()
        var originalARequest: String? = null
        ProtocolDevice(contextFor("A"), string(fixture, "hub_base_url")).use { driverA ->
            val deniedManifest = encryptedPermissionDenied(driverA.send(
                "group.key_manifest", foreignManifestBody(b),
            ))
            originalARequest = deniedManifest.packetJson
            aWireResult.addProperty("foreign_manifest", deniedManifest.classification)

            val deniedStatus = encryptedPermissionDenied(driverA.send(
                "group.key_status", JsonObject().apply {
                    addProperty("group_id", groupB)
                    addProperty("endpoint_id", endpointB)
                },
            ))
            aWireResult.addProperty("foreign_status", deniedStatus.classification)

            val deniedGrant = encryptedPermissionDenied(driverA.send(
                "group.key_grant", foreignGrantBody(b, proofB),
            ))
            aWireResult.addProperty("foreign_grant", deniedGrant.classification)

            val deniedTamperedProof = encryptedBusinessRejection(driverA.send(
                "group.key_grant", ownGrantBody(a, tamperOwnerProof(proofA)),
            ))
            aWireResult.addProperty("tampered_public_proof", deniedTamperedProof.classification)

            val afterCrossA = driverA.send("group.key_status", JsonObject().apply {
                addProperty("group_id", groupA)
                addProperty("endpoint_id", endpointA)
            })
            val statusAfterCrossA = successfulStatus(afterCrossA.body, a, manifestA)
            assertEquals(ownStatusA.first, statusAfterCrossA.first)
            assertEquals(ownStatusA.second, statusAfterCrossA.second)
            aWireResult.addProperty("own_status_unchanged", true)
            aWireResult.add("protocol_sequence", driverA.sequenceEvidence())
        }
        assertSessionOwnerAndPendingUnmixed(aBeforeWire, sequenceSnapshot("A"))
        assertSessionOwnerAndPendingUnmixed(bBeforeAProbe, sequenceSnapshot("B"))

        revokeOwnerADevice(sessionAdminA, a)

        var revokedRequestCode = ""
        try {
            sessionA.groupKeyStatus(groupA, endpointA)
            fail("Revoked Owner A device unexpectedly completed an encrypted status request")
        } catch (error: HubSessionException) {
            assertEquals("HTTP_403", error.errorCode)
            revokedRequestCode = error.errorCode
        }
        val fencedA = sessionA.getStatus()
        assertTrue("HTTP authentication rejection must fence local Owner A RPC", fencedA.get("authFenced").asBoolean)
        assertFalse(fencedA.get("sessionCapabilitiesReady").asBoolean)
        assertTrue(fencedA.has("pendingOperationId"))
        val aPendingPacket = pendingPacket("A")
        val aPendingRoute = JsonParser.parseString(aPendingPacket).asJsonObject.getAsJsonObject("route")
        assertEquals(string(a, "owner_id"), string(aPendingRoute, "owner_id"))
        assertEquals(string(a, "device_id"), string(aPendingRoute, "device_id"))

        val packet = originalARequest ?: error("No original encrypted Owner A request was captured")
        val pinnedBaseA = pinnedBaseUrl(contextFor("A"), string(fixture, "hub_base_url"))
        val recoveryHttp = postExactPacket(pinnedBaseA, "/v2/client/rpc/recover", packet)
        val replayHttp = postExactPacket(pinnedBaseA, "/v2/client/rpc", packet)
        assertEquals("Revoked A recovery must be rejected at HTTP authentication", 403, recoveryHttp.status)
        assertEquals("Revoked A exact packet replay must be rejected at HTTP authentication", 403, replayHttp.status)

        // No request from B has used the independent wire driver yet: the product session must
        // still work with its own next sequence after A's device is revoked.
        val capabilitiesB = sessionB.rpc("session.capabilities", JsonObject())
        assertTrue("Owner B capabilities request failed after A revocation", capabilitiesB.get("ok").asBoolean)
        assertEquals(string(b, "owner_id"), string(capabilitiesB.getAsJsonObject("result"), "owner_id"))
        val statusBAfterRevoke = sessionB.groupKeyStatus(groupB, endpointB)
        val bAfterRevoke = successfulStatus(statusBAfterRevoke, b, manifestB)
        assertEquals(ownStatusB.first, bAfterRevoke.first)
        assertEquals(ownStatusB.second, bAfterRevoke.second)

        val bWireResult = JsonObject()
        val bBeforeBProbe = sequenceSnapshot("B")
        ProtocolDevice(contextFor("B"), string(fixture, "hub_base_url")).use { driverB ->
            val deniedManifestB = encryptedPermissionDenied(driverB.send(
                "group.key_manifest", foreignManifestBody(a),
            ))
            assertOtherDeviceCannotOpen("A", deniedManifestB.response)
            bWireResult.addProperty("foreign_manifest", deniedManifestB.classification)
            bWireResult.addProperty("foreign_status", encryptedPermissionDenied(driverB.send(
                "group.key_status", JsonObject().apply {
                    addProperty("group_id", groupA)
                    addProperty("endpoint_id", endpointA)
                },
            )).classification)
            bWireResult.addProperty("foreign_grant", encryptedPermissionDenied(driverB.send(
                "group.key_grant", foreignGrantBody(a, proofA),
            )).classification)
            val afterCrossB = driverB.send("group.key_status", JsonObject().apply {
                addProperty("group_id", groupB)
                addProperty("endpoint_id", endpointB)
            })
            val statusAfterCrossB = successfulStatus(afterCrossB.body, b, manifestB)
            assertEquals(ownStatusB.first, statusAfterCrossB.first)
            assertEquals(ownStatusB.second, statusAfterCrossB.second)
            bWireResult.addProperty("own_status_unchanged", true)
            bWireResult.add("protocol_sequence", driverB.sequenceEvidence())
        }
        assertSessionOwnerAndPendingUnmixed(bBeforeBProbe, sequenceSnapshot("B"))
        assertEquals("Owner A pending packet changed during Owner B's foreign requests",
            aPendingPacket, pendingPacket("A"))
        val aAdminStatusAfterForeignCalls = sessionAdminA.groupKeyStatus(groupA, endpointA)
        val aAdminCurrentAfterForeignCalls = successfulStatus(aAdminStatusAfterForeignCalls, a, manifestA)
        assertEquals("Owner B's cross-owner grant attempt changed Owner A's grant status",
            ownStatusA.first, aAdminCurrentAfterForeignCalls.first)
        assertEquals("Owner B's cross-owner grant attempt replaced Owner A's grant record",
            ownStatusA.second, aAdminCurrentAfterForeignCalls.second)

        val result = JsonObject().apply {
            add("owner_a", JsonObject().apply {
                addProperty("role_owner_matched", true)
                addProperty("positive_grant_status", ownStatusA.first)
                addProperty("local_foreign_manifest", aLocalClassifications.first)
                addProperty("local_foreign_grant", aLocalClassifications.second)
                add("encrypted_foreign_requests", aWireResult)
                addProperty("post_revoke_fresh_request", revokedRequestCode)
                addProperty("post_revoke_recover_http", recoveryHttp.status)
                addProperty("post_revoke_exact_replay_http", replayHttp.status)
                addProperty("local_auth_fenced", fencedA.get("authFenced").asBoolean)
            })
            add("owner_b", JsonObject().apply {
                addProperty("role_owner_matched", true)
                addProperty("positive_grant_status", ownStatusB.first)
                addProperty("post_owner_a_revoke_status", bAfterRevoke.first)
                add("encrypted_foreign_requests", bWireResult)
            })
            addProperty("local_preflight_sequence_and_pending_state_isolated", true)
            addProperty("protocol_sequences_bound_to_owner_device_routes", true)
            addProperty("owner_a_grant_unchanged_after_owner_b_attempts", true)
            addProperty("hub_business_and_http_auth_rejections_distinguished", true)
        }
        writeResult("authorization_and_revocation", result)
        publish("two_owner_local_rejection_a", "OWNER_KEY_ID_MISMATCH")
        publish("two_owner_local_rejection_b", "OWNER_KEY_ID_MISMATCH")
        publish("two_owner_encrypted_rejection_a", "permission_denied")
        publish("two_owner_encrypted_rejection_b", "permission_denied")
        publish("two_owner_revoked_a_request_http", revokedRequestCode)
        publish("two_owner_revoked_a_recover_http", recoveryHttp.status.toString())
        publish("two_owner_revoked_a_replay_http", replayHttp.status.toString())
        publish("two_owner_b_status_after_a_revoke", bAfterRevoke.first)
        publish("two_owner_acceptance_complete", "true")
    }

    private fun enrollAndCheckCapabilities(
        fixture: JsonObject,
        owner: JsonObject,
        session: ClientHubSession,
        label: String,
        deviceId: String,
        grant: String,
        preparedIdentity: JsonObject,
    ) {
        val ownerId = string(owner, "owner_id")
        val keyId = string(owner, "owner_key_id")
        assertEquals(keyId, string(owner.getAsJsonObject("owner_public_identity"), "id"))
        assertEquals("Prepared Android key changed before grant signing",
            string(preparedIdentity, "id"), loadPublicDeviceIdentity(contextFor(label)).id)

        val hub = fixture.getAsJsonObject("hub_identity")
        val baseUrl = string(fixture, "hub_base_url")
        val before = session.getStatus()
        if (!before.get("pinned").asBoolean) {
            session.pinHub(baseUrl, string(hub, "hub_id"), hub.getAsJsonObject("control_public_identity").toString())
        } else {
            assertEquals(string(hub, "hub_id"), string(before, "hubId"))
            assertEquals(baseUrl, string(before, "baseUrl"))
        }
        if (!session.getStatus().get("enrolled").asBoolean) {
            session.enroll(ownerId, keyId, owner.getAsJsonObject("owner_public_identity").toString(), deviceId, grant)
        } else {
            val existing = session.getStatus()
            assertEquals(ownerId, string(existing, "ownerId"))
            assertEquals(deviceId, string(existing, "deviceId"))
        }

        val capabilities = session.rpc("session.capabilities", JsonObject())
        assertTrue("Encrypted capabilities failed for device label $label", capabilities.get("ok").asBoolean)
        val result = capabilities.getAsJsonObject("result")
        assertEquals(ownerId, string(result, "owner_id"))
        assertEquals("external", string(result, "role"))
        assertEquals("client-hub-v1.2.1", string(result, "contract_revision"))
        assertEquals("25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9",
            string(result, "catalog_sha256"))
        val allowed = result.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        assertTrue(allowed.containsAll(setOf("group.key_manifest", "group.key_grant", "group.key_status")))
        if (label == "A_admin") assertTrue(allowed.contains("devices.revoke"))
    }

    private data class CreatedGroup(val groupId: String, val groupName: String, val nodeId: String)

    private fun confirmNodeAndCreateGroup(
        session: ClientHubSession,
        code: String,
        ownerName: String,
        expectedNodeId: String,
    ): CreatedGroup {
        val preview = session.rpc("nodes.preview", JsonObject().apply { addProperty("user_code", code) })
        assertTrue("Encrypted Node preview failed for Owner $ownerName", preview.get("ok").asBoolean)
        val node = preview.getAsJsonObject("result")
        val nodeId = string(node, "node_id")
        val nodeName = string(node, "node_name")
        assertEquals("Node preview did not match this Owner's staged Node", expectedNodeId, nodeId)
        assertTrue(nodeId.isNotBlank() && nodeName.isNotBlank())
        assertTrue("Node binding did not receive an on-device confirmation", confirmOnDevice(
            "Confirm Owner $ownerName Node binding",
            "Bind this Node to Owner $ownerName and this Android device?",
            listOf("Node ID: $nodeId", "Node name: $nodeName", "Expires at: ${string(node, "expires_at")}"),
            "Confirm Node",
            "Owner $ownerName",
        ))
        val confirmed = session.rpc("nodes.confirm", JsonObject().apply { addProperty("user_code", code) })
        assertTrue("Encrypted Node confirmation failed for Owner $ownerName", confirmed.get("ok").asBoolean)
        val binding = confirmed.getAsJsonObject("result")
        assertEquals(nodeId, string(binding, "node_id"))

        val groupName = "Two Owner ${runId()} $ownerName"
        assertTrue("Group creation did not receive an on-device confirmation", confirmOnDevice(
            "Create Owner $ownerName Group",
            "Create this Group under Owner $ownerName's authority?",
            listOf("Group name: $groupName"),
            "Create Group",
            "Owner $ownerName",
        ))
        val created = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("name", groupName) })
            })
        })
        assertTrue("Encrypted Group creation failed for Owner $ownerName", created.get("ok").asBoolean)
        val group = created.getAsJsonObject("result").getAsJsonObject("group")
        return CreatedGroup(string(group, "group_id"), string(group, "name"), nodeId)
    }

    private fun ownVerifiedManifest(session: ClientHubSession, owner: JsonObject): JsonObject {
        val groupId = string(owner, "group_id")
        val endpointId = string(owner, "endpoint_id")
        assertTrue("Expected a real existing Group ID", groupId.isNotBlank())
        assertTrue("Expected a real existing Endpoint ID", endpointId.isNotBlank())
        val result = session.previewGroupKey(groupId, endpointId, string(owner, "owner_key_id"))
        assertTrue("Android did not independently verify the Owner's live manifest", result.get("verified").asBoolean)
        val manifest = result.getAsJsonObject("result")
        assertEquals(string(owner, "owner_id"), string(manifest, "owner_id"))
        assertEquals(groupId, string(manifest, "group_id"))
        assertEquals(endpointId, string(manifest, "endpoint_id"))
        assertEquals(string(owner, "owner_key_id"), string(manifest, "owner_key_id"))
        return manifest
    }

    private fun approveOwnGrantAndReadStatus(
        session: ClientHubSession,
        owner: JsonObject,
        manifest: JsonObject,
        proof: String,
        label: String,
    ): Pair<String, String> {
        val groupId = string(owner, "group_id")
        val endpointId = string(owner, "endpoint_id")
        val ownerKeyId = string(owner, "owner_key_id")
        val digest = string(manifest, "digest")
        val reviewed = session.previewGroupKeyGrant(groupId, endpointId, ownerKeyId, digest, proof)
        assertTrue("Product rejected the separately signed own-Group proof for Owner $label",
            reviewed.get("verified").asBoolean)
        assertEquals(digest, string(reviewed.getAsJsonObject("result"), "digest"))
        assertTrue("Owner Group key grant did not receive a separate user confirmation", confirmOnDevice(
            "Approve Owner $label Group key grant",
            "Approve the externally signed key grant for this verified Group Endpoint?",
            listOf("Group ID: $groupId", "Endpoint ID: $endpointId", "Manifest digest: $digest"),
            "Approve key grant",
            "Owner $label",
        ))
        val grant = session.grantGroupKey(groupId, endpointId, ownerKeyId, digest, proof)
        assertTrue("Encrypted own Group grant failed for Owner $label", grant.get("ok").asBoolean)
        val status = session.groupKeyStatus(groupId, endpointId)
        return successfulStatus(status, owner, manifest)
    }

    private fun successfulStatus(response: JsonObject, owner: JsonObject, manifest: JsonObject): Pair<String, String> {
        assertTrue("Expected a successful encrypted own Group status", response.get("ok").asBoolean)
        val result = response.getAsJsonObject("result")
        assertEquals(string(owner, "owner_id"), string(result, "owner_id"))
        assertEquals(string(owner, "group_id"), string(result, "group_id"))
        assertEquals(string(owner, "endpoint_id"), string(result, "endpoint_id"))
        assertEquals(string(manifest, "digest"), string(result.getAsJsonObject("manifest"), "digest"))
        return string(result, "current_status") to string(result, "grant_id")
    }

    private fun rejectForeignCallsLocally(
        session: ClientHubSession,
        own: JsonObject,
        foreign: JsonObject,
        foreignManifest: JsonObject,
        foreignProof: String,
    ): Pair<String, String> {
        val ownKeyId = string(own, "owner_key_id")
        val foreignKeyId = string(foreign, "owner_key_id")
        val foreignGroup = string(foreign, "group_id")
        val foreignEndpoint = string(foreign, "endpoint_id")
        val manifestCode = expectLocalRejection("OWNER_KEY_ID_MISMATCH") {
            session.previewGroupKey(foreignGroup, foreignEndpoint, foreignKeyId)
        }
        val grantCode = expectLocalRejection("GROUP_CONSENT_MISMATCH") {
            session.grantGroupKey(foreignGroup, foreignEndpoint, foreignKeyId,
                string(foreignManifest, "digest"), foreignProof)
        }
        assertNotEquals("Local owner proof guard must be tied to the current enrolled Owner",
            ownKeyId, foreignKeyId)
        return manifestCode to grantCode
    }

    private fun expectLocalRejection(expected: String, action: () -> Any?): String {
        try {
            action()
            fail("Product local owner/proof guard unexpectedly allowed a foreign operation")
        } catch (error: HubSessionException) {
            assertEquals("Unexpected product-local rejection classification", expected, error.errorCode)
            return error.errorCode
        }
        return "UNREACHABLE"
    }

    private fun foreignManifestBody(foreign: JsonObject): JsonObject {
        val issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS)
        return JsonObject().apply {
            addProperty("group_id", string(foreign, "group_id"))
            addProperty("endpoint_id", string(foreign, "endpoint_id"))
            addProperty("owner_key_id", string(foreign, "owner_key_id"))
            addProperty("issued_at", issuedAt.toString())
            addProperty("expires_at", issuedAt.plusSeconds(600).toString())
        }
    }

    private fun foreignGrantBody(foreign: JsonObject, foreignProof: String): JsonObject = JsonObject().apply {
        addProperty("group_id", string(foreign, "group_id"))
        addProperty("endpoint_id", string(foreign, "endpoint_id"))
        addProperty("owner_key_id", string(foreign, "owner_key_id"))
        addProperty("signed_proof", foreignProof)
    }

    private fun ownGrantBody(owner: JsonObject, proof: String): JsonObject = JsonObject().apply {
        addProperty("group_id", string(owner, "group_id"))
        addProperty("endpoint_id", string(owner, "endpoint_id"))
        addProperty("owner_key_id", string(owner, "owner_key_id"))
        addProperty("signed_proof", proof)
    }

    private fun encryptedPermissionDenied(result: WireResponse): ClassifiedResult {
        assertEquals("Foreign RPC must reach the real Hub over encrypted Client-Control", 200, result.httpStatus)
        assertFalse("Hub must return an encrypted business authorization rejection", result.body.get("ok").asBoolean)
        assertEquals("Hub must reject a real foreign Group/Endpoint with its owner-scope Guard",
            "permission denied", string(result.body, "error"))
        return ClassifiedResult("HTTP_200_ENCRYPTED_PERMISSION_DENIED", result.packetJson, result)
    }

    private fun encryptedBusinessRejection(result: WireResponse): ClassifiedResult {
        assertEquals("Tampered public proof must be evaluated inside encrypted Hub RPC", 200, result.httpStatus)
        assertFalse("Hub accepted a tampered public Owner signature", result.body.get("ok").asBoolean)
        assertTrue("Hub did not reject the corrupted signature at proof verification",
            string(result.body, "error").startsWith("verify Group Endpoint key grant signature:"))
        return ClassifiedResult("HTTP_200_ENCRYPTED_SIGNATURE_REJECTION", result.packetJson, result)
    }

    private fun tamperOwnerProof(proofBase64: String): String {
        val proofBytes = Base64.decode(proofBase64, Base64.NO_WRAP)
        try {
            val proof = JsonParser.parseString(String(proofBytes, StandardCharsets.UTF_8)).asJsonObject
            val signatureText = string(proof, "signature")
            val signature = Base64.decode(signatureText, Base64.NO_WRAP)
            try {
                assertTrue("Owner public proof signature is unexpectedly empty", signature.isNotEmpty())
                signature[0] = (signature[0].toInt() xor 1).toByte()
                proof.addProperty("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
                return Base64.encodeToString(proof.toString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)
            } finally {
                signature.fill(0)
            }
        } finally {
            proofBytes.fill(0)
        }
    }

    private fun revokeOwnerADevice(admin: ClientHubSession, ownerA: JsonObject) {
        val targetDevice = string(ownerA, "device_id")
        val listed = admin.rpc("devices.list", JsonObject())
        assertTrue("Owner A admin device could not read its own device list", listed.get("ok").asBoolean)
        val devices = listed.getAsJsonArray("result")
        val target = devices.map { it.asJsonObject }.singleOrNull {
            string(it, "device_id") == targetDevice
        } ?: error("Owner A admin did not find the real enrolled A device")
        assertEquals("ACTIVE", string(target, "state"))
        val revoked = admin.rpc("devices.revoke", JsonObject().apply {
            addProperty("device_id", targetDevice)
            addProperty("expected_version", target.get("version").asLong)
        })
        assertTrue("Owner A admin's version-guarded device revoke failed", revoked.get("ok").asBoolean)
        val result = revoked.getAsJsonObject("result")
        assertEquals(targetDevice, string(result, "device_id"))
        assertEquals("REVOKED", string(result, "state"))
    }

    private fun requireForeignIds(a: JsonObject, b: JsonObject) {
        for ((left, right) in listOf(
            string(a, "group_id") to string(b, "group_id"),
            string(a, "endpoint_id") to string(b, "endpoint_id"),
        )) {
            assertTrue("Cross-owner test requires two real distinct object IDs", left.isNotBlank() && right.isNotBlank())
            assertNotEquals("Cross-owner test IDs must belong to different objects", left, right)
        }
        assertNotEquals("Synthetic Owners must be distinct", string(a, "owner_id"), string(b, "owner_id"))
    }

    private data class SequenceSnapshot(
        val ownerId: String,
        val deviceId: String,
        val nextRequest: Long,
        val lastResponse: Long,
        val pending: Boolean,
        val capabilitiesReady: Boolean,
    )

    private fun sequenceSnapshot(label: String): SequenceSnapshot {
        val state = parseJson(File(File(contextFor(label).noBackupFilesDir, "client-hub"), "session-state.json"))
        val enrollment = state.getAsJsonObject("enrollment")
        return SequenceSnapshot(
            string(enrollment, "ownerId"), string(enrollment, "deviceId"),
            state.get("nextSequence").asLong, state.get("lastResponseSequence").asLong,
            state.has("pending") && !state.get("pending").isJsonNull,
            state.get("sessionCapabilitiesReady").asBoolean,
        )
    }

    private fun assertSequenceUnchanged(before: SequenceSnapshot, after: SequenceSnapshot) {
        assertEquals("Owner/device session storage crossed identities", before.ownerId, after.ownerId)
        assertEquals("Owner/device session storage crossed device identities", before.deviceId, after.deviceId)
        assertEquals("Local RPC request sequence changed outside product session", before.nextRequest, after.nextRequest)
        assertEquals("Local RPC response sequence changed outside product session", before.lastResponse, after.lastResponse)
        assertEquals("An Owner's pending slot mixed with another packet", before.pending, after.pending)
        assertEquals("Encrypted capabilities readiness mixed between Owners", before.capabilitiesReady, after.capabilitiesReady)
        assertFalse("No pending request may be left before raw protocol probes", after.pending)
    }

    /** The independent packet driver advances Hub counters in memory; this checks only app-state isolation. */
    private fun assertSessionOwnerAndPendingUnmixed(before: SequenceSnapshot, after: SequenceSnapshot) {
        assertEquals("Owner/device state crossed identities", before.ownerId, after.ownerId)
        assertEquals("Owner/device state crossed device identities", before.deviceId, after.deviceId)
        assertEquals("Capability readiness crossed Owners", before.capabilitiesReady, after.capabilitiesReady)
        assertEquals("Independent driver changed persisted request sequence", before.nextRequest, after.nextRequest)
        assertEquals("Independent driver changed persisted response sequence", before.lastResponse, after.lastResponse)
        assertEquals("Independent driver changed persisted pending state", before.pending, after.pending)
        assertFalse("Independent packet driver wrote an Owner's pending slot", after.pending)
    }

    private fun pendingPacket(label: String): String {
        val state = parseJson(File(File(contextFor(label).noBackupFilesDir, "client-hub"), "session-state.json"))
        return string(state.getAsJsonObject("pending"), "packetJson")
    }

    private fun loadPublicDeviceIdentity(context: OwnerContext): ClientWireCrypto.PublicIdentity {
        val identity = unwrapIdentity(File(context.noBackupFilesDir, "client-hub"))
        return try { identity.publicIdentity } finally { identity.close() }
    }

    private fun unwrapIdentity(directory: File): ClientWireCrypto.Identity {
        val wrapped = parseJson(File(directory, "device-key.wrap.json"))
        val nonce = Base64.decode(string(wrapped, "nonce"), Base64.DEFAULT)
        val ciphertext = Base64.decode(string(wrapped, "ciphertext"), Base64.DEFAULT)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(DEVICE_WRAP_ALIAS, null) as? SecretKey
            ?: error("Android Keystore device wrapper is unavailable")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(DEVICE_WRAP_AAD)
        val plaintext = cipher.doFinal(ciphertext)
        return try {
            ClientWireCrypto.Identity.fromPrivateJson(String(plaintext, StandardCharsets.UTF_8))
        } finally {
            plaintext.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun assertOtherDeviceCannotOpen(label: String, response: WireResponse) {
        val context = contextFor(label)
        val identity = unwrapIdentity(File(context.noBackupFilesDir, "client-hub"))
        try {
            val state = parseJson(File(File(context.noBackupFilesDir, "client-hub"), "session-state.json"))
            val pin = state.getAsJsonObject("pin")
            val ownerId = string(state.getAsJsonObject("enrollment"), "ownerId")
            assertNotEquals("Response test must cross Owner scopes", ownerId, response.requestRoute.ownerId)
            val control = ClientWireCrypto.PublicIdentity.parse(
                JsonParser.parseString(string(pin, "controlPublicIdentityJson")).asJsonObject,
            )
            val openedByWrongDevice = try {
                ClientWireCrypto.openResponse(identity, control,
                    response.requestRoute, response.responsePacketJson)
                true
            } catch (_: IllegalArgumentException) {
                false
            }
            assertFalse("One Owner's encrypted response was opened with the other Owner's device key",
                openedByWrongDevice)
        } finally {
            identity.close()
        }
    }

    private data class WireResponse(
        val httpStatus: Int,
        val body: JsonObject,
        val packetJson: String,
        val requestRoute: ClientWireCrypto.Route,
        val responsePacketJson: String,
    )
    private data class ClassifiedResult(
        val classification: String,
        val packetJson: String,
        val response: WireResponse,
    )

    /** Test-only Client-Control sender for negative Hub authorization and public-proof cases. */
    private inner class ProtocolDevice(context: OwnerContext, expectedBaseUrl: String) : AutoCloseable {
        private val sessionDirectory = File(context.noBackupFilesDir, "client-hub")
        private val state = parseJson(File(sessionDirectory, "session-state.json"))
        private val pin = state.getAsJsonObject("pin")
        private val enrollment = state.getAsJsonObject("enrollment")
        private val identity: ClientWireCrypto.Identity = unwrapIdentity(sessionDirectory)
        private val control = ClientWireCrypto.PublicIdentity.parse(
            JsonParser.parseString(string(pin, "controlPublicIdentityJson")).asJsonObject,
        )
        private val baseUrl = string(pin, "baseUrl")
        private val initialRequestSequence = state.get("nextSequence").asLong
        private val initialResponseSequence = state.get("lastResponseSequence").asLong + 1
        private var requestSequence = initialRequestSequence
        private var responseSequence = initialResponseSequence
        private var requestsSent = 0L

        init {
            assertEquals("Test packet sender must use the already pinned disposable Hub", expectedBaseUrl, baseUrl)
            assertLoopbackBase(baseUrl)
            assertFalse("Product session must be clear before independent packet probes",
                state.has("pending") && !state.get("pending").isJsonNull)
            val expectedIdentity = parseJson(File(runRoot(), "device-publics.json"))
                .getAsJsonObject(context.noBackupFilesDir.name)
            assertEquals("Raw packet sender did not load this context's generated device key",
                string(expectedIdentity, "id"), identity.publicIdentity.id)
            val localStatus = ClientHubSession(context).getStatus()
            assertEquals(string(enrollment, "ownerId"), string(localStatus, "ownerId"))
            assertEquals(string(enrollment, "deviceId"), string(localStatus, "deviceId"))
        }

        fun send(operation: String, body: JsonObject): WireResponse {
            require(operation in setOf("group.key_manifest", "group.key_grant", "group.key_status"))
            val route = ClientWireCrypto.Route().apply {
                version = 1
                direction = "REQUEST"
                hubId = string(pin, "hubId")
                ownerId = string(enrollment, "ownerId")
                deviceId = string(enrollment, "deviceId")
                sessionEpoch = enrollment.get("sessionEpoch").asLong
                sequence = requestSequence
                operationId = "two-owner-${UUID.randomUUID()}"
                this.operation = operation
                senderKeyId = identity.publicIdentity.id
                senderKeyVersion = enrollment.get("deviceKeyVersion").asLong
                receiverKeyId = control.id
                receiverKeyVersion = pin.get("controlKeyVersion").asLong
            }
            val packet = ClientWireCrypto.sealRequest(identity, control, route, body.toString())
            val response = postExactPacket(baseUrl, "/v2/client/rpc", packet)
            assertEquals("Test-only packet sender did not receive an encrypted RPC response", 200, response.status)
            val opened = ClientWireCrypto.openResponse(identity, control, route, response.body)
            assertEquals("Hub response sequence crossed Owner sessions", responseSequence, opened.route.sequence)
            assertEquals(route.ownerId, opened.route.ownerId)
            assertEquals(route.deviceId, opened.route.deviceId)
            assertEquals(route.operationId, opened.route.operationId)
            requestSequence += 1
            responseSequence += 1
            requestsSent += 1
            return WireResponse(response.status, opened.body, packet, route, response.body)
        }

        fun sequenceEvidence(): JsonObject {
            assertEquals("Independent request sequence did not advance once per packet",
                initialRequestSequence + requestsSent, requestSequence)
            assertEquals("Independent response sequence did not advance once per authenticated response",
                initialResponseSequence + requestsSent, responseSequence)
            return JsonObject().apply {
                addProperty("owner_id", string(enrollment, "ownerId"))
                addProperty("device_id", string(enrollment, "deviceId"))
                addProperty("first_request_sequence", initialRequestSequence)
                addProperty("next_request_sequence", requestSequence)
                addProperty("first_response_sequence", initialResponseSequence)
                addProperty("next_response_sequence", responseSequence)
                addProperty("requests_sent", requestsSent)
            }
        }

        override fun close() {
            identity.close()
        }

    }

    private data class HttpResult(val status: Int, val body: String)

    private fun postExactPacket(baseUrl: String, path: String, packet: String): HttpResult {
        assertLoopbackBase(baseUrl)
        val connection = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 30_000
            requestMethod = "POST"
            instanceFollowRedirects = false
            useCaches = false
            doOutput = true
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Connection", "close")
        }
        try {
            connection.outputStream.use { it.write(packet.toByteArray(StandardCharsets.UTF_8)) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { input -> input.readBytes().take(MAX_RESPONSE_BYTES).toByteArray() } ?: ByteArray(0)
            return HttpResult(status, String(bytes, StandardCharsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    private fun pinnedBaseUrl(context: OwnerContext, expected: String): String {
        val state = parseJson(File(File(context.noBackupFilesDir, "client-hub"), "session-state.json"))
        val actual = string(state.getAsJsonObject("pin"), "baseUrl")
        assertEquals("Revocation probe must reuse the pinned Hub", expected, actual)
        return actual
    }

    private fun assertLoopbackBase(baseUrl: String) {
        val uri = URI(baseUrl)
        assertEquals("Two-owner wire harness is limited to disposable emulator HTTP reverse", "http", uri.scheme)
        assertEquals("Two-owner wire harness is limited to the ADB reverse loopback", "127.0.0.1", uri.host)
        assertTrue("Hub must use the fixture's unique high port", uri.port in 1024..65535)
    }

    private fun confirmOnDevice(
        title: String,
        action: String,
        details: List<String>,
        positiveLabel: String,
        ownerLabel: String,
    ): Boolean {
        val activity = instrumentation.startActivitySync(
            Intent(target, MainActivity::class.java).apply {
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
        publish("confirmation_owner", ownerLabel)
        publish("confirmation_title", title)
        val timeout = arguments.getString("approval_timeout_ms")?.toLongOrNull()
            ?.coerceIn(1_000L, 600_000L) ?: 180_000L
        return try {
            assertTrue("Timed out waiting for explicit on-device confirmation",
                latch.await(timeout, TimeUnit.MILLISECONDS))
            accepted.get()
        } finally {
            instrumentation.runOnMainSync {
                dialogHolder[0]?.dismiss()
                activity.finish()
            }
        }
    }

    private fun parseJson(file: File): JsonObject = try {
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) {
        error("Staged public fixture or private test state is invalid JSON")
    }

    private fun writeJson(file: File, value: JsonObject) {
        val temporary = File(file.parentFile, file.name + ".tmp")
        temporary.writeText(value.toString(), StandardCharsets.UTF_8)
        if (file.exists() && !file.delete()) error("Could not replace public two-owner stage output")
        if (!temporary.renameTo(file)) error("Could not commit public two-owner stage output")
    }

    private fun string(value: JsonObject, field: String): String {
        val element = value.get(field)
        if (element == null || element.isJsonNull || !element.isJsonPrimitive || !element.asJsonPrimitive.isString) {
            throw AssertionError("Required public fixture field is invalid: $field")
        }
        return element.asString
    }

    private fun assertLoopbackPublicDeviceContext(context: OwnerContext) {
        assertTrue(context.noBackupFilesDir.isDirectory)
    }

    private data class OwnerContext(val base: Context, val privateRoot: File) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this
        override fun getNoBackupFilesDir(): File = privateRoot
    }

    companion object {
        private const val DEVICE_WRAP_ALIAS = "ai.cicada.client.hub.device-wrap.v1"
        private val DEVICE_WRAP_AAD = "cicada/android/client-device-key/wrap/v1\u0000".toByteArray(StandardCharsets.UTF_8)
        private const val MAX_RESPONSE_BYTES = 256 * 1024
    }
}
