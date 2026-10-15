package ai.cicada.client

import ai.cicada.client.hub.ClientHubSession
import ai.cicada.client.hub.HubSessionException
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.time.Instant

/** Cross-owner proposal tests using the APK's actual Android Keystore and RPC implementation. */
@RunWith(AndroidJUnit4::class)
class LinkProposalInteropTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val session get() = ClientHubSession(context)
    private val arguments get() = InstrumentationRegistry.getArguments()
    private val files get() = File(context.filesDir, "link-interop").apply { mkdirs() }

    private fun argument(name: String): String = arguments.getString(name)
        ?: error("Instrumentation argument $name is required")

    private fun file(name: String) = File(files, name)

    private fun readText(name: String): String = file(name).readText(StandardCharsets.UTF_8).trim()

    private fun readJson(name: String): JsonObject =
        JsonParser.parseString(readText(name)).asJsonObject

    private fun getHubJson(path: String): JsonObject {
        val connection = URL("${argument("hub_base_url")}$path").openConnection() as HttpURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.instanceFollowRedirects = false
        try {
            assertEquals(200, connection.responseCode)
            return JsonParser.parseReader(
                InputStreamReader(connection.inputStream, StandardCharsets.UTF_8),
            ).asJsonObject
        } finally {
            connection.disconnect()
        }
    }

    private fun writePrivate(name: String, value: String) {
        val output = file(name)
        output.writeText(value, StandardCharsets.UTF_8)
        assertTrue("Could not restrict test artifact permissions", output.setReadable(false, false))
        assertTrue("Could not restrict test artifact permissions", output.setWritable(false, false))
        assertTrue("Could not set test artifact owner-readable", output.setReadable(true, true))
        assertTrue("Could not set test artifact owner-writable", output.setWritable(true, true))
    }

    private fun jsonObject(vararg fields: Pair<String, String>) = JsonObject().apply {
        fields.forEach { (name, value) -> addProperty(name, value) }
    }

    private fun assertEncryptedSuccess(response: JsonObject, description: String) {
        assertTrue("$description was rejected by the encrypted Hub RPC", response.get("ok").asBoolean)
    }

    private fun ownerCapabilities(): JsonObject {
        val response = session.rpc("session.capabilities", JsonObject())
        assertEncryptedSuccess(response, "session.capabilities")
        assertEquals("external", response.getAsJsonObject("result").get("role").asString)
        return response.getAsJsonObject("result")
    }

    private fun listLinks(): JsonArray {
        val response = session.rpc("link.list", JsonObject().apply { addProperty("limit", 50) })
        assertEncryptedSuccess(response, "link.list")
        return response.getAsJsonObject("result").getAsJsonArray("links")
    }

    private fun findLink(links: JsonArray, linkId: String): JsonObject? =
        links.firstOrNull { row ->
            row.asJsonObject.getAsJsonObject("link").get("link_id").asString == linkId
        }?.asJsonObject

    @Test fun androidResolvesTheIsolatedHubIdentityThroughRelay() {
        val expected = readJson("trusted-hub-identity.json")
        val identity = getHubJson("/v2/client/identity")
        assertEquals(expected.get("hub_id").asString, identity.get("hub_id").asString)
        assertEquals(
            expected.getAsJsonObject("control_public_identity").get("id").asString,
            identity.getAsJsonObject("control_public_identity").get("id").asString,
        )

        val capabilities = getHubJson("/v2/client/capabilities")
        assertEquals("partial", capabilities.get("status").asString)
        assertTrue(capabilities.get("external_link_invites").asBoolean)
        assertFalse(capabilities.get("external_thread_links").asBoolean)
    }

    @Test fun prepareDeviceIdentity() {
        val identity = session.createDeviceIdentity().getAsJsonObject("devicePublicIdentity")
        assertTrue(identity.get("id").asString.startsWith("pq1-"))
        writePrivate("device-public-identity.json", identity.toString())
    }

    @Test fun enrollOwnerAndCreateGroup() {
        val hub = readJson("trusted-hub-identity.json")
        val owner = readJson("owner-public-identity.json")
        val grant = Base64.encodeToString(
            file("owner-device-grant.json").readBytes(), Base64.NO_WRAP,
        )
        session.pinHub(
            argument("hub_base_url"), hub.get("hub_id").asString,
            hub.getAsJsonObject("control_public_identity").toString(),
        )
        val enrollment = session.enroll(
            argument("owner_id"), owner.get("id").asString, owner.toString(),
            argument("device_id"), grant,
        )
        assertEquals("ACTIVE", enrollment.get("state").asString)
        val operations = ownerCapabilities().getAsJsonArray("available_rpc_operations")
            .map { it.asString }
        assertTrue(operations.contains("topology.apply"))
        assertTrue(operations.contains("link.invite_create"))
        assertTrue(operations.contains("link.invite_accept"))

        val groupName = argument("group_name")
        val created = session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("group", JsonObject().apply { addProperty("name", groupName) })
            })
        })
        assertEncryptedSuccess(created, "external owner Group creation")
        val group = created.getAsJsonObject("result").getAsJsonObject("group")
        assertTrue(group.get("group_id").asString.isNotBlank())
        writePrivate("group-id.txt", group.get("group_id").asString)
    }

    @Test fun confirmBoundNode() {
        ownerCapabilities()
        val code = readText("node-user-code.txt")
        val expectedNodeId = readText("node-id.txt")
        val preview = session.rpc("nodes.preview", jsonObject("user_code" to code))
        assertEncryptedSuccess(preview, "nodes.preview")
        assertEquals(expectedNodeId,
            preview.getAsJsonObject("result").get("node_id").asString)
        val confirmed = session.rpc("nodes.confirm", jsonObject("user_code" to code))
        assertEncryptedSuccess(confirmed, "nodes.confirm")
        assertEquals(expectedNodeId,
            confirmed.getAsJsonObject("result").get("node_id").asString)
        assertEquals(argument("owner_id"),
            confirmed.getAsJsonObject("result").get("owner_id").asString)
    }

    @Test fun createOneUseInviteForJoinedEndpoint() {
        ownerCapabilities()
        val endpointId = readText("endpoint-id.txt")
        val groupId = readText("group-id.txt")
        val hub = readJson("trusted-hub-identity.json")
        val body = JsonObject().apply {
            addProperty("source_endpoint_id", endpointId)
            addProperty("source_group_id", groupId)
            addProperty("hub_id", hub.get("hub_id").asString)
            add("actions", JsonArray().apply { add("ask"); add("reply") })
            add("data_scopes", JsonArray().apply { add("benchmark.public_result") })
            addProperty("expires_at", Instant.now().plusSeconds(1800).toString())
        }
        val response = session.rpc("link.invite_create", body)
        assertEncryptedSuccess(response, "link.invite_create")
        val invitation = response.getAsJsonObject("result")
        val token = invitation.get("token").asString
        assertTrue("Hub returned an invalid one-use token shape", token.matches(Regex("[A-Za-z0-9_-]{43}")))
        assertEquals(hub.get("hub_id").asString, invitation.get("hub_id").asString)
        writePrivate("invite-token.txt", token)
        writePrivate("invite-id.txt", invitation.get("invite_id").asString)
        writePrivate("invite-expires-at.txt", invitation.get("expires_at").asString)
    }

    @Test fun previewAcceptReplayCasConflictAndRevoke() {
        ownerCapabilities()
        val token = readText("invite-token.txt")
        val targetEndpointId = readText("endpoint-id.txt")
        val targetGroupId = readText("group-id.txt")
        val sourceEndpointId = readText("source-endpoint-id.txt")
        val sourceGroupId = readText("source-group-id.txt")
        val hub = readJson("trusted-hub-identity.json")

        val badPreview = session.rpc("link.invite_preview", jsonObject("token" to "invalid-link-token"))
        assertFalse("An invalid invitation token was accepted by preview",
            badPreview.get("ok").asBoolean)
        val badAccept = session.rpc("link.invite_accept", JsonObject().apply {
            addProperty("token", "invalid-link-token")
            addProperty("target_endpoint_id", targetEndpointId)
            addProperty("target_group_id", targetGroupId)
        })
        assertFalse("An invalid invitation token was accepted",
            badAccept.get("ok").asBoolean)
        val foreignSource = session.rpc("link.invite_create", JsonObject().apply {
            addProperty("source_endpoint_id", sourceEndpointId)
            addProperty("source_group_id", sourceGroupId)
            addProperty("hub_id", hub.get("hub_id").asString)
            add("actions", JsonArray().apply { add("ask"); add("reply") })
            add("data_scopes", JsonArray().apply { add("benchmark.public_result") })
            addProperty("expires_at", Instant.now().plusSeconds(900).toString())
        })
        assertFalse("The target owner created an invite for the source owner's Endpoint",
            foreignSource.get("ok").asBoolean)

        val preview = session.rpc("link.invite_preview", jsonObject("token" to token))
        assertEncryptedSuccess(preview, "link.invite_preview")
        val terms = preview.getAsJsonObject("result")
        assertEquals(hub.get("hub_id").asString, terms.get("hub_id").asString)
        assertEquals("forward", terms.get("direction").asString)
        assertEquals(setOf("ask", "reply"),
            terms.getAsJsonArray("actions").map { it.asString }.toSet())
        assertEquals(setOf("benchmark.public_result"),
            terms.getAsJsonArray("data_scopes").map { it.asString }.toSet())
        assertNotEquals(sourceEndpointId, terms.get("source_endpoint_label").asString)
        assertNotEquals(sourceGroupId, terms.get("source_group_label").asString)
        val sourceLabel = terms.get("source_endpoint_label").asString
        val groupLabel = terms.get("source_group_label").asString
        assertTrue(sourceLabel.isNotBlank())
        assertTrue(groupLabel.isNotBlank())

        val accepted = session.rpc("link.invite_accept", JsonObject().apply {
            addProperty("token", token)
            addProperty("target_endpoint_id", targetEndpointId)
            addProperty("target_group_id", targetGroupId)
        })
        assertEncryptedSuccess(accepted, "link.invite_accept")
        val acceptedLink = accepted.getAsJsonObject("result")
        assertEquals("PROPOSED", acceptedLink.get("state").asString)
        val linkId = acceptedLink.get("link_id").asString
        val originalVersion = acceptedLink.get("version").asLong
        writePrivate("link-id.txt", linkId)

        val replay = session.rpc("link.invite_accept", JsonObject().apply {
            addProperty("token", token)
            addProperty("target_endpoint_id", targetEndpointId)
            addProperty("target_group_id", targetGroupId)
        })
        assertFalse("A consumed one-use invitation token was accepted again",
            replay.get("ok").asBoolean)

        val acceptedListRow = findLink(listLinks(), linkId)
        assertNotNull("Target owner's link.list did not recover its proposal", acceptedListRow)
        assertEquals("TARGET", acceptedListRow!!.get("my_side").asString)
        assertLinkTerms(acceptedListRow.getAsJsonObject("link"), sourceEndpointId,
            sourceGroupId, targetEndpointId, targetGroupId, originalVersion, "PROPOSED")

        val staleRevoke = revoke(linkId, originalVersion + 1)
        assertFalse("A stale Link version unexpectedly revoked the proposal",
            staleRevoke.get("ok").asBoolean)
        val afterConflict = findLink(listLinks(), linkId)
        assertNotNull("The proposal disappeared after a rejected stale CAS", afterConflict)
        assertLinkTerms(afterConflict!!.getAsJsonObject("link"), sourceEndpointId,
            sourceGroupId, targetEndpointId, targetGroupId, originalVersion, "PROPOSED")

        val revoked = revoke(linkId, originalVersion)
        assertEncryptedSuccess(revoked, "link.revoke with current version")
        val revokedLink = revoked.getAsJsonObject("result").getAsJsonObject("link")
        assertEquals("REVOKED", revokedLink.get("state").asString)
        assertEquals(originalVersion + 1, revokedLink.get("version").asLong)
        val finalRow = findLink(listLinks(), linkId)
        assertNotNull("Target owner's link.list lost the revoked record", finalRow)
        assertEquals("TARGET", finalRow!!.get("my_side").asString)
        assertLinkTerms(finalRow.getAsJsonObject("link"), sourceEndpointId,
            sourceGroupId, targetEndpointId, targetGroupId, originalVersion + 1, "REVOKED")

        assertTrue("Consumed invitation token could not be cleared", file("invite-token.txt").delete())
    }

    @Test fun sourceOwnerRecoversRevokedLinkFromList() {
        ownerCapabilities()
        val linkId = readText("link-id.txt")
        val sourceEndpointId = readText("endpoint-id.txt")
        val sourceGroupId = readText("group-id.txt")
        val targetEndpointId = readText("target-endpoint-id.txt")
        val targetGroupId = readText("target-group-id.txt")
        val link = findLink(listLinks(), linkId)
        assertNotNull("Source owner's link.list did not recover the accepted proposal", link)
        assertEquals("SOURCE", link!!.get("my_side").asString)
        assertLinkTerms(link.getAsJsonObject("link"), sourceEndpointId, sourceGroupId,
            targetEndpointId, targetGroupId, argument("revoked_link_version").toLong(), "REVOKED")
    }

    @Test fun linkListLeavesExactPendingWhenResponseIsDropped() {
        ownerCapabilities()
        try {
            session.rpc("link.list", JsonObject().apply { addProperty("limit", 50) },
                "android-link-offline-list-v1")
            throw AssertionError("Client unexpectedly received a response from the drop relay")
        } catch (error: HubSessionException) {
            assertEquals("NETWORK_ERROR", error.errorCode)
        }
        assertEquals("android-link-offline-list-v1",
            session.getStatus().get("pendingOperationId").asString)
    }

    @Test fun recoverExactPendingLinkListAfterResponseDrop() {
        val before = session.getStatus()
        assertEquals("android-link-offline-list-v1", before.get("pendingOperationId").asString)
        val recovered = session.recoverPending()
        assertTrue(recovered.get("ok").asBoolean)
        assertEquals("android-link-offline-list-v1", recovered.get("operationId").asString)
        assertFalse(session.getStatus().has("pendingOperationId"))
        val links = recovered.getAsJsonObject("result").getAsJsonArray("links")
        assertTrue("Recovered link.list omitted the revoked cross-owner record",
            findLink(links, readText("link-id.txt")) != null)
    }

    private fun revoke(linkId: String, expectedVersion: Long): JsonObject =
        session.rpc("topology.apply", JsonObject().apply {
            addProperty("kind", "link.revoke")
            add("revoke_link", JsonObject().apply {
                addProperty("link_id", linkId)
                addProperty("expected_link_version", expectedVersion)
                addProperty("reason", "Android Link proposal interop acceptance")
            })
        })

    private fun assertLinkTerms(
        link: JsonObject,
        sourceEndpointId: String,
        sourceGroupId: String,
        targetEndpointId: String,
        targetGroupId: String,
        version: Long,
        state: String,
    ) {
        assertEquals(sourceEndpointId, link.get("source_endpoint_id").asString)
        assertEquals(sourceGroupId, link.get("source_group_id").asString)
        assertEquals(targetEndpointId, link.get("target_endpoint_id").asString)
        assertEquals(targetGroupId, link.get("target_group_id").asString)
        assertEquals(version, link.get("version").asLong)
        assertEquals(state, link.get("state").asString)
        assertEquals("forward", link.get("direction").asString)
        assertEquals(setOf("ask", "reply"),
            link.getAsJsonArray("actions").map { it.asString }.toSet())
        assertEquals(setOf("benchmark.public_result"),
            link.getAsJsonArray("data_scopes").map { it.asString }.toSet())
    }
}
