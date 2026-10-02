package ai.cicada.client.hub

import android.util.AtomicFile
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest

/** Live v1.6.1 Link policy status checks using one already-enrolled Owner profile. */
@RunWith(AndroidJUnit4::class)
class LinkReviewPolicyStatusInteropTest {
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val profiles get() = HubProfileStore(target)
    private val args get() = InstrumentationRegistry.getArguments()
    private val runId get() = args.getString("run_id")
        ?.takeIf { it.matches(Regex("v16-deterministic-v161-[A-Za-z0-9_-]{1,80}")) }
        ?: error("A bounded v1.6.1 run ID is required")
    private val directory get() = File(target.noBackupFilesDir, "network-v16/$runId")

    private data class Selection(
        val hubId: String,
        val ownerId: String,
        val deviceId: String,
        val catalogSha256: String,
        val linkId: String,
        val linkVersion: Long,
        val foreignLinkId: String?,
    )

    private data class Lookup(val selection: LinkReviewPolicySelection?, val pages: Int)

    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
        ?: error("Missing bounded public status fixture field")

    private fun long(value: JsonObject, key: String): Long = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asLong
        ?: error("Missing bounded public status fixture field")

    private fun hash(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun activeScope(): HubProfileStore.Scope {
        val selected = profiles.listHubProfiles().getAsJsonObject("activeScope")
        return HubProfileStore.Scope(text(selected, "profileId"), long(selected, "selectionGeneration"))
    }

    private fun read(name: String): JsonObject = try {
        val file = File(directory, name)
        require(!Files.isSymbolicLink(file.toPath()) && file.length() in 1..256 * 1024)
        JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    } catch (_: Exception) {
        error("Required bounded public status fixture is unavailable")
    }

    private fun selection(): Selection {
        val value = read("link-status-selection.json")
        assertEquals("cicada.client-v161-link-status-selection.v1", text(value, "schema"))
        assertEquals(runId, text(value, "run_id"))
        val allowed = setOf("schema", "run_id", "hub_id", "owner_id", "device_id", "link_id",
            "catalog_sha256", "expected_link_version", "foreign_link_id")
        assertTrue("Status selection has unknown fields", allowed.containsAll(value.keySet()))
        assertTrue("Status selection is incomplete", value.keySet().containsAll(allowed - "foreign_link_id"))
        if (value.has("foreign_link_id")) {
            assertTrue("Optional selector must be a string",
                value.get("foreign_link_id").isJsonPrimitive && value.get("foreign_link_id").asJsonPrimitive.isString)
        }
        val result = Selection(
            text(value, "hub_id"), text(value, "owner_id"), text(value, "device_id"),
            text(value, "catalog_sha256"), text(value, "link_id"), long(value, "expected_link_version"),
            value.get("foreign_link_id")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString,
        )
        assertTrue(result.catalogSha256.matches(Regex("[0-9a-f]{64}")))
        assertTrue(result.linkVersion in 1L..9_007_199_254_740_991L)
        assertTrue(result.linkId.isNotBlank() && result.linkId.length <= 256)
        result.foreignLinkId?.let { assertTrue(it.isNotBlank() && it.length <= 256 && it != result.linkId) }
        return result
    }

    private fun sessionState(scope: HubProfileStore.Scope): JsonObject {
        val stateFile = File(ClientHubSession.profileDirectory(target, scope.profileId), "session-state.json")
        require(!Files.isSymbolicLink(stateFile.toPath()) && stateFile.length() in 1..1024 * 1024)
        return JsonParser.parseString(stateFile.readText(StandardCharsets.UTF_8)).asJsonObject
    }

    private fun ownerSession(scope: HubProfileStore.Scope, expected: Selection, block: (ClientHubSession, JsonObject) -> Unit) {
        val status = profiles.getStatus(scope)
        assertTrue("The selected Owner session must be enrolled", status.get("enrolled").asBoolean)
        assertTrue("The selected Owner session must have encrypted capabilities", status.get("sessionCapabilitiesReady").asBoolean)
        assertEquals(expected.hubId, text(status, "hubId"))
        assertEquals(expected.ownerId, text(status, "ownerId"))
        assertEquals(expected.deviceId, text(status, "deviceId"))
        assertTrue(long(status, "sessionEpoch") > 0L)
        assertFalse("Resolve any prior encrypted request first", status.has("pendingOperationId"))

        profiles.withActiveScope(scope) { session ->
            val packet = session.rpc("session.capabilities", JsonObject())
            assertTrue("Encrypted Owner capabilities were refused", packet.get("ok").asBoolean)
            val capabilities = packet.getAsJsonObject("result")
            assertEquals("client-hub-v1.6.1", text(capabilities, "contract_revision"))
            assertEquals(expected.catalogSha256, text(capabilities, "catalog_sha256"))
            assertEquals(expected.ownerId, text(capabilities, "owner_id"))
            assertTrue(text(capabilities, "role") in setOf("manager", "external"))
            val operations = capabilities.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
            assertTrue(operations.containsAll(setOf("link.list", "link.review_policy_status")))
            assertTrue(session.getStatus().getAsJsonArray("allowedOperations").map { it.asString }
                .containsAll(setOf("link.list", "link.review_policy_status")))
            block(session, capabilities)
        }

        assertEquals("Active Hub profile changed during status read", scope, activeScope())
        val after = profiles.getStatus(scope)
        assertEquals(expected.hubId, text(after, "hubId"))
        assertEquals(expected.ownerId, text(after, "ownerId"))
        assertEquals(expected.deviceId, text(after, "deviceId"))
        assertEquals(status.get("sessionEpoch").asLong, after.get("sessionEpoch").asLong)
    }

    private fun findSelection(session: ClientHubSession, linkId: String): Lookup {
        var cursor: String? = null
        val seenCursors = HashSet<String>()
        val seenLinks = HashSet<String>()
        var pages = 0
        repeat(32) {
            val request = JsonObject().apply {
                addProperty("limit", 100)
                cursor?.let { addProperty("cursor", it) }
            }
            val response = session.rpc("link.list", request)
            assertTrue("Encrypted Owner Link list was refused", response.get("ok").asBoolean)
            pages += 1
            val page = LinkReviewPolicyStatusValidation.parseLinkListPage(response.getAsJsonObject("result"))
            page.links.forEach { item ->
                assertTrue("Encrypted Owner Link list repeated an ID", seenLinks.add(item.linkId))
                if (item.linkId == linkId) return Lookup(item, pages)
            }
            if (!page.hasMore) return Lookup(null, pages)
            assertTrue("Encrypted Owner Link list repeated a cursor", seenCursors.add(page.cursor))
            cursor = page.cursor
        }
        error("Encrypted Owner Link list exceeded the bounded page count")
    }

    private fun expectCode(expected: String, action: () -> Unit) {
        try {
            action()
            fail("Expected bounded status refusal")
        } catch (error: HubSessionException) {
            assertEquals(expected, error.errorCode)
        }
    }

    private fun save(name: String, value: JsonObject) {
        check(directory.isDirectory || directory.mkdirs())
        val file = AtomicFile(File(directory, name))
        val stream = file.startWrite()
        try {
            stream.write(value.toString().toByteArray(StandardCharsets.UTF_8))
            stream.fd.sync()
            file.finishWrite(stream)
        } catch (_: Exception) {
            file.failWrite(stream)
            error("Could not save redacted Link status evidence")
        }
        check(file.baseFile.setReadable(false, false) && file.baseFile.setReadable(true, true))
        check(file.baseFile.setWritable(false, false) && file.baseFile.setWritable(true, true))
    }

    private fun receiptName(scenario: String, ownerId: String) =
        "link-status-$scenario-${hash(ownerId).take(16)}.redacted.json"

    @Test fun readsCurrentNonePolicyForSelectedOwnerLink() {
        val scope = activeScope()
        val expected = selection()
        ownerSession(scope, expected) { session, capabilities ->
            val lookup = findSelection(session, expected.linkId)
            val selected = lookup.selection
                ?: error("Selected Link is not present in the authenticated Owner Link list")
            assertEquals(expected.linkVersion, selected.linkVersion)
            val status = session.linkReviewPolicyStatus(expected.linkId, expected.linkVersion)
            val parsed = LinkReviewPolicyStatusValidation.validateStatus(status, expected.linkId, expected.linkVersion)
            assertEquals("NONE", parsed.mode)
            assertEquals(0L, parsed.policyVersion)
            assertEquals("", parsed.policyDigest)
            assertTrue(parsed.current)
            assertTrue(parsed.acceptedSides.isEmpty())
            assertEquals(null, parsed.expiresAt)
            assertEquals(selected.mySide, findSelection(session, expected.linkId).selection?.mySide)

            val after = session.getStatus()
            assertFalse(after.has("pendingOperationId"))
            save(receiptName("none", expected.ownerId), JsonObject().apply {
                addProperty("schema", "cicada.client-v161-link-status-owner-result.v1")
                addProperty("result", "PASS")
                addProperty("scenario", "selected_link_default_none")
                addProperty("hub_id_sha256", hash(expected.hubId))
                addProperty("owner_id_sha256", hash(expected.ownerId))
                addProperty("device_id_sha256", hash(expected.deviceId))
                addProperty("profile_id_sha256", hash(scope.profileId))
                addProperty("link_id_sha256", hash(expected.linkId))
                addProperty("my_side", selected.mySide)
                addProperty("link_version", parsed.linkVersion)
                addProperty("policy_mode", parsed.mode)
                addProperty("policy_version", parsed.policyVersion)
                addProperty("policy_digest_sha256", hash(parsed.policyDigest))
                addProperty("current", parsed.current)
                addProperty("accepted_side_count", parsed.acceptedSides.size)
                addProperty("expires_at_present", parsed.expiresAt != null)
                addProperty("approval_inferred", false)
                addProperty("role", text(capabilities, "role"))
                addProperty("session_epoch", after.get("sessionEpoch").asLong)
                addProperty("pending", false)
            })
        }
    }

    @Test fun refusesUnknownAndOptionalForeignLinkBeforeStatusRpc() {
        val scope = activeScope()
        val expected = selection()
        ownerSession(scope, expected) { session, _ ->
            val unknown = "unknown-${hash(runId + expected.ownerId).take(20)}"
            val unknownLookup = findSelection(session, unknown)
            assertEquals(null, unknownLookup.selection)
            var before = sessionState(scope)
            expectCode("LINK_REVIEW_LINK_UNAVAILABLE") {
                session.linkReviewPolicyStatus(unknown, expected.linkVersion)
            }
            var after = sessionState(scope)
            assertEquals(before.get("nextSequence").asLong + unknownLookup.pages, after.get("nextSequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + unknownLookup.pages, after.get("lastResponseSequence").asLong)
            assertFalse(after.has("pending"))

            var foreignResult = "NOT_RUN"
            expected.foreignLinkId?.let { foreignLinkId ->
                val foreignLookup = findSelection(session, foreignLinkId)
                assertEquals(null, foreignLookup.selection)
                before = sessionState(scope)
                expectCode("LINK_REVIEW_LINK_UNAVAILABLE") {
                    session.linkReviewPolicyStatus(foreignLinkId, expected.linkVersion)
                }
                after = sessionState(scope)
                assertEquals(before.get("nextSequence").asLong + foreignLookup.pages, after.get("nextSequence").asLong)
                assertEquals(before.get("lastResponseSequence").asLong + foreignLookup.pages, after.get("lastResponseSequence").asLong)
                assertFalse(after.has("pending"))
                foreignResult = "AUTHENTICATED_LIST_SELECTION_REFUSAL_TO_UNVERIFIED_REFERENCE"
            }
            save(receiptName("owner-filter", expected.ownerId), JsonObject().apply {
                addProperty("schema", "cicada.client-v161-link-status-negative-result.v1")
                addProperty("result", "PASS")
                addProperty("unknown_link", "AUTHENTICATED_LIST_SELECTION_REFUSAL")
                addProperty("optional_unverified_link_selector", foreignResult)
                addProperty("foreign_owner_hub_guard", "NOT_RUN")
                addProperty("owner_id_sha256", hash(expected.ownerId))
                addProperty("unknown_selector_sha256", hash(unknown))
                expected.foreignLinkId?.let { addProperty("foreign_selector_sha256", hash(it)) }
                addProperty("status_rpc_sent_for_refused_selectors", false)
            })
        }
    }

    @Test fun rejectsStaleExpectedLinkVersionBeforeStatusRpc() {
        val scope = activeScope()
        val expected = selection()
        ownerSession(scope, expected) { session, _ ->
            val lookup = findSelection(session, expected.linkId)
            val current = lookup.selection
                ?: error("Selected Link is not present in the authenticated Owner Link list")
            assertEquals(expected.linkVersion, current.linkVersion)
            val staleSelection = if (current.linkVersion < 9_007_199_254_740_991L) {
                current.linkVersion + 1
            } else current.linkVersion - 1
            val before = sessionState(scope)
            expectCode("LINK_REVIEW_LINK_STALE") {
                session.linkReviewPolicyStatus(expected.linkId, staleSelection)
            }
            val after = sessionState(scope)
            assertEquals(before.get("nextSequence").asLong + lookup.pages, after.get("nextSequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + lookup.pages, after.get("lastResponseSequence").asLong)
            assertFalse(after.has("pending"))
            save(receiptName("stale-selection", expected.ownerId), JsonObject().apply {
                addProperty("schema", "cicada.client-v161-link-status-negative-result.v1")
                addProperty("result", "PASS")
                addProperty("boundary", "CLIENT_EXPECTED_VERSION_GUARD_AFTER_AUTHENTICATED_LIST")
                addProperty("owner_id_sha256", hash(expected.ownerId))
                addProperty("link_id_sha256", hash(expected.linkId))
                addProperty("current_link_version", current.linkVersion)
                addProperty("mismatched_expected_version", staleSelection)
                addProperty("status_rpc_sent", false)
            })
        }
    }

    @Test fun rejectsGenericStatusRpcBypassWithoutSequenceUse() {
        val scope = activeScope()
        val expected = selection()
        ownerSession(scope, expected) { session, _ ->
            val before = sessionState(scope)
            expectCode("VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED") {
                session.rpc("link.review_policy_status", JsonObject().apply {
                    addProperty("link_id", expected.linkId)
                })
            }
            val after = sessionState(scope)
            assertEquals(before.get("nextSequence").asLong, after.get("nextSequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong, after.get("lastResponseSequence").asLong)
            assertEquals(before.get("pending"), after.get("pending"))
            assertEquals(before.get("linkReviewStatusReadContext"), after.get("linkReviewStatusReadContext"))
            save(receiptName("generic-bypass", expected.ownerId), JsonObject().apply {
                addProperty("schema", "cicada.client-v161-link-status-negative-result.v1")
                addProperty("result", "PASS")
                addProperty("boundary", "CLIENT_GENERIC_RPC_BYPASS_GUARD")
                addProperty("owner_id_sha256", hash(expected.ownerId))
                addProperty("link_id_sha256", hash(expected.linkId))
                addProperty("sequence_unchanged", true)
                addProperty("pending_unchanged", true)
            })
        }
    }

    @Test fun capturesAndRecoversExactStatusPacket() {
        val scope = activeScope()
        val expected = selection()
        ownerSession(scope, expected) { session, _ ->
            val lookup = findSelection(session, expected.linkId)
            val selected = lookup.selection
                ?: error("Selected Link is not present in the authenticated Owner Link list")
            assertEquals(expected.linkVersion, selected.linkVersion)
            val sessionEpoch = session.getStatus().get("sessionEpoch").asLong
            val before = sessionState(scope)
            assertFalse(before.has("pending"))
            assertFalse(before.has("linkReviewStatusReadContext"))
            expectCode("NETWORK_ERROR") {
                session.linkReviewPolicyStatus(expected.linkId, expected.linkVersion)
            }

            val lost = sessionState(scope)
            val pending = lost.getAsJsonObject("pending")
            val exactPacket = text(pending, "packetJson")
            val packet = JsonParser.parseString(exactPacket).asJsonObject
            val route = ClientWireCrypto.Route.parse(packet.getAsJsonObject("route"))
            val context = lost.getAsJsonObject("linkReviewStatusReadContext")
            assertEquals("link.review_policy_status", text(pending, "operation"))
            assertEquals("link.review_policy_status", route.operation)
            assertEquals(expected.hubId, route.hubId)
            assertEquals(expected.ownerId, route.ownerId)
            assertEquals(expected.deviceId, route.deviceId)
            assertEquals(sessionEpoch, route.sessionEpoch)
            assertEquals(text(pending, "operationId"), route.operationId)
            assertEquals(pending.get("sequence").asLong, route.sequence)
            assertEquals(expected.linkId, text(context, "link_id"))
            assertEquals(expected.linkVersion, context.get("link_version").asLong)
            assertEquals(selected.mySide, text(context, "my_side"))
            assertEquals(expected.hubId, text(context, "hub_id"))
            assertEquals(expected.ownerId, text(context, "owner_id"))
            assertEquals(expected.deviceId, text(context, "device_id"))
            assertEquals(route.sessionEpoch, context.get("session_epoch").asLong)
            assertEquals(route.operationId, text(context, "operation_id"))
            assertEquals(route.sequence, context.get("sequence").asLong)
            assertEquals(before.get("nextSequence").asLong + lookup.pages + 1, lost.get("nextSequence").asLong)
            assertEquals(before.get("lastResponseSequence").asLong + lookup.pages,
                lost.get("lastResponseSequence").asLong)
            assertEquals(before.get("nextSequence").asLong + lookup.pages, route.sequence)
            assertEquals(route.sequence + 1, lost.get("nextSequence").asLong)

            val recovered = session.recoverPending()
            assertTrue(recovered.get("ok").asBoolean)
            assertEquals(route.operationId, text(recovered, "operationId"))
            val result = recovered.getAsJsonObject("result")
            val parsed = LinkReviewPolicyStatusValidation.validateStatus(result, expected.linkId, expected.linkVersion)
            assertEquals("NONE", parsed.mode)
            assertEquals(0L, parsed.policyVersion)

            val resolved = sessionState(scope)
            assertFalse(resolved.has("pending"))
            assertFalse(resolved.has("linkReviewStatusReadContext"))
            assertEquals(lost.get("nextSequence").asLong, resolved.get("nextSequence").asLong)
            assertEquals(lost.get("lastResponseSequence").asLong + 1, resolved.get("lastResponseSequence").asLong)
            save(receiptName("response-loss-recovery", expected.ownerId), JsonObject().apply {
                addProperty("schema", "cicada.client-v161-link-status-recovery-result.v1")
                addProperty("result", "PASS")
                addProperty("scope", "SAME_PROCESS_DURABLE_JOURNAL")
                addProperty("owner_id_sha256", hash(expected.ownerId))
                addProperty("device_id_sha256", hash(expected.deviceId))
                addProperty("link_id_sha256", hash(expected.linkId))
                addProperty("my_side", selected.mySide)
                addProperty("operation", route.operation)
                addProperty("operation_id_sha256", hash(route.operationId))
                addProperty("original_packet_sha256", hash(exactPacket))
                addProperty("sequence", route.sequence)
                addProperty("policy_mode", parsed.mode)
                addProperty("policy_version", parsed.policyVersion)
                addProperty("pending_after_recovery", false)
                addProperty("context_after_recovery", false)
                addProperty("process_death_recovery", "NOT_RUN")
            })
        }
    }
}
