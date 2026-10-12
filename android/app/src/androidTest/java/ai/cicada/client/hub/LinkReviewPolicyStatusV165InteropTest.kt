package ai.cicada.client.hub

import android.util.AtomicFile
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Instant

/** Eight independent v1.6.5 status cases. Root owns enrollment, faults and Hub restart. */
@RunWith(AndroidJUnit4::class)
class LinkReviewPolicyStatusV165InteropTest {
    private val target get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val args get() = InstrumentationRegistry.getArguments()
    private val profiles get() = HubProfileStore(target)
    private val runId get() = argument("run_id").also {
        guard(it.matches(Regex("v165-link-policy-status-[A-Za-z0-9_-]{1,64}")), "RUN_SCOPE")
    }
    private val directory get() = File(target.noBackupFilesDir, "link-policy-status-v165/$runId")
    private val fixtureSha get() = argument("fixture_sha256").also { guard(hashPattern.matches(it), "FIXTURE_PIN") }

    @Test fun keyStatusAcrossOwnedRestart() = runCase("KEY", "restart")
    @Test fun noneStatusAcrossOwnedRestart() = runCase("NONE", "restart")
    @Test fun keyOwnerRefusalsAcrossOwnedRestart() = runCase("KEY", "owner-refusal")
    @Test fun noneOwnerRefusalsAcrossOwnedRestart() = runCase("NONE", "owner-refusal")
    @Test fun keyVersionAndBypassRefusalsAcrossOwnedRestart() = runCase("KEY", "version-bypass")
    @Test fun noneVersionAndBypassRefusalsAcrossOwnedRestart() = runCase("NONE", "version-bypass")
    @Test fun keyStatusResponseLossAcrossOwnedRestart() = runCase("KEY", "response-loss")
    @Test fun noneStatusResponseLossAcrossOwnedRestart() = runCase("NONE", "response-loss")

    private fun runCase(lane: String, scenario: String) {
        assumeTrue("NOT_RUN_V165_FIXTURE_ARGUMENTS_REQUIRED", listOf("run_id", "fixture_sha256", "phase",
            "case_deadline_utc", "source_revision", "source_fingerprint", "hub_image_id").all { args.containsKey(it) })
        val phase = argument("phase")
        guard(LinkPolicyStatusFixtureV165.phaseAllowed(phase, scenario), "PHASE_SCOPE")
        if (phase == "capture_response_loss") assumeTrue("NOT_RUN_STATUS_FAULT_FIXTURE_REQUIRED", args.containsKey("fault_sha256"))
        if (phase in setOf("recover_after_restart", "after_restart")) {
            assumeTrue("NOT_RUN_OWNED_RESTART_FIXTURE_REQUIRED", args.containsKey("restart_sha256"))
        }
        deadline()
        val raw = readRequired("fixture.public.json", fixtureSha, 64 * 1024)
        val fixture = try {
            LinkPolicyStatusFixtureV165.parse(raw, runId, lane, scenario)
        } catch (_: IllegalArgumentException) { throw AssertionError("STATUS_FIXTURE_INVALID") }
        for (key in listOf("source_revision", "source_fingerprint", "hub_image_id")) {
            guard(text(fixture.root, key) == argument(key), "DELIVERY_PIN")
        }
        val scope = selectedScope(fixture)
        if (phase != "before_restart") {
            val baseline = readObject("before.redacted.json")
            guard(text(baseline, "fixture_sha256") == fixtureSha &&
                text(baseline, "case_deadline_utc") == argument("case_deadline_utc"), "BASELINE_SCOPE")
        }
        if (scenario == "version-bypass") {
            assumeTrue("NOT_RUN_OLD_VERSION_FIXTURE_REQUIRED", fixture.linkVersion > 1)
        }
        profiles.withActiveScope(scope) { session ->
            assertIdentity(session, scope, fixture)
            when (phase) {
                "before_restart" -> {
                    assertResolved(state(scope))
                    val status = freshStatus(session, scope, fixture)
                    refusalChecks(session, scope, fixture)
                    save("before.redacted.json", snapshot(session, scope, fixture, status).apply {
                        addProperty("result", "BEFORE_RESTART_VERIFIED")
                    })
                }
                "capture_response_loss" -> captureLoss(session, scope, fixture)
                "recover_after_restart" -> {
                    assertRestart(fixture)
                    recoverLoss(session, scope, fixture)
                }
                "after_restart" -> {
                    val before = readObject("before.redacted.json")
                    guard(text(before, "fixture_sha256") == fixtureSha, "BASELINE_SCOPE")
                    assertRestart(fixture)
                    if (scenario == "response-loss") reconcileRecoveredLoss(session, scope, fixture)
                    val status = freshStatus(session, scope, fixture)
                    refusalChecks(session, scope, fixture)
                    val after = snapshot(session, scope, fixture, status)
                    for (key in identityReceiptFields) {
                        guard(before.get(key) == after.get(key), "RESTART_IDENTITY_CHANGED")
                    }
                    guard(before.get("status_metadata_sha256") == after.get("status_metadata_sha256"),
                        "RESTART_POLICY_CHANGED")
                    guard(number(after, "next_sequence") > number(before, "next_sequence") &&
                        number(after, "last_response_sequence") > number(before, "last_response_sequence"),
                        "RESTART_COUNTER_REGRESSION")
                    save("after.redacted.json", after.apply {
                        addProperty("result", "PASS")
                        addProperty("owned_restart_receipt_sha256", argument("restart_sha256"))
                        addProperty("android_status_read", "PASS")
                        addProperty("external_go_status_substitute", false)
                        addProperty("database_read", false)
                        if (scenario == "response-loss") addProperty("uncertain_nonnull_recovery",
                            if (fixture.recoveryResult == "OUTCOME_UNCERTAIN") "PASS" else "NOT_RUN")
                        addProperty("native_runtime", "NOT_RUN")
                        addProperty("physical_android", "NOT_RUN")
                        addProperty("public_https", "NOT_RUN")
                    })
                }
            }
            guard(selectedScope(fixture) == scope, "PROFILE_CHANGED")
        }
    }

    private fun selectedScope(fixture: LinkPolicyStatusFixtureV165.Fixture): HubProfileStore.Scope {
        val active = profiles.listHubProfiles().getAsJsonObject("activeScope")
        val scope = HubProfileStore.Scope(text(active, "profileId"), number(active, "selectionGeneration"))
        guard(scope.profileId == fixture.profileId && scope.selectionGeneration == fixture.profileGeneration,
            "PROFILE_SCOPE")
        return scope
    }

    private fun assertIdentity(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture) {
        val status = session.getStatus()
        guard(bool(status, "pinned") && bool(status, "enrolled"), "SESSION_SCOPE")
        guard(text(status, "profileId") == scope.profileId && text(status, "hubId") == fixture.hubId &&
            text(status, "ownerId") == fixture.ownerId && text(status, "deviceId") == fixture.deviceId &&
            number(status, "sessionEpoch") == fixture.sessionEpoch, "SESSION_SCOPE")
        val saved = state(scope)
        val pin = saved.getAsJsonObject("pin")
        val publicIdentity = ClientWireCrypto.PublicIdentity.parse(fixture.controlPublicIdentity)
        val savedIdentity = ClientWireCrypto.PublicIdentity.parse(
            JsonParser.parseString(text(pin, "controlPublicIdentityJson")).asJsonObject)
        guard(publicIdentity.sameAs(savedIdentity) && number(pin, "controlKeyVersion") == fixture.controlKeyVersion,
            "HUB_PUBLIC_PIN_CHANGED")
    }

    private fun capabilities(session: ClientHubSession, fixture: LinkPolicyStatusFixtureV165.Fixture): Set<String> {
        deadline()
        val response = session.rpc("session.capabilities", JsonObject())
        guard(bool(response, "ok"), "CAPABILITIES_REFUSED")
        val value = response.getAsJsonObject("result")
        guard(text(value, "contract_revision") == LinkPolicyStatusFixtureV165.CONTRACT &&
            text(value, "catalog_sha256") == LinkPolicyStatusFixtureV165.CATALOG &&
            text(value, "owner_id") == fixture.ownerId && text(value, "role") in setOf("manager", "external"),
            "ENCRYPTED_CAPABILITIES_SCOPE")
        val operations = value.getAsJsonArray("available_rpc_operations").map { it.asString }.toSet()
        guard(operations.containsAll(setOf("session.capabilities", "link.list", "link.review_policy_status")),
            "STATUS_OPERATION_UNAVAILABLE")
        guard(session.getStatus().getAsJsonArray("allowedOperations").map { it.asString }.toSet()
            .containsAll(setOf("session.capabilities", "link.list", "link.review_policy_status")),
            "STATUS_OPERATION_UNAVAILABLE")
        return operations
    }

    private fun listSelection(session: ClientHubSession, linkId: String): LinkReviewPolicySelection? {
        var cursor: String? = null
        val cursors = HashSet<String>()
        val seenLinks = HashSet<String>()
        repeat(32) {
            deadline()
            val response = session.rpc("link.list", JsonObject().apply {
                addProperty("limit", 100)
                cursor?.let { addProperty("cursor", it) }
            })
            guard(bool(response, "ok"), "LINK_LIST_REFUSED")
            val page = LinkReviewPolicyStatusValidation.parseLinkListPage(response.getAsJsonObject("result"))
            for (link in page.links) {
                guard(seenLinks.add(link.linkId), "LINK_LIST_DUPLICATE")
                if (link.linkId == linkId) return link
            }
            if (!page.hasMore) return null
            guard(cursors.add(page.cursor), "LINK_LIST_CURSOR_REPEATED")
            cursor = page.cursor
        }
        throw AssertionError("LINK_LIST_BOUND")
    }

    private fun freshStatus(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture): JsonObject {
        capabilities(session, fixture)
        val selected = listSelection(session, fixture.linkId)
            ?: throw AssertionError("SELECTED_LINK_UNAVAILABLE")
        guard(selected.linkVersion == fixture.linkVersion && selected.mySide == fixture.mySide, "LINK_SCOPE")
        deadline()
        val status = session.linkReviewPolicyStatus(fixture.linkId, fixture.linkVersion, scope.selectionGeneration)
        LinkPolicyStatusFixtureV165.assertStatus(status, fixture)
        assertResolved(state(scope))
        assertIdentity(session, scope, fixture)
        return status
    }

    private fun refusalChecks(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture) {
        when (fixture.scenario) {
            "owner-refusal" -> {
                val unknown = "unknown-${sha256((runId + fixture.caseId).toByteArray()).take(24)}"
                for (id in listOf(unknown, fixture.foreignLinkId!!)) {
                    guard(listSelection(session, id) == null, "FOREIGN_LINK_VISIBLE")
                    expect("LINK_REVIEW_LINK_UNAVAILABLE") {
                        session.linkReviewPolicyStatus(id, fixture.linkVersion, scope.selectionGeneration)
                    }
                    assertResolved(state(scope))
                }
            }
            "version-bypass" -> {
                expect("LINK_REVIEW_LINK_STALE") {
                    session.linkReviewPolicyStatus(fixture.linkId, fixture.linkVersion - 1, scope.selectionGeneration)
                }
                assertResolved(state(scope))
                val before = state(scope)
                expect("VERIFIED_LINK_REVIEW_STATUS_FLOW_REQUIRED") {
                    session.rpc("link.review_policy_status", JsonObject().apply { addProperty("link_id", fixture.linkId) })
                }
                val after = state(scope)
                for (key in journalFields) guard(before.get(key) == after.get(key), "BYPASS_CHANGED_JOURNAL")
            }
        }
    }

    private fun captureLoss(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture) {
        val baseline = readObject("before.redacted.json")
        guard(text(baseline, "fixture_sha256") == fixtureSha, "BASELINE_SCOPE")
        val fault = readObject("fault.public.json", argument("fault_sha256"))
        guard(fault.keySet() == setOf("schema", "run_id", "case_id", "fixture_sha256", "operation", "ready", "recovery_result"),
            "FAULT_FIELDS")
        guard(text(fault, "schema") == "cicada.client-v165-link-policy-status-fault.v1" &&
            text(fault, "run_id") == runId && number(fault, "case_id") == fixture.caseId.toLong() &&
            text(fault, "fixture_sha256") == fixtureSha && text(fault, "operation") == "link.review_policy_status" &&
            bool(fault, "ready") && text(fault, "recovery_result") == fixture.recoveryResult, "FAULT_SCOPE")
        assertResolved(state(scope))
        capabilities(session, fixture)
        val selected = listSelection(session, fixture.linkId)
            ?: throw AssertionError("SELECTED_LINK_UNAVAILABLE")
        guard(selected.linkVersion == fixture.linkVersion && selected.mySide == fixture.mySide, "LINK_SCOPE")
        expect("NETWORK_ERROR") {
            session.linkReviewPolicyStatus(fixture.linkId, fixture.linkVersion, scope.selectionGeneration)
        }
        val lost = journalSnapshot(session, scope, fixture)
        // Complete the reopen check before publishing the restart ACK.
        profiles.withActiveScope(scope) { reopened ->
            guard(journalSnapshot(reopened, scope, fixture) == lost, "REOPEN_CLEARED_PENDING_CONTEXT")
        }
        save("loss.redacted.json", lost.apply {
            addProperty("schema", "cicada.client-v165-link-policy-status-loss.v1")
            addProperty("result", "ORIGINAL_STATUS_PACKET_PENDING")
            addProperty("fixture_sha256", fixtureSha)
            addProperty("case_deadline_utc", argument("case_deadline_utc"))
            addProperty("fault_receipt_sha256", argument("fault_sha256"))
        })
    }

    private fun journalSnapshot(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture): JsonObject {
        assertIdentity(session, scope, fixture)
        val saved = state(scope)
        val pending = saved.getAsJsonObject("pending") ?: throw AssertionError("ORIGINAL_PENDING_MISSING")
        val route = ClientWireCrypto.Route.parse(JsonParser.parseString(text(pending, "packetJson"))
            .asJsonObject.getAsJsonObject("route"))
        val context = saved.getAsJsonObject("linkConsentStatusReadContext")
            ?: throw AssertionError("CURRENT_STATUS_CONTEXT_MISSING")
        guard(!saved.has("linkReviewStatusReadContext"), "CONFLICTING_STATUS_CONTEXT")
        guard(text(pending, "operation") == "link.review_policy_status" && route.operation == "link.review_policy_status" &&
            route.operationId == text(pending, "operationId") && route.sequence == number(pending, "sequence") &&
            route.hubId == fixture.hubId && route.ownerId == fixture.ownerId && route.deviceId == fixture.deviceId &&
            route.sessionEpoch == fixture.sessionEpoch, "ORIGINAL_PACKET_SCOPE")
        guard(context.keySet() == setOf("link_id", "link_version", "my_side", "hub_id", "owner_id", "device_id",
            "session_epoch", "operation_id", "sequence", "profile_generation"), "STATUS_CONTEXT_FIELDS")
        guard(text(context, "link_id") == fixture.linkId && number(context, "link_version") == fixture.linkVersion &&
            text(context, "my_side") == fixture.mySide && text(context, "hub_id") == fixture.hubId &&
            text(context, "owner_id") == fixture.ownerId && text(context, "device_id") == fixture.deviceId &&
            number(context, "session_epoch") == fixture.sessionEpoch && text(context, "operation_id") == route.operationId &&
            number(context, "sequence") == route.sequence && number(context, "profile_generation") == scope.selectionGeneration,
            "STATUS_CONTEXT_SCOPE")
        val public = session.getStatus()
        guard(text(public, "pendingOperationId") == route.operationId, "PENDING_OPERATION_CHANGED")
        guard(number(saved, "nextSequence") == route.sequence + 1 &&
            number(pending, "expectedResponseSequence") == number(saved, "lastResponseSequence") + 1,
            "ORIGINAL_COUNTER_CONTEXT")
        return JsonObject().apply {
            addProperty("operation_id_sha256", hash(route.operationId))
            addProperty("original_packet_sha256", hash(text(pending, "packetJson")))
            addProperty("context_sha256", hash(context.toString()))
            addProperty("profile_generation", number(context, "profile_generation"))
            addProperty("request_sequence", route.sequence)
            addProperty("expected_response_sequence", number(pending, "expectedResponseSequence"))
            addProperty("next_sequence", number(saved, "nextSequence"))
            addProperty("last_response_sequence", number(saved, "lastResponseSequence"))
            addProperty("uncertain_needs_reconciliation", bool(saved, "uncertainNeedsReconciliation"))
            addProperty("legacy_context_present", saved.has("linkReviewStatusReadContext"))
        }
    }

    private fun recoverLoss(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture) {
        guard(!File(directory, "recovery.redacted.json").exists(), "RECOVERY_ALREADY_RECORDED")
        val capture = readObject("loss.redacted.json")
        guard(text(capture, "fixture_sha256") == fixtureSha, "LOSS_SCOPE")
        val reopened = journalSnapshot(session, scope, fixture)
        for (key in reopened.keySet()) guard(capture.get(key) == reopened.get(key), "RESTART_CLEARED_PENDING_CONTEXT")
        val stateBefore = state(scope)
        val original = stateBefore.getAsJsonObject("pending")
        deadline()
        val recovered = session.recoverPending()
        guard(hash(text(recovered, "operationId")) == text(capture, "operation_id_sha256"), "RECOVER_OPERATION_CHANGED")
        val after = state(scope)
        guard(!after.has("pending") && !after.has("linkReviewStatusReadContext") &&
            !after.has("linkConsentStatusReadContext"), "AUTHENTICATED_RECOVERY_NOT_CONSUMED")
        guard(number(after, "nextSequence") == number(capture, "next_sequence") &&
            number(after, "lastResponseSequence") == number(capture, "expected_response_sequence"),
            "RECOVER_COUNTER_CHANGED")
        when (fixture.recoveryResult) {
            "COMPLETED" -> {
                guard(bool(recovered, "ok"), "RECOVERY_NOT_COMPLETED")
                LinkPolicyStatusFixtureV165.assertStatus(metadata(recovered.getAsJsonObject("result")), fixture)
                guard(!bool(after, "uncertainNeedsReconciliation"), "RECOVERY_UNEXPECTED_UNCERTAINTY")
            }
            "OUTCOME_UNCERTAIN" -> {
                guard(!bool(recovered, "ok") && text(recovered, "errorCode") == "OUTCOME_UNCERTAIN" &&
                    bool(after, "uncertainNeedsReconciliation") && after.get("retiredPending") == original,
                    "UNCERTAINTY_NOT_RETAINED")
                profiles.withActiveScope(scope) { reopenedSession ->
                    guard(bool(reopenedSession.getStatus(), "uncertainNeedsReconciliation"), "REOPEN_CLEARED_UNCERTAINTY")
                    expect("BUSINESS_RECONCILIATION_REQUIRED") {
                        reopenedSession.linkReviewPolicyStatus(fixture.linkId, fixture.linkVersion, scope.selectionGeneration)
                    }
                }
            }
            else -> throw AssertionError("RECOVERY_FIXTURE_INVALID")
        }
        val receipt = JsonObject().apply {
            addProperty("schema", "cicada.client-v165-link-policy-status-recovery.v1")
            addProperty("fixture_sha256", fixtureSha)
            addProperty("result", "ORIGINAL_PACKET_RECOVERED")
            addProperty("operation_id_sha256", text(capture, "operation_id_sha256"))
            addProperty("original_packet_sha256", text(capture, "original_packet_sha256"))
            addProperty("recovery_result", fixture.recoveryResult)
            addProperty("new_operation_created_for_recovery", false)
            addProperty("unresolved_fence_retention_checked", true)
            addProperty("next_sequence", number(after, "nextSequence"))
            addProperty("last_response_sequence", number(after, "lastResponseSequence"))
            addProperty("uncertain_needs_reconciliation", bool(after, "uncertainNeedsReconciliation"))
            addProperty("legacy_nonnull_context_restart", "NOT_RUN")
            addProperty("process_death", "NOT_RUN")
        }
        LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(receipt, capture, fixture)
        // No new RPC on the faulted proxy. Root routes the same pinned origin
        // back to the Hub only after this stage's receipt and JUnit exit 0.
        save("recovery.redacted.json", receipt)
    }

    private fun reconcileRecoveredLoss(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture) {
        val capture = readObject("loss.redacted.json")
        guard(text(capture, "fixture_sha256") == fixtureSha, "LOSS_SCOPE")
        val receipt = readObject("recovery.redacted.json")
        LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(receipt, capture, fixture)
        val retained = state(scope)
        guard(!retained.has("pending") && !retained.has("linkReviewStatusReadContext") &&
            !retained.has("linkConsentStatusReadContext"), "RECOVERY_CONTEXT_REAPPEARED")
        guard(number(retained, "nextSequence") == number(receipt, "next_sequence") &&
            number(retained, "lastResponseSequence") == number(receipt, "last_response_sequence") &&
            bool(retained, "uncertainNeedsReconciliation") == bool(receipt, "uncertain_needs_reconciliation"),
            "CONTINUE_CLEARED_RECOVERY_FENCE")
        if (fixture.recoveryResult == "COMPLETED") return

        val original = retained.getAsJsonObject("retiredPending")
            ?: throw AssertionError("STATUS_RETIRED_ORIGINAL_MISSING")
        guard(hash(text(original, "packetJson")) == text(capture, "original_packet_sha256") &&
            hash(text(original, "operationId")) == text(capture, "operation_id_sha256") &&
            number(original, "sequence") == number(capture, "request_sequence") &&
            text(original, "operation") == "link.review_policy_status" &&
            text(retained, "outcomeUncertainOperationId") == text(original, "operationId"),
            "CONTINUE_CHANGED_RETIRED_ORIGINAL")
        expect("BUSINESS_RECONCILIATION_REQUIRED") {
            session.linkReviewPolicyStatus(fixture.linkId, fixture.linkVersion, scope.selectionGeneration)
        }
        val operations = capabilities(session, fixture)
        guard(bool(session.getStatus(), "uncertainNeedsReconciliation"), "CAPABILITIES_CLEARED_UNCERTAINTY")
        listSelection(session, fixture.linkId)
        guard(bool(session.getStatus(), "uncertainNeedsReconciliation"), "LINK_LIST_CLEARED_UNCERTAINTY")
        val afterReads = state(scope)
        guard(afterReads.get("retiredPending") == original &&
            text(afterReads, "outcomeUncertainOperationId") == text(original, "operationId"),
            "READS_CLEARED_RETIRED_ORIGINAL")
        val pin = afterReads.getAsJsonObject("pin")
        val advertised = session.fetchHubMetadata(text(pin, "baseUrl")).getAsJsonObject("capabilities")
        val role = text(session.getStatus(), "role")
        val publicOperations = advertised.getAsJsonArray(
            if (role == "external") "external_rpc_operations" else "available_rpc_operations")
            .map { it.asString }.toSet()
        assumeTrue("NOT_RUN_AUTHENTICATED_RECONCILIATION_FIXTURE_REQUIRED",
            "status.snapshot" in operations && "status.snapshot" in publicOperations)
        val snapshot = session.rpc("status.snapshot", JsonObject())
        guard(bool(snapshot, "ok") && !bool(session.getStatus(), "uncertainNeedsReconciliation"),
            "AUTHENTICATED_RECONCILIATION_REFUSED")
        val reconciled = state(scope)
        guard(reconciled.get("retiredPending") == original &&
            text(reconciled, "outcomeUncertainOperationId") == text(original, "operationId"),
            "SNAPSHOT_DISCARDED_RETIRED_ORIGINAL")
    }

    private fun metadata(raw: JsonObject): JsonObject = JsonObject().apply {
        for (key in listOf("link_id", "link_version", "policy_version", "policy_digest", "policy", "current", "accepted_sides")) {
            add(key, raw.get(key)?.deepCopy() ?: throw AssertionError("RECOVER_STATUS_INVALID"))
        }
        raw.get("expires_at")?.let { add("expires_at", it.deepCopy()) }
    }

    private fun assertRestart(fixture: LinkPolicyStatusFixtureV165.Fixture) {
        val restart = readObject("restart.public.json", argument("restart_sha256"))
        guard(restart.keySet() == setOf("schema", "run_id", "case_id", "fixture_sha256", "status",
            "hub_id_sha256", "hub_container_id_sha256", "hub_image_id", "source_revision", "source_fingerprint",
            "before_started_at", "after_started_at"), "RESTART_FIELDS")
        guard(text(restart, "schema") == "cicada.client-v165-link-policy-status-owned-restart.v1" &&
            text(restart, "run_id") == runId && number(restart, "case_id") == fixture.caseId.toLong() &&
            text(restart, "fixture_sha256") == fixtureSha && text(restart, "status") == "PASS" &&
            text(restart, "hub_id_sha256") == hash(fixture.hubId) &&
            hashPattern.matches(text(restart, "hub_container_id_sha256")), "OWNED_RESTART_SCOPE")
        for (key in listOf("source_revision", "source_fingerprint", "hub_image_id")) {
            guard(restart.get(key) == fixture.root.get(key), "OWNED_RESTART_PIN")
        }
        val before = Instant.parse(text(restart, "before_started_at"))
        val after = Instant.parse(text(restart, "after_started_at"))
        guard(after.isAfter(before), "OWNED_RESTART_NOT_OBSERVED")
    }

    private fun snapshot(session: ClientHubSession, scope: HubProfileStore.Scope,
        fixture: LinkPolicyStatusFixtureV165.Fixture, status: JsonObject): JsonObject {
        val saved = state(scope)
        val parsed = LinkReviewPolicyStatusValidation.validateStatus(status, fixture.linkId, fixture.linkVersion)
        return JsonObject().apply {
            addProperty("schema", "cicada.client-v165-link-policy-status-result.v1")
            addProperty("run_id", runId); addProperty("case_id", fixture.caseId)
            addProperty("fixture_sha256", fixtureSha)
            addProperty("case_deadline_utc", argument("case_deadline_utc"))
            addProperty("fixture_lane", fixture.lane); addProperty("scenario", fixture.scenario)
            addProperty("profile_id_sha256", hash(scope.profileId)); addProperty("profile_generation", scope.selectionGeneration)
            addProperty("hub_id_sha256", hash(fixture.hubId)); addProperty("owner_id_sha256", hash(fixture.ownerId))
            addProperty("device_id_sha256", hash(fixture.deviceId)); addProperty("session_epoch", fixture.sessionEpoch)
            addProperty("link_id_sha256", hash(fixture.linkId)); addProperty("link_version", fixture.linkVersion)
            addProperty("my_side", fixture.mySide); addProperty("policy_mode", parsed.mode)
            addProperty("policy_version", parsed.policyVersion); addProperty("policy_digest", parsed.policyDigest)
            addProperty("current", parsed.current)
            add("accepted_sides", JsonArray().apply { parsed.acceptedSides.forEach(::add) })
            parsed.expiresAt?.let { addProperty("expires_at", it) }
            addProperty("status_metadata_sha256", hash(status.toString()))
            addProperty("next_sequence", number(saved, "nextSequence"))
            addProperty("last_response_sequence", number(saved, "lastResponseSequence"))
            addProperty("pending", session.getStatus().has("pendingOperationId"))
            addProperty("uncertain_needs_reconciliation", bool(saved, "uncertainNeedsReconciliation"))
            addProperty("profile_switch", "NOT_PERFORMED")
            if (fixture.scenario == "owner-refusal") {
                addProperty("local_owner_target_refusal", "PASS")
                addProperty("foreign_owner_hub_guard", "NOT_RUN")
            }
            if (fixture.scenario == "version-bypass") {
                addProperty("refusal_boundary", "CLIENT_FRESH_LIST_AND_GENERIC_RPC_GUARDS")
                addProperty("server_version_guard", "NOT_RUN")
                addProperty("server_generic_rpc_bypass", "NOT_RUN")
            }
        }
    }

    private fun assertResolved(saved: JsonObject) {
        guard(!saved.has("pending") && !saved.has("linkReviewStatusReadContext") &&
            !saved.has("linkConsentStatusReadContext") && !bool(saved, "uncertainNeedsReconciliation"), "PRIOR_STATUS_UNRESOLVED")
    }

    private fun state(scope: HubProfileStore.Scope): JsonObject {
        val file = File(ClientHubSession.profileDirectory(target, scope.profileId), "session-state.json")
        guard(!Files.isSymbolicLink(file.toPath()) && file.length() in 1..1_048_576, "PRIVATE_STATE_INVALID")
        return JsonParser.parseString(file.readText(StandardCharsets.UTF_8)).asJsonObject
    }

    private fun readObject(name: String, expectedSha: String? = null): JsonObject =
        JsonParser.parseString(readRequired(name, expectedSha, 64 * 1024)).asJsonObject

    private fun readRequired(name: String, expectedSha: String?, maximum: Int): String {
        val file = File(directory, name)
        assumeTrue("NOT_RUN_PUBLIC_FIXTURE_REQUIRED", file.isFile)
        guard(!Files.isSymbolicLink(file.toPath()) && file.length() in 1..maximum.toLong(), "PUBLIC_FILE_INVALID")
        val bytes = file.readBytes()
        expectedSha?.let { guard(hashPattern.matches(it) && sha256(bytes) == it, "PUBLIC_FILE_PIN") }
        return bytes.toString(StandardCharsets.UTF_8)
    }

    private fun save(name: String, value: JsonObject) {
        guard(!Files.isSymbolicLink(directory.toPath()) && (directory.isDirectory || directory.mkdirs()), "EVIDENCE_DIRECTORY")
        val base = File(directory, name)
        guard(!base.exists() && !Files.isSymbolicLink(base.toPath()), "EVIDENCE_ALREADY_EXISTS")
        val file = AtomicFile(base)
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(StandardCharsets.UTF_8)); output.fd.sync()
            file.finishWrite(output)
        } catch (_: Exception) {
            file.failWrite(output); throw AssertionError("STATUS_EVIDENCE_WRITE_FAILED")
        }
        guard(base.setReadable(false, false) && base.setReadable(true, true) &&
            base.setWritable(false, false) && base.setWritable(true, true), "EVIDENCE_PERMISSIONS")
    }

    private fun expect(code: String, action: () -> Unit) {
        try { action() } catch (error: HubSessionException) {
            guard(error.errorCode == code, "EXPECTED_STATUS_GUARD_NOT_OBSERVED"); return
        }
        throw AssertionError("EXPECTED_STATUS_GUARD_NOT_OBSERVED")
    }

    private fun deadline() {
        val end = Instant.parse(argument("case_deadline_utc"))
        guard(end.isAfter(Instant.now()) && end <= Instant.now().plusSeconds(360), "CASE_DEADLINE")
    }
    private fun argument(key: String): String = args.getString(key) ?: throw AssertionError("STATUS_ARGUMENT_REQUIRED")
    private fun text(value: JsonObject, key: String): String = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString ?: throw AssertionError("STATUS_STRING_FIELD")
    private fun number(value: JsonObject, key: String): Long {
        val item = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: throw AssertionError("STATUS_NUMBER_FIELD")
        val text = item.asString
        guard(text.matches(Regex("0|[1-9][0-9]*")), "STATUS_NUMBER_FIELD")
        return text.toLongOrNull() ?: throw AssertionError("STATUS_NUMBER_FIELD")
    }
    private fun bool(value: JsonObject, key: String): Boolean = value.get(key)
        ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean ?: throw AssertionError("STATUS_BOOLEAN_FIELD")
    private fun hash(value: String) = sha256(value.toByteArray(StandardCharsets.UTF_8))
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun guard(condition: Boolean, code: String) {
        if (!condition) throw AssertionError("STATUS_$code")
    }
    companion object {
        private val hashPattern = Regex("[0-9a-f]{64}")
        private val identityReceiptFields = listOf("profile_id_sha256", "profile_generation", "hub_id_sha256",
            "owner_id_sha256", "device_id_sha256", "session_epoch", "link_id_sha256", "link_version", "my_side", "fixture_sha256")
        private val journalFields = listOf("nextSequence", "lastResponseSequence", "pending", "linkReviewStatusReadContext",
            "linkConsentStatusReadContext", "uncertainNeedsReconciliation", "outcomeUncertainOperationId", "retiredPending")
    }
}
