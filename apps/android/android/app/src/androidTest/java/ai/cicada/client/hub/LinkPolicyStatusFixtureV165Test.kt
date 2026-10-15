package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/** Pure fixture checks using synthetic public buffers only; no Android, Hub, or private keys. */
class LinkPolicyStatusFixtureV165Test {
    @Test
    fun acceptsAllEightCasesAndKeepsFixtureLaneSeparateFromPolicyMode() {
        repeat(8) { caseId ->
            val value = fixture(caseId)
            val parsed = parse(value, caseId)
            assertEquals(caseId, parsed.caseId)
            assertEquals(if (caseId % 2 == 0) "KEY" else "NONE", parsed.lane)
            assertEquals(SCENARIOS[caseId / 2], parsed.scenario)
            assertEquals("link-fixture", parsed.linkId)
            assertEquals(7L, parsed.linkVersion)
            assertEquals("SOURCE", parsed.mySide)
            assertEquals(if (caseId % 2 == 0) "NONE" else "METADATA",
                parsed.expectedStatus.getAsJsonObject("policy").get("mode").asString)
        }
    }

    @Test
    fun acceptsRevokedVersionTwoZeroHeadInBothFixtureLanesWithoutCurrentAuthority() {
        for (caseId in listOf(4, 5)) {
            val status = noneStatus().apply {
                addProperty("link_version", 2)
                addProperty("current", false)
            }
            val parsed = parse(fixture(caseId).apply { add("expected_status", status) }, caseId)
            assertEquals(2L, parsed.linkVersion)
            assertEquals("SOURCE", parsed.mySide)
            assertEquals(0L, parsed.expectedStatus.get("policy_version").asLong)
            assertEquals(false, parsed.expectedStatus.get("current").asBoolean)
            assertTrue(parsed.expectedStatus.getAsJsonArray("accepted_sides").isEmpty)
            LinkPolicyStatusFixtureV165.assertStatus(status.deepCopy(), parsed)
            expectInvalid {
                LinkPolicyStatusFixtureV165.assertStatus(
                    status.deepCopy().apply { addProperty("current", true) }, parsed)
            }
        }
    }

    @Test
    fun rejectsDuplicateExtraOversizedAndDeepJson() {
        val valid = fixture(0).toString()
        val duplicate = "{\"schema\":\"duplicate\",${valid.substring(1)}"
        expectInvalid { LinkPolicyStatusFixtureV165.parse(duplicate, RUN_ID, "KEY", "restart") }

        expectInvalid {
            parse(fixture(0).apply { addProperty("unexpected", true) }, 0)
        }
        expectInvalid {
            LinkPolicyStatusFixtureV165.parse(" ".repeat(64 * 1024 + 1), RUN_ID, "KEY", "restart")
        }
        val tooDeep = "{\"nested\":" + "[".repeat(20) + "0" + "]".repeat(20) + "}"
        expectInvalid { LinkPolicyStatusFixtureV165.parse(tooDeep, RUN_ID, "KEY", "restart") }
    }

    @Test
    fun rejectsWrongContractCatalogAndCaseBindings() {
        expectInvalid { parse(fixture(0).apply { addProperty("contract_revision", "client-hub-v1.6.4") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("catalog_sha256", "b".repeat(64)) }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("case_id", 2) }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("fixture_lane", "NONE") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("scenario", "owner-refusal") }, 0) }
        expectInvalid {
            LinkPolicyStatusFixtureV165.parse(fixture(0).toString(), "v165-link-policy-status-other", "KEY", "restart")
        }
        expectInvalid {
            LinkPolicyStatusFixtureV165.parse(fixture(0).toString(), RUN_ID, "NONE", "restart")
        }
    }

    @Test
    fun rejectsInappropriateForeignAndRecoveryFields() {
        expectInvalid { parse(fixture(0).apply { addProperty("foreign_link_id", "link-foreign") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("recovery_result", "COMPLETED") }, 0) }
        expectInvalid { parse(fixture(2).apply { remove("foreign_owner_id") }, 2) }
        expectInvalid { parse(fixture(6).apply { remove("recovery_result") }, 6) }
        expectInvalid { parse(fixture(6).apply { addProperty("recovery_result", "UNKNOWN") }, 6) }
        expectInvalid { parse(fixture(2).apply { addProperty("foreign_owner_id", "owner-fixture") }, 2) }
        expectInvalid { parse(fixture(2).apply { addProperty("foreign_link_id", "link-fixture") }, 2) }
    }

    @Test
    fun rejectsUnsafeIdentifiersAndNoncanonicalOrOutOfRangeVersions() {
        expectInvalid { parse(fixture(0).apply { addProperty("owner_id", "") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("device_id", "device\u0001bad") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("profile_id", "ABCDEF12-1234-1234-1234-123456789abc") }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("profile_generation", 0) }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("profile_generation", true) }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("session_epoch", 9_007_199_254_740_992L) }, 0) }
        expectInvalid { parse(fixture(0).apply { addProperty("control_key_version", 1.5) }, 0) }
        expectInvalid {
            parse(fixture(0).apply { getAsJsonObject("expected_status").addProperty("link_version", 0) }, 0)
        }
    }

    @Test
    fun validatesPublicIdentityShapeCanonicalBase64LengthsAndId() {
        val missing = fixture(0).apply { getAsJsonObject("control_public_identity").remove("signing_public") }
        expectInvalid { parse(missing, 0) }

        val extra = fixture(0).apply { getAsJsonObject("control_public_identity").addProperty("private_key", "never") }
        expectInvalid { parse(extra, 0) }

        val unpadded = fixture(0).apply {
            val identity = getAsJsonObject("control_public_identity")
            identity.addProperty("kem_public", identity.get("kem_public").asString.trimEnd('='))
        }
        expectInvalid { parse(unpadded, 0) }

        val wrongLength = fixture(0).apply {
            val identity = getAsJsonObject("control_public_identity")
            identity.addProperty("signing_public", Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3)))
        }
        expectInvalid { parse(wrongLength, 0) }

        val wrongId = fixture(0).apply {
            getAsJsonObject("control_public_identity").addProperty("id", "pq1-${"0".repeat(32)}")
        }
        expectInvalid { parse(wrongId, 0) }
    }

    @Test
    fun rejectsInvalidStatusTupleAndPolicyMode() {
        expectInvalid { parse(fixture(0).apply { getAsJsonObject("expected_status").addProperty("policy_digest", "A".repeat(64)) }, 0) }
        expectInvalid { parse(fixture(0).apply { getAsJsonObject("expected_status").addProperty("link_id", "") }, 0) }
        expectInvalid { parse(fixture(0).apply { getAsJsonObject("expected_status").addProperty("link_version", 0) }, 0) }
        expectInvalid {
            parse(fixture(0).apply {
                getAsJsonObject("expected_status").getAsJsonObject("policy").addProperty("mode", "KEY")
            }, 0)
        }
        expectInvalid {
            parse(fixture(1).apply {
                getAsJsonObject("expected_status").getAsJsonObject("policy").getAsJsonArray("reviewers")
                    .add(JsonObject().apply { addProperty("endpoint_id", "reviewer-fixture"); addProperty("group_id", "group") })
            }, 1)
        }
        expectInvalid {
            parse(fixture(1).apply {
                getAsJsonObject("expected_status").addProperty("expires_at", "not-a-timestamp")
            }, 1)
        }
        expectInvalid {
            parse(fixture(0).apply { getAsJsonObject("expected_status").addProperty("unexpected", true) }, 0)
        }
    }

    @Test
    fun assertStatusRejectsDigestCurrentSidesExpiryAndFullReviewerScopeChanges() {
        val fixture = parse(fixture(1), 1)
        val matching = fixture.expectedStatus.deepCopy()
        LinkPolicyStatusFixtureV165.assertStatus(matching, fixture)

        val changedLinkId = fixture.expectedStatus.deepCopy().apply { addProperty("link_id", "another-link") }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedLinkId, fixture) }

        val changedLinkVersion = fixture.expectedStatus.deepCopy().apply { addProperty("link_version", 8) }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedLinkVersion, fixture) }

        val changedDigest = fixture.expectedStatus.deepCopy().apply { addProperty("policy_digest", "e".repeat(64)) }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedDigest, fixture) }

        val changedCurrent = fixture.expectedStatus.deepCopy().apply { addProperty("current", false) }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedCurrent, fixture) }

        val changedSides = fixture.expectedStatus.deepCopy().apply {
            getAsJsonArray("accepted_sides").remove(1)
        }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedSides, fixture) }

        val changedExpiry = fixture.expectedStatus.deepCopy().apply { addProperty("expires_at", "2031-01-01T00:00:00Z") }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedExpiry, fixture) }

        val changedReviewerScope = fixture.expectedStatus.deepCopy().apply {
            getAsJsonObject("policy").getAsJsonArray("reviewers")[0].asJsonObject.addProperty("group_id", "other-group")
        }
        expectInvalid { LinkPolicyStatusFixtureV165.assertStatus(changedReviewerScope, fixture) }
    }

    @Test
    fun recoveryPhasesAreRestrictedToLossCases() {
        SCENARIOS.forEach { scenario ->
            assertTrue(LinkPolicyStatusFixtureV165.phaseAllowed("before_restart", scenario))
            assertTrue(LinkPolicyStatusFixtureV165.phaseAllowed("after_restart", scenario))
            assertEquals(scenario == "response-loss",
                LinkPolicyStatusFixtureV165.phaseAllowed("capture_response_loss", scenario))
            assertEquals(scenario == "response-loss",
                LinkPolicyStatusFixtureV165.phaseAllowed("recover_after_restart", scenario))
        }
        assertEquals(false, LinkPolicyStatusFixtureV165.phaseAllowed("retry", "response-loss"))
        assertEquals(false, LinkPolicyStatusFixtureV165.phaseAllowed("before_restart", "unknown"))
    }

    @Test
    fun recoveryCheckpointBindsOriginalHashesCountersAndUnresolvedOutcome() {
        for (outcome in listOf("COMPLETED", "OUTCOME_UNCERTAIN")) {
            val fixture = parse(fixture(6).apply { addProperty("recovery_result", outcome) }, 6)
            val capture = JsonObject().apply {
                addProperty("fixture_sha256", "a".repeat(64))
                addProperty("operation_id_sha256", "b".repeat(64))
                addProperty("original_packet_sha256", "c".repeat(64))
                addProperty("next_sequence", 12)
                addProperty("expected_response_sequence", 9)
            }
            val receipt = JsonObject().apply {
                addProperty("schema", "cicada.client-v165-link-policy-status-recovery.v1")
                addProperty("result", "ORIGINAL_PACKET_RECOVERED")
                for (key in listOf("fixture_sha256", "operation_id_sha256", "original_packet_sha256")) {
                    add(key, capture.get(key).deepCopy())
                }
                addProperty("recovery_result", outcome)
                addProperty("new_operation_created_for_recovery", false)
                addProperty("unresolved_fence_retention_checked", true)
                addProperty("next_sequence", 12)
                addProperty("last_response_sequence", 9)
                addProperty("uncertain_needs_reconciliation", outcome == "OUTCOME_UNCERTAIN")
                addProperty("legacy_nonnull_context_restart", "NOT_RUN")
                addProperty("process_death", "NOT_RUN")
            }
            LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(receipt, capture, fixture)
            for (key in listOf("fixture_sha256", "operation_id_sha256", "original_packet_sha256")) {
                expectInvalid {
                    LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                        receipt.deepCopy().apply { addProperty(key, "d".repeat(64)) }, capture, fixture)
                }
            }
            for (key in listOf("next_sequence", "last_response_sequence")) {
                expectInvalid {
                    LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                        receipt.deepCopy().apply { addProperty(key, 13) }, capture, fixture)
                }
            }
            for (key in listOf("new_operation_created_for_recovery", "unresolved_fence_retention_checked",
                "uncertain_needs_reconciliation")) {
                expectInvalid {
                    LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                        receipt.deepCopy().apply { addProperty(key, !receipt.get(key).asBoolean) }, capture, fixture)
                }
            }
            expectInvalid {
                LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                    receipt.deepCopy().apply { addProperty("result", "PASS") }, capture, fixture)
            }
            expectInvalid {
                LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                    receipt.deepCopy().apply { addProperty("last_response_sequence", true) }, capture, fixture)
            }
            expectInvalid {
                LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                    receipt.deepCopy().apply { addProperty("extra", true) }, capture, fixture)
            }
            expectInvalid {
                LinkPolicyStatusFixtureV165.assertRecoveryCheckpoint(
                    receipt.deepCopy().apply { remove("original_packet_sha256") }, capture, fixture)
            }
        }
    }

    private fun parse(value: JsonObject, caseId: Int): LinkPolicyStatusFixtureV165.Fixture =
        LinkPolicyStatusFixtureV165.parse(
            value.toString(), RUN_ID,
            if (caseId % 2 == 0) "KEY" else "NONE",
            SCENARIOS[caseId / 2],
        )

    private fun fixture(caseId: Int): JsonObject {
        val lane = if (caseId % 2 == 0) "KEY" else "NONE"
        val status = if (lane == "KEY") noneStatus() else metadataStatus()
        return JsonObject().apply {
            addProperty("schema", LinkPolicyStatusFixtureV165.SCHEMA)
            addProperty("run_id", RUN_ID)
            addProperty("case_id", caseId)
            addProperty("fixture_lane", lane)
            addProperty("scenario", SCENARIOS[caseId / 2])
            addProperty("source_revision", "a".repeat(40))
            addProperty("source_fingerprint", "b".repeat(64))
            addProperty("hub_image_id", "sha256:${"c".repeat(64)}")
            addProperty("contract_revision", LinkPolicyStatusFixtureV165.CONTRACT)
            addProperty("catalog_sha256", LinkPolicyStatusFixtureV165.CATALOG)
            addProperty("hub_id", "hub-fixture")
            addProperty("owner_id", "owner-fixture")
            addProperty("device_id", "device-fixture")
            addProperty("profile_id", "00000000-0000-4000-8000-000000000001")
            addProperty("profile_generation", 1)
            addProperty("session_epoch", 2)
            add("control_public_identity", publicIdentity())
            addProperty("control_key_version", 3)
            addProperty("my_side", "SOURCE")
            add("expected_status", status)
            if (caseId / 2 == 1) {
                addProperty("foreign_link_id", "link-foreign")
                addProperty("foreign_owner_id", "owner-foreign")
            }
            if (caseId / 2 == 3) addProperty("recovery_result", "COMPLETED")
        }
    }

    private fun noneStatus(): JsonObject = JsonObject().apply {
        addProperty("link_id", "link-fixture")
        addProperty("link_version", 7)
        addProperty("policy_version", 0)
        addProperty("policy_digest", "")
        add("policy", JsonObject().apply {
            addProperty("mode", "NONE")
            add("reviewers", JsonArray())
            addProperty("max_failovers", 0)
            addProperty("reviewer_lease_seconds", 0)
            addProperty("max_review_age_seconds", 0)
        })
        addProperty("current", true)
        add("accepted_sides", JsonArray())
    }

    private fun metadataStatus(): JsonObject = JsonObject().apply {
        addProperty("link_id", "link-fixture")
        addProperty("link_version", 7)
        addProperty("policy_version", 3)
        addProperty("policy_digest", "d".repeat(64))
        add("policy", JsonObject().apply {
            addProperty("mode", "METADATA")
            add("reviewers", JsonArray().apply {
                add(JsonObject().apply { addProperty("endpoint_id", "reviewer-fixture"); addProperty("group_id", "group-fixture") })
            })
            addProperty("max_failovers", 0)
            addProperty("reviewer_lease_seconds", 60)
            addProperty("max_review_age_seconds", 300)
        })
        addProperty("current", true)
        add("accepted_sides", JsonArray().apply { add("SOURCE"); add("TARGET") })
        addProperty("expires_at", "2030-01-01T00:00:00Z")
    }

    private fun publicIdentity(): JsonObject {
        val kem = ByteArray(1184) { index -> (index * 17 + 9).toByte() }
        val signing = ByteArray(1952) { index -> (index * 29 + 5).toByte() }
        val id = "pq1-" + sha256(kem + signing).take(32)
        return JsonObject().apply {
            addProperty("id", id)
            addProperty("kem_public", Base64.getEncoder().encodeToString(kem))
            addProperty("signing_public", Base64.getEncoder().encodeToString(signing))
        }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun expectInvalid(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        }
        fail("Expected the v1.6.5 fixture/status guard to reject the value")
    }

    private companion object {
        const val RUN_ID = "v165-link-policy-status-synthetic"
        val SCENARIOS = listOf("restart", "owner-refusal", "version-bypass", "response-loss")
    }
}
