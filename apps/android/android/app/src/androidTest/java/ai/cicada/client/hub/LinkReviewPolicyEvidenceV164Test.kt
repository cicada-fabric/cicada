package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.JsonParser
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/** Pure JVM v1.6.4 candidate checks using only the public synthetic Core vector. */
class LinkReviewPolicyEvidenceV164Test {
    private val now = Instant.parse("2026-10-02T12:40:00Z")
    private val vectorBytes by lazy {
        javaClass.classLoader!!.getResourceAsStream("link-review-policy-client-evidence-v1.json")!!
            .use { it.readBytes() }
    }
    private val vector by lazy {
        JsonParser.parseString(String(vectorBytes, StandardCharsets.UTF_8)).asJsonObject
    }
    private val sourceProof by lazy { proofForSide("SOURCE") }
    private val targetProof by lazy { proofForSide("TARGET") }
    private val sourcePin by lazy { pinFor(sourceProof) }
    private val targetPin by lazy { pinFor(targetProof) }
    private val sourceLifecycle by lazy {
        LinkReviewPolicyEvidenceV164.validateActiveStatus(
            bytes(vector.getAsJsonObject("status")), authority, now,
        ).ownerApprovals.first { it.side == "SOURCE" }.ownerLifecycle!!
    }
    private val authority by lazy {
        val preview = signingPreviewJson()
        val reviewers = preview.getAsJsonObject("policy").getAsJsonArray("reviewers")
        LinkReviewPolicyV164CurrentLink(
            linkId = preview.get("link_id").asString,
            linkVersion = preview.get("link_version").asLong,
            contractDigest = preview.get("contract_digest").asString,
            localSide = "SOURCE",
            sourceOwnerId = sourcePin.ownerId,
            targetOwnerId = targetPin.ownerId,
            sourceEndpointId = "endpoint_link_source",
            sourceGroupId = reviewers[0].asJsonObject.get("group_id").asString,
            targetEndpointId = "endpoint_link_target",
            targetGroupId = reviewers[1].asJsonObject.get("group_id").asString,
            expiresAt = Instant.parse(vector.getAsJsonObject("status").get("expires_at").asString),
            sourceOwnerPin = sourcePin,
            targetOwnerPin = targetPin,
        )
    }

    @Test
    fun publicVectorBindsCanonicalPolicyQualificationsAndBothIndependentOwnerProofs() {
        assertEquals(
            "aeb0985056e305a2ea06616e39bebd2bd58957efe61d5e2be9511f6a52039bcd",
            sha256(vectorBytes),
        )
        assertTrue(vector.get("synthetic_only").asBoolean)
        val previewJson = signingPreviewJson()
        val statusJson = vector.getAsJsonObject("status")
        val policy = reviewedPolicy(previewJson.getAsJsonObject("policy"))
        assertEquals(vector.get("canonical_policy_json").asString,
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy))
        assertEquals(vector.get("policy_digest").asString,
            LinkReviewPolicyConsentValidation.policyDigest(policy))

        val status = LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(statusJson), authority, now)
        assertTrue(status.current)
        assertEquals(listOf("SOURCE", "TARGET"), status.acceptedSides)
        assertEquals(listOf("SOURCE", "TARGET"), status.ownerApprovals.map { it.side })
        assertEquals("ACTIVE", status.ownerApprovals[0].ownerLifecycle?.state)
        assertEquals(1L, status.ownerApprovals[0].ownerLifecycle?.version)
        assertEquals("ACTIVE", status.ownerApprovals[1].ownerLifecycle?.state)
        assertEquals(1L, status.ownerApprovals[1].ownerLifecycle?.version)
        assertNotNull(status.ownerApprovals[0].verifiedProof)
        assertNotNull(status.ownerApprovals[1].verifiedProof)
        assertArrayEquals(sourceProof.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8),
            status.ownerApprovals[0].proofBytesCopy()!!)
        assertArrayEquals(targetProof.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8),
            status.ownerApprovals[1].proofBytesCopy()!!)

        val candidate = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(previewJson), policy, bytes(previousHeadStatus()), authority, now,
        )
        assertEquals(2L, candidate.expectedPolicyVersion)
        assertEquals(3L, candidate.policyVersion)
        assertEquals(policy, candidate.policy)
        assertEquals(2, candidate.reviewerQualifications.size)
        assertTrue(candidate.reviewerQualifications.all { it.action == "link.review" })

        val request = LinkReviewPolicyEvidenceV164.buildGrantRequest(
            candidate, bytes(previewJson), bytes(previousHeadStatus()), authority, sourcePin,
            sourceLifecycle, sourceProof.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8), now,
        )
        assertEquals("link_synthetic_bilateral_policy", request.linkId)
        assertEquals(sourcePin.keyId, request.ownerKeyId)
        assertEquals(2L, request.expectedPolicyVersion)
        assertEquals(vector.get("canonical_policy_json").asString, request.policyJson)

        val grant = LinkReviewPolicyEvidenceV164.validateGrantResult(
            bytes(statusJson), candidate, authority, now,
        )
        assertTrue(grant.isGrantCandidate)
        assertTrue(grant.current)
        assertEquals(2, grant.ownerApprovals.count { it.verifiedProof != null })
    }

    @Test
    fun hubSnapshotMetadataDoesNotReplaceLocalProofAndLeaseValidity() {
        val futureSnapshot = now.plusNanos(1)
        val status = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("verified_at", futureSnapshot.toString())
            getAsJsonArray("owner_approvals").forEach { row ->
                row.asJsonObject.getAsJsonObject("evidence")
                    .addProperty("accepted_at", futureSnapshot.toString())
            }
        }
        val verified = LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(status), authority, now)
        assertEquals(futureSnapshot, verified.verifiedAt)
        assertEquals(listOf("SOURCE", "TARGET"), verified.acceptedSides)
        assertTrue(verified.ownerApprovals.all { it.verifiedProof != null })
        val historical = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(status), authority)
        assertEquals(futureSnapshot, historical.verifiedAt)
        assertTrue(historical.ownerApprovals.all { it.verifiedProof != null })

        val acceptedAfterSnapshot = status.deepCopy().apply {
            getAsJsonArray("owner_approvals")[0].asJsonObject.getAsJsonObject("evidence")
                .addProperty("accepted_at", futureSnapshot.plusNanos(1).toString())
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(acceptedAfterSnapshot), authority, now)
        }

        val preview = signingPreviewJson().deepCopy().apply {
            addProperty("verified_at", futureSnapshot.toString())
        }
        val head = previousHeadStatus().apply { addProperty("verified_at", futureSnapshot.toString()) }
        val candidate = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(preview), reviewedPolicy(preview.getAsJsonObject("policy")), bytes(head), authority, now,
        )
        assertEquals(futureSnapshot, candidate.verifiedAt)
        assertTrue(candidate.reviewerQualifications.all { it.leaseExpiresAt > now })
        val proofBytes = proofJson(sourceProof)
        val claims = JsonParser.parseString(String(proofBytes, StandardCharsets.UTF_8)).asJsonObject
        val beforeIssue = Instant.parse(claims.get("issued_at").asString).minusNanos(1)
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(preview), bytes(head), authority, sourcePin, sourceLifecycle,
                proofBytes, beforeIssue,
            )
        }
        val expiry = Instant.parse(claims.get("expires_at").asString)
        val acceptedBeforeIssue = status.deepCopy().apply {
            getAsJsonArray("owner_approvals")[0].asJsonObject.getAsJsonObject("evidence")
                .addProperty("accepted_at", beforeIssue.toString())
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(acceptedBeforeIssue), authority, now)
        }
        val acceptedAtExpiry = status.deepCopy().apply {
            addProperty("verified_at", expiry.toString())
            getAsJsonArray("owner_approvals")[0].asJsonObject.getAsJsonObject("evidence")
                .addProperty("accepted_at", expiry.toString())
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(acceptedAtExpiry), authority, now)
        }
        // Keep the Link valid to isolate rejection of the original signed proof at its expiry.
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(
                bytes(status), authority.copy(expiresAt = expiry.plusSeconds(60)), expiry,
            )
        }
        val expiredLease = preview.deepCopy().apply {
            getAsJsonArray("reviewer_qualifications")[0].asJsonObject
                .addProperty("lease_expires_at", now.toString())
        }
        expect("LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(expiredLease), candidate.policy, bytes(head), authority, now,
            )
        }
    }

    @Test
    fun currentFalsePartialGrantRemainsDiagnosticAndCannotBecomeBilateralConsent() {
        val candidate = candidate()
        val partial = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("current", false)
            add("accepted_sides", JsonArray().apply { add("SOURCE") })
            val approvals = getAsJsonArray("owner_approvals")
            approvals[1].asJsonObject.apply {
                addProperty("current_status", "MISSING")
                remove("evidence")
            }
        }

        val result = LinkReviewPolicyEvidenceV164.validateGrantResult(bytes(partial), candidate, authority, now)

        assertFalse(result.current)
        assertTrue(result.isGrantCandidate)
        assertEquals(listOf("VERIFIED", "MISSING"), result.ownerApprovals.map { it.currentStatus })
        assertNotNull(result.ownerApprovals[0].verifiedProof)
        assertNotNull(result.ownerApprovals[0].ownerLifecycle)
        assertNull(result.ownerApprovals[1].verifiedProof)
        assertNull(result.ownerApprovals[1].ownerLifecycle)
        expect("LINK_REVIEW_POLICY_V164_GRANT_RESULT_MISMATCH") {
            LinkReviewPolicyEvidenceV164.validateGrantResult(
                bytes(partial), withPolicyVersion(candidate, candidate.policyVersion + 1), authority, now,
            )
        }
    }

    @Test
    fun noncurrentActiveHeadCanBeUsedForCasRepairOnlyWhenFreshLinkTupleMatches() {
        val diagnostic = LinkReviewPolicyEvidenceV164.validateActiveStatus(
            bytes(previousHeadStatus()), authority, now,
        )
        assertFalse(diagnostic.current)
        assertEquals(2L, diagnostic.policyVersion)

        val preview = signingPreviewJson().deepCopy()
        preview.addProperty("expected_policy_version", diagnostic.policyVersion)
        preview.addProperty("policy_version", diagnostic.policyVersion + 1)
        val validated = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(preview), reviewedPolicy(preview.getAsJsonObject("policy")),
            bytes(previousHeadStatus()), authority, now,
        )
        assertEquals(3L, validated.policyVersion)

        val changedLink = authority.copy(linkVersion = authority.linkVersion + 1)
        expect("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(previousHeadStatus()), changedLink, now)
        }
    }

    @Test
    fun proofAndOwnerEvidenceMustMatchFullIndependentPinsAndExactCandidateTuple() {
        val candidate = candidate()
        val request = LinkReviewPolicyEvidenceV164.buildGrantRequest(
            candidate, bytes(signingPreviewJson()), bytes(previousHeadStatus()),
            authority, sourcePin, sourceLifecycle, proofJson(sourceProof), now,
        )
        assertEquals(sourcePin.keyId, request.ownerKeyId)

        expect("LINK_REVIEW_POLICY_V164_OWNER_PIN_MISMATCH") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(
                bytes(vector.getAsJsonObject("status")),
                authority.copy(sourceOwnerPin = sourcePin.copy(
                    keyId = targetPin.keyId,
                    publicIdentity = targetPin.publicIdentity,
                )), now,
            )
        }
        val noncanonicalIdentity = vector.getAsJsonObject("status").deepCopy().apply {
            getAsJsonArray("owner_approvals")[0].asJsonObject
                .getAsJsonObject("evidence").getAsJsonObject("owner_public_identity")
                .addProperty("kem_public", sourcePin.publicIdentity.kemPublic.let {
                    java.util.Base64.getEncoder().encodeToString(it).trimEnd('=')
                })
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(noncanonicalIdentity), authority, now)
        }
        expect("LINK_REVIEW_POLICY_V164_OWNER_PIN_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(signingPreviewJson()), bytes(previousHeadStatus()),
                authority, sourcePin.copy(keyId = "different-key-id"), sourceLifecycle, proofJson(sourceProof), now,
            )
        }
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(signingPreviewJson()), bytes(previousHeadStatus()),
                authority, sourcePin, sourceLifecycle,
                proofJson(sourceProof).also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, now,
            )
        }
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(signingPreviewJson()), bytes(previousHeadStatus()),
                authority, sourcePin, sourceLifecycle, ByteArray(16 * 1024 + 1), now,
            )
        }
    }

    @Test
    fun changedReviewerSnapshotRequiresExplicitReconfirmation() {
        val cached = candidate()
        val changedPreview = signingPreviewJson().deepCopy().apply {
            getAsJsonArray("reviewer_qualifications")[0].asJsonObject.addProperty("binding_epoch", 99)
        }

        expect("LINK_REVIEW_POLICY_V164_PREVIEW_STALE") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                cached, bytes(changedPreview), bytes(previousHeadStatus()), authority,
                sourcePin, sourceLifecycle, proofJson(sourceProof), now,
            )
        }
    }

    @Test
    fun grantRequiresCurrentActiveLocalLifecycleAndExactReviewedCandidate() {
        val previewJson = signingPreviewJson()
        val candidate = candidate()
        expect("LINK_REVIEW_POLICY_V164_OWNER_KEY_REVOKED") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(previewJson), bytes(previousHeadStatus()), authority, sourcePin,
                sourceLifecycle.copy(state = "REVOKED"), proofJson(sourceProof), now,
            )
        }
        expect("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(previewJson), bytes(previousHeadStatus()), authority, sourcePin,
                sourceLifecycle.copy(version = 0L), proofJson(sourceProof), now,
            )
        }

        val targetPreview = signingPreviewJson("TARGET").apply {
            addProperty("side", "TARGET")
            addProperty("owner_id", targetPin.ownerId)
        }
        val targetCandidate = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(targetPreview), candidate.policy, bytes(previousHeadStatus()),
            authority.copy(localSide = "TARGET"), now,
        )
        val targetLifecycle = LinkReviewPolicyEvidenceV164.validateActiveStatus(
            bytes(vector.getAsJsonObject("status")), authority, now,
        ).ownerApprovals.first { it.side == "TARGET" }.ownerLifecycle!!
        val targetRequest = LinkReviewPolicyEvidenceV164.buildGrantRequest(
            targetCandidate, bytes(targetPreview), bytes(previousHeadStatus()),
            authority.copy(localSide = "TARGET"), targetPin, targetLifecycle, proofJson(targetProof), now,
        )
        assertEquals(targetPin.keyId, targetRequest.ownerKeyId)
    }

    @Test
    fun previewRejectsChangedLinkOwnerPolicyDigestSideAndHead() {
        val base = signingPreviewJson()
        val mutations = listOf<Pair<JsonObject, String>>(
            base.deepCopy().apply { addProperty("contract_digest", "0".repeat(64)) }
                to "LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH",
            base.deepCopy().apply { addProperty("side", "TARGET") }
                to "LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH",
            base.deepCopy().apply { addProperty("owner_id", targetPin.ownerId) }
                to "LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH",
            base.deepCopy().apply { addProperty("expected_policy_version", 1) }
                to "LINK_REVIEW_POLICY_V164_HEAD_MISMATCH",
            base.deepCopy().apply { addProperty("policy_digest", "0".repeat(64)) }
                to "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
        )
        for ((preview, code) in mutations) {
            expect(code) {
                LinkReviewPolicyEvidenceV164.validatePreview(
                    bytes(preview), reviewedPolicy(base.getAsJsonObject("policy")),
                    bytes(previousHeadStatus()), authority, now,
                )
            }
        }

        val changedPolicy = base.deepCopy().apply {
            getAsJsonObject("policy").addProperty("max_review_age_seconds", 360)
            addProperty("policy_digest", LinkReviewPolicyConsentValidation.policyDigest(
                reviewedPolicy(getAsJsonObject("policy")),
            ))
        }
        expect("LINK_REVIEW_POLICY_V164_REVIEWED_INPUT_MISMATCH") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(changedPolicy), reviewedPolicy(base.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }
    }

    @Test
    fun statusValidatesAcceptedSidesOnlyAsProjectionAndChecksOwnerLifecycleStates() {
        val partial = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("current", false)
            add("accepted_sides", JsonArray().apply { add("TARGET") })
            val rows = getAsJsonArray("owner_approvals")
            rows[0].asJsonObject.apply {
                addProperty("current_status", "OWNER_KEY_REVOKED")
                remove("evidence")
            }
        }
        val revokedAuthority = authority
        val result = LinkReviewPolicyEvidenceV164.validateGrantResult(
            bytes(partial), candidate(), revokedAuthority, now,
        )
        assertEquals(listOf("OWNER_KEY_REVOKED", "VERIFIED"), result.ownerApprovals.map { it.currentStatus })
        assertFalse(result.current)

        val falseAcceptedSide = partial.deepCopy().apply {
            add("accepted_sides", JsonArray().apply { add("SOURCE") })
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateGrantResult(
                bytes(falseAcceptedSide), candidate(), revokedAuthority, now,
            )
        }

        val wrongOrder = vector.getAsJsonObject("status").deepCopy().apply {
            val rows = getAsJsonArray("owner_approvals")
            val source = rows[0].deepCopy()
            val target = rows[1].deepCopy()
            rows.remove(0); rows.remove(0); rows.add(target); rows.add(source)
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(wrongOrder), authority, now)
        }
    }

    @Test
    fun exactQualificationRowsRequireCurrentLinkReviewAndCanonicalFutureLeases() {
        val base = signingPreviewJson()
        val mutations = listOf<Pair<JsonObject, String>>(
            base.deepCopy().apply {
                getAsJsonArray("reviewer_qualifications")[0].asJsonObject.addProperty("action", "Monitor")
            } to "LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH",
            base.deepCopy().apply {
                getAsJsonArray("reviewer_qualifications")[0].asJsonObject.addProperty("lease_expires_at", "2026-10-02T12:39:00Z")
            } to "LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH",
            base.deepCopy().apply {
                val rows = getAsJsonArray("reviewer_qualifications")
                val first = rows[0].deepCopy(); val second = rows[1].deepCopy()
                rows.remove(0); rows.remove(0); rows.add(second); rows.add(first)
            } to "LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH",
            base.deepCopy().apply { getAsJsonArray("reviewer_qualifications")[0].asJsonObject.addProperty("binding_epoch", 0) }
                to "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
        )
        for ((preview, code) in mutations) {
            expect(code) {
                LinkReviewPolicyEvidenceV164.validatePreview(
                    bytes(preview), reviewedPolicy(preview.getAsJsonObject("policy")),
                    bytes(previousHeadStatus()), authority, now,
                )
            }
        }
    }

    @Test
    fun normalizedNonePolicyHasNoQualificationsAndConfiguredNoneKeepsBilateralStatusShape() {
        val none = LinkReviewPolicyConsentPolicy("NONE", emptyList(), 0, 0, 0)
        val preview = signingPreviewJson().deepCopy().apply {
            add("policy", policyJson(none))
            addProperty("policy_digest", LinkReviewPolicyConsentValidation.policyDigest(none))
            add("reviewer_qualifications", JsonArray())
        }
        val candidate = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(preview), none, bytes(previousHeadStatus()), authority, now,
        )
        assertTrue(candidate.reviewerQualifications.isEmpty())

        val configuredNone = previousHeadStatus()
        assertEquals(2, configuredNone.getAsJsonArray("owner_approvals").size())
        val unconfiguredNone = configuredNone.deepCopy().apply {
            addProperty("policy_version", 0)
            addProperty("policy_digest", "")
            addProperty("current", true)
            add("owner_approvals", JsonArray())
        }
        val unconfigured = LinkReviewPolicyEvidenceV164.validateActiveStatus(
            bytes(unconfiguredNone), authority, now,
        )
        assertTrue(unconfigured.unconfigured)
        assertTrue(unconfigured.ownerApprovals.isEmpty())
        assertTrue(unconfigured.acceptedSides.isEmpty())
        val active = LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(vector.getAsJsonObject("status")), authority, now)
        assertFalse(active.unconfigured)
    }

    @Test
    fun rejectsDuplicateUnknownNoncanonicalJsonAndNoncanonicalTimestamps() {
        val preview = signingPreviewJson()
        val previewString = preview.toString()
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                previewString.replaceFirst("\"link_id\":", "\"link_id\":\"duplicate\",\"link_id\":")
                    .toByteArray(StandardCharsets.UTF_8), reviewedPolicy(preview.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }
        val unknown = preview.deepCopy().apply { addProperty("untrusted", true) }
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(unknown), reviewedPolicy(preview.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }
        val deeplyNestedUnknown = "{\"unknown\":" + "[".repeat(18) + "null" + "]".repeat(18) + "}"
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                deeplyNestedUnknown.toByteArray(StandardCharsets.UTF_8),
                reviewedPolicy(preview.getAsJsonObject("policy")), bytes(previousHeadStatus()), authority, now,
            )
        }
        val offsetTime = preview.deepCopy().apply { addProperty("verified_at", "2026-10-02T12:30:00+00:00") }
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(offsetTime), reviewedPolicy(preview.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }
        val trailingFraction = preview.deepCopy().apply { addProperty("verified_at", "2026-10-02T12:30:00.1200Z") }
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(trailingFraction), reviewedPolicy(preview.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }
        val duplicateStatus = vector.getAsJsonObject("status").toString()
            .replaceFirst("\"link_id\":", "\"link_id\":\"duplicate\",\"link_id\":")
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(
                duplicateStatus.toByteArray(StandardCharsets.UTF_8), authority, now,
            )
        }
    }

    @Test
    fun nativeLongBoundsAreExactAndOverflowOrLossyNumbersReject() {
        val preview = signingPreviewJson().deepCopy().apply {
            val qualification = getAsJsonArray("reviewer_qualifications")[0].asJsonObject
            qualification.add("membership_revision", JsonPrimitive(BigInteger.valueOf(Long.MAX_VALUE)))
            qualification.add("join_revision", JsonPrimitive(BigInteger.valueOf(Long.MAX_VALUE)))
            qualification.add("group_version", JsonPrimitive(BigInteger.valueOf(Long.MAX_VALUE)))
            qualification.add("binding_epoch", JsonPrimitive(BigInteger.valueOf(Long.MAX_VALUE)))
        }
        val validated = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(preview), reviewedPolicy(preview.getAsJsonObject("policy")),
            bytes(previousHeadStatus()), authority, now,
        )
        assertEquals(Long.MAX_VALUE, validated.reviewerQualifications[0].membershipRevision)
        assertEquals(Long.MAX_VALUE, validated.reviewerQualifications[0].bindingEpoch)

        val overflow = preview.deepCopy().apply {
            getAsJsonArray("reviewer_qualifications")[0].asJsonObject.add(
                "membership_revision", JsonPrimitive(BigInteger("9223372036854775808")),
            )
        }
        expect("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(
                bytes(overflow), reviewedPolicy(overflow.getAsJsonObject("policy")),
                bytes(previousHeadStatus()), authority, now,
            )
        }

        val maximumHead = previousHeadStatus().apply {
            addProperty("policy_version", Long.MAX_VALUE - 1)
        }
        val maximumPreview = signingPreviewJson().deepCopy().apply {
            addProperty("expected_policy_version", Long.MAX_VALUE - 1)
            addProperty("policy_version", Long.MAX_VALUE)
        }
        val maxCandidate = LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(maximumPreview), reviewedPolicy(maximumPreview.getAsJsonObject("policy")),
            bytes(maximumHead), authority, now,
        )
        assertEquals(Long.MAX_VALUE, maxCandidate.policyVersion)
    }

    @Test
    fun rawDtoAndProofSizeLimitsRejectOversizedInputs() {
        val candidate = candidate()
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateActiveStatus(
                ByteArray(64 * 1024 + 1) { ' '.code.toByte() }, authority, now,
            )
        }
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(signingPreviewJson()), bytes(previousHeadStatus()),
                authority, sourcePin, sourceLifecycle, ByteArray(16 * 1024 + 1), now,
            )
        }
    }

    private fun candidate(): LinkReviewPolicyV164Preview {
        val preview = signingPreviewJson()
        return LinkReviewPolicyEvidenceV164.validatePreview(
            bytes(preview), reviewedPolicy(preview.getAsJsonObject("policy")),
            bytes(previousHeadStatus()), authority, now,
        )
    }

    private fun withPolicyVersion(
        candidate: LinkReviewPolicyV164Preview,
        policyVersion: Long,
    ): LinkReviewPolicyV164Preview = LinkReviewPolicyV164Preview(
        linkId = candidate.linkId,
        side = candidate.side,
        ownerId = candidate.ownerId,
        contractDigest = candidate.contractDigest,
        linkVersion = candidate.linkVersion,
        expectedPolicyVersion = candidate.expectedPolicyVersion,
        policyVersion = policyVersion,
        policyDigest = candidate.policyDigest,
        policy = candidate.policy,
        maximumProofExpiresAt = candidate.maximumProofExpiresAt,
        verifiedAt = candidate.verifiedAt,
        reviewerQualifications = candidate.reviewerQualifications,
        signingOwnerKey = candidate.signingOwnerKey,
        canonicalPolicyJson = candidate.canonicalPolicyJson,
        rawPreview = candidate.rawPreviewCopy(),
    )

    // Extend the unchanged public v1.6.4 vector only in test memory with the proposed tuple.
    private fun signingPreviewJson(side: String = "SOURCE"): JsonObject {
        val pin = if (side == "SOURCE") sourcePin else targetPin
        return vector.getAsJsonObject("preview").deepCopy().apply {
            add("signing_owner_key", JsonObject().apply {
                addProperty("owner_id", pin.ownerId)
                addProperty("key_id", pin.keyId)
                add("public_identity", JsonParser.parseString(pin.publicIdentity.toJson()))
                addProperty("state", "ACTIVE")
                addProperty("version", 1)
            })
        }
    }

    private fun previousHeadStatus(): JsonObject {
        val policy = LinkReviewPolicyConsentPolicy("NONE", emptyList(), 0, 0, 0)
        return JsonObject().apply {
            addProperty("link_id", authority.linkId)
            addProperty("link_version", authority.linkVersion)
            addProperty("contract_digest", authority.contractDigest)
            addProperty("policy_version", 2)
            addProperty("policy_digest", LinkReviewPolicyConsentValidation.policyDigest(policy))
            add("policy", policyJson(policy))
            addProperty("current", false)
            add("accepted_sides", JsonArray())
            addProperty("verified_at", "2026-10-02T12:30:00Z")
            add("owner_approvals", JsonArray().apply {
                add(approval("SOURCE", authority.sourceOwnerId, "MISSING"))
                add(approval("TARGET", authority.targetOwnerId, "MISSING"))
            })
        }
    }

    private fun approval(side: String, ownerId: String, state: String): JsonObject = JsonObject().apply {
        addProperty("side", side)
        addProperty("owner_id", ownerId)
        addProperty("current_status", state)
    }

    private fun policyJson(policy: LinkReviewPolicyConsentPolicy): JsonObject = JsonObject().apply {
        addProperty("mode", policy.mode)
        add("reviewers", JsonArray().apply {
            policy.reviewers.forEach { reviewer ->
                add(JsonObject().apply {
                    addProperty("endpoint_id", reviewer.endpointId)
                    addProperty("group_id", reviewer.groupId)
                })
            }
        })
        addProperty("max_failovers", policy.maxFailovers)
        addProperty("reviewer_lease_seconds", policy.reviewerLeaseSeconds)
        addProperty("max_review_age_seconds", policy.maxReviewAgeSeconds)
    }

    private fun reviewedPolicy(value: JsonObject): LinkReviewPolicyConsentPolicy = LinkReviewPolicyConsentPolicy(
        mode = value.get("mode").asString,
        reviewers = value.getAsJsonArray("reviewers").map { row ->
            LinkReviewPolicyConsentReviewer(
                row.asJsonObject.get("endpoint_id").asString,
                row.asJsonObject.get("group_id").asString,
            )
        },
        maxFailovers = value.get("max_failovers").asInt,
        reviewerLeaseSeconds = value.get("reviewer_lease_seconds").asInt,
        maxReviewAgeSeconds = value.get("max_review_age_seconds").asInt,
    )

    private fun proofForSide(side: String): JsonObject = vector.getAsJsonArray("proofs")
        .map { it.asJsonObject }.first { it.get("side").asString == side }

    private fun pinFor(proof: JsonObject): LinkReviewPolicyV164OwnerPin {
        val identity = ClientWireCrypto.PublicIdentity.parse(proof.getAsJsonObject("owner_public_identity"))
        return LinkReviewPolicyV164OwnerPin(
            ownerId = proof.get("owner_id").asString,
            keyId = identity.id,
            publicIdentity = identity,
        )
    }

    private fun proofJson(proof: JsonObject): ByteArray =
        proof.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8)

    private fun bytes(value: JsonObject): ByteArray = value.toString().toByteArray(StandardCharsets.UTF_8)

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun expect(code: String, action: () -> Unit) {
        try {
            action()
            fail("Expected $code")
        } catch (error: LinkReviewPolicyEvidenceV164Exception) {
            assertEquals(code, error.code)
        }
    }
}
