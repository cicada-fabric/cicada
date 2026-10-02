package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

/** Pure JVM DTO and proof-vector checks; no Android context, Hub, or network is involved. */
class LinkReviewPolicyConsentValidationTest {
    private val now = Instant.parse("2026-10-01T13:00:00Z")
    private val vectorBytes by lazy {
        javaClass.classLoader!!.getResourceAsStream("owner-link-review-policy-proof-v1.json")!!.use { it.readBytes() }
    }
    private val vector by lazy {
        JsonParser.parseString(String(vectorBytes, StandardCharsets.UTF_8)).asJsonObject
    }
    private val proofRaw by lazy { vector.get("proof_json").asString.toByteArray(StandardCharsets.UTF_8) }
    private val proof by lazy { JsonParser.parseString(String(proofRaw, StandardCharsets.UTF_8)).asJsonObject }
    private val owner by lazy {
        ClientWireCrypto.PublicIdentity.parse(vector.getAsJsonObject("owner_public_identity"))
    }

    @Test
    fun verifiesPublishedOwnerProofWithIndependentlySuppliedTrustedKeyAndExpectedAuthority() {
        assertEquals("PUBLIC SYNTHETIC TEST KEY — NEVER USE IN A DEPLOYMENT", vector.get("warning").asString)
        assertEquals("27e7cf05232d2e7559d684421f11fdcd370e78e84ab92eb059a4176d7a605d5c", sha256(proofRaw))
        val expected = vectorExpected()

        val verified = OwnerLinkReviewPolicyV1Verifier.verify(proofRaw, owner, expected, now)

        assertEquals(expected.ownerId, verified.ownerId)
        assertEquals(expected.linkId, verified.linkId)
        assertEquals(expected.contractDigest, verified.contractDigest)
        assertEquals(expected.policyDigest, verified.policyDigest)
        assertEquals(7L, verified.expectedLinkVersion)
        assertEquals(3L, verified.policyVersion)
        assertEquals("SOURCE", verified.side)
        assertEquals(Instant.parse("2026-10-01T14:00:00Z"), verified.expiresAt)
    }

    @Test
    fun publishedProofRejectsChangedOwnerDigestVersionSideAndStaleLinkVersion() {
        val expected = vectorExpected()
        val changedAuthorities = listOf(
            expected.copy(ownerId = "owner_synthetic_other"),
            expected.copy(linkId = "link_synthetic_other"),
            expected.copy(contractDigest = "0".repeat(64)),
            expected.copy(policyDigest = "0".repeat(64)),
            expected.copy(expectedLinkVersion = 8L),
            expected.copy(policyVersion = 4L),
            expected.copy(side = "TARGET"),
        )
        changedAuthorities.forEach { changed ->
            expectCode("LINK_REVIEW_POLICY_PROOF_INVALID") {
                verifyProof(expected = changed, trusted = owner, at = now)
            }
        }
        expectCode("LINK_REVIEW_POLICY_PROOF_INVALID") {
            verifyProof(expected = expected, trusted = owner, at = Instant.parse("2026-10-01T14:00:00Z"))
        }
    }

    @Test
    fun validatesPreviewAgainstReviewedPolicyFreshStatusAndExplicitCurrentReviewerAuthority() {
        val policy = metadataPolicy()
        val scope = currentScope().copy(
            reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "group-source")),
        )

        val preview = validate(policy, scope)

        assertEquals("link_synthetic_review_policy", preview.linkId)
        assertEquals("SOURCE", preview.side)
        assertEquals("owner_synthetic_review_policy", preview.ownerId)
        assertEquals(7L, preview.linkVersion)
        assertEquals(2L, preview.expectedPolicyVersion)
        assertEquals(3L, preview.policyVersion)
        assertEquals(LinkReviewPolicyConsentValidation.policyDigest(policy), preview.policyDigest)
        assertEquals(policy, preview.policy)
        assertEquals(Instant.parse("2026-10-01T18:00:00Z"), preview.maximumProofExpiresAt)
        assertTrue(preview.policyDigest.matches(Regex("^[0-9a-f]{64}$")))
    }

    @Test
    fun rejectsMetadataPreviewWhenIndependentCurrentLinkReviewAuthorityIsAbsentOrMismatched() {
        val policy = metadataPolicy()
        expectCode("LINK_REVIEW_POLICY_REVIEWER_AUTHORITY_MISSING") {
            validate(policy, currentScope())
        }
        expectCode("LINK_REVIEW_POLICY_REVIEWER_AUTHORITY_MISSING") {
            validate(policy, currentScope().copy(
                reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "other-group")),
            ))
        }
        expectCode("LINK_REVIEW_POLICY_REVIEWER_AUTHORITY_MISSING") {
            validate(policy.copy(reviewers = listOf(LinkReviewPolicyConsentReviewer("source-endpoint", "group-source"))),
                currentScope().copy(
                    reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("source-endpoint", "group-source")),
                ))
        }
    }

    @Test
    fun rejectsPreviewScopeChangesPolicyChangesAndHeadCasMismatches() {
        val policy = metadataPolicy()
        val validScope = currentScope().copy(
            reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "group-source")),
        )

        expectCode("LINK_REVIEW_POLICY_SCOPE_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("owner_id", "owner_synthetic_other") })
        }
        expectCode("LINK_REVIEW_POLICY_SCOPE_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("side", "TARGET") })
        }
        expectCode("LINK_REVIEW_POLICY_SCOPE_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("contract_digest", "0".repeat(64)) })
        }
        expectCode("LINK_REVIEW_POLICY_SCOPE_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("link_version", 8) })
        }
        expectCode("LINK_REVIEW_POLICY_HEAD_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("expected_policy_version", 1) })
        }
        expectCode("LINK_REVIEW_POLICY_HEAD_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("policy_version", 4) })
        }
        expectCode("LINK_REVIEW_POLICY_REVIEWED_INPUT_MISMATCH") {
            validateRaw(
                previewJson(policy).toString().toByteArray(StandardCharsets.UTF_8),
                policy.copy(maxReviewAgeSeconds = 601),
                validScope,
            )
        }
        expectCode("LINK_REVIEW_POLICY_DIGEST_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("policy_digest", "0".repeat(64)) })
        }
        expectCode("LINK_REVIEW_POLICY_PROOF_EXPIRY_MISMATCH") {
            validate(policy, validScope, previewMutation = { addProperty("maximum_proof_expires_at", "2026-10-03T18:00:00Z") })
        }
    }

    @Test
    fun rejectsDuplicateJsonKeysUnknownPreviewFieldsAndUnnormalizedReviewerOrder() {
        val policy = metadataPolicy()
        val scope = currentScope().copy(
            reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "group-source")),
        )
        val duplicate = previewJson(policy).toString().replaceFirst(
            "{\"link_id\":",
            "{\"link_id\":\"link_synthetic_review_policy\",\"link_id\":",
        )
        expectCode("LINK_REVIEW_POLICY_PREVIEW_INVALID") {
            validateRaw(duplicate.toByteArray(StandardCharsets.UTF_8), policy, scope)
        }
        expectCode("LINK_REVIEW_POLICY_PREVIEW_INVALID") {
            validate(policy, scope, previewMutation = { addProperty("owner_public_identity", "untrusted") })
        }
        val deeplyNestedUnknown = "{\"unknown\":" + "[".repeat(18) + "null" + "]".repeat(18) + "}"
        expectCode("LINK_REVIEW_POLICY_PREVIEW_INVALID") {
            validateRaw(deeplyNestedUnknown.toByteArray(StandardCharsets.UTF_8), policy, scope)
        }

        val unsorted = LinkReviewPolicyConsentPolicy(
            mode = "METADATA",
            reviewers = listOf(
                LinkReviewPolicyConsentReviewer("reviewer-z", "group-source"),
                LinkReviewPolicyConsentReviewer("reviewer-a", "group-source"),
            ),
            maxFailovers = 1,
            reviewerLeaseSeconds = 60,
            maxReviewAgeSeconds = 600,
        )
        expectCode("LINK_REVIEW_POLICY_INVALID") {
            LinkReviewPolicyConsentValidation.policyDigest(unsorted)
        }
    }

    @Test
    fun GoPolicyDigestUsesExactStructOrderAndDefaultHtmlSafeEscaping() {
        val policy = LinkReviewPolicyConsentPolicy(
            mode = "METADATA",
            reviewers = listOf(
                LinkReviewPolicyConsentReviewer("ep<&='line\u2028end", "grp>&=line\u2029end"),
            ),
            maxFailovers = 0,
            reviewerLeaseSeconds = 30,
            maxReviewAgeSeconds = 60,
        )
        val canonical = """
            {"mode":"METADATA","reviewers":[{"endpoint_id":"ep\u003c\u0026='line\u2028end","group_id":"grp\u003e\u0026=line\u2029end"}],"max_failovers":0,"reviewer_lease_seconds":30,"max_review_age_seconds":60}
        """.trimIndent()

        assertEquals(sha256(canonical.toByteArray(StandardCharsets.UTF_8)),
            LinkReviewPolicyConsentValidation.policyDigest(policy))
        assertFalse(canonical.contains("\\u003d"))
        assertFalse(canonical.contains("\\u0027"))
    }

    @Test
    fun grantBuilderRejectsVectorProofWhenCandidateDigestOrVersionDiffers() {
        val policy = metadataPolicy()
        val scope = currentScope().copy(
            reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "group-source")),
        )
        val validatedPreview = validate(policy, scope)
        val trustedOwner = LinkReviewPolicyTrustedOwnerKey(
            ownerId = "owner_synthetic_review_policy",
            ownerKeyId = owner.id,
            publicIdentity = owner,
            state = "ACTIVE",
            version = 1L,
        )

        expectCode("LINK_REVIEW_POLICY_PROOF_INVALID") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                validatedPreview, scope, statusBytes(), trustedOwner, proofRaw, now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_OWNER_KEY_SCOPE_MISMATCH") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                validatedPreview,
                scope,
                statusBytes(),
                trustedOwner.copy(ownerId = "owner_synthetic_other"),
                proofRaw,
                now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_OWNER_KEY_SCOPE_MISMATCH") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                validatedPreview, scope, statusBytes(),
                trustedOwner.copy(ownerKeyId = "different-key-id"), proofRaw, now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_OWNER_KEY_REVOKED") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                validatedPreview, scope, statusBytes(), trustedOwner.copy(state = "REVOKED"), proofRaw, now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_OWNER_KEY_VERSION_INVALID") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                validatedPreview, scope, statusBytes(), trustedOwner.copy(version = 0L), proofRaw, now,
            )
        }
    }

    @Test
    fun grantBuilderRevalidatesFreshLinkReviewerAndHeadAuthorityBeforeUsingCachedPreview() {
        val policy = metadataPolicy()
        val scope = currentScope().copy(
            reviewerAuthorities = setOf(LinkReviewPolicyCurrentReviewerAuthority("reviewer-1", "group-source")),
        )
        val cached = validate(policy, scope)
        val trustedOwner = LinkReviewPolicyTrustedOwnerKey(
            ownerId = "owner_synthetic_review_policy",
            ownerKeyId = owner.id,
            publicIdentity = owner,
            state = "ACTIVE",
            version = 1L,
        )

        expectCode("LINK_REVIEW_POLICY_REVIEWER_AUTHORITY_MISSING") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                cached, scope.copy(reviewerAuthorities = emptySet()), statusBytes(), trustedOwner, proofRaw, now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_HEAD_MISMATCH") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                cached, scope, statusBytes(policyVersion = 3L), trustedOwner, proofRaw, now,
            )
        }
        expectCode("LINK_REVIEW_POLICY_HEAD_MISMATCH") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                cached, scope, statusBytes(current = false), trustedOwner, proofRaw, now,
            )
        }
        val changedLinkScope = scope.copy(linkVersion = 8L)
        expectCode("LINK_REVIEW_POLICY_SCOPE_MISMATCH") {
            LinkReviewPolicyConsentValidation.buildGrantRequest(
                cached, changedLinkScope, statusBytes(linkVersion = 8L), trustedOwner, proofRaw, now,
            )
        }
    }

    private fun vectorExpected(proofJson: JsonObject = proof): OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority =
        OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority(
            ownerId = proofJson.get("owner_id").asString,
            linkId = proofJson.get("link_id").asString,
            contractDigest = proofJson.get("contract_digest").asString,
            policyDigest = proofJson.get("policy_digest").asString,
            expectedLinkVersion = proofJson.get("expected_link_version").asLong,
            policyVersion = proofJson.get("policy_version").asLong,
            side = proofJson.get("side").asString,
        )

    private fun verifyProof(
        expected: OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority,
        trusted: ClientWireCrypto.PublicIdentity,
        at: Instant,
    ) {
        try {
            OwnerLinkReviewPolicyV1Verifier.verify(proofRaw, trusted, expected, at)
        } catch (_: Exception) {
            throw LinkReviewPolicyConsentValidationException("LINK_REVIEW_POLICY_PROOF_INVALID")
        }
    }

    private fun metadataPolicy(): LinkReviewPolicyConsentPolicy = LinkReviewPolicyConsentPolicy(
        mode = "METADATA",
        reviewers = listOf(LinkReviewPolicyConsentReviewer("reviewer-1", "group-source")),
        maxFailovers = 0,
        reviewerLeaseSeconds = 60,
        maxReviewAgeSeconds = 600,
    )

    private fun currentScope(): LinkReviewPolicyCurrentScope = LinkReviewPolicyCurrentScope(
        linkId = "link_synthetic_review_policy",
        authenticatedOwnerId = "owner_synthetic_review_policy",
        mySide = "SOURCE",
        contractDigest = "2daccb501326e130b034eea0406c7b44f3b755a6cad28bb5bf6906bcdb6c1ab8",
        linkVersion = 7L,
        sourceEndpointId = "source-endpoint",
        sourceGroupId = "group-source",
        targetEndpointId = "target-endpoint",
        targetGroupId = "group-target",
        linkExpiresAt = Instant.parse("2026-10-01T18:00:00Z"),
    )

    private fun statusJson(
        policyVersion: Long = 2L,
        current: Boolean = true,
        linkVersion: Long = 7L,
    ): JsonObject = JsonObject().apply {
        addProperty("link_id", "link_synthetic_review_policy")
        addProperty("link_version", linkVersion)
        addProperty("policy_version", policyVersion)
        addProperty("policy_digest", if (policyVersion == 0L) "" else "a".repeat(64))
        add("policy", JsonObject().apply {
            addProperty("mode", "NONE")
            add("reviewers", JsonArray())
            addProperty("max_failovers", 0)
            addProperty("reviewer_lease_seconds", 0)
            addProperty("max_review_age_seconds", 0)
        })
        addProperty("current", current)
        add("accepted_sides", JsonArray().apply { if (policyVersion > 0) add("SOURCE") })
        if (policyVersion > 0) addProperty("expires_at", "2026-10-01T17:00:00Z")
    }

    private fun previewJson(policy: LinkReviewPolicyConsentPolicy): JsonObject = JsonObject().apply {
        addProperty("link_id", "link_synthetic_review_policy")
        addProperty("side", "SOURCE")
        addProperty("owner_id", "owner_synthetic_review_policy")
        addProperty("contract_digest", "2daccb501326e130b034eea0406c7b44f3b755a6cad28bb5bf6906bcdb6c1ab8")
        addProperty("link_version", 7)
        addProperty("expected_policy_version", 2)
        addProperty("policy_version", 3)
        addProperty("policy_digest", LinkReviewPolicyConsentValidation.policyDigest(policy))
        add("policy", policyJson(policy))
        addProperty("maximum_proof_expires_at", "2026-10-01T18:00:00Z")
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

    private fun validate(
        policy: LinkReviewPolicyConsentPolicy,
        scope: LinkReviewPolicyCurrentScope,
        previewMutation: JsonObject.() -> Unit = {},
    ): LinkReviewPolicyConsentPreview = validateRaw(
        previewJson(policy).apply(previewMutation).toString().toByteArray(StandardCharsets.UTF_8),
        policy,
        scope,
    )

    private fun validateRaw(
        rawPreview: ByteArray,
        reviewedPolicy: LinkReviewPolicyConsentPolicy,
        scope: LinkReviewPolicyCurrentScope,
        rawCurrentStatus: ByteArray = statusBytes(),
    ): LinkReviewPolicyConsentPreview = LinkReviewPolicyConsentValidation.validatePreview(
        rawPreview = rawPreview,
        reviewedPolicy = reviewedPolicy,
        rawCurrentStatus = rawCurrentStatus,
        currentScope = scope,
        now = now,
    )

    private fun statusBytes(
        policyVersion: Long = 2L,
        current: Boolean = true,
        linkVersion: Long = 7L,
    ): ByteArray = statusJson(policyVersion, current, linkVersion).toString().toByteArray(StandardCharsets.UTF_8)

    private fun expectCode(expected: String, action: () -> Unit) {
        try {
            action()
            fail("Expected $expected")
        } catch (error: LinkReviewPolicyConsentValidationException) {
            assertEquals(expected, error.code)
        }
    }

    private fun sha256(raw: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(raw).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
