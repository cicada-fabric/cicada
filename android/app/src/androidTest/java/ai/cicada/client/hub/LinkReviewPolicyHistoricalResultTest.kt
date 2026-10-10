package ai.cicada.client.hub

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

/** Historical grant-result checks using only the public synthetic Core vector. */
class LinkReviewPolicyHistoricalResultTest {
    private val vector by lazy {
        javaClass.classLoader!!.getResourceAsStream("link-review-policy-client-evidence-v1.json")!!
            .use { JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject }
    }
    private val sourcePin by lazy { pinFor("SOURCE") }
    private val targetPin by lazy { pinFor("TARGET") }
    private val authority by lazy {
        val preview = vector.getAsJsonObject("preview")
        val reviewers = preview.getAsJsonObject("policy").getAsJsonArray("reviewers")
        LinkReviewPolicyV164CurrentLink(
            linkId = preview.get("link_id").asString,
            linkVersion = preview.get("link_version").asLong,
            contractDigest = preview.get("contract_digest").asString,
            localSide = "SOURCE",
            sourceOwnerId = approval("SOURCE").get("owner_id").asString,
            targetOwnerId = approval("TARGET").get("owner_id").asString,
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
    fun acceptsOriginalSignedSnapshotAndCanonicalGoFractionalVerifiedAt() {
        val original = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(
            bytes(vector.getAsJsonObject("status")), authority,
        )
        assertTrue(original.isGrantCandidate)
        assertTrue(original.current)
        assertEquals(listOf("SOURCE", "TARGET"), original.acceptedSides)
        assertEquals(2, original.ownerApprovals.count { it.verifiedProof != null })

        val fractional = vector.getAsJsonObject("status").deepCopy().apply {
            // Go RFC3339Nano omits trailing fractional zeroes.
            addProperty("verified_at", "2026-10-02T12:30:00.12Z")
        }
        val parsed = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(fractional), authority)
        assertEquals(Instant.parse("2026-10-02T12:30:00.12Z"), parsed.verifiedAt)
        assertTrue(parsed.verifiedAt > Instant.parse("2026-10-02T12:30:00Z"))
        assertTrue(parsed.current)
    }

    @Test
    fun rejectsNoncanonicalSnapshotTime() {
        val noncanonical = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("verified_at", "2026-10-02T12:30:00.120Z")
        }
        expect("LINK_REVIEW_POLICY_V164_STATUS_INVALID") {
            LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(noncanonical), authority)
        }
    }

    @Test
    fun rejectsOriginalProofsIssuedAfterTheirHistoricalSnapshotTime() {
        val snapshotTime = Instant.parse(proof("SOURCE").get("issued_at").asString).minusNanos(1)
        val futureIssued = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("verified_at", snapshotTime.toString())
            // accepted_at is unsigned Hub metadata; pin it to the snapshot so proof-time checking
            // itself rejects the original signed proof as not yet issued.
            getAsJsonArray("owner_approvals").forEach { row ->
                row.asJsonObject.getAsJsonObject("evidence").addProperty("accepted_at", snapshotTime.toString())
            }
        }
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(futureIssued), authority)
        }
    }

    @Test
    fun rejectsOriginalProofsExpiredByTheirHistoricalSnapshotTime() {
        val proofExpiry = Instant.parse(proof("SOURCE").get("expires_at").asString)
        val expiredSnapshot = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("verified_at", proofExpiry.plusNanos(1).toString())
            // Omit the optional status expiry so the Owner proof's own expiry is the rejecting guard.
            remove("expires_at")
        }
        val laterLink = authority.copy(expiresAt = proofExpiry.plusSeconds(60))
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(expiredSnapshot), laterLink)
        }
    }

    @Test
    fun rejectsTamperedProofAndWrongIndependentOwnerPin() {
        val tampered = vector.getAsJsonObject("status").deepCopy()
        val evidence = tampered.getAsJsonArray("owner_approvals")[0].asJsonObject.getAsJsonObject("evidence")
        val originalProofJson = String(
            Base64.getDecoder().decode(evidence.get("signed_proof").asString), StandardCharsets.UTF_8,
        )
        val signaturePattern = Regex("""("signature":")([^\"]+)(")""")
        val match = signaturePattern.find(originalProofJson)
            ?: error("Public proof vector omitted its signature")
        val signature = match.groupValues[2]
        val replacement = if (signature.first() == 'A') 'B' else 'A'
        val changedProofJson = originalProofJson.replaceRange(
            match.groups[2]!!.range, replacement + signature.drop(1),
        )
        assertFalse("proof vector must contain a signature field", changedProofJson == originalProofJson)
        evidence.addProperty(
            "signed_proof",
            Base64.getEncoder().encodeToString(changedProofJson.toByteArray(StandardCharsets.UTF_8)),
        )
        expect("LINK_REVIEW_POLICY_V164_PROOF_INVALID") {
            LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(tampered), authority)
        }

        val wrongPin = authority.copy(sourceOwnerPin = targetPin)
        expect("LINK_REVIEW_POLICY_V164_OWNER_PIN_INVALID") {
            LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(
                bytes(vector.getAsJsonObject("status")), wrongPin,
            )
        }
    }

    @Test
    fun secondSideCompletionVerifiesPeerProofWithoutInventingPeerPreviewLifecycle() {
        val status = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(
            bytes(vector.getAsJsonObject("status")), authority,
        )
        assertTrue(status.ownerApprovals.all { it.verifiedProof != null })
        val source = status.ownerApprovals.first { it.side == "SOURCE" }.ownerLifecycle!!
        val target = status.ownerApprovals.first { it.side == "TARGET" }.ownerLifecycle!!
        LinkReviewPolicyEvidenceV164.validateReviewedSigningLifecycles(status, "SOURCE", source, null)
        LinkReviewPolicyEvidenceV164.validateReviewedSigningLifecycles(status, "TARGET", null, target)
    }

    @Test
    fun terminalLifecycleCheckRequiresLocalReviewAndRejectsChangedReviewedLifecycle() {
        val status = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(
            bytes(vector.getAsJsonObject("status")), authority,
        )
        val source = status.ownerApprovals.first { it.side == "SOURCE" }.ownerLifecycle!!
        val target = status.ownerApprovals.first { it.side == "TARGET" }.ownerLifecycle!!
        expect("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
            LinkReviewPolicyEvidenceV164.validateReviewedSigningLifecycles(status, "SOURCE", null, null)
        }
        expect("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
            LinkReviewPolicyEvidenceV164.validateReviewedSigningLifecycles(status, "SOURCE", source.copy(version = 2), null)
        }
        expect("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
            LinkReviewPolicyEvidenceV164.validateReviewedSigningLifecycles(status, "SOURCE", source, target.copy(version = 2))
        }
    }

    @Test
    fun firstSidePartialResultRemainsNoncurrent() {
        val partial = vector.getAsJsonObject("status").deepCopy().apply {
            addProperty("current", false)
            add("accepted_sides", com.google.gson.JsonArray().apply { add("SOURCE") })
            getAsJsonArray("owner_approvals")[1].asJsonObject.apply {
                addProperty("current_status", "MISSING")
                remove("evidence")
            }
        }

        val result = LinkReviewPolicyEvidenceV164.validateHistoricalGrantResult(bytes(partial), authority)

        assertFalse(result.current)
        assertTrue(result.isGrantCandidate)
        assertEquals(listOf("SOURCE"), result.acceptedSides)
        assertEquals(listOf("VERIFIED", "MISSING"), result.ownerApprovals.map { it.currentStatus })
        assertNotNull(result.ownerApprovals[0].verifiedProof)
        assertNull(result.ownerApprovals[1].verifiedProof)
    }

    private fun approval(side: String): JsonObject = vector.getAsJsonObject("status")
        .getAsJsonArray("owner_approvals").map { it.asJsonObject }
        .first { it.get("side").asString == side }

    private fun proof(side: String): JsonObject {
        val evidence = approval(side).getAsJsonObject("evidence")
        return JsonParser.parseString(
            String(Base64.getDecoder().decode(evidence.get("signed_proof").asString), StandardCharsets.UTF_8),
        ).asJsonObject
    }

    private fun pinFor(side: String): LinkReviewPolicyV164OwnerPin {
        val row = approval(side)
        val evidence = row.getAsJsonObject("evidence")
        val identity = ClientWireCrypto.PublicIdentity.parse(evidence.getAsJsonObject("owner_public_identity"))
        return LinkReviewPolicyV164OwnerPin(row.get("owner_id").asString, identity.id, identity)
    }

    private fun bytes(value: JsonObject): ByteArray = value.toString().toByteArray(StandardCharsets.UTF_8)

    private fun expect(code: String, action: () -> Unit) {
        try {
            action()
            fail("Expected $code")
        } catch (error: LinkReviewPolicyEvidenceV164Exception) {
            assertEquals(code, error.code)
        }
    }
}
