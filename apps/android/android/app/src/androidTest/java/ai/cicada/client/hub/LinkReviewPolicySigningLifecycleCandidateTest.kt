package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64

/** Offline registered-signer tests; they do not establish Android runtime acceptance. */
class LinkReviewPolicySigningLifecycleCandidateTest {
    private val now = Instant.parse("2026-10-02T12:40:00Z")
    private val none = LinkReviewPolicyConsentPolicy("NONE", emptyList(), 0, 0, 0)
    private val vector by lazy {
        javaClass.classLoader!!.getResourceAsStream("link-review-policy-client-evidence-v1.json")!!
            .use { JsonParser.parseString(String(it.readBytes(), StandardCharsets.UTF_8)).asJsonObject }
    }
    private val sourcePin by lazy { pin("SOURCE") }
    private val targetPin by lazy { pin("TARGET") }
    private val link by lazy {
        val preview = vector.getAsJsonObject("preview")
        LinkReviewPolicyV164CurrentLink(
            linkId = preview.get("link_id").asString,
            linkVersion = preview.get("link_version").asLong,
            contractDigest = preview.get("contract_digest").asString,
            localSide = "SOURCE",
            sourceOwnerId = sourcePin.ownerId, targetOwnerId = targetPin.ownerId,
            sourceEndpointId = "endpoint_source", sourceGroupId = "group_source",
            targetEndpointId = "endpoint_target", targetGroupId = "group_target",
            expiresAt = now.plusSeconds(300),
            sourceOwnerPin = sourcePin, targetOwnerPin = targetPin,
        )
    }

    @Test
    fun freshNoneHeadZeroCanPrepareAndVerifyIndependentPolicyProofWithoutLinkKeyGrant() {
        for (side in listOf("SOURCE", "TARGET")) {
            ClientWireCrypto.Identity.generate().use { signer ->
                val ownerId = if (side == "SOURCE") sourcePin.ownerId else targetPin.ownerId
                val selectedPin = LinkReviewPolicyV164OwnerPin(ownerId, signer.publicIdentity.id, signer.publicIdentity)
                val authority = if (side == "SOURCE") link.copy(sourceOwnerPin = selectedPin)
                    else link.copy(localSide = side, targetOwnerPin = selectedPin)
                val head = emptyHead(authority)
                assertEquals(0, head.getAsJsonArray("owner_approvals").size())
                val preview = preview(authority)
                val candidate = validate(preview, authority)
                val lifecycle = LinkReviewPolicyV164OwnerLifecycle(ownerId, selectedPin.keyId, "ACTIVE", 7)
                val proof = signPolicy(signer, candidate)
                val request = LinkReviewPolicyEvidenceV164.buildGrantRequest(
                    candidate, bytes(preview), bytes(head), authority, selectedPin, lifecycle, proof, now,
                )
                assertEquals(selectedPin.keyId, request.ownerKeyId)
                assertEquals(0L, request.expectedPolicyVersion)
                assertEquals(LinkReviewPolicyConsentValidation.canonicalPolicyJson(none), request.policyJson)
            }
        }
    }

    @Test
    fun missingNullPartialExtraOrWrongTypeTupleCannotFallBackToPinsOrDeviceVersions() {
        val mutations = listOf(
            preview().apply { remove("signing_owner_key") } to "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
            preview().apply { add("signing_owner_key", JsonNull.INSTANCE) } to SIGNING_INVALID,
            preview().apply { addProperty("signing_owner_key", true) } to SIGNING_INVALID,
            preview().apply { key(this).remove("version") } to SIGNING_INVALID,
            preview().apply { key(this).addProperty("device_key_version", 7) } to SIGNING_INVALID,
            preview().apply { key(this).addProperty("public_identity", sourcePin.keyId) } to SIGNING_INVALID,
        )
        mutations.forEach { (value, code) -> reject(code) { validate(value) } }
    }

    @Test
    fun exactLocalOwnerSelectedKeyAndFullPublicIdentityMustMatchIndependentPin() {
        for (field in listOf("owner_id", "key_id")) {
            reject("LINK_REVIEW_POLICY_V164_OWNER_PIN_MISMATCH") {
                validate(preview().apply { key(this).addProperty(field, "wrong-selected-owner-key") })
            }
        }
        reject("LINK_REVIEW_POLICY_V164_OWNER_PIN_MISMATCH") {
            validate(preview().apply { add("signing_owner_key", signingKey(targetPin)) })
        }
        for (field in listOf("kem_public", "signing_public")) {
            val changed = preview().apply {
                val public = key(this).getAsJsonObject("public_identity")
                val raw = Base64.getDecoder().decode(public.get(field).asString)
                raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
                public.addProperty(field, Base64.getEncoder().encodeToString(raw))
            }
            reject(SIGNING_INVALID) { validate(changed) }
        }
        reject(SIGNING_INVALID) {
            validate(preview().apply { key(this).getAsJsonObject("public_identity").addProperty("extra", true) })
        }
    }

    @Test
    fun nonActiveAndNonCanonicalOrNonPositiveVersionsReject() {
        reject("LINK_REVIEW_POLICY_V164_OWNER_KEY_REVOKED") {
            validate(preview().apply { key(this).addProperty("state", "REVOKED") })
        }
        for (state in listOf("active", "PENDING", "", "STALE")) {
            reject("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
                validate(preview().apply { key(this).addProperty("state", state) })
            }
        }
        for (value in listOf("0", "-1", "true", "null", "\"7\"", "7.0", "7e0", "9223372036854775808")) {
            reject(SIGNING_INVALID) {
                validate(preview().apply { key(this).add("version", JsonParser.parseString(value)) })
            }
        }
        validate(preview().apply { key(this).addProperty("version", Long.MAX_VALUE) })
    }

    @Test
    fun freshLifecycleVersionChangeRequiresReconfirmationAndRevocationRejectsBeforeProofUse() {
        val original = preview()
        val candidate = validate(original)
        val lifecycle = LinkReviewPolicyV164OwnerLifecycle(sourcePin.ownerId, sourcePin.keyId, "ACTIVE", 7)
        reject("LINK_REVIEW_POLICY_V164_PREVIEW_STALE") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(original.deepCopy().apply { key(this).addProperty("version", 8) }),
                bytes(emptyHead()), link, sourcePin, lifecycle, byteArrayOf(1), now,
            )
        }
        reject("LINK_REVIEW_POLICY_V164_OWNER_KEY_REVOKED") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(original.deepCopy().apply { key(this).addProperty("state", "REVOKED") }),
                bytes(emptyHead()), link, sourcePin, lifecycle, byteArrayOf(1), now,
            )
        }
        reject("LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID") {
            LinkReviewPolicyEvidenceV164.buildGrantRequest(
                candidate, bytes(original), bytes(emptyHead()), link, sourcePin,
                lifecycle.copy(version = 8), byteArrayOf(1), now,
            )
        }
    }

    @Test
    fun policyHeadSideLinkExpiryAndReviewerGuardsRemainIndependentOfSigningTuple() {
        reject("LINK_REVIEW_POLICY_V164_HEAD_MISMATCH") {
            validate(preview().apply { addProperty("expected_policy_version", 1) })
        }
        reject("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH") {
            validate(preview().apply { addProperty("side", "TARGET") })
        }
        reject("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH") {
            validate(preview().apply { addProperty("link_version", link.linkVersion + 1) })
        }
        reject("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            validate(preview().apply { addProperty("maximum_proof_expires_at", now.toString()) })
        }
        reject("LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH") {
            validate(preview().apply {
                add("reviewer_qualifications", JsonArray().apply { add(JsonObject()) })
            })
        }
    }

    @Test
    fun currentRegistryTupleDoesNotProvePolicyGrantAcceptanceOrBilateralConsent() {
        val candidate = validate(preview())
        val head = LinkReviewPolicyEvidenceV164.validateActiveStatus(bytes(emptyHead()), link, now)
        assertEquals(1L, candidate.policyVersion)
        assertEquals(0L, head.policyVersion)
        assertTrue(head.unconfigured)
        assertTrue(head.acceptedSides.isEmpty())
        assertTrue(head.ownerApprovals.isEmpty())
    }

    @Test
    fun duplicateSigningFieldsCannotBeCollapsedByJsonParsing() {
        val raw = preview().toString().replaceFirst("\"version\":7", "\"version\":7,\"version\":7")
        reject("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID") {
            LinkReviewPolicyEvidenceV164.validatePreview(bytes(raw), none, bytes(emptyHead()), link, now)
        }
    }

    private fun validate(value: JsonObject, authority: LinkReviewPolicyV164CurrentLink = link) =
        LinkReviewPolicyEvidenceV164.validatePreview(bytes(value), none, bytes(emptyHead(authority)), authority, now)

    private fun preview(authority: LinkReviewPolicyV164CurrentLink = link): JsonObject =
        vector.getAsJsonObject("preview").deepCopy().apply {
            val local = if (authority.localSide == "SOURCE") authority.sourceOwnerPin else authority.targetOwnerPin
            addProperty("side", authority.localSide)
            addProperty("owner_id", local.ownerId)
            addProperty("expected_policy_version", 0)
            addProperty("policy_version", 1)
            addProperty("policy_digest", LinkReviewPolicyConsentValidation.policyDigest(none))
            add("policy", JsonParser.parseString(LinkReviewPolicyConsentValidation.canonicalPolicyJson(none)))
            addProperty("maximum_proof_expires_at", now.plusSeconds(120).toString())
            add("reviewer_qualifications", JsonArray())
            add("signing_owner_key", signingKey(local))
        }

    private fun signingKey(pin: LinkReviewPolicyV164OwnerPin) = JsonObject().apply {
        addProperty("owner_id", pin.ownerId)
        addProperty("key_id", pin.keyId)
        add("public_identity", JsonParser.parseString(pin.publicIdentity.toJson()))
        addProperty("state", "ACTIVE")
        addProperty("version", 7)
    }

    private fun emptyHead(authority: LinkReviewPolicyV164CurrentLink = link) = JsonObject().apply {
        addProperty("link_id", authority.linkId)
        addProperty("link_version", authority.linkVersion)
        addProperty("contract_digest", authority.contractDigest)
        addProperty("policy_version", 0)
        addProperty("policy_digest", "")
        add("policy", JsonParser.parseString(LinkReviewPolicyConsentValidation.canonicalPolicyJson(none)))
        addProperty("current", true)
        add("accepted_sides", JsonArray())
        addProperty("verified_at", now.toString())
        add("owner_approvals", JsonArray())
    }

    private fun signPolicy(signer: ClientWireCrypto.Identity, candidate: LinkReviewPolicyV164Preview): ByteArray {
        val claims = JsonObject().apply {
            addProperty("version", 1)
            addProperty("owner_id", candidate.ownerId)
            addProperty("link_id", candidate.linkId)
            addProperty("contract_digest", candidate.contractDigest)
            addProperty("policy_digest", candidate.policyDigest)
            addProperty("expected_link_version", candidate.linkVersion)
            addProperty("policy_version", candidate.policyVersion)
            addProperty("side", candidate.side)
            addProperty("issued_at", now.toString())
            addProperty("expires_at", now.plusSeconds(60).toString())
            addProperty("nonce", "1".repeat(64))
        }
        val domain = bytes("cicada/communication-link/review-policy-owner-approval/v1\u0000")
        claims.addProperty("signature", Base64.getEncoder().encodeToString(signer.sign(domain + bytes(claims))))
        return bytes(claims)
    }

    private fun pin(side: String): LinkReviewPolicyV164OwnerPin {
        val proof = vector.getAsJsonArray("proofs").map { it.asJsonObject }.first { it.get("side").asString == side }
        val public = ClientWireCrypto.PublicIdentity.parse(proof.getAsJsonObject("owner_public_identity"))
        return LinkReviewPolicyV164OwnerPin(proof.get("owner_id").asString, public.id, public)
    }

    private fun key(value: JsonObject) = value.getAsJsonObject("signing_owner_key")
    private fun bytes(value: JsonObject) = bytes(value.toString())
    private fun bytes(value: String) = value.toByteArray(StandardCharsets.UTF_8)
    private fun reject(code: String, action: () -> Unit) {
        try { action(); fail("Expected $code") } catch (error: LinkReviewPolicyEvidenceV164Exception) {
            assertEquals(code, error.code)
        }
    }

    private companion object {
        const val SIGNING_INVALID = "LINK_REVIEW_POLICY_V165_SIGNING_OWNER_INVALID"
    }
}
