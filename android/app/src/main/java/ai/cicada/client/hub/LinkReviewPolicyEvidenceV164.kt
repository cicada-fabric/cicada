package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Collections
import java.util.Locale

/** Independently sourced Owner identity pin; never construct this from preview/status JSON. */
internal data class LinkReviewPolicyV164OwnerPin(
    val ownerId: String,
    val keyId: String,
    val publicIdentity: ClientWireCrypto.PublicIdentity,
)

/** Current lifecycle facts must come from authenticated native authority, not an Owner pin. */
internal data class LinkReviewPolicyV164OwnerLifecycle(
    val ownerId: String,
    val keyId: String,
    val state: String,
    val version: Long,
)

/**
 * Fresh current Link facts supplied by the caller after authenticating the Link selection.
 * Both Owner pins are independent trust inputs. Reviewer permissions are represented only by
 * fresh qualifications returned from the authenticated Hub preview, never inferred from roles.
 */
internal data class LinkReviewPolicyV164CurrentLink(
    val linkId: String,
    val linkVersion: Long,
    val contractDigest: String,
    val localSide: String,
    val sourceOwnerId: String,
    val targetOwnerId: String,
    val sourceEndpointId: String,
    val sourceGroupId: String,
    val targetEndpointId: String,
    val targetGroupId: String,
    val expiresAt: Instant,
    val sourceOwnerPin: LinkReviewPolicyV164OwnerPin,
    val targetOwnerPin: LinkReviewPolicyV164OwnerPin,
)

internal data class LinkReviewPolicyV164ReviewerQualification(
    val endpointId: String,
    val groupId: String,
    val membershipRevision: Long,
    val joinRevision: Long,
    val groupVersion: Long,
    val bindingId: String,
    val bindingEpoch: Long,
    val leaseExpiresAt: Instant,
    val action: String,
)

@ConsistentCopyVisibility
internal data class LinkReviewPolicyV164VerifiedOwnerApproval internal constructor(
    val side: String,
    val ownerId: String,
    val currentStatus: String,
    val ownerLifecycle: LinkReviewPolicyV164OwnerLifecycle?,
    val verifiedProof: OwnerLinkReviewPolicyV1Verifier.VerifiedProof?,
    private val retainedProof: ByteArray?,
) {
    internal fun proofBytesCopy(): ByteArray? = retainedProof?.clone()
}

/**
 * A parsed status response. `current=false` is retained as diagnostic state: it can be an
 * active-head repair CAS input or a partial grant result, depending on which parser created it.
 */
@ConsistentCopyVisibility
internal data class LinkReviewPolicyV164Status internal constructor(
    val linkId: String,
    val linkVersion: Long,
    val contractDigest: String,
    val policyVersion: Long,
    val policyDigest: String,
    val policy: LinkReviewPolicyConsentPolicy,
    val current: Boolean,
    val acceptedSides: List<String>,
    val verifiedAt: Instant,
    val ownerApprovals: List<LinkReviewPolicyV164VerifiedOwnerApproval>,
    val expiresAt: Instant?,
    val isGrantCandidate: Boolean,
) {
    val unconfigured: Boolean get() = policyVersion == 0L
}

/** A strictly parsed, explicitly reviewed v1.6.4 preview candidate. */
internal class LinkReviewPolicyV164Preview internal constructor(
    val linkId: String,
    val side: String,
    val ownerId: String,
    val contractDigest: String,
    val linkVersion: Long,
    val expectedPolicyVersion: Long,
    val policyVersion: Long,
    val policyDigest: String,
    val policy: LinkReviewPolicyConsentPolicy,
    val maximumProofExpiresAt: Instant,
    val verifiedAt: Instant,
    val reviewerQualifications: List<LinkReviewPolicyV164ReviewerQualification>,
    internal val canonicalPolicyJson: String,
    rawPreview: ByteArray,
) {
    private val original = rawPreview.clone()
    internal fun rawPreviewCopy(): ByteArray = original.clone()
}

/** Candidate-only v1.6.4 Link review-policy DTO/evidence validation. No RPC, signing, or state. */
internal object LinkReviewPolicyEvidenceV164 {
    private const val MAX_RAW_JSON_BYTES = 64 * 1024
    private const val MAX_JSON_DEPTH = 16
    private const val MAX_PROOF_BYTES = 16 * 1024
    private const val MAX_ID_BYTES = 256
    private const val MAX_REVIEWERS = 8
    private const val MAX_POLICY_VERSION = Long.MAX_VALUE
    private const val MAX_POLICY_HEAD = Long.MAX_VALUE - 1L

    private val digestPattern = Regex("^[0-9a-f]{64}$")
    private val previewFields = setOf(
        "link_id", "side", "owner_id", "contract_digest", "link_version",
        "expected_policy_version", "policy_version", "policy_digest", "policy",
        "maximum_proof_expires_at", "verified_at", "reviewer_qualifications",
    )
    private val policyFields = setOf(
        "mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds",
    )
    private val reviewerFields = setOf("endpoint_id", "group_id")
    private val qualificationFields = setOf(
        "endpoint_id", "group_id", "membership_revision", "join_revision", "group_version",
        "binding_id", "binding_epoch", "lease_expires_at", "action",
    )
    private val statusRequiredFields = setOf(
        "link_id", "link_version", "contract_digest", "policy_version", "policy_digest",
        "policy", "current", "accepted_sides", "verified_at", "owner_approvals",
    )
    private val approvalRequiredFields = setOf("side", "owner_id", "current_status")
    private val approvalEvidenceFields = setOf(
        "owner_key_id", "owner_public_identity", "owner_key_state", "owner_key_version",
        "signed_proof", "accepted_at",
    )
    private val utcSeconds = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss", Locale.ROOT)
        .withZone(ZoneOffset.UTC)

    /**
     * Parses `link.review_policy_status` as an active-head snapshot. `current=false` is allowed
     * for bounded diagnostics and CAS repair if its outer Link tuple still matches fresh authority.
     * The raw bytes must be the response body from the authenticated/pinned Hub channel.
     */
    fun validateActiveStatus(
        rawStatus: ByteArray,
        currentLink: LinkReviewPolicyV164CurrentLink,
        now: Instant,
    ): LinkReviewPolicyV164Status = parseStatus(
        rawStatus = rawStatus,
        currentLink = currentLink,
        now = now,
        grantCandidate = false,
    )

    /**
     * Parses a grant response and binds its tuple to this exact candidate. A first-side partial
     * result remains `current=false`; it is not promoted to an active bilateral policy head.
     */
    fun validateGrantResult(
        rawResult: ByteArray,
        candidate: LinkReviewPolicyV164Preview,
        currentLink: LinkReviewPolicyV164CurrentLink,
        now: Instant,
    ): LinkReviewPolicyV164Status {
        val result = parseStatus(rawResult, currentLink, now, grantCandidate = true)
        if (result.linkId != candidate.linkId || result.linkVersion != candidate.linkVersion ||
            result.contractDigest != candidate.contractDigest || result.policyVersion != candidate.policyVersion ||
            result.policyDigest != candidate.policyDigest || result.policy != candidate.policy) {
            invalid("LINK_REVIEW_POLICY_V164_GRANT_RESULT_MISMATCH")
        }
        if (result.current && !result.ownerApprovals.map { it.currentStatus }
                .all { it == "VERIFIED" }) {
            invalid("LINK_REVIEW_POLICY_V164_GRANT_RESULT_INVALID")
        }
        return result
    }

    /**
     * Checks an explicit user-reviewed policy against a fresh preview and active-head response.
     * A noncurrent status is accepted as a diagnostic CAS head only while the current Link tuple
     * itself matches; current=false never means a partial candidate is the active status API.
     */
    fun validatePreview(
        rawPreview: ByteArray,
        reviewedPolicy: LinkReviewPolicyConsentPolicy,
        rawCurrentStatus: ByteArray,
        currentLink: LinkReviewPolicyV164CurrentLink,
        now: Instant,
    ): LinkReviewPolicyV164Preview {
        validateCurrentLink(currentLink, now)
        val currentStatus = validateActiveStatus(rawCurrentStatus, currentLink, now)
        val root = parseUniqueObject(rawPreview, "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        exactFields(root, previewFields, "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")

        val linkId = token(root, "link_id", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val side = string(root, "side", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val ownerId = token(root, "owner_id", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val contractDigest = digest(root, "contract_digest", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val linkVersion = integer(root, "link_version", 1L, Long.MAX_VALUE, "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val expectedPolicyVersion = integer(
            root, "expected_policy_version", 0L, MAX_POLICY_HEAD,
            "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
        )
        val policyVersion = integer(
            root, "policy_version", 1L, MAX_POLICY_VERSION,
            "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
        )
        val policyDigest = digest(root, "policy_digest", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val policyElement = root.get("policy")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val policy = parsePolicy(policyElement, "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        val canonicalPolicyJson = try {
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy)
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        }
        val maximumProofExpiresAt = canonicalUtc(
            root, "maximum_proof_expires_at", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID",
        )
        val verifiedAt = canonicalUtc(root, "verified_at", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        if (verifiedAt > now || !maximumProofExpiresAt.isAfter(now) ||
            maximumProofExpiresAt > currentLink.expiresAt ||
            sha256(canonicalPolicyJson.toByteArray(StandardCharsets.UTF_8)) != policyDigest) {
            invalid("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        }
        if (linkId != currentLink.linkId || side != currentLink.localSide ||
            ownerId != ownerForSide(currentLink, side).ownerId ||
            contractDigest != currentLink.contractDigest || linkVersion != currentLink.linkVersion) {
            invalid("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH")
        }
        if (expectedPolicyVersion != currentStatus.policyVersion ||
            expectedPolicyVersion == Long.MAX_VALUE || policyVersion != expectedPolicyVersion + 1L) {
            invalid("LINK_REVIEW_POLICY_V164_HEAD_MISMATCH")
        }
        if (policy != validateReviewedPolicy(reviewedPolicy)) {
            invalid("LINK_REVIEW_POLICY_V164_REVIEWED_INPUT_MISMATCH")
        }

        val qualifications = parseQualifications(
            root.get("reviewer_qualifications"), policy, currentLink, verifiedAt, now,
        )
        return LinkReviewPolicyV164Preview(
            linkId = linkId,
            side = side,
            ownerId = ownerId,
            contractDigest = contractDigest,
            linkVersion = linkVersion,
            expectedPolicyVersion = expectedPolicyVersion,
            policyVersion = policyVersion,
            policyDigest = policyDigest,
            policy = policy,
            maximumProofExpiresAt = maximumProofExpiresAt,
            verifiedAt = verifiedAt,
            reviewerQualifications = Collections.unmodifiableList(qualifications),
            canonicalPolicyJson = canonicalPolicyJson,
            rawPreview = rawPreview,
        )
    }

    /**
     * Rechecks a cached candidate against fresh Hub preview + status and verifies the supplied
     * original Owner proof. It only constructs a request; it never creates or signs a proof.
     */
    fun buildGrantRequest(
        cachedPreview: LinkReviewPolicyV164Preview,
        freshRawPreview: ByteArray,
        freshRawStatus: ByteArray,
        currentLink: LinkReviewPolicyV164CurrentLink,
        trustedLocalOwnerPin: LinkReviewPolicyV164OwnerPin,
        trustedLocalOwnerLifecycle: LinkReviewPolicyV164OwnerLifecycle,
        proofJson: ByteArray,
        now: Instant,
    ): LinkReviewPolicyConsentGrantRequest {
        val freshPreview = validatePreview(
            rawPreview = freshRawPreview,
            reviewedPolicy = cachedPreview.policy,
            rawCurrentStatus = freshRawStatus,
            currentLink = currentLink,
            now = now,
        )
        if (!samePreview(cachedPreview, freshPreview)) {
            invalid("LINK_REVIEW_POLICY_V164_PREVIEW_STALE")
        }
        val expectedOwner = ownerForSide(currentLink, freshPreview.side)
        validatePin(trustedLocalOwnerPin, expectedOwner.ownerId)
        if (!trustedLocalOwnerPin.publicIdentity.sameAs(expectedOwner.publicIdentity) ||
            trustedLocalOwnerPin.keyId != expectedOwner.keyId) {
            invalid("LINK_REVIEW_POLICY_V164_OWNER_PIN_MISMATCH")
        }
        validateLifecycle(trustedLocalOwnerLifecycle, expectedOwner.ownerId, trustedLocalOwnerPin.keyId)
        val verified = verifyOwnerProof(
            proofJson = proofJson,
            pin = trustedLocalOwnerPin,
            linkId = freshPreview.linkId,
            contractDigest = freshPreview.contractDigest,
            policyDigest = freshPreview.policyDigest,
            linkVersion = freshPreview.linkVersion,
            policyVersion = freshPreview.policyVersion,
            side = freshPreview.side,
            linkExpiresAt = currentLink.expiresAt,
            maximumProofExpiresAt = freshPreview.maximumProofExpiresAt,
            now = now,
        )
        if (verified.expiresAt > freshPreview.maximumProofExpiresAt) {
            invalid("LINK_REVIEW_POLICY_V164_PROOF_EXPIRY_MISMATCH")
        }
        return LinkReviewPolicyConsentGrantRequest(
            linkId = freshPreview.linkId,
            ownerKeyId = trustedLocalOwnerPin.keyId,
            expectedPolicyVersion = freshPreview.expectedPolicyVersion,
            policy = freshPreview.policy,
            signedProofBase64 = Base64.getEncoder().encodeToString(proofJson),
            policyJson = freshPreview.canonicalPolicyJson,
        )
    }

    private fun parseStatus(
        rawStatus: ByteArray,
        currentLink: LinkReviewPolicyV164CurrentLink,
        now: Instant,
        grantCandidate: Boolean,
    ): LinkReviewPolicyV164Status {
        validateCurrentLink(currentLink, now)
        val root = parseUniqueObject(rawStatus, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val optional = setOf("expires_at")
        if (!root.keySet().containsAll(statusRequiredFields) ||
            root.keySet().any { it !in statusRequiredFields && it !in optional }) {
            invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        }
        val linkId = token(root, "link_id", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val linkVersion = integer(root, "link_version", 1L, Long.MAX_VALUE, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val contractDigest = digest(root, "contract_digest", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val policyVersion = integer(root, "policy_version", 0L, Long.MAX_VALUE, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val policyDigest = string(root, "policy_digest", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val policy = parsePolicy(
            root.get("policy")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID"),
            "LINK_REVIEW_POLICY_V164_STATUS_INVALID",
        )
        val current = boolean(root, "current", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val verifiedAt = canonicalUtc(root, "verified_at", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        if (verifiedAt > now) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val acceptedSides = stringArray(root, "accepted_sides", 2, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        if (acceptedSides.any { it !in SIDES } || acceptedSides.distinct().size != acceptedSides.size) {
            invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        }
        val expiresAt = if (root.has("expires_at")) {
            canonicalUtc(root, "expires_at", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
                .also { if (it > currentLink.expiresAt) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID") }
        } else null

        if (linkId != currentLink.linkId || linkVersion != currentLink.linkVersion ||
            contractDigest != currentLink.contractDigest) {
            invalid("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH")
        }
        val canonicalPolicyJson = try {
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy)
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        }
        val computedDigest = sha256(canonicalPolicyJson.toByteArray(StandardCharsets.UTF_8))
        if (policyVersion == 0L) {
            if (policyDigest.isNotEmpty() || policy.mode != "NONE" || current.not() ||
                acceptedSides.isNotEmpty() || expiresAt != null) {
                invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            }
        } else if (!digestPattern.matches(policyDigest) || policyDigest != computedDigest) {
            invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        }

        val approvals = parseApprovals(root.get("owner_approvals"), policyVersion, currentLink, policy,
            policyDigest, policyVersion, verifiedAt, now)
        val verifiedSides = approvals.filter { it.currentStatus == "VERIFIED" }.map { it.side }
        if (acceptedSides != verifiedSides) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        if (current && policyVersion > 0L && (verifiedSides != SIDES ||
                expiresAt?.isAfter(now) == false)) {
            invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        }
        return LinkReviewPolicyV164Status(
            linkId = linkId,
            linkVersion = linkVersion,
            contractDigest = contractDigest,
            policyVersion = policyVersion,
            policyDigest = policyDigest,
            policy = policy,
            current = current,
            acceptedSides = Collections.unmodifiableList(acceptedSides),
            verifiedAt = verifiedAt,
            ownerApprovals = Collections.unmodifiableList(approvals),
            expiresAt = expiresAt,
            isGrantCandidate = grantCandidate,
        )
    }

    private fun parseApprovals(
        element: JsonElement?,
        policyVersion: Long,
        currentLink: LinkReviewPolicyV164CurrentLink,
        policy: LinkReviewPolicyConsentPolicy,
        policyDigest: String,
        proofPolicyVersion: Long,
        verifiedAt: Instant,
        now: Instant,
    ): List<LinkReviewPolicyV164VerifiedOwnerApproval> {
        val values = element?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        if (values.size() > 2) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        if (policyVersion == 0L) {
            if (values.size() != 0 || policyDigest.isNotEmpty() || policy.mode != "NONE") {
                invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            }
            return emptyList()
        }
        if (values.size() != 2) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        val result = ArrayList<LinkReviewPolicyV164VerifiedOwnerApproval>(2)
        for ((index, side) in SIDES.withIndex()) {
            val row = values[index].takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val allowedFields = approvalRequiredFields + "evidence"
            if (!row.keySet().containsAll(approvalRequiredFields) ||
                row.keySet().any { it !in allowedFields }) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val actualSide = string(row, "side", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val ownerId = token(row, "owner_id", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val currentStatus = string(row, "current_status", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            if (actualSide != side || ownerId != ownerForSide(currentLink, side).ownerId ||
                currentStatus !in OWNER_STATUSES) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val hasEvidence = row.has("evidence")
            if ((currentStatus == "VERIFIED") != hasEvidence) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            if (currentStatus != "VERIFIED") {
                result += LinkReviewPolicyV164VerifiedOwnerApproval(
                    side, ownerId, currentStatus, null, null, null,
                )
                continue
            }
            val evidence = row.get("evidence")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            exactFields(evidence, approvalEvidenceFields, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val pin = ownerForSide(currentLink, side)
            validatePin(pin, ownerId)
            val keyId = token(evidence, "owner_key_id", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val keyState = string(evidence, "owner_key_state", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val keyVersion = integer(
                evidence, "owner_key_version", 1L, Long.MAX_VALUE,
                "LINK_REVIEW_POLICY_V164_STATUS_INVALID",
            )
            val evidenceIdentity = parsePublicIdentity(
                evidence.get("owner_public_identity"), "LINK_REVIEW_POLICY_V164_STATUS_INVALID",
            )
            if (keyId != pin.keyId || keyState != "ACTIVE" ||
                !evidenceIdentity.sameAs(pin.publicIdentity)) {
                invalid("LINK_REVIEW_POLICY_V164_OWNER_PIN_MISMATCH")
            }
            val lifecycle = LinkReviewPolicyV164OwnerLifecycle(ownerId, keyId, keyState, keyVersion)
            val acceptedAt = canonicalUtc(evidence, "accepted_at", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            if (acceptedAt > verifiedAt || acceptedAt > now) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val proofText = string(evidence, "signed_proof", "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val proof = decodeProof(proofText, "LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            val verifiedProof = verifyOwnerProof(
                proofJson = proof,
                pin = pin,
                linkId = currentLink.linkId,
                contractDigest = currentLink.contractDigest,
                policyDigest = policyDigest,
                linkVersion = currentLink.linkVersion,
                policyVersion = proofPolicyVersion,
                side = side,
                linkExpiresAt = currentLink.expiresAt,
                maximumProofExpiresAt = currentLink.expiresAt,
                now = now,
            )
            if (acceptedAt < verifiedProof.issuedAt || verifiedProof.expiresAt > currentLink.expiresAt) {
                invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
            }
            result += LinkReviewPolicyV164VerifiedOwnerApproval(
                side, ownerId, currentStatus, lifecycle, verifiedProof, proof,
            )
        }
        if (result.map { it.side } != SIDES) invalid("LINK_REVIEW_POLICY_V164_STATUS_INVALID")
        return result
    }

    private fun parseQualifications(
        element: JsonElement?,
        policy: LinkReviewPolicyConsentPolicy,
        currentLink: LinkReviewPolicyV164CurrentLink,
        verifiedAt: Instant,
        now: Instant,
    ): List<LinkReviewPolicyV164ReviewerQualification> {
        val values = element?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
        if (values.size() > MAX_REVIEWERS || values.size() != policy.reviewers.size) {
            invalid("LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH")
        }
        val linkEndpoints = setOf(currentLink.sourceEndpointId, currentLink.targetEndpointId)
        val linkGroups = setOf(currentLink.sourceGroupId, currentLink.targetGroupId)
        val result = ArrayList<LinkReviewPolicyV164ReviewerQualification>(values.size())
        for ((index, reviewer) in policy.reviewers.withIndex()) {
            val row = values[index].takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            exactFields(row, qualificationFields, "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val endpointId = token(row, "endpoint_id", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val groupId = token(row, "group_id", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val membershipRevision = integer(row, "membership_revision", 1L, Long.MAX_VALUE,
                "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val joinRevision = integer(row, "join_revision", 1L, Long.MAX_VALUE,
                "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val groupVersion = integer(row, "group_version", 1L, Long.MAX_VALUE,
                "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val bindingId = token(row, "binding_id", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val bindingEpoch = integer(row, "binding_epoch", 1L, Long.MAX_VALUE,
                "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val leaseExpiresAt = canonicalUtc(row, "lease_expires_at", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            val action = string(row, "action", "LINK_REVIEW_POLICY_V164_PREVIEW_INVALID")
            if (endpointId != reviewer.endpointId || groupId != reviewer.groupId ||
                endpointId in linkEndpoints || groupId !in linkGroups || action != "link.review" ||
                leaseExpiresAt <= now || leaseExpiresAt <= verifiedAt) {
                invalid("LINK_REVIEW_POLICY_V164_QUALIFICATION_MISMATCH")
            }
            result += LinkReviewPolicyV164ReviewerQualification(
                endpointId, groupId, membershipRevision, joinRevision, groupVersion,
                bindingId, bindingEpoch, leaseExpiresAt, action,
            )
        }
        return result
    }

    private fun parsePolicy(value: JsonObject, code: String): LinkReviewPolicyConsentPolicy {
        exactFields(value, policyFields, code)
        val mode = string(value, "mode", code)
        if (mode !in setOf("NONE", "METADATA")) invalid(code)
        val reviewersJson = value.get("reviewers")?.takeIf { it.isJsonArray }?.asJsonArray ?: invalid(code)
        if (reviewersJson.size() > MAX_REVIEWERS) invalid(code)
        val reviewers = reviewersJson.map { element ->
            val row = element.takeIf { it.isJsonObject }?.asJsonObject ?: invalid(code)
            exactFields(row, reviewerFields, code)
            LinkReviewPolicyConsentReviewer(
                policyIdentifier(string(row, "endpoint_id", code), code),
                policyIdentifier(string(row, "group_id", code), code),
            )
        }
        val policy = LinkReviewPolicyConsentPolicy(
            mode = mode,
            reviewers = reviewers,
            maxFailovers = integer(value, "max_failovers", 0L, 8L, code).toInt(),
            reviewerLeaseSeconds = integer(value, "reviewer_lease_seconds", 0L, 3600L, code).toInt(),
            maxReviewAgeSeconds = integer(value, "max_review_age_seconds", 0L, 86400L, code).toInt(),
        )
        return try {
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy)
            policy.copy(reviewers = Collections.unmodifiableList(reviewers))
        } catch (_: Exception) {
            invalid(code)
        }
    }

    private fun validateReviewedPolicy(policy: LinkReviewPolicyConsentPolicy): LinkReviewPolicyConsentPolicy {
        return try {
            LinkReviewPolicyConsentValidation.canonicalPolicyJson(policy)
            policy.copy(reviewers = Collections.unmodifiableList(policy.reviewers.toList()))
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_V164_REVIEWED_INPUT_INVALID")
        }
    }

    private fun validateCurrentLink(currentLink: LinkReviewPolicyV164CurrentLink, now: Instant) {
        if (!canonicalToken(currentLink.linkId) || currentLink.linkVersion < 1L ||
            !digestPattern.matches(currentLink.contractDigest) || currentLink.localSide !in SIDES ||
            !canonicalToken(currentLink.sourceOwnerId) || !canonicalToken(currentLink.targetOwnerId) ||
            !policyIdentifierValid(currentLink.sourceEndpointId) || !policyIdentifierValid(currentLink.targetEndpointId) ||
            !policyIdentifierValid(currentLink.sourceGroupId) || !policyIdentifierValid(currentLink.targetGroupId) ||
            currentLink.sourceEndpointId == currentLink.targetEndpointId ||
            !currentLink.expiresAt.isAfter(now)) {
            invalid("LINK_REVIEW_POLICY_V164_CURRENT_SCOPE_INVALID")
        }
        validatePin(currentLink.sourceOwnerPin, currentLink.sourceOwnerId)
        validatePin(currentLink.targetOwnerPin, currentLink.targetOwnerId)
    }

    private fun validatePin(pin: LinkReviewPolicyV164OwnerPin, expectedOwnerId: String) {
        if (pin.ownerId != expectedOwnerId || !canonicalToken(pin.ownerId) || !canonicalToken(pin.keyId)) {
            invalid("LINK_REVIEW_POLICY_V164_OWNER_PIN_INVALID")
        }
        try {
            pin.publicIdentity.validate()
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_V164_OWNER_PIN_INVALID")
        }
        if (pin.keyId != pin.publicIdentity.id) invalid("LINK_REVIEW_POLICY_V164_OWNER_PIN_INVALID")
    }

    private fun validateLifecycle(
        lifecycle: LinkReviewPolicyV164OwnerLifecycle,
        expectedOwnerId: String,
        expectedKeyId: String,
    ) {
        if (lifecycle.ownerId != expectedOwnerId || lifecycle.keyId != expectedKeyId ||
            lifecycle.state != "ACTIVE" || lifecycle.version < 1L) {
            invalid(if (lifecycle.state == "REVOKED") "LINK_REVIEW_POLICY_V164_OWNER_KEY_REVOKED"
                else "LINK_REVIEW_POLICY_V164_OWNER_LIFECYCLE_INVALID")
        }
    }

    private fun ownerForSide(currentLink: LinkReviewPolicyV164CurrentLink, side: String): LinkReviewPolicyV164OwnerPin =
        when (side) {
            "SOURCE" -> currentLink.sourceOwnerPin
            "TARGET" -> currentLink.targetOwnerPin
            else -> invalid("LINK_REVIEW_POLICY_V164_SCOPE_MISMATCH")
        }

    private fun verifyOwnerProof(
        proofJson: ByteArray,
        pin: LinkReviewPolicyV164OwnerPin,
        linkId: String,
        contractDigest: String,
        policyDigest: String,
        linkVersion: Long,
        policyVersion: Long,
        side: String,
        linkExpiresAt: Instant,
        maximumProofExpiresAt: Instant,
        now: Instant,
    ): OwnerLinkReviewPolicyV1Verifier.VerifiedProof {
        if (proofJson.isEmpty() || proofJson.size > MAX_PROOF_BYTES) {
            invalid("LINK_REVIEW_POLICY_V164_PROOF_INVALID")
        }
        validatePin(pin, pin.ownerId)
        val expected = OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority(
            ownerId = pin.ownerId,
            linkId = linkId,
            contractDigest = contractDigest,
            policyDigest = policyDigest,
            expectedLinkVersion = linkVersion,
            policyVersion = policyVersion,
            side = side,
        )
        val verified = try {
            OwnerLinkReviewPolicyV1Verifier.verify(proofJson, pin.publicIdentity, expected, now)
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_V164_PROOF_INVALID")
        }
        if (verified.expiresAt > linkExpiresAt || verified.expiresAt > maximumProofExpiresAt) {
            invalid("LINK_REVIEW_POLICY_V164_PROOF_EXPIRY_MISMATCH")
        }
        return verified
    }

    private fun parsePublicIdentity(element: JsonElement?, code: String): ClientWireCrypto.PublicIdentity {
        val value = element?.takeIf { it.isJsonObject }?.asJsonObject ?: invalid(code)
        exactFields(value, setOf("id", "kem_public", "signing_public"), code)
        val kemPublic = string(value, "kem_public", code)
        val signingPublic = string(value, "signing_public", code)
        decodeCanonicalBase64(kemPublic, 1_184, code)
        decodeCanonicalBase64(signingPublic, 1_952, code)
        return try {
            ClientWireCrypto.PublicIdentity.parse(value)
        } catch (_: Exception) {
            invalid(code)
        }
    }

    private fun decodeCanonicalBase64(value: String, expectedBytes: Int, code: String): ByteArray {
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (_: Exception) {
            invalid(code)
        }
        if (decoded.size != expectedBytes || Base64.getEncoder().encodeToString(decoded) != value) invalid(code)
        return decoded
    }

    private fun decodeProof(value: String, code: String): ByteArray {
        if (value.length > 21_848) invalid(code)
        val decoded = try {
            Base64.getDecoder().decode(value)
        } catch (_: Exception) {
            invalid(code)
        }
        if (decoded.isEmpty() || decoded.size > MAX_PROOF_BYTES ||
            Base64.getEncoder().encodeToString(decoded) != value) invalid(code)
        return decoded
    }

    private fun parseUniqueObject(raw: ByteArray, code: String): JsonObject {
        if (raw.isEmpty() || raw.size > MAX_RAW_JSON_BYTES) invalid(code)
        try {
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
            val reader = JsonReader(StringReader(text)).apply { isLenient = false }
            val value = readJsonValue(reader, code, 0)
            if (!value.isJsonObject || reader.peek() != JsonToken.END_DOCUMENT) invalid(code)
            return value.asJsonObject
        } catch (_: LinkReviewPolicyEvidenceV164Exception) {
            throw LinkReviewPolicyEvidenceV164Exception(code)
        } catch (_: Exception) {
            invalid(code)
        }
    }

    private fun readJsonValue(reader: JsonReader, code: String, depth: Int): JsonElement {
        if (depth > MAX_JSON_DEPTH) invalid(code)
        return when (reader.peek()) {
            JsonToken.BEGIN_OBJECT -> {
                val result = JsonObject()
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (result.has(name)) invalid(code)
                    result.add(name, readJsonValue(reader, code, depth + 1))
                }
                reader.endObject()
                result
            }
            JsonToken.BEGIN_ARRAY -> {
                val result = JsonArray()
                reader.beginArray()
                while (reader.hasNext()) result.add(readJsonValue(reader, code, depth + 1))
                reader.endArray()
                result
            }
            JsonToken.STRING -> JsonPrimitive(reader.nextString())
            JsonToken.NUMBER -> JsonPrimitive(RawJsonNumber(reader.nextString()))
            JsonToken.BOOLEAN -> JsonPrimitive(reader.nextBoolean())
            JsonToken.NULL -> {
                reader.nextNull()
                JsonNull.INSTANCE
            }
            else -> invalid(code)
        }
    }

    private fun exactFields(value: JsonObject, expected: Set<String>, code: String) {
        if (value.keySet() != expected) invalid(code)
    }

    private fun string(value: JsonObject, field: String, code: String): String =
        value.get(field)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?: invalid(code)

    private fun token(value: JsonObject, field: String, code: String): String =
        string(value, field, code).also { if (!canonicalToken(it)) invalid(code) }

    private fun digest(value: JsonObject, field: String, code: String): String =
        string(value, field, code).also { if (!digestPattern.matches(it)) invalid(code) }

    private fun boolean(value: JsonObject, field: String, code: String): Boolean =
        value.get(field)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            ?: invalid(code)

    private fun integer(value: JsonObject, field: String, min: Long, max: Long, code: String): Long {
        val element = value.get(field)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asJsonPrimitive
            ?: invalid(code)
        val text = element.asString
        if (!text.matches(Regex("^(0|[1-9][0-9]*)$"))) invalid(code)
        val parsed = text.toLongOrNull() ?: invalid(code)
        if (parsed !in min..max) invalid(code)
        return parsed
    }

    private fun stringArray(value: JsonObject, field: String, max: Int, code: String): List<String> {
        val array = value.get(field)?.takeIf { it.isJsonArray }?.asJsonArray ?: invalid(code)
        if (array.size() > max) invalid(code)
        return array.map { it.takeIf { item -> item.isJsonPrimitive && item.asJsonPrimitive.isString }?.asString
            ?: invalid(code) }
    }

    private fun canonicalUtc(value: JsonObject, field: String, code: String): Instant =
        canonicalUtc(string(value, field, code), code)

    private fun canonicalUtc(value: String, code: String): Instant {
        if (value.length > 40) invalid(code)
        val instant = try {
            Instant.parse(value)
        } catch (_: Exception) {
            invalid(code)
        }
        val seconds = utcSeconds.format(instant)
        val canonical = if (instant.nano == 0) {
            "${seconds}Z"
        } else {
            "${seconds}.${instant.nano.toString().padStart(9, '0').trimEnd('0')}Z"
        }
        if (canonical != value) invalid(code)
        return instant
    }

    private fun policyIdentifier(value: String, code: String): String {
        if (!policyIdentifierValid(value)) invalid(code)
        return value
    }

    private fun policyIdentifierValid(value: String): Boolean = value.isNotEmpty() &&
        value.toByteArray(StandardCharsets.UTF_8).size <= MAX_ID_BYTES &&
        value == value.trim() && isWellFormedUtf16(value)

    private fun canonicalToken(value: String): Boolean {
        if (value.isEmpty() || value.toByteArray(StandardCharsets.UTF_8).size > MAX_ID_BYTES ||
            !isWellFormedUtf16(value)) return false
        var offset = 0
        while (offset < value.length) {
            val point = value.codePointAt(offset)
            if (Character.isWhitespace(point) || Character.isSpaceChar(point) ||
                Character.isISOControl(point) || point == '/'.code || point == '\\'.code) return false
            offset += Character.charCount(point)
        }
        return true
    }

    private fun isWellFormedUtf16(value: String): Boolean {
        var index = 0
        while (index < value.length) {
            val current = value[index]
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) return false
                index += 2
            } else {
                if (Character.isLowSurrogate(current)) return false
                index++
            }
        }
        return true
    }

    private fun samePreview(left: LinkReviewPolicyV164Preview, right: LinkReviewPolicyV164Preview): Boolean =
        left.linkId == right.linkId && left.side == right.side && left.ownerId == right.ownerId &&
            left.contractDigest == right.contractDigest && left.linkVersion == right.linkVersion &&
            left.expectedPolicyVersion == right.expectedPolicyVersion && left.policyVersion == right.policyVersion &&
            left.policyDigest == right.policyDigest && left.policy == right.policy &&
            left.maximumProofExpiresAt == right.maximumProofExpiresAt &&
            left.reviewerQualifications == right.reviewerQualifications &&
            left.canonicalPolicyJson == right.canonicalPolicyJson

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun invalid(code: String): Nothing = throw LinkReviewPolicyEvidenceV164Exception(code)

    private val SIDES = listOf("SOURCE", "TARGET")
    private val OWNER_STATUSES = setOf(
        "MISSING", "VERIFIED", "OWNER_KEY_REVOKED", "PROOF_EXPIRED", "SCOPE_STALE", "INVALID",
    )

    private class RawJsonNumber(private val value: String) : Number() {
        override fun toByte(): Byte = value.toByte()
        override fun toChar(): Char = value.toInt().toChar()
        override fun toDouble(): Double = value.toDouble()
        override fun toFloat(): Float = value.toFloat()
        override fun toInt(): Int = value.toInt()
        override fun toLong(): Long = value.toLong()
        override fun toShort(): Short = value.toShort()
        override fun toString(): String = value
    }
}

internal class LinkReviewPolicyEvidenceV164Exception(val code: String) : IllegalArgumentException(code)
