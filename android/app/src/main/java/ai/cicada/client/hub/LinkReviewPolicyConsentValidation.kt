package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.util.Collections
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Base64

/** Exact v1.6.1 Link review-policy DTOs. Reviewer order is part of the reviewed body. */
internal data class LinkReviewPolicyConsentReviewer(
    val endpointId: String,
    val groupId: String,
)

internal data class LinkReviewPolicyConsentPolicy(
    val mode: String,
    val reviewers: List<LinkReviewPolicyConsentReviewer>,
    val maxFailovers: Int,
    val reviewerLeaseSeconds: Int,
    val maxReviewAgeSeconds: Int,
)

/**
 * One reviewer which a separate current-scope verifier has established is an active Endpoint in
 * this Group and has the explicit `link.review` permission. This is not a Monitor/Join role.
 */
internal data class LinkReviewPolicyCurrentReviewerAuthority(
    val endpointId: String,
    val groupId: String,
)

/**
 * Current Link and authenticated Owner facts obtained outside the untrusted policy preview.
 * `reviewerAuthorities` must come from an independent current-permission verifier. The pinned
 * Client contract does not currently provide that verifier's evidence, so METADATA must remain
 * unavailable until a trusted caller can supply this set.
 */
internal data class LinkReviewPolicyCurrentScope(
    val linkId: String,
    val authenticatedOwnerId: String,
    val mySide: String,
    val contractDigest: String,
    val linkVersion: Long,
    val sourceEndpointId: String,
    val sourceGroupId: String,
    val targetEndpointId: String,
    val targetGroupId: String,
    val linkExpiresAt: Instant,
    val reviewerAuthorities: Set<LinkReviewPolicyCurrentReviewerAuthority> = emptySet(),
)

/** Validated, immutable preview. Construct through [LinkReviewPolicyConsentValidation.validatePreview]. */
internal class LinkReviewPolicyConsentPreview internal constructor(
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
    internal val canonicalPolicyJson: String,
    rawPreview: ByteArray,
) {
    private val originalPreview = rawPreview.clone()

    internal fun rawPreviewCopy(): ByteArray = originalPreview.clone()
}

/** Owner key material is passed from the Client's trusted local Owner-key association. */
internal data class LinkReviewPolicyTrustedOwnerKey(
    val ownerId: String,
    val ownerKeyId: String,
    val publicIdentity: ClientWireCrypto.PublicIdentity,
    val state: String,
    val version: Long,
)

/** Exact request fields for `link.review_policy_grant`; the proof has already been verified. */
internal data class LinkReviewPolicyConsentGrantRequest(
    val linkId: String,
    val ownerKeyId: String,
    val expectedPolicyVersion: Long,
    val policy: LinkReviewPolicyConsentPolicy,
    val signedProofBase64: String,
    val policyJson: String,
) {
    /** Serializes only the pinned grant fields and the exact reviewed policy. */
    fun toJson(): String = ClientWireCrypto.json { writer ->
        writer.beginObject()
            .name("link_id").value(linkId)
            .name("owner_key_id").value(ownerKeyId)
            .name("expected_policy_version").value(expectedPolicyVersion)
            .name("policy")
        writer.jsonValue(policyJson)
        writer.name("signed_proof").value(signedProofBase64)
            .endObject()
    }
}

/**
 * Pure, fail-closed validation for the pinned Client-Control v1 Link review-policy DTOs.
 * This object does not fetch scope, discover permission, create/sign proofs, or trust Hub keys.
 */
internal object LinkReviewPolicyConsentValidation {
    private const val MAX_RAW_JSON_BYTES = 64 * 1024
    private const val MAX_JSON_DEPTH = 16
    private const val MAX_PROOF_BYTES = 16 * 1024
    private const val MAX_ID_BYTES = 256
    private const val MAX_POLICY_REVIEWERS = 8
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val POLICY_VERSION_MAX_HEAD = MAX_SAFE_INTEGER - 1L

    private val sha256Pattern = Regex("^[0-9a-f]{64}$")
    private val previewFields = setOf(
        "link_id", "side", "owner_id", "contract_digest", "link_version",
        "expected_policy_version", "policy_version", "policy_digest", "policy",
        "maximum_proof_expires_at",
    )
    private val policyFields = setOf(
        "mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds",
    )
    private val reviewerFields = setOf("endpoint_id", "group_id")

    /**
     * Validates a raw preview against the exact policy the user reviewed, a fresh status response,
     * and Link/Owner facts obtained independently from the current authenticated Link selection.
     * Duplicate JSON object keys are rejected before Gson can collapse them.
     */
    fun validatePreview(
        rawPreview: ByteArray,
        reviewedPolicy: LinkReviewPolicyConsentPolicy,
        rawCurrentStatus: ByteArray,
        currentScope: LinkReviewPolicyCurrentScope,
        now: Instant,
    ): LinkReviewPolicyConsentPreview {
        validateCurrentScope(currentScope, now)
        val statusJson = parseUniqueObject(rawCurrentStatus, "LINK_REVIEW_POLICY_CURRENT_STATUS_INVALID")
        val currentStatus = try {
            LinkReviewPolicyStatusValidation.validateStatus(
                statusJson,
                currentScope.linkId,
                currentScope.linkVersion,
            )
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_CURRENT_STATUS_INVALID")
        }
        if (!currentStatus.current) invalid("LINK_REVIEW_POLICY_HEAD_MISMATCH")

        val root = parseUniqueObject(rawPreview, "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        exactFields(root, previewFields, "LINK_REVIEW_POLICY_PREVIEW_INVALID")

        val linkId = token(root, "link_id", "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val side = string(root, "side", "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val ownerId = token(root, "owner_id", "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val contractDigest = digest(root, "contract_digest", "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val linkVersion = integer(root, "link_version", 1L, MAX_SAFE_INTEGER, "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val expectedPolicyVersion = integer(
            root, "expected_policy_version", 0L, POLICY_VERSION_MAX_HEAD,
            "LINK_REVIEW_POLICY_PREVIEW_INVALID",
        )
        val policyVersion = integer(root, "policy_version", 1L, MAX_SAFE_INTEGER, "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val policyDigest = digest(root, "policy_digest", "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val policyElement = root.get("policy")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val policy = parseNormalizedPolicy(policyElement, "LINK_REVIEW_POLICY_PREVIEW_INVALID")
        val expiresAt = timestamp(root, "maximum_proof_expires_at", "LINK_REVIEW_POLICY_PREVIEW_INVALID")

        if (linkId != currentScope.linkId || side != currentScope.mySide || ownerId != currentScope.authenticatedOwnerId ||
            contractDigest != currentScope.contractDigest || linkVersion != currentScope.linkVersion) {
            invalid("LINK_REVIEW_POLICY_SCOPE_MISMATCH")
        }
        if (expectedPolicyVersion != currentStatus.policyVersion ||
            expectedPolicyVersion >= MAX_SAFE_INTEGER || policyVersion != expectedPolicyVersion + 1L) {
            invalid("LINK_REVIEW_POLICY_HEAD_MISMATCH")
        }
        if (expiresAt != currentScope.linkExpiresAt || !expiresAt.isAfter(now)) {
            invalid("LINK_REVIEW_POLICY_PROOF_EXPIRY_MISMATCH")
        }

        val reviewed = validateReviewedPolicy(reviewedPolicy)
        if (policy != reviewed) invalid("LINK_REVIEW_POLICY_REVIEWED_INPUT_MISMATCH")
        validateReviewerAuthority(policy, currentScope)

        val canonicalPolicyJson = encodeGoPolicy(policy)
        if (sha256(canonicalPolicyJson.toByteArray(StandardCharsets.UTF_8)) != policyDigest) {
            invalid("LINK_REVIEW_POLICY_DIGEST_MISMATCH")
        }

        return LinkReviewPolicyConsentPreview(
            linkId = linkId,
            side = side,
            ownerId = ownerId,
            contractDigest = contractDigest,
            linkVersion = linkVersion,
            expectedPolicyVersion = expectedPolicyVersion,
            policyVersion = policyVersion,
            policyDigest = policyDigest,
            policy = policy,
            maximumProofExpiresAt = expiresAt,
            canonicalPolicyJson = canonicalPolicyJson,
            rawPreview = rawPreview,
        )
    }

    /** Computes the exact no-domain-prefix SHA-256 used by Go's normalized policy DTO. */
    fun policyDigest(policy: LinkReviewPolicyConsentPolicy): String =
        sha256(encodeGoPolicy(validateReviewedPolicy(policy)).toByteArray(StandardCharsets.UTF_8))

    /**
     * Verifies this Client's exact Owner proof with a locally trusted Owner key. The preview never
     * supplies the key or key ID. This proves only the local Owner's side; status.accepted_sides is
     * not accepted here as evidence of the peer Owner's signature.
     */
    fun buildGrantRequest(
        preview: LinkReviewPolicyConsentPreview,
        currentScope: LinkReviewPolicyCurrentScope,
        rawCurrentStatus: ByteArray,
        trustedOwnerKey: LinkReviewPolicyTrustedOwnerKey,
        proofJson: ByteArray,
        now: Instant,
    ): LinkReviewPolicyConsentGrantRequest {
        val refreshedPreview = validatePreview(
            rawPreview = preview.rawPreviewCopy(),
            reviewedPolicy = preview.policy,
            rawCurrentStatus = rawCurrentStatus,
            currentScope = currentScope,
            now = now,
        )
        if (!samePreview(preview, refreshedPreview)) invalid("LINK_REVIEW_POLICY_PREVIEW_STALE")

        validateTrustedOwnerKey(refreshedPreview, trustedOwnerKey)
        if (proofJson.isEmpty() || proofJson.size > MAX_PROOF_BYTES) {
            invalid("LINK_REVIEW_POLICY_PROOF_INVALID")
        }
        val expected = OwnerLinkReviewPolicyV1Verifier.ExpectedAuthority(
            ownerId = refreshedPreview.ownerId,
            linkId = refreshedPreview.linkId,
            contractDigest = refreshedPreview.contractDigest,
            policyDigest = refreshedPreview.policyDigest,
            expectedLinkVersion = refreshedPreview.linkVersion,
            policyVersion = refreshedPreview.policyVersion,
            side = refreshedPreview.side,
        )
        val verified = try {
            OwnerLinkReviewPolicyV1Verifier.verify(proofJson, trustedOwnerKey.publicIdentity, expected, now)
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_PROOF_INVALID")
        }
        if (verified.expiresAt.isAfter(refreshedPreview.maximumProofExpiresAt)) {
            invalid("LINK_REVIEW_POLICY_PROOF_EXPIRY_MISMATCH")
        }
        return LinkReviewPolicyConsentGrantRequest(
            linkId = refreshedPreview.linkId,
            ownerKeyId = trustedOwnerKey.ownerKeyId,
            expectedPolicyVersion = refreshedPreview.expectedPolicyVersion,
            policy = refreshedPreview.policy,
            signedProofBase64 = Base64.getEncoder().encodeToString(proofJson),
            policyJson = refreshedPreview.canonicalPolicyJson,
        )
    }

    private fun validateCurrentScope(scope: LinkReviewPolicyCurrentScope, now: Instant) {
        if (!canonicalProofToken(scope.linkId) || !canonicalProofToken(scope.authenticatedOwnerId) ||
            scope.mySide !in setOf("SOURCE", "TARGET") || !sha256Pattern.matches(scope.contractDigest) ||
            scope.linkVersion !in 1L..MAX_SAFE_INTEGER || !scope.linkExpiresAt.isAfter(now)) {
            invalid("LINK_REVIEW_POLICY_CURRENT_SCOPE_INVALID")
        }
        listOf(scope.sourceEndpointId, scope.sourceGroupId, scope.targetEndpointId, scope.targetGroupId)
            .forEach { policyIdentifier(it, "LINK_REVIEW_POLICY_CURRENT_SCOPE_INVALID") }
        for (authority in scope.reviewerAuthorities) {
            policyIdentifier(authority.endpointId, "LINK_REVIEW_POLICY_CURRENT_SCOPE_INVALID")
            policyIdentifier(authority.groupId, "LINK_REVIEW_POLICY_CURRENT_SCOPE_INVALID")
        }
    }

    private fun validateTrustedOwnerKey(
        preview: LinkReviewPolicyConsentPreview,
        trustedOwnerKey: LinkReviewPolicyTrustedOwnerKey,
    ) {
        if (trustedOwnerKey.ownerId != preview.ownerId || !canonicalProofToken(trustedOwnerKey.ownerId) ||
            !canonicalProofToken(trustedOwnerKey.ownerKeyId) ||
            trustedOwnerKey.ownerKeyId != trustedOwnerKey.publicIdentity.id) {
            invalid("LINK_REVIEW_POLICY_OWNER_KEY_SCOPE_MISMATCH")
        }
        if (trustedOwnerKey.state != "ACTIVE") invalid("LINK_REVIEW_POLICY_OWNER_KEY_REVOKED")
        if (trustedOwnerKey.version !in 1L..MAX_SAFE_INTEGER) {
            invalid("LINK_REVIEW_POLICY_OWNER_KEY_VERSION_INVALID")
        }
        try {
            trustedOwnerKey.publicIdentity.validate()
        } catch (_: Exception) {
            invalid("LINK_REVIEW_POLICY_OWNER_KEY_INVALID")
        }
    }

    private fun validateReviewerAuthority(
        policy: LinkReviewPolicyConsentPolicy,
        scope: LinkReviewPolicyCurrentScope,
    ) {
        if (policy.mode == "NONE") return
        val linkGroups = setOf(scope.sourceGroupId, scope.targetGroupId)
        val linkEndpoints = setOf(scope.sourceEndpointId, scope.targetEndpointId)
        val currentAuthorities = scope.reviewerAuthorities
        for (reviewer in policy.reviewers) {
            val authority = LinkReviewPolicyCurrentReviewerAuthority(reviewer.endpointId, reviewer.groupId)
            if (reviewer.groupId !in linkGroups || reviewer.endpointId in linkEndpoints || authority !in currentAuthorities) {
                invalid("LINK_REVIEW_POLICY_REVIEWER_AUTHORITY_MISSING")
            }
        }
    }

    private fun validateReviewedPolicy(value: LinkReviewPolicyConsentPolicy): LinkReviewPolicyConsentPolicy {
        if (value.mode !in setOf("NONE", "METADATA") || value.reviewers.size > MAX_POLICY_REVIEWERS) {
            invalid("LINK_REVIEW_POLICY_INVALID")
        }
        value.reviewers.forEach {
            policyIdentifier(it.endpointId, "LINK_REVIEW_POLICY_INVALID")
            policyIdentifier(it.groupId, "LINK_REVIEW_POLICY_INVALID")
        }
        val sorted = value.reviewers.sortedWith { left, right ->
            val endpointOrder = compareUtf8(left.endpointId, right.endpointId)
            if (endpointOrder != 0) endpointOrder else compareUtf8(left.groupId, right.groupId)
        }
        if (value.reviewers != sorted || value.reviewers.map { it.endpointId }.distinct().size != value.reviewers.size) {
            invalid("LINK_REVIEW_POLICY_INVALID")
        }
        if (value.mode == "NONE") {
            if (value.reviewers.isNotEmpty() || value.maxFailovers != 0 || value.reviewerLeaseSeconds != 0 ||
                value.maxReviewAgeSeconds != 0) invalid("LINK_REVIEW_POLICY_INVALID")
        } else if (value.reviewers.isEmpty() || value.maxFailovers !in 0..minOf(8, value.reviewers.size - 1) ||
            value.reviewerLeaseSeconds !in 30..3600 || value.maxReviewAgeSeconds !in 60..86400) {
            invalid("LINK_REVIEW_POLICY_INVALID")
        }
        return value.copy(reviewers = Collections.unmodifiableList(value.reviewers.toList()))
    }

    private fun parseNormalizedPolicy(value: JsonObject, code: String): LinkReviewPolicyConsentPolicy {
        exactFields(value, policyFields, code)
        val mode = string(value, "mode", code)
        if (mode !in setOf("NONE", "METADATA")) invalid(code)
        val reviewersElement = value.get("reviewers")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid(code)
        if (reviewersElement.size() > MAX_POLICY_REVIEWERS) invalid(code)
        val reviewers = reviewersElement.map { element ->
            val reviewer = element.takeIf { it.isJsonObject }?.asJsonObject ?: invalid(code)
            exactFields(reviewer, reviewerFields, code)
            LinkReviewPolicyConsentReviewer(
                endpointId = policyIdentifier(string(reviewer, "endpoint_id", code), code),
                groupId = policyIdentifier(string(reviewer, "group_id", code), code),
            )
        }
        val result = LinkReviewPolicyConsentPolicy(
            mode = mode,
            reviewers = reviewers,
            maxFailovers = integer(value, "max_failovers", 0L, 8L, code).toInt(),
            reviewerLeaseSeconds = integer(value, "reviewer_lease_seconds", 0L, 3600L, code).toInt(),
            maxReviewAgeSeconds = integer(value, "max_review_age_seconds", 0L, 86400L, code).toInt(),
        )
        return try {
            validateReviewedPolicy(result)
        } catch (_: LinkReviewPolicyConsentValidationException) {
            invalid(code)
        }
    }

    /** Mirrors normalizeCommunicationLinkReviewPolicy + Go encoding/json struct field order. */
    private fun encodeGoPolicy(value: LinkReviewPolicyConsentPolicy): String {
        val json = ClientWireCrypto.json { writer ->
            writer.beginObject()
                .name("mode").value(value.mode)
                .name("reviewers").beginArray()
            for (reviewer in value.reviewers) {
                writer.beginObject()
                    .name("endpoint_id").value(reviewer.endpointId)
                    .name("group_id").value(reviewer.groupId)
                    .endObject()
            }
            writer.endArray()
                .name("max_failovers").value(value.maxFailovers)
                .name("reviewer_lease_seconds").value(value.reviewerLeaseSeconds)
                .name("max_review_age_seconds").value(value.maxReviewAgeSeconds)
                .endObject()
        }
        // Go encoding/json's default HTML-safe escaping does not escape '=' or apostrophe.
        return json.replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
    }

    private fun parseUniqueObject(raw: ByteArray, code: String): JsonObject {
        if (raw.isEmpty() || raw.size > MAX_RAW_JSON_BYTES) invalid(code)
        try {
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
            val reader = JsonReader(StringReader(text))
            reader.isLenient = false
            val value = readJsonValue(reader, code, 0)
            if (!value.isJsonObject || reader.peek() != JsonToken.END_DOCUMENT) invalid(code)
            return value.asJsonObject
        } catch (_: LinkReviewPolicyConsentValidationException) {
            throw LinkReviewPolicyConsentValidationException(code)
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

    private fun samePreview(
        cached: LinkReviewPolicyConsentPreview,
        refreshed: LinkReviewPolicyConsentPreview,
    ): Boolean = cached.linkId == refreshed.linkId && cached.side == refreshed.side &&
        cached.ownerId == refreshed.ownerId && cached.contractDigest == refreshed.contractDigest &&
        cached.linkVersion == refreshed.linkVersion && cached.expectedPolicyVersion == refreshed.expectedPolicyVersion &&
        cached.policyVersion == refreshed.policyVersion && cached.policyDigest == refreshed.policyDigest &&
        cached.policy == refreshed.policy && cached.maximumProofExpiresAt == refreshed.maximumProofExpiresAt &&
        cached.canonicalPolicyJson == refreshed.canonicalPolicyJson

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

    private fun exactFields(value: JsonObject, expected: Set<String>, code: String) {
        if (value.keySet() != expected) invalid(code)
    }

    private fun string(value: JsonObject, name: String, code: String): String =
        value.get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?: invalid(code)

    private fun token(value: JsonObject, name: String, code: String): String =
        string(value, name, code).also { if (!canonicalProofToken(it)) invalid(code) }

    private fun digest(value: JsonObject, name: String, code: String): String =
        string(value, name, code).also { if (!sha256Pattern.matches(it)) invalid(code) }

    private fun integer(value: JsonObject, name: String, minimum: Long, maximum: Long, code: String): Long {
        val primitive = value.get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }?.asJsonPrimitive
            ?: invalid(code)
        val text = primitive.asString
        if (!text.matches(Regex("^(0|[1-9][0-9]*)$"))) invalid(code)
        val parsed = text.toLongOrNull() ?: invalid(code)
        if (parsed !in minimum..maximum) invalid(code)
        return parsed
    }

    private fun timestamp(value: JsonObject, name: String, code: String): Instant {
        val text = string(value, name, code)
        if (text.length > 40) invalid(code)
        return try {
            OffsetDateTime.parse(text).toInstant()
        } catch (_: Exception) {
            invalid(code)
        }
    }

    private fun policyIdentifier(value: String, code: String): String {
        val byteLength = value.toByteArray(StandardCharsets.UTF_8).size
        if (value.isEmpty() || byteLength > MAX_ID_BYTES || value != value.trim() || !isWellFormedUtf16(value)) {
            invalid(code)
        }
        return value
    }

    private fun canonicalProofToken(value: String): Boolean {
        if (value.isEmpty() || value.toByteArray(StandardCharsets.UTF_8).size > MAX_ID_BYTES || !isWellFormedUtf16(value)) {
            return false
        }
        var offset = 0
        while (offset < value.length) {
            val point = value.codePointAt(offset)
            if (Character.isWhitespace(point) || Character.isSpaceChar(point) || Character.isISOControl(point) ||
                point == '/'.code || point == '\\'.code) return false
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

    private fun compareUtf8(left: String, right: String): Int {
        val leftBytes = left.toByteArray(StandardCharsets.UTF_8)
        val rightBytes = right.toByteArray(StandardCharsets.UTF_8)
        val common = minOf(leftBytes.size, rightBytes.size)
        for (index in 0 until common) {
            val a = leftBytes[index].toInt() and 0xff
            val b = rightBytes[index].toInt() and 0xff
            if (a != b) return a - b
        }
        return leftBytes.size - rightBytes.size
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun invalid(code: String): Nothing = throw LinkReviewPolicyConsentValidationException(code)
}

internal class LinkReviewPolicyConsentValidationException(val code: String) : IllegalArgumentException(code)
