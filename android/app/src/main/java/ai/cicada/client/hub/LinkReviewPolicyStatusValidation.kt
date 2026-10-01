package ai.cicada.client.hub

import com.google.gson.JsonObject
import java.time.OffsetDateTime

/** Minimal public metadata captured from the authenticated, owner-scoped link.list projection. */
internal data class LinkReviewPolicySelection(
    val linkId: String,
    val linkVersion: Long,
    val mySide: String,
)

internal data class LinkReviewPolicyListPage(
    val links: List<LinkReviewPolicySelection>,
    val cursor: String,
    val hasMore: Boolean,
)

/** Validated wire DTO. This is metadata only; it carries no decision or routing authority. */
internal data class LinkReviewPolicyStatusDto(
    val linkId: String,
    val linkVersion: Long,
    val policyVersion: Long,
    val policyDigest: String,
    val mode: String,
    val reviewerCount: Int,
    val maxFailovers: Int,
    val reviewerLeaseSeconds: Int,
    val maxReviewAgeSeconds: Int,
    val current: Boolean,
    val acceptedSides: List<String>,
    val expiresAt: String?,
)

/** Strict, bounded parsers for the v1.6.1 Link list selection and policy status DTOs. */
internal object LinkReviewPolicyStatusValidation {
    private const val MAX_ID_LENGTH = 256
    private const val MAX_CURSOR_LENGTH = 4096
    private const val MAX_LINKS_PER_PAGE = 100
    private const val MAX_ACTIONS = 32
    private const val MAX_DATA_SCOPES = 32
    private const val MAX_POLICY_REVIEWERS = 8
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L

    private val listResultFields = setOf("links", "cursor", "has_more")
    private val viewFields = setOf("link", "my_side")
    private val linkRequiredFields = setOf(
        "link_id", "source_endpoint_id", "source_group_id", "target_endpoint_id", "target_group_id",
        "direction", "actions", "data_scopes", "expires_at", "state", "version",
    )
    private val statusRequiredFields = setOf(
        "link_id", "link_version", "policy_version", "policy_digest", "policy", "current", "accepted_sides",
    )
    private val policyFields = setOf(
        "mode", "reviewers", "max_failovers", "reviewer_lease_seconds", "max_review_age_seconds",
    )

    fun validateLinkId(value: String): String {
        if (!validIdentifier(value)) invalid("LINK_REVIEW_SELECTOR_INVALID")
        return value
    }

    fun validateExpectedLinkVersion(value: Long): Long {
        if (value !in 1L..MAX_SAFE_INTEGER) invalid("LINK_REVIEW_SELECTOR_INVALID")
        return value
    }

    fun parseLinkListPage(value: JsonObject): LinkReviewPolicyListPage {
        requireExactFields(value, listResultFields, listResultFields, "LINK_REVIEW_LIST_INVALID")
        val links = value.get("links")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_LIST_INVALID")
        if (links.size() > MAX_LINKS_PER_PAGE) invalid("LINK_REVIEW_LIST_INVALID")
        val cursor = value.get("cursor")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?: invalid("LINK_REVIEW_LIST_INVALID")
        val hasMore = value.get("has_more")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            ?: invalid("LINK_REVIEW_LIST_INVALID")
        if (cursor.length > MAX_CURSOR_LENGTH || (hasMore && cursor.isBlank()) || (!hasMore && cursor.isNotEmpty())) {
            invalid("LINK_REVIEW_LIST_INVALID")
        }

        val selections = ArrayList<LinkReviewPolicySelection>(links.size())
        val seenIds = HashSet<String>()
        for (item in links) {
            val view = item.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_LIST_INVALID")
            requireExactFields(view, viewFields, viewFields, "LINK_REVIEW_LIST_INVALID")
            val link = view.get("link")?.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_LIST_INVALID")
            requireExactFields(link, linkRequiredFields, linkRequiredFields + "transport_hub_id", "LINK_REVIEW_LIST_INVALID")
            validateLinkProjection(link)
            val linkId = string(link, "link_id", MAX_ID_LENGTH, "LINK_REVIEW_LIST_INVALID")
            val version = integer(link, "version", 1L, MAX_SAFE_INTEGER, "LINK_REVIEW_LIST_INVALID")
            val side = string(view, "my_side", 16, "LINK_REVIEW_LIST_INVALID")
            if (side !in setOf("SOURCE", "TARGET") || !seenIds.add(linkId)) invalid("LINK_REVIEW_LIST_INVALID")
            selections += LinkReviewPolicySelection(linkId, version, side)
        }
        return LinkReviewPolicyListPage(selections, cursor, hasMore)
    }

    fun validateStatus(
        value: JsonObject,
        expectedLinkId: String,
        expectedLinkVersion: Long,
    ): LinkReviewPolicyStatusDto {
        validateLinkId(expectedLinkId)
        validateExpectedLinkVersion(expectedLinkVersion)
        requireExactFields(value, statusRequiredFields, statusRequiredFields + "expires_at", "LINK_REVIEW_STATUS_INVALID")
        val linkId = string(value, "link_id", MAX_ID_LENGTH, "LINK_REVIEW_STATUS_INVALID")
        val linkVersion = integer(value, "link_version", 1L, MAX_SAFE_INTEGER, "LINK_REVIEW_STATUS_INVALID")
        if (linkId != expectedLinkId || linkVersion != expectedLinkVersion) invalid("LINK_REVIEW_STATUS_SCOPE_MISMATCH")
        val policyVersion = integer(value, "policy_version", 0L, MAX_SAFE_INTEGER, "LINK_REVIEW_STATUS_INVALID")
        val digest = string(value, "policy_digest", 64, "LINK_REVIEW_STATUS_INVALID", allowEmpty = true)
        val policy = value.get("policy")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("LINK_REVIEW_STATUS_INVALID")
        requireExactFields(policy, policyFields, policyFields, "LINK_REVIEW_STATUS_INVALID")
        val mode = string(policy, "mode", 16, "LINK_REVIEW_STATUS_INVALID")
        if (mode !in setOf("NONE", "METADATA")) invalid("LINK_REVIEW_STATUS_INVALID")
        val reviewers = policy.get("reviewers")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_STATUS_INVALID")
        if (reviewers.size() > MAX_POLICY_REVIEWERS) invalid("LINK_REVIEW_STATUS_INVALID")
        val reviewerEndpointIds = HashSet<String>()
        for (item in reviewers) {
            val reviewer = item.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("LINK_REVIEW_STATUS_INVALID")
            requireExactFields(reviewer, setOf("endpoint_id", "group_id"), setOf("endpoint_id", "group_id"), "LINK_REVIEW_STATUS_INVALID")
            val endpointId = string(reviewer, "endpoint_id", MAX_ID_LENGTH, "LINK_REVIEW_STATUS_INVALID")
            val groupId = string(reviewer, "group_id", MAX_ID_LENGTH, "LINK_REVIEW_STATUS_INVALID")
            if (!reviewerEndpointIds.add(endpointId)) invalid("LINK_REVIEW_STATUS_INVALID")
        }
        val maxFailovers = integer(policy, "max_failovers", 0L, 8L, "LINK_REVIEW_STATUS_INVALID").toInt()
        val leaseSeconds = integer(policy, "reviewer_lease_seconds", 0L, 3600L, "LINK_REVIEW_STATUS_INVALID").toInt()
        val maxAgeSeconds = integer(policy, "max_review_age_seconds", 0L, 86400L, "LINK_REVIEW_STATUS_INVALID").toInt()
        if (mode == "NONE" && (reviewers.size() != 0 || maxFailovers != 0 || leaseSeconds != 0 || maxAgeSeconds != 0)) {
            invalid("LINK_REVIEW_STATUS_INVALID")
        }
        if (mode == "METADATA" && (reviewers.size() == 0 || maxFailovers > reviewers.size() - 1 ||
                leaseSeconds !in 30..3600 || maxAgeSeconds !in 60..86400)) invalid("LINK_REVIEW_STATUS_INVALID")

        val current = value.get("current")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean
            ?: invalid("LINK_REVIEW_STATUS_INVALID")
        val rawSides = value.get("accepted_sides")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_STATUS_INVALID")
        if (rawSides.size() > 2) invalid("LINK_REVIEW_STATUS_INVALID")
        val acceptedSides = rawSides.map { item ->
            val side = item.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: invalid("LINK_REVIEW_STATUS_INVALID")
            if (side !in setOf("SOURCE", "TARGET")) invalid("LINK_REVIEW_STATUS_INVALID")
            side
        }
        if (acceptedSides.distinct().size != acceptedSides.size) invalid("LINK_REVIEW_STATUS_INVALID")

        val expiresAt = if (value.has("expires_at")) {
            val expiry = string(value, "expires_at", 40, "LINK_REVIEW_STATUS_INVALID")
            if (!isTimestamp(expiry)) invalid("LINK_REVIEW_STATUS_INVALID")
            expiry
        } else null

        if (policyVersion == 0L) {
            if (digest.isNotEmpty() || mode != "NONE" || reviewers.size() != 0 || maxFailovers != 0 ||
                leaseSeconds != 0 || maxAgeSeconds != 0 || !current || acceptedSides.isNotEmpty() || expiresAt != null) {
                invalid("LINK_REVIEW_STATUS_INVALID")
            }
        } else if (!digest.matches(Regex("^[0-9a-f]{64}$"))) {
            invalid("LINK_REVIEW_STATUS_INVALID")
        }

        return LinkReviewPolicyStatusDto(
            linkId, linkVersion, policyVersion, digest, mode, reviewers.size(), maxFailovers,
            leaseSeconds, maxAgeSeconds, current, acceptedSides, expiresAt,
        )
    }

    private fun validateLinkProjection(link: JsonObject) {
        for (field in listOf("link_id", "source_endpoint_id", "source_group_id", "target_endpoint_id", "target_group_id")) {
            string(link, field, MAX_ID_LENGTH, "LINK_REVIEW_LIST_INVALID")
        }
        val direction = string(link, "direction", 32, "LINK_REVIEW_LIST_INVALID")
        if (direction !in setOf("forward", "bidirectional")) invalid("LINK_REVIEW_LIST_INVALID")
        boundedStringArray(link, "actions", MAX_ACTIONS)
        boundedStringArray(link, "data_scopes", MAX_DATA_SCOPES)
        val expiry = string(link, "expires_at", 40, "LINK_REVIEW_LIST_INVALID")
        if (!isTimestamp(expiry)) invalid("LINK_REVIEW_LIST_INVALID")
        string(link, "state", 32, "LINK_REVIEW_LIST_INVALID")
        integer(link, "version", 1L, MAX_SAFE_INTEGER, "LINK_REVIEW_LIST_INVALID")
        if (link.has("transport_hub_id")) string(link, "transport_hub_id", MAX_ID_LENGTH, "LINK_REVIEW_LIST_INVALID")
    }

    private fun boundedStringArray(parent: JsonObject, field: String, maximum: Int) {
        val values = parent.get(field)?.takeIf { it.isJsonArray }?.asJsonArray
            ?: invalid("LINK_REVIEW_LIST_INVALID")
        if (values.size() > maximum) invalid("LINK_REVIEW_LIST_INVALID")
        val seen = HashSet<String>()
        for (value in values) {
            val text = value.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                ?: invalid("LINK_REVIEW_LIST_INVALID")
            if (!validIdentifier(text) || !seen.add(text)) invalid("LINK_REVIEW_LIST_INVALID")
        }
    }

    private fun requireExactFields(value: JsonObject, required: Set<String>, allowed: Set<String>, code: String) {
        if (!value.keySet().containsAll(required) || value.keySet().any { it !in allowed }) invalid(code)
    }

    private fun string(
        value: JsonObject,
        key: String,
        maxLength: Int,
        code: String,
        allowEmpty: Boolean = false,
    ): String {
        val text = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
            ?: invalid(code)
        if (text.length > maxLength || (allowEmpty && text.trim() != text) || (!allowEmpty && !validIdentifier(text))) invalid(code)
        return text
    }

    private fun integer(value: JsonObject, key: String, min: Long, max: Long, code: String): Long {
        val element = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: invalid(code)
        val text = element.asString
        if (!text.matches(Regex("^(0|[1-9][0-9]*)$"))) invalid(code)
        val number = text.toLongOrNull() ?: invalid(code)
        if (number !in min..max) invalid(code)
        return number
    }

    private fun validIdentifier(value: String): Boolean = value.isNotBlank() && value.length <= MAX_ID_LENGTH &&
        value == value.trim() && value.none { it.isISOControl() }

    private fun isTimestamp(value: String): Boolean = try {
        value.length <= 40 && OffsetDateTime.parse(value).offset.totalSeconds in -64800..64800
    } catch (_: Exception) {
        false
    }

    private fun invalid(code: String): Nothing = throw LinkReviewPolicyStatusValidationException(code)
}

internal class LinkReviewPolicyStatusValidationException(val code: String) : IllegalArgumentException(code)
