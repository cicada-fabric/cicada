package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Pure DTO tests; no Android context, Hub, device key, or network is involved. */
class LinkReviewPolicyStatusValidationTest {
    @Test
    fun acceptsExactUnconfiguredNoneForFreshSelectedLink() {
        val status = LinkReviewPolicyStatusValidation.validateStatus(defaultStatus(), "link-1", 4L)
        assertEquals("link-1", status.linkId)
        assertEquals(4L, status.linkVersion)
        assertEquals(0L, status.policyVersion)
        assertEquals("", status.policyDigest)
        assertEquals("NONE", status.mode)
        assertTrue(status.current)
        assertTrue(status.acceptedSides.isEmpty())
        assertEquals(null, status.expiresAt)
    }

    @Test
    fun rejectsStatusBoundToDifferentLinkOrStaleLinkVersion() {
        expectCode("LINK_REVIEW_STATUS_SCOPE_MISMATCH") {
            LinkReviewPolicyStatusValidation.validateStatus(defaultStatus(), "other-link", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_SCOPE_MISMATCH") {
            LinkReviewPolicyStatusValidation.validateStatus(defaultStatus(version = 5L), "link-1", 4L)
        }
        expectCode("LINK_REVIEW_SELECTOR_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(defaultStatus(), "link-1", 9_007_199_254_740_992L)
        }
    }

    @Test
    fun acceptsBoundedMetadataPolicyAndBothAcceptedSides() {
        val status = LinkReviewPolicyStatusValidation.validateStatus(metadataStatus(), "link-1", 4L)
        assertEquals(3L, status.policyVersion)
        assertEquals("METADATA", status.mode)
        assertEquals(2, status.reviewerCount)
        assertEquals(listOf("SOURCE", "TARGET"), status.acceptedSides)
        assertTrue(status.current)
        assertEquals("2030-01-01T00:00:00Z", status.expiresAt)
    }

    @Test
    fun rejectsMalformedDefaultsUnknownFieldsDuplicatesAndUnsupportedPolicyValues() {
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(defaultStatus().apply { addProperty("unexpected", true) }, "link-1", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(defaultStatus().apply {
                getAsJsonArray("accepted_sides").add("SOURCE")
            }, "link-1", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(metadataStatus().apply {
                val reviewers = getAsJsonObject("policy").getAsJsonArray("reviewers")
                reviewers.add(reviewers[0].deepCopy().asJsonObject.apply { addProperty("group_id", "different-group") })
            }, "link-1", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(metadataStatus().apply {
                getAsJsonObject("policy").addProperty("max_failovers", 2)
            }, "link-1", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(metadataStatus().apply {
                getAsJsonObject("policy").addProperty("reviewer_lease_seconds", 29)
            }, "link-1", 4L)
        }
        expectCode("LINK_REVIEW_STATUS_INVALID") {
            LinkReviewPolicyStatusValidation.validateStatus(metadataStatus().apply { addProperty("policy_digest", "ABCDEF") }, "link-1", 4L)
        }
    }

    @Test
    fun parsesOnlyBoundedAuthenticatedListProjectionAndOwnerSide() {
        val page = LinkReviewPolicyStatusValidation.parseLinkListPage(JsonObject().apply {
            add("links", JsonArray().apply {
                add(JsonObject().apply {
                    add("link", linkProjection())
                    addProperty("my_side", "TARGET")
                })
            })
            addProperty("cursor", "")
            addProperty("has_more", false)
        })
        assertEquals(1, page.links.size)
        assertEquals("link-1", page.links.single().linkId)
        assertEquals(4L, page.links.single().linkVersion)
        assertEquals("TARGET", page.links.single().mySide)
        assertFalse(page.hasMore)

        expectCode("LINK_REVIEW_LIST_INVALID") {
            LinkReviewPolicyStatusValidation.parseLinkListPage(JsonObject().apply {
                add("links", JsonArray().apply {
                    add(JsonObject().apply { add("link", linkProjection()); addProperty("my_side", "OWNER") })
                })
                addProperty("cursor", "")
                addProperty("has_more", false)
            })
        }
    }

    private fun defaultStatus(version: Long = 4L): JsonObject = JsonObject().apply {
        addProperty("link_id", "link-1")
        addProperty("link_version", version)
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
        addProperty("link_id", "link-1")
        addProperty("link_version", 4)
        addProperty("policy_version", 3)
        addProperty("policy_digest", "a".repeat(64))
        add("policy", JsonObject().apply {
            addProperty("mode", "METADATA")
            add("reviewers", JsonArray().apply {
                add(JsonObject().apply { addProperty("endpoint_id", "endpoint-1"); addProperty("group_id", "group-1") })
                add(JsonObject().apply { addProperty("endpoint_id", "endpoint-2"); addProperty("group_id", "group-2") })
            })
            addProperty("max_failovers", 1)
            addProperty("reviewer_lease_seconds", 60)
            addProperty("max_review_age_seconds", 600)
        })
        addProperty("current", true)
        add("accepted_sides", JsonArray().apply { add("SOURCE"); add("TARGET") })
        addProperty("expires_at", "2030-01-01T00:00:00Z")
    }

    private fun linkProjection(): JsonObject = JsonObject().apply {
        addProperty("link_id", "link-1")
        addProperty("source_endpoint_id", "source-endpoint")
        addProperty("source_group_id", "source-group")
        addProperty("target_endpoint_id", "target-endpoint")
        addProperty("target_group_id", "target-group")
        addProperty("direction", "forward")
        add("actions", JsonArray().apply { add("ask") })
        add("data_scopes", JsonArray().apply { add("metadata") })
        addProperty("expires_at", "2030-01-01T00:00:00Z")
        addProperty("state", "ACCEPTED")
        addProperty("version", 4)
    }

    private fun expectCode(expected: String, action: () -> Unit) {
        try {
            action()
            fail("Expected $expected")
        } catch (error: LinkReviewPolicyStatusValidationException) {
            assertEquals(expected, error.code)
        }
    }
}
