package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Pure candidate DTO/guard tests; no Android context, Hub, key, or transport is used. */
class GroupDirectoryPermissionValidationTest {
    @Test
    fun earlyGuardBlocksCandidateAndMalformedBypassButLeavesLegacyActionsAvailable() {
        assertGuarded(JsonObject().apply {
            addProperty("kind", GroupDirectoryPermissionValidation.ACTION_KIND)
        })
        assertGuarded(JsonObject().apply {
            addProperty("kind", "group.create")
            add("set_directory_permission", JsonNull.INSTANCE)
        })
        GroupDirectoryPermissionValidation.guardGenericRpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply {
                add("nested", JsonObject().apply { add("set_directory_permission", JsonNull.INSTANCE) })
            })
        })

        GroupDirectoryPermissionValidation.guardGenericRpc("topology.apply", JsonObject().apply {
            addProperty("kind", "group.create")
            add("create_group", JsonObject().apply { addProperty("name", "Example") })
        })
        GroupDirectoryPermissionValidation.guardGenericRpc("topology.apply", JsonObject().apply {
            addProperty("kind", "membership.set_broadcast_permission")
            add("set_broadcast_permission", JsonObject())
        })
        GroupDirectoryPermissionValidation.guardGenericRpc("topology.snapshot", JsonObject().apply {
            addProperty("kind", GroupDirectoryPermissionValidation.ACTION_KIND)
        })
    }

    @Test
    fun parsesOnlyExactActionWithRequiredBooleanAndSafePositiveCasVersion() {
        val parsed = GroupDirectoryPermissionValidation.parseAction(action(enabled = false))
        assertEquals("group-1", parsed.groupId)
        assertEquals("membership-1", parsed.membershipId)
        assertFalse(parsed.enabled)
        assertEquals(7L, parsed.expectedMembershipVersion)

        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply { remove("set_directory_permission") })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").add("enabled", JsonNull.INSTANCE)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").remove("enabled")
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("enabled", "true")
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("expected_membership_version", true)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("expected_membership_version", 7.5)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("expected_membership_version", 0)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("expected_membership_version", 9_007_199_254_740_992L)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply {
                getAsJsonObject("set_directory_permission").addProperty("owner_approved", true)
            })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply { add("bind_role", JsonObject()) })
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.parseAction(action().apply { addProperty("kind", "group.create") })
        }
    }

    @Test
    fun snapshotScopesMembershipToOwnerAndGroupAndIncludesAllMatchingPrincipalEndpoints() {
        val parsedAction = GroupDirectoryPermissionValidation.parseAction(action())
        val preview = GroupDirectoryPermissionValidation.validateSnapshotMember(snapshot(), "owner-1", parsedAction)
        assertEquals("principal-1", preview.principalId)
        assertEquals("group-1", preview.groupId)
        assertEquals(7L, preview.membershipVersion)
        // Endpoint binding epochs are distinct counters; they do not replace the Membership CAS version.
        assertEquals(listOf("endpoint-1", "endpoint-2"), preview.endpointIds)

        expectInvalid {
            GroupDirectoryPermissionValidation.validateSnapshotMember(snapshot(), "other-owner", parsedAction)
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateSnapshotMember(
                snapshot(), "owner-1", parsedAction.copy(expectedMembershipVersion = 99L),
            )
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateSnapshotMember(
                snapshot(), "owner-1", parsedAction.copy(membershipId = "different-membership"),
            )
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateSnapshotMember(snapshot().apply {
                getAsJsonArray("memberships").add(membership(id = "duplicate-membership", groupId = "group-1"))
            }, "owner-1", parsedAction)
        }
    }

    @Test
    fun validatesChangedMembershipResultAndExactVersionAdvance() {
        val parsedAction = GroupDirectoryPermissionValidation.parseAction(action(enabled = false))
        val preview = GroupDirectoryPermissionValidation.validateSnapshotMember(snapshot(), "owner-1", parsedAction)
        val validated = GroupDirectoryPermissionValidation.validateResult(result(version = 8L, enabled = false), parsedAction, preview)
        assertEquals(GroupDirectoryPermissionValidation.ACTION_KIND, validated.action)
        assertTrue(validated.changed)
        assertEquals(8L, validated.membershipVersion)
        assertFalse(validated.directoryPermissionEnabled)

        expectInvalid {
            GroupDirectoryPermissionValidation.validateResult(result(version = 7L, enabled = false), parsedAction, preview)
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateResult(result(version = 8L, enabled = true), parsedAction, preview)
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateResult(result(version = 8L, enabled = false, changed = false), parsedAction, preview)
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateResult(result(version = 8L, enabled = false).apply {
                getAsJsonObject("membership").addProperty("group_id", "foreign-group")
            }, parsedAction, preview)
        }
        expectInvalid {
            GroupDirectoryPermissionValidation.validateResult(result(version = 8L, enabled = false).apply {
                addProperty("owner_approved", true)
            }, parsedAction, preview)
        }
    }

    private fun assertGuarded(body: JsonObject) {
        try {
            GroupDirectoryPermissionValidation.guardGenericRpc("topology.apply", body)
            fail("Expected GROUP_DIRECTORY_PERMISSION_NOT_READY")
        } catch (error: HubSessionException) {
            assertEquals("GROUP_DIRECTORY_PERMISSION_NOT_READY", error.errorCode)
        }
    }

    private fun expectInvalid(block: () -> Unit) {
        try {
            block()
            fail("Expected candidate DTO rejection")
        } catch (_: GroupDirectoryPermissionValidationException) {
            // Expected strict candidate rejection.
        }
    }

    private fun action(enabled: Boolean = true): JsonObject = JsonObject().apply {
        addProperty("kind", GroupDirectoryPermissionValidation.ACTION_KIND)
        add("set_directory_permission", JsonObject().apply {
            addProperty("group_id", "group-1")
            addProperty("membership_id", "membership-1")
            addProperty("enabled", enabled)
            addProperty("expected_membership_version", 7)
        })
    }

    private fun snapshot(): JsonObject = JsonObject().apply {
        addProperty("contract_version", 2)
        addProperty("owner_principal_id", "owner-1")
        addProperty("captured_at", "2030-01-01T00:00:00Z")
        addProperty("read_consistency", "best_effort")
        addProperty("networks_truncated", false)
        addProperty("network_endpoints_truncated", false)
        add("networks", JsonArray())
        add("groups", JsonArray().apply {
            add(group("group-1"))
            add(group("group-2"))
        })
        add("memberships", JsonArray().apply {
            add(membership())
            add(membership(id = "membership-2", groupId = "group-2"))
        })
        add("endpoints", JsonArray().apply {
            add(endpoint("endpoint-1", "principal-1", listOf("group-1"), 51L))
            add(endpoint("endpoint-2", "principal-1", listOf("group-1", "group-2"), 52L))
            add(endpoint("endpoint-other-principal", "principal-2", listOf("group-1"), 53L))
        })
        add("links", JsonArray())
    }

    private fun group(id: String): JsonObject = JsonObject().apply {
        addProperty("group_id", id)
        addProperty("network_id", "network-1")
        addProperty("name", id)
        addProperty("state", "ACTIVE")
        addProperty("context_policy", "group_scoped")
        addProperty("version", 2)
    }

    private fun membership(
        id: String = "membership-1",
        groupId: String = "group-1",
        principalId: String = "principal-1",
        version: Long = 7L,
        directoryEnabled: Boolean = true,
    ): JsonObject = JsonObject().apply {
        addProperty("membership_id", id)
        addProperty("principal_id", principalId)
        addProperty("group_id", groupId)
        addProperty("display_name", "Principal")
        addProperty("role", "member")
        add("roles", JsonArray().apply { add("member") })
        addProperty("broadcast_permission_enabled", false)
        addProperty("directory_permission_enabled", directoryEnabled)
        addProperty("status", "active")
        addProperty("version", version)
    }

    private fun endpoint(id: String, principalId: String, groupIds: List<String>, bindingEpoch: Long): JsonObject = JsonObject().apply {
        addProperty("endpoint_id", id)
        addProperty("name", id)
        addProperty("principal_id", principalId)
        add("group_ids", JsonArray().apply { groupIds.forEach { add(it) } })
        add("network_ids", JsonArray().apply { add("network-1") })
        addProperty("presence", "online")
        addProperty("binding_id", "binding-$id")
        addProperty("binding_epoch", bindingEpoch)
        addProperty("binding_status", "active")
    }

    private fun result(version: Long, enabled: Boolean, changed: Boolean = true): JsonObject = JsonObject().apply {
        addProperty("contract_version", 2)
        addProperty("action", GroupDirectoryPermissionValidation.ACTION_KIND)
        addProperty("changed", changed)
        add("membership", membership(version = version, directoryEnabled = enabled))
    }
}
