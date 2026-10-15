package ai.cicada.client.hub

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import java.math.BigInteger

/** Candidate-only DTO checks for the not-yet-shipped Group directory permission action. */
internal object GroupDirectoryPermissionValidation {
    const val ACTION_KIND = "membership.set_directory_permission"
    private const val MAX_ID_LENGTH = 256
    private const val MAX_NAME_LENGTH = 512
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private const val MAX_TOPOLOGY_ITEMS = 10_000
    private const val MAX_GROUP_ROWS = 1_000
    private val UINT64_MAX = BigInteger("18446744073709551615")

    private val actionFields = setOf("kind", "set_directory_permission")
    private val payloadFields = setOf("group_id", "membership_id", "enabled", "expected_membership_version")
    private val snapshotFields = setOf(
        "contract_version", "owner_principal_id", "captured_at", "read_consistency",
        "networks_truncated", "network_endpoints_truncated", "networks", "groups", "memberships",
        "endpoints", "links",
    )
    private val groupFields = setOf("group_id", "name", "state", "context_policy", "version")
    private val groupOptionalFields = setOf("network_id", "parent_group_id")
    private val membershipFields = setOf(
        "membership_id", "principal_id", "group_id", "role", "broadcast_permission_enabled",
        "directory_permission_enabled", "status", "version",
    )
    private val membershipOptionalFields = setOf("display_name", "roles")
    private val endpointFields = setOf("endpoint_id", "name", "principal_id", "group_ids", "network_ids", "presence")
    private val endpointOptionalFields = setOf(
        "node_id", "harness", "native_session_id", "binding_id", "binding_epoch", "binding_status",
    )
    private val resultFields = setOf("contract_version", "action", "changed", "membership")

    internal data class Action(
        val groupId: String,
        val membershipId: String,
        val enabled: Boolean,
        val expectedMembershipVersion: Long,
    )

    /**
     * A best-effort preview scoped to one Principal Membership. Endpoint binding
     * epochs are deliberately not part of the Membership CAS version.
     */
    internal data class Preview(
        val groupId: String,
        val membershipId: String,
        val principalId: String,
        val directoryPermissionEnabled: Boolean,
        val membershipVersion: Long,
        val role: String,
        val roles: List<String>?,
        val broadcastPermissionEnabled: Boolean,
        val displayName: String?,
        val endpointIds: List<String>,
    )

    internal data class AppliedResult(
        val action: String,
        val changed: Boolean,
        val membershipVersion: Long,
        val directoryPermissionEnabled: Boolean,
    )

    /**
     * Fail closed before ClientHubSession reads state or touches the device key.
     * The candidate operation is deliberately unavailable in the pinned build.
     */
    fun guardGenericRpc(operation: String, body: JsonObject) {
        if (operation == "topology.apply" && containsCandidateSignal(body)) {
            throw HubSessionException(
                "GROUP_DIRECTORY_PERMISSION_NOT_READY",
                "Group directory permission is not available in this Client build",
            )
        }
    }

    /** A malformed or mismatched candidate payload is still recognized by the early RPC guard. */
    fun containsCandidateSignal(body: JsonObject): Boolean = body.has("set_directory_permission") ||
        body.get("kind")?.let { it.isJsonPrimitive && it.asJsonPrimitive.isString && it.asString == ACTION_KIND } == true

    /** Parses only the exact candidate tagged-union member; extra action/approval fields fail. */
    fun parseAction(value: JsonObject): Action {
        exact(value, actionFields, "GROUP_DIRECTORY_PERMISSION_INVALID")
        if (string(value, "kind", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_INVALID") != ACTION_KIND) {
            invalid("GROUP_DIRECTORY_PERMISSION_INVALID")
        }
        val payload = value.get("set_directory_permission")
            ?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("GROUP_DIRECTORY_PERMISSION_INVALID")
        exact(payload, payloadFields, "GROUP_DIRECTORY_PERMISSION_INVALID")
        val groupId = identifier(payload, "group_id")
        val membershipId = identifier(payload, "membership_id")
        val enabled = boolean(payload, "enabled", "GROUP_DIRECTORY_PERMISSION_INVALID")
        val version = positiveSafeInteger(payload, "expected_membership_version", "GROUP_DIRECTORY_PERMISSION_INVALID")
        return Action(groupId, membershipId, enabled, version)
    }

    /** Validates the owner-scoped v2 snapshot and returns the selected Principal plus every visible Endpoint in that Group. */
    fun validateSnapshotMember(snapshot: JsonObject, expectedOwnerPrincipalId: String, action: Action): Preview {
        val ownerId = validIdentifier(expectedOwnerPrincipalId)
        exact(snapshot, snapshotFields, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
        if (positiveSafeInteger(snapshot, "contract_version", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID") != 2L ||
            identifier(snapshot, "owner_principal_id") != ownerId ||
            string(snapshot, "read_consistency", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID") != "best_effort") {
            invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_SCOPE_MISMATCH")
        }
        string(snapshot, "captured_at", 40, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
        boolean(snapshot, "networks_truncated", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
        boolean(snapshot, "network_endpoints_truncated", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
        array(snapshot, "networks", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", 100)
        val groups = array(snapshot, "groups", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", MAX_TOPOLOGY_ITEMS)
        val memberships = array(snapshot, "memberships", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", MAX_TOPOLOGY_ITEMS)
        val endpoints = array(snapshot, "endpoints", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", MAX_TOPOLOGY_ITEMS)
        array(snapshot, "links", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", MAX_TOPOLOGY_ITEMS)

        val groupIds = HashSet<String>()
        var selectedGroupActive = false
        for (item in groups) {
            val group = item.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            exact(group, groupFields, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", groupOptionalFields)
            val groupId = identifier(group, "group_id")
            if (!groupIds.add(groupId)) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            text(group, "name", MAX_NAME_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            val state = string(group, "state", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            string(group, "context_policy", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            positiveSafeInteger(group, "version", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            for (field in groupOptionalFields) if (group.has(field)) identifier(group, field)
            if (groupId == action.groupId) selectedGroupActive = state == "ACTIVE"
        }
        if (action.groupId !in groupIds || !selectedGroupActive) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_SCOPE_MISMATCH")

        val seenMembershipIds = HashSet<String>()
        val selectedMembers = ArrayList<ParsedMembership>()
        var membershipCountForGroup = 0
        for (item in memberships) {
            val member = item.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            val parsed = parseMembership(member, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            if (!seenMembershipIds.add(parsed.membershipId)) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            if (parsed.groupId == action.groupId) membershipCountForGroup++
            if (parsed.membershipId == action.membershipId) selectedMembers += parsed
        }
        if (membershipCountForGroup >= MAX_GROUP_ROWS) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INCOMPLETE")
        if (selectedMembers.size != 1) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_SCOPE_MISMATCH")
        val member = selectedMembers.single()
        if (member.groupId != action.groupId || member.status != "active" ||
            member.version != action.expectedMembershipVersion) {
            invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_SCOPE_MISMATCH")
        }
        if (memberships.any { item ->
                val candidate = item.asJsonObject
                identifier(candidate, "principal_id") == member.principalId &&
                    identifier(candidate, "group_id") == action.groupId &&
                    identifier(candidate, "membership_id") != action.membershipId
            }) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")

        val endpointIds = ArrayList<String>()
        val seenEndpointIds = HashSet<String>()
        var targetGroupEndpointCount = 0
        for (item in endpoints) {
            val endpoint = item.takeIf { it.isJsonObject }?.asJsonObject
                ?: invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            exact(endpoint, endpointFields, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", endpointOptionalFields)
            val endpointId = identifier(endpoint, "endpoint_id")
            if (!seenEndpointIds.add(endpointId)) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            text(endpoint, "name", MAX_NAME_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            val principalId = identifier(endpoint, "principal_id")
            val groupIdsForEndpoint = stringArray(endpoint, "group_ids", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            stringArray(endpoint, "network_ids", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            string(endpoint, "presence", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID", allowEmpty = true)
            for (field in listOf("node_id", "harness", "native_session_id", "binding_id", "binding_status")) {
                if (endpoint.has(field)) identifier(endpoint, field)
            }
            if (endpoint.has("binding_epoch")) unsigned64(endpoint, "binding_epoch", "GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INVALID")
            if (action.groupId in groupIdsForEndpoint) targetGroupEndpointCount++
            if (principalId == member.principalId && action.groupId in groupIdsForEndpoint) endpointIds += endpointId
        }
        // The candidate producer caps each per-Group Endpoint read at 1000 and has no Group-level truncation bit.
        if (targetGroupEndpointCount >= MAX_GROUP_ROWS) invalid("GROUP_DIRECTORY_PERMISSION_SNAPSHOT_INCOMPLETE")

        return Preview(
            groupId = action.groupId,
            membershipId = member.membershipId,
            principalId = member.principalId,
            directoryPermissionEnabled = member.directoryPermissionEnabled,
            membershipVersion = member.version,
            role = member.role,
            roles = member.roles,
            broadcastPermissionEnabled = member.broadcastPermissionEnabled,
            displayName = member.displayName,
            endpointIds = endpointIds.sorted(),
        )
    }

    /** Validates the exact v2 apply result and its Membership CAS transition. */
    fun validateResult(value: JsonObject, action: Action, preview: Preview): AppliedResult {
        if (preview.groupId != action.groupId || preview.membershipId != action.membershipId ||
            preview.membershipVersion != action.expectedMembershipVersion) {
            invalid("GROUP_DIRECTORY_PERMISSION_RESULT_SCOPE_MISMATCH")
        }
        exact(value, resultFields, "GROUP_DIRECTORY_PERMISSION_RESULT_INVALID")
        if (positiveSafeInteger(value, "contract_version", "GROUP_DIRECTORY_PERMISSION_RESULT_INVALID") != 2L ||
            string(value, "action", MAX_ID_LENGTH, "GROUP_DIRECTORY_PERMISSION_RESULT_INVALID") != ACTION_KIND) {
            invalid("GROUP_DIRECTORY_PERMISSION_RESULT_SCOPE_MISMATCH")
        }
        val changed = boolean(value, "changed", "GROUP_DIRECTORY_PERMISSION_RESULT_INVALID")
        if (!changed) invalid("GROUP_DIRECTORY_PERMISSION_RESULT_INVALID")
        val memberObject = value.get("membership")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: invalid("GROUP_DIRECTORY_PERMISSION_RESULT_INVALID")
        val member = parseMembership(memberObject, "GROUP_DIRECTORY_PERMISSION_RESULT_INVALID")
        val nextVersion = action.expectedMembershipVersion + 1L
        if (nextVersion > MAX_SAFE_INTEGER || member.membershipId != action.membershipId ||
            member.groupId != action.groupId || member.principalId != preview.principalId ||
            member.status != "active" || member.version != nextVersion ||
            member.directoryPermissionEnabled != action.enabled || member.role != preview.role ||
            member.roles != preview.roles || member.broadcastPermissionEnabled != preview.broadcastPermissionEnabled ||
            member.displayName != preview.displayName) {
            invalid("GROUP_DIRECTORY_PERMISSION_RESULT_SCOPE_MISMATCH")
        }
        return AppliedResult(ACTION_KIND, changed, member.version, member.directoryPermissionEnabled)
    }

    private data class ParsedMembership(
        val membershipId: String,
        val principalId: String,
        val groupId: String,
        val role: String,
        val roles: List<String>?,
        val broadcastPermissionEnabled: Boolean,
        val directoryPermissionEnabled: Boolean,
        val status: String,
        val version: Long,
        val displayName: String?,
    )

    private fun parseMembership(value: JsonObject, code: String): ParsedMembership {
        exact(value, membershipFields, code, membershipOptionalFields)
        val roles = if (value.has("roles")) stringArray(value, "roles", code) else null
        val displayName = if (value.has("display_name")) text(value, "display_name", MAX_NAME_LENGTH, code, allowEmpty = true) else null
        return ParsedMembership(
            membershipId = identifier(value, "membership_id", code),
            principalId = identifier(value, "principal_id", code),
            groupId = identifier(value, "group_id", code),
            role = identifier(value, "role", code),
            roles = roles,
            broadcastPermissionEnabled = boolean(value, "broadcast_permission_enabled", code),
            directoryPermissionEnabled = boolean(value, "directory_permission_enabled", code),
            status = string(value, "status", MAX_ID_LENGTH, code),
            version = positiveSafeInteger(value, "version", code),
            displayName = displayName,
        )
    }

    private fun array(value: JsonObject, key: String, code: String, maximum: Int): JsonArray {
        val items = value.get(key)?.takeIf { it.isJsonArray }?.asJsonArray ?: invalid(code)
        if (items.size() > maximum) invalid(code)
        return items
    }

    private fun stringArray(value: JsonObject, key: String, code: String): List<String> {
        val items = array(value, key, code, MAX_TOPOLOGY_ITEMS)
        val parsed = items.map { item ->
            if (!item.isJsonPrimitive || !item.asJsonPrimitive.isString) invalid(code)
            validIdentifier(item.asString, code)
        }
        if (parsed.distinct().size != parsed.size) invalid(code)
        return parsed
    }

    private fun exact(value: JsonObject, required: Set<String>, code: String, optional: Set<String> = emptySet()) {
        if (!value.keySet().containsAll(required) || value.keySet().any { it !in required && it !in optional }) invalid(code)
    }

    private fun identifier(value: JsonObject, key: String, code: String = "GROUP_DIRECTORY_PERMISSION_INVALID"): String =
        validIdentifier(string(value, key, MAX_ID_LENGTH, code), code)

    private fun validIdentifier(value: String, code: String = "GROUP_DIRECTORY_PERMISSION_INVALID"): String {
        if (value.isBlank() || value != value.trim() || value.length > MAX_ID_LENGTH || value.any { it.isISOControl() }) invalid(code)
        return value
    }

    private fun text(
        value: JsonObject,
        key: String,
        maximum: Int,
        code: String,
        allowEmpty: Boolean = false,
    ): String {
        val result = string(value, key, maximum, code, allowEmpty)
        if (result.any { it.isISOControl() }) invalid(code)
        return result
    }

    private fun string(value: JsonObject, key: String, maximum: Int, code: String, allowEmpty: Boolean = false): String {
        val element = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
            ?: invalid(code)
        val result = element.asString
        if (result.length > maximum || (!allowEmpty && (result.isBlank() || result != result.trim()))) invalid(code)
        return result
    }

    private fun boolean(value: JsonObject, key: String, code: String): Boolean =
        value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean ?: invalid(code)

    private fun positiveSafeInteger(value: JsonObject, key: String, code: String): Long {
        val primitive = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: invalid(code)
        val raw = primitive.asString
        if (!raw.matches(Regex("^[1-9][0-9]*$"))) invalid(code)
        val parsed = raw.toLongOrNull() ?: invalid(code)
        if (parsed !in 1L..MAX_SAFE_INTEGER) invalid(code)
        return parsed
    }

    private fun unsigned64(value: JsonObject, key: String, code: String) {
        val primitive = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: invalid(code)
        val raw = primitive.asString
        if (!raw.matches(Regex("^(0|[1-9][0-9]*)$"))) invalid(code)
        val parsed = try { BigInteger(raw) } catch (_: NumberFormatException) { invalid(code) }
        if (parsed.signum() < 0 || parsed > UINT64_MAX) invalid(code)
    }

    private fun invalid(code: String): Nothing = throw GroupDirectoryPermissionValidationException(code)
}

internal class GroupDirectoryPermissionValidationException(val code: String) : IllegalArgumentException(code)
