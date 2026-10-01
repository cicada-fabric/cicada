package ai.cicada.client.hub

import com.google.gson.JsonObject
import java.time.Instant

/** Exact metadata checks for Owner review. These are not native Endpoint proofs. */
internal object RegroupDelegationValidation {
    private const val MAX_SAFE_INTEGER = 9_007_199_254_740_991L
    private val proposalFields = setOf("proposal_id", "hub_id", "owner_id", "endpoint_id",
        "principal_id", "binding_id", "binding_epoch", "input", "state", "created_at", "expires_at")
    private val inputFields = setOf("operation_id", "network_id", "source_group_id", "target_group_id",
        "action", "expected_source_version", "expected_target_version")
    private val membershipFields = setOf("membership_id", "principal_id", "group_id", "role",
        "broadcast_permission_enabled", "status", "version")
    private val delegationFields = setOf("delegation_id", "proposal_id", "hub_id", "owner_id", "network_id",
        "source_group_id", "target_group_id", "action", "expected_source_version", "expected_target_version",
        "expires_at", "max_uses", "use_count", "state", "version", "created_at")

    fun proposal(value: JsonObject, topology: JsonObject, hubId: String, ownerId: String,
                 networkId: String, proposalId: String): JsonObject {
        exact(value, proposalFields, setOf("delegation"))
        require(token(value, "proposal_id") == proposalId && token(value, "hub_id") == hubId &&
            token(value, "owner_id") == ownerId && token(value, "state") in setOf("PROPOSED", "APPLIED"))
        require(number(value, "binding_epoch") > 0)
        require(instant(value, "expires_at") > instant(value, "created_at"))
        val input = value.get("input").takeIf { it.isJsonObject }?.asJsonObject
            ?: throw IllegalArgumentException("Proposal input is missing")
        exact(input, inputFields, setOf("new_group_name"))
        token(input, "operation_id")
        require(token(input, "network_id") == networkId &&
            token(input, "action") in setOf("SET_PARENT", "CREATE_CHILD"))
        val sourceId = token(input, "source_group_id")
        val targetId = token(input, "target_group_id")
        require((token(input, "action") != "SET_PARENT" || sourceId != targetId) &&
            number(input, "expected_source_version") > 0 &&
            number(input, "expected_target_version") > 0)
        if (input.has("new_group_name")) {
            val name = string(input, "new_group_name")
            require(name.length <= 80)
        }
        if (token(input, "action") == "CREATE_CHILD") {
            require(string(input, "new_group_name").isNotBlank())
        }
        require(number(topology, "contract_version") == 2L && token(topology, "owner_principal_id") == ownerId &&
            string(topology, "read_consistency") == "best_effort")
        val network = item(topology, "networks", "network_id", networkId)
        require(token(network, "state") == "ACTIVE" && number(network, "version") > 0 &&
            network.get("can_create_group")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean == true)
        for (groupId in listOf(sourceId, targetId)) {
            val group = item(topology, "groups", "group_id", groupId)
            require(token(group, "network_id") == networkId && number(group, "version") > 0)
        }
        // Endpoint principals identify agents. They are not the human Owner principal.
        val endpoint = item(topology, "endpoints", "endpoint_id", token(value, "endpoint_id"))
        require(token(endpoint, "principal_id") == token(value, "principal_id"))
        val groups = endpoint.get("group_ids")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Endpoint Group projection is missing")
        require(groups.any { it.isJsonPrimitive && it.asJsonPrimitive.isString && it.asString == sourceId })
        value.get("delegation")?.let {
            require(it.isJsonObject)
            delegation(it.asJsonObject, value)
        }
        return value.deepCopy()
    }

    fun currentIssue(value: JsonObject, topology: JsonObject, now: Instant) {
        require(token(value, "state") == "PROPOSED" && !value.has("delegation") &&
            instant(value, "expires_at") > now)
        val input = value.getAsJsonObject("input")
        for ((idField, versionField) in listOf("source_group_id" to "expected_source_version",
                "target_group_id" to "expected_target_version")) {
            val group = item(topology, "groups", "group_id", token(input, idField))
            require(token(group, "state") == "ACTIVE" && number(group, "version") == number(input, versionField))
        }
        val endpoint = item(topology, "endpoints", "endpoint_id", token(value, "endpoint_id"))
        val principalId = token(value, "principal_id")
        require(token(endpoint, "principal_id") == principalId &&
            token(endpoint, "binding_id") == token(value, "binding_id") &&
            number(endpoint, "binding_epoch") == number(value, "binding_epoch") &&
            token(endpoint, "binding_status") in setOf("active", "leased", "online", "ready", "acquired"))
        val sourceId = token(input, "source_group_id")
        val targetId = token(input, "target_group_id")
        val checkedMemberships = linkedMapOf<String, JsonObject>()
        for (groupId in listOf(sourceId, targetId).distinct()) {
            val membership = activeEndpointMembership(topology, endpoint, principalId, groupId)
            checkedMemberships[groupId] = membership
        }
        require(hasMonitorRole(checkedMemberships.getValue(sourceId)))
    }

    /** The Owner topology exposes Endpoint group_ids and principal Memberships separately. */
    private fun activeEndpointMembership(
        topology: JsonObject,
        endpoint: JsonObject,
        principalId: String,
        groupId: String,
    ): JsonObject {
        val groupIds = endpoint.get("group_ids")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Endpoint Group projection is missing")
        require(groupIds.all { it.isJsonPrimitive && it.asJsonPrimitive.isString })
        require(groupIds.any { it.asString == groupId })

        val memberships = topology.get("memberships")?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Owner Membership projection is missing")
        require(memberships.size() <= 10_000)
        val matches = memberships.filter { member ->
            member.isJsonObject && token(member.asJsonObject, "principal_id") == principalId &&
                token(member.asJsonObject, "group_id") == groupId
        }
        require(matches.size == 1)
        val membership = matches.single().asJsonObject
        exact(membership, membershipFields, setOf("display_name", "roles"))
        token(membership, "membership_id")
        string(membership, "role")
        require(token(membership, "principal_id") == principalId && token(membership, "group_id") == groupId &&
            token(membership, "status") == "active" && number(membership, "version") > 0)
        membership.get("broadcast_permission_enabled")
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }
            ?: throw IllegalArgumentException("Membership projection is invalid")
        if (membership.has("display_name")) string(membership, "display_name")
        if (membership.has("roles")) {
            val roles = membership.get("roles")?.takeIf { it.isJsonArray }?.asJsonArray
                ?: throw IllegalArgumentException("Membership roles are invalid")
            require(roles.all { it.isJsonPrimitive && it.asJsonPrimitive.isString })
        }
        return membership
    }

    private fun hasMonitorRole(membership: JsonObject): Boolean {
        if (string(membership, "role") == "monitor") return true
        val roles = membership.get("roles")?.takeIf { it.isJsonArray }?.asJsonArray ?: return false
        return roles.any { it.isJsonPrimitive && it.asJsonPrimitive.isString && it.asString == "monitor" }
    }

    fun issueExpiry(value: JsonObject, expiry: String, now: Instant): Instant {
        val deadline = Instant.parse(expiry)
        require(deadline > now && deadline <= now.plusSeconds(24 * 60 * 60) &&
            deadline <= instant(value, "expires_at"))
        return deadline
    }

    fun delegation(value: JsonObject, proposal: JsonObject): JsonObject {
        exact(value, delegationFields)
        val input = proposal.getAsJsonObject("input")
        token(value, "delegation_id")
        for (key in listOf("proposal_id", "hub_id", "owner_id")) {
            require(token(value, key) == token(proposal, key))
        }
        for (key in listOf("network_id", "source_group_id", "target_group_id", "action")) {
            require(token(value, key) == token(input, key))
        }
        for (key in listOf("expected_source_version", "expected_target_version")) {
            require(number(value, key) == number(input, key))
        }
        require(number(value, "max_uses") == 1L && number(value, "use_count") in 0L..1L &&
            number(value, "version") > 0 && token(value, "state") in setOf("ACTIVE", "REVOKED", "EXHAUSTED") &&
            instant(value, "expires_at") > instant(value, "created_at"))
        if (token(value, "state") == "ACTIVE") require(number(value, "use_count") == 0L)
        if (token(value, "state") == "EXHAUSTED") require(number(value, "use_count") == 1L)
        return value.deepCopy()
    }

    fun number(value: JsonObject, key: String): Long {
        val item = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber }
            ?: throw IllegalArgumentException("Integer field is missing")
        return item.asString.toLongOrNull()?.takeIf { it in 0..MAX_SAFE_INTEGER }
            ?: throw IllegalArgumentException("Integer field is outside the display range")
    }

    fun token(value: JsonObject, key: String): String = string(value, key).also {
        require(it.isNotBlank() && it == it.trim() && it.length <= 256)
    }

    private fun string(value: JsonObject, key: String): String {
        val item = value.get(key)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
            ?: throw IllegalArgumentException("String field is missing")
        return item.asString
    }

    private fun instant(value: JsonObject, key: String): Instant = Instant.parse(string(value, key))

    private fun item(value: JsonObject, list: String, key: String, id: String): JsonObject {
        val items = value.get(list)?.takeIf { it.isJsonArray }?.asJsonArray
            ?: throw IllegalArgumentException("Owner projection is missing")
        require(items.size() <= 10_000)
        return items.filter { it.isJsonObject && it.asJsonObject.get(key)?.let { field ->
            field.isJsonPrimitive && field.asJsonPrimitive.isString && field.asString == id
        } == true }.single().asJsonObject
    }

    private fun exact(value: JsonObject, required: Set<String>, optional: Set<String> = emptySet()) {
        require(value.entrySet().all { it.key in required || it.key in optional } &&
            required.all { value.has(it) && !value.get(it).isJsonNull })
    }
}
