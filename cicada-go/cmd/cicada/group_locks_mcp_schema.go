package main

// These are Root-approved MCP consumer names. The catalog is connected together
// with its verified Node handlers; a schema never grants a Group permission.
func groupLocksMCPTools() []map[string]any {
	object := func(properties map[string]any, required ...string) map[string]any {
		if required == nil {
			required = []string{}
		}
		return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
	}
	text := func(description string) map[string]any {
		return map[string]any{"type": "string", "description": description}
	}
	integer := func(description string, maximum uint64) map[string]any {
		return map[string]any{"type": "integer", "minimum": 1, "maximum": maximum, "description": description}
	}
	read := func(name, description string) map[string]any {
		return map[string]any{"name": name, "description": description, "inputSchema": object(map[string]any{}),
			"annotations": map[string]any{"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false, "openWorldHint": false}}
	}
	tools := []map[string]any{
		read("cicada_thread_scope", "Read this original Thread's single Network, Owner-assigned classification and scope conflicts using fresh Host proof. Does not register, join or change roles."),
		read("cicada_group_locks", "Read eight coordination slots in the currently selected authorized Group, including visible holder names, notes and expiry. Reading never acquires or renews a slot."),
	}
	for _, operation := range []string{"acquire", "renew", "release"} {
		properties := map[string]any{
			"recover":          map[string]any{"type": "boolean", "description": "Explicitly recover this saved idempotency key's original operation; never creates a replacement operation"},
			"slot":             integer("Exact observed slot number", 8),
			"expected_version": integer("Exact version from the authenticated slot observation", 1<<63-1),
			"idempotency_key":  text("Stable key for this exact operation; retain it after an uncertain result"),
		}
		required := []string{"slot", "expected_version", "idempotency_key"}
		if operation != "acquire" {
			properties["generation"] = integer("Exact generation of this original Thread's confirmed holding", 1<<63-1)
			required = append(required, "generation")
		}
		if operation != "release" {
			properties["ttl_seconds"] = integer("Explicit lease duration, 1..3600 seconds; omitted uses 300 seconds. Never renew implicitly.", 3600)
		}
		if operation == "acquire" {
			properties["note"] = map[string]any{"type": "string", "maxLength": 1024, "description": "Optional Group coordination purpose; at most 1024 UTF-8 bytes"}
		}
		description := map[string]string{
			"acquire": "Explicitly acquire one observed Group coordination slot atomically. Busy/version conflict grants nothing. The Node persists the exact original before sending; recover uncertain outcomes rather than creating another operation.",
			"renew":   "Explicitly renew this original Thread's still-live holding at the exact version/generation. Expired or transferred holdings cannot be renewed. This records a lease, not actual resource usage.",
			"release": "Explicitly release this original Thread's exact holding. Fresh Host identity, current Group authorization, version and generation must match; cannot clear another holder.",
		}[operation]
		tools = append(tools, map[string]any{"name": "cicada_group_lock_" + operation, "description": description,
			"inputSchema": object(properties, required...), "annotations": map[string]any{"readOnlyHint": false, "idempotentHint": false, "destructiveHint": false, "openWorldHint": false}})
	}
	return tools
}

func isGroupLocksMCPTool(name string) bool {
	switch name {
	case "cicada_thread_scope", "cicada_group_locks", "cicada_group_lock_acquire", "cicada_group_lock_renew", "cicada_group_lock_release":
		return true
	}
	return false
}
