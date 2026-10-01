package main

import (
	"testing"
	"time"
)

func TestMCPNetworkBroadcastToolsAreRegisteredAndClosed(t *testing.T) {
	want := map[string]map[string]struct{}{
		"cicada_network_broadcast_preview": {"network_id": {}},
		"cicada_network_broadcast": {"network_id": {}, "snapshot_digest": {}, "body": {},
			"record_refs": {}, "expires_at": {}, "idempotency_key": {}},
		"cicada_network_broadcast_status": {"network_id": {}, "broadcast_id": {}},
	}
	registered := map[string]map[string]any{}
	for _, raw := range cicadaMCPTools() {
		name, _ := raw["name"].(string)
		if _, ok := want[name]; ok {
			registered[name] = raw
		}
	}
	if len(registered) != len(want) {
		t.Fatalf("Network Broadcast tools = %v, want %v", registered, want)
	}
	for name, allowed := range want {
		if !isCicadaMCPTool(name) || !isMCPNetworkBroadcastTool(name) {
			t.Fatalf("%s is not routed through the common MCP tool gate", name)
		}
		schema, ok := registered[name]["inputSchema"].(map[string]any)
		if !ok || schema["additionalProperties"] != false {
			t.Fatalf("%s does not advertise a closed input schema", name)
		}
		for key := range allowed {
			if _, ok := schema["properties"].(map[string]any)[key]; !ok {
				t.Fatalf("%s schema omits %q", name, key)
			}
		}
	}
	for name, authorityField := range map[string]string{
		"cicada_network_broadcast_preview": "owner_id",
		"cicada_network_broadcast":         "receiver_endpoint_id",
		"cicada_network_broadcast_status":  "role",
	} {
		args := map[string]any{"network_id": "net_synthetic", authorityField: "forged"}
		if err := validateMCPArguments(name, args); err == nil {
			t.Fatalf("%s accepted caller authority field %q", name, authorityField)
		}
	}
	if err := validateMCPArguments("cicada_network_broadcast_preview", map[string]any{
		"network_id": "net_synthetic",
	}); err != nil {
		t.Fatalf("valid read-only preview args rejected: %v", err)
	}
}

func TestNetworkBroadcastDeadlineAndSnapshotValidation(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := networkBroadcastDeadline(now.Add(time.Hour).Format(time.RFC3339Nano), now); err != nil {
		t.Fatalf("bounded deadline rejected: %v", err)
	}
	for _, deadline := range []time.Time{now, now.Add(-time.Second), now.Add(24*time.Hour + time.Second)} {
		if _, err := networkBroadcastDeadline(deadline.Format(time.RFC3339Nano), now); err == nil {
			t.Fatalf("invalid deadline %s accepted", deadline)
		}
	}
	if _, err := canonicalNetworkBroadcastTargets([]string{"ep_second", "ep_first"}, "ep_publisher"); err != nil {
		t.Fatalf("valid synthetic recipient set rejected: %v", err)
	}
	for _, recipients := range [][]string{{}, {"ep_same", "ep_same"}, {"ep_publisher"}, {"invalid"}} {
		if _, err := canonicalNetworkBroadcastTargets(recipients, "ep_publisher"); err == nil {
			t.Fatalf("invalid recipient set %v accepted", recipients)
		}
	}
}
