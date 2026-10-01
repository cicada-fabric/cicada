package main

import (
	"strings"
	"testing"
)

func TestMCPOwnerLinkReviewToolsAreRegisteredMetadataOnlyAndStrict(t *testing.T) {
	want := map[string]bool{
		"cicada_link_review_list":       false,
		"cicada_link_review_get":        false,
		"cicada_link_review_claim_next": false,
		"cicada_link_review_decide":     false,
	}
	for _, tool := range cicadaMCPTools() {
		name, _ := tool["name"].(string)
		if _, exists := want[name]; !exists {
			continue
		}
		if !isCicadaMCPTool(name) {
			t.Fatalf("advertised review tool %s is not dispatchable", name)
		}
		description, _ := tool["description"].(string)
		if strings.Contains(strings.ToLower(description), "ciphertext") == false ||
			strings.Contains(strings.ToLower(description), "body") == false {
			t.Fatalf("review tool %s does not state its metadata-only boundary: %q", name, description)
		}
		want[name] = true
	}
	for name, found := range want {
		if !found {
			t.Fatalf("missing registered Link reviewer tool %s", name)
		}
	}
	server := newMCPServer("http://127.0.0.1:8787", "", "")
	if _, err := server.callTool("cicada_link_review_get", map[string]any{"message_id": "msg_synthetic", "owner_id": "forged"}); err == nil {
		t.Fatal("review tool accepted a model-supplied owner identity")
	}
	if _, err := server.callTool("cicada_link_review_claim_next", map[string]any{
		"message_id": "msg_synthetic", "expected_version": 1.5, "expected_owner_epoch": 2,
	}); err == nil || !strings.Contains(err.Error(), "integer") {
		t.Fatalf("claim tool accepted lossy expected version: %v", err)
	}
	if _, err := server.callTool("cicada_link_review_decide", map[string]any{
		"message_id": "msg_synthetic", "expected_version": 1, "expected_owner_epoch": 2,
		"decision": "approve",
	}); err == nil || !strings.Contains(err.Error(), "APPROVED or REJECTED") {
		t.Fatalf("decision tool accepted an unknown state: %v", err)
	}
}
