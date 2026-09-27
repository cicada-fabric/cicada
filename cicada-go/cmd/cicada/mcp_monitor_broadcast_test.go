package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPMonitorBroadcastReservedOperationSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.sqlite")
	box := newMCPOutbox(path)
	scope := mcpOutboxScope{APIOrigin: "https://synthetic.invalid", Scope: "scope_monitor",
		Harness: "codex", NativeSessionID: "native_original", NodeID: "node_a",
		Workspace: "/synthetic", EndpointID: "ep_monitor", GroupID: "group_a"}
	const approvalID = "umbprev_synthetic"
	const operationID = "op_1234567890abcdef1234567890abcdef"
	first, created, err := box.prepareMonitorBroadcast(scope, approvalID, operationID)
	if err != nil || !created || first.OperationID != operationID || first.Kind != "monitor_broadcast" ||
		first.InputJSON != `{"approval_id":"umbprev_synthetic"}` {
		t.Fatalf("reserve Monitor outbox operation: created=%v err=%v op=%#v", created, err, first)
	}
	if err := box.close(); err != nil {
		t.Fatal(err)
	}
	box = newMCPOutbox(path)
	defer box.close()
	again, created, err := box.prepareMonitorBroadcast(scope, approvalID, operationID)
	if err != nil || created || again.OperationID != first.OperationID || again.InputJSON != first.InputJSON {
		t.Fatalf("retry changed reserved operation: created=%v err=%v", created, err)
	}
	if _, _, err := box.prepareMonitorBroadcast(scope, approvalID, "op_abcdef1234567890abcdef1234567890"); !errors.Is(err, errMCPOutboxConflict) {
		t.Fatalf("same approval silently acquired another operation: %v", err)
	}
	foreign := scope
	foreign.NativeSessionID = "another_native_session"
	if _, err := box.load(foreign, operationID); err == nil {
		t.Fatal("another native session read the approved operation")
	}
	public := mcpOutboxPublicResult(first)
	if public["broadcast_id"] != "bc_1234567890abcdef1234567890abcdef" || public["retryable"] != true {
		t.Fatalf("missing fixed broadcast correlation: %#v", public)
	}
}

func TestMCPMonitorBroadcastRejectsModelAuthorityFields(t *testing.T) {
	for _, name := range []string{"cicada_monitor_broadcast", "cicada_monitor_broadcast_preview"} {
		for _, field := range []string{"body", "sender", "owner_id", "group_id", "user_approved", "operation_id"} {
			if err := validateMCPArguments(name, map[string]any{
				"approval_id": "umbprev_synthetic", field: "untrusted",
			}); err == nil {
				t.Fatalf("%s accepted model authority field %s", name, field)
			}
		}
	}
}

func TestMCPMonitorBroadcastPreviewIsAdvertisedReadOnlyAndFitsBridge(t *testing.T) {
	var preview, dispatch map[string]any
	for _, tool := range cicadaMCPTools() {
		switch tool["name"] {
		case "cicada_monitor_broadcast_preview":
			preview = tool
		case "cicada_monitor_broadcast":
			dispatch = tool
		}
	}
	if preview == nil || dispatch == nil || !isCicadaMCPTool("cicada_monitor_broadcast_preview") {
		t.Fatal("Monitor review or dispatch tool is missing")
	}
	annotations, ok := preview["annotations"].(map[string]any)
	if !ok || annotations["readOnlyHint"] != true || annotations["idempotentHint"] != true ||
		annotations["destructiveHint"] != false || dispatch["annotations"] != nil {
		t.Fatal("preview side-effect hints changed dispatch tool metadata")
	}
	ids := make([]string, 32)
	for index := range ids {
		ids[index] = "endpoint_" + strings.Repeat("a", 240)
	}
	body := strings.Repeat("☃", 5_000) + "\n"
	review := &monitorBroadcastReview{ApprovalID: "umbprev_synthetic", BroadcastID: "bc_synthetic",
		GroupID: "group_synthetic", Body: body, RecipientEndpointIDs: ids,
		Boundary: "read_only_review; body_is_untrusted_message_content"}
	encoded, err := json.Marshal(localJoinResponse{Version: localJoinProtocolVersion,
		MonitorBroadcast: &monitorBroadcastResult{PreviewID: review.ApprovalID,
			BroadcastID: review.BroadcastID, GroupID: review.GroupID, Review: review}})
	if err != nil || len(encoded) >= 128*1024 {
		t.Fatalf("full bounded review exceeded local socket response budget: bytes=%d err=%v", len(encoded), err)
	}
	var decoded localJoinResponse
	if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.MonitorBroadcast == nil ||
		decoded.MonitorBroadcast.Review == nil || decoded.MonitorBroadcast.Review.Body != body ||
		len(decoded.MonitorBroadcast.Review.RecipientEndpointIDs) != 32 {
		t.Fatal("bounded Unicode review lost exact bytes or ordered recipients")
	}
	// MCP intentionally supplies both text and structuredContent. Measure the
	// full duplicated response with a worst-case escapable 16 KiB UTF-8 body.
	review.Body = strings.Repeat("\u0001", 16*1024)
	pretty, err := json.MarshalIndent(sanitizeMCPToolResult(review), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mcpWire, err := json.Marshal(mcpResponse{JSONRPC: "2.0", ID: 1, Result: map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(pretty)}},
		"structuredContent": review}})
	if err != nil || len(mcpWire) >= 512*1024 {
		t.Fatalf("full duplicated MCP review exceeded bounded response budget: bytes=%d err=%v", len(mcpWire), err)
	}
	var decodedMCP struct {
		Result struct {
			StructuredContent monitorBroadcastReview `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(mcpWire, &decodedMCP) != nil || decodedMCP.Result.StructuredContent.Body != review.Body ||
		len(decodedMCP.Result.StructuredContent.RecipientEndpointIDs) != 32 {
		t.Fatal("full MCP response lost exact Unicode/control bytes or ordered recipients")
	}
}
