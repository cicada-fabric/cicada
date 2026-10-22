package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func codexConsumerIssueProfile(t *testing.T, authority *localCodexContextAuthority, q localCodexContextIssue, profile localCodexContext) *localCodexContextIssueResult {
	t.Helper()
	issued, err := authority.issue(q, "synthetic-node-binding", time.Now())
	if err != nil {
		t.Error(err)
		return nil
	}
	if profile.VerificationProfile != "" {
		id := strings.Split(issued.Ticket, ".")[0]
		authority.mu.Lock()
		record := authority.live[id]
		record.Context.VerificationProfile, record.Context.LocalDomainVersion, record.Context.LocalDomain = profile.VerificationProfile, profile.LocalDomainVersion, profile.LocalDomain
		authority.live[id] = record
		issued.Ticket = id + "." + authority.sign(id, record)
		authority.mu.Unlock()
	}
	return issued
}

// This scripted private Node checks the real native record and uses the real
// one-use HMAC authority. It isolates consumer behavior from service admission;
// actual domain profile selection/Owner Guard remain the separate Node gate.
func codexConsumerOperatorNode(t *testing.T, stateDir, nodeID string, profile localCodexContext, endpoint func(net.Conn, json.RawMessage)) {
	t.Helper()
	var authority localCodexContextAuthority
	codexConsumerNode(t, stateDir, nodeID, func(connection net.Conn, raw json.RawMessage) {
		var header struct {
			Operation string `json:"operation"`
		}
		_ = json.Unmarshal(raw, &header)
		switch header.Operation {
		case "codex_context_issue":
			var q localCodexContextIssue
			response := localJoinResponse{Version: localJoinProtocolVersion}
			if decodeLocalBridgeRequest(raw, &q) != nil || codexOperatorContextTool(strings.TrimPrefix(q.ToolName, "codex.operator.")) != q.ToolName || verifyCodexContextTranscript(q.TranscriptPath, q.NativeSessionID, q.Workspace) != nil {
				response.Error = "synthetic context refused"
			} else {
				response.CodexContextIssue = codexConsumerIssueProfile(t, &authority, q, profile)
			}
			_ = json.NewEncoder(connection).Encode(response)
		case "codex_context_consume":
			var q localCodexContextConsume
			_ = json.Unmarshal(raw, &q)
			result, err := authority.consume(q, "synthetic-node-binding", time.Now())
			response := localJoinResponse{Version: localJoinProtocolVersion, CodexContextConsume: result}
			if err != nil {
				response.Error = "synthetic context refused"
			}
			_ = json.NewEncoder(connection).Encode(response)
		default:
			endpoint(connection, raw)
		}
	})
}
