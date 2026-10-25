package n3_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// This first product boundary deliberately supplies no legitimate native
// actor. It must fail before elicitation, directory reads or business writes.
// It is not the positive real-Host/form/cross-Node acceptance lane.
func TestN3PeerFormUnverifiedContext(t *testing.T) {
	if os.Getenv("CICADA_N3_PEER_FORM") != "1" {
		t.Skip("PEER_FORM_NOT_RUN: explicit isolated integration is off")
	}
	v := newCodexProductFixture(t, "1h")
	v.requireEmptyOwnerDirectory(t)
	host := startProductPeerFormHost(t, v, map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})
	nonce := peerFormAdvertisedNonce(t, host, "cicada_select_peer")
	for index, name := range []string{"missing", "nonce-only", "wrong-nonce", "forged-ticket", "extra-SID"} {
		t.Run(name, func(t *testing.T) {
			before := len(v.f.proxy.snapshot())
			stateBefore, err := os.ReadFile(v.mcpState)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal("owned native session state unavailable before refused selection")
			}
			defer clear(stateBefore)
			context := map[string]any{"connection_nonce": nonce, "ticket": strings.Repeat("0", 64) + "." + strings.Repeat("0", 64)}
			arguments := map[string]any{"scope": "group", "_cicada_context": context}
			switch name {
			case "missing":
				delete(arguments, "_cicada_context")
			case "nonce-only":
				delete(context, "ticket")
			case "wrong-nonce":
				context["connection_nonce"] = strings.Repeat("x", 64)
			case "extra-SID":
				context["native_session_id"] = "synthetic-peer-form-untrusted-SID"
			}
			id := 10 + index
			host.call(t, id, "tools/call", map[string]any{"name": "cicada_select_peer", "arguments": arguments})
			frame := host.reply(t, id)
			defer frame.clear()
			var result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				Structured json.RawMessage `json:"structuredContent"`
			}
			if len(frame.Error) != 0 || json.Unmarshal(frame.Result, &result) != nil || !result.IsError || len(result.Content) != 1 ||
				!strings.Contains(result.Content[0].Text, "CODEX_CALL_CONTEXT_REQUIRED") || len(result.Structured) != 0 {
				t.Fatal("actual selection did not refuse the original unverified native context")
			}
			for _, saved := range host.saved {
				if saved.Method == "elicitation/create" {
					t.Fatal("unverified selection exposed an unauthorized form before its refusal")
				}
			}
			for _, ex := range v.f.proxy.snapshot()[before:] {
				base := "/v2/relay/nodes/" + v.actualNode.id
				if ex.Method == http.MethodPost && ex.Path == base+"/heartbeat" || ex.Method == http.MethodGet && ex.Path == base+"/events" {
					continue
				}
				t.Fatal("unverified selection caused a Hub directory or business request")
			}
			stateAfter, err := os.ReadFile(v.mcpState)
			if err != nil && !os.IsNotExist(err) {
				t.Fatal("owned native session state unavailable after selection refusal")
			}
			defer clear(stateAfter)
			if !bytes.Equal(stateBefore, stateAfter) {
				t.Fatal("unverified selection changed durable native session authority")
			}
		})
	}
	v.requireEmptyOwnerDirectory(t)
	t.Log("PEER_FORM_CONTEXT actual_CLI_MCP_Node_App=true missing_and_forged_actor_refused=true unauthorized_forms=0 directory_or_business_dispatch=0 native_UI=NOT_RUN")
}
