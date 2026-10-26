package n3_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Persist closed protocol diagnostics before Go's temporary fixture cleanup.
// Only routes, times, digests and independently authenticated closed errors
// leave memory. Keys, tokens, packets, bodies and result DTOs never do.
func registerOwnerGroupsProtocolAudit(t *testing.T, v *codexProductFixture) {
	t.Helper()
	t.Cleanup(func() {
		key, binding := ownerGroupsNodeAuditIdentity(t, v)
		closedCode := regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)
		var rows []map[string]any
		for _, ex := range v.f.proxy.snapshot() {
			if ex.Path != "/v2/node/control/rpc" && !strings.HasPrefix(ex.Path, "/v2/owner/endpoint-groups/") {
				continue
			}
			row := map[string]any{"path": ex.Path, "method": ex.Method, "forwarded": ex.Forwarded,
				"http_status": ex.Status, "request_sha256": ex.RequestSHA256, "response_sha256": ex.ResponseSHA256,
				"started_at": ex.StartedAt, "recorded_at": ex.RecordedAt, "fault_mode": ex.FaultMode}
			if ex.Path == "/v2/node/control/rpc" {
				packet, err := nodewire.DecodePacket(ex.request)
				if err != nil {
					row["packet_state"] = "MALFORMED"
				} else {
					row["operation"], row["operation_id_sha256"], row["sequence"] = packet.Route.Operation, hash([]byte(packet.Route.OperationID)), packet.Route.Sequence
					if ex.Forwarded && ex.Status == 200 && len(ex.response) > 0 {
						opened, err := nodewire.OpenResponse(key, binding.HubKey, binding, ex.response)
						if err == nil {
							want := packet.Route
							want.Direction = nodewire.DirectionResponse
							want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
							want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
							var result appPairNodeReply
							if opened.Route == want && json.Unmarshal(opened.Plaintext, &result) == nil &&
								result.OperationID == packet.Route.OperationID && result.Sequence == packet.Route.Sequence {
								row["authenticated"], row["ok"] = true, result.OK
								if closedCode.MatchString(result.ErrorCode) {
									row["error_code"] = result.ErrorCode
								}
							}
							clear(opened.Plaintext)
						}
					}
				}
			}
			rows = append(rows, row)
		}
		// Decode only metadata from protected state, never reserialize its
		// private request/response/body fields into evidence.
		var state struct {
			PendingOperation string `json:"pending_operation"`
			PendingSequence  uint64 `json:"pending_sequence"`
			Intents          map[string]struct {
				Steps map[string]struct {
					Operation   string `json:"operation"`
					Settled     bool   `json:"settled"`
					CompletedAt string `json:"completed_at"`
				} `json:"steps"`
			} `json:"local_endpoint_intents"`
		}
		readJSON(t, v.actualNode.statePath(), &state)
		var steps []map[string]any
		for intentID, intent := range state.Intents {
			for stepID, step := range intent.Steps {
				steps = append(steps, map[string]any{"intent_id_sha256": hash([]byte(intentID)), "step_id_sha256": hash([]byte(stepID)),
					"operation": step.Operation, "settled": step.Settled, "completed_at": step.CompletedAt})
			}
		}
		if filepath.Dir(os.Getenv("CICADA_N3_CICADA_BINARY")) != "/out" {
			t.Error("protocol audit output is not the owned driver artifact mount")
			return
		}
		directory := filepath.Join("/out", "owner-groups-protocol-audit")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Error("owned protocol audit directory unavailable")
			return
		}
		path := filepath.Join(directory, hash([]byte(v.root))[:16]+".json")
		writeJSON(t, path, map[string]any{"scope": "CLOSED_PROTOCOL_DIAGNOSTICS_NOT_ACCEPTANCE", "captured_at": time.Now().UTC().Format(time.RFC3339Nano),
			"trace": rows, "steps": steps, "pending_operation": state.PendingOperation, "pending_sequence": state.PendingSequence})
		t.Logf("OWNER_GROUPS_PROTOCOL_AUDIT file=%s sha256=%s", "owner-groups-protocol-audit/"+filepath.Base(path), hash(readPrivate(t, path)))
	})
}
