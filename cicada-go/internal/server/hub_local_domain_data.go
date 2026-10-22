package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// SEND remains absent from the legacy Hub-Nodes route profile. Its new domain
// variant is selected by the persisted dedicated Group, never caller flags.
func (h *hubNodesHandler) localDomainRelaySend(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/relay/nodes/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v2/relay/nodes/") || len(parts) != 4 || parts[0] == "" || parts[1] != "group" || parts[2] != "sealed" || parts[3] != "send" {
		return false
	}
	deny := func() { writeError(w, http.StatusNotFound, errors.New("route unavailable in Hub Nodes mode")) }
	if r.Method != http.MethodPost {
		deny()
		return true
	}
	token, err := fabric.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		deny()
		return true
	}
	svc := h.nodes.Fabric()
	node, err := svc.AuthenticateNode(token)
	if err != nil || node != parts[0] {
		deny()
		return true
	}
	var input fabric.NodeSameGroupSealedV1SendInput
	if decodeStrictClientJSON(r.Body, 512<<10, &input) != nil || svc.RequireLocalDomainRelay(token, input.GroupID) != nil {
		deny()
		return true
	}
	record, err := svc.SendNodeSameGroupSealedV1Message(token, input)
	if err != nil {
		relayNodeSameGroupSealedWriteError(w, err)
		return true
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"message_id": record.Route.MessageID, "payload_mode": store.RelayPayloadModeSealedV1, "outbox_state": record.OutboxState, "sequence": record.Sequence})
	return true
}
