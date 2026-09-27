package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// relayNodeGroupBroadcastSnapshot captures the immutable recipient set for a
// same-Group broadcast. The current Session credential travels separately
// from the Node credential and is never copied into a response or JSON body.
func (h *Handler) relayNodeGroupBroadcastSnapshot(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	response.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if request.URL.RawQuery != "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group broadcast snapshot request"))
		return
	}
	var input fabricpkg.NodeSameGroupBroadcastV2SnapshotInput
	if err := decodeStrictClientJSON(request.Body, 2048, &input); err != nil ||
		strings.TrimSpace(input.GroupID) == "" || strings.TrimSpace(input.BroadcastID) == "" {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group broadcast snapshot request"))
		return
	}
	// Match the local Node authorization contract: keep the session secret in
	// its own header, separate from the Node bearer and body fields.
	sessionToken := strings.TrimSpace(request.Header.Get("X-Cicada-Session"))
	if !strings.HasPrefix(sessionToken, "cicada_session_") || strings.ContainsAny(sessionToken, " \t\r\n,") {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	snapshot, err := h.fabricService.CreateNodeSameGroupBroadcastV2Snapshot(nodeToken, sessionToken, input)
	if err != nil {
		// Group, sender binding, grants, readiness and replay conflicts must not
		// reveal whether a broadcast or membership exists to this Node.
		writeError(response, http.StatusNotFound, errors.New("same-Group broadcast snapshot unavailable"))
		return
	}
	hubID, err := h.fabricService.ClientHubID()
	if err != nil || strings.TrimSpace(hubID) == "" {
		writeError(response, http.StatusInternalServerError, errors.New("same-Group broadcast snapshot unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, struct {
		HubID    string                              `json:"hub_id"`
		Snapshot *store.SameGroupBroadcastV2Snapshot `json:"snapshot"`
	}{HubID: hubID, Snapshot: snapshot})
}
