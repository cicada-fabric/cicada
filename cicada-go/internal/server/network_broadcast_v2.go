package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// Network Broadcast metadata is separate from the per-reader sealed SENDs.
// The exact recipient snapshot must be committed only after those ciphertext
// routes have been durably enqueued; pre-publication routes remain unclaimable.
func (h *Handler) fabricV2NetworkBroadcast(w http.ResponseWriter, r *http.Request,
	networkID, operation string) {
	token, err := networkCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	actor, err := h.fabricService.AuthenticateForNetwork(token, networkID)
	if err != nil {
		networkV2Error(w, err)
		return
	}
	switch operation {
	case "preview":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		snapshot, err := h.fabricService.PreviewNetworkBroadcastRecipients(actor)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, snapshot)
	case "publish":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input store.NetworkBroadcastPublishInput
		if err := decodeStrictClientJSON(r.Body, 64*1024, &input); err != nil ||
			input.BroadcastID == "" || input.SnapshotDigest == "" || input.ExpiresAt == "" ||
			len(input.Recipients) == 0 || len(input.Recipients) > 64 {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network Broadcast publication"))
			return
		}
		broadcast, err := h.fabricService.PublishNetworkBroadcast(actor, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, broadcast)
	case "get":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		query := r.URL.Query()
		ids, exists := query["broadcast_id"]
		if !exists || len(ids) != 1 || strings.TrimSpace(ids[0]) == "" || len(ids[0]) > 96 || len(query) != 1 {
			writeError(w, http.StatusBadRequest, errors.New("one broadcast_id is required"))
			return
		}
		broadcast, err := h.fabricService.GetNetworkBroadcast(actor, ids[0])
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, broadcast)
	default:
		writeError(w, http.StatusNotFound, errors.New("Network Broadcast route not found"))
	}
}
