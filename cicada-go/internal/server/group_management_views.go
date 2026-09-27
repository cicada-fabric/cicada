package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/store"
)

type representativeRequestManagementView struct {
	store.FederationRequest
	ReceiptState string `json:"receipt_state"`
}

func (h *Handler) groupRepresentativeRequests(response http.ResponseWriter, request *http.Request, groupID string, remainder []string) {
	if len(remainder) != 0 {
		writeError(response, http.StatusNotFound, errors.New("representative request route not found"))
		return
	}
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	requests, err := h.control.FederationRequestsForGroup(groupID, queryInt(request, "limit", 100))
	if err != nil {
		managementError(response, err)
		return
	}
	view := make([]representativeRequestManagementView, 0, len(requests))
	for _, item := range requests {
		// The Gateway request record is not authoritatively correlated with a
		// Relay receipt yet. Keep that uncertainty visible instead of deriving
		// delivery from the request lifecycle state.
		view = append(view, representativeRequestManagementView{
			FederationRequest: item,
			ReceiptState:      "UNKNOWN",
		})
	}
	writeJSON(response, http.StatusOK, map[string]any{"requests": view})
}
