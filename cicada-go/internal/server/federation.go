package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

type federationMessageInput struct {
	ID          string          `json:"id"`
	ContactID   string          `json:"contact_id"`
	SenderID    string          `json:"sender_id"`
	RecipientID string          `json:"recipient_id"`
	Sequence    uint64          `json:"sequence"`
	Envelope    json.RawMessage `json:"envelope"`
	AADBase64   string          `json:"aad_base64"`
}

func (h *Handler) federationMessages(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input federationMessageInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	aad, err := base64.RawStdEncoding.DecodeString(input.AADBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid aad_base64"))
		return
	}
	receipt, err := h.control.ReceiveFederatedPeerMessage(
		input.ID, input.SenderID, input.RecipientID, input.Sequence, input.Envelope, aad,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(response, http.StatusForbidden, errors.New("federation sender is not trusted"))
			return
		}
		status := http.StatusBadRequest
		if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
			status = http.StatusForbidden
		} else if errors.Is(err, store.ErrPeerReplay) {
			status = http.StatusConflict
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusAccepted, receipt)
}
