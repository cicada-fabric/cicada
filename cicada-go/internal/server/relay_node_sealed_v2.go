package server

import (
	"errors"
	"net/http"
	"strconv"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// relayNodeSealedV2 is a Node-only opaque-byte transport. The Client never
// supplies a sender or receives peer ciphertext through its Control RPC.
func (h *Handler) relayNodeSealedV2(response http.ResponseWriter, request *http.Request, nodeID, nodeToken, action string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	switch action {
	case "send":
		var input fabricpkg.NodeSealedLinkSendInput
		if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
			input.LinkID == "" || input.MessageID == "" || input.DataScope == "" || len(input.Ciphertext) == 0 {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Link send"))
			return
		}
		record, err := h.fabricService.SendNodeSealedLinkMessage(nodeToken, input)
		if err != nil {
			if errors.Is(err, store.ErrCommunicationLinkRelayDenied) {
				writeError(response, http.StatusForbidden, errors.New("sealed Link send is not authorized"))
			} else if errors.Is(err, store.ErrRelayIdempotencyConflict) {
				writeError(response, http.StatusConflict, err)
			} else {
				writeError(response, http.StatusInternalServerError, errors.New("sealed Link send could not be accepted"))
			}
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]any{
			"message_id":   record.Route.MessageID,
			"payload_mode": record.PayloadMode,
			"outbox_state": record.OutboxState,
			"sequence":     record.Sequence,
		})
	case "ask":
		var input fabricpkg.NodeSealedLinkAskInput
		if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
			input.LinkID == "" || input.MessageID == "" || input.RequestID == "" ||
			input.DataScope == "" || input.ExpiresAt == "" || len(input.Ciphertext) == 0 {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Link ask"))
			return
		}
		requestState, err := h.fabricService.AskNodeSealedLinkMessage(nodeToken, input)
		if err != nil {
			relayNodeSealedWriteError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]any{
			"request_id": requestState.RequestID, "message_id": requestState.MessageID,
			"state": requestState.State, "expires_at": requestState.ExpiresAt,
			"reply_mode": "asynchronous", "payload_mode": store.RelayPayloadModeSealedV1,
		})
	case "reply":
		var input fabricpkg.NodeSealedLinkReplyInput
		if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
			input.RequestID == "" || input.MessageID == "" || input.DataScope == "" ||
			len(input.Ciphertext) == 0 {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Link reply"))
			return
		}
		requestState, err := h.fabricService.ReplyNodeSealedLinkMessage(nodeToken, input)
		if err != nil {
			relayNodeSealedWriteError(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]any{
			"request_id": requestState.RequestID, "message_id": input.MessageID,
			"state": requestState.State, "payload_mode": store.RelayPayloadModeSealedV1,
		})
	case "claim":
		var input fabricpkg.NodeClaimInput
		if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid sealed Node claim"))
			return
		}
		deliveries, err := h.fabricService.ClaimNodeSealedDeliveries(nodeToken, nodeID, input)
		if err != nil {
			if errors.Is(err, fabricpkg.ErrUnauthenticated) {
				writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			} else {
				writeError(response, http.StatusInternalServerError, errors.New("sealed Node claim failed"))
			}
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"deliveries": deliveries})
	default:
		writeError(response, http.StatusNotFound, errors.New("sealed Node route not found"))
	}
}

func relayNodeSealedWriteError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrCommunicationLinkRelayDenied):
		writeError(response, http.StatusForbidden, errors.New("sealed Link action is not authorized"))
	case errors.Is(err, store.ErrRelayResourceExhausted):
		var limit *store.RelayAdmissionError
		if errors.As(err, &limit) && limit.RetryAfterSeconds > 0 {
			response.Header().Set("Retry-After", strconv.Itoa(limit.RetryAfterSeconds))
		}
		writeError(response, http.StatusTooManyRequests, err)
	case errors.Is(err, store.ErrRelayIdempotencyConflict),
		errors.Is(err, store.ErrRelayMessageConflict),
		errors.Is(err, store.ErrRelayRequestTerminal),
		errors.Is(err, store.ErrRelayCausalBudget):
		writeError(response, http.StatusConflict, err)
	default:
		writeError(response, http.StatusInternalServerError, errors.New("sealed Link action could not be accepted"))
	}
}
