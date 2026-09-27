package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const relayNodeGroupSealedPrefix = "/v2/relay/nodes/"

func isRelayNodeGroupSealedV2Path(path string) bool {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(path, relayNodeGroupSealedPrefix), "/"), "/")
	return strings.HasPrefix(path, relayNodeGroupSealedPrefix) && len(parts) >= 4 &&
		parts[0] != "" && parts[1] == "group" && parts[2] == "sealed"
}

// relayNodeGroupSealedV2 is an opaque Node-only transport for same-Group
// cross-Node SEND/ASK/REPLY. Every route uses CicadaNode credentials; it never
// calls Control business methods or accepts plaintext peer content.
func (h *Handler) relayNodeGroupSealedV2(response http.ResponseWriter,
	request *http.Request) {
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(request.URL.Path,
		relayNodeGroupSealedPrefix), "/"), "/")
	if len(parts) < 4 || parts[0] == "" || parts[1] != "group" || parts[2] != "sealed" {
		writeError(response, http.StatusNotFound, errors.New("Group sealed Node route not found"))
		return
	}
	nodeID := parts[0]
	nodeToken, err := fabricpkg.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	authenticatedNodeID, err := h.fabricService.AuthenticateNode(nodeToken)
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	if authenticatedNodeID != nodeID {
		writeError(response, http.StatusForbidden, fabricpkg.ErrPermissionDenied)
		return
	}
	path := parts[3:]
	if len(path) == 1 {
		switch path[0] {
		case "send":
			h.relayNodeGroupSealedSend(response, request, nodeToken)
			return
		case "ask":
			h.relayNodeGroupSealedAsk(response, request, nodeToken)
			return
		case "reply":
			h.relayNodeGroupSealedReply(response, request, nodeToken)
			return
		case "claim":
			h.relayNodeGroupSealedClaim(response, request, nodeID, nodeToken)
			return
		case "peer-key":
			h.relayNodeGroupSealedPeerKey(response, request, nodeToken)
			return
		}
	}
	if len(path) == 2 && path[0] == "requests" && path[1] != "" {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		status, err := h.fabricService.NodeSameGroupSealedV1RequestStatus(nodeToken, path[1])
		if err != nil {
			if sameGroupSealedUnavailable(err) {
				writeError(response, http.StatusNotFound, errors.New("same-Group sealed request status unavailable"))
			} else {
				writeError(response, http.StatusInternalServerError, errors.New("same-Group sealed request status failed"))
			}
			return
		}
		writeJSON(response, http.StatusOK, status)
		return
	}
	if len(path) == 3 && path[0] == "requests" && path[1] != "" && path[2] == "cancel" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct{}
		if err := decodeStrictClientJSON(request.Body, 1024, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid same-Group sealed request cancellation"))
			return
		}
		status, err := h.fabricService.CancelNodeSameGroupSealedV1Request(nodeToken, path[1])
		if err != nil {
			relayNodeSameGroupSealedWriteError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, status)
		return
	}
	if len(path) == 3 && path[0] == "deliveries" && path[1] != "" && path[2] == "authorization" {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		query, ok := exactQuery(request, "attempt_id")
		if !ok || query.Get("attempt_id") == "" {
			writeError(response, http.StatusBadRequest, errors.New("attempt_id is required"))
			return
		}
		authorization, err := h.fabricService.AuthorizeNodeSameGroupSealedV1Delivery(
			nodeToken, path[1], query.Get("attempt_id"))
		if err != nil {
			if sameGroupSealedUnavailable(err) {
				writeError(response, http.StatusNotFound, errors.New("current same-Group delivery authorization unavailable"))
			} else {
				writeError(response, http.StatusInternalServerError, errors.New("same-Group delivery authorization failed"))
			}
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusOK, authorization)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("same-Group sealed Node route not found"))
}

func (h *Handler) relayNodeGroupSealedSend(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input fabricpkg.NodeSameGroupSealedV1SendInput
	if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
		input.GroupID == "" || input.SourceEndpointID == "" || input.TargetEndpointID == "" ||
		input.MessageID == "" || input.DataScope != store.SameGroupSealedV1DataScope || len(input.Ciphertext) == 0 {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group sealed SEND"))
		return
	}
	record, err := h.fabricService.SendNodeSameGroupSealedV1Message(nodeToken, input)
	if err != nil {
		relayNodeSameGroupSealedWriteError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]any{
		"message_id": record.Route.MessageID, "payload_mode": record.PayloadMode,
		"outbox_state": record.OutboxState, "sequence": record.Sequence,
	})
}

func (h *Handler) relayNodeGroupSealedAsk(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input fabricpkg.NodeSameGroupSealedV1AskInput
	if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
		input.GroupID == "" || input.SourceEndpointID == "" || input.TargetEndpointID == "" ||
		input.MessageID == "" || input.RequestID == "" || input.DataScope != store.SameGroupSealedV1DataScope ||
		input.ExpiresAt == "" || len(input.Ciphertext) == 0 {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group sealed ASK"))
		return
	}
	if expiry, err := time.Parse(time.RFC3339Nano, input.ExpiresAt); err != nil || !expiry.After(time.Now().UTC()) {
		writeError(response, http.StatusBadRequest, errors.New("same-Group sealed ASK expiry must be a future RFC3339Nano timestamp"))
		return
	}
	requestState, err := h.fabricService.AskNodeSameGroupSealedV1Message(nodeToken, input)
	if err != nil {
		relayNodeSameGroupSealedWriteError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]any{
		"request_id": requestState.RequestID, "message_id": requestState.MessageID,
		"state": requestState.State, "expires_at": requestState.ExpiresAt,
		"reply_mode": "asynchronous", "payload_mode": store.RelayPayloadModeSealedV1,
	})
}

func (h *Handler) relayNodeGroupSealedReply(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input fabricpkg.NodeSameGroupSealedV1ReplyInput
	if err := decodeStrictClientJSON(request.Body, 512*1024, &input); err != nil ||
		input.RequestID == "" || input.MessageID == "" || len(input.Ciphertext) == 0 {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group sealed REPLY"))
		return
	}
	requestState, err := h.fabricService.ReplyNodeSameGroupSealedV1Message(nodeToken, input)
	if err != nil {
		relayNodeSameGroupSealedWriteError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]any{
		"request_id": requestState.RequestID, "message_id": input.MessageID,
		"state": requestState.State, "payload_mode": store.RelayPayloadModeSealedV1,
	})
}

func (h *Handler) relayNodeGroupSealedClaim(response http.ResponseWriter,
	request *http.Request, nodeID, nodeToken string) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input fabricpkg.NodeClaimInput
	if err := decodeStrictClientJSON(request.Body, 4096, &input); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid same-Group sealed Node claim"))
		return
	}
	deliveries, err := h.fabricService.ClaimNodeSameGroupSealedV1Deliveries(nodeToken, nodeID, input)
	if err != nil {
		relayNodeSameGroupSealedWriteError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"deliveries": deliveries})
}

func (h *Handler) relayNodeGroupSealedPeerKey(response http.ResponseWriter,
	request *http.Request, nodeToken string) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	query, ok := exactQuery(request, "group_id", "source_endpoint_id", "target_endpoint_id")
	if !ok || query.Get("group_id") == "" || query.Get("source_endpoint_id") == "" || query.Get("target_endpoint_id") == "" {
		writeError(response, http.StatusBadRequest, errors.New("group_id, source_endpoint_id, and target_endpoint_id are required"))
		return
	}
	evidence, err := h.fabricService.NodeSameGroupSealedV1PeerKey(nodeToken,
		query.Get("group_id"), query.Get("source_endpoint_id"), query.Get("target_endpoint_id"))
	if err != nil {
		if sameGroupSealedUnavailable(err) {
			writeError(response, http.StatusNotFound, errors.New("current same-Group peer key evidence unavailable"))
		} else {
			writeError(response, http.StatusInternalServerError, errors.New("same-Group peer key lookup failed"))
		}
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusOK, evidence)
}

func relayNodeSameGroupSealedWriteError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fabricpkg.ErrUnauthenticated):
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
	case errors.Is(err, store.ErrSameGroupSealedV1Denied):
		writeError(response, http.StatusForbidden, errors.New("same-Group sealed action is not authorized"))
	case errors.Is(err, store.ErrSameGroupSealedV1NotFound):
		writeError(response, http.StatusNotFound, errors.New("same-Group sealed request is unavailable"))
	case errors.Is(err, store.ErrRelayResourceExhausted):
		var limit *store.RelayAdmissionError
		if errors.As(err, &limit) && limit.RetryAfterSeconds > 0 {
			response.Header().Set("Retry-After", strconv.Itoa(limit.RetryAfterSeconds))
		}
		writeError(response, http.StatusTooManyRequests, err)
	case errors.Is(err, store.ErrRelayIdempotencyConflict),
		errors.Is(err, store.ErrRelayMessageConflict),
		errors.Is(err, store.ErrRelayRequestTerminal):
		writeError(response, http.StatusConflict, err)
	default:
		writeError(response, http.StatusInternalServerError, errors.New("same-Group sealed action could not be accepted"))
	}
}

func sameGroupSealedUnavailable(err error) bool {
	return errors.Is(err, store.ErrSameGroupSealedV1Denied) ||
		errors.Is(err, store.ErrSameGroupSealedV1NotFound)
}

func exactQuery(request *http.Request, allowed ...string) (url.Values, bool) {
	query := request.URL.Query()
	if len(query) != len(allowed) {
		return nil, false
	}
	for _, key := range allowed {
		values, ok := query[key]
		if !ok || len(values) != 1 {
			return nil, false
		}
	}
	return query, true
}
