package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

// Network direct routes deliberately keep Node authority separate from the
// Network access credential. The former proves the current owner-bound Node;
// the latter selects one already enrolled Endpoint and Network.
func (h *Handler) fabricV2NetworkDirectNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	nodeToken, err := fabricpkg.NodeCredentialFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	operation := strings.TrimPrefix(r.URL.Path, "/v2/fabric/node/networks/direct/")
	switch operation {
	case "send":
		var input fabricpkg.NetworkDirectSendInput
		if err := decodeStrictClientJSON(r.Body, 256*1024, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct send"))
			return
		}
		value, err := h.fabricService.SendNetworkDirectSealed(nodeToken, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, value)
	case "collaboration-send":
		var input fabricpkg.NetworkCollaborationSendInput
		if err := decodeStrictClientJSON(r.Body, 256*1024, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network collaboration send"))
			return
		}
		value, err := h.fabricService.SendNetworkCollaborationSealed(nodeToken, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, value)
	case "ask":
		var input fabricpkg.NetworkDirectAskInput
		if err := decodeStrictClientJSON(r.Body, 256*1024, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct ask"))
			return
		}
		value, err := h.fabricService.AskNetworkDirectSealed(nodeToken, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, value)
	case "reply":
		var input fabricpkg.NetworkDirectReplyInput
		if err := decodeStrictClientJSON(r.Body, 256*1024, &input); err != nil {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct reply"))
			return
		}
		value, err := h.fabricService.ReplyNetworkDirectSealed(nodeToken, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, value)
	case "claim":
		var input struct {
			NodeID string `json:"node_id"`
			fabricpkg.NodeClaimInput
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.NodeID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct claim"))
			return
		}
		value, err := h.fabricService.ClaimNetworkDirectSealed(nodeToken, input.NodeID, input.NodeClaimInput)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deliveries": value})
	case "authorize":
		var input struct {
			MessageID string `json:"message_id"`
			AttemptID string `json:"attempt_id"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.MessageID == "" || input.AttemptID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct authorization"))
			return
		}
		value, err := h.fabricService.AuthorizeNetworkDirectDelivery(nodeToken, input.MessageID, input.AttemptID)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "receipt":
		var input fabricpkg.NodeReceiptInput
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.AttemptID == "" || input.MessageID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct receipt"))
			return
		}
		receipt, err := h.fabricService.RecordNetworkDirectReceipt(nodeToken, input)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, receipt)
	case "reply-route":
		var input struct {
			NetworkID           string `json:"network_id"`
			NetworkSessionToken string `json:"network_session_token"`
			RequestID           string `json:"request_id"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.NetworkID == "" || input.NetworkSessionToken == "" || input.RequestID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network direct reply route"))
			return
		}
		value, err := h.fabricService.NetworkDirectReplyPeerKey(nodeToken, input.NetworkSessionToken, input.NetworkID, input.RequestID)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	default:
		writeError(w, http.StatusNotFound, errors.New("Network route not found"))
	}
}

func (h *Handler) fabricV2NetworkDirectSession(w http.ResponseWriter, r *http.Request, networkID, operation string) {
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
	case "native-binding":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		value, err := h.fabricService.NetworkDirectNativeBinding(actor)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "key-candidate":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Attestation []byte `json:"attestation"`
		}
		if err := decodeStrictClientJSON(r.Body, 64*1024, &input); err != nil || len(input.Attestation) == 0 {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network key candidate"))
			return
		}
		value, err := h.fabricService.PublishNetworkDirectKeyCandidate(actor, input.Attestation)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, value)
	case "peer-key":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			TargetEndpointID string `json:"target_endpoint_id"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.TargetEndpointID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network peer key request"))
			return
		}
		value, err := h.fabricService.NetworkDirectPeerKey(actor, input.TargetEndpointID)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "collaboration-peer-key":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			TargetEndpointID string `json:"target_endpoint_id"`
			Purpose          string `json:"purpose"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil ||
			input.TargetEndpointID == "" || (input.Purpose != "TASK" && input.Purpose != "BROADCAST") {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network collaboration peer key request"))
			return
		}
		value, err := h.fabricService.NetworkCollaborationPeerKey(actor, input.TargetEndpointID, input.Purpose)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "request-status":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		requestID := r.URL.Query().Get("request_id")
		if requestID == "" {
			writeError(w, http.StatusBadRequest, errors.New("request_id is required"))
			return
		}
		value, err := h.fabricService.NetworkDirectRequestStatus(actor, requestID)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	case "request-cancel":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			RequestID string `json:"request_id"`
			Reason    string `json:"reason"`
		}
		if err := decodeStrictClientJSON(r.Body, 4096, &input); err != nil || input.RequestID == "" {
			writeError(w, http.StatusBadRequest, errors.New("invalid Network request cancellation"))
			return
		}
		value, err := h.fabricService.CancelNetworkDirectRequest(actor, input.RequestID, input.Reason)
		if err != nil {
			networkV2Error(w, err)
			return
		}
		writeJSON(w, http.StatusOK, value)
	default:
		writeError(w, http.StatusNotFound, errors.New("Network route not found"))
	}
}
