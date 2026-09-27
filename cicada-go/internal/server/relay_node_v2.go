package server

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

const relayNodeStreamRevalidateInterval = time.Second

func (h *Handler) relayNodeV2(response http.ResponseWriter, request *http.Request) {
	if h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("fabric service is unavailable"))
		return
	}
	remainder := strings.Trim(strings.TrimPrefix(request.URL.Path, "/v2/relay/nodes/"), "/")
	parts := strings.Split(remainder, "/")
	if (len(parts) != 2 && len(parts) != 4) || strings.TrimSpace(parts[0]) == "" {
		writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
		return
	}
	nodeID := parts[0]
	token, err := fabricpkg.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	authenticatedNodeID, err := h.fabricService.AuthenticateNode(token)
	if err != nil {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	if authenticatedNodeID != nodeID {
		writeError(response, http.StatusForbidden, fabricpkg.ErrPermissionDenied)
		return
	}
	if len(parts) == 4 {
		if parts[1] != "links" || parts[2] == "" || parts[3] != "authorization" || request.Method != http.MethodGet {
			writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
			return
		}
		bundle, err := h.fabricService.NodeCommunicationLinkAuthorizationBundle(token, parts[2])
		if err != nil {
			// Do not reveal whether a Link exists, expired, was revoked, or has
			// only one owner's proof to a Node without current bilateral scope.
			writeError(response, http.StatusNotFound, errors.New("current Link authorization unavailable"))
			return
		}
		writeJSON(response, http.StatusOK, bundle)
		return
	}
	switch parts[1] {
	case "heartbeat":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct{}
		if err := decodeStrictClientJSON(request.Body, 64, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("Node heartbeat body must be empty JSON object"))
			return
		}
		if err := h.fabricService.HeartbeatNode(token); err != nil {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	case "events":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		h.relayNodeEvents(response, request, nodeID, token)
	case "claim":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.NodeClaimInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		deliveries, err := h.fabricService.ClaimNodeDeliveries(nodeID, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"deliveries": deliveries})
	case "receipts":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input fabricpkg.NodeReceiptInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		receipt, err := h.fabricService.RecordNodeReceipt(nodeID, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, receipt)
	default:
		writeError(response, http.StatusNotFound, errors.New("relay node route not found"))
	}
}

// relayNodeEvents keeps a Node-initiated HTTPS connection open. Hints contain
// no message content and never replace the durable claim/receipt protocol.
func (h *Handler) relayNodeEvents(response http.ResponseWriter, request *http.Request, nodeID, token string) {
	if !h.relayNodeCredentialCurrent(nodeID, token) {
		writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
		return
	}
	flusher, ok := response.(http.Flusher)
	if !ok {
		writeError(response, http.StatusInternalServerError, errors.New("streaming is unavailable"))
		return
	}
	events, unsubscribe := h.fabricService.SubscribeNodeEvents(nodeID)
	defer unsubscribe()
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache, no-transform")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(response, "event: ready\ndata: claim\n\n"); err != nil {
		return
	}
	flusher.Flush()
	lastCredentialCheck := time.Now()
	credentialCurrentIfDue := func() bool {
		if time.Since(lastCredentialCheck) < relayNodeStreamRevalidateInterval {
			return true
		}
		lastCredentialCheck = time.Now()
		return h.relayNodeCredentialCurrent(nodeID, token)
	}
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-events:
			// An already-open stream is still an authenticated Node capability.
			// Check at most once per second during active streams so revocation
			// takes effect promptly without making wake traffic drive unbounded DB
			// reads. Idle streams are rechecked by the keepalive timer below.
			if !credentialCurrentIfDue() {
				return
			}
			if _, err := io.WriteString(response, "event: wake\ndata: claim\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-heartbeat.C:
			// Credential rotation/revocation fences an already-open stream.
			if !h.relayNodeCredentialCurrent(nodeID, token) {
				return
			}
			lastCredentialCheck = time.Now()
			if _, err := io.WriteString(response, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (h *Handler) relayNodeCredentialCurrent(nodeID, token string) bool {
	currentNode, err := h.fabricService.AuthenticateNode(token)
	return err == nil && currentNode == nodeID
}
