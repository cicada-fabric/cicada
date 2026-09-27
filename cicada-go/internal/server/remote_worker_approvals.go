package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const maxNodeApprovalWait = 20 * time.Second

type nodeWorkerApprovalResponse struct {
	ApprovalID string `json:"approval_id"`
	GoalID     string `json:"goal_id"`
	WorkerID   string `json:"worker_id"`
	Attempt    int    `json:"attempt"`
	Status     string `json:"status"`
	Decision   string `json:"decision,omitempty"`
}

func (h *Handler) relayNodeWorkerApprovals(response http.ResponseWriter, request *http.Request,
	nodeID, token string, parts []string) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Control service is unavailable"))
		return
	}
	if len(parts) < 4 || len(parts) > 5 || parts[2] == "" || parts[3] != "approvals" ||
		(len(parts) == 5 && parts[4] == "") {
		writeError(response, http.StatusNotFound, errors.New("Node Worker approval route not found"))
		return
	}
	workerID := parts[2]
	digest := fabricpkg.HashSessionCredential(token)
	if len(parts) == 4 {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			Attempt   int             `json:"attempt"`
			RequestID string          `json:"request_id"`
			Method    string          `json:"method"`
			Request   json.RawMessage `json:"request"`
		}
		if err := decodeStrictClientJSON(request.Body, 64*1024+2048, &input); err != nil {
			writeError(response, http.StatusBadRequest, errors.New("invalid Node Worker approval request"))
			return
		}
		approval, created, err := h.control.CreateBoundNodeWorkerApproval(digest, nodeID, workerID,
			input.Attempt, input.RequestID, input.Method, input.Request)
		if err != nil {
			relayNodeApprovalError(response, h, nodeID, token, err)
			return
		}
		if approval == nil {
			writeError(response, http.StatusInternalServerError, errors.New("Node Worker approval could not be created"))
			return
		}
		_ = created // The durable create result is reflected by the same idempotent DTO.
		writeJSON(response, http.StatusAccepted, nodeApprovalResponse(approval))
		return
	}
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	attempt, err := strconv.Atoi(request.URL.Query().Get("attempt"))
	if err != nil || attempt <= 0 {
		writeError(response, http.StatusBadRequest, errors.New("attempt is required"))
		return
	}
	wait := maxNodeApprovalWait
	if rawWait := request.URL.Query().Get("wait_ms"); rawWait != "" {
		milliseconds, parseErr := strconv.Atoi(rawWait)
		if parseErr != nil || milliseconds < 0 || time.Duration(milliseconds)*time.Millisecond > maxNodeApprovalWait {
			writeError(response, http.StatusBadRequest, errors.New("wait_ms must be between 0 and 20000"))
			return
		}
		wait = time.Duration(milliseconds) * time.Millisecond
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		approval, lookupErr := h.control.BoundNodeWorkerApproval(digest, nodeID, workerID, attempt, parts[4])
		if lookupErr != nil {
			relayNodeApprovalError(response, h, nodeID, token, lookupErr)
			return
		}
		if approval == nil {
			writeError(response, http.StatusNotFound, errors.New("Node Worker approval is unavailable"))
			return
		}
		if approval.Status != "pending" || wait == 0 {
			writeJSON(response, http.StatusOK, nodeApprovalResponse(approval))
			return
		}
		select {
		case <-request.Context().Done():
			return
		case <-deadline.C:
			writeJSON(response, http.StatusOK, nodeApprovalResponse(approval))
			return
		case <-ticker.C:
		}
	}
}

func nodeApprovalResponse(approval *store.Approval) nodeWorkerApprovalResponse {
	return nodeWorkerApprovalResponse{
		ApprovalID: approval.ID, GoalID: approval.GoalID, WorkerID: approval.WorkerID,
		Attempt: approval.Attempt, Status: approval.Status, Decision: approval.Decision,
	}
}

func relayNodeApprovalError(response http.ResponseWriter, h *Handler, nodeID, token string, err error) {
	switch {
	case errors.Is(err, store.ErrNodeApprovalNotAuthorized), errors.Is(err, store.ErrNodeWorkerNotAuthorized):
		if !h.relayNodeCredentialCurrent(nodeID, token) {
			writeError(response, http.StatusUnauthorized, fabricpkg.ErrUnauthenticated)
			return
		}
		writeError(response, http.StatusNotFound, errors.New("Node Worker approval is unavailable"))
	case errors.Is(err, store.ErrNodeApprovalStale), errors.Is(err, store.ErrNodeApprovalConflict),
		errors.Is(err, store.ErrNodeWorkerUnavailable):
		writeError(response, http.StatusConflict, err)
	case errors.Is(err, control.ErrWorkerUnavailable):
		writeError(response, http.StatusConflict, err)
	default:
		writeError(response, http.StatusInternalServerError, errors.New("Node Worker approval could not be processed"))
	}
}

func validNodeApprovalRoute(parts []string) bool {
	return len(parts) >= 4 && len(parts) <= 5 && parts[1] == "jobs" && parts[2] != "" &&
		parts[3] == "approvals" && (len(parts) == 4 || strings.TrimSpace(parts[4]) != "")
}
