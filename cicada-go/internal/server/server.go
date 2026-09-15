// Package server exposes the small language-neutral Control API.
package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

type Handler struct {
	control *control.Control
}

func NewHandler(controlPlane *control.Control) http.Handler {
	return &Handler{control: controlPlane}
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if request.URL.Path == "/" {
		serveClient(response, request)
		return
	}
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, map[string]any{"status": "ok", "service": "cicada-control", "version": buildinfo.Version, "stage": buildinfo.Stage})
		return
	}
	if request.URL.Path == "/v1/machines" {
		h.machines(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/machines/") {
		h.machine(response, request)
		return
	}
	if request.URL.Path == "/v1/workers" && request.Method == http.MethodGet {
		workers, err := h.control.Workers()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"workers": workers})
		return
	}
	if request.URL.Path == "/v1/approvals" && request.Method == http.MethodGet {
		pendingOnly := request.URL.Query().Get("pending") != "false"
		approvals, err := h.control.Approvals(pendingOnly)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"approvals": approvals})
		return
	}
	if request.URL.Path == "/v1/threads/messages" && request.Method == http.MethodPost {
		var input struct {
			FromWorkerID string `json:"from_worker_id"`
			ToWorkerID   string `json:"to_worker_id"`
			Message      string `json:"message"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		message, err := h.control.SendThreadMessage(input.FromWorkerID, input.ToWorkerID, input.Message)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, message)
		return
	}
	if request.URL.Path == "/v1/identity" && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, h.control.Identity())
		return
	}
	if request.URL.Path == "/v1/contacts" {
		h.contacts(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/contacts/") {
		h.contact(response, request)
		return
	}
	if request.URL.Path == "/v1/permissions" {
		h.permissions(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/permissions/") {
		h.permission(response, request)
		return
	}
	if request.URL.Path == "/v1/peer-messages" {
		h.peerMessages(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/peer-messages/") {
		h.peerMessage(response, request)
		return
	}
	if request.URL.Path == "/v1/notifications" && request.Method == http.MethodGet {
		unreadOnly := request.URL.Query().Get("unread") != "false"
		notifications, err := h.control.Notifications(unreadOnly)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"notifications": notifications})
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/notifications/") && strings.HasSuffix(request.URL.Path, "/read") && request.Method == http.MethodPost {
		id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/notifications/"), "/read")
		if id == "" || strings.Contains(id, "/") {
			writeError(response, http.StatusNotFound, errors.New("notification not found"))
			return
		}
		notification, err := h.control.MarkNotificationRead(id)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, notification)
		return
	}
	if request.URL.Path == "/v1/ideas" {
		h.ideas(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/ideas/") {
		h.idea(response, request)
		return
	}
	if request.URL.Path == "/v1/memories" {
		h.memories(response, request)
		return
	}
	if request.URL.Path == "/v1/artifacts" {
		h.artifacts(response, request)
		return
	}
	if request.URL.Path == "/v1/workspaces" {
		h.workspaces(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/workspaces/") {
		h.workspace(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/approvals/") && request.Method == http.MethodPost {
		approvalID := strings.TrimPrefix(request.URL.Path, "/v1/approvals/")
		if approvalID == "" || strings.Contains(approvalID, "/") {
			writeError(response, http.StatusNotFound, errors.New("approval not found"))
			return
		}
		var input struct {
			Decision string `json:"decision"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		approval, err := h.control.ResolveApproval(approvalID, input.Decision)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, approval)
		return
	}
	if request.URL.Path == "/v1/goals" {
		h.goals(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/goals/") {
		h.goal(response, request)
		return
	}
	writeError(response, http.StatusNotFound, errors.New("route not found"))
}

func (h *Handler) workspaces(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		workspaces, err := h.control.Workspaces(request.URL.Query().Get("goal_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"workspaces": workspaces})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.WorkspaceInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	workspace, err := h.control.CreateWorkspace(input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusCreated, workspace)
}

func (h *Handler) contacts(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		contacts, err := h.control.Contacts()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"contacts": contacts})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label    string              `json:"label"`
		Identity e2ee.PublicIdentity `json:"identity"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	contact, err := h.control.CreateContact(input.Label, input.Identity)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, contact)
}

func (h *Handler) contact(response http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, "/v1/contacts/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("contact not found"))
		return
	}
	if request.Method == http.MethodGet {
		contact, err := h.control.Contact(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if contact == nil {
			writeError(response, http.StatusNotFound, errors.New("contact not found"))
			return
		}
		writeJSON(response, http.StatusOK, contact)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Label  string `json:"label"`
		Status string `json:"status"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	contact, err := h.control.UpdateContact(id, input.Label, input.Status)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, contact)
}

func (h *Handler) permissions(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		permissions, err := h.control.Permissions(request.URL.Query().Get("subject_type"), request.URL.Query().Get("subject_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"permissions": permissions})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.PermissionInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	permission, err := h.control.SetPermission(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusOK, permission)
}

func (h *Handler) permission(response http.ResponseWriter, request *http.Request) {
	id := strings.TrimPrefix(request.URL.Path, "/v1/permissions/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("permission not found"))
		return
	}
	if request.Method == http.MethodGet {
		permission, err := h.control.Permission(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if permission == nil {
			writeError(response, http.StatusNotFound, errors.New("permission not found"))
			return
		}
		writeJSON(response, http.StatusOK, permission)
		return
	}
	if request.Method != http.MethodDelete {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if err := h.control.DeletePermission(id); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *Handler) peerMessages(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		messages, err := h.control.PeerMessages(request.URL.Query().Get("contact_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"messages": messages})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		ContactID string          `json:"contact_id"`
		Message   string          `json:"message"`
		Envelope  json.RawMessage `json:"envelope"`
		AAD       string          `json:"aad"`
		AADBase64 string          `json:"aad_base64"`
		Direction string          `json:"direction"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	if input.Direction == "inbound" {
		aad := []byte(input.AAD)
		if input.AADBase64 != "" {
			decoded, decodeErr := base64.RawStdEncoding.DecodeString(input.AADBase64)
			if decodeErr != nil {
				writeError(response, http.StatusBadRequest, fmt.Errorf("invalid aad_base64: %w", decodeErr))
				return
			}
			aad = decoded
		}
		plaintext, stored, err := h.control.ReceivePeerMessage(input.ContactID, input.Envelope, aad)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, map[string]any{"message": stored, "plaintext": string(plaintext)})
		return
	}
	message, err := h.control.SendPeerMessage(input.ContactID, input.Message, []byte(input.AAD))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
			status = http.StatusForbidden
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusAccepted, message)
}

func (h *Handler) peerMessage(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	path := strings.TrimPrefix(request.URL.Path, "/v1/peer-messages/")
	if !strings.HasSuffix(path, "/deliver") {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	id := strings.TrimSuffix(path, "/deliver")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("peer message not found"))
		return
	}
	message, err := h.control.DeliverPeerMessage(id)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusAccepted, message)
}

func (h *Handler) ideas(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		ideas, err := h.control.Ideas(request.URL.Query().Get("status"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"ideas": ideas})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.IdeaInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	idea, err := h.control.CreateIdea(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, idea)
}

func (h *Handler) idea(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/ideas/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("idea id is required"))
		return
	}
	id := parts[0]
	if len(parts) == 2 && parts[1] == "promote" && request.Method == http.MethodPost {
		var input control.GoalInput
		if request.ContentLength != 0 {
			if err := readJSON(request, &input); err != nil {
				writeError(response, http.StatusBadRequest, err)
				return
			}
		}
		goal, err := h.control.PromoteIdea(id, input)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusCreated, goal)
		return
	}
	if len(parts) == 2 && parts[1] == "research" && request.Method == http.MethodPost {
		goal, err := h.control.ResearchIdea(id)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, goal)
		return
	}
	if len(parts) != 1 {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	if request.Method == http.MethodGet {
		idea, err := h.control.Idea(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if idea == nil {
			writeError(response, http.StatusNotFound, errors.New("idea not found"))
			return
		}
		writeJSON(response, http.StatusOK, idea)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Status      string `json:"status"`
		Rationale   string `json:"rationale"`
		RevisitWhen string `json:"revisit_when"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	idea, err := h.control.UpdateIdea(id, input.Status, input.Rationale, input.RevisitWhen)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, idea)
}

func (h *Handler) memories(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		memories, err := h.control.Memories(request.URL.Query().Get("scope"), request.URL.Query().Get("namespace"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"memories": memories})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var memory store.Memory
	if err := readJSON(request, &memory); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	created, err := h.control.CreateMemory(memory)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, created)
}

func (h *Handler) artifacts(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		artifacts, err := h.control.Artifacts(request.URL.Query().Get("goal_id"))
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"artifacts": artifacts})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var artifact store.Artifact
	if err := readJSON(request, &artifact); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	created, err := h.control.CreateArtifact(artifact)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusCreated, created)
}

func (h *Handler) workspace(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/workspaces/"), "/")
	id := parts[0]
	if id == "" {
		writeError(response, http.StatusNotFound, errors.New("workspace not found"))
		return
	}
	if len(parts) == 2 && parts[1] == "actions" && request.Method == http.MethodPost {
		var input struct {
			Action     string `json:"action"`
			TargetPath string `json:"target_path"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		workspace, err := h.control.WorkspaceAction(id, input.Action, input.TargetPath)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			} else if errors.Is(err, control.ErrPermissionDenied) || errors.Is(err, control.ErrPermissionApproval) {
				status = http.StatusForbidden
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusOK, workspace)
		return
	}
	if len(parts) != 1 {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	if request.Method == http.MethodGet {
		workspace, err := h.control.Workspace(id)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if workspace == nil {
			writeError(response, http.StatusNotFound, errors.New("workspace not found"))
			return
		}
		writeJSON(response, http.StatusOK, workspace)
		return
	}
	if request.Method != http.MethodPatch {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		Status   string `json:"status"`
		Revision string `json:"revision"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	workspace, err := h.control.UpdateWorkspace(id, input.Status, input.Revision)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, workspace)
}

func (h *Handler) machines(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		machines, err := h.control.Machines()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"machines": machines})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input struct {
		ID           string         `json:"id"`
		Name         string         `json:"name"`
		Status       string         `json:"status"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	if input.ID == "" || input.Name == "" {
		writeError(response, http.StatusBadRequest, errors.New("id and name are required"))
		return
	}
	if input.Status == "" {
		input.Status = "available"
	}
	// Machine registration is intentionally idempotent. The local machine
	// records are created at Control startup; future agents use this endpoint.
	registered, err := h.control.RegisterMachine(input.ID, input.Name, input.Capabilities, input.Status)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, registered)
}

func (h *Handler) machine(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/machines/"), "/")
	if len(parts) != 2 || parts[1] != "heartbeat" || request.Method != http.MethodPost || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("machine heartbeat route not found"))
		return
	}
	var input struct {
		Status       string         `json:"status"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	machine, err := h.control.HeartbeatMachine(parts[0], input.Status, input.Capabilities)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(response, status, err)
		return
	}
	writeJSON(response, http.StatusOK, machine)
}

func (h *Handler) goals(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		goals, err := h.control.Goals()
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"goals": goals})
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.GoalInput
	if err := readJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	goal, err := h.control.CreateGoal(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, goal)
}

func (h *Handler) goal(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/goals/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, errors.New("goal id is required"))
		return
	}
	goalID := parts[0]
	if len(parts) == 2 && parts[1] == "events" && request.Method == http.MethodGet {
		after, _ := strconv.ParseInt(request.URL.Query().Get("after"), 10, 64)
		events, err := h.control.Events(goalID, after)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"events": events})
		return
	}
	if len(parts) == 2 && parts[1] == "workers" {
		if request.Method == http.MethodGet {
			goal, err := h.control.Goal(goalID)
			if err != nil {
				writeError(response, http.StatusInternalServerError, err)
				return
			}
			if goal == nil {
				writeError(response, http.StatusNotFound, errors.New("goal not found"))
				return
			}
			writeJSON(response, http.StatusOK, map[string]any{"workers": goal.Workers})
			return
		}
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input control.WorkerInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		worker, err := h.control.AddWorker(goalID, input)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, worker)
		return
	}
	if len(parts) == 2 && parts[1] == "commands" && request.Method == http.MethodPost {
		var input struct {
			Command string `json:"command"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		command, err := h.control.SendCommand(goalID, input.Command)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, command)
		return
	}
	if len(parts) == 2 && parts[1] == "stop" && request.Method == http.MethodPost {
		goal, err := h.control.StopGoal(goalID)
		if err != nil {
			writeError(response, http.StatusInternalServerError, err)
			return
		}
		if goal == nil {
			writeError(response, http.StatusNotFound, errors.New("goal not found"))
			return
		}
		writeJSON(response, http.StatusOK, goal)
		return
	}
	if len(parts) != 1 || request.Method != http.MethodGet {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	goal, err := h.control.Goal(goalID)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if goal == nil {
		writeError(response, http.StatusNotFound, errors.New("goal not found"))
		return
	}
	writeJSON(response, http.StatusOK, goal)
}

func readJSON(request *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(request.Body, 2<<20+1))
	if len(data) > 2<<20 {
		return errors.New("request body exceeds 2 MiB")
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, err error) {
	message := err.Error()
	if status >= 500 {
		message = "internal server error"
	}
	writeJSON(response, status, map[string]any{"error": message})
}
