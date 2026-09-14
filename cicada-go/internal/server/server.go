// Package server exposes the small language-neutral Control API.
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
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
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		writeJSON(response, http.StatusOK, map[string]any{"status": "ok", "service": "cicada-control", "version": "0.1.0"})
		return
	}
	if request.URL.Path == "/v1/machines" {
		h.machines(response, request)
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
			}
			writeError(response, status, err)
			return
		}
		writeJSON(response, http.StatusAccepted, message)
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
