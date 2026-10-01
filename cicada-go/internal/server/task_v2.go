package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
)

const retiredPeerTaskHandoffMessage = "Thread-to-Thread plaintext Task handoffs are retired; use sealed cicada_send and explicitly authorized Artifact references. This does not transfer Task responsibility or stop resources."

func (h *Handler) fabricV2Task(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	path := strings.TrimPrefix(request.URL.Path, "/v2/fabric/tasks")
	if strings.HasPrefix(path, "/sealed-handoffs") {
		h.fabricV2SealedTaskHandoff(response, request, actor, strings.TrimPrefix(path, "/sealed-handoffs"))
		return
	}
	if path == "/handoffs" && request.Method == http.MethodPost {
		writeError(response, http.StatusGone, errors.New(retiredPeerTaskHandoffMessage))
		return
	}
	if strings.HasPrefix(path, "/handoffs/") {
		parts := strings.Split(strings.TrimPrefix(path, "/handoffs/"), "/")
		if (len(parts) == 1 && parts[0] != "" && request.Method == http.MethodGet) ||
			(len(parts) == 2 && parts[0] != "" && parts[1] == "accept" && request.Method == http.MethodPost) {
			writeError(response, http.StatusGone, errors.New(retiredPeerTaskHandoffMessage))
			return
		}
		writeError(response, http.StatusNotFound, errors.New("task handoff route not found"))
		return
	}
	if path == "" && request.Method == http.MethodGet {
		tasks, err := h.fabricService.ListTasks(actor, queryInt(request, "limit", 100))
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"tasks": tasks})
		return
	}
	if request.Method == http.MethodGet && strings.HasPrefix(path, "/") && !strings.Contains(strings.TrimPrefix(path, "/"), "/") {
		task, err := h.fabricService.GetTask(actor, strings.TrimPrefix(path, "/"))
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	switch path {
	case "/claim":
		var input fabricpkg.TaskClaimInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.fabricService.ClaimTask(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	case "/release":
		var input fabricpkg.TaskReleaseInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.fabricService.ReleaseTask(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	case "/renew":
		var input fabricpkg.TaskRenewInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.fabricService.RenewTask(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	case "/result":
		var input fabricpkg.TaskResultInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		result, err := h.fabricService.SubmitTaskResult(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusAccepted, result)
	case "/accept":
		var input fabricpkg.TaskAcceptInput
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		task, err := h.fabricService.AcceptTaskResult(actor, input)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, task)
	default:
		writeError(response, http.StatusNotFound, errors.New("task route not found"))
	}
}
