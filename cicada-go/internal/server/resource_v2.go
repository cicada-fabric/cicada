package server

import (
	"errors"
	"net/http"
	"strings"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func (h *Handler) resourceManagementV2(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("control management is unavailable"))
		return
	}
	if request.URL.Path == "/v1/resource-leases" && request.Method == http.MethodPost {
		var input store.ResourceLeaseRequest
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		lease, err := h.control.AcquireResourceLease(input)
		if err != nil {
			resourceV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusCreated, lease)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/resource-leases/") && request.Method == http.MethodGet {
		id := strings.TrimPrefix(request.URL.Path, "/v1/resource-leases/")
		if id == "" || strings.Contains(id, "/") {
			writeError(response, http.StatusNotFound, errors.New("lease not found"))
			return
		}
		lease, err := h.control.ResourceLease(id)
		if err != nil {
			resourceV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, lease)
		return
	}
	if request.URL.Path == "/v1/resources/reconcile" && request.Method == http.MethodPost {
		var input struct {
			ResourceID       string `json:"resource_id"`
			FencingEpoch     int64  `json:"fencing_epoch"`
			StoppedConfirmed bool   `json:"stopped_confirmed"`
			Evidence         string `json:"evidence"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		if err := h.control.ReconcileResourceLease(input.ResourceID, input.FencingEpoch, input.StoppedConfirmed, input.Evidence); err != nil {
			resourceV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]string{"state": store.ResourceAvailable})
		return
	}
	writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func (h *Handler) fabricV2ResourceLease(response http.ResponseWriter, request *http.Request, actor fabricpkg.Actor) {
	path := strings.TrimPrefix(request.URL.Path, "/v2/fabric/leases/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || request.Method != http.MethodPost {
		writeError(response, http.StatusNotFound, errors.New("lease route not found"))
		return
	}
	switch parts[1] {
	case "renew":
		var input struct {
			FencingEpoch int64 `json:"fencing_epoch"`
			TTLSeconds   int   `json:"ttl_seconds"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		lease, err := h.fabricService.RenewResourceLease(actor, parts[0], input.FencingEpoch, input.TTLSeconds)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, lease)
	case "quarantine":
		var input struct {
			FencingEpoch int64 `json:"fencing_epoch"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		lease, err := h.fabricService.QuarantineResourceLease(actor, parts[0], input.FencingEpoch)
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, lease)
	case "write-managed-blob":
		var input struct {
			FencingEpoch int64  `json:"fencing_epoch"`
			Value        string `json:"value"`
		}
		if err := readJSON(request, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		digest, err := h.fabricService.WriteManagedBlob(actor, parts[0], input.FencingEpoch, []byte(input.Value))
		if err != nil {
			fabricV2Error(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]string{"digest": digest})
	default:
		writeError(response, http.StatusNotFound, errors.New("lease route not found"))
	}
}

func resourceV2Error(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, store.ErrResourceBusy), errors.Is(err, store.ErrResourceStaleEpoch), errors.Is(err, store.ErrResourceLeaseExpired), errors.Is(err, store.ErrSharedTaskStaleOwner):
		status = http.StatusConflict
	case errors.Is(err, store.ErrResourceLeaseNotFound), errors.Is(err, store.ErrSharedTaskNotFound):
		status = http.StatusNotFound
	}
	writeError(response, status, err)
}
