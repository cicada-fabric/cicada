package server

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/cicada-ai/cicada/internal/control"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type HubAccountAcceptor interface {
	Handle(context.Context, string, []byte) ([]byte, error)
	ExpectedOrigin() (string, error)
}

func NewHubHandlerWithAccount(owner *hubowner.Service, account *hubauth.Service) http.Handler {
	h := NewHubHandler(owner).(*Handler)
	h.accountAuth = account
	return h
}
func NewHandlerWithAccount(c *control.Control, account *hubauth.Service) http.Handler {
	h := NewHandler(c).(*Handler)
	h.accountAuth = account
	return h
}
func accountOperation(path string) string {
	for _, op := range []string{wire.OperationActivationPrepare, wire.OperationActivationComplete, wire.OperationActivationStatus, wire.OperationAccountReconcile} {
		if path == wire.ActivationHTTPPath(op) {
			return op
		}
	}
	switch path {
	case wire.OwnerEndpointReadPath:
		return wire.OperationOwnerEndpointRead
	case "/v2/owner/account/claim/prepare":
		return wire.OperationClaimPrepare
	case "/v2/owner/account/claim/complete":
		return wire.OperationClaimComplete
	case "/v2/owner/account/login/prepare":
		return wire.OperationLoginPrepare
	case "/v2/owner/account/login/complete":
		return wire.OperationLoginComplete
	case "/v2/owner/account/session/inspect":
		return wire.OperationSessionInspect
	case "/v2/owner/account/session/logout":
		return wire.OperationSessionLogout
	}
	return ""
}
func (h *Handler) hubAccount(response http.ResponseWriter, request *http.Request, operation string) {
	if operation == wire.OperationOwnerEndpointRead && request.Method == http.MethodGet {
		profiles := request.URL.Query()["profile"]
		if len(profiles) > 0 {
			if len(profiles) != 1 || profiles[0] != nodewire.NodeOperatorProfile {
				writeError(response, http.StatusNotFound, errors.New("directory capability profile unavailable"))
				return
			}
			provider, ok := h.accountAuth.(interface {
				NodeOperatorCapabilities() (nodewire.NodeOperatorCapabilities, error)
			})
			if !ok {
				writeError(response, http.StatusNotFound, errors.New("Node operator directory unavailable"))
				return
			}
			caps, err := provider.NodeOperatorCapabilities()
			if err != nil {
				writeError(response, http.StatusServiceUnavailable, errors.New("Node operator directory unavailable"))
				return
			}
			response.Header().Set("Cache-Control", "no-store")
			writeJSON(response, http.StatusOK, caps)
			return
		}
		provider, ok := h.accountAuth.(interface {
			OwnerEndpointReadCapabilities() (wire.OwnerEndpointReadCapabilities, error)
		})
		if !ok {
			writeError(response, http.StatusNotFound, errors.New("Owner Endpoint directory unavailable"))
			return
		}
		caps, err := provider.OwnerEndpointReadCapabilities()
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, errors.New("Owner Endpoint directory unavailable"))
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		writeJSON(response, http.StatusOK, caps)
		return
	}
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.accountAuth == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Hub account authentication unavailable"))
		return
	}
	if request.Header.Get("Origin") != "" {
		origin, e := h.accountAuth.ExpectedOrigin()
		if e != nil || origin != request.Header.Get("Origin") {
			writeError(response, http.StatusForbidden, errors.New("Hub account authentication rejected"))
			return
		}
	}
	limit := wire.MaxPacketBytes
	if wire.LocalDomainHTTPPath(operation) != "" {
		limit = wire.MaxLocalDomainOriginalBytes
		if operation == wire.OperationLocalDomainReconcile {
			limit = wire.MaxLocalDomainReconcilePacketBytes
		}
	}
	if wire.NativePairHTTPPath(operation) != "" {
		limit = wire.MaxNativePairOriginalBytes
		if operation == wire.OperationNativePairReconcile {
			limit = wire.MaxNativePairReconcilePacketBytes
		}
	}
	raw, e := io.ReadAll(http.MaxBytesReader(response, request.Body, int64(limit)))
	if e != nil {
		writeError(response, http.StatusRequestEntityTooLarge, errors.New("Hub account packet exceeds limit"))
		return
	}
	packet, e := h.accountAuth.Handle(request.Context(), operation, raw)
	if e != nil {
		if errors.Is(e, hubauth.ErrNodePairTrustACKRequired) {
			writeError(response, http.StatusConflict, hubauth.ErrNodePairTrustACKRequired)
			return
		}
		if errors.Is(e, hubauth.ErrAppNodeCounterConflict) {
			writeError(response, http.StatusConflict, hubauth.ErrAppNodeCounterConflict)
			return
		}
		status := http.StatusForbidden
		if errors.Is(e, hubauth.ErrBusy) {
			status = http.StatusTooManyRequests
			response.Header().Set("Retry-After", "1")
		}
		writeError(response, status, errors.New("Hub account authentication rejected"))
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(packet)
}
