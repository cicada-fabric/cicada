package server

import (
	"errors"
	"net/http"

	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

type NodeTLSCurrentReader func(credentialDigest, nodeID string, packet []byte) ([]byte, error)

func (h *Handler) nodeTLSCurrentStatus(w http.ResponseWriter, r *http.Request, credential, nodeID string, packet []byte) {
	if h.nodeTLSCurrent == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("current Node TLS authority is unavailable"))
		return
	}
	check, strict := r.Context().Value(nodeTransportCheckKey{}).(nodeTransportCheck)
	if _, err := pqtls.StateFromContext(r.Context()); err != nil || !strict || !check() {
		writeError(w, http.StatusForbidden, errors.New("enrolled Node PQ transport is required"))
		return
	}
	reply, err := h.nodeTLSCurrent(credential, nodeID, packet)
	if err != nil || len(reply) == 0 || len(reply) > nodewire.MaxTLSCurrentPacketBytes {
		writeError(w, http.StatusForbidden, errors.New("fresh current Node TLS authority could not be authenticated"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(reply)
}
