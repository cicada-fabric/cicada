package server

import (
	"errors"
	"io"
	"net/http"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
)

func (h *hubNodesHandler) nodePairTrustScoped(w http.ResponseWriter, r *http.Request) bool {
	if !h.account.ScopedNodeAuthorityEnabled() {
		return false
	}
	op := hubauth.NodePairTrustScopedOperationForPath(r.URL.Path)
	if op == "" {
		return false
	}
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !hubauth.NodePairTrustCredentialsAbsent(r.Header.Get("Authorization"), r.Header.Get("Cookie")) {
		writeError(w, http.StatusBadRequest, errors.New("Node pairing request rejected"))
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		expected, err := h.account.ExpectedOrigin()
		if err != nil || expected != origin {
			writeError(w, http.StatusForbidden, errors.New("Node pairing origin rejected"))
			return true
		}
	}
	limit := wire.MaxNodePairTrustScopedPacketBytes
	if op == wire.OperationNodePairTrustScopedReconcile {
		limit = wire.MaxNodePairTrustScopedReconcilePacketBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(raw) == 0 || len(raw) > limit {
		writeError(w, http.StatusBadRequest, errors.New("Node pairing packet rejected"))
		return true
	}
	packet, err := h.account.HandleNodePairTrustScoped(r.Context(), op, raw)
	if err != nil {
		if errors.Is(err, hubauth.ErrBusy) {
			writeError(w, http.StatusServiceUnavailable, errors.New("Node pairing busy"))
		} else if errors.Is(err, hubauth.ErrNodePairTrustACKRequired) {
			writeError(w, http.StatusConflict, hubauth.ErrNodePairTrustACKRequired)
		} else {
			writeError(w, http.StatusForbidden, errors.New("Node pairing request rejected"))
		}
		return true
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packet)
	return true
}
