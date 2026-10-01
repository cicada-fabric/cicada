package server

import (
	"errors"
	"net/http"
)

// relayNodeWorkerSnapshot retires the former raw-tar management route. The
// only supported Node workspace transfer is the independently sealed,
// chunked Node-Control stream handled by relayNodeWorkerSnapshotStream.
func (h *Handler) relayNodeWorkerSnapshot(response http.ResponseWriter, request *http.Request,
	nodeID, workerID, digest, token string) {
	_ = request
	_ = nodeID
	_ = workerID
	_ = digest
	_ = token
	writeError(response, http.StatusUpgradeRequired,
		errors.New("MIGRATION_BLOCKED: raw workspace snapshot transfer is retired; use encrypted Node-Control streaming"))
}
