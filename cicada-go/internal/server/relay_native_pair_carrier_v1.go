package server

import (
	"encoding/json"
	"errors"
	"net/http"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// Pair carriers use exactly the Marshal bytes measured by the Store writer.
// The ordinary writeJSON Encoder adds LF; at the boundary that extra byte would
// exceed the Node's complete HTTP-body limit. Legacy Group rendering is intact.
func writeSameGroupSealedV1Carrier(response http.ResponseWriter, status int, carrier any) {
	var evidence, current bool
	switch v := carrier.(type) {
	case *store.SameGroupSealedV1PeerKey:
		if v != nil {
			evidence, current = v.NativePairEvidence != nil, v.NativePairCurrent != nil
		} else {
			writeError(response, http.StatusNotFound, errors.New("current same-Group carrier unavailable"))
			return
		}
	case *store.SameGroupSealedV1DeliveryAuthorization:
		if v != nil {
			evidence, current = v.NativePairEvidence != nil, v.NativePairCurrent != nil
		} else {
			writeError(response, http.StatusNotFound, errors.New("current same-Group carrier unavailable"))
			return
		}
	default:
		writeError(response, http.StatusNotFound, errors.New("current same-Group carrier unavailable"))
		return
	}
	if !evidence && !current {
		writeJSON(response, status, carrier)
		return
	}
	encoded, err := json.Marshal(carrier)
	if !evidence || !current || err != nil || len(encoded) > wire.MaxNativePairCarrierBytes {
		writeError(response, http.StatusNotFound, errors.New("current native pair carrier unavailable"))
		return
	}
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}
