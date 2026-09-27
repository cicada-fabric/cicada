package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/store"
)

// clientRPCRecover accepts the exact original signed request packet. It never
// dispatches that request again. All identity and replay checks use the same
// durable device binding as the ordinary encrypted RPC ingress.
func (h *Handler) clientRPCRecover(response http.ResponseWriter, request *http.Request) {
	data, err := io.ReadAll(io.LimitReader(request.Body, maxClientPacketBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxClientPacketBytes {
		writeError(response, http.StatusBadRequest, errors.New("invalid Client packet size"))
		return
	}
	var packet clientwire.Packet
	if err := decodeStrictClientJSON(bytes.NewReader(data), maxClientPacketBytes, &packet); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Client packet"))
		return
	}
	device, err := h.control.ClientDevice(packet.Route.OwnerID, packet.Route.DeviceID)
	if err != nil || device.State != store.ClientDeviceActive ||
		h.control.ValidateClientSessionOwner(packet.Route.OwnerID) != nil {
		writeError(response, http.StatusForbidden, errors.New("Client device is not authorized"))
		return
	}
	hubID, err := h.control.ClientHubID()
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, err)
		return
	}
	binding := clientwire.Binding{
		HubID: hubID, OwnerID: device.OwnerID, DeviceID: device.DeviceID,
		SessionEpoch: device.SessionEpoch, HubKeyVersion: 1,
		DeviceKeyVersion: device.KeyVersion,
	}
	opened, err := h.control.OpenClientControlPacket(device.Public, binding, data)
	if err != nil {
		writeError(response, http.StatusForbidden, errors.New("Client packet authentication failed"))
		return
	}
	digest := sha256.Sum256(data)
	requestBinding := store.AcceptClientRequestInput{
		OwnerID: device.OwnerID, DeviceID: device.DeviceID,
		SessionEpoch: opened.Route.SessionEpoch, Sequence: opened.Route.Sequence,
		OperationID: opened.Route.OperationID, CiphertextDigest: hex.EncodeToString(digest[:]),
	}
	state, err := h.control.LookupClientControlRequestRecovery(requestBinding)
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "RECOVERY_REJECTED", "error": "Client recovery was rejected by identity, replay, or request state guard"})
		return
	}
	if state.Request.Status == store.ClientRequestCompleted && len(state.Request.ResponsePacket) != 0 {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(state.Request.ResponsePacket)
		return
	}
	if state.Request.Status == store.ClientRequestProcessing {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "STILL_PROCESSING", "error": "Client operation is still processing"})
		return
	}
	if state.Request.Status != store.ClientRequestUncertain && state.Request.Status != store.ClientRequestFailed {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "RECOVERY_REJECTED", "error": "Client operation cannot be recovered"})
		return
	}
	if !state.Supported {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "RECOVERY_UNAVAILABLE", "error": "Legacy request has no durable response reservation"})
		return
	}
	if len(state.RecoveryPacket) != 0 {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(state.RecoveryPacket)
		return
	}
	sequence, err := h.control.ReserveClientControlResponseSequence(requestBinding)
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "RECOVERY_REJECTED", "error": "Client recovery sequence could not be reserved"})
		return
	}
	body, err := json.Marshal(map[string]any{
		"request_id": state.Request.ID, "operation_id": opened.Route.OperationID,
		"ok": false, "error_code": "OUTCOME_UNCERTAIN",
		"error":    "Prior operation may have taken effect; inspect authoritative state before retrying.",
		"recovery": map[string]any{"state": "UNCERTAIN", "request_sequence": opened.Route.Sequence},
	})
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	responseRoute := opened.Route
	responseRoute.Direction = clientwire.DirectionResponse
	responseRoute.Sequence = sequence
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	sealed, err := h.control.SealClientControlResponse(device.Public, binding, responseRoute, body)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	cached, err := h.control.CacheClientControlRecoveryPacket(requestBinding, sequence, sealed)
	if err != nil {
		writeJSON(response, http.StatusConflict, map[string]any{"code": "RECOVERY_REJECTED", "error": "Client recovery state changed"})
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(cached)
}
