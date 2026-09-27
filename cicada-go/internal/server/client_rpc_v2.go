package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/store"
)

const maxClientPacketBytes = 256 * 1024

// clientRPC authenticates the device's signed PQ envelope before accepting a
// durable operation. Public route fields are indices only; authority comes
// from the stored owner grant, device key, epoch, and decrypted signature.
func (h *Handler) clientRPC(response http.ResponseWriter, request *http.Request) {
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
	route := packet.Route
	device, err := h.control.ClientDevice(route.OwnerID, route.DeviceID)
	if err != nil || device.State != store.ClientDeviceActive ||
		h.control.ValidateClientOwnerScope(route.OwnerID) != nil {
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
	accepted, err := h.control.AcceptClientControlRequest(store.AcceptClientRequestInput{
		OwnerID: device.OwnerID, DeviceID: device.DeviceID,
		SessionEpoch: opened.Route.SessionEpoch, Sequence: opened.Route.Sequence,
		OperationID: opened.Route.OperationID, CiphertextDigest: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		writeError(response, http.StatusConflict, errors.New("Client request was rejected by replay or device state guard"))
		return
	}
	if accepted.Outcome == store.ClientRequestOutcomeExactRetry {
		if len(accepted.Request.ResponsePacket) == 0 {
			writeError(response, http.StatusConflict, errors.New("Client operation is still processing or uncertain; reconcile before submitting a new action"))
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(accepted.Request.ResponsePacket)
		return
	}

	result, dispatchErr := h.dispatchClientRPC(device.OwnerID, device.DeviceID, accepted.Request.ID,
		opened.Route.Operation, opened.Plaintext)
	resultBody := map[string]any{
		"request_id":   accepted.Request.ID,
		"operation_id": opened.Route.OperationID,
		"ok":           dispatchErr == nil,
	}
	if dispatchErr == nil {
		resultBody["result"] = result
	} else {
		resultBody["error"] = dispatchErr.Error()
	}
	encoded, err := json.Marshal(resultBody)
	if err != nil {
		_, _ = h.control.FailClientControlRequest(device.OwnerID, device.DeviceID, opened.Route.OperationID)
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	sequence, err := h.control.AllocateClientControlResponseSequence(device.OwnerID, device.DeviceID, binding.SessionEpoch)
	if err != nil {
		_, _ = h.control.FailClientControlRequest(device.OwnerID, device.DeviceID, opened.Route.OperationID)
		writeError(response, http.StatusConflict, errors.New("Client device session changed before response"))
		return
	}
	responseRoute := opened.Route
	responseRoute.Direction = clientwire.DirectionResponse
	responseRoute.Sequence = sequence
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	sealed, err := h.control.SealClientControlResponse(device.Public, binding, responseRoute, encoded)
	if err != nil {
		_, _ = h.control.FailClientControlRequest(device.OwnerID, device.DeviceID, opened.Route.OperationID)
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if _, err := h.control.CompleteClientControlRequest(device.OwnerID, device.DeviceID, opened.Route.OperationID, sealed); err != nil {
		writeError(response, http.StatusConflict, errors.New("Client operation completion is uncertain"))
		return
	}
	if opened.Route.Operation == "intent.submit" && dispatchErr == nil {
		if intent, ok := result.(*store.Intent); ok {
			// The accepted response is durable before work begins. If shutdown
			// prevents launch, the QUEUED job is recovered on the next start.
			_ = h.control.DispatchClientIntentAsync(intent.ID)
		}
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(sealed)
}

func (h *Handler) dispatchClientRPC(ownerID, callerDeviceID, clientRequestID, operation string, plaintext []byte) (any, error) {
	if err := h.control.ValidateClientOwnerScope(ownerID); err != nil {
		return nil, errors.New("Client owner scope is unavailable")
	}
	switch operation {
	case "link.key_manifest":
		var input struct {
			LinkID string `json:"link_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.LinkID == "" {
			return nil, errors.New("invalid communication link key manifest request")
		}
		return h.control.ClientCommunicationLinkKeyManifest(ownerID, input.LinkID)
	case "link.key_grants":
		var input struct {
			LinkID string `json:"link_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.LinkID == "" {
			return nil, errors.New("invalid communication link key grant status request")
		}
		return h.control.ClientCommunicationLinkKeyGrants(ownerID, input.LinkID)
	case "link.key_grant":
		var input struct {
			LinkID      string `json:"link_id"`
			Side        string `json:"side"`
			OwnerKeyID  string `json:"owner_key_id"`
			SignedProof []byte `json:"signed_proof"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.LinkID == "" || input.OwnerKeyID == "" || len(input.SignedProof) == 0 {
			return nil, errors.New("invalid communication link key grant")
		}
		return h.control.ClientRecordCommunicationLinkKeyGrant(ownerID,
			input.LinkID, input.Side, input.OwnerKeyID, input.SignedProof)
	case "nodes.preview":
		var input struct {
			UserCode string `json:"user_code"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.UserCode == "" {
			return nil, errors.New("invalid Node device code preview")
		}
		return h.control.PreviewNodeDeviceCode(ownerID, callerDeviceID, input.UserCode)
	case "nodes.confirm":
		var input struct {
			UserCode string `json:"user_code"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.UserCode == "" {
			return nil, errors.New("invalid Node device code confirmation")
		}
		return h.control.ConfirmNodeDeviceCode(ownerID, callerDeviceID, input.UserCode)
	case "nodes.list":
		var input struct{}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid Node binding list request")
		}
		return h.control.NodeDeviceBindings(ownerID)
	case "nodes.revoke":
		var input struct {
			BindingID       string `json:"binding_id"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.BindingID == "" || input.ExpectedVersion <= 0 {
			return nil, errors.New("invalid Node binding revocation")
		}
		return h.control.RevokeNodeDeviceBinding(ownerID, input.BindingID, input.ExpectedVersion)
	case "devices.list":
		var input struct{}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid device list request")
		}
		return h.control.ClientDevices(ownerID)
	case "devices.revoke":
		var input struct {
			DeviceID        string `json:"device_id"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.DeviceID == "" || input.ExpectedVersion <= 0 {
			return nil, errors.New("invalid device revocation request")
		}
		// The response must be sealed and cached under the active caller's
		// session. Revoking that session here would strand an accepted request.
		if input.DeviceID == callerDeviceID {
			return nil, errors.New("current Client device cannot revoke itself through this session")
		}
		return h.control.RevokeClientDevice(ownerID, input.DeviceID, input.ExpectedVersion)
	case "status.snapshot":
		var input struct{}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid status snapshot request")
		}
		return h.control.BuildClientStatusSnapshot(ownerID)
	case "status.changes":
		var input struct {
			Cursor string `json:"cursor,omitempty"`
			Limit  int    `json:"limit,omitempty"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid status changes request")
		}
		return h.control.ReadClientStatusChanges(ownerID, input.Cursor, input.Limit)
	case "topology.snapshot":
		var input struct{}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid topology snapshot request")
		}
		return h.control.BuildClientTopologySnapshot(ownerID)
	case "topology.apply":
		var input control.ClientTopologyAction
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid topology change request")
		}
		return h.control.ApplyClientTopologyChange(ownerID, input)
	case "approvals.list":
		var input struct {
			PendingOnly bool `json:"pending_only"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid approval list request")
		}
		return h.control.Approvals(input.PendingOnly)
	case "intent.get":
		var input struct {
			IntentID string `json:"intent_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.IntentID == "" {
			return nil, errors.New("invalid intent lookup request")
		}
		return h.control.Intent(input.IntentID)
	case "intent.status":
		var input struct {
			IntentID string `json:"intent_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.IntentID == "" {
			return nil, errors.New("invalid intent status request")
		}
		return h.control.ClientIntentStatus(ownerID, input.IntentID)
	case "intent.list":
		var input struct {
			Status string `json:"status,omitempty"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid intent list request")
		}
		return h.control.Intents(input.Status)
	case "intent.submit":
		var input control.IntentInput
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || strings.TrimSpace(input.Text) == "" {
			return nil, errors.New("invalid intent submission")
		}
		return h.control.AcceptClientIntent(clientRequestID, input)
	case "approvals.decide":
		var input struct {
			ApprovalID string `json:"approval_id"`
			Decision   string `json:"decision"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.ApprovalID == "" ||
			(input.Decision != "accept" && input.Decision != "decline") {
			return nil, errors.New("invalid approval decision")
		}
		approval, err := h.control.ClientApproval(ownerID, input.ApprovalID)
		if err != nil || approval == nil || approval.Status != "pending" {
			return nil, errors.New("approval is not pending")
		}
		return h.control.ResolveApproval(input.ApprovalID, input.Decision)
	default:
		return nil, errors.New("Client operation is not available")
	}
}
