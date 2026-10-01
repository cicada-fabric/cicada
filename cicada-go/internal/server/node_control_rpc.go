package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

const nodeControlRPCMaxRequestBytes = nodewire.MaxRequestPacketBytes

type nodeControlRPCJobList struct {
	Jobs     []control.MachineJob
	TooLarge bool
}

func (h *Handler) nodeControlIdentity(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control identity is unavailable"))
		return
	}
	identity, err := h.control.NodeControlPublicIdentity()
	if err != nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control identity is unavailable"))
		return
	}
	writeJSON(response, http.StatusOK, identity)
}

func (h *Handler) nodeControlPairingStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || h.control == nil {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		} else {
			writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control pairing is unavailable"))
		}
		return
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "v2" || parts[1] != "node" || parts[2] != "device-code" ||
		parts[3] == "" || parts[4] != "status" {
		writeError(response, http.StatusNotFound, errors.New("Node-Control pairing status not found"))
		return
	}
	token, err := fabric.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, errors.New("Node credential is required"))
		return
	}
	status, err := h.control.NodeControlPairingStatus(token, request.URL.Query().Get("node_id"), parts[3])
	if err != nil {
		if errors.Is(err, store.ErrNodeControlPairingNotFound) {
			writeError(response, http.StatusNotFound, errors.New("Node-Control pairing is not approved"))
		} else if errors.Is(err, store.ErrNodeControlKeyUnauthorized) {
			writeError(response, http.StatusUnauthorized, errors.New("Node credential is not active"))
		} else {
			writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control pairing status is unavailable"))
		}
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (h *Handler) nodeControlKeyUpgrade(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control pairing is unavailable"))
		return
	}
	token, err := fabric.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, errors.New("Node credential is required"))
		return
	}
	var input nodeControlPairingInput
	if err := decodeStrictClientJSON(request.Body, 96*1024, &input); err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node-Control key upgrade"))
		return
	}
	challenge, err := h.control.StartNodeControlKeyUpgrade(token, input.controlInput())
	if err != nil {
		writeNodeControlPairingError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, challenge)
}

type nodeControlPairingInput struct {
	NodeID             string              `json:"node_id"`
	NodeName           string              `json:"node_name"`
	CredentialDigest   string              `json:"credential_digest,omitempty"`
	RequestNonce       []byte              `json:"request_nonce"`
	NodePublicIdentity e2ee.PublicIdentity `json:"node_public_identity"`
	NodeFingerprint    string              `json:"node_fingerprint"`
	ProofPacket        []byte              `json:"proof_packet"`
	HubID              string              `json:"hub_id"`
	HubPublicIdentity  e2ee.PublicIdentity `json:"hub_public_identity"`
	HubKeyVersion      uint64              `json:"hub_key_version"`
	HubFingerprint     string              `json:"hub_fingerprint"`
}

func (input nodeControlPairingInput) controlInput() control.NodeControlDeviceCodeInput {
	return control.NodeControlDeviceCodeInput{
		NodeID: input.NodeID, NodeName: input.NodeName, CredentialDigest: input.CredentialDigest,
		RequestNonce:       input.RequestNonce,
		NodePublicIdentity: input.NodePublicIdentity,
		NodeFingerprint:    input.NodeFingerprint, ProofPacket: input.ProofPacket,
		HubID: input.HubID, HubPublicIdentity: input.HubPublicIdentity,
		HubKeyVersion: input.HubKeyVersion, HubFingerprint: input.HubFingerprint,
	}
}

func (h *Handler) nodeControlRPC(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	if h.control == nil || h.fabricService == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Node-Control RPC is unavailable"))
		return
	}
	// Reject unauthenticated traffic before consuming the bounded encrypted
	// request body. The bearer identifies the Node token; the binding and packet
	// authentication below provide the application-layer PQ authorization.
	token, err := fabric.NodeCredentialFromAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		writeError(response, http.StatusUnauthorized, errors.New("Node credential is required"))
		return
	}
	packetBytes, err := io.ReadAll(io.LimitReader(request.Body, int64(nodeControlRPCMaxRequestBytes)+1))
	if err != nil || len(packetBytes) == 0 || len(packetBytes) > nodeControlRPCMaxRequestBytes {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node-Control packet size"))
		return
	}
	packet, err := nodewire.DecodePacket(packetBytes)
	if err != nil {
		writeError(response, http.StatusBadRequest, errors.New("invalid Node-Control packet"))
		return
	}
	route := packet.Route
	if !nodeControlOperationAllowed(route.Operation) {
		writeError(response, http.StatusForbidden, errors.New("Node-Control operation is not allowed"))
		return
	}
	digest := fabric.HashSessionCredential(token)
	keyBinding, err := h.control.NodeControlKeyForCredential(digest, route.NodeID)
	if err != nil {
		if errors.Is(err, store.ErrNodeControlMigrationBlocked) {
			writeError(response, http.StatusUpgradeRequired, errors.New("MIGRATION_BLOCKED: Owner approval of the Node-Control PQ key is required"))
		} else {
			writeError(response, http.StatusForbidden, errors.New("Node-Control key binding is unavailable"))
		}
		return
	}
	opened, err := h.control.OpenNodeControlRequest(keyBinding, packetBytes)
	if err != nil {
		writeError(response, http.StatusForbidden, errors.New("Node-Control packet authentication failed"))
		return
	}
	if opened.Route.Direction != nodewire.DirectionRequest || opened.Route.Operation != route.Operation {
		writeError(response, http.StatusForbidden, errors.New("Node-Control request route is invalid"))
		return
	}
	packetDigest := sha256.Sum256(packetBytes)
	replayInput := store.NodeControlRPCInput{
		CredentialDigest: digest, NodeID: route.NodeID, BindingID: keyBinding.OwnerBindingID,
		BindingVersion: keyBinding.BindingVersion, NodeKeyID: keyBinding.NodeKeyID,
		NodeKeyEpoch: keyBinding.NodeKeyEpoch, Sequence: route.Sequence,
		OperationID: route.OperationID, Operation: route.Operation,
		RequestDigest: hex.EncodeToString(packetDigest[:]),
	}
	record, exactRetry, err := h.control.NodeControlRPCBegin(replayInput)
	if err != nil {
		if errors.Is(err, store.ErrNodeControlMigrationBlocked) {
			writeError(response, http.StatusUpgradeRequired, errors.New("MIGRATION_BLOCKED: Owner approval of the Node-Control PQ key is required"))
		} else {
			writeError(response, http.StatusConflict, errors.New("Node-Control request was rejected by the current binding or replay guard"))
		}
		return
	}
	if exactRetry {
		if record.State == store.NodeControlRPCComplete && len(record.ResponsePacket) > 0 {
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(record.ResponsePacket)
			return
		}
		if record.State == store.NodeControlRPCComplete {
			// Response-cache eviction never authorizes redispatch. Return an
			// authenticated terminal marker so the Node can retire its exact
			// durable outbox while preserving the operation tombstone/highwater.
			if !h.writeNodeControlRPCStatus(response, opened.Route, keyBinding, "RESULT_EXPIRED") {
				writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
			}
			return
		}
		status := "IN_PROGRESS"
		if record.State == store.NodeControlRPCUncertain {
			status = "OUTCOME_UNCERTAIN"
		}
		if !h.writeNodeControlRPCStatus(response, opened.Route, keyBinding, status) {
			writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
		}
		return
	}
	result, dispatchErr := h.dispatchNodeControlRPC(token, replayInput, keyBinding, opened.Route.Operation, opened.Plaintext)
	if dispatchErr != nil {
		_ = h.control.NodeControlRPCUncertain(replayInput)
		if !h.writeNodeControlRPCStatus(response, opened.Route, keyBinding, "OUTCOME_UNCERTAIN") {
			writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
		}
		return
	}
	body, err := nodeControlRPCResponseBody(replayInput, result)
	if err != nil || len(body) == 0 || len(body) > nodewire.MaxPlaintextBytes {
		_ = h.control.NodeControlRPCUncertain(replayInput)
		writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
		return
	}
	responseRoute := opened.Route
	responseRoute.Direction = nodewire.DirectionResponse
	responseRoute.SenderKeyID, responseRoute.ReceiverKeyID = responseRoute.ReceiverKeyID, responseRoute.SenderKeyID
	responseRoute.SenderKeyVersion, responseRoute.ReceiverKeyVersion = responseRoute.ReceiverKeyVersion, responseRoute.SenderKeyVersion
	sealed, err := h.control.SealNodeControlResponse(keyBinding, responseRoute, body)
	if err != nil {
		_ = h.control.NodeControlRPCUncertain(replayInput)
		writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
		return
	}
	if err := h.control.NodeControlRPCComplete(store.NodeControlRPCCompletion{
		NodeControlRPCInput: replayInput, ResponsePacket: sealed,
	}); err != nil {
		_ = h.control.NodeControlRPCUncertain(replayInput)
		if !h.writeNodeControlRPCStatus(response, opened.Route, keyBinding, "OUTCOME_UNCERTAIN") {
			writeError(response, http.StatusInternalServerError, errors.New("Node-Control response could not be sealed"))
		}
		return
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(sealed)
}

// writeNodeControlRPCStatus returns an authenticated recovery status under the
// exact operation route. The status itself is not cached: PROCESSING may later
// become COMPLETE, and a terminal tombstone remains the durable authority.
func (h *Handler) writeNodeControlRPCStatus(response http.ResponseWriter, requestRoute nodewire.Route,
	keyBinding *store.NodeControlKeyBinding, code string) bool {
	if code != "RESULT_EXPIRED" && code != "IN_PROGRESS" && code != "OUTCOME_UNCERTAIN" {
		return false
	}
	body, err := json.Marshal(map[string]any{"ok": false, "error_code": code,
		"operation_id": requestRoute.OperationID, "sequence": requestRoute.Sequence})
	if err != nil {
		return false
	}
	route := requestRoute
	route.Direction = nodewire.DirectionResponse
	route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	sealed, err := h.control.SealNodeControlResponse(keyBinding, route, body)
	if err != nil || len(sealed) == 0 || len(sealed) > nodewire.MaxPacketBytes {
		return false
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(sealed)
	return true
}

func nodeControlRPCResponseBody(rpc store.NodeControlRPCInput, result any) ([]byte, error) {
	marshal := func(ok bool, result any, errorCode string) ([]byte, error) {
		body := map[string]any{"ok": ok, "operation_id": rpc.OperationID, "sequence": rpc.Sequence}
		if ok {
			body["result"] = result
		} else {
			body["error_code"] = errorCode
		}
		return json.Marshal(body)
	}
	if rpc.Operation != "node.jobs.list" {
		return marshal(true, result, "")
	}
	list, ok := result.(nodeControlRPCJobList)
	if !ok {
		return nil, errors.New("Node-Control job list result has an invalid shape")
	}
	if list.TooLarge {
		return marshal(false, nil, "RESULT_TOO_LARGE")
	}
	if len(list.Jobs) == 0 {
		return marshal(true, map[string]any{"jobs": []control.MachineJob{}}, "")
	}
	// Append each encoded job once. The previous prefix loop re-marshaled every
	// progressively shorter list and was quadratic in large Worker results.
	operationID, err := json.Marshal(rpc.OperationID)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, nodewire.MaxPlaintextBytes)
	body = append(body, `{"ok":true,"operation_id":`...)
	body = append(body, operationID...)
	body = append(body, `,"sequence":`...)
	body = append(body, fmt.Sprint(rpc.Sequence)...)
	body = append(body, `,"result":{"jobs":[`...)
	const suffix = `]}}`
	count := 0
	for _, job := range list.Jobs {
		encoded, err := json.Marshal(job)
		if err != nil {
			return nil, err
		}
		separator := 0
		if count > 0 {
			separator = 1
		}
		if len(body)+separator+len(encoded)+len(suffix) > nodewire.MaxPlaintextBytes {
			if count == 0 {
				return marshal(false, nil, "RESULT_TOO_LARGE")
			}
			break
		}
		if separator != 0 {
			body = append(body, ',')
		}
		body = append(body, encoded...)
		count++
	}
	body = append(body, suffix...)
	return body, nil
}

func nodeControlOperationAllowed(operation string) bool {
	switch operation {
	case "node.binding.status", "node.heartbeat", "node.jobs.list", "node.jobs.claim",
		"node.jobs.result", "node.approvals.create", "node.approvals.status":
		return true
	default:
		return false
	}
}

func (h *Handler) dispatchNodeControlRPC(token string, rpc store.NodeControlRPCInput,
	keyBinding *store.NodeControlKeyBinding, operation string, plaintext []byte) (any, error) {
	credentialDigest := rpc.CredentialDigest
	decode := func(target any) error {
		return decodeStrictClientJSON(bytes.NewReader(plaintext), nodewire.MaxRequestPlaintextBytes, target)
	}
	switch operation {
	case "node.binding.status":
		var input struct{}
		if err := decode(&input); err != nil {
			return nil, err
		}
		return map[string]any{
			"request_id": keyBinding.ApprovedRequestID, "candidate_version": keyBinding.ApprovedRequestVersion,
			"candidate_digest": keyBinding.ApprovedCandidateDigest, "node_id": keyBinding.NodeID,
			"hub_id": keyBinding.HubID, "binding_id": keyBinding.OwnerBindingID,
			"binding_version": keyBinding.BindingVersion, "node_key_id": keyBinding.NodeKeyID,
			"node_key_fingerprint": keyBinding.NodeKeyFingerprint, "node_key_epoch": keyBinding.NodeKeyEpoch,
			"hub_key_id": keyBinding.HubKeyID, "hub_key_version": keyBinding.HubKeyVersion,
			"hub_key_fingerprint": keyBinding.HubKeyFingerprint,
		}, nil
	case "node.heartbeat":
		var input struct {
			Status       string         `json:"status,omitempty"`
			Capabilities map[string]any `json:"capabilities,omitempty"`
		}
		if err := decode(&input); err != nil {
			return nil, err
		}
		if err := h.control.RecordNodeControlHeartbeat(token, rpc, input.Status, input.Capabilities); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, nil
	case "node.jobs.list":
		var input struct{}
		if err := decode(&input); err != nil {
			return nil, err
		}
		jobs, tooLarge, err := h.control.BoundNodeMachineJobsBounded(credentialDigest,
			keyBinding.NodeID, nodewire.MaxPlaintextBytes-1024)
		if err != nil {
			return nil, err
		}
		return nodeControlRPCJobList{Jobs: jobs, TooLarge: tooLarge}, nil
	case "node.jobs.claim":
		var input struct {
			WorkerID string `json:"worker_id"`
		}
		if err := decode(&input); err != nil || strings.TrimSpace(input.WorkerID) == "" {
			return nil, errors.New("invalid Node job claim")
		}
		return h.control.ClaimBoundNodeRemoteWorkerNodeControl(rpc, input.WorkerID)
	case "node.jobs.result":
		var input struct {
			WorkerID          string `json:"worker_id"`
			Attempt           int    `json:"attempt"`
			Status            string `json:"status"`
			Summary           string `json:"summary"`
			ThreadID          string `json:"thread_id"`
			Error             string `json:"error"`
			WorkspaceRevision string `json:"workspace_revision"`
			ResourceStopState string `json:"resource_stop_state,omitempty"`
		}
		if err := decode(&input); err != nil || strings.TrimSpace(input.WorkerID) == "" || input.Attempt <= 0 {
			return nil, errors.New("invalid Node job result")
		}
		return h.control.CompleteBoundNodeRemoteWorkerNodeControl(rpc,
			input.WorkerID, input.Attempt, input.Status, input.Summary, input.ThreadID,
			input.Error, input.WorkspaceRevision, input.ResourceStopState)
	case "node.approvals.create":
		var input struct {
			WorkerID  string          `json:"worker_id"`
			Attempt   int             `json:"attempt"`
			RequestID string          `json:"request_id"`
			Method    string          `json:"method"`
			Request   json.RawMessage `json:"request"`
		}
		if err := decode(&input); err != nil || strings.TrimSpace(input.WorkerID) == "" ||
			input.Attempt <= 0 || strings.TrimSpace(input.RequestID) == "" || len(input.Request) == 0 {
			return nil, errors.New("invalid Node approval request")
		}
		approval, created, err := h.control.CreateBoundNodeWorkerApprovalNodeControl(rpc,
			input.WorkerID, input.Attempt, input.RequestID, input.Method, input.Request)
		if err != nil {
			return nil, err
		}
		if approval == nil {
			return nil, errors.New("Node approval is unavailable")
		}
		return map[string]any{"approval_id": approval.ID, "goal_id": approval.GoalID,
			"worker_id": approval.WorkerID, "attempt": approval.Attempt,
			"status": approval.Status, "decision": approval.Decision, "created": created}, nil
	case "node.approvals.status":
		var input struct {
			WorkerID   string `json:"worker_id"`
			Attempt    int    `json:"attempt"`
			ApprovalID string `json:"approval_id"`
		}
		if err := decode(&input); err != nil || strings.TrimSpace(input.WorkerID) == "" ||
			input.Attempt <= 0 || strings.TrimSpace(input.ApprovalID) == "" {
			return nil, errors.New("invalid Node approval status request")
		}
		approval, err := h.control.BoundNodeWorkerApprovalNodeControl(rpc,
			input.WorkerID, input.Attempt, input.ApprovalID)
		if err != nil || approval == nil {
			return nil, errors.New("Node approval status is unavailable")
		}
		return map[string]any{"approval_id": approval.ID, "goal_id": approval.GoalID,
			"worker_id": approval.WorkerID, "attempt": approval.Attempt,
			"status": approval.Status, "decision": approval.Decision}, nil
	default:
		return nil, fmt.Errorf("Node-Control operation is not authorized")
	}
}

func writeNodeControlPairingError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNodeDeviceBindingRateLimited):
		writeError(response, http.StatusTooManyRequests, errors.New("Node-Control pairing rate limited"))
	case errors.Is(err, store.ErrNodeControlPairingConflict), errors.Is(err, store.ErrNodeControlMigrationBlocked):
		writeError(response, http.StatusConflict, errors.New("MIGRATION_BLOCKED or a Node-Control pairing is already pending"))
	case errors.Is(err, store.ErrNodeControlKeyUnauthorized):
		writeError(response, http.StatusUnauthorized, errors.New("Node credential is not active"))
	default:
		writeError(response, http.StatusBadRequest, errors.New("Node-Control pairing request rejected"))
	}
}
