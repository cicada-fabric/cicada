package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientcontract"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
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
		h.control.ValidateClientSessionOwner(route.OwnerID) != nil {
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
		OperationID: opened.Route.OperationID, RouteOperation: opened.Route.Operation,
		CiphertextDigest: hex.EncodeToString(digest[:]),
	}
	accepted, err := h.control.AcceptClientControlRequest(requestBinding)
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
		_, _ = h.control.MarkClientControlRequestUncertain(device.OwnerID, device.DeviceID, opened.Route.OperationID)
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	sequence, err := h.control.ReserveClientControlResponseSequence(requestBinding)
	if err != nil {
		_, _ = h.control.MarkClientControlRequestUncertain(device.OwnerID, device.DeviceID, opened.Route.OperationID)
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
		_, _ = h.control.MarkClientControlRequestUncertain(device.OwnerID, device.DeviceID, opened.Route.OperationID)
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if _, err := h.control.CompleteClientControlRequest(device.OwnerID, device.DeviceID, opened.Route.OperationID, sealed); err != nil {
		_, _ = h.control.MarkClientControlRequestUncertain(device.OwnerID, device.DeviceID, opened.Route.OperationID)
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
	if err := h.control.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, errors.New("Client session owner is unavailable")
	}
	role := clientcontract.RoleExternal
	if ownerID == h.control.Identity().ID {
		role = clientcontract.RoleManager
	}
	// The catalog is the common allowlist for both capability discovery and
	// dispatch authorization. It does not replace operation-specific owner,
	// Link, Group, version, or proof checks below.
	if !clientcontract.Allows(role, operation) {
		return nil, errors.New("Client operation is not authorized for this owner")
	}
	switch operation {
	case "link.list":
		var input struct {
			Cursor string `json:"cursor"`
			Limit  int    `json:"limit"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.Limit < 0 {
			return nil, errors.New("invalid communication link list request")
		}
		return h.control.ClientCommunicationLinks(ownerID, input.Cursor, input.Limit)
	case "session.capabilities":
		var input struct{}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid Client session capabilities request")
		}
		return map[string]any{
			"owner_id": ownerID, "role": string(role),
			"contract_revision":        clientcontract.ContractRevision,
			"catalog_sha256":           clientcontract.CatalogSHA256(),
			"rpc_recovery":             true,
			"available_rpc_operations": clientcontract.OperationsForRole(role),
		}, nil
	case "link.invite_create":
		var input struct {
			SourceEndpointID string   `json:"source_endpoint_id"`
			SourceGroupID    string   `json:"source_group_id"`
			HubID            string   `json:"hub_id"`
			Direction        string   `json:"direction,omitempty"`
			Actions          []string `json:"actions,omitempty"`
			DataScopes       []string `json:"data_scopes"`
			ExpiresAt        string   `json:"expires_at"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.SourceEndpointID == "" || input.SourceGroupID == "" || input.HubID == "" || input.ExpiresAt == "" {
			return nil, errors.New("invalid external Thread invitation request")
		}
		return h.control.CreateClientExternalThreadInvite(ownerID, store.ExternalThreadInviteInput{
			SourceEndpointID: input.SourceEndpointID, SourceGroupID: input.SourceGroupID,
			HubID: input.HubID, Direction: input.Direction, Actions: input.Actions, DataScopes: input.DataScopes,
			ExpiresAt: input.ExpiresAt,
		})
	case "link.invite_preview":
		var input struct {
			Token string `json:"token"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.Token == "" {
			return nil, errors.New("invalid external Thread invitation preview")
		}
		return h.control.PreviewClientExternalThreadInvite(ownerID, input.Token)
	case "link.invite_accept":
		var input struct {
			Token            string `json:"token"`
			TargetEndpointID string `json:"target_endpoint_id"`
			TargetGroupID    string `json:"target_group_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.Token == "" || input.TargetEndpointID == "" || input.TargetGroupID == "" {
			return nil, errors.New("invalid external Thread invitation acceptance")
		}
		return h.control.AcceptClientExternalThreadInvite(ownerID, input.Token,
			input.TargetEndpointID, input.TargetGroupID)
	case "monitor.broadcast_prepare":
		var input struct {
			GroupID           string `json:"group_id"`
			MonitorEndpointID string `json:"monitor_endpoint_id"`
			BodySHA256        string `json:"body_sha256"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.GroupID == "" || input.MonitorEndpointID == "" || input.BodySHA256 == "" {
			return nil, errors.New("invalid Monitor broadcast preparation request")
		}
		return h.control.ClientPrepareMonitorBroadcast(ownerID, clientRequestID,
			input.GroupID, input.MonitorEndpointID, input.BodySHA256)
	case "monitor.broadcast_confirm":
		var input struct {
			PreviewID      string `json:"preview_id"`
			SnapshotDigest string `json:"snapshot_digest"`
			BodySHA256     string `json:"body_sha256"`
			SealedPayload  []byte `json:"sealed_payload"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.PreviewID == "" || input.SnapshotDigest == "" || input.BodySHA256 == "" || len(input.SealedPayload) == 0 {
			return nil, errors.New("invalid consent-bound Monitor broadcast confirmation")
		}
		return h.control.ClientConfirmMonitorBroadcast(ownerID, clientRequestID,
			input.PreviewID, input.SnapshotDigest, input.BodySHA256, input.SealedPayload)
	case "monitor.broadcast_status":
		var input struct {
			PreviewID string `json:"preview_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.PreviewID == "" {
			return nil, errors.New("invalid Monitor broadcast status request")
		}
		return h.control.ClientMonitorBroadcastStatus(ownerID, clientRequestID, input.PreviewID)
	case "monitor.broadcast_recover":
		var input struct {
			OperationID string `json:"operation_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.OperationID == "" || len(input.OperationID) > 256 {
			return nil, errors.New("invalid Monitor broadcast recovery request")
		}
		return h.control.ClientRecoverMonitorBroadcast(ownerID, clientRequestID, input.OperationID)
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
	case "link.review_policy_preview":
		var input struct {
			LinkID string                              `json:"link_id"`
			Policy store.CommunicationLinkReviewPolicy `json:"policy"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.LinkID == "" {
			return nil, errors.New("invalid Communication Link review-policy preview")
		}
		return h.control.ClientPreviewCommunicationLinkReviewPolicy(ownerID, input.LinkID, input.Policy)
	case "link.review_policy_grant":
		var input struct {
			LinkID                string                              `json:"link_id"`
			OwnerKeyID            string                              `json:"owner_key_id"`
			ExpectedPolicyVersion *int64                              `json:"expected_policy_version"`
			Policy                store.CommunicationLinkReviewPolicy `json:"policy"`
			SignedProof           []byte                              `json:"signed_proof"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.LinkID == "" || input.OwnerKeyID == "" || input.ExpectedPolicyVersion == nil || *input.ExpectedPolicyVersion < 0 || *input.ExpectedPolicyVersion == math.MaxInt64 || len(input.SignedProof) == 0 {
			return nil, errors.New("invalid Communication Link review-policy Owner grant")
		}
		var proof e2ee.OwnerLinkReviewPolicyProof
		if err := json.Unmarshal(input.SignedProof, &proof); err != nil || proof.OwnerID != ownerID || proof.LinkID != input.LinkID ||
			proof.PolicyVersion != uint64(*input.ExpectedPolicyVersion+1) {
			return nil, errors.New("review-policy proof does not match the authenticated Owner and requested version")
		}
		return h.control.ClientRecordCommunicationLinkReviewPolicy(ownerID, input.LinkID,
			string(proof.Side), input.OwnerKeyID, *input.ExpectedPolicyVersion, input.Policy, input.SignedProof)
	case "link.review_policy_status":
		var input struct {
			LinkID string `json:"link_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.LinkID == "" {
			return nil, errors.New("invalid Communication Link review-policy status request")
		}
		return h.control.ClientCommunicationLinkReviewPolicy(ownerID, input.LinkID)
	case "group.key_manifest":
		var input struct {
			GroupID    string `json:"group_id"`
			EndpointID string `json:"endpoint_id"`
			OwnerKeyID string `json:"owner_key_id"`
			IssuedAt   string `json:"issued_at"`
			ExpiresAt  string `json:"expires_at"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" || input.OwnerKeyID == "" ||
			input.IssuedAt == "" || input.ExpiresAt == "" {
			return nil, errors.New("invalid Group Endpoint key grant manifest request")
		}
		issuedAt, err := parseCanonicalGroupKeyGrantTime(input.IssuedAt)
		if err != nil {
			return nil, errors.New("invalid Group Endpoint key grant issue time")
		}
		expiresAt, err := parseCanonicalGroupKeyGrantTime(input.ExpiresAt)
		if err != nil {
			return nil, errors.New("invalid Group Endpoint key grant expiry")
		}
		return h.control.ClientPreviewGroupEndpointKeyGrant(ownerID, input.GroupID,
			input.EndpointID, input.OwnerKeyID, issuedAt, expiresAt)
	case "group.key_grant":
		var input struct {
			GroupID     string `json:"group_id"`
			EndpointID  string `json:"endpoint_id"`
			OwnerKeyID  string `json:"owner_key_id"`
			SignedProof []byte `json:"signed_proof"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" || input.OwnerKeyID == "" || len(input.SignedProof) == 0 {
			return nil, errors.New("invalid Group Endpoint key grant")
		}
		return h.control.ClientAcceptGroupEndpointKeyGrant(ownerID, input.GroupID,
			input.EndpointID, input.OwnerKeyID, input.SignedProof)
	case "group.key_status":
		var input struct {
			GroupID    string `json:"group_id"`
			EndpointID string `json:"endpoint_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" {
			return nil, errors.New("invalid Group Endpoint key grant status request")
		}
		return h.control.ClientGroupEndpointKeyGrantStatus(ownerID, input.GroupID, input.EndpointID)
	case "network.key_manifest":
		var input struct {
			NetworkID  string `json:"network_id"`
			EndpointID string `json:"endpoint_id"`
			OwnerKeyID string `json:"owner_key_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" || input.OwnerKeyID == "" {
			return nil, errors.New("invalid Network Endpoint key manifest request")
		}
		return h.control.ClientPreviewNetworkDirectKeyGrant(ownerID, input.NetworkID, input.EndpointID, input.OwnerKeyID)
	case "network.key_grant":
		var input struct {
			NetworkID   string `json:"network_id"`
			EndpointID  string `json:"endpoint_id"`
			SignedProof []byte `json:"signed_proof"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" || len(input.SignedProof) == 0 {
			return nil, errors.New("invalid Network Endpoint key grant")
		}
		return h.control.ClientAcceptNetworkDirectKeyGrant(ownerID, clientRequestID, input.NetworkID, input.EndpointID, input.SignedProof)
	case "network.key_status":
		var input struct {
			NetworkID  string `json:"network_id"`
			EndpointID string `json:"endpoint_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" {
			return nil, errors.New("invalid Network Endpoint key status request")
		}
		return h.control.ClientNetworkDirectKeyGrantStatus(ownerID, input.NetworkID, input.EndpointID)
	case "network.collaboration_key_manifest":
		var input struct {
			NetworkID  string `json:"network_id"`
			EndpointID string `json:"endpoint_id"`
			Purpose    string `json:"purpose"`
			OwnerKeyID string `json:"owner_key_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" || input.OwnerKeyID == "" ||
			(input.Purpose != e2ee.NetworkCollaborationPurposeTask && input.Purpose != e2ee.NetworkCollaborationPurposeBroadcast) {
			return nil, errors.New("invalid Network collaboration key manifest request")
		}
		return h.control.ClientPreviewNetworkCollaborationKeyGrant(ownerID, input.NetworkID,
			input.EndpointID, input.Purpose, input.OwnerKeyID)
	case "network.collaboration_key_grant":
		var input struct {
			NetworkID   string `json:"network_id"`
			EndpointID  string `json:"endpoint_id"`
			Purpose     string `json:"purpose"`
			SignedProof []byte `json:"signed_proof"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" || len(input.SignedProof) == 0 ||
			(input.Purpose != e2ee.NetworkCollaborationPurposeTask && input.Purpose != e2ee.NetworkCollaborationPurposeBroadcast) {
			return nil, errors.New("invalid Network collaboration key grant")
		}
		return h.control.ClientAcceptNetworkCollaborationKeyGrant(ownerID, clientRequestID,
			input.NetworkID, input.EndpointID, input.Purpose, input.SignedProof)
	case "network.collaboration_key_status":
		var input struct {
			NetworkID  string `json:"network_id"`
			EndpointID string `json:"endpoint_id"`
			Purpose    string `json:"purpose"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.NetworkID == "" || input.EndpointID == "" ||
			(input.Purpose != e2ee.NetworkCollaborationPurposeTask && input.Purpose != e2ee.NetworkCollaborationPurposeBroadcast) {
			return nil, errors.New("invalid Network collaboration key grant status request")
		}
		return h.control.ClientNetworkCollaborationKeyGrantStatus(ownerID,
			input.NetworkID, input.EndpointID, input.Purpose)
	case "nodes.preview":
		var input struct {
			UserCode string `json:"user_code"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.UserCode == "" {
			return nil, errors.New("invalid Node device code preview")
		}
		return h.control.PreviewNodeControlDeviceCode(ownerID, callerDeviceID, input.UserCode)
	case "nodes.confirm":
		var input struct {
			UserCode         string `json:"user_code"`
			CandidateDigest  string `json:"candidate_digest"`
			CandidateVersion int64  `json:"candidate_version"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.UserCode == "" || input.CandidateDigest == "" || input.CandidateVersion <= 0 {
			return nil, errors.New("invalid Node device code confirmation")
		}
		return h.control.ConfirmNodeControlDeviceCode(ownerID, callerDeviceID, input.UserCode,
			input.CandidateDigest, input.CandidateVersion)
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
	case "goal.lifecycle":
		var input struct {
			GoalID          string `json:"goal_id"`
			Action          string `json:"action"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil ||
			input.GoalID == "" || input.ExpectedVersion <= 0 ||
			(input.Action != "pause" && input.Action != "resume") {
			return nil, errors.New("invalid Goal lifecycle request")
		}
		return h.control.ChangeClientGoalLifecycle(ownerID, callerDeviceID, clientRequestID,
			input.GoalID, input.Action, input.ExpectedVersion)
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
		return h.control.ApplyClientTopologyChangeForClientRequest(ownerID, clientRequestID, input)
	case "topology.endpoint_admission_preview":
		var input struct {
			NetworkID  string `json:"network_id"`
			GroupID    string `json:"group_id"`
			EndpointID string `json:"endpoint_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.NetworkID == "" || input.GroupID == "" || input.EndpointID == "" {
			return nil, errors.New("invalid same-Owner Endpoint admission preview")
		}
		return h.control.PreviewClientTopologyEndpointAdmissionForClientRequest(clientRequestID,
			ownerID, input.NetworkID, input.GroupID, input.EndpointID)
	case "network.directory":
		var input struct {
			NetworkID       string `json:"network_id"`
			AfterEndpointID string `json:"after_endpoint_id,omitempty"`
			Limit           *int   `json:"limit,omitempty"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.NetworkID == "" || len(input.AfterEndpointID) > 256 {
			return nil, errors.New("invalid opted-in Network directory request")
		}
		limit := 64
		if input.Limit != nil {
			limit = *input.Limit
		}
		if limit < 1 || limit > 64 {
			return nil, errors.New("Network directory page limit must be between 1 and 64")
		}
		return h.control.ListClientOwnerNetworkEndpointCardsForRequest(clientRequestID,
			ownerID, input.NetworkID, input.AfterEndpointID, limit)
	case "space.foreign_member_admit":
		var input struct {
			GroupID                    string   `json:"group_id"`
			EndpointID                 string   `json:"endpoint_id"`
			Grants                     []string `json:"grants"`
			ExpiresAt                  string   `json:"expires_at"`
			ExpectedGroupRevision      int64    `json:"expected_group_revision"`
			ExpectedMembershipRevision *int64   `json:"expected_membership_revision"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" || len(input.Grants) == 0 ||
			input.ExpiresAt == "" || input.ExpectedGroupRevision <= 0 ||
			input.ExpectedMembershipRevision == nil || *input.ExpectedMembershipRevision < 0 {
			return nil, errors.New("invalid cross-Owner Group admission request")
		}
		return h.control.AdmitCrossOwnerGroupMemberForClientRequest(clientRequestID, ownerID,
			input.GroupID, input.EndpointID, input.Grants, input.ExpiresAt,
			input.ExpectedGroupRevision, *input.ExpectedMembershipRevision)
	case "space.foreign_endpoint_preview":
		var input struct {
			AdmissionID string `json:"admission_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil || input.AdmissionID == "" {
			return nil, errors.New("invalid exact cross-Owner Endpoint admission preview")
		}
		return h.control.PreviewCrossOwnerGroupPreconsentForClientRequest(clientRequestID,
			ownerID, input.AdmissionID)
	case "space.foreign_endpoint_join":
		var input struct {
			AdmissionID                   string `json:"admission_id"`
			ExpectedBindingID             string `json:"expected_binding_id"`
			ExpectedBindingEpoch          uint64 `json:"expected_binding_epoch"`
			SharedContextRiskAcknowledged bool   `json:"shared_context_risk_acknowledged"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.AdmissionID == "" || input.ExpectedBindingID == "" || input.ExpectedBindingEpoch == 0 ||
			!input.SharedContextRiskAcknowledged {
			return nil, errors.New("invalid foreign Endpoint Group Join consent")
		}
		return h.control.ConsentCrossOwnerGroupJoinForClientRequest(clientRequestID, ownerID,
			input.AdmissionID, input.ExpectedBindingID, input.ExpectedBindingEpoch,
			input.SharedContextRiskAcknowledged)
	case "space.foreign_member_revoke":
		var input struct {
			AdmissionID                string `json:"admission_id"`
			ExpectedMembershipRevision *int64 `json:"expected_membership_revision"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.AdmissionID == "" || input.ExpectedMembershipRevision == nil ||
			*input.ExpectedMembershipRevision <= 0 {
			return nil, errors.New("invalid cross-Owner Group admission revoke request")
		}
		return h.control.RevokeCrossOwnerGroupAdmissionForClientRequest(clientRequestID, ownerID,
			input.AdmissionID, *input.ExpectedMembershipRevision)
	case "space.key_manifest_v2", "space.key_status_v2":
		var input struct {
			GroupID    string `json:"group_id"`
			EndpointID string `json:"endpoint_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" {
			return nil, errors.New("invalid cross-Owner Group key scope")
		}
		if operation == "space.key_manifest_v2" {
			return h.control.PreviewCrossOwnerGroupKeyManifestForClientRequest(clientRequestID,
				ownerID, input.GroupID, input.EndpointID)
		}
		return h.control.GetCrossOwnerGroupKeyStatusForClientRequest(clientRequestID,
			ownerID, input.GroupID, input.EndpointID)
	case "space.key_consent_v2", "space.key_admission_v2":
		var input struct {
			GroupID     string `json:"group_id"`
			EndpointID  string `json:"endpoint_id"`
			OwnerKeyID  string `json:"owner_key_id"`
			SignedProof []byte `json:"signed_proof_base64"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 20*1024, &input); err != nil ||
			input.GroupID == "" || input.EndpointID == "" || input.OwnerKeyID == "" ||
			len(input.SignedProof) == 0 || len(input.SignedProof) > 16*1024 {
			return nil, errors.New("invalid cross-Owner Group key proof")
		}
		side := store.CrossOwnerKeySideEndpoint
		if operation == "space.key_admission_v2" {
			side = store.CrossOwnerKeySideGroup
		}
		return h.control.AcceptCrossOwnerGroupKeyProofForClientRequest(clientRequestID,
			ownerID, input.GroupID, input.EndpointID, input.OwnerKeyID, side, input.SignedProof)
	case "topology.regroup_proposal":
		var input struct {
			ProposalID string `json:"proposal_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil || input.ProposalID == "" {
			return nil, errors.New("invalid regroup proposal request")
		}
		return h.control.GetRegroupProposalForClientRequest(clientRequestID, ownerID, input.ProposalID)
	case "topology.delegation_issue":
		var input struct {
			ProposalID string `json:"proposal_id"`
			ExpiresAt  string `json:"expires_at"`
			MaxUses    int    `json:"max_uses"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.ProposalID == "" || input.ExpiresAt == "" || input.MaxUses < 1 || input.MaxUses > 1 {
			return nil, errors.New("invalid regroup delegation request")
		}
		return h.control.IssueRegroupDelegationForClientRequest(clientRequestID, ownerID,
			input.ProposalID, input.ExpiresAt, input.MaxUses)
	case "topology.delegation_revoke":
		var input struct {
			DelegationID    string `json:"delegation_id"`
			ExpectedVersion int64  `json:"expected_version"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 4096, &input); err != nil ||
			input.DelegationID == "" || input.ExpectedVersion <= 0 {
			return nil, errors.New("invalid regroup delegation revocation")
		}
		return h.control.RevokeRegroupDelegationForClientRequest(clientRequestID, ownerID,
			input.DelegationID, input.ExpectedVersion)
	case "approvals.list":
		var input struct {
			PendingOnly bool `json:"pending_only"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid approval list request")
		}
		return h.control.ClientApprovals(ownerID, input.PendingOnly)
	case "intent.get":
		var input struct {
			IntentID string `json:"intent_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.IntentID == "" {
			return nil, errors.New("invalid intent lookup request")
		}
		return h.control.ClientIntentForOwner(ownerID, input.IntentID)
	case "intent.status":
		var input struct {
			IntentID string `json:"intent_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.IntentID == "" {
			return nil, errors.New("invalid intent status request")
		}
		return h.control.ClientIntentStatus(ownerID, input.IntentID)
	case "goal.result":
		var input struct {
			IntentID string `json:"intent_id"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.IntentID == "" {
			return nil, errors.New("invalid Goal result request")
		}
		return h.control.ClientGoalResultForIntent(ownerID, input.IntentID)
	case "intent.list":
		var input struct {
			Status string `json:"status,omitempty"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil {
			return nil, errors.New("invalid intent list request")
		}
		return h.control.ClientIntentsForOwner(ownerID, input.Status)
	case "intent.submit":
		var input control.IntentInput
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || strings.TrimSpace(input.Text) == "" {
			return nil, errors.New("invalid intent submission")
		}
		return h.control.AcceptClientIntentForOwner(ownerID, clientRequestID, input)
	case "approvals.decide":
		var input struct {
			ApprovalID string `json:"approval_id"`
			Decision   string `json:"decision"`
		}
		if err := decodeStrictClientJSON(bytes.NewReader(plaintext), 64*1024, &input); err != nil || input.ApprovalID == "" ||
			(input.Decision != "accept" && input.Decision != "decline") {
			return nil, errors.New("invalid approval decision")
		}
		return h.control.ResolveApprovalForClientRequest(clientRequestID, ownerID,
			input.ApprovalID, input.Decision)
	default:
		return nil, errors.New("Client operation is not available")
	}
}

func managerClientRPCOperations() []string {
	return clientcontract.OperationsForRole(clientcontract.RoleManager)
}

func externalClientRPCOperations() []string {
	return clientcontract.OperationsForRole(clientcontract.RoleExternal)
}

func parseCanonicalGroupKeyGrantTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("Group Endpoint key grant time must be canonical UTC RFC3339Nano")
	}
	return parsed.UTC(), nil
}
