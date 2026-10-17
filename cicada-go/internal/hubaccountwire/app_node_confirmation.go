package hubaccountwire

import (
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

// AppNodeConfirmationResponse is a local verified projection, not a new wire
// response. It retains the existing Client RPC wrapper and Node binding DTO.
type AppNodeConfirmationResponse struct {
	RequestID, OperationID string
	OK                     bool
	Error                  string
	Binding                *e2ee.OwnerAppNodeBinding
}

func SealAppNodeConfirmation(device *e2ee.Identity, hub HubIdentity, grant e2ee.OwnerAppNodeGrantClaims, code string, requestSequence uint64, now time.Time) ([]byte, error) {
	if device == nil || grant.Profile != AppNodeProfileInitial || grant.Candidate == nil || ValidateAppNodeGrantClaims(grant, hub, time.Time{}) != nil || !reflect.DeepEqual(device.Public(), grant.Scope.DevicePublic) || requestSequence == 0 || requestSequence > math.MaxInt64 || now.IsZero() {
		return nil, ErrInvalid
	}
	for _, end := range []string{grant.LeaseExpiresAt, grant.Scope.AccountSessionExpiresAt, grant.Candidate.ExpiresAt} {
		t, err := parseCanonicalUTC(end)
		if err != nil || !now.Before(t) {
			return nil, ErrInvalid
		}
	}
	normalized, err := NormalizeAppNodeCode(code)
	if err != nil {
		return nil, err
	}
	digest, err := AppNodeCodeDigest(hub.HubID, normalized)
	if err != nil || digest != grant.Candidate.CodeDigest {
		return nil, ErrInvalid
	}
	nonce, err := NewRequestID()
	if err != nil {
		return nil, err
	}
	id, err := AppNodeBusinessOperationID(grant.GrantID, nonce)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		Code    string `json:"user_code"`
		Digest  string `json:"candidate_digest"`
		Version uint64 `json:"candidate_version"`
	}{normalized, grant.Candidate.CandidateDigest, grant.Candidate.Version})
	if err != nil {
		return nil, err
	}
	b := appNodeClientBinding(grant, hub)
	r := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: b.HubID, OwnerID: b.OwnerID, DeviceID: b.DeviceID, SessionEpoch: b.SessionEpoch, Sequence: requestSequence, OperationID: id, Operation: "nodes.confirm", SenderKeyID: device.Public().ID, SenderKeyVersion: b.DeviceKeyVersion, ReceiverKeyID: hub.Public.ID, ReceiverKeyVersion: hub.KeyVersion}
	packet, err := clientwire.SealRequest(device, hub.Public, b, r, body)
	if err != nil || len(packet) > MaxAppNodeMutationPacketBytes {
		return nil, ErrInvalid
	}
	return packet, nil
}

func appNodeClientBinding(grant e2ee.OwnerAppNodeGrantClaims, hub HubIdentity) clientwire.Binding {
	return clientwire.Binding{HubID: hub.HubID, OwnerID: grant.Scope.OwnerID, DeviceID: grant.Scope.DeviceID, SessionEpoch: grant.Scope.ClientSessionEpoch, HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
}

// OpenAppNodeConfirmationResponse authenticates the exact persisted original
// route and expected durable response sequence. Historical receipt recovery is
// allowed; callers must separately require fresh current authority for actions.
func OpenAppNodeConfirmationResponse(device *e2ee.Identity, hub HubIdentity, grant e2ee.OwnerAppNodeGrantClaims, original, response []byte, expectedResponseSequence uint64) (AppNodeConfirmationResponse, error) {
	if device == nil || ValidateAppNodeGrantClaims(grant, hub, time.Time{}) != nil || !reflect.DeepEqual(device.Public(), grant.Scope.DevicePublic) || expectedResponseSequence == 0 || expectedResponseSequence > math.MaxInt64 {
		return AppNodeConfirmationResponse{}, ErrInvalid
	}
	r, _, err := appNodeOriginalRoute(AppNodeOriginalClient, original)
	if err != nil {
		return AppNodeConfirmationResponse{}, err
	}
	instance, _, err := ParseAppNodeBusinessOperationID(r.OperationID)
	if err != nil || instance != grant.GrantID || r.HubID != hub.HubID || r.OwnerID != grant.Scope.OwnerID || r.DeviceID != grant.Scope.DeviceID || r.SessionEpoch != grant.Scope.ClientSessionEpoch || r.SenderKeyID != device.Public().ID || r.ReceiverKeyID != hub.Public.ID {
		return AppNodeConfirmationResponse{}, ErrInvalid
	}
	opened, err := clientwire.OpenResponse(device, hub.Public, appNodeClientBinding(grant, hub), response)
	expected := responseRoute(r)
	expected.Sequence = expectedResponseSequence
	if err != nil || opened.Route != expected {
		return AppNodeConfirmationResponse{}, ErrInvalid
	}
	var wrapper struct {
		Error       string          `json:"error,omitempty"`
		OK          bool            `json:"ok"`
		OperationID string          `json:"operation_id"`
		RequestID   string          `json:"request_id"`
		Result      json.RawMessage `json:"result,omitempty"`
	}
	if decodeCanonical(opened.Plaintext, 64*1024, &wrapper) != nil || wrapper.OperationID != r.OperationID || !validID(wrapper.RequestID) || (wrapper.OK && wrapper.Error != "") || (!wrapper.OK && (wrapper.Error == "" || len(wrapper.Result) > 0)) {
		return AppNodeConfirmationResponse{}, ErrInvalid
	}
	out := AppNodeConfirmationResponse{RequestID: wrapper.RequestID, OperationID: wrapper.OperationID, OK: wrapper.OK, Error: wrapper.Error}
	if !wrapper.OK {
		return out, nil
	}
	binding, err := decodeAppNodeLegacyBinding(wrapper.Result)
	if err != nil || ValidateAppNodeConfirmationBinding(grant, binding) != nil {
		return AppNodeConfirmationResponse{}, ErrInvalid
	}
	out.Binding = &binding
	return out, nil
}

func ValidateAppNodeConfirmationBinding(grant e2ee.OwnerAppNodeGrantClaims, b e2ee.OwnerAppNodeBinding) error {
	if grant.Profile != AppNodeProfileInitial || grant.Candidate == nil || ValidateAppNodeExistingBinding(b, grant.Scope) != nil {
		return ErrInvalid
	}
	n := grant.Candidate
	approved, err := parseCanonicalUTC(b.ApprovedAt)
	prepared, _ := parseCanonicalUTC(grant.PreparedAt)
	if err != nil || approved.Before(prepared) || b.NodeKeyVersion != 1 {
		return ErrInvalid
	}
	for _, end := range []string{grant.LeaseExpiresAt, grant.Scope.AccountSessionExpiresAt, n.ExpiresAt} {
		deadline, e := parseCanonicalUTC(end)
		if e != nil || !approved.Before(deadline) {
			return ErrInvalid
		}
	}
	if b.NodeID != n.NodeID || b.NodeName != n.NodeName || !reflect.DeepEqual(b.NodePublic, n.NodePublic) || b.NodeKeyFingerprint != n.NodeKeyFingerprint || b.NodeKeyEpoch != n.NodeKeyEpoch || !reflect.DeepEqual(b.HubNodeControlPublic, n.HubNodeControlPublic) || b.HubNodeControlFingerprint != n.HubNodeControlFingerprint || b.HubNodeControlKeyVersion != n.HubNodeControlKeyVersion || b.ApprovedRequestID != n.RequestID || b.ApprovedRequestVersion != n.Version || b.ApprovedCandidateDigest != n.CandidateDigest {
		return ErrInvalid
	}
	return nil
}

func decodeAppNodeLegacyBinding(raw []byte) (e2ee.OwnerAppNodeBinding, error) {
	// This exactly mirrors the frozen Store NodeControlKeyBinding public shape.
	// The adapter stays here so the App does not import Store or guess aliases.
	var old struct {
		OwnerBindingID          string              `json:"owner_binding_id"`
		OwnerID                 string              `json:"owner_id"`
		HubID                   string              `json:"hub_id"`
		NodeID                  string              `json:"node_id"`
		NodeName                string              `json:"node_name"`
		ClientDeviceID          string              `json:"client_device_id"`
		OwnerKeyID              string              `json:"owner_key_id"`
		NodeCredentialVersion   uint64              `json:"node_credential_version"`
		BindingVersion          uint64              `json:"binding_version"`
		NodeKeyID               string              `json:"node_key_id"`
		NodePublicIdentity      e2ee.PublicIdentity `json:"node_public_identity"`
		NodeKeyFingerprint      string              `json:"node_key_fingerprint"`
		NodeKeyVersion          uint64              `json:"node_key_version"`
		NodeKeyEpoch            uint64              `json:"node_key_epoch"`
		HubKeyID                string              `json:"hub_key_id"`
		HubPublicIdentity       e2ee.PublicIdentity `json:"hub_public_identity"`
		HubKeyFingerprint       string              `json:"hub_key_fingerprint"`
		HubKeyVersion           uint64              `json:"hub_key_version"`
		ApprovedRequestID       string              `json:"approved_request_id"`
		ApprovedRequestVersion  int64               `json:"approved_request_version"`
		ApprovedCandidateDigest string              `json:"approved_candidate_digest"`
		ApprovedOwnerDeviceID   string              `json:"approved_owner_device_id"`
		ApprovedOwnerKeyID      string              `json:"approved_owner_key_id"`
		ApprovedAt              string              `json:"approved_at"`
		State                   string              `json:"state"`
		Version                 uint64              `json:"version"`
		RevokedAt               string              `json:"revoked_at,omitempty"`
	}
	if decodeCanonical(raw, 64*1024, &old) != nil || old.NodeKeyID != old.NodePublicIdentity.ID || old.HubKeyID != old.HubPublicIdentity.ID || old.ApprovedRequestVersion <= 0 || old.ApprovedOwnerDeviceID != old.ClientDeviceID || old.ApprovedOwnerKeyID != old.OwnerKeyID || old.Version == 0 || old.RevokedAt != "" {
		return e2ee.OwnerAppNodeBinding{}, ErrInvalid
	}
	return e2ee.OwnerAppNodeBinding{OwnerBindingID: old.OwnerBindingID, OwnerID: old.OwnerID, HubID: old.HubID, NodeID: old.NodeID, NodeName: old.NodeName, ClientDeviceID: old.ClientDeviceID, OwnerKeyID: old.OwnerKeyID, CredentialVersion: old.NodeCredentialVersion, BindingVersion: old.BindingVersion,
		NodePublic: old.NodePublicIdentity, NodeKeyFingerprint: old.NodeKeyFingerprint, NodeKeyVersion: old.NodeKeyVersion, NodeKeyEpoch: old.NodeKeyEpoch, HubNodeControlPublic: old.HubPublicIdentity, HubNodeControlFingerprint: old.HubKeyFingerprint, HubNodeControlKeyVersion: old.HubKeyVersion,
		ApprovedRequestID: old.ApprovedRequestID, ApprovedRequestVersion: uint64(old.ApprovedRequestVersion), ApprovedCandidateDigest: old.ApprovedCandidateDigest, ApprovedAt: old.ApprovedAt, State: old.State}, nil
}
