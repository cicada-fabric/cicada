package hubaccountwire

import (
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

// AppNodeScopedConfirmationResponse is a local verified projection, not a new wire
// response. It retains the existing Client RPC wrapper and Node binding DTO.
type AppNodeScopedConfirmationResponse struct {
	RequestID, OperationID string
	OK                     bool
	Error                  string
	Binding                *e2ee.OwnerAppNodeBinding
}

func SealAppNodeScopedConfirmation(device *e2ee.Identity, hub HubIdentity, grant e2ee.OwnerAppNodeScopedGrantClaims, code string, requestSequence uint64, now time.Time) ([]byte, error) {
	if device == nil || grant.Profile != AppNodeScopedProfileInitial || grant.Candidate == nil || ValidateAppNodeScopedGrantClaims(grant, hub, time.Time{}) != nil || !reflect.DeepEqual(device.Public(), grant.Scope.DevicePublic) || requestSequence == 0 || requestSequence > math.MaxInt64 || now.IsZero() {
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
	id, err := AppNodeScopedBusinessOperationID(grant.GrantID, nonce)
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
	b := appNodeScopedClientBinding(grant, hub)
	r := clientwire.Route{Version: 1, Direction: clientwire.DirectionRequest, HubID: b.HubID, OwnerID: b.OwnerID, DeviceID: b.DeviceID, SessionEpoch: b.SessionEpoch, Sequence: requestSequence, OperationID: id, Operation: "nodes.confirm", SenderKeyID: device.Public().ID, SenderKeyVersion: b.DeviceKeyVersion, ReceiverKeyID: hub.Public.ID, ReceiverKeyVersion: hub.KeyVersion}
	packet, err := clientwire.SealRequest(device, hub.Public, b, r, body)
	if err != nil || len(packet) > MaxAppNodeScopedMutationPacketBytes {
		return nil, ErrInvalid
	}
	return packet, nil
}

func appNodeScopedClientBinding(grant e2ee.OwnerAppNodeScopedGrantClaims, hub HubIdentity) clientwire.Binding {
	return clientwire.Binding{HubID: hub.HubID, OwnerID: grant.Scope.OwnerID, DeviceID: grant.Scope.DeviceID, SessionEpoch: grant.Scope.ClientSessionEpoch, HubKeyVersion: hub.KeyVersion, DeviceKeyVersion: DeviceKeyVersion}
}

// OpenAppNodeScopedConfirmationResponse authenticates the exact persisted original
// route and expected durable response sequence. Historical receipt recovery is
// allowed; callers must separately require fresh current authority for actions.
func OpenAppNodeScopedConfirmationResponse(device *e2ee.Identity, hub HubIdentity, grant e2ee.OwnerAppNodeScopedGrantClaims, original, response []byte, expectedResponseSequence uint64) (AppNodeScopedConfirmationResponse, error) {
	if device == nil || ValidateAppNodeScopedGrantClaims(grant, hub, time.Time{}) != nil || !reflect.DeepEqual(device.Public(), grant.Scope.DevicePublic) || expectedResponseSequence == 0 || expectedResponseSequence > math.MaxInt64 {
		return AppNodeScopedConfirmationResponse{}, ErrInvalid
	}
	r, _, err := appNodeScopedOriginalRoute(AppNodeScopedOriginalClient, original)
	if err != nil {
		return AppNodeScopedConfirmationResponse{}, err
	}
	instance, _, err := ParseAppNodeScopedBusinessOperationID(r.OperationID)
	if err != nil || instance != grant.GrantID || r.HubID != hub.HubID || r.OwnerID != grant.Scope.OwnerID || r.DeviceID != grant.Scope.DeviceID || r.SessionEpoch != grant.Scope.ClientSessionEpoch || r.SenderKeyID != device.Public().ID || r.ReceiverKeyID != hub.Public.ID {
		return AppNodeScopedConfirmationResponse{}, ErrInvalid
	}
	opened, err := clientwire.OpenResponse(device, hub.Public, appNodeScopedClientBinding(grant, hub), response)
	expected := responseRoute(r)
	expected.Sequence = expectedResponseSequence
	if err != nil || opened.Route != expected {
		return AppNodeScopedConfirmationResponse{}, ErrInvalid
	}
	var wrapper struct {
		Error       string          `json:"error,omitempty"`
		OK          bool            `json:"ok"`
		OperationID string          `json:"operation_id"`
		RequestID   string          `json:"request_id"`
		Result      json.RawMessage `json:"result,omitempty"`
	}
	if decodeCanonical(opened.Plaintext, 64*1024, &wrapper) != nil || wrapper.OperationID != r.OperationID || !validID(wrapper.RequestID) || (wrapper.OK && wrapper.Error != "") || (!wrapper.OK && (wrapper.Error == "" || len(wrapper.Result) > 0)) {
		return AppNodeScopedConfirmationResponse{}, ErrInvalid
	}
	out := AppNodeScopedConfirmationResponse{RequestID: wrapper.RequestID, OperationID: wrapper.OperationID, OK: wrapper.OK, Error: wrapper.Error}
	if !wrapper.OK {
		return out, nil
	}
	binding, err := decodeAppNodeLegacyBinding(wrapper.Result)
	if err != nil || ValidateAppNodeScopedConfirmationBinding(grant, binding) != nil {
		return AppNodeScopedConfirmationResponse{}, ErrInvalid
	}
	out.Binding = &binding
	return out, nil
}

func ValidateAppNodeScopedConfirmationBinding(grant e2ee.OwnerAppNodeScopedGrantClaims, b e2ee.OwnerAppNodeBinding) error {
	if grant.Profile != AppNodeScopedProfileInitial || grant.Candidate == nil || ValidateAppNodeScopedExistingBinding(b, grant.Scope) != nil {
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
