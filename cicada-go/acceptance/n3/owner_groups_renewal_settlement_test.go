package n3_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type ownerGroupsSettlementRegistration struct {
	Anchor   wire.EndpointGroupsRegistrationAnchor `json:"anchor"`
	IntentID string                                `json:"intent_id"`
}

type ownerGroupsRenewalReference struct {
	before             ownerGroupsSettlementRegistration
	request            wire.EndpointGroupsNodeRenew
	hub                wire.HubIdentity
	originalRecordedAt string
	exchanges          func() []exchange
}

// Snapshot the stopped real Node before the unshortened cold interval. These
// original anchors stay in memory only; no registration or grant is installed.
func readOwnerGroupsRenewalAnchors(t *testing.T, v *codexProductFixture, originals []ownerGroupsIdentity) map[string]ownerGroupsSettlementRegistration {
	t.Helper()
	raw := readNodeControlState(t, v.actualNode.statePath())
	var state ownerGroupsSettlementState
	err := json.Unmarshal(raw, &state)
	clear(raw)
	if err != nil || len(originals) != 4 {
		t.Fatal("renewal observation lost the four original protected registrations")
	}
	result := make(map[string]ownerGroupsSettlementRegistration)
	for _, original := range originals {
		matches := 0
		for digest, registered := range state.Registrations {
			a := registered.Anchor
			if a.Registration.EndpointID != original.Endpoint {
				continue
			}
			if digest != a.RegistrationDigest || registered.IntentID == "" || wire.ValidateEndpointGroupsRegistrationAnchor(a, v.f.cfg.Hub) != nil || a.State != "REGISTERED" ||
				a.Registration.NativeSessionID != original.SID || a.Registration.PrincipalID != original.Principal || a.Registration.Workspace != original.Workspace ||
				a.Registration.NodeID != original.NodeID || a.BindingID != original.BindingID || a.BindingEpoch != original.BindingEpoch || hash(must(json.Marshal(a.CandidatePublic))) != original.PublicKeySHA256 {
				t.Fatal("cold renewal snapshot changed an original registration or key")
			}
			matches++
			result[digest] = registered
		}
		if matches != 1 {
			t.Fatal("cold renewal lacks a unique original registration")
		}
	}
	if len(result) != 4 {
		t.Fatal("cold renewal merged original registrations")
	}
	return result
}

func awaitOwnerGroupsRenewalSettlement(t *testing.T, v *codexProductFixture, label string, original exchange, started time.Time, frozen map[string]ownerGroupsSettlementRegistration) {
	t.Helper()
	q, ok := openOwnerGroupsNodeRequest(t, v, original.request).(wire.EndpointGroupsNodeRenew)
	before, present := frozen[q.RegistrationDigest]
	if !ok || !present {
		t.Fatal("lost renewal is not one of the four frozen original registrations")
	}
	ref := &ownerGroupsRenewalReference{before: before, request: q, hub: v.f.cfg.Hub, originalRecordedAt: original.RecordedAt, exchanges: v.f.proxy.snapshot}
	awaitOwnerGroupsSettlementSince(t, v, label, original, started, ref)
}

// This observes convergence of the same original registration. It does not
// prove which implementation consumed a response, dispatch recovery or confer
// current Group authority. M5 still requires a fresh Guard and actual exchange.
func ownerGroupsRenewalReady(s ownerGroupsSettlementState, intentID string, original ownerGroupsSettlementReference, reply appPairNodeReply, key *e2ee.Identity, binding nodewire.Binding) (bool, map[string]any, error) {
	d := map[string]any{"local_present": false, "expiry_relation": "NOT_READ", "renewal_progress_source": "NONE"}
	reject := func(code string) (bool, map[string]any, error) { return false, d, errors.New(code) }
	r := original.renewal
	if r == nil || !reply.OK {
		return reject("RENEWAL_ORIGINAL_POSITIVE_REQUIRED")
	}
	before, q := r.before.Anchor, r.request
	d["old_lease_expires_at"] = before.LeaseExpiresAt
	var renewed wire.EndpointGroupsNodeRenewResult
	if json.Unmarshal(reply.Result, &renewed) != nil || renewed.ContractRevision != wire.OwnerEndpointGroupsContractRevision ||
		wire.ValidateEndpointGroupsRegistrationAnchor(before, r.hub) != nil || wire.ValidateEndpointGroupsRegistrationAnchor(renewed.Registration, r.hub) != nil ||
		before.State != "REGISTERED" || renewed.Registration.State != "REGISTERED" || r.before.IntentID != intentID ||
		q.EndpointID != before.Registration.EndpointID || q.RegistrationDigest != before.RegistrationDigest || q.ExpectedBindingID != before.BindingID || q.ExpectedBindingEpoch != before.BindingEpoch {
		return reject("RENEWAL_ORIGINAL_REGISTRATION_CHANGED")
	}
	d["original_lease_expires_at"] = renewed.Registration.LeaseExpiresAt
	oldExpiry, oldErr := time.Parse(time.RFC3339Nano, before.LeaseExpiresAt)
	newExpiry, newErr := time.Parse(time.RFC3339Nano, renewed.Registration.LeaseExpiresAt)
	if _, err := time.Parse(time.RFC3339Nano, renewed.ObservedAt); err != nil || oldErr != nil || newErr != nil || !newExpiry.After(oldExpiry) {
		return reject("RENEWAL_ORIGINAL_LEASE_NOT_EXTENDED")
	}
	immutable := renewed.Registration
	immutable.LeaseExpiresAt = before.LeaseExpiresAt
	if !reflect.DeepEqual(immutable, before) {
		return reject("RENEWAL_IMMUTABLE_ANCHOR_CHANGED")
	}
	local, present := s.Registrations[before.RegistrationDigest]
	d["local_present"] = present
	if !present {
		return false, d, nil
	}
	localImmutable := local.Anchor
	localImmutable.LeaseExpiresAt = before.LeaseExpiresAt
	if local.IntentID != r.before.IntentID || !reflect.DeepEqual(localImmutable, before) || wire.ValidateEndpointGroupsRegistrationAnchor(local.Anchor, r.hub) != nil {
		return reject("RENEWAL_LOCAL_REGISTRATION_CHANGED")
	}
	localExpiry, err := time.Parse(time.RFC3339Nano, local.Anchor.LeaseExpiresAt)
	d["local_lease_expires_at"] = local.Anchor.LeaseExpiresAt
	if err != nil {
		return reject("RENEWAL_LOCAL_LEASE_INVALID")
	}
	d["local_lease_current"] = time.Now().Before(localExpiry)
	switch {
	case localExpiry.Before(newExpiry):
		d["expiry_relation"] = "BEFORE_ORIGINAL"
	case localExpiry.Equal(newExpiry):
		d["expiry_relation"] = "EQUAL_ORIGINAL"
	default:
		d["expiry_relation"] = "AFTER_ORIGINAL"
	}
	if !time.Now().Before(localExpiry) || localExpiry.Before(newExpiry) {
		return false, d, nil
	}
	if reflect.DeepEqual(local.Anchor, renewed.Registration) {
		d["renewal_progress_source"] = "ORIGINAL_AUTHENTICATED_RENEW"
		return true, d, nil
	}
	// A larger scalar is insufficient. Only this run's later actual forwarded
	// Hub response, matching this exact local anchor/tuple, witnesses progress.
	if r.exchanges == nil {
		return false, d, nil
	}
	after, err := time.Parse(time.RFC3339Nano, r.originalRecordedAt)
	if err != nil {
		return false, d, nil
	}
	for _, ex := range r.exchanges() {
		source := ownerGroupsRenewalProgressSource(ex, after, local.Anchor, r.hub, key, binding)
		if source == "" {
			continue
		}
		d["renewal_progress_source"], d["progress_request_sha256"], d["progress_response_sha256"] = source, ex.RequestSHA256, ex.ResponseSHA256
		d["progress_started_at"], d["progress_recorded_at"] = ex.StartedAt, ex.RecordedAt
		return true, d, nil
	}
	return false, d, nil
}

// exchanges must come from the fixture's fixed-origin forwarding proxy. The
// heartbeat branch is transport/session-Guard evidence, not a new PQ signature.
// Describe additionally authenticates the full Node response route and DTO.
func ownerGroupsRenewalProgressSource(ex exchange, after time.Time, local wire.EndpointGroupsRegistrationAnchor, hub wire.HubIdentity, key *e2ee.Identity, binding nodewire.Binding) string {
	started, e1 := time.Parse(time.RFC3339Nano, ex.StartedAt)
	recorded, e2 := time.Parse(time.RFC3339Nano, ex.RecordedAt)
	if e1 != nil || e2 != nil || !started.After(after) || recorded.Before(started) || recorded.After(time.Now()) ||
		!ex.Forwarded || ex.Status != http.StatusOK || ex.FaultMode != "" || ex.Method != http.MethodPost ||
		ex.RequestSHA256 != hash(ex.request) || len(ex.response) == 0 || ex.ResponseSHA256 != hash(ex.response) {
		return ""
	}
	if ex.Path == "/v2/fabric/heartbeat" {
		var actor fabric.Actor
		decoder := json.NewDecoder(bytes.NewReader(ex.response))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&actor) != nil || decoder.Decode(new(any)) != io.EOF || actor.EndpointID != local.Registration.EndpointID || actor.PrincipalID != local.Registration.PrincipalID ||
			actor.NetworkID != local.NetworkID || actor.BindingID != local.BindingID || actor.BindingEpoch != local.BindingEpoch || actor.LeaseOwner != local.LeaseOwner || actor.LeaseExpiresAt != local.LeaseExpiresAt || actor.GroupID != "" || actor.MembershipID != "" || actor.MembershipRevision != 0 {
			return ""
		}
		return "FORWARDED_HUB_HEARTBEAT_SESSION_GUARD_NOT_PQ"
	}
	if ex.Path != "/v2/node/control/rpc" {
		return ""
	}
	packet, err := wire.DecodeEndpointGroupsNodePacket(ex.request)
	if err != nil || packet.Route.Direction != nodewire.DirectionRequest || packet.Route.Operation != wire.OperationEndpointGroupsNodeDescribe {
		return ""
	}
	opened, err := nodewire.OpenResponse(key, binding.HubKey, binding, ex.response)
	if err != nil {
		return ""
	}
	defer clear(opened.Plaintext)
	want := packet.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	var reply appPairNodeReply
	var described wire.EndpointGroupsNodeDescribeResult
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &reply) != nil || !reply.OK || reply.ErrorCode != "" || reply.OperationID != want.OperationID || reply.Sequence != want.Sequence ||
		json.Unmarshal(reply.Result, &described) != nil || wire.ValidateEndpointGroupsNodeDescribeResult(described, hub, recorded) != nil || !reflect.DeepEqual(described.Registration, local) {
		return ""
	}
	return "AUTHENTICATED_NODE_DESCRIBE"
}
