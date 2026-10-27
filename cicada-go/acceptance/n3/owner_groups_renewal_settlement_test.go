package n3_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type ownerGroupsSettlementRegistration struct {
	Anchor   wire.EndpointGroupsRegistrationAnchor `json:"anchor"`
	IntentID string                                `json:"intent_id"`
}

type ownerGroupsRenewalReference struct {
	before  ownerGroupsSettlementRegistration
	request wire.EndpointGroupsNodeRenew
	hub     wire.HubIdentity
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
	ref := &ownerGroupsRenewalReference{before: before, request: q, hub: v.f.cfg.Hub}
	awaitOwnerGroupsSettlementSince(t, v, label, original, started, ref)
}

// This matcher observes a settled original plus its consumed local anchor. It
// cannot dispatch recovery, update a lease, or supply current Group authority.
func ownerGroupsRenewalReady(s ownerGroupsSettlementState, intentID string, original ownerGroupsSettlementReference, reply appPairNodeReply) (bool, error) {
	r := original.renewal
	if r == nil || !reply.OK {
		return false, errors.New("RENEWAL_ORIGINAL_POSITIVE_REQUIRED")
	}
	before, q := r.before.Anchor, r.request
	var renewed wire.EndpointGroupsNodeRenewResult
	if json.Unmarshal(reply.Result, &renewed) != nil || renewed.ContractRevision != wire.OwnerEndpointGroupsContractRevision ||
		wire.ValidateEndpointGroupsRegistrationAnchor(before, r.hub) != nil || wire.ValidateEndpointGroupsRegistrationAnchor(renewed.Registration, r.hub) != nil ||
		before.State != "REGISTERED" || renewed.Registration.State != "REGISTERED" || r.before.IntentID != intentID ||
		q.EndpointID != before.Registration.EndpointID || q.RegistrationDigest != before.RegistrationDigest || q.ExpectedBindingID != before.BindingID || q.ExpectedBindingEpoch != before.BindingEpoch {
		return false, errors.New("RENEWAL_ORIGINAL_REGISTRATION_CHANGED")
	}
	oldExpiry, oldErr := time.Parse(time.RFC3339Nano, before.LeaseExpiresAt)
	newExpiry, newErr := time.Parse(time.RFC3339Nano, renewed.Registration.LeaseExpiresAt)
	if _, err := time.Parse(time.RFC3339Nano, renewed.ObservedAt); err != nil || oldErr != nil || newErr != nil || !newExpiry.After(oldExpiry) {
		return false, errors.New("RENEWAL_ORIGINAL_LEASE_NOT_EXTENDED")
	}
	immutable := renewed.Registration
	immutable.LeaseExpiresAt = before.LeaseExpiresAt
	if !reflect.DeepEqual(immutable, before) {
		return false, errors.New("RENEWAL_IMMUTABLE_ANCHOR_CHANGED")
	}
	local, present := s.Registrations[before.RegistrationDigest]
	if !present {
		return false, nil
	}
	localImmutable := local.Anchor
	localImmutable.LeaseExpiresAt = before.LeaseExpiresAt
	if local.IntentID != r.before.IntentID || !reflect.DeepEqual(localImmutable, before) {
		return false, errors.New("RENEWAL_LOCAL_REGISTRATION_CHANGED")
	}
	return reflect.DeepEqual(local.Anchor, renewed.Registration), nil
}
