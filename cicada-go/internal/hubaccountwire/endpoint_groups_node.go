package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointGroupsNodeOperation(op string) bool {
	return endpointGroupsContains(EndpointGroupsNodeOperations(), op)
}

func DecodeEndpointGroupsNodePacket(raw []byte) (nodewire.Packet, error) {
	var p nodewire.Packet
	if decodeCanonical(raw, MaxEndpointGroupsNodeReconcilePacketBytes, &p) != nil || p.Route.Version != nodewire.Version || !validID(p.Route.HubID) || !validID(p.Route.NodeID) || !validID(p.Route.BindingID) || !validID(p.Route.OperationID) || !validID(p.Route.SenderKeyID) || !validID(p.Route.ReceiverKeyID) ||
		!nativePairPositive(p.Route.BindingVersion) || !nativePairPositive(p.Route.NodeKeyEpoch) || !nativePairPositive(p.Route.Sequence) || !nativePairPositive(p.Route.SenderKeyVersion) || !nativePairPositive(p.Route.ReceiverKeyVersion) || !endpointGroupsNodeOperation(p.Route.Operation) || len(p.Envelope) == 0 {
		return nodewire.Packet{}, ErrInvalid
	}
	limit := MaxEndpointGroupsNodeReceiptBytes
	if p.Route.Direction == nodewire.DirectionRequest {
		limit = MaxEndpointGroupsNodeOriginalBytes
	} else if p.Route.Direction != nodewire.DirectionResponse {
		return nodewire.Packet{}, ErrInvalid
	}
	if p.Route.Operation == OperationEndpointGroupsNodeReconcile {
		limit = MaxEndpointGroupsNodeReconcilePacketBytes
	}
	if len(raw) > limit {
		return nodewire.Packet{}, ErrInvalid
	}
	return p, nil
}

func DecodeEndpointGroupsNodeRequest(op string, raw []byte) (any, error) {
	var out any
	limit := nodewire.MaxRequestPlaintextBytes
	switch op {
	case OperationEndpointGroupsNodeDescribe:
		out = &EndpointGroupsNodeDescribe{}
	case OperationEndpointGroupsNodeKeyPrepare:
		out = &EndpointGroupsNodeKeyPrepare{}
	case OperationEndpointGroupsNodeKeyComplete:
		out = &EndpointGroupsNodeKeyComplete{}
	case OperationEndpointGroupsNodeRenew:
		out = &EndpointGroupsNodeRenew{}
	case OperationEndpointGroupsNodeReconcile:
		out = &EndpointGroupsNodeReconcile{}
		limit = MaxEndpointGroupsNodeReconcileBodyBytes
	default:
		return nil, ErrInvalid
	}
	if decodeCanonical(raw, limit, out) != nil {
		return nil, ErrInvalid
	}
	switch q := dereference(out).(type) {
	case EndpointGroupsNodeDescribe:
		if !validID(q.EndpointID) || !validID(q.NetworkID) || !ownerEndpointGroupsCursor(q.Cursor) || q.Limit < 0 || q.Limit > 64 {
			return nil, ErrInvalid
		}
	case EndpointGroupsNodeKeyPrepare:
		if !isHex(q.PolicyID, 16) || !nativePairPositive(q.PolicyEpoch) || !validID(q.EndpointID) || !validID(q.GroupID) || !nativePairPositive(q.ExpectedRelationRevision) {
			return nil, ErrInvalid
		}
	case EndpointGroupsNodeKeyComplete:
		if !isHex(q.PolicyID, 16) || !nativePairPositive(q.PolicyEpoch) || !validID(q.EndpointID) || !validID(q.GroupID) || !nativePairPositive(q.ExpectedRelationRevision) || !isHex(q.ChallengeID, 16) || len(q.NodeProof) == 0 || len(q.NodeProof) > e2ee.MaxEndpointGroupProofBytes {
			return nil, ErrInvalid
		}
		var proof e2ee.EndpointGroupKeyProof
		if decodeCanonical(q.NodeProof, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || proof.Claims.PolicyID != q.PolicyID || proof.Claims.PolicyEpoch != q.PolicyEpoch || proof.Claims.ChallengeID != q.ChallengeID {
			return nil, ErrInvalid
		}
	case EndpointGroupsNodeRenew:
		if !validID(q.EndpointID) || !isHex(q.RegistrationDigest, 32) || !validID(q.ExpectedBindingID) || !nativePairPositive(q.ExpectedBindingEpoch) {
			return nil, ErrInvalid
		}
	case EndpointGroupsNodeReconcile:
		p, err := DecodeEndpointGroupsNodePacket(q.OriginalPacket)
		if err != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation == OperationEndpointGroupsNodeReconcile || len(q.OriginalPacket) > MaxEndpointGroupsNodeOriginalBytes {
			return nil, ErrInvalid
		}
	}
	return dereference(out), nil
}

func CanonicalEndpointGroupsNodeRequest(op string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := DecodeEndpointGroupsNodeRequest(op, raw); err != nil {
		return nil, ErrInvalid
	}
	return raw, nil
}

func ValidateEndpointGroupsRegistrationAnchor(a EndpointGroupsRegistrationAnchor, hub HubIdentity) error {
	digest, err := e2ee.EndpointGroupRegistrationDigest(a.Registration)
	if err != nil || validateHubIdentity(hub) != nil || a.Registration.HubID != hub.HubID || digest != a.RegistrationDigest || a.Profile != EndpointGroupsNativeProfile || a.RegistrationSource != EndpointGroupsRegistrationSource ||
		!e2ee.ValidLocalDomainUserScope(a.LocalUserScope) || !validID(a.NetworkID) || !validID(a.BindingID) || !validID(a.LeaseOwner) || !validID(a.NetworkAccessBindingID) ||
		e2ee.ValidatePublicIdentity(a.CandidatePublic) != nil || a.CandidateKeyID != a.CandidatePublic.ID || a.CandidateFingerprint != nativePairPeerFingerprint(a.CandidatePublic) || !isHex(a.CandidateProofDigest, 32) ||
		!endpointGroupsContains([]string{"REGISTERED", "OFFLINE", "REVOKED"}, a.State) || validateCanonicalTime(a.LeaseExpiresAt) != nil {
		return ErrInvalid
	}
	for _, n := range []uint64{a.RegistrationRevision, a.BindingEpoch, a.NodeKeyEpoch, a.NetworkAccessEpoch, a.NetworkMembershipRevision, a.EndpointNetworkRevision, a.CandidateVersion} {
		if !nativePairPositive(n) {
			return ErrInvalid
		}
	}
	return nil
}

func EndpointGroupsNativeIdentity(a EndpointGroupsRegistrationAnchor) e2ee.EndpointGroupNativeIdentity {
	r := a.Registration
	return e2ee.EndpointGroupNativeIdentity{HubID: r.HubID, OwnerID: r.OwnerID, NodeID: r.NodeID, LocalUserScope: a.LocalUserScope, Harness: r.Harness, NativeSessionID: r.NativeSessionID, Workspace: r.Workspace}
}

func endpointGroupsRelationForAnchor(r EndpointGroupRelation, a EndpointGroupsRegistrationAnchor) bool {
	n := a.Registration
	return r.HubID == n.HubID && r.OwnerID == n.OwnerID && r.NodeID == n.NodeID && r.LocalUserScope == a.LocalUserScope && r.NetworkID == a.NetworkID && r.EndpointID == n.EndpointID && r.PrincipalID == n.PrincipalID &&
		r.RegistrationDigest == a.RegistrationDigest && r.RegistrationRevision == a.RegistrationRevision && r.BindingID == a.BindingID && r.BindingEpoch == a.BindingEpoch && r.CandidateVersion == a.CandidateVersion &&
		r.CandidateKeyID == a.CandidateKeyID && r.CandidateFingerprint == a.CandidateFingerprint && r.CandidateProofDigest == a.CandidateProofDigest
}

func ValidateEndpointGroupsNodeDescribeResult(r EndpointGroupsNodeDescribeResult, hub HubIdentity, now time.Time) error {
	if now.IsZero() || r.ContractRevision != OwnerEndpointGroupsContractRevision || ValidateEndpointGroupsRegistrationAnchor(r.Registration, hub) != nil || r.Registration.State == "REVOKED" ||
		len(r.Relations) > 64 || len(r.Authorities) > len(r.Relations) || r.RelationsRevision >= 1<<63 || !ownerEndpointGroupsCursor(r.NextCursor) || r.Complete != (r.NextCursor == "") || validateRecent(r.ObservedAt, now, 30*time.Second) != nil {
		return ErrInvalid
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > MaxOwnerEndpointGroupsPageBytes {
		return ErrInvalid
	}
	nativeDigest, err := e2ee.EndpointGroupNativeIdentityDigest(EndpointGroupsNativeIdentity(r.Registration))
	if err != nil {
		return ErrInvalid
	}
	authorities := map[string]EndpointGroupCurrentEndpoint{}
	for i, a := range r.Authorities {
		if validateEndpointGroupCurrentEndpoint(a, now) != nil || !endpointGroupsRelationForAnchor(a.Relation, r.Registration) || i > 0 && r.Authorities[i-1].Relation.GroupID >= a.Relation.GroupID {
			return ErrInvalid
		}
		digest, err := e2ee.EndpointGroupOwnerControlDigest(nativeDigest, a.Relation.GroupID, a.OwnerControl)
		if err != nil || digest != a.Relation.OwnerControlDigest {
			return ErrInvalid
		}
		authorities[a.Relation.GroupID] = a
	}
	for i, c := range r.Relations {
		if !endpointGroupsRelationCard(c) || c.NetworkID != r.Registration.NetworkID || i > 0 && r.Relations[i-1].GroupID >= c.GroupID {
			return ErrInvalid
		}
		a, found := authorities[c.GroupID]
		if (c.State == "ACTIVE") != found {
			return ErrInvalid
		}
		if found && (c.OwnerControl != a.OwnerControl || c.SelectedSource == nil || *c.SelectedSource != (EndpointGroupSourceReference{a.Relation.Source, a.Relation.AuthorityID, a.Relation.AuthorityEpoch, a.Relation.ContributionRevision}) || c.ExpiresAt != a.Relation.ExpiresAt) {
			return ErrInvalid
		}
		delete(authorities, c.GroupID)
	}
	if len(authorities) != 0 {
		return ErrInvalid
	}
	return nil
}

func ValidateEndpointGroupsNodeReconcileTarget(r EndpointGroupsNodeReconciled, original []byte) error {
	p, err := DecodeEndpointGroupsNodePacket(original)
	if err != nil || p.Route.Direction != nodewire.DirectionRequest || p.Route.Operation == OperationEndpointGroupsNodeReconcile || r.ContractRevision != OwnerEndpointGroupsContractRevision ||
		r.OriginalOperation != p.Route.Operation || r.OriginalOperationID != p.Route.OperationID || r.OriginalSequence != p.Route.Sequence || r.OriginalPacketDigest != nodewire.RecoveryDigest(original) ||
		!endpointGroupsContains([]string{"COMPLETED", "REJECTED_FENCED", "READ_EXPIRED"}, r.State) || validateCanonicalTime(r.ObservedAt) != nil || len(r.ReceiptPacket) == 0 || len(r.ReceiptPacket) > MaxEndpointGroupsNodeReceiptBytes {
		return ErrInvalid
	}
	receipt, err := DecodeEndpointGroupsNodePacket(r.ReceiptPacket)
	want := p.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = p.Route.ReceiverKeyID, p.Route.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = p.Route.ReceiverKeyVersion, p.Route.SenderKeyVersion
	if err != nil || receipt.Route != want {
		return ErrInvalid
	}
	return nil
}

func endpointGroupsPolicyForAnchor(p e2ee.EndpointGroupPolicy, a EndpointGroupsRegistrationAnchor) bool {
	n := a.Registration
	return p.HubID == n.HubID && p.OwnerID == n.OwnerID && p.Node.NodeID == n.NodeID && p.Node.NodeKeyEpoch == a.NodeKeyEpoch && p.LocalUserScope == a.LocalUserScope && p.NetworkID == a.NetworkID &&
		p.EndpointID == n.EndpointID && p.PrincipalID == n.PrincipalID && p.RegistrationDigest == a.RegistrationDigest && p.RegistrationRevision == a.RegistrationRevision && p.BindingID == a.BindingID && p.BindingEpoch == a.BindingEpoch &&
		p.CandidateVersion == a.CandidateVersion && p.EndpointKeyID == a.CandidateKeyID && reflect.DeepEqual(p.EndpointPublic, a.CandidatePublic) && p.EndpointFingerprint == a.CandidateFingerprint && p.CandidateProofDigest == a.CandidateProofDigest
}
