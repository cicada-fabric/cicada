package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func OwnerEndpointGroupsReviewDigest(r OwnerEndpointGroupsReview) (string, error) {
	return ownerEndpointGroupsDigest("cicada/owner/endpoint-groups/review/v1\x00", struct {
		ReviewID            string                        `json:"review_id"`
		RequestID           string                        `json:"request_id"`
		RequestPacketDigest string                        `json:"request_packet_digest"`
		Action              string                        `json:"action"`
		Target              OwnerEndpointGroupsTarget     `json:"target"`
		Expected            OwnerEndpointGroupsCAS        `json:"expected"`
		Projection          OwnerEndpointGroupsProjection `json:"projection"`
		KeyManifest         *LocalDomainKeyManifest       `json:"key_manifest,omitempty"`
		ObservedAt          string                        `json:"observed_at"`
		ExpiresAt           string                        `json:"expires_at"`
	}{r.ReviewID, r.RequestID, r.RequestPacketDigest, r.Action, r.Target, r.Expected, r.Projection, r.KeyManifest, r.ObservedAt, r.ExpiresAt})
}

func ownerEndpointGroupsCASValid(c OwnerEndpointGroupsCAS, create bool) bool {
	for _, n := range []uint64{c.OwnerKeyVersion, c.NodeOwnerBindingVersion, c.NodeKeyEpoch, c.NetworkVersion} {
		if !nativePairPositive(n) {
			return false
		}
	}
	if !validID(c.NodeOwnerBindingID) {
		return false
	}
	if create {
		return c == (OwnerEndpointGroupsCAS{OwnerKeyVersion: c.OwnerKeyVersion, NodeOwnerBindingID: c.NodeOwnerBindingID, NodeOwnerBindingVersion: c.NodeOwnerBindingVersion, NodeKeyEpoch: c.NodeKeyEpoch, NetworkVersion: c.NetworkVersion})
	}
	for _, n := range []uint64{c.GroupVersion, c.RegistrationRevision, c.BindingEpoch, c.CandidateVersion} {
		if !nativePairPositive(n) {
			return false
		}
	}
	for _, n := range []uint64{c.MembershipRevision, c.EndpointJoinRevision, c.RelationRevision, c.DecisionRevision, c.PolicyEpoch} {
		if n >= 1<<63-1 {
			return false
		}
	}
	return validID(c.BindingID) && isHex(c.RegistrationDigest, 32) && isHex(c.CandidateProofDigest, 32) && strings.HasPrefix(c.CandidateFingerprint, "sha256:") && isHex(strings.TrimPrefix(c.CandidateFingerprint, "sha256:"), 32) && isHex(c.OwnerControlDigest, 32)
}

func ownerEndpointGroupsTargetValid(t OwnerEndpointGroupsTarget, action string) bool {
	if !validID(t.HubID) || !validID(t.OwnerID) || !validID(t.NodeID) || !validID(t.NetworkID) || !validID(t.GroupID) {
		return false
	}
	if action == OwnerEndpointGroupsCreateGroup {
		return ownerEndpointGroupsName(t.Name) && t.ContextPolicy == "group_scoped" && t.LocalUserScope == "" && t.EndpointID == "" && t.PrincipalID == "" && t.RegistrationDigest == ""
	}
	return (action == OwnerEndpointGroupsAddEndpoint || action == OwnerEndpointGroupsRemoveEndpoint) && t.Name == "" && t.ContextPolicy == "" &&
		e2ee.ValidLocalDomainUserScope(t.LocalUserScope) && validID(t.EndpointID) && validID(t.PrincipalID) && isHex(t.RegistrationDigest, 32)
}

// This verifies original candidate possession independently of Hub labels. It
// accepts zero pre-admission revisions only when they are the exact review CAS.
func validateEndpointGroupManifest(m LocalDomainKeyManifest, p e2ee.EndpointGroupPolicy, groupVersion, membership, join uint64) error {
	if m.Version != 1 || m.Operation != "group-endpoint-key-grant:v1" || m.HubID != p.HubID || m.OwnerID != p.OwnerID || m.OwnerKeyID != p.OwnerPublic.ID ||
		m.GroupID != p.GroupID || m.GroupRevision != int64(groupVersion) || m.NodeID != p.Node.NodeID || m.EndpointID != p.EndpointID || m.PrincipalID != p.PrincipalID ||
		m.BindingID != p.BindingID || m.BindingEpoch != p.BindingEpoch || m.MembershipRevision != int64(membership) || m.EndpointJoinRevision != int64(join) ||
		m.CandidateVersion != int64(p.CandidateVersion) || m.CandidateKeyID != p.EndpointKeyID || !reflect.DeepEqual(m.CandidatePublicIdentity, p.EndpointPublic) ||
		m.CandidateFingerprint != p.EndpointFingerprint || m.CandidateProofDigest != p.CandidateProofDigest || m.ExpiresAt != p.ExpiresAt || len(m.CandidateAttestation) > 16<<10 {
		return ErrInvalid
	}
	public, err := e2ee.VerifyEndpointKeyAttestation(m.CandidateAttestation, m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
	proofDigest := sha256.Sum256(m.CandidateAttestation)
	if err != nil || !reflect.DeepEqual(public, p.EndpointPublic) || hex.EncodeToString(proofDigest[:]) != p.CandidateProofDigest {
		return ErrInvalid
	}
	binding, err := LocalDomainGroupBindingDigest(m)
	digest, de := LocalDomainGroupManifestDigest(m)
	if err != nil || de != nil || binding != m.CandidateBindingDigest || digest != m.Digest {
		return ErrInvalid
	}
	return nil
}

func ownerEndpointGroupsReviewShape(r OwnerEndpointGroupsReview) error {
	if !isHex(r.ReviewID, 16) || !isHex(r.RequestID, 16) || !isHex(r.RequestPacketDigest, 32) || !isHex(r.ReviewDigest, 32) ||
		!ownerEndpointGroupsTargetValid(r.Target, r.Action) || !ownerEndpointGroupsCASValid(r.Expected, r.Action == OwnerEndpointGroupsCreateGroup) ||
		validateTimeWindow(r.ObservedAt, r.ExpiresAt, e2ee.EndpointGroupsRequestLifetime) != nil {
		return ErrInvalid
	}
	digest, err := OwnerEndpointGroupsReviewDigest(r)
	if err != nil || digest != r.ReviewDigest {
		return ErrInvalid
	}
	p := r.Projection
	switch r.Action {
	case OwnerEndpointGroupsCreateGroup:
		if p.OwnerManagementOnly == nil || !*p.OwnerManagementOnly || r.Policy != nil || r.KeyManifest != nil ||
			!reflect.DeepEqual(p, OwnerEndpointGroupsProjection{GroupID: r.Target.GroupID, Name: r.Target.Name, ContextPolicy: "group_scoped", OwnerManagementOnly: p.OwnerManagementOnly}) {
			return ErrInvalid
		}
	case OwnerEndpointGroupsRemoveEndpoint:
		if p.ManualDeny == nil || !*p.ManualDeny || r.Policy != nil || r.KeyManifest != nil ||
			!reflect.DeepEqual(p, OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", RelationState: "REMOVED", ManualDeny: p.ManualDeny, WithdrawScope: "EXACT_ENDPOINT_GROUP"}) {
			return ErrInvalid
		}
	case OwnerEndpointGroupsAddEndpoint:
		if p.Grants == nil || *p.Grants == nil || len(*p.Grants) != 0 || !reflect.DeepEqual(p.ProjectedRights, e2ee.EndpointGroupRights()) || p.PolicyCore == nil || r.Policy == nil || r.KeyManifest == nil ||
			p.ExpectedOwnerControl == nil || p.CompletionOwnerControl == nil || e2ee.ValidateEndpointGroupOwnerControl(*p.ExpectedOwnerControl) != nil || e2ee.ValidateEndpointGroupOwnerControl(*p.CompletionOwnerControl) != nil ||
			p.ExpectedOwnerControl.Revision != r.Expected.DecisionRevision ||
			!reflect.DeepEqual(*p.CompletionOwnerControl, e2ee.EndpointGroupOwnerControl{Mode: "OWNER", Revision: r.Expected.DecisionRevision + 1, DenyReason: "NONE", PolicyID: r.Policy.PolicyID, PolicyEpoch: r.Policy.Epoch}) ||
			!reflect.DeepEqual(p, OwnerEndpointGroupsProjection{Source: "OWNER_EXPLICIT", ContributionState: "PENDING_KEY", EffectiveRelationState: p.EffectiveRelationState, Grants: p.Grants, ProjectedRights: e2ee.EndpointGroupRights(), Duration: p.Duration, ExpectedOwnerControl: p.ExpectedOwnerControl, CompletionOwnerControl: p.CompletionOwnerControl, PolicyCore: p.PolicyCore}) {
			return ErrInvalid
		}
		if e2ee.ValidateEndpointGroupPolicy(*r.Policy, time.Time{}) != nil {
			return ErrInvalid
		}
		switch p.EffectiveRelationState {
		case "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED":
		default:
			return ErrInvalid
		}
		if p.ExpectedOwnerControl.DenyReason == "REMOVED" && p.EffectiveRelationState != "REMOVED" || p.ExpectedOwnerControl.DenyReason == "EXPIRED" && p.EffectiveRelationState != "EXPIRED" ||
			p.EffectiveRelationState == "ACTIVE" && (p.ExpectedOwnerControl.Mode != "DEFAULT" || p.ExpectedOwnerControl.DenyReason != "NONE") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// ValidateOwnerEndpointGroupsReview is called on the authenticated Hub response
// before showing approval or signing the exact persistent delegation.
func ValidateOwnerEndpointGroupsReview(q OwnerEndpointGroupsPrepareRequest, original []byte, r OwnerEndpointGroupsReview, hub HubIdentity, now time.Time) error {
	if ValidateOwnerEndpointGroupsRequest(q, hub, time.Time{}) != nil || ownerEndpointGroupsReviewShape(r) != nil || now.IsZero() ||
		r.Action != q.Body.Action || r.RequestID != q.Context.RequestID || r.RequestPacketDigest != OwnerEndpointGroupsPacketDigest(original) ||
		r.Target.HubID != q.Context.HubID || r.Target.OwnerID != q.Context.OwnerID || r.Target.NodeID != q.Body.NodeID || r.Target.NetworkID != q.Body.NetworkID {
		return ErrInvalid
	}
	packet, err := DecodeOwnerEndpointGroupsPacket(original)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if err != nil || packet.Packet.Route.Operation != OperationOwnerEndpointGroupsPrepare || packet.Packet.Route.Direction != clientwire.DirectionRequest || packet.Packet.Route.OperationID != q.Context.RequestID ||
		packet.Packet.Route.OwnerID != q.Context.OwnerID || packet.Packet.Route.DeviceID != q.Context.DeviceID || packet.Packet.Route.HubID != hub.HubID ||
		decodeCanonical(q.OwnerProof, e2ee.MaxEndpointGroupProofBytes, &proof) != nil || !reflect.DeepEqual(packet.SenderPublicIdentity, proof.Claims.Scope.DevicePublic) {
		return ErrInvalid
	}
	observed, _ := parseCanonicalUTC(r.ObservedAt)
	end, _ := parseCanonicalUTC(r.ExpiresAt)
	issued, _ := parseCanonicalUTC(q.Context.IssuedAt)
	proofEnd, _ := parseCanonicalUTC(proof.Claims.ExpiresAt)
	digest, err := OwnerEndpointGroupsReviewDigest(r)
	if err != nil || digest != r.ReviewDigest || observed.Before(issued) || observed.After(now.Add(30*time.Second)) || !now.Before(end) || end.After(proofEnd) || r.Expected.OwnerKeyVersion != proof.Claims.Scope.OwnerKeyVersion {
		return ErrInvalid
	}
	if r.Action == OwnerEndpointGroupsCreateGroup {
		if r.Target.Name != q.Body.Name {
			return ErrInvalid
		}
		return nil
	}
	if r.Target.GroupID != q.Body.GroupID || r.Target.EndpointID != q.Body.EndpointID || r.Target.RegistrationDigest != r.Expected.RegistrationDigest {
		return ErrInvalid
	}
	if r.Action == OwnerEndpointGroupsRemoveEndpoint {
		return nil
	}
	p, c := *r.Policy, r.Expected
	expiry, err := EndpointGroupDurationExpiry(q.Body.Duration, observed)
	if err != nil || r.Projection.Duration != q.Body.Duration || p.IssuedAt != r.ObservedAt || p.ExpiresAt != expiry || p.ReviewID != r.ReviewID || p.ReviewDigest != r.ReviewDigest ||
		ValidateOwnerEndpointGroupsPolicy(p, hub, now) != nil || !reflect.DeepEqual(p.OwnerPublic, proof.Claims.Scope.OwnerPublic) || p.OwnerKeyVersion != c.OwnerKeyVersion ||
		p.OwnerID != r.Target.OwnerID || p.Origin != q.Context.Origin || p.Node.NodeID != r.Target.NodeID || p.Node.OwnerBindingID != c.NodeOwnerBindingID ||
		p.Node.BindingVersion != c.NodeOwnerBindingVersion || p.Node.NodeKeyEpoch != c.NodeKeyEpoch || p.LocalUserScope != r.Target.LocalUserScope ||
		p.NetworkID != r.Target.NetworkID || p.GroupID != r.Target.GroupID || p.EndpointID != r.Target.EndpointID || p.PrincipalID != r.Target.PrincipalID ||
		p.RegistrationDigest != c.RegistrationDigest || p.RegistrationRevision != c.RegistrationRevision || p.BindingID != c.BindingID || p.BindingEpoch != c.BindingEpoch ||
		p.EndpointFingerprint != c.CandidateFingerprint || p.CandidateVersion != c.CandidateVersion || p.CandidateProofDigest != c.CandidateProofDigest ||
		p.ExpectedOwnerControlDigest != c.OwnerControlDigest || p.ExpectedDecisionRevision != c.DecisionRevision || p.Epoch != c.PolicyEpoch+1 ||
		!reflect.DeepEqual(p.Core(), *r.Projection.PolicyCore) || validateEndpointGroupManifest(*r.KeyManifest, p, c.GroupVersion, c.MembershipRevision, c.EndpointJoinRevision) != nil {
		return ErrInvalid
	}
	return nil
}

func NewOwnerEndpointGroupsApply(s AppNodeSession, scope e2ee.OwnerAppNodeScope, prepare OwnerEndpointGroupsPrepareRequest, original []byte, review OwnerEndpointGroupsReview, owner *e2ee.Identity, now time.Time) (OwnerEndpointGroupsApplyRequest, error) {
	if ValidateOwnerEndpointGroupsReview(prepare, original, review, s.Hub, now) != nil || !appNodeContextScope(prepare.Context, scope) {
		return OwnerEndpointGroupsApplyRequest{}, ErrInvalid
	}
	body := OwnerEndpointGroupsApplyBody{ReviewID: review.ReviewID, ReviewDigest: review.ReviewDigest, PreparePacketDigest: OwnerEndpointGroupsPacketDigest(original)}
	if review.Action == OwnerEndpointGroupsAddEndpoint {
		var err error
		body.PolicyProof, err = e2ee.SignOwnerEndpointGroupPolicy(owner, *review.Policy)
		if err != nil {
			return OwnerEndpointGroupsApplyRequest{}, err
		}
	}
	c, token, proof, err := newOwnerEndpointGroupsRequest(s, scope, OperationOwnerEndpointGroupsApply, body, owner, now)
	return OwnerEndpointGroupsApplyRequest{OwnerEndpointGroupsFormat, c, token, proof, body}, err
}
