package hubaccountwire

import (
	"math"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func ValidateNodePairTrustRetainedBinding(r NodePairTrustRetainedBinding, node e2ee.PublicIdentity, hub HubIdentity) error {
	if e2ee.ValidatePublicIdentity(node) != nil || node.ID == hub.Public.ID || !validID(r.NodeID) || !validID(r.OwnerBindingID) || !validID(r.ApprovedRequestID) || r.NodeKeyID != node.ID || r.NodeKeyFingerprint != nodewire.IdentityFingerprint(node) || e2ee.ValidatePublicIdentity(r.HubNodeControlPublic) != nil || r.HubNodeControlPublic.ID == node.ID || r.HubNodeControlPublic.ID == hub.Public.ID || r.HubNodeControlFingerprint != nodewire.IdentityFingerprint(r.HubNodeControlPublic) || !isHex(r.ApprovedCandidateDigest, 32) || !nodePairCredentialDigest(r.CredentialDigest) {
		return ErrInvalid
	}
	for _, v := range []uint64{r.BindingVersion, r.NodeKeyVersion, r.NodeKeyEpoch, r.HubNodeControlKeyVersion, r.ApprovedRequestVersion} {
		if v == 0 || v > math.MaxInt64 {
			return ErrInvalid
		}
	}
	return nil
}

// This compares every public coordinate retained locally. The Hub must also
// query the original ACTIVE credential/binding by the exact CredentialDigest;
// the public response intentionally carries no bearer or credential digest.
func MatchNodePairTrustRetainedBinding(r NodePairTrustRetainedBinding, b e2ee.OwnerAppNodeBinding, node e2ee.PublicIdentity) error {
	if b.State != "ACTIVE" || b.NodeID != r.NodeID || b.OwnerBindingID != r.OwnerBindingID || b.BindingVersion != r.BindingVersion || !reflect.DeepEqual(b.NodePublic, node) || node.ID != r.NodeKeyID || b.NodeKeyVersion != r.NodeKeyVersion || b.NodeKeyEpoch != r.NodeKeyEpoch || b.NodeKeyFingerprint != r.NodeKeyFingerprint || !reflect.DeepEqual(b.HubNodeControlPublic, r.HubNodeControlPublic) || b.HubNodeControlKeyVersion != r.HubNodeControlKeyVersion || b.HubNodeControlFingerprint != r.HubNodeControlFingerprint || b.ApprovedRequestID != r.ApprovedRequestID || b.ApprovedRequestVersion != r.ApprovedRequestVersion || b.ApprovedCandidateDigest != r.ApprovedCandidateDigest || !nodePairCredentialDigest(r.CredentialDigest) {
		return ErrInvalid
	}
	return nil
}
