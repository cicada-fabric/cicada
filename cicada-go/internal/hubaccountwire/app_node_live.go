package hubaccountwire

import (
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// ValidateAppNodeLiveResult compares the current observation with the exact
// locally retained signed grant. The generic envelope reader cannot recover
// private request-body scope from outbound ciphertext; a caller must not
// substitute another account/epoch/instance merely because Hub signed it.
func ValidateAppNodeLiveResult(v AppNodeResult, grant e2ee.OwnerAppNodeGrantClaims, hub HubIdentity, now time.Time) error {
	if now.IsZero() || validateOpenedAppNodeResult(v, hub) != nil || ValidateAppNodeGrantClaims(grant, hub, time.Time{}) != nil || v.State != AppNodeCompleted || v.Authority.State != AppNodeActive || v.Authority.LoginRequired ||
		!reflect.DeepEqual(v.Authority.Scope, grant.Scope) || v.Authority.GrantID != grant.GrantID || v.Authority.Profile != grant.Profile || v.Authority.LeaseExpiresAt != grant.LeaseExpiresAt || v.Authority.RemainingConfirmations > grant.ConfirmationLimit {
		return ErrInvalid
	}
	if grant.Profile == AppNodeProfileStatus && v.Authority.ConfirmationProvenanceID != grant.ConfirmationProvenanceID {
		return ErrInvalid
	}
	for _, end := range []string{grant.LeaseExpiresAt, grant.Scope.AccountSessionExpiresAt} {
		t, err := parseCanonicalUTC(end)
		if err != nil || !now.Before(t) {
			return ErrInvalid
		}
	}
	observed, _ := parseCanonicalUTC(v.ObservedAt)
	if observed.After(now.Add(30 * time.Second)) {
		return ErrInvalid
	}
	if v.Node != nil {
		var nodeID, keyID, fingerprint string
		var epoch uint64
		if grant.Candidate != nil {
			nodeID, keyID, fingerprint, epoch = grant.Candidate.NodeID, grant.Candidate.NodePublic.ID, grant.Candidate.NodeKeyFingerprint, grant.Candidate.NodeKeyEpoch
		} else if grant.Binding != nil {
			nodeID, keyID, fingerprint, epoch = grant.Binding.NodeID, grant.Binding.NodePublic.ID, grant.Binding.NodeKeyFingerprint, grant.Binding.NodeKeyEpoch
		}
		if v.Node.NodeID != nodeID || v.Node.NodeKeyID != keyID || v.Node.NodeKeyFingerprint != fingerprint || v.Node.NodeKeyEpoch != epoch {
			return ErrInvalid
		}
		if grant.Binding != nil && (v.Node.BindingID != grant.Binding.OwnerBindingID || v.Node.BindingVersion != grant.Binding.BindingVersion || v.Node.CredentialVersion != grant.Binding.CredentialVersion) {
			return ErrInvalid
		}
	}
	return nil
}
