package e2ee

import (
	"math"
	"net/url"
	"reflect"
	"time"
)

const MaxOwnerAppNodeScopedProofBytes = 32 * 1024

// Proof helpers verify canonical claims, the domain, exact existing Owner key
// and signature. They never establish an active Root, grant, session or Node.
// hubaccountwire validates the full pinned route/target; Store checks current
// enrollment, epochs, head, session and replay state atomically with effects.
func SignOwnerAppNodeScopedPreview(owner *Identity, c OwnerAppNodeScopedPreviewClaims) ([]byte, error) {
	if err := validateAppNodeScopedPreviewProofClaims(c, time.Time{}); err != nil {
		return nil, err
	}
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, c.Scope.OwnerPublic.ID, OwnerAppNodeScopedPreviewDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalOwnerAppNodeProof(OwnerAppNodeScopedPreview{Claims: c, Signature: sig})
}

func VerifyOwnerAppNodeScopedPreview(trusted PublicIdentity, raw []byte, now time.Time) (OwnerAppNodeScopedPreviewClaims, error) {
	var p OwnerAppNodeScopedPreview
	if tlsProofRead(raw, &p) != nil || !reflect.DeepEqual(trusted, p.Claims.Scope.OwnerPublic) ||
		validateAppNodeScopedPreviewProofClaims(p.Claims, now) != nil || verifyAppNodeSignature(trusted, OwnerAppNodeScopedPreviewDomain, p.Claims, p.Signature) != nil {
		return OwnerAppNodeScopedPreviewClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func SignOwnerAppNodeScopedGrant(owner *Identity, c OwnerAppNodeScopedGrantClaims) ([]byte, error) {
	if err := validateAppNodeScopedGrantProofClaims(c, time.Time{}); err != nil {
		return nil, err
	}
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, c.Scope.OwnerPublic.ID, OwnerAppNodeScopedGrantDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalOwnerAppNodeProof(OwnerAppNodeScopedGrant{Claims: c, Signature: sig})
}

// A zero now verifies retained historical proof syntax/signature only. A new
// grant completion must pass actual current time and the independent Store CAS.
func VerifyOwnerAppNodeScopedGrant(trusted PublicIdentity, raw []byte, now time.Time) (OwnerAppNodeScopedGrantClaims, error) {
	var p OwnerAppNodeScopedGrant
	if tlsProofRead(raw, &p) != nil || !reflect.DeepEqual(trusted, p.Claims.Scope.OwnerPublic) ||
		validateAppNodeScopedGrantProofClaims(p.Claims, now) != nil || verifyAppNodeSignature(trusted, OwnerAppNodeScopedGrantDomain, p.Claims, p.Signature) != nil {
		return OwnerAppNodeScopedGrantClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func appNodeScopedProofScope(s OwnerAppNodeScopedScope) error {
	if s.Version != 2 || !tlsGrantToken(s.AuthorityNodeID) || s.AuthorityNodeID == "control-local" || s.AuthorityNodeID == "worker-local" || ValidatePublicIdentity(s.OwnerPublic) != nil || ValidatePublicIdentity(s.DevicePublic) != nil || s.OwnerPublic.ID == s.DevicePublic.ID ||
		!canonicalSHA256Hex(s.HubFingerprint) || !tlsGrantToken(s.HubID) || !tlsGrantToken(s.AccountID) || !tlsGrantToken(s.AccountSessionID) ||
		!tlsGrantToken(s.OwnerID) || !tlsGrantToken(s.DeviceID) || s.HeadVersion > math.MaxInt64 {
		return ErrInvalidEnvelope
	}
	u, err := url.Parse(s.Origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != s.Origin {
		return ErrInvalidEnvelope
	}
	for _, n := range []uint64{s.OwnerKeyVersion, s.AccountEpoch, s.DeviceEpoch, s.ClientSessionEpoch} {
		if n == 0 || n > math.MaxInt64 {
			return ErrInvalidEnvelope
		}
	}
	if _, err := parseCanonicalUTC(s.AccountSessionExpiresAt); err != nil {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateAppNodeScopedPreviewProofClaims(c OwnerAppNodeScopedPreviewClaims, now time.Time) error {
	if appNodeScopedProofScope(c.Scope) != nil || !appNodeProofID(c.GrantID) || !appNodeProofID(c.RequestID) || !appNodeHex(c.Nonce, 32) || appNodeProofWindow(c.IssuedAt, c.ExpiresAt, time.Minute, now) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	switch c.Purpose {
	case OwnerAppNodeScopedPreviewPurpose:
		if !canonicalSHA256Hex(c.CodeDigest) || c.PreviousGrantID != "" {
			return ErrInvalidEnvelope
		}
	case OwnerAppNodeScopedStatusPreviewPurpose:
		if c.CodeDigest != "" || !appNodeProofID(c.PreviousGrantID) || c.PreviousGrantID == c.GrantID {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}

func validateAppNodeScopedGrantProofClaims(c OwnerAppNodeScopedGrantClaims, now time.Time) error {
	if appNodeScopedProofScope(c.Scope) != nil || c.ExpectedHeadVersion >= math.MaxInt64 || c.Scope.HeadVersion != c.ExpectedHeadVersion+1 ||
		!appNodeProofID(c.GrantID) || !appNodeProofID(c.PrepareRequestID) || !canonicalSHA256Hex(c.PreparePacketDigest) || !canonicalSHA256Hex(c.PreviewProofDigest) || !appNodeHex(c.ServerNonce, 32) ||
		!c.ReadNodeStatus || appNodeProofWindow(c.PreparedAt, c.ProofExpiresAt, 5*time.Minute, now) != nil {
		return ErrInvalidEnvelope
	}
	i, _ := parseCanonicalUTC(c.PreparedAt)
	lease, err := parseCanonicalUTC(c.LeaseExpiresAt)
	proof, _ := parseCanonicalUTC(c.ProofExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if err != nil || !lease.Equal(i.Add(15*time.Minute)) || proof.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	switch c.Profile {
	case "INITIAL_CONFIRM":
		if c.Purpose != OwnerAppNodeScopedGrantPurpose || c.Candidate == nil || c.Binding != nil || c.PreviousGrantID != "" || c.ConfirmationProvenanceID != "" || c.ConfirmationLimit != 1 || !reflect.DeepEqual(c.AllowedOperations, []string{"nodes.confirm"}) {
			return ErrInvalidEnvelope
		}
		n := c.Candidate
		e, err := parseCanonicalUTC(n.ExpiresAt)
		if err != nil || proof.After(e) || n.NodeID != c.Scope.AuthorityNodeID || n.Mode != "INITIAL" || n.State != "PENDING" || n.HubID != c.Scope.HubID || ValidatePublicIdentity(n.NodePublic) != nil || ValidatePublicIdentity(n.HubNodeControlPublic) != nil {
			return ErrInvalidEnvelope
		}
	case "READ_EXISTING":
		if c.Purpose != OwnerAppNodeScopedStatusGrantPurpose || c.Candidate != nil || c.Binding == nil || !appNodeProofID(c.PreviousGrantID) || c.PreviousGrantID == c.GrantID || !appNodeProofID(c.ConfirmationProvenanceID) || c.ConfirmationLimit != 0 || c.AllowedOperations == nil || len(c.AllowedOperations) != 0 {
			return ErrInvalidEnvelope
		}
		b := c.Binding
		if b.NodeID != c.Scope.AuthorityNodeID || b.State != "ACTIVE" || b.OwnerID != c.Scope.OwnerID || b.HubID != c.Scope.HubID || b.ClientDeviceID != c.Scope.DeviceID || b.OwnerKeyID != c.Scope.OwnerPublic.ID || ValidatePublicIdentity(b.NodePublic) != nil || ValidatePublicIdentity(b.HubNodeControlPublic) != nil {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}
