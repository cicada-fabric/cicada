package e2ee

import (
	"encoding/json"
	"math"
	"net/url"
	"reflect"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const MaxOwnerAppNodeProofBytes = 32 * 1024

// Proof helpers verify canonical claims, the domain, exact existing Owner key
// and signature. They never establish an active Root, grant, session or Node.
// hubaccountwire validates the full pinned route/target; Store checks current
// enrollment, epochs, head, session and replay state atomically with effects.
func SignOwnerAppNodePreview(owner *Identity, c OwnerAppNodePreviewClaims) ([]byte, error) {
	if err := validateAppNodePreviewProofClaims(c, time.Time{}); err != nil {
		return nil, err
	}
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, c.Scope.OwnerPublic.ID, OwnerAppNodePreviewDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalOwnerAppNodeProof(OwnerAppNodePreview{Claims: c, Signature: sig})
}

func VerifyOwnerAppNodePreview(trusted PublicIdentity, raw []byte, now time.Time) (OwnerAppNodePreviewClaims, error) {
	var p OwnerAppNodePreview
	if tlsProofRead(raw, &p) != nil || !reflect.DeepEqual(trusted, p.Claims.Scope.OwnerPublic) ||
		validateAppNodePreviewProofClaims(p.Claims, now) != nil || verifyAppNodeSignature(trusted, OwnerAppNodePreviewDomain, p.Claims, p.Signature) != nil {
		return OwnerAppNodePreviewClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func SignOwnerAppNodeGrant(owner *Identity, c OwnerAppNodeGrantClaims) ([]byte, error) {
	if err := validateAppNodeGrantProofClaims(c, time.Time{}); err != nil {
		return nil, err
	}
	if owner == nil || !reflect.DeepEqual(owner.Public(), c.Scope.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, c.Scope.OwnerPublic.ID, OwnerAppNodeGrantDomain, c)
	if err != nil {
		return nil, err
	}
	return marshalOwnerAppNodeProof(OwnerAppNodeGrant{Claims: c, Signature: sig})
}

// A zero now verifies retained historical proof syntax/signature only. A new
// grant completion must pass actual current time and the independent Store CAS.
func VerifyOwnerAppNodeGrant(trusted PublicIdentity, raw []byte, now time.Time) (OwnerAppNodeGrantClaims, error) {
	var p OwnerAppNodeGrant
	if tlsProofRead(raw, &p) != nil || !reflect.DeepEqual(trusted, p.Claims.Scope.OwnerPublic) ||
		validateAppNodeGrantProofClaims(p.Claims, now) != nil || verifyAppNodeSignature(trusted, OwnerAppNodeGrantDomain, p.Claims, p.Signature) != nil {
		return OwnerAppNodeGrantClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func marshalOwnerAppNodeProof(proof any) ([]byte, error) {
	raw, err := json.Marshal(proof)
	if err != nil || len(raw) > MaxOwnerAppNodeProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

func verifyAppNodeSignature(trusted PublicIdentity, domain string, claims any, sig []byte) error {
	_, public, err := validatePublic(trusted)
	if err != nil || len(sig) != mldsa65.SignatureSize {
		return ErrInvalidEnvelope
	}
	raw, err := json.Marshal(claims)
	if err != nil || !mldsa65.Verify(public, append([]byte(domain), raw...), nil, sig) {
		return ErrInvalidEnvelope
	}
	return nil
}

func appNodeProofScope(s OwnerAppNodeScope) error {
	if s.Version != 1 || ValidatePublicIdentity(s.OwnerPublic) != nil || ValidatePublicIdentity(s.DevicePublic) != nil || s.OwnerPublic.ID == s.DevicePublic.ID ||
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

func appNodeProofWindow(issued, expires string, max time.Duration, now time.Time) error {
	i, err := parseCanonicalUTC(issued)
	if err != nil {
		return ErrInvalidEnvelope
	}
	e, err := parseCanonicalUTC(expires)
	if err != nil || !e.After(i) || e.Sub(i) > max || (!now.IsZero() && (i.After(now.Add(30*time.Second)) || !now.Before(e))) {
		return ErrInvalidEnvelope
	}
	return nil
}

func appNodeHex(value string, size int) bool {
	return len(value) == size*2 && canonicalSHA256Hex(value)
}

func appNodeProofID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validateAppNodePreviewProofClaims(c OwnerAppNodePreviewClaims, now time.Time) error {
	if appNodeProofScope(c.Scope) != nil || !appNodeProofID(c.GrantID) || !appNodeProofID(c.RequestID) || !appNodeHex(c.Nonce, 32) || appNodeProofWindow(c.IssuedAt, c.ExpiresAt, time.Minute, now) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	switch c.Purpose {
	case OwnerAppNodePreviewPurpose:
		if !canonicalSHA256Hex(c.CodeDigest) || c.PreviousGrantID != "" {
			return ErrInvalidEnvelope
		}
	case OwnerAppNodeStatusPreviewPurpose:
		if c.CodeDigest != "" || !appNodeProofID(c.PreviousGrantID) || c.PreviousGrantID == c.GrantID {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}

func validateAppNodeGrantProofClaims(c OwnerAppNodeGrantClaims, now time.Time) error {
	if appNodeProofScope(c.Scope) != nil || c.ExpectedHeadVersion >= math.MaxInt64 || c.Scope.HeadVersion != c.ExpectedHeadVersion+1 ||
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
		if c.Purpose != OwnerAppNodeGrantPurpose || c.Candidate == nil || c.Binding != nil || c.PreviousGrantID != "" || c.ConfirmationProvenanceID != "" || c.ConfirmationLimit != 1 || !reflect.DeepEqual(c.AllowedOperations, []string{"nodes.confirm"}) {
			return ErrInvalidEnvelope
		}
		n := c.Candidate
		e, err := parseCanonicalUTC(n.ExpiresAt)
		if err != nil || proof.After(e) || n.Mode != "INITIAL" || n.State != "PENDING" || n.HubID != c.Scope.HubID || ValidatePublicIdentity(n.NodePublic) != nil || ValidatePublicIdentity(n.HubNodeControlPublic) != nil {
			return ErrInvalidEnvelope
		}
	case "READ_EXISTING":
		if c.Purpose != OwnerAppNodeStatusGrantPurpose || c.Candidate != nil || c.Binding == nil || !appNodeProofID(c.PreviousGrantID) || c.PreviousGrantID == c.GrantID || !appNodeProofID(c.ConfirmationProvenanceID) || c.ConfirmationLimit != 0 || c.AllowedOperations == nil || len(c.AllowedOperations) != 0 {
			return ErrInvalidEnvelope
		}
		b := c.Binding
		if b.State != "ACTIVE" || b.OwnerID != c.Scope.OwnerID || b.HubID != c.Scope.HubID || b.ClientDeviceID != c.Scope.DeviceID || b.OwnerKeyID != c.Scope.OwnerPublic.ID || ValidatePublicIdentity(b.NodePublic) != nil || ValidatePublicIdentity(b.HubNodeControlPublic) != nil {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}
