package hubaccountwire

import (
	"math"
	"net"
	"net/url"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// These structural checks neither verify an Owner signature nor authorize an
// HTTP operation. In particular, a matching candidate digest must also be
// recomputed from the original persisted Store candidate and credential digest.
func ValidateAppNodeScopedScope(s e2ee.OwnerAppNodeScopedScope, hub HubIdentity) error {
	fp, err := HubFingerprint(hub)
	if err != nil || s.Version != AppNodeScopedScopeVersion || !appNodeScopedNodeID(s.AuthorityNodeID) || s.HubID != hub.HubID || s.HubFingerprint != fp ||
		validateOrigin(s.Origin) != nil || !validID(s.AccountID) || !validID(s.AccountSessionID) || !validID(s.OwnerID) ||
		validateCanonicalTime(s.AccountSessionExpiresAt) != nil ||
		!validDeviceID(s.DeviceID) || e2ee.ValidatePublicIdentity(s.OwnerPublic) != nil ||
		e2ee.ValidatePublicIdentity(s.DevicePublic) != nil || s.OwnerPublic.ID == s.DevicePublic.ID {
		return ErrInvalid
	}
	for _, n := range []uint64{s.AccountEpoch, s.DeviceEpoch, s.ClientSessionEpoch, s.OwnerKeyVersion} {
		if n == 0 || n > math.MaxInt64 {
			return ErrInvalid
		}
	}
	if s.HeadVersion > math.MaxInt64 {
		return ErrInvalid
	}
	u, err := url.Parse(s.Origin)
	if err != nil {
		return ErrInvalid
	}
	switch s.TransportPolicy {
	case AppNodeScopedTransportHTTPS:
		if u.Scheme != "https" {
			return ErrInvalid
		}
	case AppNodeScopedTransportLoopbackTest:
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// AppNodeCodeDigest intentionally matches the existing Node code selector.
// It is not an authority, a Node identity fingerprint or a credential bearer.
func ValidateAppNodeScopedPreviewClaims(c e2ee.OwnerAppNodeScopedPreviewClaims, hub HubIdentity, now time.Time) error {
	if ValidateAppNodeScopedScope(c.Scope, hub) != nil || !isHex(c.GrantID, RequestIDBytes) ||
		!isHex(c.RequestID, RequestIDBytes) || !isHex(c.Nonce, NonceBytes) {
		return ErrInvalid
	}
	switch c.Purpose {
	case e2ee.OwnerAppNodeScopedPreviewPurpose:
		if !isHex(c.CodeDigest, 32) || c.PreviousGrantID != "" {
			return ErrInvalid
		}
	case e2ee.OwnerAppNodeScopedStatusPreviewPurpose:
		if c.CodeDigest != "" || !isHex(c.PreviousGrantID, RequestIDBytes) || c.PreviousGrantID == c.GrantID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return validateTimeWindowNow(c.IssuedAt, c.ExpiresAt, MaxAppNodeScopedIntentLifetime, now)
}

func ValidateAppNodeScopedGrantClaims(c e2ee.OwnerAppNodeScopedGrantClaims, hub HubIdentity, now time.Time) error {
	if ValidateAppNodeScopedScope(c.Scope, hub) != nil || c.Scope.HeadVersion == 0 ||
		c.ExpectedHeadVersion >= math.MaxInt64 || c.Scope.HeadVersion != c.ExpectedHeadVersion+1 ||
		!isHex(c.GrantID, RequestIDBytes) || !isHex(c.PrepareRequestID, RequestIDBytes) ||
		!isHex(c.PreparePacketDigest, 32) || !isHex(c.PreviewProofDigest, 32) || !isHex(c.ServerNonce, NonceBytes) ||
		!c.ReadNodeStatus ||
		validateTimeWindowNow(c.PreparedAt, c.ProofExpiresAt, MaxAppNodeScopedProofLifetime, now) != nil {
		return ErrInvalid
	}
	prepared, _ := parseCanonicalUTC(c.PreparedAt)
	proofEnd, _ := parseCanonicalUTC(c.ProofExpiresAt)
	leaseEnd, err := parseCanonicalUTC(c.LeaseExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if err != nil || !leaseEnd.Equal(prepared.Add(AppNodeScopedLeaseLifetime)) || proofEnd.After(sessionEnd) {
		return ErrInvalid
	}
	switch c.Profile {
	case AppNodeScopedProfileInitial:
		if c.Purpose != e2ee.OwnerAppNodeScopedGrantPurpose || c.Candidate == nil || c.Binding != nil || c.PreviousGrantID != "" || c.ConfirmationProvenanceID != "" ||
			ValidateAppNodeCandidate(*c.Candidate, c.Scope.HubID) != nil || c.Candidate.NodeID != c.Scope.AuthorityNodeID ||
			!reflect.DeepEqual(c.AllowedOperations, AppNodeScopedAllowedOperations()) || c.ConfirmationLimit != 1 {
			return ErrInvalid
		}
		candidateEnd, _ := parseCanonicalUTC(c.Candidate.ExpiresAt)
		if proofEnd.After(candidateEnd) || !candidateEnd.After(prepared) {
			return ErrInvalid
		}
	case AppNodeScopedProfileStatus:
		if c.Purpose != e2ee.OwnerAppNodeScopedStatusGrantPurpose || c.Candidate != nil || c.Binding == nil ||
			!isHex(c.PreviousGrantID, RequestIDBytes) || c.PreviousGrantID == c.GrantID ||
			!isHex(c.ConfirmationProvenanceID, RequestIDBytes) ||
			!reflect.DeepEqual(c.AllowedOperations, AppNodeScopedStatusAllowedOperations()) || c.ConfirmationLimit != 0 ||
			ValidateAppNodeScopedExistingBinding(*c.Binding, c.Scope) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateAppNodeScopedExistingBinding(b e2ee.OwnerAppNodeBinding, s e2ee.OwnerAppNodeScopedScope) error {
	if b.NodeID != s.AuthorityNodeID || b.State != "ACTIVE" || b.HubID != s.HubID || b.OwnerID != s.OwnerID || b.ClientDeviceID != s.DeviceID ||
		b.OwnerKeyID != s.OwnerPublic.ID || !validID(b.OwnerBindingID) || !validID(b.NodeID) ||
		b.NodeID == "control-local" || b.NodeID == "worker-local" || !validUsername(b.NodeName) || len(b.NodeName) > 128 ||
		!validID(b.ApprovedRequestID) || !isHex(b.ApprovedCandidateDigest, 32) || validateCanonicalTime(b.ApprovedAt) != nil ||
		e2ee.ValidatePublicIdentity(b.NodePublic) != nil || e2ee.ValidatePublicIdentity(b.HubNodeControlPublic) != nil ||
		b.NodeKeyFingerprint != nodewire.IdentityFingerprint(b.NodePublic) || b.HubNodeControlFingerprint != nodewire.IdentityFingerprint(b.HubNodeControlPublic) {
		return ErrInvalid
	}
	for _, n := range []uint64{b.CredentialVersion, b.BindingVersion, b.NodeKeyVersion, b.NodeKeyEpoch, b.HubNodeControlKeyVersion, b.ApprovedRequestVersion} {
		if n == 0 || n > math.MaxInt64 {
			return ErrInvalid
		}
	}
	return nil
}

// ValidateAppNodeScopedPreparedResponse prevents a substituted code/candidate/scope
// or an independently valid challenge from replacing this exact prepare.
// The caller must authenticate the outer Hub response before using this check.
func ValidateAppNodeScopedPreparedResponse(ch AppNodeScopedChallenge, intent e2ee.OwnerAppNodeScopedPreviewClaims, previewProof, original []byte, hub HubIdentity, now time.Time) error {
	var proof e2ee.OwnerAppNodeScopedPreview
	if decodeCanonical(previewProof, MaxAppNodeScopedProofBytes, &proof) != nil || !reflect.DeepEqual(proof.Claims, intent) ||
		ch.Claims.PreviewProofDigest != AppNodeScopedProofDigest(previewProof) {
		return ErrInvalid
	}
	if ch.Format != AppNodeScopedChallengeFormat || ch.RequestID != intent.RequestID ||
		ch.RequestPacketDigest != AppNodeScopedPacketDigest(original) || ValidateAppNodeScopedGrantClaims(ch.Claims, hub, now) != nil ||
		ch.Claims.GrantID != intent.GrantID || ch.Claims.PrepareRequestID != intent.RequestID ||
		ch.Claims.ExpectedHeadVersion != intent.Scope.HeadVersion || ch.Claims.PreparePacketDigest != ch.RequestPacketDigest ||
		validateCanonicalTime(ch.ObservedAt) != nil || intent.Scope.HeadVersion >= math.MaxInt64 {
		return ErrInvalid
	}
	if intent.Purpose == e2ee.OwnerAppNodeScopedPreviewPurpose {
		if ch.Claims.Profile != AppNodeScopedProfileInitial || ch.Claims.Candidate == nil || ch.Claims.Candidate.CodeDigest != intent.CodeDigest {
			return ErrInvalid
		}
	} else if intent.Purpose == e2ee.OwnerAppNodeScopedStatusPreviewPurpose {
		if ch.Claims.Profile != AppNodeScopedProfileStatus || ch.Claims.PreviousGrantID != intent.PreviousGrantID {
			return ErrInvalid
		}
	} else {
		return ErrInvalid
	}
	expected := intent.Scope
	expected.HeadVersion++
	if !reflect.DeepEqual(ch.Claims.Scope, expected) {
		return ErrInvalid
	}
	return nil
}
