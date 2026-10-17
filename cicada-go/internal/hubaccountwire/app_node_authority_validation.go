package hubaccountwire

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// These structural checks neither verify an Owner signature nor authorize an
// HTTP operation. In particular, a matching candidate digest must also be
// recomputed from the original persisted Store candidate and credential digest.
func ValidateAppNodeScope(s e2ee.OwnerAppNodeScope, hub HubIdentity) error {
	fp, err := HubFingerprint(hub)
	if err != nil || s.Version != 1 || s.HubID != hub.HubID || s.HubFingerprint != fp ||
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
	case AppNodeTransportHTTPS:
		if u.Scheme != "https" {
			return ErrInvalid
		}
	case AppNodeTransportLoopbackTest:
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func NormalizeAppNodeCode(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.NewReplacer("-", "", " ", "").Replace(code)
	if len(code) != 12 {
		return "", ErrInvalid
	}
	for _, c := range code {
		if !strings.ContainsRune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ", c) {
			return "", ErrInvalid
		}
	}
	return code, nil
}

// AppNodeCodeDigest intentionally matches the existing Node code selector.
// It is not an authority, a Node identity fingerprint or a credential bearer.
func AppNodeCodeDigest(hubID, code string) (string, error) {
	code, err := NormalizeAppNodeCode(code)
	if err != nil || !validID(hubID) {
		return "", ErrInvalid
	}
	h := sha256.Sum256([]byte("cicada-node-device-code-v1\x00" + hubID + "\x00" + code))
	return hex.EncodeToString(h[:]), nil
}

func ValidateAppNodePreviewClaims(c e2ee.OwnerAppNodePreviewClaims, hub HubIdentity, now time.Time) error {
	if ValidateAppNodeScope(c.Scope, hub) != nil || !isHex(c.GrantID, RequestIDBytes) ||
		!isHex(c.RequestID, RequestIDBytes) || !isHex(c.Nonce, NonceBytes) {
		return ErrInvalid
	}
	switch c.Purpose {
	case e2ee.OwnerAppNodePreviewPurpose:
		if !isHex(c.CodeDigest, 32) || c.PreviousGrantID != "" {
			return ErrInvalid
		}
	case e2ee.OwnerAppNodeStatusPreviewPurpose:
		if c.CodeDigest != "" || !isHex(c.PreviousGrantID, RequestIDBytes) || c.PreviousGrantID == c.GrantID {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return validateTimeWindowNow(c.IssuedAt, c.ExpiresAt, MaxAppNodeIntentLifetime, now)
}

func ValidateAppNodeCandidate(c e2ee.OwnerAppNodeCandidate, hubID string) error {
	if c.Mode != "INITIAL" || c.State != "PENDING" || c.HubID != hubID || !validID(c.RequestID) ||
		!validID(c.NodeID) || c.NodeID == "control-local" || c.NodeID == "worker-local" ||
		!validUsername(c.NodeName) || len(c.NodeName) > 128 || c.Version == 0 || c.Version > math.MaxInt64 ||
		c.NodeKeyEpoch == 0 || c.NodeKeyEpoch > math.MaxInt64 || c.HubNodeControlKeyVersion == 0 || c.HubNodeControlKeyVersion > math.MaxInt64 ||
		e2ee.ValidatePublicIdentity(c.NodePublic) != nil || e2ee.ValidatePublicIdentity(c.HubNodeControlPublic) != nil ||
		c.NodePublic.ID == c.HubNodeControlPublic.ID || c.NodeKeyFingerprint != nodewire.IdentityFingerprint(c.NodePublic) ||
		c.HubNodeControlFingerprint != nodewire.IdentityFingerprint(c.HubNodeControlPublic) ||
		!isHex(c.CandidateDigest, 32) || !isHex(c.CodeDigest, 32) || validateCanonicalTime(c.ExpiresAt) != nil {
		return ErrInvalid
	}
	return nil
}

func ValidateAppNodeGrantClaims(c e2ee.OwnerAppNodeGrantClaims, hub HubIdentity, now time.Time) error {
	if ValidateAppNodeScope(c.Scope, hub) != nil || c.Scope.HeadVersion == 0 ||
		c.ExpectedHeadVersion >= math.MaxInt64 || c.Scope.HeadVersion != c.ExpectedHeadVersion+1 ||
		!isHex(c.GrantID, RequestIDBytes) || !isHex(c.PrepareRequestID, RequestIDBytes) ||
		!isHex(c.PreparePacketDigest, 32) || !isHex(c.PreviewProofDigest, 32) || !isHex(c.ServerNonce, NonceBytes) ||
		!c.ReadNodeStatus ||
		validateTimeWindowNow(c.PreparedAt, c.ProofExpiresAt, MaxAppNodeProofLifetime, now) != nil {
		return ErrInvalid
	}
	prepared, _ := parseCanonicalUTC(c.PreparedAt)
	proofEnd, _ := parseCanonicalUTC(c.ProofExpiresAt)
	leaseEnd, err := parseCanonicalUTC(c.LeaseExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if err != nil || !leaseEnd.Equal(prepared.Add(AppNodeLeaseLifetime)) || proofEnd.After(sessionEnd) {
		return ErrInvalid
	}
	switch c.Profile {
	case AppNodeProfileInitial:
		if c.Purpose != e2ee.OwnerAppNodeGrantPurpose || c.Candidate == nil || c.Binding != nil || c.PreviousGrantID != "" || c.ConfirmationProvenanceID != "" ||
			ValidateAppNodeCandidate(*c.Candidate, c.Scope.HubID) != nil ||
			!reflect.DeepEqual(c.AllowedOperations, AppNodeAllowedOperations()) || c.ConfirmationLimit != 1 {
			return ErrInvalid
		}
		candidateEnd, _ := parseCanonicalUTC(c.Candidate.ExpiresAt)
		if proofEnd.After(candidateEnd) || !candidateEnd.After(prepared) {
			return ErrInvalid
		}
	case AppNodeProfileStatus:
		if c.Purpose != e2ee.OwnerAppNodeStatusGrantPurpose || c.Candidate != nil || c.Binding == nil ||
			!isHex(c.PreviousGrantID, RequestIDBytes) || c.PreviousGrantID == c.GrantID ||
			!isHex(c.ConfirmationProvenanceID, RequestIDBytes) ||
			!reflect.DeepEqual(c.AllowedOperations, AppNodeStatusAllowedOperations()) || c.ConfirmationLimit != 0 ||
			ValidateAppNodeExistingBinding(*c.Binding, c.Scope) != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateAppNodeExistingBinding(b e2ee.OwnerAppNodeBinding, s e2ee.OwnerAppNodeScope) error {
	if b.State != "ACTIVE" || b.HubID != s.HubID || b.OwnerID != s.OwnerID || b.ClientDeviceID != s.DeviceID ||
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

// ValidateAppNodePreparedResponse prevents a substituted code/candidate/scope
// or an independently valid challenge from replacing this exact prepare.
// The caller must authenticate the outer Hub response before using this check.
func ValidateAppNodePreparedResponse(ch AppNodeChallenge, intent e2ee.OwnerAppNodePreviewClaims, previewProof, original []byte, hub HubIdentity, now time.Time) error {
	var proof e2ee.OwnerAppNodePreview
	if decodeCanonical(previewProof, MaxAppNodeProofBytes, &proof) != nil || !reflect.DeepEqual(proof.Claims, intent) ||
		ch.Claims.PreviewProofDigest != AppNodeProofDigest(previewProof) {
		return ErrInvalid
	}
	if ch.Format != AppNodeChallengeFormat || ch.RequestID != intent.RequestID ||
		ch.RequestPacketDigest != AppNodePacketDigest(original) || ValidateAppNodeGrantClaims(ch.Claims, hub, now) != nil ||
		ch.Claims.GrantID != intent.GrantID || ch.Claims.PrepareRequestID != intent.RequestID ||
		ch.Claims.ExpectedHeadVersion != intent.Scope.HeadVersion || ch.Claims.PreparePacketDigest != ch.RequestPacketDigest ||
		validateCanonicalTime(ch.ObservedAt) != nil || intent.Scope.HeadVersion >= math.MaxInt64 {
		return ErrInvalid
	}
	if intent.Purpose == e2ee.OwnerAppNodePreviewPurpose {
		if ch.Claims.Profile != AppNodeProfileInitial || ch.Claims.Candidate == nil || ch.Claims.Candidate.CodeDigest != intent.CodeDigest {
			return ErrInvalid
		}
	} else if intent.Purpose == e2ee.OwnerAppNodeStatusPreviewPurpose {
		if ch.Claims.Profile != AppNodeProfileStatus || ch.Claims.PreviousGrantID != intent.PreviousGrantID {
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
