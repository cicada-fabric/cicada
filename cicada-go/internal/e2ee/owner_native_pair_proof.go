package e2ee

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxOwnerNativePairProofBytes = 32 * 1024

func ownerNativePairDomain(purpose string) string {
	switch purpose {
	case OwnerNativePairBootstrapPreview:
		return OwnerNativePairBootstrapPreviewDomain
	case OwnerNativePairBootstrapCommit:
		return OwnerNativePairBootstrapCommitDomain
	case OwnerNativePairConsentPreview:
		return OwnerNativePairConsentPreviewDomain
	case OwnerNativePairSlotConsent:
		return OwnerNativePairSlotConsentDomain
	case OwnerNativePairSlotReject:
		return OwnerNativePairSlotRejectDomain
	case OwnerNativePairRevoke:
		return OwnerNativePairRevokeDomain
	}
	return ""
}

// SignOwnerNativePair signs only this protocol's validated, typed purposes.
// It does not establish current Root/device/Node/slot authority.
func SignOwnerNativePair(owner *Identity, claims OwnerNativePairClaims) ([]byte, error) {
	if ValidateOwnerNativePairClaims(claims, time.Time{}) != nil || owner == nil || !reflect.DeepEqual(owner.Public(), claims.Scope.Actor.OwnerPublic) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, ownerNativePairDomain(claims.Purpose), claims)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(OwnerNativePairProof{Claims: claims, Signature: sig})
	if err != nil || len(raw) > MaxOwnerNativePairProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

// expectedPurpose is selected by the trusted operation, never from the proof.
// Zero now verifies history only; live admission must use transaction time.
func VerifyOwnerNativePair(trusted PublicIdentity, raw []byte, expectedPurpose string, now time.Time) (OwnerNativePairClaims, error) {
	var p OwnerNativePairProof
	if len(raw) > MaxOwnerNativePairProofBytes || ownerNativePairDomain(expectedPurpose) == "" || tlsProofRead(raw, &p) != nil || p.Claims.Purpose != expectedPurpose ||
		!reflect.DeepEqual(trusted, p.Claims.Scope.Actor.OwnerPublic) || ValidateOwnerNativePairClaims(p.Claims, now) != nil ||
		verifyAppNodeSignature(trusted, ownerNativePairDomain(expectedPurpose), p.Claims, p.Signature) != nil {
		return OwnerNativePairClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func nativePairToken(s string) bool {
	return len(s) <= 128 && tlsGrantToken(s) && s != "." && s != ".." && !strings.ContainsAny(s, "/\\")
}

func nativePairRevision(n uint64) bool { return n > 0 && n < math.MaxInt64 }

func validateOwnerNativePairScope(s OwnerNativePairScope) error {
	a, b := s.Actor, s.Node
	if appNodeProofScope(a) != nil || a.HeadVersion != 0 || !nativePairRevision(s.NodeControlBindingVersion) ||
		len(a.Origin) > 512 || !utf8.ValidString(b.NodeName) || len(b.NodeName) > 128 || strings.ContainsAny(b.NodeName, "\x00\r\n") ||
		!canonicalSHA256Hex(s.CredentialCommitment) || !canonicalSHA256Hex(s.NodeTupleDigest) ||
		b.OwnerID != a.OwnerID || b.HubID != a.HubID || b.ClientDeviceID != a.DeviceID || b.OwnerKeyID != a.OwnerPublic.ID || b.State != "ACTIVE" ||
		!nativePairToken(b.OwnerBindingID) || !nativePairToken(b.NodeID) || b.NodeID == "control-local" || b.NodeID == "worker-local" ||
		ValidatePublicIdentity(b.NodePublic) != nil || ValidatePublicIdentity(b.HubNodeControlPublic) != nil || b.NodePublic.ID == b.HubNodeControlPublic.ID ||
		!canonicalSHA256Hex(b.NodeKeyFingerprint) || !canonicalSHA256Hex(b.HubNodeControlFingerprint) ||
		!nativePairToken(b.ApprovedRequestID) || !canonicalSHA256Hex(b.ApprovedCandidateDigest) {
		return ErrInvalidEnvelope
	}
	for _, id := range []string{a.HubID, a.AccountID, a.AccountSessionID, a.OwnerID, a.DeviceID} {
		if !nativePairToken(id) {
			return ErrInvalidEnvelope
		}
	}
	for _, n := range []uint64{b.BindingVersion, b.CredentialVersion, b.NodeKeyVersion, b.NodeKeyEpoch, b.HubNodeControlKeyVersion, b.ApprovedRequestVersion} {
		if !nativePairRevision(n) {
			return ErrInvalidEnvelope
		}
	}
	if _, err := parseCanonicalUTC(b.ApprovedAt); err != nil {
		return ErrInvalidEnvelope
	}
	return nil
}

// Structural proof checks are independent of current Store authority and of
// full public manifest/digest recomputation in hubaccountwire.
func ValidateOwnerNativePairClaims(c OwnerNativePairClaims, now time.Time) error {
	if c.Version != 1 || ownerNativePairDomain(c.Purpose) == "" || validateOwnerNativePairScope(c.Scope) != nil ||
		!appNodeProofID(c.RequestID) || !canonicalSHA256Hex(c.Nonce) {
		return ErrInvalidEnvelope
	}
	count := 0
	for _, present := range []bool{c.Bootstrap != nil, c.Consent != nil, c.Reject != nil, c.Revoke != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return ErrInvalidEnvelope
	}
	lifetime := time.Minute
	if c.Purpose == OwnerNativePairBootstrapCommit || c.Purpose == OwnerNativePairSlotConsent {
		lifetime = 5 * time.Minute
	}
	if appNodeProofWindow(c.IssuedAt, c.ExpiresAt, lifetime, now) != nil {
		return ErrInvalidEnvelope
	}
	end, _ := parseCanonicalUTC(c.ExpiresAt)
	sessionEnd, _ := parseCanonicalUTC(c.Scope.Actor.AccountSessionExpiresAt)
	if end.After(sessionEnd) {
		return ErrInvalidEnvelope
	}
	switch c.Purpose {
	case OwnerNativePairBootstrapPreview, OwnerNativePairBootstrapCommit:
		b := c.Bootstrap
		if b == nil || b.Runtime != "codex" || b.SlotCount != 2 || b.Policy != NativePairFixedPeerPolicy() ||
			!utf8.ValidString(b.GroupLabel) || b.GroupLabel == "" || len(b.GroupLabel) > 128 || strings.TrimSpace(b.GroupLabel) != b.GroupLabel || strings.ContainsAny(b.GroupLabel, "\x00\r\n") {
			return ErrInvalidEnvelope
		}
		if c.Purpose == OwnerNativePairBootstrapPreview {
			if b.PairID != "" || b.NetworkID != "" || b.GroupID != "" || b.PreparedAt != "" || b.JoinUntil != "" || b.PeerExpiresAt != "" || b.PrepareRequestID != "" || b.PreparePacketDigest != "" || b.ServerNonce != "" {
				return ErrInvalidEnvelope
			}
			return nil
		}
		if !appNodeProofID(b.PairID) || !nativePairToken(b.NetworkID) || !nativePairToken(b.GroupID) || !appNodeProofID(b.PrepareRequestID) || b.PrepareRequestID == c.RequestID || !canonicalSHA256Hex(b.PreparePacketDigest) || !canonicalSHA256Hex(b.ServerNonce) {
			return ErrInvalidEnvelope
		}
		prepared, e := parseCanonicalUTC(b.PreparedAt)
		join, je := parseCanonicalUTC(b.JoinUntil)
		peer, pe := parseCanonicalUTC(b.PeerExpiresAt)
		issued, _ := parseCanonicalUTC(c.IssuedAt)
		if e != nil || je != nil || pe != nil || issued.Before(prepared) || end.After(prepared.Add(5*time.Minute)) || !join.Equal(prepared.Add(10*time.Minute)) || !peer.Equal(prepared.Add(time.Hour)) {
			return ErrInvalidEnvelope
		}
	case OwnerNativePairConsentPreview, OwnerNativePairSlotConsent:
		p := c.Consent
		if p == nil || !appNodeProofID(p.PairID) || !nativePairRevision(p.ExpectedRevision) || !canonicalSHA256Hex(p.SlotADigest) || !canonicalSHA256Hex(p.SlotBDigest) || p.SlotADigest == p.SlotBDigest {
			return ErrInvalidEnvelope
		}
		peer, e := parseCanonicalUTC(p.PeerExpiresAt)
		if e != nil || end.After(peer) {
			return ErrInvalidEnvelope
		}
		if c.Purpose == OwnerNativePairConsentPreview {
			if p.PlanID != "" || p.PlanDigest != "" || p.Slot != "" || p.SlotGeneration != 0 || p.SlotAttemptID != "" || p.NativeSessionID != "" || p.PeerNativeSessionID != "" || p.ActivateWhenBoth || p.PlanExpiresAt != "" {
				return ErrInvalidEnvelope
			}
			return nil
		}
		planEnd, e := parseCanonicalUTC(p.PlanExpiresAt)
		if e != nil || end.After(planEnd) || planEnd.After(peer) || !appNodeProofID(p.PlanID) || !canonicalSHA256Hex(p.PlanDigest) || (p.Slot != "A" && p.Slot != "B") ||
			!nativePairRevision(p.SlotGeneration) || p.SlotGeneration > 16 || !appNodeProofID(p.SlotAttemptID) || !nativePairToken(p.NativeSessionID) || !nativePairToken(p.PeerNativeSessionID) || p.NativeSessionID == p.PeerNativeSessionID || !p.ActivateWhenBoth {
			return ErrInvalidEnvelope
		}
	case OwnerNativePairSlotReject:
		r := c.Reject
		if r == nil || !appNodeProofID(r.PairID) || !nativePairRevision(r.ExpectedRevision) || (r.Slot != "A" && r.Slot != "B") || !nativePairRevision(r.SlotGeneration) || r.SlotGeneration > 16 || !appNodeProofID(r.SlotAttemptID) || !canonicalSHA256Hex(r.SlotDigest) {
			return ErrInvalidEnvelope
		}
	case OwnerNativePairRevoke:
		r := c.Revoke
		if r == nil || !appNodeProofID(r.PairID) || !nativePairRevision(r.ExpectedRevision) || !canonicalSHA256Hex(r.PairTargetDigest) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}
