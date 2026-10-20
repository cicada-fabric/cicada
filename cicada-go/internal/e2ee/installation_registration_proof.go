package e2ee

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"
)

const (
	installationCandidateDomain = "cicada/installation-registration/candidate/v1\x00"
	installationOOBDomain       = "cicada/installation-registration/oob/v1\x00"
	installationSubjectDomain   = "cicada/installation-registration/subject/v1\x00"
	installationApprovalDomain  = "cicada/installation-registration/approval-base/v1\x00"
	installationCapsuleAAD      = "cicada/installation-registration/capsule-aad/v1\x00"
	installationCapsuleDomain   = "cicada/installation-registration/capsule-digest/v1\x00"
	installationACKDomain       = "cicada/installation-registration/ack/v1\x00"
	installationOwnerDomain     = "cicada/owner/installation-register/v1\x00"
	installationReadDomain      = "cicada/owner/installation-read/v1\x00"
	installationQueryDomain     = "cicada/installation-registration/read-target/v1\x00"
	installationAccessDomain    = "cicada/owner/installation-app-access/v1\x00"
	installationPacketDomain    = "cicada/installation-registration/packet/v1\x00"
)

// Only fixed structs are marshalled by the public helpers. Hashes frame raw
// canonical bytes with a 32-bit length; binary nonce concatenations are fixed.
func installationHash(domain string, data []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func installationStructDigest(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxInstallationProofBytes {
		return "", ErrInvalidEnvelope
	}
	return installationHash(domain, raw), nil
}

func installationReadCanonical(raw []byte, target any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum {
		return ErrInvalidEnvelope
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalidEnvelope
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalidEnvelope
	}
	return nil
}

func InstallationCandidateDigest(b InstallationCandidateBase) (string, error) {
	if ValidateInstallationBase(b) != nil {
		return "", ErrInvalidEnvelope
	}
	return installationStructDigest(installationCandidateDomain, b)
}

func InstallationSubjectDigest(s InstallationSubject) (string, error) {
	return installationStructDigest(installationSubjectDomain, s)
}

func InstallationApprovalDigest(t InstallationApprovalBase) (string, error) {
	return installationStructDigest(installationApprovalDomain, t)
}

func InstallationPacketDigest(raw []byte) string {
	return installationHash(installationPacketDomain, raw)
}

func InstallationCapsuleDigest(raw []byte) string {
	return installationHash(installationCapsuleDomain, raw)
}

func installationNonceCommitment(domain, digest string, nonce []byte) (string, error) {
	d, err := hex.DecodeString(digest)
	if err != nil || !canonicalSHA256Hex(digest) || len(nonce) != 32 {
		return "", ErrInvalidEnvelope
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(d)
	_, _ = h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func InstallationOOBCommitment(candidateDigest string, secret []byte) (string, error) {
	return installationNonceCommitment(installationOOBDomain, candidateDigest, secret)
}

func NewInstallationCandidate(base InstallationCandidateBase, secret []byte) (InstallationCandidate, error) {
	d, err := InstallationCandidateDigest(base)
	if err != nil {
		return InstallationCandidate{}, err
	}
	c := InstallationCandidate{Base: base, CandidateDigest: d}
	if base.Trust.Kind == InstallationFirstOOB {
		c.OOBCommitment, err = InstallationOOBCommitment(d, secret)
	} else if len(secret) != 0 {
		err = ErrInvalidEnvelope
	}
	if err != nil {
		return InstallationCandidate{}, err
	}
	return c, nil
}

func InstallationACKCommitment(t InstallationApprovalBase, nonce []byte) (string, error) {
	d, err := InstallationApprovalDigest(t)
	if err != nil {
		return "", err
	}
	return installationNonceCommitment(installationACKDomain, d, nonce)
}

func InstallationReadQueryDigest(q InstallationReadQuery) (string, error) {
	if ValidateInstallationReadQuery(q) != nil {
		return "", ErrInvalidEnvelope
	}
	return installationStructDigest(installationQueryDomain, q)
}

func installationProofBytes(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxInstallationProofBytes {
		return nil, ErrInvalidEnvelope
	}
	return raw, nil
}

func SignInstallationOwnerProof(owner *Identity, c InstallationCandidate, claims InstallationOwnerClaims) ([]byte, error) {
	if owner == nil || claims.Version != 1 || claims.Purpose != InstallationRegisterPurpose || ValidateInstallationApproval(claims.Approval, c) != nil ||
		!installationSamePublic(owner.Public(), claims.Approval.Scope.OwnerPublic) || !canonicalSHA256Hex(claims.CapsuleDigest) || !canonicalSHA256Hex(claims.ACKCommitment) {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, installationOwnerDomain, claims)
	if err != nil {
		return nil, err
	}
	return installationProofBytes(InstallationOwnerProof{Claims: claims, Signature: sig})
}

// First admission requires actual current time. Unlike retained legacy proof
// helpers, zero now is never a shortcut for a first registration or Owner pin.
func VerifyInstallationOwnerProof(trusted PublicIdentity, c InstallationCandidate, raw []byte, now time.Time) (InstallationOwnerClaims, error) {
	var p InstallationOwnerProof
	if installationReadCanonical(raw, &p, MaxInstallationProofBytes) != nil || p.Claims.Version != 1 || p.Claims.Purpose != InstallationRegisterPurpose ||
		!installationSamePublic(trusted, p.Claims.Approval.Scope.OwnerPublic) || ValidateInstallationApprovalAt(p.Claims.Approval, c, now) != nil ||
		!canonicalSHA256Hex(p.Claims.CapsuleDigest) || !canonicalSHA256Hex(p.Claims.ACKCommitment) || verifyAppNodeSignature(trusted, installationOwnerDomain, p.Claims, p.Signature) != nil {
		return InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func installationCapsuleAADBytes(t InstallationApprovalBase) ([]byte, error) {
	d, err := InstallationApprovalDigest(t)
	if err != nil {
		return nil, err
	}
	b, _ := hex.DecodeString(d)
	return append([]byte(installationCapsuleAAD), b...), nil
}

// Secrets are supplied by the existing trusted local random/persistence path.
// This helper neither exports them nor writes trust or authorization state.
func SealInstallationOwnerApproval(owner *Identity, c InstallationCandidate, t InstallationApprovalBase, secret, ackNonce []byte) ([]byte, []byte, error) {
	if owner == nil || ValidateInstallationApproval(t, c) != nil || !installationSamePublic(owner.Public(), t.Scope.OwnerPublic) || len(ackNonce) != 32 {
		return nil, nil, ErrInvalidEnvelope
	}
	if c.Base.Trust.Kind == InstallationFirstOOB {
		o, err := InstallationOOBCommitment(c.CandidateDigest, secret)
		if err != nil || o != c.OOBCommitment || bytes.Equal(secret, ackNonce) {
			return nil, nil, ErrInvalidEnvelope
		}
	} else if secret != nil || c.OOBCommitment != "" {
		return nil, nil, ErrInvalidEnvelope
	}
	aad, err := installationCapsuleAADBytes(t)
	if err != nil {
		return nil, nil, err
	}
	plain, err := installationProofBytes(InstallationTrustCapsule{Format: InstallationRegistrationFormat, Approval: t, OwnerPublic: owner.Public(), OOBSecret: secret, ACKNonce: ackNonce})
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	capsule, err := Seal(owner, c.Base.AdmissionPublic, plain, aad, 1)
	if err != nil {
		return nil, nil, err
	}
	a, err := InstallationACKCommitment(t, ackNonce)
	if err != nil {
		return nil, nil, err
	}
	proof, err := SignInstallationOwnerProof(owner, c, InstallationOwnerClaims{Version: 1, Purpose: InstallationRegisterPurpose, Approval: t, CapsuleDigest: InstallationCapsuleDigest(capsule), ACKCommitment: a})
	return proof, capsule, err
}

func openInstallationCapsule(admission *Identity, c InstallationCandidate, proof, capsule []byte, now time.Time) (InstallationTrustCapsule, InstallationOwnerClaims, error) {
	var out InstallationTrustCapsule
	var p InstallationOwnerProof
	if admission == nil || !installationSamePublic(admission.Public(), c.Base.AdmissionPublic) ||
		installationReadCanonical(proof, &p, MaxInstallationProofBytes) != nil {
		return out, InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	claims, err := VerifyInstallationOwnerProof(p.Claims.Approval.Scope.OwnerPublic, c, proof, now)
	if err != nil || claims.CapsuleDigest != InstallationCapsuleDigest(capsule) {
		return out, InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	aad, err := installationCapsuleAADBytes(claims.Approval)
	if err != nil {
		return out, InstallationOwnerClaims{}, err
	}
	plain, seq, err := Open(admission, claims.Approval.Scope.OwnerPublic, capsule, aad)
	if err != nil || seq != 1 {
		return out, InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	defer clear(plain)
	if installationReadCanonical(plain, &out, MaxInstallationProofBytes) != nil || out.Format != InstallationRegistrationFormat ||
		!installationSamePublic(out.OwnerPublic, claims.Approval.Scope.OwnerPublic) || !bytes.Equal(mustInstallationJSON(out.Approval), mustInstallationJSON(claims.Approval)) ||
		len(out.ACKNonce) != 32 {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return InstallationTrustCapsule{}, InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	a, ae := InstallationACKCommitment(claims.Approval, out.ACKNonce)
	if ae != nil || a != claims.ACKCommitment {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return InstallationTrustCapsule{}, InstallationOwnerClaims{}, ErrInvalidEnvelope
	}
	return out, claims, nil
}

// The candidate and OOB secret come from the retained local attempt, never
// from Hub. No fallback to the existing-pin branch exists. Clear the result.
func OpenInstallationTrustCapsuleFirstOOB(admission *Identity, c InstallationCandidate, proof, capsule, localSecret []byte, now time.Time) (InstallationTrustCapsule, error) {
	if c.Base.Trust.Kind != InstallationFirstOOB || len(localSecret) != 32 {
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	out, _, err := openInstallationCapsule(admission, c, proof, capsule, now)
	if err != nil {
		return InstallationTrustCapsule{}, err
	}
	o, oe := InstallationOOBCommitment(c.CandidateDigest, localSecret)
	if oe != nil || o != c.OOBCommitment || len(out.OOBSecret) != 32 || bytes.Equal(out.OOBSecret, out.ACKNonce) || subtle.ConstantTimeCompare(out.OOBSecret, localSecret) != 1 {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	return out, nil
}

// The expected pin/admission context is independently read from guarded local
// state. A Hub-supplied Existing descriptor, empty pin or revoked pin rejects.
// Adding a component does not require another secret transfer or Owner key copy.
func OpenInstallationTrustCapsuleExistingPin(admission *Identity, c InstallationCandidate, proof, capsule []byte, pin InstallationLocalPin, now time.Time) (InstallationTrustCapsule, error) {
	if admission == nil || !installationSamePublic(admission.Public(), c.Base.AdmissionPublic) || c.Base.Trust.Kind != InstallationExistingLocalPin || c.Base.Trust.Existing == nil || pin.TrustState != "ACTIVE" ||
		pin.InstallationID != c.Base.InstallationID || pin.Hub.HubID != c.Base.Hub.HubID || pin.Hub.Origin != c.Base.Hub.Origin {
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	d, err := OwnerDevicePublicKeyFingerprint(pin.OwnerPublic)
	e := c.Base.Trust.Existing
	if err != nil || e.Source != pin.Source ||
		e.OwnerID != pin.OwnerID || e.OwnerKeyID != pin.OwnerPublic.ID || e.OwnerPublicDigest != d || e.LocalTrustVersion != pin.TrustVersion {
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	switch e.Source {
	case InstallationRegisteredParent:
		if pin.RegistrationState != "REGISTERED" || pin.LegacyNode != nil || pin.LegacyNodeState != "" ||
			!installationSamePublic(pin.AdmissionPublic, c.Base.AdmissionPublic) || !bytes.Equal(mustInstallationJSON(pin.Hub), mustInstallationJSON(c.Base.Hub)) ||
			e.ParentRegistrationID != pin.ParentRegistrationID || e.RegistrationEpoch != pin.RegistrationEpoch || e.AdmissionCredentialVersion != pin.AdmissionCredentialVersion {
			return InstallationTrustCapsule{}, ErrInvalidEnvelope
		}
	case InstallationLegacyNode:
		if pin.RegistrationState != "" || pin.ParentRegistrationID != "" || pin.RegistrationEpoch != 0 || pin.AdmissionCredentialVersion != 0 || pin.LegacyNodeState != "ACTIVE" ||
			!installationSamePublic(pin.AdmissionPublic, PublicIdentity{}) || pin.LegacyNode == nil || c.Base.Subject.Node == nil || c.Base.Subject.Mode != InstallationAdoptExisting ||
			!bytes.Equal(mustInstallationJSON(*pin.LegacyNode), mustInstallationJSON(*c.Base.Subject.Node)) {
			return InstallationTrustCapsule{}, ErrInvalidEnvelope
		}
		if pin.Hub.Public.ID != "" || len(pin.Hub.Public.KEMPublic) != 0 || len(pin.Hub.Public.SigningPublic) != 0 || pin.Hub.KeyVersion != 0 || pin.Hub.Fingerprint != "" {
			if !bytes.Equal(mustInstallationJSON(pin.Hub), mustInstallationJSON(c.Base.Hub)) {
				return InstallationTrustCapsule{}, ErrInvalidEnvelope
			}
		}
	default:
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	if _, err := VerifyInstallationOwnerProof(pin.OwnerPublic, c, proof, now); err != nil {
		return InstallationTrustCapsule{}, err
	}
	out, _, err := openInstallationCapsule(admission, c, proof, capsule, now)
	if err != nil {
		return InstallationTrustCapsule{}, err
	}
	if out.OOBSecret != nil || !installationSamePublic(out.OwnerPublic, pin.OwnerPublic) {
		clear(out.OOBSecret)
		clear(out.ACKNonce)
		return InstallationTrustCapsule{}, ErrInvalidEnvelope
	}
	return out, nil
}

func mustInstallationJSON(v any) []byte {
	b, _ := json.Marshal(v) // Fixed structs contain no unsupported JSON values.
	return b
}

// This validates capsule possession only; Store must still verify current
// actor/epochs, both key PoPs, the subject acknowledgement and revision CAS.
func VerifyInstallationACK(trusted PublicIdentity, c InstallationCandidate, proof, capsule, nonce []byte, now time.Time) error {
	claims, err := VerifyInstallationOwnerProof(trusted, c, proof, now)
	if err != nil || claims.CapsuleDigest != InstallationCapsuleDigest(capsule) {
		return ErrInvalidEnvelope
	}
	a, err := InstallationACKCommitment(claims.Approval, nonce)
	if err != nil || a != claims.ACKCommitment {
		return ErrInvalidEnvelope
	}
	return nil
}

func SignInstallationOwnerRead(owner *Identity, claims InstallationOwnerReadClaims, query InstallationReadQuery) ([]byte, error) {
	if owner == nil || !installationSamePublic(owner.Public(), claims.Scope.OwnerPublic) || validateInstallationReadClaims(claims, query) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, installationReadDomain, claims)
	if err != nil {
		return nil, err
	}
	return installationProofBytes(InstallationOwnerReadProof{Claims: claims, Signature: sig})
}

func VerifyInstallationOwnerRead(trusted PublicIdentity, raw []byte, query InstallationReadQuery, now time.Time) (InstallationOwnerReadClaims, error) {
	var p InstallationOwnerReadProof
	if installationReadCanonical(raw, &p, MaxInstallationProofBytes) != nil || !installationSamePublic(trusted, p.Claims.Scope.OwnerPublic) || validateInstallationReadClaims(p.Claims, query) != nil || verifyAppNodeSignature(trusted, installationReadDomain, p.Claims, p.Signature) != nil {
		return InstallationOwnerReadClaims{}, ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(p.Claims.IssuedAt, p.Claims.ExpiresAt, time.Minute)
	if installationCurrent(i, e, now) != nil {
		return InstallationOwnerReadClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}

func SignInstallationAccess(owner *Identity, claims InstallationAccessClaims) ([]byte, error) {
	if owner == nil || !installationSamePublic(owner.Public(), claims.Scope.OwnerPublic) || validateInstallationAccessClaims(claims) != nil {
		return nil, ErrInvalidEnvelope
	}
	sig, err := tlsProofSignature(owner, owner.Public().ID, installationAccessDomain, claims)
	if err != nil {
		return nil, err
	}
	return installationProofBytes(InstallationAccessProof{Claims: claims, Signature: sig})
}

// This is admission of a newly signed finite read grant, not later grant use.
// Later use requires the immutable stored expiry and current recipient Guards.
func VerifyInstallationAccess(trusted PublicIdentity, raw []byte, now time.Time) (InstallationAccessClaims, error) {
	var p InstallationAccessProof
	if installationReadCanonical(raw, &p, MaxInstallationProofBytes) != nil || !installationSamePublic(trusted, p.Claims.Scope.OwnerPublic) || validateInstallationAccessClaims(p.Claims) != nil || verifyAppNodeSignature(trusted, installationAccessDomain, p.Claims, p.Signature) != nil {
		return InstallationAccessClaims{}, ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(p.Claims.PreparedAt, p.Claims.ProofExpiresAt, 5*time.Minute)
	if installationCurrent(i, e, now) != nil {
		return InstallationAccessClaims{}, ErrInvalidEnvelope
	}
	return p.Claims, nil
}
