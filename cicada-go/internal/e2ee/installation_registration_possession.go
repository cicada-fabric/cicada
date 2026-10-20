package e2ee

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"time"
)

const (
	installationKEMDomain           = "cicada/installation-registration/kem-challenge/v1\x00"
	installationKEMNonceDomain      = "cicada/installation-registration/kem-nonce/v1\x00"
	installationSubjectKEMDomain    = "cicada/installation-registration/subject-kem-receipt/v1\x00"
	installationAdmissionKEMDomain  = "cicada/installation-registration/admission-kem-receipt/v1\x00"
	installationSubjectAcceptDomain = "cicada/installation-registration/subject-accept/v1\x00"
)

func installationAAD(domain string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxInstallationProofBytes {
		return nil, ErrInvalidEnvelope
	}
	out := append([]byte(nil), []byte(domain)...)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	out = append(out, size[:]...)
	return append(out, b...), nil
}

func InstallationKEMHeader(c InstallationKEMChallenge) InstallationKEMChallenge {
	c.Nonce = nil
	return c
}

func installationChallengeRecipient(c InstallationCandidate, purpose string) (PublicIdentity, error) {
	switch purpose {
	case InstallationAdmissionKEM:
		return c.Base.AdmissionPublic, nil
	case InstallationSubjectKEM:
		return InstallationSubjectPublic(c.Base.Subject)
	}
	return PublicIdentity{}, ErrInvalidEnvelope
}

func validateInstallationKEMChallenge(c InstallationCandidate, challenge InstallationKEMChallenge) error {
	public, err := installationChallengeRecipient(c, challenge.Purpose)
	if err != nil || ValidateInstallationCandidate(c) != nil || challenge.Format != InstallationRegistrationFormat || challenge.CandidateDigest != c.CandidateDigest || challenge.OOBCommitment != c.OOBCommitment ||
		challenge.HubID != c.Base.Hub.HubID || challenge.InstallationID != c.Base.InstallationID || challenge.AttemptID != c.Base.AttemptID ||
		!canonicalSHA256Hex(challenge.StartPacketDigest) || !appNodeProofID(challenge.ChallengeID) || challenge.RecipientKeyID != public.ID || len(challenge.Nonce) != 32 {
		return ErrInvalidEnvelope
	}
	i, e, err := installationWindow(challenge.IssuedAt, challenge.ExpiresAt, 2*time.Minute)
	begin, _ := parseCanonicalUTC(c.Base.IssuedAt)
	end, _ := parseCanonicalUTC(c.Base.ExpiresAt)
	if err != nil || i.Before(begin.Add(-InstallationIssuanceSkew)) || e.After(end) {
		return ErrInvalidEnvelope
	}
	return nil
}

func InstallationKEMNonceDigest(c InstallationKEMChallenge) (string, error) {
	if len(c.Nonce) != 32 {
		return "", ErrInvalidEnvelope
	}
	return installationStructDigest(installationKEMNonceDomain, c)
}

func SealInstallationKEMChallenge(hub *Identity, c InstallationCandidate, challenge InstallationKEMChallenge) ([]byte, error) {
	if hub == nil || !installationSamePublic(hub.Public(), c.Base.Hub.Public) || validateInstallationKEMChallenge(c, challenge) != nil {
		return nil, ErrInvalidEnvelope
	}
	public, _ := installationChallengeRecipient(c, challenge.Purpose)
	aad, err := installationAAD(installationKEMDomain, InstallationKEMHeader(challenge))
	if err != nil {
		return nil, err
	}
	plain, err := installationProofBytes(challenge)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return Seal(hub, public, plain, aad, 1)
}

func OpenInstallationKEMChallenge(recipient *Identity, c InstallationCandidate, header InstallationKEMChallenge, packet []byte, now time.Time) (InstallationKEMChallenge, error) {
	var out InstallationKEMChallenge
	public, err := installationChallengeRecipient(c, header.Purpose)
	if recipient == nil || err != nil || !installationSamePublic(recipient.Public(), public) || header.Nonce != nil {
		return out, ErrInvalidEnvelope
	}
	aad, err := installationAAD(installationKEMDomain, header)
	if err != nil {
		return out, err
	}
	plain, seq, err := Open(recipient, c.Base.Hub.Public, packet, aad)
	if err != nil || seq != 1 {
		clear(plain)
		return out, ErrInvalidEnvelope
	}
	defer clear(plain)
	if installationReadCanonical(plain, &out, MaxInstallationProofBytes) != nil || validateInstallationKEMChallenge(c, out) != nil || !bytes.Equal(mustInstallationJSON(InstallationKEMHeader(out)), mustInstallationJSON(header)) {
		clear(out.Nonce)
		return InstallationKEMChallenge{}, ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(out.IssuedAt, out.ExpiresAt, 2*time.Minute)
	if installationCurrent(i, e, now) != nil {
		clear(out.Nonce)
		return InstallationKEMChallenge{}, ErrInvalidEnvelope
	}
	return out, nil
}

func installationReceiptHeader(r InstallationKEMReceipt) InstallationKEMReceipt {
	r.Challenge = InstallationKEMHeader(r.Challenge)
	return r
}

func installationReceiptDomain(r InstallationKEMReceipt) (string, error) {
	if !appNodeProofID(r.ProveRequestID) || r.Format != InstallationRegistrationFormat {
		return "", ErrInvalidEnvelope
	}
	switch r.Challenge.Purpose {
	case InstallationSubjectKEM:
		if r.SubjectReceiptDigest == "" {
			return installationSubjectKEMDomain, nil
		}
	case InstallationAdmissionKEM:
		if canonicalSHA256Hex(r.SubjectReceiptDigest) {
			return installationAdmissionKEMDomain, nil
		}
	}
	return "", ErrInvalidEnvelope
}

func SealInstallationKEMReceipt(sender *Identity, c InstallationCandidate, r InstallationKEMReceipt) ([]byte, error) {
	public, err := installationChallengeRecipient(c, r.Challenge.Purpose)
	domain, de := installationReceiptDomain(r)
	if sender == nil || err != nil || de != nil || !installationSamePublic(sender.Public(), public) || validateInstallationKEMChallenge(c, r.Challenge) != nil {
		return nil, ErrInvalidEnvelope
	}
	aad, err := installationAAD(domain, installationReceiptHeader(r))
	if err != nil {
		return nil, err
	}
	plain, err := installationProofBytes(r)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return Seal(sender, c.Base.Hub.Public, plain, aad, 1)
}

func openInstallationKEMReceipt(hub *Identity, c InstallationCandidate, expected InstallationKEMReceipt, packet []byte, expectedNonceDigest string, now time.Time) (InstallationKEMReceipt, error) {
	var out InstallationKEMReceipt
	public, err := installationChallengeRecipient(c, expected.Challenge.Purpose)
	domain, de := installationReceiptDomain(expected)
	if hub == nil || err != nil || de != nil || !installationSamePublic(hub.Public(), c.Base.Hub.Public) || expected.Challenge.Nonce != nil || !canonicalSHA256Hex(expectedNonceDigest) {
		return out, ErrInvalidEnvelope
	}
	aad, err := installationAAD(domain, expected)
	if err != nil {
		return out, err
	}
	plain, seq, err := Open(hub, public, packet, aad)
	if err != nil || seq != 1 {
		clear(plain)
		return out, ErrInvalidEnvelope
	}
	defer clear(plain)
	if installationReadCanonical(plain, &out, MaxInstallationProofBytes) != nil || validateInstallationKEMChallenge(c, out.Challenge) != nil || !bytes.Equal(mustInstallationJSON(installationReceiptHeader(out)), mustInstallationJSON(expected)) {
		clear(out.Challenge.Nonce)
		return InstallationKEMReceipt{}, ErrInvalidEnvelope
	}
	d, err := InstallationKEMNonceDigest(out.Challenge)
	i, e, _ := installationWindow(out.Challenge.IssuedAt, out.Challenge.ExpiresAt, 2*time.Minute)
	if err != nil || subtle.ConstantTimeCompare([]byte(d), []byte(expectedNonceDigest)) != 1 || installationCurrent(i, e, now) != nil {
		clear(out.Challenge.Nonce)
		return InstallationKEMReceipt{}, ErrInvalidEnvelope
	}
	return out, nil
}

func VerifyInstallationPossession(hub *Identity, c InstallationCandidate, admissionHeader, subjectHeader InstallationKEMChallenge, requestID string, admissionPacket, subjectPacket []byte, admissionNonceDigest, subjectNonceDigest string, now time.Time) (InstallationPossession, error) {
	var empty InstallationPossession
	if admissionHeader.Purpose != InstallationAdmissionKEM || subjectHeader.Purpose != InstallationSubjectKEM || admissionHeader.ChallengeID != subjectHeader.ChallengeID ||
		admissionHeader.StartPacketDigest != subjectHeader.StartPacketDigest || admissionHeader.IssuedAt != subjectHeader.IssuedAt || admissionHeader.ExpiresAt != subjectHeader.ExpiresAt {
		return empty, ErrInvalidEnvelope
	}
	s, err := openInstallationKEMReceipt(hub, c, InstallationKEMReceipt{Format: InstallationRegistrationFormat, Challenge: subjectHeader, ProveRequestID: requestID}, subjectPacket, subjectNonceDigest, now)
	if err != nil {
		return empty, err
	}
	defer clear(s.Challenge.Nonce)
	a, err := openInstallationKEMReceipt(hub, c, InstallationKEMReceipt{Format: InstallationRegistrationFormat, Challenge: admissionHeader, ProveRequestID: requestID, SubjectReceiptDigest: InstallationPacketDigest(subjectPacket)}, admissionPacket, admissionNonceDigest, now)
	if err != nil {
		return empty, err
	}
	defer clear(a.Challenge.Nonce)
	if bytes.Equal(a.Challenge.Nonce, s.Challenge.Nonce) {
		return empty, ErrInvalidEnvelope
	}
	return InstallationPossession{CandidateDigest: c.CandidateDigest, OOBCommitment: c.OOBCommitment, ChallengeID: admissionHeader.ChallengeID, StartPacketDigest: admissionHeader.StartPacketDigest, AdmissionKeyID: c.Base.AdmissionPublic.ID, SubjectKeyID: s.Challenge.RecipientKeyID, ProveRequestID: requestID, VerifiedAt: now.UTC().Format(time.RFC3339Nano)}, nil
}

func installationAcceptHeader(a InstallationSubjectAccept) InstallationSubjectAccept {
	a.ACKNonce = nil
	return a
}

func SealInstallationSubjectAccept(subject *Identity, c InstallationCandidate, claims InstallationOwnerClaims, ownerProof []byte, requestID string, nonce []byte) ([]byte, error) {
	public, err := InstallationSubjectPublic(c.Base.Subject)
	if subject == nil || err != nil || !installationSamePublic(subject.Public(), public) || ValidateInstallationApproval(claims.Approval, c) != nil || !appNodeProofID(requestID) {
		return nil, ErrInvalidEnvelope
	}
	ack, err := InstallationACKCommitment(claims.Approval, nonce)
	if err != nil || ack != claims.ACKCommitment {
		return nil, ErrInvalidEnvelope
	}
	t, _ := InstallationApprovalDigest(claims.Approval)
	s, _ := InstallationSubjectDigest(c.Base.Subject)
	a := InstallationSubjectAccept{Format: InstallationRegistrationFormat, CandidateDigest: c.CandidateDigest, ApprovalDigest: t, CapsuleDigest: claims.CapsuleDigest, OwnerProofDigest: InstallationPacketDigest(ownerProof), ACKNonce: nonce, AcceptRequestID: requestID, SubjectDigest: s}
	aad, err := installationAAD(installationSubjectAcceptDomain, installationAcceptHeader(a))
	if err != nil {
		return nil, err
	}
	plain, err := installationProofBytes(a)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return Seal(subject, c.Base.Hub.Public, plain, aad, 1)
}

func OpenInstallationSubjectAccept(hub *Identity, trustedOwner PublicIdentity, c InstallationCandidate, proof, capsule, packet []byte, requestID string, now time.Time) (InstallationSubjectAccept, error) {
	var out InstallationSubjectAccept
	claims, err := VerifyInstallationOwnerProof(trustedOwner, c, proof, now)
	if hub == nil || err != nil || !installationSamePublic(hub.Public(), c.Base.Hub.Public) || !appNodeProofID(requestID) {
		return out, ErrInvalidEnvelope
	}
	public, _ := InstallationSubjectPublic(c.Base.Subject)
	t, _ := InstallationApprovalDigest(claims.Approval)
	s, _ := InstallationSubjectDigest(c.Base.Subject)
	expected := InstallationSubjectAccept{Format: InstallationRegistrationFormat, CandidateDigest: c.CandidateDigest, ApprovalDigest: t, CapsuleDigest: claims.CapsuleDigest, OwnerProofDigest: InstallationPacketDigest(proof), AcceptRequestID: requestID, SubjectDigest: s}
	aad, err := installationAAD(installationSubjectAcceptDomain, expected)
	if err != nil {
		return out, err
	}
	plain, seq, err := Open(hub, public, packet, aad)
	if err != nil || seq != 1 {
		clear(plain)
		return out, ErrInvalidEnvelope
	}
	defer clear(plain)
	if installationReadCanonical(plain, &out, MaxInstallationProofBytes) != nil || !bytes.Equal(mustInstallationJSON(installationAcceptHeader(out)), mustInstallationJSON(expected)) || VerifyInstallationACK(trustedOwner, c, proof, capsule, out.ACKNonce, now) != nil {
		clear(out.ACKNonce)
		return InstallationSubjectAccept{}, ErrInvalidEnvelope
	}
	return out, nil
}
