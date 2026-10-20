package installationclient

import (
	"context"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var (
	ErrTrust    = errors.New("independent local Owner trust is missing, changed or revoked")
	ErrDeadline = errors.New("registration approval expired; retain local trust and recover the original")
)

// OwnerPin is a public trust fact; it contains neither Owner private key nor
// business authority. The independent App persists it in its protected store.
type OwnerPin struct {
	OwnerID string              `json:"owner_id"`
	Public  e2ee.PublicIdentity `json:"public_identity"`
	Version uint64              `json:"version"`
	State   string              `json:"state"`
}

// PinBackend connects an actual Node's guarded local trust store. Commit must
// reject new/replacement/revoked trust and first-pin publication after before.
// Returning success means the actual pin is durable. Check rereads that same
// current independent fact. It must never accept a Hub descriptor as its input
// trust source. No backend is needed for App pins stored in the same OS vault.
type PinBackend interface {
	Commit(ctx context.Context, ownerID string, public e2ee.PublicIdentity, before time.Time) (OwnerPin, error)
	Check(context.Context, OwnerPin) error
}

type validatedApproval struct {
	CandidateDigest       string `json:"candidate_digest"`
	ApprovalReceiptDigest string `json:"approval_receipt_digest"`
	ApprovalDigest        string `json:"approval_digest"`
	CapsuleDigest         string `json:"capsule_digest"`
	OwnerProofDigest      string `json:"owner_proof_digest"`
	ACKNonce              []byte `json:"ack_nonce"`
	ValidatedAt           string `json:"validated_at"`
	AcceptBefore          string `json:"accept_before"`
}

func (c *Client) checkOwnerPin(ctx context.Context) error {
	p := c.state.OwnerPin
	v := c.state.Validation
	if p == nil || v == nil || p.State != "ACTIVE" || p.Version == 0 || e2ee.ValidatePublicIdentity(p.Public) != nil ||
		v.CandidateDigest != c.state.Candidate.CandidateDigest || c.state.Approved == nil ||
		v.ApprovalReceiptDigest != e2ee.InstallationPacketDigest(c.state.ApprovalReceipt) || v.OwnerProofDigest != e2ee.InstallationPacketDigest(c.state.Approved.OwnerProof) ||
		v.CapsuleDigest != e2ee.InstallationCapsuleDigest(c.state.Approved.TrustCapsule) || len(v.ACKNonce) != 32 {
		return ErrTrust
	}
	if c.state.Candidate.Base.Subject.Kind == e2ee.InstallationNodeSubject && c.cfg.Pins == nil {
		return ErrTrust // An in-memory flag cannot replace the real Node pin.
	}
	if c.cfg.Pins != nil && c.cfg.Pins.Check(ctx, *p) != nil {
		return ErrTrust
	}
	return nil
}

func (c *Client) saveOwnerPin(ctx context.Context) error {
	if c.checkOwnerPin(ctx) == nil {
		return nil
	}
	if c.state.Approved == nil || len(c.state.ApprovalOriginal) == 0 || len(c.state.ApprovalReceipt) == 0 {
		return ErrState
	}
	admission, err := c.admission.E2EE()
	if err != nil {
		return ErrState
	}
	// Authenticate the retained delivery itself before using any public scope
	// or capsule, including after a restart between Poll and local pin save.
	var delivered wire.InstallationApproved
	if wire.OpenInstallationResponse(admission, c.cfg.Hub, c.state.ApprovalOriginal, c.state.ApprovalReceipt, &delivered) != nil {
		return ErrTrust
	}
	now := c.cfg.Now().UTC()
	var capsule e2ee.InstallationTrustCapsule
	candidate := c.state.Candidate
	switch candidate.Base.Trust.Kind {
	case e2ee.InstallationFirstOOB:
		capsule, err = e2ee.OpenInstallationTrustCapsuleFirstOOB(admission, candidate, delivered.OwnerProof, delivered.TrustCapsule, c.state.OOBSecret, now)
	case e2ee.InstallationExistingLocalPin:
		if c.cfg.LocalPin == nil {
			return ErrTrust
		}
		local, loadErr := c.cfg.LocalPin(ctx)
		if loadErr != nil {
			return ErrTrust
		}
		capsule, err = e2ee.OpenInstallationTrustCapsuleExistingPin(admission, candidate, delivered.OwnerProof, delivered.TrustCapsule, local, now)
	default:
		return ErrTrust
	}
	if err != nil {
		return ErrTrust // Never try another trust branch after a mismatch.
	}
	defer clear(capsule.OOBSecret)
	defer clear(capsule.ACKNonce)
	claims, err := e2ee.VerifyInstallationOwnerProof(capsule.OwnerPublic, candidate, delivered.OwnerProof, now)
	if err != nil {
		return ErrTrust
	}
	deadline, err := time.Parse(time.RFC3339Nano, claims.Approval.AcceptBefore)
	if err != nil || !c.cfg.Now().UTC().Before(deadline) {
		return ErrDeadline
	}
	pin := OwnerPin{OwnerID: claims.Approval.Scope.OwnerID, Public: capsule.OwnerPublic, State: "ACTIVE", Version: 1}
	if old := c.state.OwnerPin; old != nil {
		if old.State != "ACTIVE" || old.Version == 0 || old.OwnerID != pin.OwnerID || !samePublic(old.Public, pin.Public) {
			return ErrTrust // Late ACK/retry cannot silently overwrite a pin.
		}
		pin.Version = old.Version
	}
	if candidate.Base.Subject.Kind == e2ee.InstallationNodeSubject && c.cfg.Pins == nil {
		return ErrTrust
	}
	if c.cfg.Pins != nil {
		pin, err = c.cfg.Pins.Commit(ctx, pin.OwnerID, pin.Public, deadline)
		if err != nil || pin.State != "ACTIVE" || pin.Version == 0 || pin.OwnerID != claims.Approval.Scope.OwnerID || !samePublic(pin.Public, capsule.OwnerPublic) {
			return ErrTrust
		}
	}
	t, err := e2ee.InstallationApprovalDigest(claims.Approval)
	if err != nil {
		return ErrTrust
	}
	c.state.OwnerPin = &pin
	c.state.Validation = &validatedApproval{CandidateDigest: candidate.CandidateDigest,
		ApprovalReceiptDigest: e2ee.InstallationPacketDigest(c.state.ApprovalReceipt), ApprovalDigest: t,
		CapsuleDigest: e2ee.InstallationCapsuleDigest(delivered.TrustCapsule), OwnerProofDigest: e2ee.InstallationPacketDigest(delivered.OwnerProof),
		ACKNonce: append([]byte(nil), capsule.ACKNonce...), ValidatedAt: now.Format(time.RFC3339Nano), AcceptBefore: claims.Approval.AcceptBefore}
	return c.persist() // Actual protected pin/witness commits before ACK creation.
}

func (c *Client) Accept(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	if c.state.Pending != nil || c.state.Recovery != nil {
		return ErrPending
	}
	if err := c.saveOwnerPin(ctx); err != nil {
		return err
	}
	now := c.cfg.Now().UTC()
	deadline, err := time.Parse(time.RFC3339Nano, c.state.Validation.AcceptBefore)
	if err != nil || !now.Before(deadline) {
		return ErrDeadline // The durable local trust fact remains; no fresh ACK.
	}
	approved := c.state.Approved
	claims, err := e2ee.VerifyInstallationOwnerProof(c.state.OwnerPin.Public, c.state.Candidate, approved.OwnerProof, now)
	if err != nil {
		return ErrTrust
	}
	header, err := c.selfHeader(wire.OperationInstallationAccept)
	if err != nil {
		return err
	}
	acceptance, err := e2ee.SealInstallationSubjectAccept(c.cfg.Subject, c.state.Candidate, claims, approved.OwnerProof, header.Self.RequestID, c.state.Validation.ACKNonce)
	if err != nil {
		return ErrTrust
	}
	v := c.state.Validation
	body := wire.InstallationAccept{Format: wire.InstallationFormat, ApprovalReceiptDigest: v.ApprovalReceiptDigest,
		ApprovalDigest: v.ApprovalDigest, CapsuleDigest: v.CapsuleDigest, OwnerProofDigest: v.OwnerProofDigest,
		ACKNonce: append([]byte(nil), v.ACKNonce...), SubjectAcceptance: acceptance}
	defer wire.ClearInstallationRequestSecrets(&body)
	if err := c.begin(header, body); err != nil {
		return err
	}
	return c.sendPending(ctx)
}

func (c *Client) validateRegistered(v wire.InstallationResult) error {
	if c.state.OwnerPin == nil || c.state.Validation == nil || v.Parent == nil || v.Subject == nil ||
		v.Parent.InstallationID != c.cfg.InstallationID || v.Parent.OwnerID != c.state.OwnerPin.OwnerID || v.Subject.ParentRegistrationID != v.Parent.RegistrationID ||
		v.Subject.Kind != c.state.Candidate.Base.Subject.Kind || !samePublic(v.Subject.Public, c.cfg.Subject.Public()) || v.Subject.SubjectRegistrationEpoch == 0 || v.Subject.Revision == 0 {
		return ErrState
	}
	subject := c.state.Candidate.Base.Subject
	instance := ""
	if subject.App != nil {
		instance = subject.App.DeviceID
	} else if subject.Node != nil {
		instance = subject.Node.NodeID
	}
	if v.Subject.InstanceID != instance {
		return ErrState
	}
	provenance := wire.InstallationNewRegisteredOnly
	if subject.Mode == e2ee.InstallationAdoptExisting {
		provenance = wire.InstallationLegacyAdopted
	}
	if v.Subject.AuthProvenance != provenance || provenance == wire.InstallationNewRegisteredOnly && len(v.Grants) != 0 {
		return ErrState
	}
	return nil
}
