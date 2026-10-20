package installationclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type Draft struct {
	Subject           e2ee.InstallationSubject
	Components        []string
	Trust             e2ee.InstallationTrustSource
	RetainedAdmission *appkeys.Identity
	NodeCredential    []byte
}

func (Draft) String() string   { return "InstallationDraft<protected>" }
func (Draft) GoString() string { return "InstallationDraft<protected>" }

// Start creates one new local attempt only on an unused store. Admission key,
// independent S, immutable candidate and exact Start ciphertext publish in one
// CAS before any secret POST. It never recreates an unresolved attempt.
func (c *Client) Start(ctx context.Context, draft Draft) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	if c.revision != 0 || c.state.Candidate.CandidateDigest != "" || c.state.Pending != nil {
		return ErrPending
	}
	if err := c.checkAvailable(ctx); err != nil {
		return err
	}
	public, err := e2ee.InstallationSubjectPublic(draft.Subject)
	if err != nil || !samePublic(public, c.cfg.Subject.Public()) || c.cfg.Now().IsZero() {
		return ErrState
	}
	attemptID, err := randomID()
	if err != nil {
		return err
	}
	if draft.Trust.Kind == "" {
		draft.Trust.Kind = e2ee.InstallationFirstOOB
	}
	if draft.RetainedAdmission != nil {
		if draft.Trust.Existing == nil || draft.Trust.Existing.Source != e2ee.InstallationRegisteredParent {
			return ErrState
		}
		private, err := draft.RetainedAdmission.MarshalBinary()
		if err != nil {
			return ErrState
		}
		defer clear(private)
		c.admission, err = appkeys.ParseIdentity(private)
	} else {
		if draft.Trust.Existing != nil && draft.Trust.Existing.Source == e2ee.InstallationRegisteredParent {
			return ErrState
		}
		c.admission, err = appkeys.Generate()
	}
	if err != nil {
		return ErrState
	}
	private, err := c.admission.MarshalBinary()
	if err != nil {
		return ErrState
	}
	var secret []byte
	if draft.Trust.Kind == e2ee.InstallationFirstOOB {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			clear(private)
			clear(secret)
			return ErrState
		}
	}
	now := c.cfg.Now().UTC()
	fingerprint, _ := wire.HubFingerprint(c.cfg.Hub)
	base := e2ee.InstallationCandidateBase{Format: wire.InstallationFormat,
		Hub: e2ee.InstallationHubRef{Origin: c.cfg.Origin, HubID: c.cfg.Hub.HubID, Public: c.cfg.Hub.Public,
			KeyVersion: c.cfg.Hub.KeyVersion, Fingerprint: fingerprint, TransportPolicy: c.cfg.TransportPolicy},
		InstallationID: c.cfg.InstallationID, AttemptID: attemptID, AdmissionPublic: c.admission.Public(),
		Components: append([]string(nil), draft.Components...), Subject: draft.Subject, Trust: draft.Trust,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	candidate, err := e2ee.NewInstallationCandidate(base, secret)
	if err != nil {
		clear(private)
		clear(secret)
		return ErrState
	}
	c.state = durableState{Format: "cicada.installation-client.state.v1", ContractRevision: wire.InstallationContractRevision,
		Candidate: candidate, AdmissionPrivate: private, OOBSecret: secret}
	header, err := c.selfHeader(wire.OperationInstallationStart)
	if err != nil {
		return err
	}
	// Start's outer context shares B's actual immutable local issuance.
	header.Self.IssuedAt = base.IssuedAt
	subjectProof, err := wire.SealInstallationStartSubject(c.cfg.Subject, c.cfg.Hub, *header.Self, candidate)
	if err != nil {
		return ErrState
	}
	body := wire.InstallationStart{Format: wire.InstallationFormat, Candidate: candidate, SubjectSignatureProof: subjectProof,
		NodeCredential: append([]byte(nil), draft.NodeCredential...)}
	defer wire.ClearInstallationRequestSecrets(&body)
	if err := c.begin(header, body); err != nil {
		return err
	}
	return c.sendPending(ctx)
}

// Prove decrypts both distinct KEM challenges with the actual retained keys.
// The complete admission/subject receipts commit before their first HTTP send.
func (c *Client) Prove(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	if c.state.Pending != nil || c.state.Recovery != nil {
		return ErrPending
	}
	if c.state.Start == nil || c.state.Possession != nil {
		return ErrState
	}
	admission, err := c.admission.E2EE()
	if err != nil {
		return ErrState
	}
	s := c.state.Start
	a, err := e2ee.OpenInstallationKEMChallenge(admission, c.state.Candidate, s.AdmissionChallenge.Header, s.AdmissionChallenge.Packet, c.cfg.Now().UTC())
	if err != nil {
		return ErrState
	}
	defer clear(a.Nonce)
	b, err := e2ee.OpenInstallationKEMChallenge(c.cfg.Subject, c.state.Candidate, s.SubjectChallenge.Header, s.SubjectChallenge.Packet, c.cfg.Now().UTC())
	if err != nil {
		return ErrState
	}
	defer clear(b.Nonce)
	if bytes.Equal(a.Nonce, b.Nonce) || a.IssuedAt != b.IssuedAt || a.ExpiresAt != b.ExpiresAt {
		return ErrState
	}
	header, err := c.selfHeader(wire.OperationInstallationProve)
	if err != nil {
		return err
	}
	subject, err := e2ee.SealInstallationKEMReceipt(c.cfg.Subject, c.state.Candidate, e2ee.InstallationKEMReceipt{Format: wire.InstallationFormat, Challenge: b, ProveRequestID: header.Self.RequestID})
	if err != nil {
		return ErrState
	}
	admitted, err := e2ee.SealInstallationKEMReceipt(admission, c.state.Candidate, e2ee.InstallationKEMReceipt{Format: wire.InstallationFormat, Challenge: a,
		ProveRequestID: header.Self.RequestID, SubjectReceiptDigest: e2ee.InstallationPacketDigest(subject)})
	if err != nil {
		return ErrState
	}
	body := wire.InstallationProve{Format: wire.InstallationFormat, ChallengeID: a.ChallengeID, StartPacketDigest: a.StartPacketDigest,
		AdmissionReceipt: admitted, SubjectReceipt: subject}
	if err := c.begin(header, body); err != nil {
		return err
	}
	return c.sendPending(ctx)
}

func (c *Client) Poll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	if c.state.Start == nil {
		return ErrState
	}
	header, err := c.selfHeader(wire.OperationInstallationPoll)
	if err != nil {
		return err
	}
	if err := c.begin(header, wire.InstallationPoll{Format: wire.InstallationFormat, CandidateDigest: c.state.Candidate.CandidateDigest}); err != nil {
		return err
	}
	return c.sendPending(ctx)
}

// Ticket is deliberately a secret-only API rather than part of PublicStatus.
// The caller may display/copy it in the explicit local pairing interaction;
// it must never enter diagnostic snapshots, logs or general public-field rows.
func (c *Client) Ticket() (string, error) {
	if !c.mu.TryLock() {
		return "", ErrPending
	}
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return "", err
	}
	if c.state.Candidate.Base.Trust.Kind != e2ee.InstallationFirstOOB || c.state.Pending != nil || c.state.Possession == nil {
		return "", ErrState
	}
	expiry, err := time.Parse(time.RFC3339Nano, c.state.Candidate.Base.ExpiresAt)
	if err != nil || c.cfg.Now().IsZero() || !c.cfg.Now().UTC().Before(expiry) {
		return "", ErrState
	}
	token, err := wire.EncodeInstallationTicket(c.state.Candidate, c.state.OOBSecret)
	if err != nil || len(token) > wire.MaxInstallationTicketBytes {
		return "", ErrState
	}
	return token, nil
}
