package installationclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type Config struct {
	Origin          string
	Hub             wire.HubIdentity
	InstallationID  string
	TransportPolicy string
	Subject         *e2ee.Identity // Borrowed actual local subject, never an Owner signer.
	Storage         Storage
	HTTP            HTTPDoer
	Now             func() time.Time
	Pins            PinBackend
	LocalPin        func(context.Context) (e2ee.InstallationLocalPin, error)
}

type Client struct {
	mu        sync.Mutex
	cfg       Config
	state     durableState
	admission *appkeys.Identity
	revision  uint64
	poisoned  bool
	closed    bool
}

func (*Client) String() string   { return "InstallationClient<protected>" }
func (*Client) GoString() string { return "InstallationClient<protected>" }

// New restores existing protected state without networking or key generation.
// Missing/corrupt state, a different subject or changed Hub pin fails closed.
func New(config Config) (*Client, error) {
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Subject == nil || config.Storage == nil || config.HTTP == nil || !id(config.InstallationID) ||
		e2ee.ValidateInstallationOrigin(config.Origin, config.TransportPolicy) != nil || e2ee.ValidatePublicIdentity(config.Subject.Public()) != nil {
		return nil, ErrState
	}
	if _, err := wire.HubFingerprint(config.Hub); err != nil {
		return nil, ErrState
	}
	c := &Client{cfg: config}
	if err := c.load(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

func id(value string) bool {
	if len(value) != 32 {
		return false
	}
	b, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(b) == value
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrState
	}
	return hex.EncodeToString(raw[:]), nil
}

func (c *Client) requireOpen() error {
	if c.closed {
		return ErrClosed
	}
	if c.poisoned {
		return ErrStorage
	}
	return nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	clearState(&c.state)
	if c.admission != nil {
		c.admission.Close()
		c.admission = nil
	}
	return nil // The caller owns Storage and the borrowed subject handle.
}

func (c *Client) checkAvailable(ctx context.Context) error {
	capabilities, err := readCapabilities(ctx, c.cfg.HTTP, c.cfg.Origin)
	if err != nil || capabilities.TransportPolicy != c.cfg.TransportPolicy {
		return ErrUnavailable
	}
	return nil
}

func (c *Client) selfHeader(operation string) (wire.InstallationPacket, error) {
	requestID, err := randomID()
	if err != nil || c.admission == nil || c.cfg.Now().IsZero() {
		return wire.InstallationPacket{}, ErrState
	}
	nonce := make([]byte, wire.NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return wire.InstallationPacket{}, ErrState
	}
	self := wire.InstallationSelfContext{HubID: c.cfg.Hub.HubID, InstallationID: c.cfg.InstallationID,
		AttemptID: c.state.Candidate.Base.AttemptID, RequestID: requestID, Nonce: nonce,
		IssuedAt: c.cfg.Now().UTC().Format(time.RFC3339Nano)}
	if trust := c.state.Candidate.Base.Trust.Existing; trust != nil && trust.Source == e2ee.InstallationRegisteredParent {
		self.ParentRegistrationID, self.RegistrationEpoch, self.AdmissionCredentialVersion = trust.ParentRegistrationID, trust.RegistrationEpoch, trust.AdmissionCredentialVersion
	}
	if result := c.state.Result; result != nil && result.Parent != nil && result.AttemptState == wire.InstallationRegistered {
		self.ParentRegistrationID, self.RegistrationEpoch, self.AdmissionCredentialVersion = result.Parent.RegistrationID, result.Parent.RegistrationEpoch, result.Parent.AdmissionCredentialVersion
	}
	return wire.InstallationPacket{Format: wire.InstallationPacketFormat, Version: 1, Operation: operation,
		SenderPublic: c.admission.Public(), Self: &self}, nil
}

func (c *Client) begin(header wire.InstallationPacket, body any) error {
	if c.state.Pending != nil || c.state.Recovery != nil {
		return ErrPending
	}
	admission, err := c.admission.E2EE()
	if err != nil {
		return ErrState
	}
	original, err := wire.SealInstallationRequest(admission, c.cfg.Hub, header, body)
	if err != nil {
		return ErrState
	}
	c.state.Pending = &requestRecord{Operation: header.Operation, RequestID: header.Self.RequestID, Original: original}
	return c.persist() // No caller may POST until this exact snapshot commits.
}

// Retry sends the retained original, or applies an already durably saved
// authenticated response. Transport failures never clear or reseal the packet.
func (c *Client) Retry(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.requireOpen(); err != nil {
		return err
	}
	return c.sendPending(ctx)
}

func (c *Client) sendPending(ctx context.Context) error {
	r := c.state.Pending
	if r == nil || c.state.Recovery != nil {
		return ErrPending
	}
	if len(r.Response) != 0 {
		return c.applyResponse(r)
	}
	if err := c.checkAvailable(ctx); err != nil {
		return err
	}
	if r.Operation == wire.OperationInstallationAccept {
		if err := c.checkOwnerPin(ctx); err != nil {
			return err
		}
	}
	raw, err := postOriginal(ctx, c.cfg.HTTP, c.cfg.Origin, r.Operation, r.Original)
	if err != nil {
		return err
	}
	defer clear(raw)
	if _, err := c.authenticateResponse(r, raw); err != nil {
		return ErrUnknown
	}
	r.Response = append([]byte(nil), raw...)
	if err := c.persist(); err != nil {
		return err
	}
	return c.applyResponse(r)
}

type openedResponse struct {
	start      *wire.InstallationStartResult
	possession *e2ee.InstallationPossession
	approved   *wire.InstallationApproved
	result     *wire.InstallationResult
	fenced     bool
}

func (c *Client) authenticateResponse(r *requestRecord, raw []byte) (openedResponse, error) {
	var reply openedResponse
	admission, err := c.admission.E2EE()
	if err != nil {
		return reply, ErrState
	}
	open := func(out any) error { return wire.OpenInstallationResponse(admission, c.cfg.Hub, r.Original, raw, out) }
	candidate := c.state.Candidate
	// A fence settles this exact mutation, without resetting other attempt or
	// parent effects, grants, identities, pins or immutable deadlines.
	fence := new(wire.InstallationResult)
	if open(fence) == nil && fence.Outcome == wire.InstallationRejectedFenced {
		if wire.InstallationIsRead(r.Operation) || fence.AttemptID != candidate.Base.AttemptID {
			return reply, ErrState
		}
		reply.result, reply.fenced = fence, true
		return reply, nil
	}
	switch r.Operation {
	case wire.OperationInstallationStart:
		v := new(wire.InstallationStartResult)
		if open(v) != nil || v.CandidateDigest != candidate.CandidateDigest || v.AttemptID != candidate.Base.AttemptID || v.ExpiresAt != candidate.Base.ExpiresAt ||
			v.AdmissionChallenge.Header.StartPacketDigest != e2ee.InstallationPacketDigest(r.Original) || v.SubjectChallenge.Header.StartPacketDigest != e2ee.InstallationPacketDigest(r.Original) ||
			v.AdmissionChallenge.Header.ChallengeID != v.SubjectChallenge.Header.ChallengeID {
			return reply, ErrState
		}
		reply.start = v
	case wire.OperationInstallationProve:
		v := new(e2ee.InstallationPossession)
		public, _ := e2ee.InstallationSubjectPublic(candidate.Base.Subject)
		if c.state.Start == nil || open(v) != nil || v.CandidateDigest != candidate.CandidateDigest || v.OOBCommitment != candidate.OOBCommitment ||
			v.ChallengeID != c.state.Start.AdmissionChallenge.Header.ChallengeID || v.StartPacketDigest != c.state.Start.AdmissionChallenge.Header.StartPacketDigest ||
			v.AdmissionKeyID != candidate.Base.AdmissionPublic.ID || v.SubjectKeyID != public.ID {
			return reply, ErrState
		}
		reply.possession = v
	case wire.OperationInstallationPoll:
		approved := new(wire.InstallationApproved)
		if open(approved) == nil {
			if approved.Result.AttemptID != candidate.Base.AttemptID {
				return reply, ErrState
			}
			reply.approved = approved
		} else {
			result := new(wire.InstallationResult)
			if open(result) != nil || result.AttemptID != candidate.Base.AttemptID || result.AttemptState == wire.InstallationRegistered {
				return reply, ErrState // Registration still requires our saved local pin/ACK.
			}
			reply.result = result
		}
	case wire.OperationInstallationAccept, wire.OperationInstallationSelf, wire.OperationInstallationHeartbeat:
		v := new(wire.InstallationResult)
		if open(v) != nil || v.AttemptID != candidate.Base.AttemptID {
			return reply, ErrState
		}
		if v.AttemptState == wire.InstallationRegistered && c.validateRegistered(*v) != nil {
			return reply, ErrState
		}
		reply.result = v
	default:
		return reply, ErrState
	}
	return reply, nil
}

func (c *Client) applyResponse(r *requestRecord) error {
	reply, err := c.authenticateResponse(r, r.Response)
	if err != nil {
		c.poisoned = true
		return ErrState
	}
	if reply.start != nil {
		c.state.Start = reply.start
	}
	if reply.possession != nil {
		c.state.Possession = reply.possession
	}
	if reply.approved != nil {
		c.state.Approved = reply.approved
		clear(c.state.ApprovalOriginal)
		clear(c.state.ApprovalReceipt)
		c.state.ApprovalOriginal = append([]byte(nil), r.Original...)
		c.state.ApprovalReceipt = append([]byte(nil), r.Response...)
	}
	if reply.result != nil {
		c.state.Result = reply.result
		if r.Operation == wire.OperationInstallationAccept && reply.result.AttemptState == wire.InstallationRegistered && !reply.fenced {
			c.state.Registered = reply.result
			clear(c.state.AcceptOriginal)
			clear(c.state.AcceptReceipt)
			c.state.AcceptOriginal = append([]byte(nil), r.Original...)
			c.state.AcceptReceipt = append([]byte(nil), r.Response...)
		}
	}
	clearRecord(c.state.Last)
	c.state.Last, c.state.Pending = r, nil
	return c.persist()
}

// PublicStatus deliberately contains no ticket, secret, admission key or raw
// packet. A registration observation is never business authorization.
type PublicStatus struct {
	InstallationID     string
	AttemptID          string
	CandidateDigest    string
	PendingOperation   string
	PossessionVerified bool
	OwnerApproved      bool
}

func (c *Client) Status() PublicStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.requireOpen() != nil {
		return PublicStatus{}
	}
	status := PublicStatus{InstallationID: c.cfg.InstallationID, AttemptID: c.state.Candidate.Base.AttemptID,
		CandidateDigest: c.state.Candidate.CandidateDigest, PossessionVerified: c.state.Possession != nil, OwnerApproved: c.state.Approved != nil}
	if c.state.Pending != nil {
		status.PendingOperation = c.state.Pending.Operation
	}
	return status
}

func samePublic(a, b e2ee.PublicIdentity) bool { return reflect.DeepEqual(a, b) }
