package installationclient

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const stateLimit = 1 << 20

// Storage must encrypt/authenticate the whole snapshot in its actual OS-private
// scope. Successful CAS is durable; an uncertain commit must fence the store.
// appvault.PreRegistrationStore supplies this contract for the independent App.
type Storage interface {
	LoadState() ([]byte, uint64, error)
	CompareAndSwapState(uint64, []byte) (uint64, error)
}

type requestRecord struct {
	Operation string `json:"operation"`
	RequestID string `json:"request_id"`
	Original  []byte `json:"original"`
	Response  []byte `json:"response"`
}

type durableState struct {
	Format           string                        `json:"format"`
	ContractRevision string                        `json:"contract_revision"`
	Candidate        wire.InstallationCandidate    `json:"candidate"`
	AdmissionPrivate []byte                        `json:"admission_private"`
	OOBSecret        []byte                        `json:"oob_secret"`
	Pending          *requestRecord                `json:"pending"`
	Recovery         *requestRecord                `json:"recovery"`
	Last             *requestRecord                `json:"last"`
	Start            *wire.InstallationStartResult `json:"start"`
	Possession       *e2ee.InstallationPossession  `json:"possession"`
	Approved         *wire.InstallationApproved    `json:"approved"`
	ApprovalOriginal []byte                        `json:"approval_original"`
	ApprovalReceipt  []byte                        `json:"approval_receipt"`
	OwnerPin         *OwnerPin                     `json:"owner_pin"`
	Validation       *validatedApproval            `json:"validation"`
	AcceptOriginal   []byte                        `json:"accept_original"`
	AcceptReceipt    []byte                        `json:"accept_receipt"`
	Registered       *wire.InstallationResult      `json:"registered"`
	Result           *wire.InstallationResult      `json:"result"`
}

func canonical(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrState
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrState
	}
	again, err := json.Marshal(out)
	defer clear(again)
	if err != nil || !bytes.Equal(again, raw) {
		return ErrState
	}
	return nil
}

func (c *Client) load() error {
	raw, revision, err := c.cfg.Storage.LoadState()
	defer clear(raw)
	if err != nil {
		return ErrStorage
	}
	c.revision = revision
	if len(raw) == 0 {
		if revision != 0 {
			return ErrState // A tombstone never means a new installation/identity.
		}
		return nil
	}
	if canonical(raw, &c.state, stateLimit) != nil || c.state.Format != "cicada.installation-client.state.v1" || c.state.ContractRevision != wire.InstallationContractRevision {
		return ErrState
	}
	b := c.state.Candidate.Base
	if wire.ValidateInstallationCandidate(c.state.Candidate, c.cfg.Hub) != nil || b.InstallationID != c.cfg.InstallationID || b.Hub.Origin != c.cfg.Origin || b.Hub.TransportPolicy != c.cfg.TransportPolicy {
		return ErrState
	}
	public, err := e2ee.InstallationSubjectPublic(b.Subject)
	if err != nil || !reflect.DeepEqual(public, c.cfg.Subject.Public()) {
		return ErrState
	}
	c.admission, err = appkeys.ParseIdentity(c.state.AdmissionPrivate)
	if err != nil || !reflect.DeepEqual(c.admission.Public(), b.AdmissionPublic) {
		return ErrState
	}
	if b.Trust.Kind == e2ee.InstallationFirstOOB {
		o, err := e2ee.InstallationOOBCommitment(c.state.Candidate.CandidateDigest, c.state.OOBSecret)
		if err != nil || o != c.state.Candidate.OOBCommitment {
			return ErrState
		}
	} else if c.state.OOBSecret != nil {
		return ErrState
	}
	for _, r := range []*requestRecord{c.state.Pending, c.state.Recovery, c.state.Last} {
		if r != nil && c.validateRecord(r) != nil {
			return ErrState
		}
	}
	return nil
}

func (c *Client) validateRecord(r *requestRecord) error {
	var p wire.InstallationPacket
	maximum := wire.MaxInstallationPacketBytes
	if r.Operation == wire.OperationInstallationReconcile {
		maximum = wire.MaxInstallationReconcilePacketBytes
	}
	if canonical(r.Original, &p, maximum) != nil || p.Format != wire.InstallationPacketFormat || p.Version != 1 || p.Operation != r.Operation || wire.InstallationHTTPPath(p.Operation) == "" ||
		!reflect.DeepEqual(p.SenderPublic, c.admission.Public()) || p.Self == nil || p.Account != nil || p.Self.HubID != c.cfg.Hub.HubID || p.Self.InstallationID != c.cfg.InstallationID ||
		p.Self.AttemptID != c.state.Candidate.Base.AttemptID || p.Self.RequestID != r.RequestID || len(p.Self.Nonce) != wire.NonceBytes {
		return ErrState
	}
	return nil
}

func (c *Client) persist() error {
	raw, err := json.Marshal(c.state)
	defer clear(raw)
	if err != nil || len(raw) > stateLimit {
		c.poisoned = true
		return ErrStorage
	}
	revision, err := c.cfg.Storage.CompareAndSwapState(c.revision, raw)
	if err != nil {
		c.poisoned = true // Never send in-memory bytes after a failed publication.
		return ErrStorage
	}
	c.revision = revision
	return nil
}

func clearRecord(r *requestRecord) {
	if r != nil {
		clear(r.Original)
		clear(r.Response)
	}
}

func clearState(s *durableState) {
	clear(s.AdmissionPrivate)
	clear(s.OOBSecret)
	clear(s.ApprovalOriginal)
	clear(s.ApprovalReceipt)
	clear(s.AcceptOriginal)
	clear(s.AcceptReceipt)
	if s.Validation != nil {
		clear(s.Validation.ACKNonce)
	}
	clearRecord(s.Pending)
	clearRecord(s.Recovery)
	clearRecord(s.Last)
	*s = durableState{}
}
