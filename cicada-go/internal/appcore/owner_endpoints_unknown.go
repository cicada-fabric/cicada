package appcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const ownerEndpointUnknownMax = 4
const ownerEndpointUnknownMaxBytes = 384 << 10

// This is local retention, never a Hub settlement, a queue or a new proof.
// Unknown entries are not evicted or replayed automatically.
type ownerEndpointUnknownRecord struct {
	Original   nodeOperation `json:"original"`
	Outcome    string        `json:"outcome"`
	RetainedAt string        `json:"retained_at"`
}

func (c *nativeController) ownerEndpointParkReviewID() string {
	p := c.node.Pending
	if c.storageFault || !c.hasOwnerEndpointPending() || c.nodeRecovery != nil || c.validateNodeStoredPacket(p) != nil {
		return ""
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), p.OwnerEndpointRead.OwnerProof, time.Time{})
	if err != nil {
		return ""
	}
	proofDigest := sha256.Sum256(p.OwnerEndpointRead.OwnerProof)
	raw, err := json.Marshal(struct{ PacketDigest, RequestID, ProofDigest string }{
		wire.AppNodePacketDigest(p.Request), claims.RequestID, hex.EncodeToString(proofDigest[:])})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(append([]byte("cicada/app/retain-unknown-owner-read/v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func (c *nativeController) ownerEndpointUnknownFits(p *nodeOperation) bool {
	if p == nil || p.Operation != wire.OperationOwnerEndpointRead || len(c.node.OwnerDirectoryUnknown) >= ownerEndpointUnknownMax {
		return false
	}
	history := append([]ownerEndpointUnknownRecord(nil), c.node.OwnerDirectoryUnknown...)
	// Reserve the longest canonical UTC timestamp before a new packet is sent.
	history = append(history, ownerEndpointUnknownRecord{Original: *p, Outcome: "UNKNOWN", RetainedAt: "9999-12-31T23:59:59.999999999Z"})
	raw, err := json.Marshal(history)
	defer clear(raw)
	if err != nil || len(raw) > ownerEndpointUnknownMaxBytes {
		return false
	}
	// Also reserve the complete existing node record, so a capacity refusal is
	// detected before POST/CAS and does not masquerade as a disk failure.
	state := c.node
	state.Pending, state.OwnerDirectoryUnknown = nil, history
	encoded, err := json.Marshal(state)
	defer clear(encoded)
	return err == nil && len(encoded) <= maxNodeStateRecordBytes
}

func cloneOwnerEndpointOriginal(p *nodeOperation) nodeOperation {
	copy := *p
	copy.Request, copy.Response = bytes.Clone(p.Request), bytes.Clone(p.Response)
	if p.OwnerEndpointRead != nil {
		q := *p.OwnerEndpointRead
		q.SessionToken, q.OwnerProof = bytes.Clone(q.SessionToken), bytes.Clone(q.OwnerProof)
		q.Context.ClientNonce = bytes.Clone(q.Context.ClientNonce)
		copy.OwnerEndpointRead = &q
	}
	return copy
}

func (c *nativeController) parkOwnerEndpoints(action OwnerEndpointReadAction) error {
	review := c.ownerEndpointParkReviewID()
	if !action.ConfirmPark || review == "" || action.ReviewID != review {
		return ErrInvalidAction
	}
	claims, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), c.node.Pending.OwnerEndpointRead.OwnerProof, time.Time{})
	now := c.cfg.Now().UTC()
	if err != nil || now.Before(parseExpiry(claims.ExpiresAt)) {
		return ErrInvalidAction
	}
	if !c.ownerEndpointUnknownFits(c.node.Pending) {
		return c.failOwnerEndpoints("APP_OWNER_DIRECTORY_HISTORY_FULL", errors.New("unconfirmed directory history capacity is exhausted"))
	}
	pending, history := c.node.Pending, c.node.OwnerDirectoryUnknown
	updated := append([]ownerEndpointUnknownRecord(nil), history...)
	updated = append(updated, ownerEndpointUnknownRecord{Original: cloneOwnerEndpointOriginal(pending), Outcome: "UNKNOWN", RetainedAt: now.Format(time.RFC3339Nano)})
	// One existing encrypted record/CAS retains the original and releases the
	// slot atomically. The original is still unresolved, with unchanged bytes.
	c.node.OwnerDirectoryUnknown, c.node.Pending = updated, nil
	if err := c.persistNode(); err != nil {
		c.node.OwnerDirectoryUnknown, c.node.Pending = history, pending
		return c.failStorage("APP_NODE_COMMIT_FAILED", err)
	}
	c.ownerEndpointError = "APP_OWNER_DIRECTORY_RETAINED_UNKNOWN"
	c.publish()
	return nil
}

func (c *nativeController) validateOwnerEndpointUnknownHistory() error {
	history := c.node.OwnerDirectoryUnknown
	if len(history) > ownerEndpointUnknownMax {
		return wire.ErrInvalid
	}
	raw, err := json.Marshal(history)
	defer clear(raw)
	if err != nil || len(raw) > ownerEndpointUnknownMaxBytes {
		return wire.ErrInvalid
	}
	seen := map[string]bool{}
	for i := range history {
		r := &history[i]
		if r.Outcome != "UNKNOWN" || r.Original.Applied || parseExpiry(r.RetainedAt).IsZero() ||
			r.Original.Operation != wire.OperationOwnerEndpointRead || c.validateNodeStoredPacket(&r.Original) != nil {
			return wire.ErrInvalid
		}
		claims, err := e2ee.VerifyOwnerEndpointRead(c.owner.Public(), r.Original.OwnerEndpointRead.OwnerProof, time.Time{})
		if err != nil || parseExpiry(r.RetainedAt).Before(parseExpiry(claims.ExpiresAt)) {
			return wire.ErrInvalid
		}
		digest := wire.AppNodePacketDigest(r.Original.Request)
		if seen[digest] {
			return wire.ErrInvalid
		}
		seen[digest] = true
	}
	return nil
}
