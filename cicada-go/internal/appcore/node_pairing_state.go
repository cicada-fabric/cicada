package appcore

import (
	"bytes"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// The original ceremony stays in the scoped encrypted Node record. Its separate
// recovery reuses the existing mutually exclusive N3 recovery slot. Code holds
// S and is never projected. Packets precede HTTP; verified receipts precede apply.
type nodePairTrustState struct {
	Code                wire.NodePairTrustCode      `json:"code"`
	Context             *wire.NodePairTrustContext  `json:"context,omitempty"`
	OOB                 string                      `json:"oob,omitempty"`
	Scope               e2ee.OwnerAppNodeScope      `json:"scope"`
	Stage               string                      `json:"stage"`
	ConsentReviewID     string                      `json:"consent_review_id,omitempty"`
	GrantProof          []byte                      `json:"grant_proof,omitempty"`
	Confirmation        *nodeOperation              `json:"confirmation,omitempty"`
	Approval            *wire.NodePairTrustApproval `json:"approval,omitempty"`
	OwnerProof          []byte                      `json:"owner_proof,omitempty"`
	Capsule             []byte                      `json:"capsule,omitempty"`
	Pending             *nodePairTrustOperation     `json:"pending,omitempty"`
	Recovery            *nodePairTrustOperation     `json:"-"`
	LastError           string                      `json:"last_error,omitempty"`
	CleanupComplete     bool                        `json:"cleanup_complete,omitempty"`
	FencedOperation     string                      `json:"fenced_operation,omitempty"`
	FencedRequestDigest string                      `json:"fenced_request_digest,omitempty"`
}
type nodePairTrustOperation struct {
	Operation  string          `json:"operation"`
	Body       json.RawMessage `json:"body"`
	Request    []byte          `json:"request"`
	Response   []byte          `json:"response,omitempty"`
	Applied    bool            `json:"applied"`
	BodyDigest string          `json:"body_digest,omitempty"`
}

func (c *nativeController) nodePairTrustPending() bool {
	t := c.node.PairTrust
	return t != nil && ((t.Pending != nil && !t.Pending.Applied) || t.Recovery != nil)
}
func (c *nativeController) nodePairTrustBusy() bool {
	t := c.node.PairTrust
	if t == nil {
		return false
	}
	return c.nodePairTrustPending() || t.FencedOperation != "" || t.Stage == "LOOKUP" || t.Stage == "REVIEW" || t.Stage == "APPROVING" || t.Stage == wire.NodePairTrustPending || t.Stage == wire.NodePairTrustOwnerApproved || (t.Confirmation != nil && !t.Confirmation.Applied) || c.nodePairTrustNeedsCleanup()
}

func (c *nativeController) nodePairTrustNeedsCleanup() bool {
	t := c.node.PairTrust
	return t != nil && pairTrustTerminal(t.Stage) && t.Context != nil && t.Context.Mode == wire.NodePairTrustInitial && !t.CleanupComplete
}
func pairTrustBody(p *nodePairTrustOperation) (any, error) {
	var out any
	switch p.Operation {
	case wire.OperationOwnerNodePairTrustLookup:
		out = new(wire.NodePairTrustOwnerLookup)
	case wire.OperationOwnerNodePairTrustPrepare:
		out = new(wire.NodePairTrustOwnerPrepare)
	case wire.OperationOwnerNodePairTrustComplete:
		out = new(wire.NodePairTrustOwnerComplete)
	case wire.OperationOwnerNodePairTrustStatus, wire.OperationOwnerNodePairTrustCancel:
		out = new(wire.NodePairTrustOwnerStatus)
	case wire.OperationNodePairTrustReconcile:
		out = new(wire.NodePairTrustReconcile)
	default:
		return nil, wire.ErrInvalid
	}
	if decodeStateJSON(p.Body, out) != nil {
		return nil, wire.ErrInvalid
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(encoded, p.Body) {
		return nil, wire.ErrInvalid
	}
	return out, nil
}
func (c *nativeController) nodePairTrustDescriptor() (string, error) {
	if c.state.Transport == nil || validateLocalTransport(c.state.Transport, c.connection) != nil {
		return "", wire.ErrInvalid
	}
	return hubtransport.EncodeDescriptor(c.state.Transport.Descriptor)
}
func (c *nativeController) matchNodePairTrust(at time.Time) error {
	t := c.node.PairTrust
	if t == nil || t.Context == nil {
		return wire.ErrInvalid
	}
	descriptor, err := c.nodePairTrustDescriptor()
	if err != nil {
		return err
	}
	o, err := wire.MatchNodePairTrustCode(t.Code, *t.Context, c.hub, c.state.Transport.Descriptor.Claims.NodeControl, c.connection.Origin, wire.NodePairTrustDescriptorDigest(descriptor), at)
	if err != nil || o != t.OOB {
		return wire.ErrInvalid
	}
	return nil
}
func (c *nativeController) restoreNodePairTrust() error {
	t := c.node.PairTrust
	if t == nil {
		return nil
	}
	if len(t.Code.OOBSecret) != 32 || t.Code.HubID != c.connection.HubID || t.Code.Origin != c.connection.Origin || t.Code.HubFingerprint != c.connection.HubFingerprint || !c.nodeScopeIdentityMatches(t.Scope) {
		return wire.ErrInvalid
	}
	descriptor, err := c.nodePairTrustDescriptor()
	if err != nil || t.Code.NodeControlFingerprint != nodewire.IdentityFingerprint(c.state.Transport.Descriptor.Claims.NodeControl) {
		return wire.ErrInvalid
	}
	if t.Context != nil {
		if t.Context.DescriptorDigest != wire.NodePairTrustDescriptorDigest(descriptor) {
			return wire.ErrInvalid
		}
		// Historical parsing never installs new trust. Match at the original Context
		// issuance time; fresh approval separately rechecks the real current clock.
		if c.matchNodePairTrust(parseExpiry(t.Context.IssuedAt)) != nil {
			return wire.ErrInvalid
		}
	}
	if t.Approval != nil && (t.Context == nil || wire.ValidateNodePairTrustApproval(*t.Approval, *t.Context, t.OOB, time.Time{}) != nil) {
		return wire.ErrInvalid
	}
	for _, p := range []*nodePairTrustOperation{t.Pending, t.Recovery} {
		if p == nil {
			continue
		}
		if len(p.Request) == 0 || len(p.Request) > wire.MaxNodePairTrustReconcilePacketBytes || len(p.Response) > wire.MaxNodePairTrustReconcileResponsePacketBytes {
			return wire.ErrInvalid
		}
		var h wire.NodePairTrustPacket
		if decodeStateJSON(p.Request, &h) != nil || h.AttemptID != t.Code.AttemptID || h.Operation != p.Operation || !reflect.DeepEqual(h.SenderPublic, c.device.Public()) {
			return wire.ErrInvalid
		}
		if _, err := c.nodePairTrustBody(p); err != nil {
			return err
		}
	}
	if t.Confirmation != nil && (c.validateNodeStoredPacket(t.Confirmation) != nil || t.Confirmation.Kind != wire.AppNodeOriginalClient || t.Confirmation.Operation != "nodes.confirm") {
		return wire.ErrInvalid
	}
	if t.Pending != nil && !t.Pending.Applied && len(t.Pending.Response) != 0 {
		return c.applyNodePairTrustResponse(false)
	}
	return nil
}
func (c *nativeController) clearNodePairTrust() {
	if t := c.node.PairTrust; t != nil {
		clear(t.Code.OOBSecret)
		clear(t.GrantProof)
		clear(t.OwnerProof)
		clear(t.Capsule)
		for _, p := range []*nodePairTrustOperation{t.Pending, t.Recovery} {
			if p != nil {
				clear(p.Body)
				clear(p.Request)
				clear(p.Response)
			}
		}
		if t.Confirmation != nil {
			clear(t.Confirmation.Request)
			clear(t.Confirmation.Response)
		}
	}
	c.pairTrustWorking, c.pairTrustAvailable, c.pairTrustDiscovery = false, false, false
	c.pairTrustAvailability = ""
}

func (c *nativeController) observesReservedNodeConfirmation(got wire.AppNodeClientCounters) bool {
	t := c.node.PairTrust
	if t == nil || t.Confirmation == nil || t.Confirmation.Applied || !c.node.Client.Initialized {
		return false
	}
	p := t.Confirmation
	var packet clientwire.Packet
	if p.Kind != wire.AppNodeOriginalClient || p.Operation != "nodes.confirm" || json.Unmarshal(p.Request, &packet) != nil {
		return false
	}
	route := packet.Route
	return route.SessionEpoch == c.node.Client.Epoch && route.Sequence == c.node.Client.NextRequest && p.ExpectedResponseSequence == c.node.Client.NextResponse && got.SessionEpoch == route.SessionEpoch && got.LastRequestSequence == route.Sequence && got.NextResponseSequence == p.ExpectedResponseSequence+1
}
