package appcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These private formats do not change the legacy authority or NPT records.
// One ceremony/original/recovery is shared by the entire App. Successful trust
// and immutable confirmation evidence are retained separately for each Node.
var scopedWorkspaces = [...]string{"appcore.node-scoped-flow.v1", "appcore.node-scoped-original.v1", "appcore.node-scoped-recovery.v1"}

const (
	scopedFlowSlot = iota
	scopedOriginalSlot
	scopedRecoverySlot
	scopedStateFormat               = "cicada.app-scoped-node.v1"
	scopedFrameFormat               = "cicada.app-scoped-original.v1"
	scopedLocalReceiptBytes         = 256 << 10
	scopedLocalRecoveryReceiptBytes = 512 << 10
)

type scopedConfirmation struct {
	Grant                    e2ee.OwnerAppNodeScopedGrantClaims
	Request, Response        []byte
	ExpectedResponseSequence uint64
}

type scopedNodeRecord struct {
	Format                                            string
	Vault                                             appvault.Scope
	DeviceKeyID, OwnerKeyID, NodeID                   string
	HighestHead                                       uint64
	LatestGrantID, ProvenanceID, SelfCancelledGrantID string
	Grant                                             *wire.AppNodeScopedChallenge
	Context                                           *wire.AppNodeScopedResult
	Current                                           *wire.AppNodeScopedResult
	Binding                                           *e2ee.OwnerAppNodeBinding
	Confirmation                                      *scopedConfirmation
	Trust                                             *scopedAcceptedTrust
	CountersCommitted                                 bool
	ReadProposal                                      *scopedReadProposal
}

type scopedReadProposal struct {
	Prepare   wire.AppNodeScopedPrepare
	Packet    []byte
	Challenge *wire.AppNodeScopedChallenge
}

type scopedAcceptedTrust struct {
	Code               wire.NodePairTrustScopedCode
	Context            wire.NodePairTrustScopedContext
	Approval           wire.NodePairTrustScopedApproval
	OOB, AcceptedAt    string
	Original           *scopedOriginal
	TrustedNodeControl e2ee.PublicIdentity
	DescriptorDigest   string
}

type scopedPairFlow struct {
	Format                           string
	Vault                            appvault.Scope
	DeviceKeyID, OwnerKeyID, NodeID  string
	Code                             wire.NodePairTrustScopedCode
	Scope                            e2ee.OwnerAppNodeScopedScope
	Context                          *wire.NodePairTrustScopedContext
	OOB, Stage, ReviewID, LastError  string
	Prepare                          *wire.AppNodeScopedPrepare
	PreparePacket                    []byte
	Challenge                        *wire.AppNodeScopedChallenge
	GrantProof                       []byte
	Confirmation                     *scopedConfirmation
	Approval                         *wire.NodePairTrustScopedApproval
	OwnerProof, Capsule              []byte
	ApprovedAt                       string
	CancelRequested, CleanupComplete bool
}

type scopedOriginal struct {
	Format                                                                    string
	Vault                                                                     appvault.Scope
	DeviceKeyID, OwnerKeyID, NodeID, Operation, RequestID, AttemptID, GrantID string
	CreatedAt                                                                 string
	PairTrust, Recovery, Applied                                              bool
	Body                                                                      json.RawMessage
	Packet, Response                                                          []byte
}

type scopedFrameHeader struct {
	Original                              scopedOriginal
	BodyBytes, PacketBytes, ResponseBytes int
}

type scopedNodesRuntime struct {
	loaded, discovered, available, adding bool
	availability, errorCode               string
	versions                              [len(scopedWorkspaces)]uint64
	flow                                  *scopedPairFlow
	original, recovery                    *scopedOriginal
	nodes                                 map[string]*scopedNodeRecord
	nodeVersions                          map[string]uint64
	fresh                                 map[string]string
}

func scopedNodeNamespace(id string) string {
	d := sha256.Sum256([]byte(id))
	// Vault names accept lowercase ASCII only. Lowercase unpadded base32 keeps
	// all 256 digest bits within the existing 64-byte namespace bound (62).
	return "app.ns." + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(d[:])) + ".v1"
}

func encodeScopedOriginal(p *scopedOriginal) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	h := scopedFrameHeader{Original: *p, BodyBytes: len(p.Body), PacketBytes: len(p.Packet), ResponseBytes: len(p.Response)}
	h.Original.Body, h.Original.Packet, h.Original.Response = nil, nil, nil
	return encodeThreadGroupFrame("CNS1", h, p.Body, p.Packet, p.Response)
}

func decodeScopedOriginal(raw []byte) (*scopedOriginal, error) {
	var h scopedFrameHeader
	data, err := decodeThreadGroupFrame(raw, "CNS1", &h)
	if err != nil || h.BodyBytes < 0 || h.PacketBytes <= 0 || h.ResponseBytes < 0 || h.BodyBytes+h.PacketBytes+h.ResponseBytes != len(data) {
		return nil, appvault.ErrInvalidVault
	}
	p := h.Original
	// A nil json.RawMessage is encoded as JSON null and decodes to the four
	// bytes "null". The actual body belongs exclusively to the framed segment.
	if len(p.Body) != 0 && !bytes.Equal(p.Body, []byte("null")) || len(p.Packet) != 0 || len(p.Response) != 0 {
		return nil, appvault.ErrInvalidVault
	}
	p.Body = slices.Clone(data[:h.BodyBytes])
	p.Packet = slices.Clone(data[h.BodyBytes : h.BodyBytes+h.PacketBytes])
	p.Response = slices.Clone(data[h.BodyBytes+h.PacketBytes:])
	return &p, nil
}

func (c *nativeController) scopedIdentity(v appvault.Scope, device, owner string) bool {
	return v == cardScope(c.connection) && device == c.state.DeviceKeyID && owner == c.state.OwnerKeyID
}

func (c *nativeController) scopedScopeMatches(s e2ee.OwnerAppNodeScopedScope, current bool) bool {
	a, err := wire.AppNodeScopedOwnerActor(s, c.hub)
	if err != nil || !c.nodeScopeIdentityMatches(a) {
		return false
	}
	if !current {
		return true
	}
	return c.scopedScopeSessionMatches(s) && s.ClientSessionEpoch == c.node.Client.Epoch
}

func (c *nativeController) scopedNode(id string) *scopedNodeRecord {
	if c.scoped.nodes == nil {
		c.scoped.nodes = map[string]*scopedNodeRecord{}
	}
	if c.scoped.nodeVersions == nil {
		c.scoped.nodeVersions = map[string]uint64{}
	}
	if c.scoped.fresh == nil {
		c.scoped.fresh = map[string]string{}
	}
	return c.scoped.nodes[id]
}

func (c *nativeController) newScopedNode(id string) *scopedNodeRecord {
	if n := c.scopedNode(id); n != nil {
		return n
	}
	n := &scopedNodeRecord{Format: scopedStateFormat, Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, NodeID: id}
	c.scoped.nodes[id] = n
	return n
}

func (c *nativeController) persistScopedNode(n *scopedNodeRecord) error {
	if n == nil || n.Format != scopedStateFormat || !c.scopedIdentity(n.Vault, n.DeviceKeyID, n.OwnerKeyID) {
		return appvault.ErrScopeMismatch
	}
	v := c.scoped.nodeVersions[n.NodeID]
	if err := c.persistNodeRecord(scopedNodeNamespace(n.NodeID), &v, n); err != nil {
		return err
	}
	c.scoped.nodeVersions[n.NodeID] = v
	return c.indexScopedNode(n, false)
}

func (c *nativeController) persistScopedFlow() error {
	var value any
	if c.scoped.flow != nil {
		value = c.scoped.flow
	}
	return c.persistNodeRecord(scopedWorkspaces[scopedFlowSlot], &c.scoped.versions[scopedFlowSlot], value)
}

func (c *nativeController) persistScopedFrame(slot int, p *scopedOriginal) error {
	raw, err := encodeScopedOriginal(p)
	if err != nil {
		return err
	}
	defer clear(raw)
	v, err := c.vault.CompareAndSwapState(scopedWorkspaces[slot], c.scoped.versions[slot], raw)
	if err != nil {
		c.storageFault = true
		return err
	}
	c.scoped.versions[slot] = v
	return nil
}

func (c *nativeController) scopedPending() bool {
	return c.scoped.original != nil && !c.scoped.original.Applied || c.scoped.recovery != nil
}

func (c *nativeController) scopedBusy() bool {
	if c.scopedPending() {
		return true
	}
	for _, n := range c.scoped.nodes {
		if n.ReadProposal != nil {
			return true
		}
	}
	f := c.scoped.flow
	return f != nil && f.Stage != wire.NodePairTrustScopedACKed && !f.CleanupComplete
}

func (c *nativeController) loadScopedNode(id string) error {
	if c.scopedNode(id) != nil {
		return nil
	}
	raw, v, found, err := c.vault.LoadState(scopedNodeNamespace(id))
	defer clear(raw)
	if err != nil {
		return err
	}
	c.scoped.nodeVersions[id] = v
	if !found || len(raw) == 0 {
		return nil
	}
	var n scopedNodeRecord
	if decodeStateJSON(raw, &n) != nil || n.Format != scopedStateFormat || n.NodeID != id || !c.scopedIdentity(n.Vault, n.DeviceKeyID, n.OwnerKeyID) {
		return appvault.ErrScopeMismatch
	}
	if n.Grant != nil && (!c.scopedScopeMatches(n.Grant.Claims.Scope, false) || n.Grant.Claims.Scope.AuthorityNodeID != id || wire.ValidateAppNodeScopedGrantClaims(n.Grant.Claims, c.hub, time.Time{}) != nil) {
		return appvault.ErrScopeMismatch
	}
	if n.Context != nil && (!c.scopedScopeMatches(n.Context.Authority.Scope, false) || n.Context.Authority.Scope.AuthorityNodeID != id) {
		return appvault.ErrScopeMismatch
	}
	if n.Binding != nil {
		if n.Binding.NodeID != id || n.Trust == nil || c.verifyStoredScopedTrust(&n) != nil {
			return appvault.ErrScopeMismatch
		}
	}
	c.scoped.nodes[id] = &n
	return nil
}

func (c *nativeController) ensureScopedNodesLoaded() error {
	if c.scoped.loaded {
		return nil
	}
	c.scoped.nodes = map[string]*scopedNodeRecord{}
	c.scoped.nodeVersions = map[string]uint64{}
	c.scoped.fresh = map[string]string{}
	for i, name := range scopedWorkspaces {
		raw, v, found, err := c.vault.LoadState(name)
		if err != nil {
			return err
		}
		c.scoped.versions[i] = v
		if found && len(raw) > 0 {
			if i == scopedFlowSlot {
				var f scopedPairFlow
				if decodeStateJSON(raw, &f) != nil || f.Format != scopedStateFormat || !c.scopedIdentity(f.Vault, f.DeviceKeyID, f.OwnerKeyID) || f.NodeID != f.Code.AuthorityNodeID {
					return appvault.ErrScopeMismatch
				}
				c.scoped.flow = &f
			} else {
				p, err := decodeScopedOriginal(raw)
				if err != nil || c.validateScopedOriginal(p) != nil {
					return appvault.ErrScopeMismatch
				}
				switch i {
				case scopedOriginalSlot:
					c.scoped.original = p
				case scopedRecoverySlot:
					c.scoped.recovery = p
				}
			}
		}
		clear(raw)
	}
	if d := c.node.Targets; d != nil {
		for _, n := range d.Nodes {
			if err := c.loadScopedNode(n.NodeID); err != nil {
				return err
			}
		}
	}
	if f := c.scoped.flow; f != nil {
		if err := c.loadScopedNode(f.NodeID); err != nil {
			return err
		}
	}
	c.scoped.loaded = true
	return nil
}

func clearScopedFlowSecrets(f *scopedPairFlow) {
	if f != nil {
		clear(f.Code.OOBSecret)
		clear(f.OwnerProof)
		clear(f.Capsule)
		clear(f.GrantProof)
		clear(f.PreparePacket)
		if f.Confirmation != nil {
			clear(f.Confirmation.Request)
			clear(f.Confirmation.Response)
		}
	}
}

func (c *nativeController) clearScopedRuntime() {
	// Encoded private code S and proof/packet bytes are owned by this runtime.
	clearScopedFlowSecrets(c.scoped.flow)
	for _, p := range []*scopedOriginal{c.scoped.original, c.scoped.recovery} {
		if p != nil {
			clear(p.Body)
			clear(p.Packet)
			clear(p.Response)
		}
	}
	for _, n := range c.scoped.nodes {
		if n.Trust != nil {
			clear(n.Trust.Code.OOBSecret)
			if p := n.Trust.Original; p != nil {
				clear(p.Body)
				clear(p.Packet)
				clear(p.Response)
			}
		}
		if n.Confirmation != nil {
			clear(n.Confirmation.Request)
			clear(n.Confirmation.Response)
		}
	}
	c.scoped = scopedNodesRuntime{}
}

func equalScopedConfirmation(a, b *scopedConfirmation) bool { return reflect.DeepEqual(a, b) }
