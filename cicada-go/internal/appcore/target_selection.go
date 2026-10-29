package appcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	localTargetsFormat               = "cicada.app-local-targets.v1"
	maxLocalNodes                    = 8
	maxLocalNetworks                 = 16
	maxLocalTargetsBytes             = 32 << 10
	ActionSelectSavedNode ActionKind = "SELECT_SAVED_NODE"
)

// This is local navigation metadata inside the existing Node-state slot. It
// contains neither authority nor copies of grants, original packets or keys.
// The legacy confirmation remains in its original immutable namespace.
type localTargetDirectory struct {
	Format         string               `json:"format"`
	SelectedNodeID string               `json:"selected_node_id"`
	Nodes          []savedNodeReference `json:"nodes"`
	Networks       []SavedNetworkView   `json:"networks,omitempty"`
}

type savedNodeReference struct {
	ScopeVersion       int    `json:"scope_version,omitempty"`
	NodeID             string `json:"node_id"`
	Name               string `json:"name"`
	ConfirmationDigest string `json:"confirmation_digest"`
}

type SavedNodeView struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Selected  bool   `json:"selected"`
	CanSelect bool   `json:"can_select"`
}

// A saved label is only a historical reference. The existing authenticated
// prepare and Owner review must recheck the Network before any authorization.
type SavedNetworkView struct {
	NetworkID      string `json:"network_id"`
	Name           string `json:"name"`
	SourceNodeID   string `json:"source_node_id"`
	SourcePolicyID string `json:"source_policy_id"`
}

type TargetSelectionSnapshot struct {
	Adding                 bool               `json:"adding"`
	CanAdd                 bool               `json:"can_add"`
	SelectedNodeID         string             `json:"selected_node_id,omitempty"`
	GestureID              string             `json:"gesture_id,omitempty"`
	Locked                 bool               `json:"locked"`
	AdditionalNodesPending bool               `json:"additional_nodes_pending"`
	Nodes                  []SavedNodeView    `json:"nodes,omitempty"`
	Networks               []SavedNetworkView `json:"networks,omitempty"`
}

type NodeSelectionAction struct{ NodeID, GestureID string }

func localTargetText(s string, allowEmpty bool) bool {
	return (allowEmpty || s != "") && len(s) <= 256 && utf8.ValidString(s) && strings.TrimSpace(s) == s && strings.IndexFunc(s, unicode.IsControl) < 0
}

func validateLocalTargets(d *localTargetDirectory) error {
	if d == nil {
		return nil
	}
	if d.Format != localTargetsFormat || len(d.Nodes) == 0 || len(d.Nodes) > maxLocalNodes || len(d.Networks) > maxLocalNetworks {
		return appvault.ErrScopeMismatch
	}
	nodes, networks := map[string]bool{}, map[string]bool{}
	for _, n := range d.Nodes {
		digest, err := hex.DecodeString(n.ConfirmationDigest)
		pending := n.ScopeVersion == 2 && n.ConfirmationDigest == ""
		if n.ScopeVersion != 0 && n.ScopeVersion != 1 && n.ScopeVersion != 2 {
			return appvault.ErrScopeMismatch
		}
		if !localTargetText(n.NodeID, false) || !localTargetText(n.Name, true) || nodes[n.NodeID] || !pending && (err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != n.ConfirmationDigest) {
			return appvault.ErrScopeMismatch
		}
		nodes[n.NodeID] = true
	}
	if d.SelectedNodeID != "" && !nodes[d.SelectedNodeID] {
		return appvault.ErrScopeMismatch
	}
	for _, n := range d.Networks {
		if !localTargetText(n.NetworkID, false) || !localTargetText(n.Name, true) || !localTargetText(n.SourcePolicyID, false) || !nodes[n.SourceNodeID] || networks[n.NetworkID] {
			return appvault.ErrScopeMismatch
		}
		networks[n.NetworkID] = true
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > maxLocalTargetsBytes {
		return appvault.ErrInvalidVault
	}
	return nil
}

func (c *nativeController) targetSelectionLocked() bool {
	return c.storageFault || c.profileRecoveryRequired || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil || c.hasNodePending() || c.node.Proposal != nil || c.hasPairPending() || c.pairReview != nil || c.hasLocalDomainPending() || c.localDomain.state.View.State == wire.LocalDomainPrepared || c.hasThreadGroupPending() || c.threadGroups.review != nil || c.nodePairTrustBusy() || c.scopedBusy() || len(c.node.OwnerDirectoryUnknown) != 0
}

func (c *nativeController) validateLegacyTargetSelection() error {
	d := c.node.Targets
	if d == nil {
		return nil
	}
	if d.SelectedNodeID == "" {
		if c.nodeConfirmation == nil {
			return nil
		}
		return appvault.ErrScopeMismatch
	}
	for _, r := range d.Nodes {
		if r.NodeID == d.SelectedNodeID && r.ScopeVersion == 2 {
			n := c.scopedNode(r.NodeID)
			if n == nil || !n.CountersCommitted || n.Binding == nil || n.Trust == nil || scopedReference(n).ConfirmationDigest != r.ConfirmationDigest || r.ConfirmationDigest == "" {
				return appvault.ErrScopeMismatch
			}
			return nil
		}
	}
	if c.nodeConfirmation == nil || d.SelectedNodeID != c.nodeConfirmation.Binding.NodeID {
		return appvault.ErrScopeMismatch
	}
	digest := sha256.Sum256(c.nodeConfirmation.Operation.Response)
	for _, n := range d.Nodes {
		if n.NodeID == d.SelectedNodeID && n.ConfirmationDigest == hex.EncodeToString(digest[:]) {
			return nil
		}
	}
	return appvault.ErrScopeMismatch
}

func expireTargetSelectionView(view *Snapshot, now time.Time) {
	if view.Hub.Verified && view.Account.State == AccountStateOwnerReady && now.Before(parseExpiry(view.Account.SessionExpiresAt)) {
		return
	}
	for i := range view.Targets.Nodes {
		view.Targets.Nodes[i].CanSelect = false
	}
	view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(k ActionKind) bool { return k == ActionSelectSavedNode })
}

func (c *nativeController) localTargets() *localTargetDirectory {
	d := &localTargetDirectory{Format: localTargetsFormat}
	if old := c.node.Targets; old != nil {
		*d = *old
		d.Nodes = slices.Clone(old.Nodes)
		d.Networks = slices.Clone(old.Networks)
	}
	if c.nodeConfirmation != nil {
		b := c.nodeConfirmation.Binding
		digest := sha256.Sum256(c.nodeConfirmation.Operation.Response)
		n := savedNodeReference{NodeID: b.NodeID, Name: b.NodeName, ConfirmationDigest: hex.EncodeToString(digest[:])}
		i := slices.IndexFunc(d.Nodes, func(v savedNodeReference) bool { return v.NodeID == n.NodeID })
		if i >= 0 && d.Nodes[i].ScopeVersion != 2 {
			d.Nodes[i] = n
		} else if i < 0 && len(d.Nodes) < maxLocalNodes {
			d.Nodes = append(d.Nodes, n)
		}
		if d.SelectedNodeID == "" {
			d.SelectedNodeID = b.NodeID
		}
	}
	b := c.selectedNodeBinding()
	if p := c.localDomain.state.Description; b != nil && p != nil && len(p.PolicyProof) != 0 && p.State != "PREPARED" && p.Policy.HubID == c.connection.HubID && p.Policy.OwnerID == c.connection.OwnerID && p.Policy.Node.NodeID == b.NodeID {
		network := SavedNetworkView{NetworkID: p.Policy.NetworkID, Name: p.Policy.NetworkName, SourceNodeID: b.NodeID, SourcePolicyID: p.Policy.PolicyID}
		i := slices.IndexFunc(d.Networks, func(v SavedNetworkView) bool { return v.NetworkID == network.NetworkID })
		if i >= 0 {
			d.Networks[i] = network
		} else if len(d.Networks) < maxLocalNetworks {
			d.Networks = append(d.Networks, network)
		}
	}
	return d
}

func (c *nativeController) targetSelectionGesture() string {
	if c.session == nil || c.nodeConfirmation == nil && c.node.Targets == nil {
		return ""
	}
	node := ""
	if c.node.Targets != nil {
		node = c.node.Targets.SelectedNodeID
	} else if c.nodeConfirmation != nil {
		node = c.nodeConfirmation.Binding.NodeID
	}
	return localCollaborationReviewID(struct {
		Node    string
		Version uint64
		Session string
	}{node, c.nodeVer, sessionTokenDigest(c.session.SessionToken)})
}

func (c *nativeController) populateTargetSelection(view *Snapshot) {
	if c.vault == nil || c.nodeConfirmation == nil && c.node.Targets == nil {
		return
	}
	d := c.localTargets()
	if validateLocalTargets(d) != nil {
		return
	}
	v := TargetSelectionSnapshot{SelectedNodeID: d.SelectedNodeID, GestureID: c.targetSelectionGesture(), Locked: c.targetSelectionLocked(), AdditionalNodesPending: !c.scoped.available, Networks: slices.Clone(d.Networks), Adding: c.scoped.adding}
	v.CanAdd = !v.Locked && c.nodeAccountReady() && len(d.Nodes) < maxLocalNodes
	for _, n := range d.Nodes {
		// Other remembered labels cannot use the legacy device's authority.
		usable := c.nodeConfirmation != nil && n.ScopeVersion != 2 && n.NodeID == c.nodeConfirmation.Binding.NodeID
		if n.ScopeVersion == 2 {
			r := c.scopedNode(n.NodeID)
			usable = r != nil && r.CountersCommitted && r.Binding != nil && r.Trust != nil
		}
		v.Nodes = append(v.Nodes, SavedNodeView{NodeID: n.NodeID, Name: n.Name, Selected: n.NodeID == d.SelectedNodeID, CanSelect: !v.Locked && c.nodeAccountReady() && usable})
	}
	view.Targets = v
	if !v.Locked && c.nodeAccountReady() {
		view.AvailableActions = append(view.AvailableActions, ActionSelectSavedNode)
		if v.CanAdd {
			view.AvailableActions = append(view.AvailableActions, ActionBeginAddNode)
		}
	}
}

func (c *nativeController) selectSavedNode(input NodeSelectionAction) error {
	if c.targetSelectionLocked() || !c.nodeAccountReady() || input.GestureID == "" || input.GestureID != c.targetSelectionGesture() {
		return ErrInvalidAction
	}
	usable := c.nodeConfirmation != nil && input.NodeID == c.nodeConfirmation.Binding.NodeID
	if n := c.scopedNode(input.NodeID); n != nil && n.Binding != nil && n.Trust != nil && n.CountersCommitted {
		usable = true
	}
	if !usable {
		return ErrInvalidAction
	}
	next := c.node
	next.Targets = c.localTargets()
	next.Targets.SelectedNodeID = input.NodeID
	if err := validateLocalTargets(next.Targets); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := c.vault.CheckStateUpdates(map[string][]byte{nodeStateNamespace: raw}); err != nil {
		return err
	}
	if err := c.persistNodeRecord(nodeStateNamespace, &c.nodeVer, next); err != nil {
		return err
	}
	c.node = next
	c.scoped.adding = false
	c.invalidateSelectedNodeViews()
	c.publish()
	return nil
}
