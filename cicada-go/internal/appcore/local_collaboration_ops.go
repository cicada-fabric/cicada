package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) localCollaborationNodeID() string {
	if b := c.selectedNodeBinding(); b != nil {
		return b.NodeID
	}
	return ""
}

func (c *nativeController) localCollaborationActor(ctx context.Context) (e2ee.OwnerAppNodeScope, error) {
	if c.selectedScopedNode() != nil {
		return c.scopedOwnerActor(ctx)
	}
	if !c.nodeAccountReady() {
		return e2ee.OwnerAppNodeScope{}, ErrInvalidAction
	}
	if !c.nodeContextChecked || c.node.Context == nil || c.node.Context.Authority.Scope.AccountSessionExpiresAt != c.session.ExpiresAt {
		if !c.nodeAvailable {
			if err := c.discoverNodeAvailability(ctx); err != nil {
				return e2ee.OwnerAppNodeScope{}, err
			}
		}
		if err := c.refreshNodeContext(ctx); err != nil {
			return e2ee.OwnerAppNodeScope{}, err
		}
	}
	a := c.node.Context.Authority.Scope
	a.HeadVersion = 0
	if wire.ValidateAppNodeScope(a, c.hub) != nil || a.Origin != c.connection.Origin || a.AccountID != c.state.AccountID || a.OwnerID != c.state.OwnerID || a.DeviceID != c.state.DeviceID || a.AccountEpoch != c.session.AccountEpoch || a.DeviceEpoch != c.session.DeviceEpoch || a.AccountSessionExpiresAt != c.session.ExpiresAt || !reflect.DeepEqual(a.OwnerPublic, c.owner.Public()) || !reflect.DeepEqual(a.DevicePublic, c.device.Public()) {
		return a, wire.ErrInvalid
	}
	return a, nil
}

func (c *nativeController) localCollaborationReady(ctx context.Context) error {
	if err := c.ensureLocalDomainLoaded(); err != nil {
		return err
	}
	if c.scopedBusy() || c.hasLocalDomainPending() || c.hasThreadGroupPending() || c.hasPairPending() || c.hasNodePending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil || !c.nodeAccountReady() || c.localCollaborationNodeID() == "" {
		return ErrInvalidAction
	}
	if !c.localDomain.discoveryTried {
		if err := c.discoverLocalCollaboration(ctx); err != nil {
			c.localDomain.errorCode = "APP_LOCAL_COLLABORATION_UNAVAILABLE"
			c.publish()
			return err
		}
	}
	if !c.localDomain.available {
		return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_UNAVAILABLE", ErrInvalidAction)
	}
	return nil
}

func (c *nativeController) initializeLocalCollaboration(ctx context.Context) {
	if c.scopedBusy() {
		return
	}
	if c.hasThreadGroupPending() {
		return
	}
	if c.nodePairTrustBusy() {
		return
	}
	if !c.nodeAccountReady() || c.localCollaborationNodeID() == "" || c.hasPairPending() || c.hasNodePending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return
	}
	if c.ensureLocalDomainLoaded() != nil || c.hasLocalDomainPending() {
		c.publish()
		return
	}
	target := c.localCollaborationNodeID() + "\x00" + c.session.ExpiresAt
	if c.localDomain.checkedTarget == target {
		return
	}
	c.localDomain.checkedTarget = target
	_ = c.refreshLocalCollaboration(ctx)
}

func localCollaborationReviewID(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (c *nativeController) prepareLocalCollaboration(ctx context.Context, input LocalCollaborationAction) error {
	if err := c.localCollaborationReady(ctx); err != nil {
		return err
	}
	view := c.localDomain.state.View
	if !view.Current || view.NodeID != c.localCollaborationNodeID() || (view.State != "UNCONFIGURED" && view.State != wire.LocalDomainExpired && view.State != wire.LocalDomainRevoked) || input.ExpiresInHours > 365*24 {
		return ErrInvalidAction
	}
	if input.NetworkID != "" {
		// A saved label only offers an exact lookup target. The authenticated
		// Hub preview below must still recheck its live ownership and state.
		known := false
		for _, n := range c.localTargets().Networks {
			known = known || n.NetworkID == input.NetworkID
		}
		if !known || input.NewNetworkName != "" {
			return ErrInvalidAction
		}
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	end := ""
	if input.ExpiresInHours != 0 {
		end = c.cfg.Now().UTC().Add(time.Duration(input.ExpiresInHours) * time.Hour).Format(time.RFC3339Nano)
	}
	target := e2ee.LocalDomainTarget{Node: *c.selectedNodeBinding(), NetworkID: input.NetworkID, NewNetworkName: input.NewNetworkName, GroupName: input.GroupName, ExpiresAt: end}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewLocalDomainPrepare(c.nodeSession(), scope, target, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	_, err = c.sendNewLocalDomain(ctx, c.localCollaborationNodeID(), request)
	return err
}

func (c *nativeController) activateLocalCollaboration(ctx context.Context, input LocalCollaborationAction) error {
	if err := c.localCollaborationReady(ctx); err != nil {
		return err
	}
	view := c.localDomain.state.View
	if !input.ConfirmActivation || input.ReviewID == "" || input.ReviewID != view.ReviewID || !view.Current || c.localDomain.reviewOriginal == nil || c.localDomain.reviewResponse == nil {
		return ErrInvalidAction
	}
	opened, err := c.openLocalDomainReceipt(c.localDomain.reviewOriginal, c.localDomain.reviewResponse.Packet, nil)
	if err != nil || opened.Challenge == nil {
		return wire.ErrInvalid
	}
	decoded, err := c.localDomainDTO(c.localDomain.reviewOriginal, nil)
	if err != nil {
		return err
	}
	prepare, ok := decoded.(wire.LocalDomainPrepare)
	if !ok {
		return wire.ErrInvalid
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewLocalDomainActivate(c.nodeSession(), scope, prepare, c.localDomain.reviewOriginal.Packet, *opened.Challenge, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	if _, err := c.sendNewLocalDomain(ctx, c.localCollaborationNodeID(), request); err != nil {
		return err
	}
	return c.refreshLocalCollaboration(ctx)
}

func (c *nativeController) revokeLocalCollaboration(ctx context.Context, input LocalCollaborationAction) error {
	if err := c.localCollaborationReady(ctx); err != nil {
		return err
	}
	view := c.localDomain.state.View
	if !input.ConfirmRevoke || input.ReviewID == "" || input.ReviewID != view.StateReviewID || !view.Current || view.State != wire.LocalDomainActive || c.localDomain.state.Description == nil {
		return ErrInvalidAction
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	request, err := wire.NewLocalDomainRevoke(c.nodeSession(), scope, *c.localDomain.state.Description, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	if _, err := c.sendNewLocalDomain(ctx, c.localCollaborationNodeID(), request); err != nil {
		return err
	}
	return c.refreshLocalCollaboration(ctx)
}

func (c *nativeController) refreshLocalCollaboration(ctx context.Context) error {
	if err := c.localCollaborationReady(ctx); err != nil {
		return err
	}
	node := c.localCollaborationNodeID()
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	c.localDomain.state.View.Current = false
	prior := ""
	if c.localDomain.state.Description != nil {
		prior = c.localDomain.state.Description.Policy.PolicyID
	}
	var nonterminal, priorDescription, only *wire.LocalDomainDescription
	rows := 0
	cursor := ""
	observed := ""
	for page := 0; page < 128; page++ {
		request, err := wire.NewLocalDomainStatusForNode(c.nodeSession(), scope, node, cursor, owner, c.cfg.Now().UTC())
		if err != nil {
			return err
		}
		receipt, err := c.sendNewLocalDomain(ctx, node, request)
		if err != nil {
			return err
		}
		if receipt.Result == nil || receipt.Result.State != wire.AppNodeCompleted {
			return wire.ErrInvalid
		}
		result := receipt.Result
		for _, item := range result.Policies {
			item := item
			rows++
			only = &item
			if item.Policy.PolicyID == prior {
				priorDescription = &item
			}
			if item.State == wire.LocalDomainActive || item.State == wire.LocalDomainPrepared {
				if nonterminal != nil {
					return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_AMBIGUOUS", wire.ErrInvalid)
				}
				nonterminal = &item
			}
		}
		observed = result.ObservedAt
		if result.NextCursor == "" {
			selected := nonterminal
			if selected == nil {
				selected = priorDescription
			}
			if selected == nil && rows == 1 {
				selected = only
			}
			c.setLocalCollaborationDescription(node, selected, observed, true)
			if err := c.restoreLocalCollaborationReview(selected); err != nil {
				return c.failLocalDomainStorage(err)
			}
			if err := c.persistLocalDomainView(); err != nil {
				return err
			}
			c.localDomain.errorCode = ""
			c.localDomain.checkedTarget = node + "\x00" + c.session.ExpiresAt
			c.publish()
			return nil
		}
		if result.NextCursor <= cursor {
			return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_READ_INVALID", wire.ErrInvalid)
		}
		cursor = result.NextCursor
	}
	return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_READ_LIMIT", errors.New("local collaboration status page limit reached"))
}

func (c *nativeController) restoreLocalCollaborationReview(description *wire.LocalDomainDescription) error {
	if description == nil || description.State != wire.LocalDomainPrepared || c.localDomain.reviewOriginal == nil || c.localDomain.reviewResponse == nil {
		return nil
	}
	record := c.localDomain.reviewOriginal
	opened, err := c.openLocalDomainReceipt(record, c.localDomain.reviewResponse.Packet, nil)
	if err != nil {
		return err
	}
	if opened.Challenge == nil || opened.Challenge.Policy.PolicyID != description.Policy.PolicyID {
		return nil
	}
	if !reflect.DeepEqual(opened.Challenge.Policy, description.Policy) {
		return wire.ErrInvalid
	}
	body, err := c.localDomainDTO(record, nil)
	if err != nil {
		return err
	}
	prepare, ok := body.(wire.LocalDomainPrepare)
	if !ok {
		return wire.ErrInvalid
	}
	claims, err := e2ee.VerifyOwnerLocalDomainRequest(c.owner.Public(), prepare.OwnerProof, e2ee.OwnerLocalDomainPreparePurpose, time.Time{})
	if err != nil {
		return err
	}
	if c.session == nil {
		return nil
	}
	var actor e2ee.OwnerAppNodeScope
	if n := c.selectedScopedNode(); n != nil {
		if n.Context == nil || c.scoped.fresh[n.NodeID] != sessionTokenDigest(c.session.SessionToken) || !c.scopedScopeMatches(n.Context.Authority.Scope, true) {
			return nil
		}
		actor, err = wire.AppNodeScopedOwnerActor(n.Context.Authority.Scope, c.hub)
		if err != nil {
			return err
		}
	} else {
		if c.node.Context == nil {
			return nil
		}
		actor = c.node.Context.Authority.Scope
		actor.HeadVersion = 0
	}
	if !reflect.DeepEqual(actor, claims.Scope) {
		return nil
	}
	view := &c.localDomain.state.View
	view.ReviewID, view.ReviewExpiresAt = localCollaborationReviewID(opened.Challenge), opened.Challenge.ProofExpiresAt
	view.Current = view.Current && wire.ValidateLocalDomainChallenge(prepare, record.Packet, *opened.Challenge, c.hub, c.cfg.Now().UTC()) == nil
	return nil
}

func (c *nativeController) setLocalCollaborationDescription(node string, description *wire.LocalDomainDescription, observed string, current bool) {
	state := &c.localDomain.state
	state.Format, state.Vault, state.DeviceKeyID, state.OwnerKeyID, state.NodeID = "cicada.app-local-domain.state.v1", cardScope(c.connection), c.state.DeviceKeyID, c.state.OwnerKeyID, node
	state.Description = description
	state.View = LocalCollaborationSnapshot{AvailabilityKnown: c.localDomain.discoveryTried, Available: c.localDomain.available, Current: current, NodeID: node, State: "UNCONFIGURED", ObservedAt: observed}
	c.snapshotMu.RLock()
	if c.snapshot.Node.Binding != nil && c.snapshot.Node.Binding.NodeID == node {
		state.View.NodeName = c.snapshot.Node.Binding.Name
	}
	c.snapshotMu.RUnlock()
	if description == nil {
		return
	}
	p := description.Policy
	state.View.State, state.View.PolicyID, state.View.PolicyEpoch, state.View.Revision = description.State, p.PolicyID, p.Epoch, description.Revision
	state.View.LocalUserScope, state.View.NetworkID, state.View.NetworkName = p.LocalUserScope, p.NetworkID, p.NetworkName
	state.View.GroupID, state.View.GroupName, state.View.ExpiresAt = p.GroupID, p.GroupName, p.ExpiresAt
	if current {
		state.View.StateReviewID = localCollaborationReviewID(description)
	}
}

func (c *nativeController) failLocalCollaboration(code string, err error) error {
	c.localDomain.errorCode = code
	c.localDomain.state.View.Current = false
	c.publish()
	return err
}

func (c *nativeController) populateLocalCollaboration(view *Snapshot) {
	domain := c.localDomain.state.View
	domain.AvailabilityKnown, domain.Available, domain.Pending, domain.ErrorCode = c.localDomain.discoveryTried, c.localDomain.available, c.hasLocalDomainPending(), c.localDomain.errorCode
	if node := c.localCollaborationNodeID(); node != "" && domain.NodeID != "" && domain.NodeID != node && !domain.Pending {
		domain = LocalCollaborationSnapshot{AvailabilityKnown: c.localDomain.discoveryTried, Available: c.localDomain.available}
	}
	view.LocalCollaboration = domain
	if c.storageFault || c.profileRecoveryRequired || !c.connected || c.vault == nil || c.device == nil || c.owner == nil {
		return
	}
	if domain.Pending {
		view.AvailableActions = append(view.AvailableActions, ActionRecoverLocalCollaboration)
		return
	}
	if !c.nodeAccountReady() || c.localCollaborationNodeID() == "" || c.hasThreadGroupPending() || c.hasNodePending() || c.hasPairPending() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return
	}
	view.AvailableActions = append(view.AvailableActions, ActionRefreshLocalCollaboration)
	if !domain.Available || !domain.Current {
		return
	}
	switch domain.State {
	case "UNCONFIGURED", wire.LocalDomainExpired, wire.LocalDomainRevoked:
		view.AvailableActions = append(view.AvailableActions, ActionPrepareLocalCollaboration)
	case wire.LocalDomainPrepared:
		if c.localDomain.reviewOriginal != nil && c.localDomain.reviewResponse != nil && c.cfg.Now().UTC().Before(parseExpiry(domain.ReviewExpiresAt)) {
			view.AvailableActions = append(view.AvailableActions, ActionActivateLocalCollaboration)
		}
	case wire.LocalDomainActive:
		view.AvailableActions = append(view.AvailableActions, ActionRevokeLocalCollaboration)
	}
}

func (c *nativeController) beginLocalDomainOriginal(record *localDomainRecord) error {
	if c.hasLocalDomainPending() {
		return ErrInvalidAction
	}
	if err := c.validateLocalDomainRequest(record, nil); err != nil {
		return err
	}
	for _, index := range []int{localDomainResponse, localDomainRecovery, localDomainRecoveryResponse} {
		if err := c.persistLocalDomain(index, nil); err != nil {
			return err
		}
	}
	if err := c.persistLocalDomain(localDomainOriginal, record); err != nil {
		return err
	}
	for _, old := range []*localDomainRecord{c.localDomain.original, c.localDomain.response, c.localDomain.recovery, c.localDomain.recoveryResponse} {
		if old != nil {
			clear(old.Packet)
			clear(old.DTO)
		}
	}
	c.localDomain.original, c.localDomain.response, c.localDomain.recovery, c.localDomain.recoveryResponse = record, nil, nil, nil
	return nil
}

func (c *nativeController) sendNewLocalDomain(ctx context.Context, node string, body any) (localDomainReceipt, error) {
	var empty localDomainReceipt
	record, err := c.newLocalDomainRequest(node, body)
	if err != nil {
		return empty, err
	}
	if err := c.beginLocalDomainOriginal(record); err != nil {
		clear(record.Packet)
		clear(record.DTO)
		return empty, err
	}
	c.publish()
	raw, err := c.postLocalDomainPacket(ctx, record)
	if err != nil {
		return empty, c.failLocalCollaboration("APP_LOCAL_COLLABORATION_UNKNOWN", err)
	}
	defer clear(raw)
	receipt, err := c.openLocalDomainReceipt(record, raw, nil)
	if err != nil {
		return empty, c.failLocalCollaboration("APP_LOCAL_COLLABORATION_RESPONSE_UNCONFIRMED", errLocalDomainUnconfirmed)
	}
	response, err := c.saveLocalDomainResponse(localDomainResponse, record, raw)
	if err != nil {
		return empty, err
	}
	c.localDomain.response = response
	if err := c.applyLocalDomainReceipt(record, receipt); err != nil {
		return receipt, err
	}
	copy := *record
	copy.Applied = true
	if err := c.persistLocalDomain(localDomainOriginal, &copy); err != nil {
		return receipt, err
	}
	c.localDomain.original = &copy
	c.publish()
	if receipt.Result != nil && receipt.Result.State != wire.AppNodeCompleted {
		return receipt, c.failLocalCollaboration("APP_LOCAL_COLLABORATION_REFUSED", ErrInvalidAction)
	}
	return receipt, nil
}

func (c *nativeController) applyLocalDomainReceipt(record *localDomainRecord, receipt localDomainReceipt) error {
	if receipt.Challenge != nil {
		body, err := c.localDomainDTO(record, nil)
		if err != nil {
			return err
		}
		prepare, ok := body.(wire.LocalDomainPrepare)
		if !ok {
			return wire.ErrInvalid
		}
		challenge := receipt.Challenge
		c.setLocalCollaborationDescription(record.NodeID, nil, challenge.ObservedAt, false)
		view := &c.localDomain.state.View
		p := challenge.Policy
		view.State, view.PolicyID, view.PolicyEpoch, view.Revision = wire.LocalDomainPrepared, p.PolicyID, p.Epoch, challenge.Revision
		view.LocalUserScope, view.NetworkID, view.NetworkName, view.GroupID, view.GroupName, view.ExpiresAt = p.LocalUserScope, p.NetworkID, p.NetworkName, p.GroupID, p.GroupName, p.ExpiresAt
		view.ReviewID, view.ReviewExpiresAt = localCollaborationReviewID(challenge), challenge.ProofExpiresAt
		view.Current = c.nodeAccountReady() && c.localCollaborationNodeID() == record.NodeID && wire.ValidateLocalDomainChallenge(prepare, record.Packet, *challenge, c.hub, c.cfg.Now().UTC()) == nil
		if c.localDomain.response == nil {
			return wire.ErrInvalid
		}
		r, err := cloneLocalDomainRecord(record)
		if err != nil {
			return err
		}
		response, err := cloneLocalDomainRecord(c.localDomain.response)
		if err != nil {
			return err
		}
		c.localDomain.reviewOriginal, c.localDomain.reviewResponse = r, response
		return c.persistLocalDomainView()
	}
	if receipt.Result == nil {
		return wire.ErrInvalid
	}
	if receipt.Result.Description != nil {
		c.setLocalCollaborationDescription(record.NodeID, receipt.Result.Description, receipt.Result.ObservedAt, false)
		c.localDomain.reviewOriginal, c.localDomain.reviewResponse = nil, nil
		return c.persistLocalDomainView()
	}
	return nil
}
