package appcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) coordinationGesture(value any) string {
	if !c.ownerAccountReady() {
		return ""
	}
	node, network := c.threadGroupScope()
	if network == "" {
		return ""
	}
	raw, err := json.Marshal(struct {
		Hub, Owner, Device, Node, Network, Session string
		AccountEpoch, DeviceEpoch                  uint64
		Value                                      any
	}{c.hub.HubID, c.state.OwnerID, c.state.DeviceID, node, network, sessionTokenDigest(c.session.SessionToken), c.session.AccountEpoch, c.session.DeviceEpoch, value})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cicada/app/coordination/gesture/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func (c *nativeController) coordinationReady(ctx context.Context, locks bool) error {
	if err := c.ensureCoordinationLoaded(); err != nil {
		return c.failStorage("APP_COORDINATION_STORAGE_FAILED", err)
	}
	if c.hasCoordinationPending() || !c.ownerOperationCanStart() || c.nodePairTrustBusy() {
		return ErrInvalidAction
	}
	if _, network := c.threadGroupScope(); network == "" {
		return ErrInvalidAction
	}
	if !c.coordination.discoveryTried {
		if err := c.discoverCoordination(ctx); err != nil {
			return c.failCoordination("UNSUPPORTED_PROFILE", err)
		}
	}
	if locks && !c.coordination.locksAvailable || !locks && !c.coordination.rolesAvailable {
		return c.failCoordination("UNSUPPORTED_PROFILE", ErrInvalidAction)
	}
	return nil
}

func (c *nativeController) currentCoordinationRead(endpoint, group string) *wire.ThreadCollaborationOwnerReadResult {
	if !c.ownerAccountReady() {
		return nil
	}
	node, network := c.threadGroupScope()
	for i := len(c.coordination.observations) - 1; i >= 0; i-- {
		o := &c.coordination.observations[i]
		if o.SessionDigest != sessionTokenDigest(c.session.SessionToken) || !c.cfg.Now().UTC().Before(parseExpiry(o.FreshUntil)) || o.Read.NetworkID != network || o.Read.HubID != c.hub.HubID {
			continue
		}
		if endpoint != "" && len(o.Read.Threads) == 1 && o.Read.View == "THREAD_SCOPE" && o.TargetEndpoint == endpoint && o.Read.Threads[0].NodeID == node {
			return &o.Read
		}
		if group != "" && o.Read.Group != nil && o.Read.Group.GroupID == group && o.Read.View == "GROUP_LOCKS" {
			return &o.Read
		}
	}
	return nil
}

func (c *nativeController) coordinationReadFreshUntil(read *wire.ThreadCollaborationOwnerReadResult) string {
	for i := range c.coordination.observations {
		if &c.coordination.observations[i].Read == read {
			return c.coordination.observations[i].FreshUntil
		}
	}
	return ""
}

func (c *nativeController) readCoordination(ctx context.Context, kind ActionKind, input CoordinationAction) error {
	locks := kind == ActionReadGroupCoordination
	if err := c.coordinationReady(ctx, locks); err != nil {
		return err
	}
	if c.coordination.review != nil || !c.Snapshot().ThreadGroups.Current {
		return ErrInvalidAction
	}
	node, network := c.threadGroupScope()
	body := wire.ThreadCollaborationOwnerReadBody{NetworkID: network}
	thread := c.threadGroups.selected
	if thread == nil {
		return ErrInvalidAction
	}
	if locks {
		found := false
		for _, relation := range thread.Relations {
			if relation.GroupID == input.GroupID && input.GestureID == c.coordinationGesture(relation) {
				found = true
			}
		}
		if !found {
			return ErrInvalidAction
		}
		body.View, body.GroupID = "GROUP_LOCKS", input.GroupID
	} else {
		if input.EndpointID != thread.EndpointID || input.GestureID != c.coordinationGesture(*thread) {
			return ErrInvalidAction
		}
		body.View, body.NodeID, body.EndpointID = "THREAD_SCOPE", node, thread.EndpointID
	}
	scope, err := c.localCollaborationActor(ctx)
	if err != nil {
		return err
	}
	owner, err := c.owner.E2EE()
	if err != nil {
		return err
	}
	q, err := wire.NewThreadCollaborationOwnerRead(c.nodeSession(), scope, body, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendCoordination(ctx, q, nil)
}

func (c *nativeController) prepareCoordination(ctx context.Context, input CoordinationAction) error {
	if err := c.coordinationReady(ctx, input.Change != wire.ThreadCollaborationSetClassification); err != nil {
		return err
	}
	if c.coordination.review != nil || !c.Snapshot().ThreadGroups.Current {
		return ErrInvalidAction
	}
	node, network := c.threadGroupScope()
	body := wire.ThreadCollaborationOwnerPrepareBody{Action: input.Change}
	switch input.Change {
	case wire.ThreadCollaborationSetClassification:
		read := c.currentCoordinationRead(input.EndpointID, "")
		if read == nil || len(read.Threads) != 1 {
			return ErrInvalidAction
		}
		t := read.Threads[0]
		if input.GestureID != c.coordinationGesture(t) || t.NodeID != node || t.NetworkID != network || t.RegistrationDigest == "" || t.State == "NETWORK_CONFLICT" || t.State == "UNRESOLVED" || t.State == "RESERVED" || input.Classification == wire.ThreadClassificationWorker && t.ActiveGroupCount > 1 {
			return ErrInvalidAction
		}
		body.Role = &wire.ThreadRoleChange{NetworkID: network, NodeID: node, EndpointID: t.EndpointID, Source: t.Source, Classification: input.Classification, ExpectedClassificationRevision: t.ClassificationRevision, ExpectedRelationsRevision: t.RelationsRevision, RegistrationDigest: t.RegistrationDigest}
	case wire.ThreadCollaborationCreateGroupWithPolicy:
		if input.GestureID != c.threadGroupGesture("read") || !c.Snapshot().ThreadGroups.CanCreate {
			return ErrInvalidAction
		}
		body.Policy = &wire.GroupPolicyChange{NetworkID: network, Name: input.Name, SlotCount: wire.GroupLockSlotCount, Rights: wire.GroupCoordinationRights()}
	case wire.ThreadCollaborationEnableGroupPolicy, wire.ThreadCollaborationRevokeGroupPolicy:
		read := c.currentCoordinationRead("", input.GroupID)
		if read == nil || read.Group == nil || input.GestureID != c.coordinationGesture(*read) {
			return ErrInvalidAction
		}
		revision := uint64(0)
		if read.GroupPolicy != nil {
			revision = read.GroupPolicy.Revision
		}
		if input.Change == wire.ThreadCollaborationEnableGroupPolicy && read.GroupPolicy != nil && read.GroupPolicy.State == "ENABLED" || input.Change == wire.ThreadCollaborationRevokeGroupPolicy && (read.GroupPolicy == nil || read.GroupPolicy.State != "ENABLED") {
			return ErrInvalidAction
		}
		body.Policy = &wire.GroupPolicyChange{NetworkID: network, GroupID: read.Group.GroupID, ExpectedGroupVersion: read.Group.GroupVersion, ExpectedPolicyRevision: revision, SlotCount: wire.GroupLockSlotCount, Rights: wire.GroupCoordinationRights()}
	case wire.ThreadCollaborationClearOneSlot:
		read := c.currentCoordinationRead("", input.GroupID)
		if read == nil || read.GroupSlots == nil || read.GroupPolicy == nil || input.Slot < 1 || input.Slot > wire.GroupLockSlotCount {
			return ErrInvalidAction
		}
		slot := read.GroupSlots.Slots[input.Slot-1]
		if slot.State != "HELD" || slot.Holder == nil || !c.cfg.Now().UTC().Before(parseExpiry(slot.ExpiresAt)) || input.GestureID != c.coordinationGesture(slot) {
			return ErrInvalidAction
		}
		body.Clear = &wire.GroupLockOwnerClear{Scope: read.GroupSlots.Scope, Slot: slot.Slot, ExpectedVersion: slot.Version, Generation: slot.Generation, ExpectedHolder: *slot.Holder}
	default:
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
	q, err := wire.NewThreadCollaborationOwnerPrepare(c.nodeSession(), scope, body, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendCoordination(ctx, q, nil)
}

func (c *nativeController) coordinationReviewCurrent() bool {
	g := &c.coordination
	if g.review == nil || g.reviewOriginal == nil || !c.ownerAccountReady() || c.hasCoordinationPending() {
		return false
	}
	request, err := c.coordinationDTO(g.reviewOriginal)
	q, ok := request.(wire.ThreadCollaborationOwnerPrepareRequest)
	return err == nil && ok && reflect.DeepEqual(q.SessionToken, c.session.SessionToken) && wire.ValidateThreadCollaborationOwnerReview(q, g.reviewOriginal.Packet, *g.review, c.hub, c.cfg.Now().UTC()) == nil
}

func (c *nativeController) applyCoordination(ctx context.Context, input CoordinationAction) error {
	if !input.Confirm || !c.coordinationReviewCurrent() || input.GestureID != c.coordinationGesture(c.coordination.review) {
		return ErrInvalidAction
	}
	if err := c.coordinationReady(ctx, c.coordination.review.Action != wire.ThreadCollaborationSetClassification); err != nil {
		return err
	}
	q, err := c.coordinationDTO(c.coordination.reviewOriginal)
	if err != nil {
		return err
	}
	prepare, ok := q.(wire.ThreadCollaborationOwnerPrepareRequest)
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
	request, err := wire.NewThreadCollaborationOwnerApply(c.nodeSession(), scope, prepare, c.coordination.reviewOriginal.Packet, *c.coordination.review, owner, c.cfg.Now().UTC())
	if err != nil {
		return err
	}
	return c.sendCoordination(ctx, request, c.coordination.review)
}

func (c *nativeController) dismissCoordination(input CoordinationAction) error {
	if c.hasCoordinationPending() || c.coordination.review == nil || input.GestureID != c.coordinationGesture(c.coordination.review) {
		return ErrInvalidAction
	}
	if err := c.dismissCoordinationReview(); err != nil {
		return err
	}
	c.publish()
	return nil
}

func (c *nativeController) coordinationReadCurrent(observation coordinationObservation) bool {
	_, network := c.threadGroupScope()
	return c.ownerAccountReady() && observation.Read.NetworkID == network && observation.Read.HubID == c.hub.HubID && observation.SessionDigest == sessionTokenDigest(c.session.SessionToken) && c.cfg.Now().UTC().Before(parseExpiry(observation.FreshUntil))
}

func (c *nativeController) coordinationObservationDeadline() string {
	var end time.Time
	for _, o := range c.coordination.observations {
		if c.coordinationReadCurrent(o) {
			t := parseExpiry(o.FreshUntil)
			if end.IsZero() || t.Before(end) {
				end = t
			}
		}
	}
	if end.IsZero() {
		return ""
	}
	return end.Format(time.RFC3339Nano)
}
