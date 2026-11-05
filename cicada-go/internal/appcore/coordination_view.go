package appcore

import (
	"slices"
	"strconv"
	"time"
)

func (c *nativeController) populateCoordination(view *Snapshot) {
	g := &c.coordination
	d := g.view
	d.Pending = c.hasCoordinationPending()
	d.AvailabilityKnown = g.discoveryTried
	d.RolesAvailable, d.LocksAvailable = g.rolesAvailable, g.locksAvailable
	d.Review = nil
	d.FreshUntil = c.coordinationObservationDeadline()
	view.Coordination = d
	if !c.ownerAccountReady() || c.appBindingHoldsBusiness() {
		return
	}
	ready := !c.storageFault && !c.profileRecoveryRequired && !c.nodePairTrustBusy() && !c.scopedBusy() && !c.hasNodePending() && !c.hasThreadGroupPending() && canBeginOperation(c.state.Pending) && c.state.Recovery == nil
	if d.Pending || g.review != nil {
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(kind ActionKind) bool {
			return nodeActionKind(kind) || threadGroupActionKind(kind) || pairActionKind(kind) || localCollaborationActionKind(kind) || ownerEndpointActionKind(kind)
		})
	}
	if d.Pending {
		if ready {
			view.AvailableActions = append(view.AvailableActions, ActionRecoverCoordination)
		}
		return
	}
	if r := g.review; r != nil && g.reviewOriginal != nil {
		d.Review = &CoordinationReview{GestureID: c.coordinationGesture(r), Change: r.Action, ExpiresAt: r.ExpiresAt, CanApply: ready && c.coordinationReviewCurrent()}
		if r.Prepared.Role != nil {
			d.Review.ThreadName = g.reviewOriginal.DisplayName
			d.Review.Classification = r.Prepared.Role.Classification
			v := r.Prepared.Role
			d.Review.Details = []CoordinationDetail{{"groups.network_id", v.NetworkID}, {"node.id", v.NodeID}, {"directory.endpoint_id", v.EndpointID}, {"coord.source", v.Source.RegistrationID}, {"coord.source_epoch", strconv.FormatUint(v.Source.SourceEpoch, 10)}, {"coord.class_revision", strconv.FormatUint(v.ExpectedClassificationRevision, 10)}, {"coord.relations_revision", strconv.FormatUint(v.ExpectedRelationsRevision, 10)}}
		}
		if r.Prepared.Policy != nil {
			d.Review.GroupName = g.reviewOriginal.DisplayName
			v := r.Prepared.Policy
			d.Review.Details = []CoordinationDetail{{"groups.network_id", v.NetworkID}, {"groups.group_id", r.TargetGroupID}, {"coord.version", strconv.FormatUint(v.ExpectedGroupVersion, 10)}, {"locks.version", strconv.FormatUint(v.ExpectedPolicyRevision, 10)}}
		}
		if r.Prepared.Clear != nil {
			d.Review.GroupName = g.reviewOriginal.DisplayName
			d.Review.HolderName = g.reviewOriginal.HolderName
			d.Review.Slot = int(r.Prepared.Clear.Slot)
			v := r.Prepared.Clear
			d.Review.Details = []CoordinationDetail{{"groups.network_id", v.Scope.NetworkID}, {"groups.group_id", v.Scope.GroupID}, {"directory.endpoint_id", v.ExpectedHolder.EndpointID}, {"coord.source", v.ExpectedHolder.Source.RegistrationID}, {"coord.source_epoch", strconv.FormatUint(v.ExpectedHolder.Source.SourceEpoch, 10)}, {"coord.version", strconv.FormatUint(v.ExpectedVersion, 10)}, {"coord.generation", strconv.FormatUint(v.Generation, 10)}}
		}
		view.Coordination = d
		if ready {
			view.AvailableActions = append(view.AvailableActions, ActionDismissCoordination)
			if d.Review.CanApply {
				view.AvailableActions = append(view.AvailableActions, ActionApplyCoordination)
			}
		}
		return
	}
	if !ready || !c.ownerOperationCanStart() || !view.ThreadGroups.Current {
		return
	}
	if !g.discoveryTried || g.rolesAvailable {
		view.AvailableActions = append(view.AvailableActions, ActionReadThreadCoordination)
	}
	if !g.discoveryTried || g.locksAvailable {
		view.AvailableActions = append(view.AvailableActions, ActionReadGroupCoordination)
	}
	if g.rolesAvailable || g.locksAvailable {
		view.AvailableActions = append(view.AvailableActions, ActionPrepareCoordination)
	}
	thread := view.ThreadGroups.Selected
	if thread == nil || c.threadGroups.selected == nil {
		return
	}
	thread.CanReadClassification = !g.discoveryTried || g.rolesAvailable
	thread.CoordinationGestureID = c.coordinationGesture(*c.threadGroups.selected)
	if read := c.currentCoordinationRead(thread.EndpointID, ""); read != nil {
		t := read.Threads[0]
		thread.Classification = &ThreadClassificationView{Current: true, State: t.State, Classification: t.Classification, ActiveGroups: t.ActiveGroupCount, GestureID: c.coordinationGesture(t), CanChange: g.rolesAvailable && t.EndpointID == thread.EndpointID && t.RegistrationDigest != "" && (t.State == "CURRENT" || t.State == "CLASSIFICATION_REQUIRED" || t.State == "GROUP_CONFLICT")}
		thread.Classification.FreshUntil = c.coordinationReadFreshUntil(read)
	}
	for i := range thread.Relations {
		relation := &thread.Relations[i]
		relation.CanReadCoordination = !g.discoveryTried || g.locksAvailable
		for _, raw := range c.threadGroups.selected.Relations {
			if raw.GroupID == relation.GroupID {
				relation.CoordinationGestureID = c.coordinationGesture(raw)
			}
		}
		read := c.currentCoordinationRead("", relation.GroupID)
		if read == nil {
			continue
		}
		board := &GroupLockBoardView{CanView: true, Current: true, ObservedAt: read.ObservedAt, GestureID: c.coordinationGesture(*read), PolicyState: "NOT_ENABLED", CanEnable: g.locksAvailable}
		board.FreshUntil = c.coordinationReadFreshUntil(read)
		if policy := read.GroupPolicy; policy != nil {
			board.Version, board.PolicyState = policy.Revision, policy.State
			board.CanEnable = g.locksAvailable && policy.State != "ENABLED"
			board.CanRevoke = g.locksAvailable && policy.State == "ENABLED"
		}
		if slots := read.GroupSlots; slots != nil {
			for i, slot := range slots.Slots {
				if i >= GroupProtocolLockSlots {
					break
				}
				row := GroupLockSlotView{Number: int(slot.Slot), Version: slot.Version, State: GroupLockState(slot.State), Purpose: slot.Note, ExpiresAt: slot.ExpiresAt, GestureID: c.coordinationGesture(slot)}
				row.Generation = slot.Generation
				if slot.HolderNameState == "VISIBLE" {
					row.HolderName = slot.HolderName
				}
				row.CanClear = g.locksAvailable && slot.State == "HELD" && slot.Holder != nil && c.cfg.Now().UTC().Before(parseExpiry(slot.ExpiresAt))
				board.Slots[i] = row
			}
		}
		projected := ProjectGroupLockBoard(*board)
		relation.Locks = &projected
	}
}

func expireCoordinationView(view *Snapshot, now time.Time) {
	d := &view.Coordination
	if !ThreadGroupsVisible(*view, now) {
		*d = CoordinationSnapshot{AvailabilityKnown: d.AvailabilityKnown, RolesAvailable: d.RolesAvailable, LocksAvailable: d.LocksAvailable, Pending: d.Pending}
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, coordinationActionKind)
		return
	}
	if d.Review != nil && !now.Before(parseExpiry(d.Review.ExpiresAt)) {
		d.Review.CanApply = false
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(k ActionKind) bool { return k == ActionApplyCoordination })
	}
	var earliest time.Time
	consider := func(stamp string, current bool) {
		t := parseExpiry(stamp)
		if current && !t.IsZero() && now.Before(t) && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	if t := view.ThreadGroups.Selected; t != nil {
		if r := t.Classification; r != nil {
			if d.Pending || r.FreshUntil != "" && !now.Before(parseExpiry(r.FreshUntil)) {
				r.Current, r.CanChange = false, false
			}
			consider(r.FreshUntil, r.Current)
		}
		for i := range t.Relations {
			if b := t.Relations[i].Locks; b != nil {
				if d.Pending || b.FreshUntil != "" && !now.Before(parseExpiry(b.FreshUntil)) {
					b.Current = false
					projected := ProjectGroupLockBoard(*b)
					t.Relations[i].Locks = &projected
					b = &projected
				}
				consider(b.FreshUntil, b.Current)
			}
		}
	}
	d.FreshUntil = ""
	if !earliest.IsZero() {
		d.FreshUntil = earliest.Format(time.RFC3339Nano)
	}
	if d.Pending {
		view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(k ActionKind) bool { return k == ActionPrepareCoordination })
	}
}
