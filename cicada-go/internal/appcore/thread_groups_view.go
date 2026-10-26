package appcore

import (
	"slices"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) applyThreadGroupReceipt(record *threadGroupRecord, result *wire.OwnerEndpointGroupsResult, fresh bool) error {
	g := &c.threadGroups
	g.view.ErrorCode = result.ErrorCode
	if result.ErrorCode != "" {
		g.view.Current = false
		if record.Route.Operation == wire.OperationOwnerEndpointGroupsApply {
			if err := c.persistThreadGroupReview(nil, nil); err != nil {
				return err
			}
			g.review, g.view.Review = nil, nil
		}
		return nil
	}
	request, err := c.threadGroupDTO(record, nil)
	if err != nil {
		return err
	}
	switch q := request.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		// Recovering an old read can settle its request, but only a fresh
		// request under the current login may populate actionable cards.
		if !fresh || !c.threadGroupRequestCurrent(record) {
			g.view.Current = false
			return nil
		}
		qctx, proof := threadGroupRequestParts(request)
		claims, err := e2ee.VerifyOwnerEndpointGroupsRequest(c.owner.Public(), proof, wire.OwnerEndpointGroupsOwnerPurpose(record.Route.Operation), time.Time{})
		captured := parseExpiry(result.CapturedAt)
		if err != nil || captured.Before(parseExpiry(qctx.IssuedAt)) || captured.After(c.cfg.Now().UTC().Add(30*time.Second)) {
			return wire.ErrInvalid
		}
		g.view.Current, g.view.CapturedAt, g.view.FreshUntil, g.view.Outcome = true, result.CapturedAt, claims.ExpiresAt, ""
		g.view.NodeID, g.view.NetworkID = record.NodeID, record.NetworkID
		g.viewSessionDigest = sessionTokenDigest(c.session.SessionToken)
		g.view.CanCreate = result.ScopeActions != nil && slices.Contains(result.ScopeActions.AllowedActions, wire.OwnerEndpointGroupsCreateGroup)
		if result.ScopeActions != nil {
			g.view.UnavailableReason = result.ScopeActions.UnavailableReason
		}
		switch q.Body.View {
		case "THREADS":
			if q.Body.Cursor == "" {
				g.threads = nil
				g.selected, g.selectedRelations, g.candidates = nil, nil, nil
				g.view.Selected, g.view.Candidates, g.view.CandidatesLoaded = nil, nil, false
			}
			g.threads = append(g.threads, result.Threads...)
			g.view.ThreadsNextCursor = result.NextCursor
		case "RELATIONS":
			if record.Thread == nil || result.RelationPage == nil {
				return wire.ErrInvalid
			}
			if q.Body.Cursor == "" {
				thread := *record.Thread
				g.selected = &thread
				g.selectedRelations, g.candidates = nil, nil
				g.view.CandidatesLoaded, g.view.CandidatesCursor = false, ""
				g.listingRevision = result.RelationPage.RelationsRevision
			} else if g.selected == nil || g.selected.EndpointID != q.Body.EndpointID || g.listingRevision != result.RelationPage.RelationsRevision {
				return wire.ErrInvalid
			}
			g.selectedRelations = append(g.selectedRelations, result.Relations...)
			g.selected.Relations = slices.Clone(g.selectedRelations)
			g.selected.RelationsRevision = result.RelationPage.RelationsRevision
			g.selected.RelationsComplete = result.RelationPage.Complete
			g.selected.RelationsNextCursor = result.RelationPage.NextCursor
		case "CANDIDATE_GROUPS":
			if g.selected == nil || g.selected.EndpointID != q.Body.EndpointID {
				return wire.ErrInvalid
			}
			if q.Body.Cursor == "" {
				g.candidates = nil
			}
			g.candidates = append(g.candidates, result.Groups...)
			g.view.CandidatesLoaded, g.view.CandidatesCursor = true, result.NextCursor
		}
	case wire.OwnerEndpointGroupsPrepareRequest:
		if result.Review == nil || c.threadGroups.response == nil {
			return wire.ErrInvalid
		}
		if !threadGroupReviewCASMatches(record, *result.Review) {
			// An authenticated zero-right prepare is known, while the card
			// the user selected is stale. Do not turn that benign race into
			// an unrecoverable unknown mutation or sign the changed review.
			g.view.Current, g.view.ErrorCode = false, "CAS_CONFLICT"
			return nil
		}
		if err := c.persistThreadGroupReview(record, c.threadGroups.response); err != nil {
			return err
		}
		g.review = result.Review
	case wire.OwnerEndpointGroupsApplyRequest:
		// The immutable apply result never replaces current membership state.
		g.view.Current = false
		if result.Operation != nil && result.Operation.State == "COMPLETED" {
			switch result.Operation.Action {
			case wire.OwnerEndpointGroupsCreateGroup:
				g.view.Outcome = "GROUP_CREATED"
			case wire.OwnerEndpointGroupsAddEndpoint:
				g.view.Outcome = "ADD_SUBMITTED"
			case wire.OwnerEndpointGroupsRemoveEndpoint:
				g.view.Outcome = "REMOVED"
			}
		}
		if err := c.persistThreadGroupReview(nil, nil); err != nil {
			return err
		}
		g.review, g.view.Review = nil, nil
	}
	return nil
}

func (c *nativeController) groupRelationView(r wire.OwnerEndpointGroupsRelationCard) ThreadGroupRelation {
	v := ThreadGroupRelation{GroupID: r.GroupID, Name: r.GroupName, State: r.State, KeyState: r.KeyState, ExpiresAt: r.ExpiresAt,
		OwnerMode: r.OwnerControl.Mode, DenyReason: r.OwnerControl.DenyReason, CanRemove: slices.Contains(r.AllowedActions, wire.OwnerEndpointGroupsRemoveEndpoint),
		UnavailableReason: r.UnavailableReason, GestureID: c.threadGroupGesture(r)}
	if r.State == "ACTIVE" && r.ExpiresAt != "" && !c.cfg.Now().UTC().Before(parseExpiry(r.ExpiresAt)) {
		v.State, v.KeyState = "EXPIRED", "EXPIRED"
	}
	for _, source := range r.Contributions {
		v.Contributions = append(v.Contributions, ThreadGroupContribution{Source: source.Source, State: source.State, KeyState: source.KeyState, ExpiresAt: source.ExpiresAt, Effective: source.Effective})
	}
	return v
}

func (c *nativeController) groupThreadView(t wire.OwnerEndpointGroupsThreadCard) GroupThreadView {
	v := GroupThreadView{EndpointID: t.EndpointID, Name: t.Name, Workspace: t.Workspace, Harness: t.Harness, GestureID: c.threadGroupGesture(t), RelationsComplete: t.RelationsComplete, RelationsCursor: t.RelationsNextCursor}
	for _, r := range t.Relations {
		v.Relations = append(v.Relations, c.groupRelationView(r))
	}
	return v
}

func (c *nativeController) populateThreadGroups(view *Snapshot) {
	g := &c.threadGroups
	d := cloneThreadGroups(g.view)
	d.Pending, d.AvailabilityKnown, d.Available = c.hasThreadGroupPending(), g.discoveryTried, g.available
	d.NativeSelfGroups = g.nativeSelfGroups
	view.ThreadGroups = d
	if !c.pairAccountReady() {
		return
	}
	node, network := c.threadGroupScope()
	cardScopeCurrent := d.NodeID == node && d.NetworkID == network && g.viewSessionDigest == sessionTokenDigest(c.session.SessionToken)
	if !cardScopeCurrent {
		d.Current, d.CanCreate = false, false
		d.Selected, d.Threads, d.Candidates = nil, nil, nil
		d.ThreadsNextCursor, d.CandidatesCursor, d.CapturedAt, d.FreshUntil, d.Outcome = "", "", "", "", ""
		d.CandidatesLoaded = false
	}
	d.NodeID, d.NetworkID, d.NodeName = node, network, c.nodeConfirmation.Binding.NodeName
	if p := c.localDomain.state.Description; p != nil && p.Policy.NetworkID == network {
		d.NetworkName = p.Policy.NetworkName
	}
	if d.Pending && g.original != nil {
		d.NetworkName = g.original.NetworkName
	}
	d.GestureID = c.threadGroupGesture("read")
	d.Threads, d.Candidates = nil, nil
	if cardScopeCurrent {
		for _, t := range g.threads {
			d.Threads = append(d.Threads, c.groupThreadView(t))
		}
		if g.selected != nil {
			t := c.groupThreadView(*g.selected)
			d.Selected = &t
		}
		for _, candidate := range g.candidates {
			d.Candidates = append(d.Candidates, ThreadGroupCandidate{GroupID: candidate.GroupID, Name: candidate.Name,
				CanAdd: slices.Contains(candidate.AllowedActions, wire.OwnerEndpointGroupsAddEndpoint), UnavailableReason: candidate.UnavailableReason, GestureID: c.threadGroupGesture(candidate)})
		}
	}
	d.Review = nil
	if r := g.review; r != nil && g.reviewOriginal != nil {
		d.Review = &ThreadGroupReview{GestureID: c.threadGroupGesture(r), Action: r.Action, EndpointID: r.Target.EndpointID, GroupID: r.Target.GroupID, LocalUserScope: r.Target.LocalUserScope, ExpiresAt: r.ExpiresAt, Duration: r.Projection.Duration}
		d.Review.NodeID, d.Review.NetworkID, d.Review.NetworkName = r.Target.NodeID, r.Target.NetworkID, g.reviewOriginal.NetworkName
		if g.reviewOriginal.Binding != nil {
			d.Review.NodeName = g.reviewOriginal.Binding.NodeName
		}
		if t := g.reviewOriginal.Thread; t != nil {
			d.Review.ThreadName, d.Review.Workspace = t.Name, t.Workspace
		}
		switch {
		case r.Action == wire.OwnerEndpointGroupsCreateGroup:
			d.Review.GroupName = r.Target.Name
		case g.reviewOriginal.Group != nil:
			d.Review.GroupName = g.reviewOriginal.Group.Name
		case g.reviewOriginal.Relation != nil:
			d.Review.GroupName = g.reviewOriginal.Relation.GroupName
		}
		if r.Policy != nil {
			d.Review.PolicyExpiresAt = r.Policy.ExpiresAt
		}
		if c.threadGroupReviewCurrent(g.reviewOriginal) && !d.Pending {
			d.Current, d.FreshUntil = true, r.ExpiresAt
		}
	}
	view.ThreadGroups = d
	if c.profileRecoveryRequired || c.storageFault || c.nodePairTrustBusy() || !c.pairAccountReady() || network == "" {
		return
	}
	if d.Pending {
		view.AvailableActions = append(view.AvailableActions, ActionRecoverThreadGroup)
		return
	}
	if !c.pairCanStart() {
		return
	}
	if !d.AvailabilityKnown || d.Available {
		view.AvailableActions = append(view.AvailableActions, ActionReadThreadGroups)
	}
	if d.Review != nil {
		view.AvailableActions = append(view.AvailableActions, ActionDismissThreadGroup)
		if c.threadGroupReviewCurrent(g.reviewOriginal) && d.Available {
			view.AvailableActions = append(view.AvailableActions, ActionApplyThreadGroup)
		}
		return
	}
	if d.Current && d.Available && c.cfg.Now().UTC().Before(parseExpiry(d.FreshUntil)) {
		view.AvailableActions = append(view.AvailableActions, ActionReadThreadRelations, ActionReadGroupCandidates, ActionPrepareThreadGroup)
	}
}
