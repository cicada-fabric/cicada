package appcore

import (
	"slices"
	"time"
)

// ThreadGroupsSnapshot is a display projection, never a grant or a saved MCP
// selection. Protocol requests, proofs, keys and pending ciphertext stay in Core.
type ThreadGroupsSnapshot struct {
	AvailabilityKnown bool
	Available         bool
	NativeSelfGroups  bool
	Current           bool
	Pending           bool
	NodeID            string
	NodeName          string
	NetworkID         string
	NetworkName       string
	CapturedAt        string
	FreshUntil        string
	GestureID         string
	ErrorCode         string
	CanCreate         bool
	UnavailableReason string
	Threads           []GroupThreadView
	ThreadsNextCursor string
	Selected          *GroupThreadView
	Candidates        []ThreadGroupCandidate
	CandidatesLoaded  bool
	CandidatesCursor  string
	Review            *ThreadGroupReview
	Outcome           string
}

type GroupThreadView struct {
	EndpointID        string
	Name              string
	Workspace         string
	Harness           string
	GestureID         string
	Relations         []ThreadGroupRelation
	RelationsComplete bool
	RelationsCursor   string
}

type ThreadGroupRelation struct {
	GroupID           string
	Name              string
	State             string
	KeyState          string
	ExpiresAt         string
	OwnerMode         string
	DenyReason        string
	CanRemove         bool
	UnavailableReason string
	GestureID         string
	Contributions     []ThreadGroupContribution
}

type ThreadGroupContribution struct {
	Source    string
	State     string
	KeyState  string
	ExpiresAt string
	Effective bool
}

type ThreadGroupCandidate struct {
	GroupID           string
	Name              string
	CanAdd            bool
	UnavailableReason string
	GestureID         string
}

type ThreadGroupReview struct {
	GestureID       string
	Action          string
	EndpointID      string
	GroupID         string
	LocalUserScope  string
	NodeID          string
	NodeName        string
	NetworkID       string
	NetworkName     string
	ThreadName      string
	Workspace       string
	GroupName       string
	ExpiresAt       string // Short consent deadline, not policy lifetime.
	PolicyExpiresAt string
	Duration        string
}

const (
	ActionReadThreadGroups    ActionKind = "READ_THREAD_GROUPS"
	ActionReadThreadRelations ActionKind = "READ_THREAD_GROUP_RELATIONS"
	ActionReadGroupCandidates ActionKind = "READ_THREAD_GROUP_CANDIDATES"
	ActionPrepareThreadGroup  ActionKind = "REVIEW_THREAD_GROUP_CHANGE"
	ActionApplyThreadGroup    ActionKind = "APPLY_REVIEWED_THREAD_GROUP_CHANGE"
	ActionDismissThreadGroup  ActionKind = "DISMISS_THREAD_GROUP_REVIEW"
	ActionRecoverThreadGroup  ActionKind = "RECOVER_ORIGINAL_THREAD_GROUP_REQUEST"
)

// IDs are copied from Core's authenticated cards by a native gesture. They are
// not user-entered identities, wire DTOs, consent proofs or communication grants.
type ThreadGroupAction struct {
	GestureID  string
	EndpointID string
	GroupID    string
	Cursor     string
	Change     string
	Name       string
	Duration   string
	Confirm    bool
}

func threadGroupActionKind(kind ActionKind) bool {
	switch kind {
	case ActionReadThreadGroups, ActionReadThreadRelations, ActionReadGroupCandidates,
		ActionPrepareThreadGroup, ActionApplyThreadGroup, ActionDismissThreadGroup, ActionRecoverThreadGroup:
		return true
	}
	return false
}

// ThreadGroupsVisible requires the original account login. A saved snapshot,
// public capability, Node presence or pending request does not supply authority.
func ThreadGroupsVisible(s Snapshot, now time.Time) bool {
	if !s.Hub.Verified || s.Hub.HubID == "" || s.Hub.Origin == "" || s.Hub.Fingerprint == "" ||
		s.Account.AccountID == "" || s.Account.OwnerID == "" || s.Account.DeviceID == "" ||
		s.Node.Binding == nil || (s.ThreadGroups.NodeID != "" && s.ThreadGroups.NodeID != s.Node.Binding.NodeID) {
		return false
	}
	for _, action := range s.AvailableActions {
		switch action {
		case ActionLogin, ActionLoginPrepare, ActionLoginComplete, ActionRetry, ActionRecover:
			return false
		}
	}
	return s.Account.RootState == RootStateActive &&
		s.Account.State == AccountStateOwnerReady && s.Account.LocalOwnerKeyPresent &&
		now.Before(parseExpiry(s.Account.SessionExpiresAt))
}

func expireThreadGroupsView(view *Snapshot, now time.Time) {
	g := &view.ThreadGroups
	live := ThreadGroupsVisible(*view, now)
	if !live {
		// Login expiry hides private cards but retains pending in Core/vault.
		*g = ThreadGroupsSnapshot{AvailabilityKnown: g.AvailabilityKnown, Available: g.Available, Pending: g.Pending}
	}
	if g.Pending {
		g.Current = false
	}
	if g.Current && !now.Before(parseExpiry(g.FreshUntil)) {
		g.Current = false
	}
	view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(kind ActionKind) bool {
		if !threadGroupActionKind(kind) {
			return false
		}
		if !live {
			return true
		}
		if kind == ActionRecoverThreadGroup {
			return !g.Pending
		}
		if g.Pending {
			return true
		}
		if kind == ActionReadThreadGroups {
			return g.AvailabilityKnown && !g.Available
		}
		if kind == ActionDismissThreadGroup {
			return g.Review == nil
		}
		if !g.Available || !g.Current {
			return true
		}
		if kind == ActionApplyThreadGroup {
			return g.Review == nil || !now.Before(parseExpiry(g.Review.ExpiresAt))
		}
		return false
	})
}

func cloneThreadGroups(source ThreadGroupsSnapshot) ThreadGroupsSnapshot {
	copy := source
	cloneThread := func(thread GroupThreadView) GroupThreadView {
		thread.Relations = slices.Clone(thread.Relations)
		for i := range thread.Relations {
			thread.Relations[i].Contributions = slices.Clone(thread.Relations[i].Contributions)
		}
		return thread
	}
	copy.Threads = slices.Clone(source.Threads)
	for i := range copy.Threads {
		copy.Threads[i] = cloneThread(copy.Threads[i])
	}
	if source.Selected != nil {
		thread := cloneThread(*source.Selected)
		copy.Selected = &thread
	}
	copy.Candidates = slices.Clone(source.Candidates)
	if source.Review != nil {
		review := *source.Review
		copy.Review = &review
	}
	return copy
}
