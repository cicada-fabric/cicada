package native

import (
	"slices"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"github.com/cicada-ai/cicada/internal/appcore"
)

// This scheduling path is shared by the Windows renderer and the portable Gio
// Router regression. It performs no network or controller operation.
func scheduleSnapshotRedraw(gtx layout.Context, snapshot appcore.Snapshot, now time.Time) {
	var earliest time.Time
	var scheduled, immediate bool
	consider := func(value string, live bool) {
		deadline, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return
		}
		if !deadline.After(now) {
			// Snapshot was sampled earlier than this scheduling decision. If
			// its projection is still live, resample on the next frame rather
			// than losing the transition until an unrelated user action.
			immediate = immediate || live
			return
		}
		if !scheduled || deadline.Before(earliest) {
			earliest, scheduled = deadline, true
		}
	}
	consider(snapshot.Authorization.ExpiresAt, snapshot.Authorization.State == "ACTIVE")
	consider(snapshot.Account.SessionExpiresAt, snapshot.Account.State != appcore.AccountStateLoginRequired)
	consider(snapshot.Node.Access.ExpiresAt, snapshot.Node.Access.State == "ACTIVE")
	if candidate := snapshot.Node.Candidate; candidate != nil {
		reviewLive := slices.Contains(snapshot.AvailableActions, appcore.ActionApproveNode)
		consider(candidate.ExpiresAt, reviewLive)
		consider(candidate.AuthorizationExpiresAt, reviewLive)
	}
	if pairing := snapshot.Node.Pairing; pairing != nil {
		consider(pairing.ExpiresAt, !pairing.DeadlineReached && (pairing.State == "OWNER_APPROVED" || slices.Contains(snapshot.AvailableActions, appcore.ActionApproveNodePairing)))
	}
	consider(snapshot.Node.Connectivity.FreshUntil, snapshot.Node.ConnectionState() == appcore.NodeOnline)
	consider(snapshot.Pair.ReviewExpiresAt, slices.Contains(snapshot.AvailableActions, appcore.ActionCompletePair) || slices.Contains(snapshot.AvailableActions, appcore.ActionApprovePairSlot))
	consider(snapshot.Pair.PeerExpiresAt, snapshot.Pair.Current)
	consider(snapshot.LocalCollaboration.ReviewExpiresAt, slices.Contains(snapshot.AvailableActions, appcore.ActionActivateLocalCollaboration))
	consider(snapshot.LocalCollaboration.ExpiresAt, snapshot.LocalCollaboration.State == "ACTIVE")
	consider(snapshot.OwnerEndpoints.ParkAfter, snapshot.OwnerEndpoints.Pending && !slices.Contains(snapshot.AvailableActions, appcore.ActionParkOwnerEndpoints))
	consider(snapshot.Coordination.FreshUntil, slices.Contains(snapshot.AvailableActions, appcore.ActionPrepareCoordination))
	if review := snapshot.Coordination.Review; review != nil {
		consider(review.ExpiresAt, review.CanApply)
	}
	if snapshot.ThreadGroups.Current {
		lockDeadlines := func(thread appcore.GroupThreadView) {
			for _, relation := range thread.Relations {
				if board := relation.Locks; board != nil && board.CanView && board.Current {
					for _, slot := range board.Slots {
						if slot.State == appcore.GroupLockHeld {
							consider(slot.ExpiresAt, true)
							if expiry, err := time.Parse(time.RFC3339Nano, slot.ExpiresAt); err == nil && now.Before(expiry) {
								// Display-only countdown; this never dispatches a refresh
								// or renewal and cannot extend the recorded lease.
								consider(now.Truncate(time.Second).Add(time.Second).Format(time.RFC3339Nano), true)
							}
						}
					}
				}
			}
		}
		for _, thread := range snapshot.ThreadGroups.Threads {
			lockDeadlines(thread)
		}
		if thread := snapshot.ThreadGroups.Selected; thread != nil {
			lockDeadlines(*thread)
		}
	}
	if immediate {
		gtx.Execute(op.InvalidateCmd{})
	} else if scheduled {
		gtx.Execute(op.InvalidateCmd{At: earliest})
	}
}
