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
	if immediate {
		gtx.Execute(op.InvalidateCmd{})
	} else if scheduled {
		gtx.Execute(op.InvalidateCmd{At: earliest})
	}
}
