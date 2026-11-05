package native

import (
	"fmt"
	"image"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The delivered core leaves this projection nil until the approved consumer is
// connected. Revealing a supplied board is a local read, not refresh or acquire.
func (v *view) groupLockBoardEntry(key string, source appcore.GroupLockBoardView, s appcore.Snapshot, group string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if !source.CanView {
			return layout.Dimensions{}
		}
		return v.disclosure("group-locks/"+key, v.groupLockBoard(key, source, s, group), "locks.show", "locks.hide")(gtx)
	}
}

func (v *view) groupLockBoard(key string, source appcore.GroupLockBoardView, s appcore.Snapshot, group string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		board := appcore.ProjectGroupLockBoard(source)
		if !board.CanView {
			return layout.Dimensions{}
		}
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "locks.title"))), layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.read_only")))}
		if board.PolicyState != "" {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.policy."+board.PolicyState))))
		}
		if board.CanEnable {
			rows = append(rows, layout.Rigid(v.coordinationButton(s, appcore.ActionPrepareCoordination, "enable/"+group, "coord.enable", appcore.CoordinationAction{Change: wire.ThreadCollaborationEnableGroupPolicy, GroupID: group, GestureID: board.GestureID}, board.Current)))
		}
		if board.CanRevoke {
			rows = append(rows, layout.Rigid(v.coordinationButton(s, appcore.ActionPrepareCoordination, "revoke/"+group, "coord.revoke", appcore.CoordinationAction{Change: wire.ThreadCollaborationRevokeGroupPolicy, GroupID: group, GestureID: board.GestureID}, board.Current)))
		}
		if !board.Current {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.not_current"))))
		}
		if board.ObservedAt != "" {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.observed")+": "+displayNodeTime(board.ObservedAt))))
		}
		for _, slot := range board.Slots {
			rows = append(rows, layout.Rigid(v.groupLockRow(slot, s, group)))
		}
		rows = append(rows, layout.Rigid(v.disclosure("group-locks/"+key+"/version", func(gtx layout.Context) layout.Dimensions {
			return v.nodeCaption(fmt.Sprintf("%s: %d", appui.Text(v.locale, "locks.version"), board.Version))(gtx)
		})))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func (v *view) groupLockRow(slot appcore.GroupLockSlotView, s appcore.Snapshot, group string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		state := "locks.unknown"
		switch slot.State {
		case appcore.GroupLockFree:
			state = "locks.free"
		case appcore.GroupLockHeld:
			state = "locks.held"
		}
		paint.FillShape(gtx.Ops, appLine, clip.Rect{Max: image.Pt(gtx.Constraints.Max.X, 1)}.Op())
		return layout.Inset{Top: 12, Bottom: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			label := fmt.Sprintf("%s %d · %s", appui.Text(v.locale, "locks.slot"), slot.Number, appui.Text(v.locale, state))
			rows := []layout.FlexChild{layout.Rigid(v.labelRow(label))}
			if slot.State == appcore.GroupLockHeld {
				holder := safeDisplay(strings.TrimSpace(slot.HolderName), 96)
				if holder == "" {
					holder = appui.Text(v.locale, "locks.holder_private")
				}
				rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.holder")+": "+holder)))
				if slot.ExpiresAt != "" {
					rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.expires")+": "+displayNodeTime(slot.ExpiresAt))))
					if expiry, err := time.Parse(time.RFC3339Nano, slot.ExpiresAt); err == nil {
						left := max(time.Duration(0), expiry.Sub(gtx.Now))
						seconds := int64(left / time.Second)
						if left%time.Second > 0 {
							seconds++
						}
						rows = append(rows, layout.Rigid(v.nodeCaption(fmt.Sprintf(appui.Text(v.locale, "locks.remaining"), seconds))))
					}
				}
			}
			if slot.Purpose != "" {
				rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.purpose")+": "+safeDisplay(slot.Purpose, 256))))
			}
			if slot.CanClear {
				rows = append(rows, layout.Rigid(v.coordinationButton(s, appcore.ActionPrepareCoordination, fmt.Sprintf("clear/%s/%d", group, slot.Number), "coord.clear", appcore.CoordinationAction{Change: wire.ThreadCollaborationClearOneSlot, GroupID: group, Slot: slot.Number, GestureID: slot.GestureID}, slot.State == appcore.GroupLockHeld)))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		})
	}
}
