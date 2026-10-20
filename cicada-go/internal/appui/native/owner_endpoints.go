//go:build windows

package native

import (
	"strconv"
	"time"

	"gioui.org/layout"
	"gioui.org/widget"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) ownerEndpointSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if !appui.OwnerEndpointDirectoryVisible(s, time.Now()) {
			return layout.Dimensions{}
		}
		directory := s.OwnerEndpoints
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "directory.title"))),
			layout.Rigid(v.labelRow(appui.Text(v.locale, "directory.scope"))),
			layout.Rigid(v.labelRow(safeDisplay(directory.NodeName, 256)))}
		if directory.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, directory.ErrorCode))))
		}
		if directory.RetainedUnknown != 0 {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "directory.retained")+": "+strconv.Itoa(directory.RetainedUnknown))))
		}
		if directory.Pending {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "directory.pending"))),
				layout.Rigid(v.ownerEndpointButton(s, false, true)))
			if directory.ParkReviewID != "" && hasAction(s, appcore.ActionParkOwnerEndpoints) {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "directory.park_body"))), layout.Rigid(v.ownerEndpointParkButton(s)))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		rows = append(rows, layout.Rigid(v.ownerEndpointButton(s, false, false)))
		if directory.State == "READ_EXPIRED" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "directory.expired"))))
		}
		if directory.State == "SNAPSHOT_ONLY" {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "directory.snapshot")+": "+displayNodeTime(directory.CapturedAt))))
			if len(directory.Endpoints) == 0 {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "directory.empty"))))
			}
		}
		for _, card := range directory.Endpoints {
			card := card
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				fields := v.publicFieldRows("directory/"+card.EndpointID+"/", appui.OwnerEndpointPublicFields(s, card, time.Now()))
				presence := map[string]string{"offline": "directory.offline", "left": "directory.left", "LEASE_RECENT": "directory.lease_recent", "UNKNOWN": "directory.unknown"}[card.Presence]
				fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, presence))), layout.Rigid(v.disclosure("directory/"+card.EndpointID, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("directory/"+card.EndpointID+"/details/", []appui.PublicField{
						{Key: "directory.endpoint_id", Value: card.EndpointID}, {Key: "directory.harness", Value: card.Harness}, {Key: "node.id", Value: directory.NodeID}})...)
				})))
				return layout.Inset{Top: 12, Bottom: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, fields...)
				})
			}))
		}
		if directory.NextCursor != "" {
			rows = append(rows, layout.Rigid(v.ownerEndpointButton(s, true, false)))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func (v *view) ownerEndpointParkButton(s appcore.Snapshot) layout.Widget {
	button := v.workspaceButtons["directory.park"]
	if button == nil {
		button = new(widget.Clickable)
		v.workspaceButtons["directory.park"] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := !v.busy.Load() && hasAction(s, appcore.ActionParkOwnerEndpoints) && s.OwnerEndpoints.ParkReviewID != ""
		if button.Clicked(gtx) && enabled {
			v.startDispatch(appcore.Action{Kind: appcore.ActionParkOwnerEndpoints, OwnerEndpoints: appcore.OwnerEndpointReadAction{ReviewID: s.OwnerEndpoints.ParkReviewID, ConfirmPark: true}})
		}
		return v.button(gtx, button, appui.Text(v.locale, "directory.park"), enabled)
	}
}

func (v *view) ownerEndpointButton(s appcore.Snapshot, next, recover bool) layout.Widget {
	kind, key, cursor, review := appcore.ActionReadOwnerEndpoints, "directory.read", "", s.OwnerEndpoints.ReviewID
	if next {
		key, cursor, review = "directory.next", s.OwnerEndpoints.NextCursor, s.OwnerEndpoints.NextReviewID
	}
	if recover {
		kind, key = appcore.ActionRecoverOwnerEndpoints, "directory.recover"
	}
	button := v.workspaceButtons[key]
	if button == nil {
		button = new(widget.Clickable)
		v.workspaceButtons[key] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := !v.busy.Load() && hasAction(s, kind) && (recover || review != "")
		if button.Clicked(gtx) && enabled {
			v.startDispatch(appcore.Action{Kind: kind, OwnerEndpoints: appcore.OwnerEndpointReadAction{ReviewID: review, Cursor: cursor, Limit: 64, ConfirmRead: !recover}})
		}
		return v.button(gtx, button, appui.Text(v.locale, key), enabled)
	}
}
