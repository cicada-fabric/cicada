//go:build windows

package native

import (
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	"time"
)

func (v *view) nodeSection(s appcore.Snapshot) layout.Widget {
	if s.Node.Pairing == nil {
		return v.legacyNodeSection(s)
	}
	return func(gtx layout.Context) layout.Dimensions {
		flow := appui.NodePairingFlow(s, time.Now())
		if flow.Stage != "code" && flow.Stage != "ended" {
			v.legacyNodePairing = false
		}
		rows := v.devicePairingRows(s)
		if v.legacyNodePairing {
			rows = []layout.Widget{v.legacyNodeSection(s)}
		}
		if flow := appui.NodePairingFlow(s, time.Now()); flow.Stage == "code" || flow.Stage == "ended" {
			rows = append(rows, func(gtx layout.Context) layout.Dimensions {
				if v.nodePairingMode.Clicked(gtx) && !v.busy.Load() {
					v.legacyNodePairing = !v.legacyNodePairing
					v.devicePairingCode.SetText("")
					v.nodeCode.SetText("")
				}
				if v.busy.Load() {
					gtx = gtx.Disabled()
				}
				label := "node_pairing.legacy"
				if v.legacyNodePairing {
					label = "node_pairing.default"
				}
				style := material.Button(v.theme, &v.nodePairingMode, appui.Text(v.locale, label))
				style.Background, style.Color = workspaceMutedSurface, v.theme.Fg
				return style.Layout(gtx)
			})
		}
		children := make([]layout.FlexChild, 0, len(rows)*2)
		for _, row := range rows {
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Inset{Top: 8, Bottom: 8}.Layout(gtx, row) }))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}
}
func (v *view) devicePairingRows(s appcore.Snapshot) []layout.Widget {
	p := s.Node.Pairing
	flow := appui.NodePairingFlow(s, time.Now())
	var rows []layout.Widget
	switch flow.Stage {
	case "code", "ended":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.title")), v.labelRow(appui.Text(v.locale, "node_pairing.intro")), v.editorRow(&v.devicePairingCode, appui.Text(v.locale, "node_pairing.code"), false))
		if flow.Stage == "ended" {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "node_pairing.ended")))
		}
	case "review", "expired":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.review_title")), v.labelRow(safeDisplay(p.Name, 128)), v.nodeCaption(appui.Text(v.locale, "node.candidate_until")+": "+displayNodeTime(p.ExpiresAt)), v.labelRow(appui.Text(v.locale, "node_pairing.scope")))
		if flow.Stage == "expired" {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "node_pairing.expired")))
		}
	case "waiting":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.waiting_title")), v.labelRow(appui.Text(v.locale, "node_pairing.waiting_body")))
	case "deadline":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.deadline")), v.labelRow(appui.Text(v.locale, "node_pairing.deadline_body")))
	case "preparing":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.preparing")))
	case "recovery":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "node_pairing.recovery")), v.labelRow(appui.Text(v.locale, "node_pairing.recovery_body")))
	case "connected":
		rows = append(rows, v.headingRow(safeDisplay(p.Name, 128)), v.labelRow(appui.Text(v.locale, "node_pairing.connected")), v.nodeCaption(appui.Text(v.locale, appui.NodeStatusMessage(s))))
		for _, kind := range []appcore.ActionKind{appcore.ActionRefreshNode, appcore.ActionReauthorizeNodeStatus, appcore.ActionCancelNodeAccess} {
			if hasAction(s, kind) {
				rows = append(rows, v.actionButton(kind, v.nodeActionLabel(kind), s))
			}
		}
	}
	if p.Availability == "UNAVAILABLE" && flow.Stage == "code" {
		rows = append(rows, v.labelRow(appui.Text(v.locale, "node_pairing.unavailable")))
	}
	if p.NodeID != "" {
		rows = append(rows, v.disclosure("device-pairing/"+p.ReviewID, func(gtx layout.Context) layout.Dimensions {
			fields := []appui.PublicField{{Key: "node.id", Value: p.NodeID}}
			if p.ExpiresAt != "" {
				fields = append(fields, appui.PublicField{Key: "node.candidate_until", Value: p.ExpiresAt})
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("device-pairing/", fields)...)
		}))
	}
	if p.ErrorCode != "" {
		rows = append(rows, v.labelRow(appui.ErrorText(v.locale, p.ErrorCode)))
	}
	if flow.Primary != "" {
		label := "node_pairing.check"
		switch flow.Primary {
		case appcore.ActionReviewNodePairing:
			label = "node.preview"
		case appcore.ActionApproveNodePairing:
			label = "node_pairing.approve"
		case appcore.ActionRecoverNodePairing:
			label = "node.recover"
		}
		rows = append(rows, v.devicePairingButton(s, flow.Primary, label))
	}
	if flow.Cancel {
		rows = append(rows, v.devicePairingButton(s, appcore.ActionCancelNodePairing, "node.cancel_review"))
	}
	return rows
}
func (v *view) devicePairingButton(s appcore.Snapshot, kind appcore.ActionKind, label string) layout.Widget {
	button := v.buttons[kind]
	if button == nil {
		button = new(widget.Clickable)
		v.buttons[kind] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := hasAction(s, kind) && !v.busy.Load()
		code, ready := devicePairingInput(&v.devicePairingCode)
		if kind == appcore.ActionReviewNodePairing {
			enabled = enabled && ready
		}
		if button.Clicked(gtx) && enabled {
			action := appcore.Action{Kind: kind}
			if s.Node.Pairing != nil {
				action.NodePairingReviewID = s.Node.Pairing.ReviewID
			}
			if kind == appcore.ActionReviewNodePairing {
				action.DevicePairingCode = code
				v.devicePairingCode.SetText("")
			}
			action.ConfirmNodePairing = kind == appcore.ActionApproveNodePairing
			v.startDispatch(action)
		}
		return v.button(gtx, button, appui.Text(v.locale, label), enabled)
	}
}
func (v *view) scheduleNodePairingPoll(gtx layout.Context, s appcore.Snapshot) {
	at, due := v.pairingPoll.next(s, time.Now(), v.busy.Load() || v.closed.Load())
	if !at.IsZero() {
		gtx.Execute(op.InvalidateCmd{At: at})
	}
	if due {
		v.startDispatch(appcore.Action{Kind: appcore.ActionRefreshNodePairing})
	}
}
