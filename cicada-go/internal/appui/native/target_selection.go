//go:build windows

package native

import (
	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) targetSelectionSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		d := s.Targets
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "targets.title")))}
		if d.Locked {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "targets.recovery_locked"))))
		}
		for _, n := range d.Nodes {
			n := n
			label := n.Name
			if label == "" {
				label = n.NodeID
			}
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(label, 256))), layout.Rigid(v.nodeCaption(safeDisplay(n.NodeID, 256))))
			if n.Selected {
				rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "targets.selected"))))
			}
			key := "target/" + n.NodeID + "/" + d.GestureID
			button := v.workspaceButtons[key]
			if button == nil {
				button = new(widget.Clickable)
				v.workspaceButtons[key] = button
			}
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				enabled := n.CanSelect && !d.Locked && !v.busy.Load() && hasAction(s, appcore.ActionSelectSavedNode)
				if button.Clicked(gtx) && enabled {
					v.startDispatch(appcore.Action{Kind: appcore.ActionSelectSavedNode, NodeSelection: appcore.NodeSelectionAction{NodeID: n.NodeID, GestureID: d.GestureID}})
				}
				return v.button(gtx, button, appui.Text(v.locale, "targets.select"), enabled)
			}))
		}
		if d.AdditionalNodesPending {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "targets.additional_pending"))))
		}
		kind, label := appcore.ActionBeginAddNode, "targets.add"
		if d.Adding {
			kind, label = appcore.ActionEndAddNode, "targets.end_add"
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			key := "target/add/" + d.GestureID + "/" + string(kind)
			button := v.workspaceButtons[key]
			if button == nil {
				button = new(widget.Clickable)
				v.workspaceButtons[key] = button
			}
			enabled := !d.Locked && !v.busy.Load() && hasAction(s, kind)
			if button.Clicked(gtx) && enabled {
				v.startDispatch(appcore.Action{Kind: kind})
			}
			return v.button(gtx, button, appui.Text(v.locale, label), enabled)
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func (v *view) localNetworkChoices(s appcore.Snapshot) []layout.FlexChild {
	rows := []layout.FlexChild{layout.Rigid(func(gtx layout.Context) layout.Dimensions {
		return material.RadioButton(v.theme, &v.localDomainNetworkChoice, "", appui.Text(v.locale, "local_collaboration.create_network")).Layout(gtx)
	})}
	if len(s.Targets.Networks) != 0 {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "targets.saved_networks"))))
	}
	for _, n := range s.Targets.Networks {
		n := n
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return material.RadioButton(v.theme, &v.localDomainNetworkChoice, n.NetworkID, safeDisplay(n.Name, 256)+" · "+safeDisplay(n.NetworkID, 256)).Layout(gtx)
		}))
	}
	return rows
}
