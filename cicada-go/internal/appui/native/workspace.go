//go:build windows

package native

import (
	"image"
	"image/color"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

var workspaceMutedSurface = color.NRGBA{R: 237, G: 243, B: 245, A: 255}

type disclosureState struct {
	button widget.Clickable
	open   bool
}

var workspacePages = []string{"overview", "devices", "sessions", "identity", "settings"}

func (v *view) workspaceLayout(gtx layout.Context, s appcore.Snapshot, flow appui.SetupFlow) layout.Dimensions {
	if v.workspaceButtons == nil {
		v.workspaceButtons = make(map[string]*widget.Clickable)
	}
	if v.workspacePage == "" {
		v.workspacePage = "overview"
	}
	secondary := make([]appcore.ActionKind, 0, len(flow.Secondary))
	for _, action := range flow.Secondary {
		if action != appcore.ActionLogout && action != appcore.ActionExportOwnerPublic {
			secondary = append(secondary, action)
		}
	}
	flow.Secondary = secondary
	sidebar := func(gtx layout.Context) layout.Dimensions {
		gtx.Constraints.Min.X = gtx.Dp(190)
		gtx.Constraints.Max.X = gtx.Constraints.Min.X
		return layout.Inset{Right: unit.Dp(18)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			children := []layout.FlexChild{layout.Rigid(v.nodeCaption(appui.Text(v.locale, "workspace.navigation")))}
			for _, page := range workspacePages {
				children = append(children, layout.Rigid(v.workspaceNavigation(page)))
			}
			children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{Size: gtx.Constraints.Min} }))
			if hasAction(s, appcore.ActionLogout) {
				children = append(children, layout.Rigid(v.actionButton(appcore.ActionLogout, appui.Text(v.locale, "account.logout"), s)))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}
	content := func(gtx layout.Context) layout.Dimensions {
		rows := []layout.Widget{v.headingRow(appui.Text(v.locale, "workspace."+v.workspacePage))}
		if banner := v.workspaceAttention(s, flow); banner != nil {
			rows = append(rows, banner)
		}
		rows = append(rows, v.workspaceRows(s, flow)...)
		return v.contentList.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
			return layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(10)}.Layout(gtx, rows[i])
		})
	}
	if gtx.Constraints.Max.X < gtx.Dp(760) {
		tabs := func(gtx layout.Context) layout.Dimensions {
			children := make([]layout.FlexChild, 0, len(workspacePages))
			for _, page := range workspacePages {
				children = append(children, layout.Flexed(1, v.workspaceNavigation(page)))
			}
			return layout.Flex{}.Layout(gtx, children...)
		}
		children := []layout.FlexChild{layout.Rigid(tabs), layout.Flexed(1, content)}
		if hasAction(s, appcore.ActionLogout) {
			children = append(children, layout.Rigid(v.actionButton(appcore.ActionLogout, appui.Text(v.locale, "account.logout"), s)))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}
	return layout.Flex{}.Layout(gtx, layout.Rigid(sidebar), layout.Flexed(1, content))
}

func (v *view) workspaceNavigation(page string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		button := v.workspaceButtons[page]
		if button == nil {
			button = new(widget.Clickable)
			v.workspaceButtons[page] = button
		}
		if button.Clicked(gtx) {
			v.workspacePage = page
			v.contentList.Position = layout.Position{}
			v.window.Invalidate()
		}
		style := material.Button(v.theme, button, appui.Text(v.locale, "workspace."+page))
		style.Background, style.Color = color.NRGBA{}, v.theme.Fg
		style.TextSize = unit.Sp(14)
		style.Inset = layout.Inset{Top: unit.Dp(13), Bottom: unit.Dp(13), Left: unit.Dp(12), Right: unit.Dp(12)}
		if v.workspacePage == page {
			style.Background, style.Color = workspaceMutedSurface, v.theme.ContrastBg
		}
		return layout.Inset{Top: unit.Dp(5), Bottom: unit.Dp(5)}.Layout(gtx, style.Layout)
	}
}

func (v *view) workspaceRows(s appcore.Snapshot, flow appui.SetupFlow) []layout.Widget {
	switch v.workspacePage {
	case "devices":
		if appui.NodeCardVisible(s, appui.Flow(s)) {
			return []layout.Widget{v.sectionCard(v.nodeSection(s))}
		}
		return []layout.Widget{v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.devices_unavailable")))}
	case "sessions":
		rows := []layout.Widget{}
		if appui.OwnerEndpointDirectoryVisible(s, time.Now()) {
			rows = append(rows, v.sectionCard(v.ownerEndpointSection(s)))
		}
		if appui.PairFlow(s, time.Now()).Visible {
			rows = append(rows, v.sectionCard(v.pairSection(s)))
		}
		if len(rows) == 0 {
			rows = append(rows, v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.sessions_unavailable"))))
		}
		return rows
	case "identity":
		rows := []layout.Widget{v.labelRow(appui.Text(v.locale, "workspace.identity_body")), func(gtx layout.Context) layout.Dimensions { return v.statusCard(gtx, s) }}
		if flow.Stage != "ready" && !strings.HasPrefix(flow.Stage, "node-") && flow.Stage != "pair-recovery" {
			rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
				children := v.contentRows(s, flow, true, false, nil, false)
				rows := make([]layout.FlexChild, 0, len(children))
				for _, child := range children {
					rows = append(rows, layout.Rigid(child))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
			}))
		}
		if hasAction(s, appcore.ActionExportOwnerPublic) {
			rows = append(rows, v.actionButton(appcore.ActionExportOwnerPublic, appui.Text(v.locale, "account.export_owner_public"), s))
		}
		if flow.Stage == "ready" && flow.Primary != "" {
			if label, ok := v.actionLabel(flow.Primary); ok {
				rows = append(rows, v.actionButton(flow.Primary, label, s))
			}
		}
		return rows
	case "settings":
		rows := []layout.Widget{
			v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.settings_body"))),
			v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.storage_body"))),
		}
		rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
			fields := v.publicFieldRows("storage/", appui.StoragePublicFields(s, time.Now()))
			if s.Storage.Legacy {
				fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "storage.legacy_body"))))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, fields...)
		}))
		// Keep the existing explicit local fixture preview reachable after the
		// navigation change. This entry never reads or claims management data.
		var objects []appui.CanvasObject
		if v.preview {
			objects = appui.PreviewCanvasObjects()
		}
		rows = append(rows, v.sectionCard(v.canvasSection(appcore.Snapshot{}, false, objects, v.preview)))
		return rows
	}
	rows := []layout.Widget{v.labelRow(appui.Text(v.locale, "workspace.overview_body"))}
	// A session being registered or an account being logged in never implies
	// peer authority. These links only navigate to the established review.
	if appui.PairFlow(s, time.Now()).Visible {
		rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
			label := strings.TrimSpace(s.Pair.Label)
			if label == "" {
				label = appui.Text(v.locale, "workspace.sessions")
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(v.headingRow(label)),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, "workspace.communication_body"))),
				layout.Rigid(v.workspaceLink("sessions", appui.Text(v.locale, "workspace.review_sessions"))))
		}))
	}
	if s.Node.Binding != nil {
		rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
			name := strings.TrimSpace(s.Node.Binding.Name)
			if name == "" {
				name = appui.Text(v.locale, "node.section")
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(v.headingRow(safeDisplay(name, 128))),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, appui.NodeStatusMessage(s)))),
				layout.Rigid(v.workspaceLink("devices", appui.Text(v.locale, "workspace.view_device"))))
		}))
	} else if appui.NodeCardVisible(s, appui.Flow(s)) {
		rows = append(rows, v.sectionCard(v.workspaceLink("devices", appui.Text(v.locale, "workspace.connect_device"))))
	}
	rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(v.headingRow(appui.Text(v.locale, "workspace.hub_verified"))),
			layout.Rigid(v.nodeCaption(safeDisplay(s.Hub.Origin, 256))),
			layout.Rigid(v.disclosure("overview/connection", func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("account/", appui.AccountPublicFields(s, time.Now()))...)
			})))
	}))
	return rows
}

func (v *view) workspaceAttention(s appcore.Snapshot, flow appui.SetupFlow) layout.Widget {
	if v.busy.Load() && !v.autoBusy.Load() {
		return v.sectionCard(v.labelRow(appui.Text(v.locale, "operation.in_progress")))
	}
	page, message := "", ""
	switch {
	case s.OwnerEndpoints.Pending:
		page, message = "sessions", "directory.pending"
	case s.Pair.Pending:
		page, message = "sessions", "pair.recovery"
	case s.Node.Pending:
		page, message = "devices", "node.recovery"
	case flow.Stage != "ready" && !strings.HasPrefix(flow.Stage, "node-") && flow.Stage != "pair-recovery":
		page, message = "identity", "workspace.continue_account"
	case s.ErrorCode != "":
		return v.sectionCard(v.labelRow(appui.ErrorText(v.locale, s.ErrorCode)))
	}
	if page == "" {
		return nil
	}
	return v.sectionCard(func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(v.labelRow(appui.Text(v.locale, message))),
			layout.Rigid(v.workspaceLink(page, appui.Text(v.locale, "workspace.continue_operation"))))
	})
}

func (v *view) sectionCard(content layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions { return v.card(gtx, content) }
}

func (v *view) workspaceLink(page, label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		key := "open/" + page + "/" + label
		button := v.workspaceButtons[key]
		if button == nil {
			button = new(widget.Clickable)
			v.workspaceButtons[key] = button
		}
		if button.Clicked(gtx) {
			v.workspacePage = page
			v.contentList.Position = layout.Position{}
			v.window.Invalidate()
		}
		style := material.Button(v.theme, button, label)
		style.TextSize = unit.Sp(14)
		return layout.Inset{Top: unit.Dp(18), Bottom: unit.Dp(4)}.Layout(gtx, style.Layout)
	}
}

func (v *view) disclosure(key string, body layout.Widget) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if v.disclosures == nil {
			v.disclosures = make(map[string]*disclosureState)
		}
		state := v.disclosures[key]
		if state == nil {
			state = new(disclosureState)
			v.disclosures[key] = state
		}
		if state.button.Clicked(gtx) {
			state.open = !state.open
			v.window.Invalidate()
		}
		label := appui.Text(v.locale, "workspace.details")
		if state.open {
			label = appui.Text(v.locale, "workspace.hide_details")
		}
		style := material.Button(v.theme, &state.button, label)
		style.TextSize, style.Background, style.Color = unit.Sp(13), color.NRGBA{}, v.theme.ContrastBg
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(style.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if !state.open {
					return layout.Dimensions{Size: image.Point{}}
				}
				return body(gtx)
			}))
	}
}
