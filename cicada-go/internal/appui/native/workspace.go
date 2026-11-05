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

var workspaceMutedSurface = sidebarSurface

type disclosureState struct {
	button widget.Clickable
	open   bool
}

var workspacePages = []string{"overview", "devices", "sessions", "identity", "settings"}

func (v *view) workspaceLayout(gtx layout.Context, s appcore.Snapshot, flow appui.SetupFlow) layout.Dimensions {
	if v.hubConnections {
		return v.dockedPage(gtx, appui.Text(v.locale, "connection.hubs"), v.hubConnectionRows(s), nil)
	}
	secondary := make([]appcore.ActionKind, 0, len(flow.Secondary))
	for _, action := range flow.Secondary {
		if action != appcore.ActionLogout && action != appcore.ActionExportOwnerPublic {
			secondary = append(secondary, action)
		}
	}
	flow.Secondary = secondary
	var rows []layout.Widget
	if banner := v.workspaceAttention(s, flow); banner != nil {
		rows = append(rows, banner)
	}
	rows = append(rows, v.workspaceRows(s, flow)...)
	var actions []layout.Widget
	if v.workspacePage == "devices" && s.Node.Pairing != nil {
		actions = v.devicePairingActionRows(s)
	}
	if v.workspacePage == "sessions" && appcore.ThreadGroupsVisible(s, time.Now()) {
		actions = v.coordinationActionRows(s)
	}
	return v.dockedPage(gtx, appui.Text(v.locale, "workspace."+v.workspacePage), rows, actions)
}

func (v *view) workspaceRows(s appcore.Snapshot, flow appui.SetupFlow) []layout.Widget {
	switch v.workspacePage {
	case "devices":
		if appui.NodeCardVisible(s, appui.Flow(s)) {
			rows := []layout.Widget{}
			if len(s.Targets.Nodes) != 0 {
				rows = append(rows, v.sectionCard(v.targetSelectionSection(s)))
			}
			rows = append(rows, v.nodeSection(s))
			if appui.LocalCollaborationFlow(s, time.Now()).Visible {
				rows = append(rows, v.sectionCard(v.localCollaborationSection(s)))
			}
			return rows
		}
		return []layout.Widget{v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.devices_unavailable")))}
	case "sessions":
		rows := []layout.Widget{}
		if appcore.ThreadGroupsVisible(s, time.Now()) {
			rows = append(rows, v.sectionCard(v.threadGroupsSection(s)))
		}
		if !s.ThreadGroups.Available && appui.OwnerEndpointDirectoryVisible(s, time.Now()) {
			rows = append(rows, v.sectionCard(v.ownerEndpointSection(s)))
		}
		if appui.PairFlow(s, time.Now()).Visible {
			rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(v.headingRow(appui.Text(v.locale, "local_collaboration.legacy_pair"))),
					layout.Rigid(v.disclosure("legacy-pair", v.pairSection(s))))
			}))
		}
		if len(rows) == 0 {
			rows = append(rows, v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.sessions_unavailable"))))
		}
		return rows
	case "identity":
		rows := []layout.Widget{v.labelRow(appui.Text(v.locale, "workspace.identity_body")), func(gtx layout.Context) layout.Dimensions { return v.statusCard(gtx, s) }}
		if flow.Stage != "ready" && !strings.HasPrefix(flow.Stage, "node-") && flow.Stage != "pair-recovery" {
			rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
				children := v.contentRows(s, flow, true, false, nil, false, true)
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
		rows := []layout.Widget{v.sectionCard(func(gtx layout.Context) layout.Dimensions {
			items := v.hubConnectionRows(s)
			children := make([]layout.FlexChild, 0, len(items))
			for _, item := range items {
				children = append(children, layout.Rigid(item))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		}),
			v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.settings_body"))),
			v.sectionCard(v.labelRow(appui.Text(v.locale, "workspace.storage_body"))),
		}
		if hasAction(s, appcore.ActionLogout) {
			rows = append(rows, v.actionButton(appcore.ActionLogout, appui.Text(v.locale, "account.logout"), s))
		}
		if hasAction(s, appcore.ActionUnbindApp) {
			rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
				items := v.appBindingRows(s, appcore.ActionUnbindApp)
				children := make([]layout.FlexChild, 0, len(items))
				for _, item := range items {
					children = append(children, layout.Rigid(item))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
			}))
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
		rows = append(rows, v.sectionCard(v.disclosure("settings/preview", func(gtx layout.Context) layout.Dimensions {
			var objects []appui.CanvasObject
			if v.preview {
				objects = appui.PreviewCanvasObjects()
			}
			return v.canvasSection(appcore.Snapshot{}, false, objects, v.preview)(gtx)
		}, "workspace.advanced", "workspace.hide_advanced")))
		return rows
	}
	rows := []layout.Widget{v.labelRow(appui.Text(v.locale, "workspace.overview_body"))}
	if domain := appui.LocalCollaborationFlow(s, time.Now()); domain.Visible {
		rows = append(rows, v.sectionCard(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(v.headingRow(appui.Text(v.locale, "local_collaboration.title"))),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, "local_collaboration."+domain.Stage))),
				layout.Rigid(v.workspaceLink("devices", appui.Text(v.locale, "workspace.view_device"))),
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
		address := s.Hub.Address
		if address == "" {
			address = s.Hub.Origin
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(v.headingRow(appui.Text(v.locale, "workspace.hub_verified"))),
			layout.Rigid(v.nodeCaption(safeDisplay(address, 256))),
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
	case s.ThreadGroups.Pending && appcore.ThreadGroupsVisible(s, time.Now()):
		page, message = "sessions", "groups.pending"
	case s.LocalCollaboration.Pending:
		page, message = "devices", "local_collaboration.pending"
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
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: 8, Bottom: 12}.Layout(gtx, content)
	}
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
		return layout.Inset{Top: unit.Dp(12), Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions { return v.secondaryButton(gtx, button, label, true) })
	}
}

func (v *view) disclosure(key string, body layout.Widget, captions ...string) layout.Widget {
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
		closedLabel, openLabel := "workspace.details", "workspace.hide_details"
		if len(captions) == 2 {
			closedLabel, openLabel = captions[0], captions[1]
		}
		label := appui.Text(v.locale, closedLabel)
		if state.open {
			label = appui.Text(v.locale, openLabel)
		}
		style := material.Button(v.theme, &state.button, label)
		style.TextSize, style.Background, style.Color = unit.Sp(12), color.NRGBA{}, mutedInk
		style.Inset = layout.Inset{Top: 8, Bottom: 8}
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
