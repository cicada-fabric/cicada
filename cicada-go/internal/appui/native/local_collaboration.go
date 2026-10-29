//go:build windows

package native

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) localCollaborationSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		flow := appui.LocalCollaborationFlow(s, time.Now())
		if !flow.Visible {
			return layout.Dimensions{}
		}
		d := s.LocalCollaboration
		if v.localDomainNodeID != s.Node.Binding.NodeID {
			v.localDomainNodeID = s.Node.Binding.NodeID
			v.localDomainNetworkChoice.Value = ""
			v.localDomainNetworkName.SetText(appui.Text(v.locale, "local_collaboration.title"))
			v.localDomainGroupName.SetText(appui.Text(v.locale, "local_collaboration.title"))
			v.localDomainNetworkName.MaxLen, v.localDomainGroupName.MaxLen = 128, 128
			v.localDomainNetworkName.SingleLine, v.localDomainGroupName.SingleLine = true, true
			v.localDomainExpiry.Value = "until"
			v.localDomainConsent.Value, v.localDomainRevokeConsent.Value = false, false
		}
		if v.localDomainReviewID != d.ReviewID {
			v.localDomainReviewID = d.ReviewID
			v.localDomainConsent.Value = false
		}
		if v.localDomainStateReviewID != d.StateReviewID {
			v.localDomainStateReviewID = d.StateReviewID
			v.localDomainRevokeConsent.Value = false
		}
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "local_collaboration.title"))),
			layout.Rigid(v.labelRow(safeDisplay(s.Node.Binding.Name, 128))),
			layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.scope"))),
			layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration."+flow.Stage)))}
		if d.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, d.ErrorCode))))
		}
		if flow.Recover {
			rows = append(rows, layout.Rigid(v.localCollaborationButton(s, appcore.ActionRecoverLocalCollaboration, "local_collaboration.recover", true)))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		if d.NetworkName != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.network_name")+": "+safeDisplay(d.NetworkName, 128))))
		}
		if d.GroupName != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.group_name")+": "+safeDisplay(d.GroupName, 128))))
		}
		if d.PolicyID != "" {
			until := appui.Text(v.locale, "local_collaboration.until_revoked")
			if d.ExpiresAt != "" {
				until = displayNodeTime(d.ExpiresAt)
			}
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.until")+": "+until)),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, "local_collaboration.independent"))),
				layout.Rigid(v.disclosure("local-collaboration/"+d.PolicyID, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("local-collaboration/", appui.LocalCollaborationPublicFields(s, time.Now()))...)
				})))
		}
		if flow.Prepare && (flow.Stage == "unconfigured" || flow.Stage == "expired" || flow.Stage == "revoked") {
			rows = append(rows, v.localNetworkChoices(s)...)
			if v.localDomainNetworkChoice.Value == "" {
				rows = append(rows, layout.Rigid(v.editorRow(&v.localDomainNetworkName, appui.Text(v.locale, "local_collaboration.network_name"), false)))
			}
			rows = append(rows,
				layout.Rigid(v.disclosure("local-collaboration/prepare", func(gtx layout.Context) layout.Dimensions {
					return v.editorRow(&v.localDomainGroupName, appui.Text(v.locale, "local_collaboration.group_name"), false)(gtx)
				})), layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.until"))))
			for _, choice := range []struct{ value, key string }{{"until", "until_revoked"}, {"day", "day"}, {"week", "week"}, {"month", "month"}} {
				choice := choice
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.RadioButton(v.theme, &v.localDomainExpiry, choice.value, appui.Text(v.locale, "local_collaboration."+choice.key)).Layout(gtx)
				}))
			}
			_, selectionValid := appui.LocalCollaborationSelection(s, v.localDomainNetworkChoice.Value, v.localDomainNetworkName.Text(), v.localDomainGroupName.Text(), 0)
			rows = append(rows, layout.Rigid(v.localCollaborationButton(s, appcore.ActionPrepareLocalCollaboration, "local_collaboration.prepare", selectionValid)))
		}
		if flow.Activate {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "local_collaboration.review_body"))),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.CheckBox(v.theme, &v.localDomainConsent, appui.Text(v.locale, "local_collaboration.consent")).Layout(gtx)
				}),
				layout.Rigid(v.localCollaborationButton(s, appcore.ActionActivateLocalCollaboration, "local_collaboration.activate", v.localDomainConsent.Value)))
		}
		if flow.Revoke {
			rows = append(rows, layout.Rigid(v.disclosure("local-collaboration/revoke/"+d.PolicyID, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return material.CheckBox(v.theme, &v.localDomainRevokeConsent, appui.Text(v.locale, "local_collaboration.revoke_consent")).Layout(gtx)
					}),
					layout.Rigid(v.localCollaborationButton(s, appcore.ActionRevokeLocalCollaboration, "local_collaboration.revoke", v.localDomainRevokeConsent.Value)))
			})))
		}
		if flow.Refresh {
			rows = append(rows, layout.Rigid(v.localCollaborationButton(s, appcore.ActionRefreshLocalCollaboration, "local_collaboration.refresh", true)))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func validLocalCollaborationName(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func (v *view) localCollaborationButton(s appcore.Snapshot, kind appcore.ActionKind, key string, allowed bool) layout.Widget {
	button := v.buttons[kind]
	if button == nil {
		button = new(widget.Clickable)
		v.buttons[kind] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := allowed && !v.busy.Load() && hasAction(s, kind)
		if button.Clicked(gtx) && enabled {
			input := appcore.LocalCollaborationAction{}
			switch kind {
			case appcore.ActionPrepareLocalCollaboration:
				var valid bool
				input, valid = appui.LocalCollaborationSelection(s, v.localDomainNetworkChoice.Value, v.localDomainNetworkName.Text(), v.localDomainGroupName.Text(), map[string]uint64{"day": 24, "week": 168, "month": 720}[v.localDomainExpiry.Value])
				if !valid {
					return v.button(gtx, button, appui.Text(v.locale, key), false)
				}
			case appcore.ActionActivateLocalCollaboration:
				input.ReviewID, input.ConfirmActivation = s.LocalCollaboration.ReviewID, v.localDomainConsent.Value
			case appcore.ActionRevokeLocalCollaboration:
				input.ReviewID, input.ConfirmRevoke = s.LocalCollaboration.StateReviewID, v.localDomainRevokeConsent.Value
			}
			v.startDispatch(appcore.Action{Kind: kind, LocalCollaboration: input})
		}
		return v.button(gtx, button, appui.Text(v.locale, key), enabled)
	}
}
