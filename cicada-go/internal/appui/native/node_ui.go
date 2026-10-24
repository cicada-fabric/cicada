//go:build windows

package native

import (
	"image/color"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) legacyNodeSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		flow := appui.NodeFlow(s)
		updating := v.updates.showingProgress(s, time.Now())
		if updating {
			flow = appui.NodeSetupFlow{Stage: "bound"}
		}
		reviewID := ""
		if s.Node.Candidate != nil {
			reviewID = s.Node.Candidate.ReviewID
		}
		if v.nodeReviewID != reviewID {
			v.nodeReviewID = reviewID
			v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
			v.nodePinDetails = true
		}
		var rows []layout.FlexChild
		if b := s.Node.Binding; b != nil {
			name := safeDisplay(b.Name, 128)
			if name == "" {
				name = appui.Text(v.locale, "node.section")
			}
			rows = append(rows, layout.Rigid(v.headingRow(name)),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, "node.saved_connection"))),
				layout.Rigid(v.nodeCaption(appui.Text(v.locale, "node.saved_connection_body"))))
		} else {
			rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, "node.section"))))
		}
		var identityRows []layout.FlexChild
		for _, field := range appui.NodePublicFields(s, time.Now()) {
			if field.Key == "node.fingerprint" || field.Key == "node.hub_fingerprint" {
				continue // Shown under the existing fingerprint detail control.
			}
			identityRows = append(identityRows, layout.Rigid(v.publicFieldRow("node/"+field.Key, field)))
		}
		if flow.Consent {
			rows = append(rows, identityRows...)
		} else if len(identityRows) != 0 {
			rows = append(rows, layout.Rigid(v.disclosure("node-identity/"+reviewID, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, identityRows...)
			})))
		}
		if s.Node.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, s.Node.ErrorCode))))
		}
		switch flow.Stage {
		case "code":
			if flow.Notice != "" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, flow.Notice))))
			}
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "node.intro"))), layout.Rigid(v.editorRow(&v.nodeCode, appui.Text(v.locale, "node.code"), false)))
		case "review", "review-expired":
			c := s.Node.Candidate
			reviewKey, scopeKey, consentKey := "node.review", "node.scope", "node.access_consent"
			if c.StatusOnly {
				reviewKey, scopeKey, consentKey = "node.review_status", "node.status_scope", "node.status_consent"
			}
			rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, reviewKey))))
			if flow.Stage == "review-expired" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, flow.Notice))))
			}
			for _, field := range []struct{ key, value string }{
				{"node.name", safeDisplay(c.Name, 128)},
				{"node.candidate_until", displayNodeTime(c.ExpiresAt)}, {"node.access_until", displayNodeTime(c.AuthorizationExpiresAt)},
			} {
				if field.value != "" {
					rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, field.key)+": "+field.value)))
				}
			}
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if v.nodePinButton.Clicked(gtx) {
					v.nodePinDetails = !v.nodePinDetails
					v.window.Invalidate()
				}
				style := material.Button(v.theme, &v.nodePinButton, appui.Text(v.locale, "node.fingerprints"))
				style.Background, style.Color = color.NRGBA{}, v.theme.ContrastBg
				return style.Layout(gtx)
			}))
			if v.nodePinDetails || flow.Consent {
				for _, field := range appui.NodePublicFields(s, time.Now()) {
					if field.Key == "node.fingerprint" || field.Key == "node.hub_fingerprint" {
						rows = append(rows, layout.Rigid(v.publicFieldRow("node/"+field.Key, field)))
					}
				}
			}
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, scopeKey))))
			if flow.Consent && !c.StatusOnly {
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.busy.Load() {
						gtx = gtx.Disabled()
					}
					return material.CheckBox(v.theme, &v.nodeIdentityConsent, appui.Text(v.locale, "node.identity_consent")).Layout(gtx)
				}))
			}
			if flow.Consent {
				rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.busy.Load() {
						gtx = gtx.Disabled()
					}
					return material.CheckBox(v.theme, &v.nodeAccessConsent, appui.Text(v.locale, consentKey)).Layout(gtx)
				}))
			}
		case "account-recovery":
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "node.account_recovery"))))
		case "recovery":
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "node.recovery"))))
		case "bound":
			key := appui.NodeStatusMessage(s)
			if updating {
				key = "node.updating_status"
			}
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "node.connection_status"))), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Body1(v.theme, appui.Text(v.locale, key))
				switch key {
				case "node.online":
					label.Color = color.NRGBA{R: 25, G: 119, B: 84, A: 255}
				case "node.stale", "node.offline":
					label.Color = color.NRGBA{R: 145, G: 103, B: 39, A: 255}
				default:
					label.Color = color.NRGBA{R: 103, G: 127, B: 140, A: 255}
				}
				return label.Layout(gtx)
			}))
			accessKey := map[string]string{"ACTIVE": "node.access_active", "EXPIRED": "node.access_expired", "REVOKED": "node.access_revoked", "SESSION_ENDED": "node.session_ended", "CANCELLED": "node.access_ended"}[s.Node.Access.State]
			if !s.Node.Access.Confirmed && accessKey == "node.access_active" {
				accessKey = ""
			}
			if accessKey == "" {
				accessKey = "node.access_unconfirmed"
			}
			if updating {
				accessKey = "node.checking_status_access"
			}
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "node.status_access"))), layout.Rigid(v.labelRow(appui.Text(v.locale, accessKey))))
			times := []struct{ key, value string }{{"node.access_until", displayNodeTime(s.Node.Access.ExpiresAt)}}
			if appui.NodeObservationVisible(s) {
				times = append(times, struct{ key, value string }{"node.observed_at", displayNodeTime(s.Node.Connectivity.ObservedAt)}, struct{ key, value string }{"node.last_heartbeat", displayNodeTime(s.Node.Connectivity.LastHeartbeatAt)})
			}
			for _, field := range times {
				if field.value != "" {
					rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, field.key)+": "+field.value)))
				}
			}
		default:
			key := flow.Notice
			if key == "" {
				key = "node.unavailable"
			}
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, key))))
		}
		if flow.Primary != "" {
			label := v.nodeActionLabel(flow.Primary)
			if flow.Primary == appcore.ActionRefreshNode && s.Node.Binding != nil && !s.Node.Access.Confirmed {
				label = appui.Text(v.locale, "node.check_access")
			}
			if flow.Primary == appcore.ActionApproveNode && s.Node.Candidate != nil && s.Node.Candidate.StatusOnly {
				label = appui.Text(v.locale, "node.authorize_status")
			}
			rows = append(rows, layout.Rigid(v.actionButton(flow.Primary, label, s)))
		}
		for _, kind := range flow.Secondary {
			label := v.nodeActionLabel(kind)
			if kind == appcore.ActionCancelNodeAccess && flow.Stage == "review" {
				label = appui.Text(v.locale, "node.cancel_review")
			}
			rows = append(rows, layout.Rigid(v.actionButton(kind, label, s)))
		}
		return layout.Inset{Top: 24, Bottom: 16}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			spaced := make([]layout.FlexChild, 0, len(rows)*2)
			for i, row := range rows {
				if i != 0 {
					spaced = append(spaced, layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout))
				}
				spaced = append(spaced, row)
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, spaced...)
		})
	}
}

func (v *view) nodeCaption(label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		style := material.Body2(v.theme, label)
		style.Color = color.NRGBA{R: 103, G: 127, B: 140, A: 255}
		return style.Layout(gtx)
	}
}

func (v *view) nodeActionLabel(kind appcore.ActionKind) string {
	key := map[appcore.ActionKind]string{appcore.ActionPreviewNode: "node.preview", appcore.ActionApproveNode: "node.approve", appcore.ActionRefreshNode: "node.refresh", appcore.ActionRecoverNode: "node.recover", appcore.ActionCancelNodeAccess: "node.end_access", appcore.ActionReauthorizeNodeStatus: "node.reauthorize_status"}[kind]
	return appui.Text(v.locale, key)
}

func (v *view) nodeActionEnabled(kind appcore.ActionKind, s appcore.Snapshot) bool {
	if !hasAction(s, kind) || v.busy.Load() {
		return false
	}
	switch kind {
	case appcore.ActionPreviewNode:
		return strings.TrimSpace(v.nodeCode.Text()) != ""
	case appcore.ActionApproveNode:
		_, ok := appui.NodeApprovalAction(s, v.nodeReviewID, v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value)
		return ok
	default:
		return true
	}
}

func (v *view) nodeActionFor(kind appcore.ActionKind, s appcore.Snapshot) (appcore.Action, bool) {
	if !v.nodeActionEnabled(kind, s) {
		return appcore.Action{}, false
	}
	a := appcore.Action{Kind: kind}
	switch kind {
	case appcore.ActionPreviewNode:
		a.NodeCode = strings.TrimSpace(v.nodeCode.Text())
		v.nodeCode.SetText("")
	case appcore.ActionApproveNode:
		var ok bool
		a, ok = appui.NodeApprovalAction(s, v.nodeReviewID, v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value)
		if !ok {
			return appcore.Action{}, false
		}
		v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
	case appcore.ActionCancelNodeAccess:
		a.NodeReviewID = s.Node.Access.ReviewID
		if s.Node.Candidate != nil && (appui.NodeFlow(s).Stage == "review" || appui.NodeFlow(s).Stage == "review-expired") {
			a.NodeReviewID = s.Node.Candidate.ReviewID
		}
		if a.NodeReviewID == "" {
			return appcore.Action{}, false
		}
	}
	return a, true
}

func displayNodeTime(value string) string {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

func isNodeAction(kind appcore.ActionKind) bool {
	return kind == appcore.ActionPreviewNode || kind == appcore.ActionApproveNode || kind == appcore.ActionRefreshNode || kind == appcore.ActionRecoverNode || kind == appcore.ActionCancelNodeAccess || kind == appcore.ActionReauthorizeNodeStatus
}
