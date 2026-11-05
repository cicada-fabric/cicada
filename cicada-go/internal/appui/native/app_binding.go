package native

import (
	"gioui.org/layout"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) appBindingRows(s appcore.Snapshot, kind appcore.ActionKind, includeActions ...bool) []layout.Widget {
	rows := []layout.Widget{v.headingRow(appui.Text(v.locale, "binding.title"))}
	body, caption, consent := "binding.unbind_body", "binding.unbind", "binding.unbind_consent"
	if kind == appcore.ActionRebindApp {
		body, caption, consent = "binding.unbound_body", "binding.rebind", "binding.rebind_consent"
	}
	if kind == appcore.ActionRecoverAppBinding {
		body, caption = "binding.pending", "binding.recover"
	}
	if s.Hub.Address != "" {
		rows = append(rows, v.labelRow(s.Hub.Address))
	}
	rows = append(rows, v.labelRow(appui.Text(v.locale, body)))
	if kind != appcore.ActionRecoverAppBinding {
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			if v.appBindingReview != s.AppBinding.ReviewID {
				v.appBindingReview = s.AppBinding.ReviewID
				v.appBindingConsent.Value = false
			}
			if v.busy.Load() || !hasAction(s, kind) {
				gtx = gtx.Disabled()
			}
			return material.CheckBox(v.theme, &v.appBindingConsent, appui.Text(v.locale, consent)).Layout(gtx)
		})
	}
	if hasAction(s, kind) && (len(includeActions) == 0 || includeActions[0]) {
		rows = append(rows, v.actionButton(kind, appui.Text(v.locale, caption), s))
	}
	return rows
}
