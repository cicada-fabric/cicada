package native

import (
	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	"strings"
)

func (v *view) hubControl(s appcore.Snapshot, kind appcore.ActionKind, caption string) layout.Widget {
	if v.profileControls == nil {
		v.profileControls = make(map[string]*widget.Clickable)
	}
	key := string(kind) + caption
	if v.profileControls[key] == nil {
		v.profileControls[key] = new(widget.Clickable)
	}
	b := v.profileControls[key]
	return func(gtx layout.Context) layout.Dimensions {
		enabled := hasAction(s, kind) && !v.busy.Load()
		if b.Clicked(gtx) && enabled {
			v.startDispatch(appcore.Action{Kind: kind})
		}
		label := caption
		if kind == appcore.ActionDiscoverProfiles && s.Hub.Verified {
			label = "connection.manage_disconnect"
		}
		return v.button(gtx, b, appui.Text(v.locale, label), enabled)
	}
}

func (v *view) hubConnectionRows(s appcore.Snapshot) []layout.Widget {
	rows := []layout.Widget{v.headingRow(appui.Text(v.locale, "connection.hubs")),
		v.labelRow(appui.Text(v.locale, "connection.hubs_body")),
		v.hubControl(s, appcore.ActionAddHub, "connection.add_hub")}
	if !s.Hub.Verified {
		rows = append(rows, v.hubControl(s, appcore.ActionDiscoverProfiles, "connection.refresh_hubs"))
	}
	if s.Hub.Address != "" || s.Hub.Verified {
		rows = append(rows, v.hubControl(s, appcore.ActionDisconnectHub, "connection.disconnect_hub"))
	}
	var removed []appcore.ProfileSnapshot
	for i, p := range s.Profiles {
		if p.Removed {
			removed = append(removed, p)
		} else {
			rows = append(rows, v.profileRow(p, i))
		}
	}
	if len(removed) != 0 {
		rows = append(rows, v.headingRow(appui.Text(v.locale, "connection.retained")))
		rows = append(rows, v.disclosure("hub-connections/retained", func(gtx layout.Context) layout.Dimensions {
			items := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "connection.retained"))), layout.Rigid(v.labelRow(appui.Text(v.locale, "connection.retained_body")))}
			for i, p := range removed {
				items = append(items, layout.Rigid(v.profileRow(p, i)))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, items...)
		}))
	}
	return rows
}

func (v *view) hubProfileRow(p appcore.ProfileSnapshot, index int) layout.Widget {
	if v.profileControls == nil {
		v.profileControls = make(map[string]*widget.Clickable)
	}
	button := func(name string) *widget.Clickable {
		key := p.ID + "/" + name
		if v.profileControls[key] == nil {
			v.profileControls[key] = new(widget.Clickable)
		}
		return v.profileControls[key]
	}
	resume, remove, confirm, cancel := button("resume"), button("remove"), button("confirm"), button("cancel")
	return func(gtx layout.Context) layout.Dimensions {
		var address *widget.Editor
		if p.Direct {
			if v.profileAddresses == nil {
				v.profileAddresses = make(map[string]*widget.Editor)
			}
			address = v.profileAddresses[p.ID]
			if address == nil {
				address = new(widget.Editor)
				address.SingleLine, address.MaxLen = true, 128
				v.profileAddresses[p.ID] = address
			}
		}
		if resume.Clicked(gtx) && !v.busy.Load() {
			kind := appcore.ActionResumeProfile
			if p.Removed {
				kind = appcore.ActionRestoreProfile
			}
			a := appcore.Action{Kind: kind, ProfileID: p.ID, ProfileReviewID: p.ReviewID}
			if address != nil {
				a.HubAddress = strings.TrimSpace(address.Text())
			}
			v.startDispatch(a)
		}
		if remove.Clicked(gtx) && !v.busy.Load() {
			v.profileRemovalID, v.profileRemovalReview = p.ID, p.ReviewID
			v.profileRemoveConsent.Value = false
		}
		if cancel.Clicked(gtx) {
			v.profileRemovalID = ""
			v.profileRemoveConsent.Value = false
		}
		if confirm.Clicked(gtx) && !v.busy.Load() && v.profileRemoveConsent.Value && v.profileRemovalID == p.ID && v.profileRemovalReview == p.ReviewID {
			v.profileRemovalID = ""
			v.startDispatch(appcore.Action{Kind: appcore.ActionRemoveProfile, ProfileID: p.ID, ProfileReviewID: p.ReviewID, ConfirmProfileRemoval: true})
		}
		return v.card(gtx, func(gtx layout.Context) layout.Dimensions {
			title := p.Address
			if title == "" {
				title = appui.SavedConnectionLabel(v.locale, index)
			}
			items := []layout.FlexChild{layout.Rigid(v.headingRow(title))}
			if p.Current {
				items = append(items, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "connection.current_hub"))))
			}
			label := "connection.switch_hub"
			if p.Removed {
				label = "connection.restore_hub"
				items = append(items, layout.Rigid(v.labelRow(appui.Text(v.locale, "connection.retained_body"))))
			}
			items = append(items, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return v.button(gtx, resume, appui.Text(v.locale, label), !v.busy.Load())
			}))
			items = append(items, layout.Rigid(v.disclosure("hub/"+p.ID, func(gtx layout.Context) layout.Dimensions {
				fields := v.publicFieldRows("hub/"+p.ID, []appui.PublicField{{Key: "connection.hub_id", Value: p.HubID}, {Key: "connection.hub_fingerprint", Value: p.Fingerprint}})
				if address != nil {
					fields = append(fields, layout.Rigid(v.editorRow(address, appui.Text(v.locale, "connection.saved_address_override"), false)))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, fields...)
			})))
			if !p.Removed {
				items = append(items, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return v.button(gtx, remove, appui.Text(v.locale, "connection.remove_hub"), !v.busy.Load())
				}))
			}
			if !p.Removed && v.profileRemovalID == p.ID && v.profileRemovalReview == p.ReviewID {
				items = append(items, layout.Rigid(v.labelRow(appui.Text(v.locale, "connection.remove_body"))), layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return material.CheckBox(v.theme, &v.profileRemoveConsent, appui.Text(v.locale, "connection.remove_confirm")).Layout(gtx)
				}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return v.button(gtx, confirm, appui.Text(v.locale, "connection.remove_hub"), v.profileRemoveConsent.Value && !v.busy.Load())
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return v.button(gtx, cancel, appui.Text(v.locale, "common.cancel"), !v.busy.Load())
					}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, items...)
		})
	}
}
