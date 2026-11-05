package native

import (
	"fmt"

	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (v *view) coordinationButton(s appcore.Snapshot, kind appcore.ActionKind, id, label string, input appcore.CoordinationAction, valid bool) layout.Widget {
	if v.workspaceButtons == nil {
		v.workspaceButtons = map[string]*widget.Clickable{}
	}
	key := "coordination/" + id + "/" + input.GestureID
	button := v.workspaceButtons[key]
	if button == nil {
		button = new(widget.Clickable)
		v.workspaceButtons[key] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := valid && !v.busy.Load() && hasAction(s, kind)
		if button.Clicked(gtx) && enabled {
			v.startDispatch(appcore.Action{Kind: kind, Coordination: input})
		}
		if kind == appcore.ActionApplyCoordination {
			return v.button(gtx, button, appui.Text(v.locale, label), enabled)
		}
		return v.secondaryButton(gtx, button, appui.Text(v.locale, label), enabled)
	}
}

func (v *view) coordinationStatusRows(s appcore.Snapshot) ([]layout.FlexChild, bool) {
	d := s.Coordination
	var rows []layout.FlexChild
	if d.ErrorCode != "" {
		rows = append(rows, layout.Rigid(v.nodeCaption(coordinationErrorText(v.locale, d.ErrorCode))))
	}
	if d.Outcome != "" {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.confirmed"))))
	}
	if d.Pending {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.pending"))))
		return rows, true
	}
	if r := d.Review; r != nil {
		if v.coordinationReviewID != r.GestureID {
			v.coordinationReviewID = r.GestureID
			v.coordinationConsent.Value = false
		}
		rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, "coord.review"))), layout.Rigid(v.labelRow(appui.Text(v.locale, "coord.change."+r.Change))))
		if r.ThreadName != "" {
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(r.ThreadName, 256))))
		}
		if r.GroupName != "" {
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(r.GroupName, 128))))
		}
		if r.Classification != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "coord.role."+r.Classification))))
		}
		if r.Change == wire.ThreadCollaborationSetClassification {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.role_hint"))))
		}
		if r.Change == wire.ThreadCollaborationEnableGroupPolicy || r.Change == wire.ThreadCollaborationCreateGroupWithPolicy {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.policy_hint"))))
		}
		if r.Slot > 0 {
			holder := safeDisplay(r.HolderName, 128)
			if holder == "" {
				holder = appui.Text(v.locale, "locks.holder_private")
			}
			rows = append(rows, layout.Rigid(v.labelRow(fmt.Sprintf("%s %d · %s", appui.Text(v.locale, "locks.slot"), r.Slot, holder))), layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.clear_hint"))))
		}
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.review_until")+": "+displayNodeTime(r.ExpiresAt))))
		if !r.CanApply {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.review_expired"))))
		}
		if len(r.Details) > 0 {
			rows = append(rows, layout.Rigid(v.disclosure("coordination/review/"+r.GestureID, func(gtx layout.Context) layout.Dimensions {
				fields := make([]appui.PublicField, 0, len(r.Details))
				for _, field := range r.Details {
					fields = append(fields, appui.PublicField{Key: field.Key, Value: field.Value})
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("coordination/review/"+r.GestureID+"/", fields)...)
			})))
		}
		return rows, true
	}
	v.coordinationReviewID = ""
	v.coordinationConsent.Value = false
	return rows, false
}

func (v *view) coordinationActionRows(s appcore.Snapshot) []layout.Widget {
	if s.Coordination.Pending {
		return []layout.Widget{v.coordinationButton(s, appcore.ActionRecoverCoordination, "recover", "coord.recover", appcore.CoordinationAction{}, true)}
	}
	r := s.Coordination.Review
	if r == nil {
		return nil
	}
	if v.coordinationReviewID != r.GestureID {
		v.coordinationReviewID = r.GestureID
		v.coordinationConsent.Value = false
	}
	return []layout.Widget{
		func(gtx layout.Context) layout.Dimensions {
			return material.CheckBox(v.theme, &v.coordinationConsent, appui.Text(v.locale, "coord.consent")).Layout(gtx)
		},
		func(gtx layout.Context) layout.Dimensions {
			return v.coordinationButton(s, appcore.ActionApplyCoordination, "apply/"+r.GestureID, "coord.apply", appcore.CoordinationAction{GestureID: r.GestureID, Confirm: v.coordinationConsent.Value}, r.CanApply && v.coordinationConsent.Value)(gtx)
		},
		v.coordinationButton(s, appcore.ActionDismissCoordination, "dismiss/"+r.GestureID, "groups.back", appcore.CoordinationAction{GestureID: r.GestureID}, true),
	}
}

func (v *view) threadClassificationRows(s appcore.Snapshot) []layout.FlexChild {
	t := s.ThreadGroups.Selected
	if t == nil {
		return nil
	}
	var rows []layout.FlexChild
	if t.CanReadClassification {
		rows = append(rows, layout.Rigid(v.coordinationButton(s, appcore.ActionReadThreadCoordination, "read-role/"+t.EndpointID, "coord.read_role", appcore.CoordinationAction{EndpointID: t.EndpointID, GestureID: t.CoordinationGestureID}, true)))
	}
	role := t.Classification
	if role == nil {
		return rows
	}
	if !role.Current {
		return append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "locks.not_current"))))
	}
	if role.State == "NETWORK_CONFLICT" {
		return append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.network_conflict"))))
	}
	if role.State == "CLASSIFICATION_REQUIRED" {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.classification_required"))))
	} else if role.Classification != "" {
		rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "coord.role."+role.Classification))))
	}
	rows = append(rows, layout.Rigid(v.nodeCaption(fmt.Sprintf(appui.Text(v.locale, "coord.group_count"), role.ActiveGroups))))
	if !role.CanChange {
		return rows
	}
	scope := s.Hub.HubID + "/" + t.EndpointID + "/" + role.GestureID
	if v.coordinationRoleScope != scope {
		v.coordinationRoleScope = scope
		v.coordinationRole.Value = role.Classification
	}
	rows = append(rows, layout.Rigid(v.disclosure("coordination/role/"+scope, func(gtx layout.Context) layout.Dimensions {
		children := []layout.FlexChild{layout.Rigid(v.nodeCaption(appui.Text(v.locale, "coord.role_hint")))}
		for _, classification := range wire.ThreadCollaborationClassifications() {
			value := classification
			children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.RadioButton(v.theme, &v.coordinationRole, value, appui.Text(v.locale, "coord.role."+value)).Layout(gtx)
			}))
		}
		children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			value := v.coordinationRole.Value
			valid := (value == "worker" || value == "advisor" || value == "manager") && !(value == "worker" && role.ActiveGroups > 1)
			return v.coordinationButton(s, appcore.ActionPrepareCoordination, "role/"+t.EndpointID, "coord.review", appcore.CoordinationAction{Change: wire.ThreadCollaborationSetClassification, EndpointID: t.EndpointID, Classification: value, GestureID: role.GestureID}, valid)(gtx)
		}))
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
	}, "coord.change_role", "workspace.hide_details")))
	return rows
}

func coordinationErrorText(locale appui.Locale, code string) string {
	switch code {
	case "THREAD_NETWORK_CONFLICT":
		return appui.Text(locale, "coord.network_conflict")
	case "THREAD_CLASSIFICATION_REQUIRED":
		return appui.Text(locale, "coord.classification_required")
	case "WORKER_GROUP_LIMIT":
		return appui.Text(locale, "coord.worker_limit")
	case "VERSION_CONFLICT", "GENERATION_STALE", "HOLDER_MISMATCH", "REVIEW_EXPIRED", "CAS_CONFLICT":
		return appui.Text(locale, "coord.conflict")
	case "ORIGINAL_OUTCOME_UNCERTAIN":
		return appui.Text(locale, "coord.pending")
	case "UNSUPPORTED_PROFILE":
		return appui.Text(locale, "groups.unavailable")
	case "AUTHORIZATION_REQUIRED", "OWNER_AUTHORITY_REQUIRED", "GROUP_LOCK_POLICY_REQUIRED":
		return appui.Text(locale, "coord.authorization_required")
	default:
		return appui.Text(locale, "common.request_failed")
	}
}
