//go:build windows

package native

import (
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func (v *view) threadGroupsSection(s appcore.Snapshot) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if !appcore.ThreadGroupsVisible(s, time.Now()) {
			return layout.Dimensions{}
		}
		d := s.ThreadGroups
		scope := s.Hub.HubID + "/" + s.Account.OwnerID + "/" + s.Account.DeviceID + "/" + d.NodeID + "/" + d.NetworkID
		if v.threadGroupsScope != scope {
			v.threadGroupsScope = scope
			v.threadGroupName.SetText("")
			v.threadGroupSearch.SetText("")
			v.threadGroupDuration.Value = "until_revoked"
			v.threadGroupConsent.Value = false
		}
		reviewID := ""
		if d.Review != nil {
			reviewID = d.Review.GestureID
		}
		if v.threadGroupReviewID != reviewID {
			v.threadGroupReviewID = reviewID
			v.threadGroupConsent.Value = false
		}
		rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "groups.title")))}
		nodeName, networkName := d.NodeName, d.NetworkName
		if d.Review != nil {
			nodeName, networkName = d.Review.NodeName, d.Review.NetworkName
		}
		rows = append(rows, v.publicFieldRows("groups/scope/", []appui.PublicField{
			{Key: "node.name", Value: safeDisplay(nodeName, 128)},
			{Key: "groups.network", Value: safeDisplay(networkName, 128)},
		})...)
		if d.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(threadGroupErrorText(v.locale, d.ErrorCode))))
		}
		if d.Pending {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.pending"))),
				layout.Rigid(v.threadGroupButton(s, appcore.ActionRecoverThreadGroup, "recover", "groups.recover", appcore.ThreadGroupAction{}, true)))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		if d.AvailabilityKnown && !d.Available {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.unavailable"))))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		if d.Review != nil {
			return v.threadGroupReview(gtx, s, rows)
		}
		rows = append(rows, layout.Rigid(v.threadGroupButton(s, appcore.ActionReadThreadGroups, "read", "groups.refresh", appcore.ThreadGroupAction{GestureID: d.GestureID}, true)))
		if d.Outcome != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.outcome."+d.Outcome))))
		}
		if !d.Current {
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.stale"))))
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
		}
		if len(d.Threads) != 0 {
			v.threadGroupSearch.SingleLine, v.threadGroupSearch.MaxLen = true, 128
			rows = append(rows, layout.Rigid(v.editorRow(&v.threadGroupSearch, appui.Text(v.locale, "groups.filter"), false)))
		}
		query := strings.ToLower(strings.TrimSpace(v.threadGroupSearch.Text()))
		for _, thread := range d.Threads {
			thread := thread
			if query != "" && !strings.Contains(strings.ToLower(thread.Name+" "+thread.Workspace+" "+d.NodeName), query) {
				continue
			}
			rows = append(rows, layout.Rigid(v.headingRow(safeDisplay(thread.Name, 256))),
				layout.Rigid(v.nodeCaption(safeDisplay(thread.Workspace, 1024))),
				layout.Rigid(v.disclosure("groups/thread/"+thread.EndpointID, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("groups/thread/"+thread.EndpointID+"/", []appui.PublicField{{Key: "directory.endpoint_id", Value: thread.EndpointID}, {Key: "directory.harness", Value: thread.Harness}, {Key: "node.id", Value: d.NodeID}})...)
				})),
				layout.Rigid(v.threadGroupButton(s, appcore.ActionReadThreadRelations, "thread/"+thread.EndpointID, "groups.view", appcore.ThreadGroupAction{GestureID: thread.GestureID, EndpointID: thread.EndpointID}, true)))
		}
		if d.ThreadsNextCursor != "" {
			rows = append(rows, layout.Rigid(v.threadGroupButton(s, appcore.ActionReadThreadGroups, "threads-next", "groups.more_threads", appcore.ThreadGroupAction{GestureID: d.GestureID, Cursor: d.ThreadsNextCursor}, true)))
		}
		if d.Selected != nil {
			rows = append(rows, v.threadGroupRelations(s)...)
		}
		if d.Current && len(d.Threads) == 0 {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.no_threads"))))
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	}
}

func (v *view) threadGroupRelations(s appcore.Snapshot) []layout.FlexChild {
	d, t := s.ThreadGroups, s.ThreadGroups.Selected
	rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "groups.memberships")))}
	rows = append(rows, v.publicFieldRows("groups/selected/", []appui.PublicField{
		{Key: "directory.name", Value: safeDisplay(t.Name, 256)},
		{Key: "directory.workspace", Value: safeDisplay(t.Workspace, 1024)},
	})...)
	rows = append(rows, layout.Rigid(v.disclosure("groups/selected-details/"+t.EndpointID, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("groups/selected/details/", []appui.PublicField{
			{Key: "directory.endpoint_id", Value: t.EndpointID}, {Key: "directory.harness", Value: t.Harness},
			{Key: "node.id", Value: d.NodeID}, {Key: "groups.network_id", Value: d.NetworkID},
			{Key: "groups.captured", Value: displayNodeTime(d.CapturedAt)},
		})...)
	})))
	for _, relation := range t.Relations {
		r := relation
		rows = append(rows, layout.Rigid(v.headingRow(safeDisplay(r.Name, 128))),
			layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.state."+r.State))))
		if r.State == "ACTIVE" {
			until := appui.Text(v.locale, "local_collaboration.until_revoked")
			if r.ExpiresAt != "" {
				until = displayNodeTime(r.ExpiresAt)
			}
			rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.until")+": "+until)))
		}
		rows = append(rows, layout.Rigid(v.disclosure("groups/relation/"+t.EndpointID+"/"+r.GroupID, func(gtx layout.Context) layout.Dimensions {
			fields := v.publicFieldRows("groups/relation/"+r.GroupID+"/", []appui.PublicField{{Key: "groups.group_id", Value: r.GroupID}})
			fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.control."+r.OwnerMode))))
			if r.DenyReason != "" && r.DenyReason != "NONE" {
				fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.deny."+r.DenyReason))))
			}
			for _, c := range r.Contributions {
				key := "groups.ineffective"
				if c.Effective {
					key = "groups.effective"
				}
				fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.source."+c.Source)+": "+appui.Text(v.locale, "groups.state."+c.State)+" · "+appui.Text(v.locale, key))))
				until := appui.Text(v.locale, "local_collaboration.until_revoked")
				if c.ExpiresAt != "" {
					until = displayNodeTime(c.ExpiresAt)
				}
				fields = append(fields, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.until")+": "+until+" · "+appui.Text(v.locale, "groups.key."+c.KeyState))))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, fields...)
		})))
		for _, c := range r.Contributions {
			if c.Source == "OWNER_EXPLICIT" && c.State == "PENDING_KEY" {
				rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.key_pending"))))
			}
		}
		if r.CanRemove {
			rows = append(rows, layout.Rigid(v.threadGroupButton(s, appcore.ActionPrepareThreadGroup, "remove/"+r.GroupID, "groups.remove", appcore.ThreadGroupAction{GestureID: r.GestureID, Change: "REMOVE_ENDPOINT", EndpointID: t.EndpointID, GroupID: r.GroupID}, true)))
		} else if r.UnavailableReason != "" {
			rows = append(rows, layout.Rigid(v.nodeCaption(threadGroupErrorText(v.locale, r.UnavailableReason))))
		}
	}
	if !t.RelationsComplete {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.partial"))),
			layout.Rigid(v.threadGroupButton(s, appcore.ActionReadThreadRelations, "relations-next", "groups.more_relations", appcore.ThreadGroupAction{GestureID: t.GestureID, EndpointID: t.EndpointID, Cursor: t.RelationsCursor}, t.RelationsCursor != "")))
	} else if len(t.Relations) == 0 {
		rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.no_relations"))))
	}
	rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.scope_hint"))),
		layout.Rigid(v.threadGroupButton(s, appcore.ActionReadGroupCandidates, "candidates", "groups.add", appcore.ThreadGroupAction{GestureID: t.GestureID, EndpointID: t.EndpointID}, true)))
	if d.NativeSelfGroups {
		rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.ai_scope_hint"))))
	}
	if d.CandidatesLoaded {
		rows = append(rows, v.threadGroupCandidates(s)...)
	}
	return rows
}

func (v *view) threadGroupCandidates(s appcore.Snapshot) []layout.FlexChild {
	d, t := s.ThreadGroups, s.ThreadGroups.Selected
	rows := []layout.FlexChild{layout.Rigid(v.headingRow(appui.Text(v.locale, "groups.candidates")))}
	for _, choice := range []struct{ value, key string }{{"until_revoked", "until_revoked"}, {"1d", "day"}, {"7d", "week"}, {"30d", "month"}} {
		choice := choice
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return material.RadioButton(v.theme, &v.threadGroupDuration, choice.value, appui.Text(v.locale, "local_collaboration."+choice.key)).Layout(gtx)
		}))
	}
	for _, candidate := range d.Candidates {
		c := candidate
		rows = append(rows, layout.Rigid(v.headingRow(safeDisplay(c.Name, 128))))
		rows = append(rows, layout.Rigid(v.disclosure("groups/candidate/"+c.GroupID, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("groups/candidate/"+c.GroupID+"/", []appui.PublicField{{Key: "groups.group_id", Value: c.GroupID}, {Key: "groups.network_id", Value: d.NetworkID}})...)
		})))
		if c.CanAdd {
			rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return v.threadGroupButton(s, appcore.ActionPrepareThreadGroup, "add/"+c.GroupID, "groups.review_add", appcore.ThreadGroupAction{GestureID: c.GestureID, Change: "ADD_ENDPOINT", EndpointID: t.EndpointID, GroupID: c.GroupID, Duration: v.threadGroupDuration.Value}, true)(gtx)
			}))
		} else if c.UnavailableReason != "" {
			rows = append(rows, layout.Rigid(v.nodeCaption(threadGroupErrorText(v.locale, c.UnavailableReason))))
		}
	}
	if d.CandidatesCursor != "" {
		rows = append(rows, layout.Rigid(v.threadGroupButton(s, appcore.ActionReadGroupCandidates, "candidate-next", "groups.more_candidates", appcore.ThreadGroupAction{GestureID: t.GestureID, EndpointID: t.EndpointID, Cursor: d.CandidatesCursor}, true)))
	}
	if d.CanCreate {
		v.threadGroupName.SingleLine, v.threadGroupName.MaxLen = true, 128
		rows = append(rows, layout.Rigid(v.editorRow(&v.threadGroupName, appui.Text(v.locale, "groups.new_name"), false)),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				name := v.threadGroupName.Text()
				return v.threadGroupButton(s, appcore.ActionPrepareThreadGroup, "create", "groups.create", appcore.ThreadGroupAction{GestureID: d.GestureID, Change: "CREATE_GROUP", Name: name}, validLocalCollaborationName(name))(gtx)
			}))
	} else if d.UnavailableReason != "" {
		rows = append(rows, layout.Rigid(v.nodeCaption(threadGroupErrorText(v.locale, d.UnavailableReason))))
	}
	return rows
}

func (v *view) threadGroupReview(gtx layout.Context, s appcore.Snapshot, rows []layout.FlexChild) layout.Dimensions {
	r := s.ThreadGroups.Review
	rows = append(rows, layout.Rigid(v.headingRow(appui.Text(v.locale, "groups.review."+r.Action))))
	rows = append(rows, v.publicFieldRows("groups/review/", []appui.PublicField{{Key: "directory.name", Value: safeDisplay(r.ThreadName, 256)}, {Key: "directory.workspace", Value: safeDisplay(r.Workspace, 1024)}, {Key: "groups.group_name", Value: safeDisplay(r.GroupName, 128)}})...)
	rows = append(rows, layout.Rigid(v.disclosure("groups/review-details/"+r.GestureID, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, v.publicFieldRows("groups/review/details/", []appui.PublicField{{Key: "groups.group_id", Value: r.GroupID}, {Key: "directory.endpoint_id", Value: r.EndpointID}, {Key: "node.id", Value: r.NodeID}, {Key: "groups.network_id", Value: r.NetworkID}, {Key: "local_collaboration.os_user", Value: r.LocalUserScope}})...)
	})))
	if r.Action == "REMOVE_ENDPOINT" {
		rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.remove_effect"))))
	} else {
		rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.memory_hint"))))
		if r.Action == "ADD_ENDPOINT" {
			until := appui.Text(v.locale, "local_collaboration.until_revoked")
			if r.PolicyExpiresAt != "" {
				until = displayNodeTime(r.PolicyExpiresAt)
			}
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.grant_effect"))), layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.until")+": "+until)))
		} else {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "groups.create_effect"))))
		}
	}
	rows = append(rows, layout.Rigid(v.nodeCaption(appui.Text(v.locale, "groups.review_until")+": "+displayNodeTime(r.ExpiresAt))),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return material.CheckBox(v.theme, &v.threadGroupConsent, appui.Text(v.locale, "groups.consent")).Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return v.threadGroupButton(s, appcore.ActionApplyThreadGroup, "apply/"+r.GestureID, "groups.apply", appcore.ThreadGroupAction{GestureID: r.GestureID, Confirm: v.threadGroupConsent.Value}, v.threadGroupConsent.Value)(gtx)
		}),
		layout.Rigid(v.threadGroupButton(s, appcore.ActionDismissThreadGroup, "dismiss/"+r.GestureID, "groups.back", appcore.ThreadGroupAction{GestureID: r.GestureID}, true)))
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
}

func (v *view) threadGroupButton(s appcore.Snapshot, kind appcore.ActionKind, id, label string, input appcore.ThreadGroupAction, valid bool) layout.Widget {
	key := "groups/" + id + "/" + input.GestureID
	button := v.workspaceButtons[key]
	if button == nil {
		button = new(widget.Clickable)
		v.workspaceButtons[key] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := valid && !v.busy.Load() && hasAction(s, kind)
		if button.Clicked(gtx) && enabled {
			v.startDispatch(appcore.Action{Kind: kind, ThreadGroups: input})
		}
		return v.button(gtx, button, appui.Text(v.locale, label), enabled)
	}
}

func threadGroupErrorText(locale appui.Locale, code string) string {
	switch code {
	case "REVIEW_EXPIRED", "CAS_CONFLICT", "KEY_NOT_READY", "OWNER_READD_REQUIRED", "GROUP_RELATION_LIMIT", "SHARED_MEMBERSHIP_CONFLICT", "CURSOR_STALE", "MANUAL_SOURCE_ALREADY_ACTIVE", "RELATION_PENDING", "OUTCOME_UNCERTAIN", "TARGET_NOT_AUTHORIZED", "UNSUPPORTED_PROFILE":
		return appui.Text(locale, "groups.error."+code)
	case "ORIGINAL_NOT_ADMITTED", "OWNER_AUTHORITY_REQUIRED", "ORIGINAL_PACKET_CONFLICT", "APP_THREAD_GROUP_STORAGE_BUDGET":
		return appui.Text(locale, "groups.error."+code)
	}
	return appui.Text(locale, "common.request_failed")
}
