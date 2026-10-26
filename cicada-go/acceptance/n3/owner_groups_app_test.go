package n3_test

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// A private UI projection of the actual Controller Snapshot. The acceptance
// branch can compile while the independently delivered consumer is pending.
// Missing product fields are errors, never a substitute implementation or a
// positive fixture. Every gesture and target comes from an actual Core card.
type ownerGroupsPanel struct {
	AvailabilityKnown, Available, Current, Pending bool
	NodeID, NetworkID, GestureID, ErrorCode        string
	CapturedAt, FreshUntil, Outcome                string
	CanCreate                                      bool
	Threads                                        []ownerGroupsThreadCard
	ThreadsNextCursor                              string
	Selected                                       *ownerGroupsThreadCard
	Candidates                                     []ownerGroupsCandidateCard
	CandidatesLoaded                               bool
	CandidatesCursor                               string
	Review                                         *ownerGroupsReviewCard
}

type ownerGroupsThreadCard struct {
	EndpointID, Name, Workspace, Harness, GestureID string
	Relations                                       []ownerGroupsRelationCard
	RelationsComplete                               bool
	RelationsCursor                                 string
}

type ownerGroupsRelationCard struct {
	GroupID, Name, State, KeyState, ExpiresAt string
	OwnerMode, DenyReason, GestureID          string
	CanRemove                                 bool
	Contributions                             []ownerGroupsContributionCard
}

type ownerGroupsContributionCard struct {
	Source, State, KeyState, ExpiresAt string
	Effective                          bool
}

type ownerGroupsCandidateCard struct {
	GroupID, Name, GestureID, UnavailableReason string
	CanAdd                                      bool
}

type ownerGroupsReviewCard struct {
	GestureID, Action, ThreadName, Workspace, GroupName string
	ExpiresAt, PolicyExpiresAt, Duration                string
}

type ownerGroupsGesture struct {
	GestureID, EndpointID, GroupID, Cursor string
	Change, Name, Duration                 string
	Confirm                                bool
}

func actualOwnerGroupsPanel(t *testing.T, snapshot appcore.Snapshot) ownerGroupsPanel {
	t.Helper()
	var top map[string]json.RawMessage
	if json.Unmarshal(must(json.Marshal(snapshot)), &top) != nil || len(top["thread_groups"]) == 0 || string(top["thread_groups"]) == "null" {
		t.Fatal("actual App consumer has no ThreadGroups snapshot; no fixture may synthesize it")
	}
	var panel ownerGroupsPanel
	if json.Unmarshal(top["thread_groups"], &panel) != nil {
		t.Fatal("actual App ThreadGroups projection is malformed")
	}
	return panel
}

func actualOwnerGroupsAction(t *testing.T, kind string, input ownerGroupsGesture) appcore.Action {
	t.Helper()
	raw := must(json.Marshal(struct {
		Kind         string
		ThreadGroups ownerGroupsGesture
	}{kind, input}))
	defer clear(raw)
	var action appcore.Action
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&action) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("actual App consumer has not delivered the exact Group action; unknown fields cannot be ignored")
	}
	return action
}

func ownerGroupsAppGesture(t *testing.T, v *codexProductFixture, kind string, input ownerGroupsGesture) (appActorReply, ownerGroupsPanel, []exchange) {
	t.Helper()
	action := actualOwnerGroupsAction(t, kind, input)
	reply, trace := performOwnerGroupsAppAction(t, v, action)
	s := reply.Current
	if s.Hub.Fingerprint != v.original.Hub.Fingerprint || s.Account.OwnerID != v.original.Account.OwnerID ||
		s.Account.DeviceID != v.original.Account.DeviceID || s.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID ||
		s.Account.OwnerFingerprint != v.original.Account.OwnerFingerprint || s.Management != appcore.ManagementUnavailable {
		t.Fatal("actual Group action changed the original App/Owner identity or claimed general management")
	}
	panel := actualOwnerGroupsPanel(t, s)
	if panel.NodeID != v.actualNode.id || panel.NetworkID == "" {
		t.Fatal("actual Group action changed the original Node/Network scope")
	}
	return reply, panel, trace
}

func requireOwnerGroupsCurrent(t *testing.T, v *codexProductFixture, panel ownerGroupsPanel) {
	t.Helper()
	deadline, err := time.Parse(time.RFC3339Nano, panel.FreshUntil)
	captured, capturedErr := time.Parse(time.RFC3339Nano, panel.CapturedAt)
	if !panel.AvailabilityKnown || !panel.Available || !panel.Current || panel.Pending || panel.ErrorCode != "" ||
		panel.NodeID != v.actualNode.id || panel.NetworkID == "" || panel.GestureID == "" ||
		err != nil || capturedErr != nil || !time.Now().Before(deadline) || captured.After(time.Now().Add(30*time.Second)) {
		t.Fatal("actual App lacks a fresh authenticated Group card in its original scope")
	}
}

func refreshOwnerGroups(t *testing.T, v *codexProductFixture, network string) ownerGroupsPanel {
	t.Helper()
	panel := actualOwnerGroupsPanel(t, v.command(t, appActorCommand{}).Current)
	if panel.Pending || panel.Review != nil || panel.GestureID == "" {
		t.Fatal("fresh Group read would displace an original request or an undismissed review")
	}
	seen := make(map[string]bool)
	cursor := ""
	for page := 0; page < 8; page++ {
		reply, next, _ := ownerGroupsAppGesture(t, v, "READ_THREAD_GROUPS", ownerGroupsGesture{GestureID: panel.GestureID, Cursor: cursor})
		if reply.ActionFailed {
			t.Fatal("actual App could not read the original Thread cards")
		}
		requireOwnerGroupsCurrent(t, v, next)
		if next.NetworkID != network {
			t.Fatal("actual Thread read changed its exact original Network")
		}
		panel = next
		cursor = panel.ThreadsNextCursor
		if cursor == "" {
			return panel
		}
		if seen[cursor] {
			t.Fatal("actual Thread pagination repeated a cursor")
		}
		seen[cursor] = true
	}
	t.Fatal("actual Thread pagination exceeded the isolated fixture bound")
	return ownerGroupsPanel{}
}

func selectOwnerGroupsThread(t *testing.T, v *codexProductFixture, network string, identity ownerGroupsIdentity) ownerGroupsPanel {
	t.Helper()
	panel := refreshOwnerGroups(t, v, network)
	var selected *ownerGroupsThreadCard
	for i := range panel.Threads {
		if panel.Threads[i].EndpointID == identity.Endpoint {
			if selected != nil {
				t.Fatal("actual private directory repeated the exact Endpoint")
			}
			selected = &panel.Threads[i]
		}
	}
	if selected == nil || selected.Workspace != identity.Workspace || selected.Harness != "codex" || selected.GestureID == "" {
		t.Fatal("actual App card does not match the original native Endpoint/workspace")
	}
	seen := make(map[string]bool)
	cursor := ""
	for page := 0; page < 8; page++ {
		reply, next, _ := ownerGroupsAppGesture(t, v, "READ_THREAD_GROUP_RELATIONS", ownerGroupsGesture{
			GestureID: selected.GestureID, EndpointID: selected.EndpointID, Cursor: cursor})
		if reply.ActionFailed {
			t.Fatal("actual App could not read the original Endpoint's relations")
		}
		requireOwnerGroupsCurrent(t, v, next)
		if next.NetworkID != network || next.Selected == nil || next.Selected.EndpointID != identity.Endpoint || next.Selected.Workspace != identity.Workspace {
			t.Fatal("actual relation read selected another native Endpoint")
		}
		panel, selected = next, next.Selected
		cursor = selected.RelationsCursor
		if cursor == "" {
			if !selected.RelationsComplete {
				t.Fatal("actual relation page is incomplete without a continuation")
			}
			return panel
		}
		if selected.RelationsComplete || seen[cursor] {
			t.Fatal("actual relation pagination is inconsistent")
		}
		seen[cursor] = true
	}
	t.Fatal("actual relation pagination exceeded the isolated fixture bound")
	return ownerGroupsPanel{}
}

func ownerGroupsCandidates(t *testing.T, v *codexProductFixture, panel ownerGroupsPanel) ownerGroupsPanel {
	t.Helper()
	if panel.Selected == nil || !panel.Current || panel.Pending || panel.Review != nil {
		t.Fatal("actual Group candidates require the current selected native Endpoint")
	}
	endpoint, network := panel.Selected.EndpointID, panel.NetworkID
	seen := make(map[string]bool)
	cursor := ""
	for page := 0; page < 8; page++ {
		reply, next, _ := ownerGroupsAppGesture(t, v, "READ_THREAD_GROUP_CANDIDATES", ownerGroupsGesture{
			GestureID: panel.Selected.GestureID, EndpointID: endpoint, Cursor: cursor})
		if reply.ActionFailed {
			t.Fatal("actual App could not read exact Group candidates")
		}
		requireOwnerGroupsCurrent(t, v, next)
		if next.NetworkID != network || next.Selected == nil || next.Selected.EndpointID != endpoint || !next.CandidatesLoaded {
			t.Fatal("actual Group candidates changed the original selected Endpoint")
		}
		panel = next
		cursor = panel.CandidatesCursor
		if cursor == "" {
			return panel
		}
		if seen[cursor] {
			t.Fatal("actual candidate pagination repeated a cursor")
		}
		seen[cursor] = true
	}
	t.Fatal("actual candidate pagination exceeded the isolated fixture bound")
	return ownerGroupsPanel{}
}

// This prepares an actual human review only. APPLY is a separate explicit
// gesture, allowing the parent to place a TCP fault at the exact original send.
func prepareOwnerGroupsChange(t *testing.T, v *codexProductFixture, panel ownerGroupsPanel, change, group, name, duration string) ownerGroupsPanel {
	t.Helper()
	requireOwnerGroupsCurrent(t, v, panel)
	input := ownerGroupsGesture{Change: change}
	groupName, threadName, workspace := "", "", ""
	switch change {
	case wire.OwnerEndpointGroupsCreateGroup:
		if !panel.CanCreate || panel.Review != nil || name == "" || group != "" || duration != "" {
			t.Fatal("actual Group create is not currently offered")
		}
		input.GestureID, input.Name, groupName = panel.GestureID, name, name
	case wire.OwnerEndpointGroupsAddEndpoint, wire.OwnerEndpointGroupsRemoveEndpoint:
		if panel.Selected == nil || panel.Review != nil || name != "" || group == "" {
			t.Fatal("actual Group mutation lacks its original selected Endpoint")
		}
		input.EndpointID, input.GroupID = panel.Selected.EndpointID, group
		threadName, workspace = panel.Selected.Name, panel.Selected.Workspace
		if change == wire.OwnerEndpointGroupsAddEndpoint {
			if !panel.CandidatesLoaded || duration == "" {
				t.Fatal("actual add requires a fresh candidate and explicit duration")
			}
			for _, candidate := range panel.Candidates {
				if candidate.GroupID == group && candidate.CanAdd {
					if input.GestureID != "" {
						t.Fatal("actual candidate repeated an exact Group")
					}
					input.GestureID, groupName = candidate.GestureID, candidate.Name
				}
			}
			input.Duration = duration
		} else {
			if !panel.Selected.RelationsComplete || duration != "" {
				t.Fatal("actual removal requires the full exact relation card")
			}
			for _, relation := range panel.Selected.Relations {
				if relation.GroupID == group && relation.CanRemove {
					if input.GestureID != "" {
						t.Fatal("actual relation repeated an exact Group")
					}
					input.GestureID, groupName = relation.GestureID, relation.Name
				}
			}
		}
	default:
		t.Fatal("unreviewed Group mutation action")
	}
	if input.GestureID == "" || groupName == "" {
		t.Fatal("actual Core did not offer the exact requested Group mutation")
	}
	reply, next, _ := ownerGroupsAppGesture(t, v, "REVIEW_THREAD_GROUP_CHANGE", input)
	r := next.Review
	if reply.ActionFailed || next.Pending || !next.Current || next.NetworkID != panel.NetworkID || r == nil ||
		r.GestureID == "" || r.Action != change || r.ThreadName != threadName || r.Workspace != workspace ||
		r.GroupName != groupName || r.Duration != duration {
		t.Fatal("actual Owner review changed the exact native Endpoint, Group or duration")
	}
	deadline, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Minute+30*time.Second)) ||
		(duration == "until_revoked" && r.PolicyExpiresAt != "") {
		t.Fatal("actual Owner consent/policy lifetime is inconsistent")
	}
	return next
}

func applyOwnerGroupsReview(t *testing.T, v *codexProductFixture, panel ownerGroupsPanel) (appActorReply, ownerGroupsPanel, []exchange) {
	t.Helper()
	if panel.Review == nil || panel.Review.GestureID == "" || panel.Pending || !panel.Current {
		t.Fatal("actual APPLY requires the original live explicit Owner review")
	}
	return ownerGroupsAppGesture(t, v, "APPLY_REVIEWED_THREAD_GROUP_CHANGE", ownerGroupsGesture{GestureID: panel.Review.GestureID, Confirm: true})
}
