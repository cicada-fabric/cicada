package n3_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func ownerGroupsCrossFacts(t *testing.T, name string, observed map[string]bool) {
	t.Helper()
	for _, value := range observed {
		if !value {
			t.Fatal("cross-Node fact has no completed positive observation")
		}
	}
	t.Log("OWNER_GROUPS_CROSS_FACTS " + string(must(json.Marshal(map[string]any{"case": name, "observed": observed}))))
}

func (f *ownerGroupsCrossNodeFixture) closeApp(t *testing.T) {
	t.Helper()
	if !f.app.running() {
		t.Fatal("original shared App is not running before normal close")
	}
	f.app.command(t, directIPAppCommand{Close: true})
	if f.app.running() || f.app.cmd.ProcessState.ExitCode() != 0 {
		t.Fatal("original App did not close normally")
	}
}

func (f *ownerGroupsCrossNodeFixture) resumeApp(t *testing.T) {
	t.Helper()
	if f.app.running() {
		t.Fatal("App resume would create a second writer for the same original profile")
	}
	f.app = startDirectIPApp(f.parent, f.app.dir) // Same private home/vault, fresh IPC only.
	for _, n := range f.nodes {
		n.pair.app = f.app
	}
	action := appcore.Action{Kind: appcore.ActionDiscoverProfiles}
	r := f.app.command(t, directIPAppCommand{Action: &action})
	if r.ActionFailed || len(r.Snapshot.Profiles) != 1 {
		t.Fatal("same App home did not discover its one original profile")
	}
	p := r.Snapshot.Profiles[0]
	if !p.Direct || p.ID == "" || p.Origin != f.original.Hub.Origin || p.AccountID != f.original.Account.AccountID || p.OwnerID != f.original.Account.OwnerID {
		t.Fatal("App restart discovered a different Hub, account or Owner profile")
	}
	f.action(t, appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: p.ID, HubAddress: f.hub.address})
	f.freshSession(t)
	if len(f.current.Targets.Nodes) != 2 || f.current.Account.OwnerFingerprint != f.original.Account.OwnerFingerprint {
		t.Fatal("original App profile did not retain both independently admitted Nodes and Owner")
	}
}

// These are authenticated current App relation cards, not SQL-created grants.
// All eight originals are checked, including the five intentionally unused ones.
func (f *ownerGroupsCrossNodeFixture) edges(t *testing.T, actors []ownerGroupsCrossActor, g, h string, removed bool) {
	t.Helper()
	for i, actor := range actors {
		p := f.thread(t, actor, false)
		for _, group := range []string{g, h} {
			want := group == g && (i == 0 || i == 1 || i == 4 && !removed) || group == h && (i == 0 || i == 4)
			found := false
			for _, r := range p.Selected.Relations {
				if r.GroupID != group {
					continue
				}
				if found {
					t.Fatal("actual relation card repeated an exact Group")
				}
				found = true
				if want {
					if r.State != "ACTIVE" || r.KeyState != "CURRENT" || r.OwnerMode != "OWNER" || r.ExpiresAt != "" {
						t.Fatal("explicit original Group edge lacks permanent key-ready Owner authority")
					}
				} else if i == 4 && group == g && removed {
					if r.State != "REMOVED" || r.OwnerMode != "OWNER" || r.KeyState == "CURRENT" {
						t.Fatal("exact removed B0-G edge retained effective key-ready authority")
					}
				} else if r.State == "ACTIVE" || r.State == "PENDING_KEY" {
					t.Fatal("explicit Group operations granted another original Endpoint an implicit edge")
				}
			}
			if want && !found || i == 4 && group == g && removed && !found {
				t.Fatal("actual App omitted an expected active or exact removed relation")
			}
		}
	}
}

// Read-only durable outbox identity. Mutable status/attempt counters are excluded;
// a new ASK, changed body, changed Group or new idempotency key cannot recover it.
func ownerGroupsCrossOutbox(t *testing.T, e *ownerGroupsCrossExchange) string {
	t.Helper()
	db := nodePairReadOnlyDB(t, e.source.node.actors.outbox)
	defer db.Close()
	var operation, node, sid, endpoint, group, idem, input, digest, created string
	if db.QueryRow(`SELECT operation_id,node_id,native_session_id,endpoint_id,group_id,idempotency_key,input_json,input_digest,created_at
FROM mcp_outbox_operations WHERE operation_id=?`, e.operation).Scan(&operation, &node, &sid, &endpoint, &group, &idem, &input, &digest, &created) != nil ||
		operation != e.operation || node != e.source.identity.NodeID || sid != e.source.identity.SID || endpoint != e.source.identity.Endpoint || group != e.group ||
		idem != e.source.node.host.fixtureScope+"-"+e.label || digest == "" || created == "" {
		t.Fatal("original cross-Node ASK lost its exact immutable private outbox scope")
	}
	var body struct {
		Target   string `json:"target"`
		Question string `json:"question"`
	}
	if json.Unmarshal([]byte(input), &body) != nil || body.Target != e.target.identity.Endpoint || body.Question != e.question {
		t.Fatal("original ASK durable body or target changed")
	}
	return hash(must(json.Marshal([]string{operation, node, sid, endpoint, group, idem, input, digest, created})))
}

func ownerGroupsCrossNativeZero(t *testing.T, target ownerGroupsCrossActor, body string) {
	t.Helper()
	r := target.node.host.command(t, ownerGroupsHostCommand{Action: "checkpoint", Actor: target.index})
	count, known := r.QueuePosts[body]
	if !known || count != 0 || !r.HistoryKept || r.RecordCount != 4 || !target.node.process.running() || !target.node.shared.hub.hub.running() {
		t.Fatal("fresh refused cross-Node work reached native Runtime or lacks its live original zero witness")
	}
}

func ownerGroupsCrossRefusedASK(t *testing.T, source, target ownerGroupsCrossActor, group string) string {
	t.Helper()
	ownerGroupsSelect(t, source.node.host, source.index, "cross-refused-source-g", group)
	ownerGroupsDenySelection(t, target.node.host, target.index, "cross-refused-b0-g", group)
	body := "SYNTHETIC_CROSS_NODE_REFUSED_" + target.node.host.fixtureScope
	target.node.host.command(t, ownerGroupsHostCommand{Action: "checkpoint", Actor: target.index,
		Queue: []ownerGroupsQueueInput{{Body: body, SID: target.identity.SID, Sender: source.identity.Endpoint, Receiver: target.identity.Endpoint, GroupID: group, Kind: "ask"}}})
	r := source.node.host.command(t, ownerGroupsHostCommand{Action: "call", Actor: source.index, Label: "cross-fresh-refused-ask", Tool: "cicada_ask",
		Arguments:     map[string]any{"target": target.identity.Endpoint, "question": body, "idempotency_key": source.node.host.fixtureScope + "-fresh-refused"},
		ObserveFields: []string{"operation_id", "request_id"}})
	operation := r.Public["operation_id"]
	if operation == "" {
		t.Fatal("fresh refusal lacks the original durable native ASK operation")
	}
	for end := time.Now().Add(30 * time.Second); r.OperationStatus != "FAILED" && time.Now().Before(end); {
		r = source.node.host.command(t, ownerGroupsHostCommand{Action: "call", Actor: source.index, Label: "cross-fresh-refused-status", Tool: "cicada_operation_status",
			Arguments: map[string]any{"operation_id": operation}, ObserveFields: []string{"operation_id"}})
		if r.Public["operation_id"] != operation {
			t.Fatal("fresh refused ASK status replaced its original operation")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if r.OperationStatus != "FAILED" || r.OperationRetryable == nil || *r.OperationRetryable {
		t.Fatal("fresh B0-G ASK did not reach a definitive business refusal")
	}
	// A terminal immutable operation plus live positive controls and the exact
	// Owner re-add error distinguish revocation from an unavailable fixture.
	ownerGroupsCrossNativeZero(t, target, body)
	return body
}

// The existing driver is the sole executable entry. No SDK actor, SQL grant,
// alias App API, paid model or legacy enrollment can satisfy this parent.
func TestN3OwnerEndpointGroupsCrossNode(t *testing.T) {
	if os.Getenv("CICADA_N3_OWNER_ENDPOINT_GROUPS_CROSS_NODE") != "1" {
		t.Skip("OWNER_GROUPS_CROSS_NOT_RUN opt in through the isolated native-pair driver")
	}
	f := newOwnerGroupsCrossNodeFixture(t)
	a, b := f.nodes[0], f.nodes[1]
	var originals [2][]ownerGroupsIdentity
	var actors []ownerGroupsCrossActor
	var g, h, refused string
	if !t.Run("C1_ScopedEnrollmentAndOriginals", func(t *testing.T) {
		f.enroll(t, a, false)
		a.startHost(t, f.activatePolicy(t, a, ""))
		f.enroll(t, b, true)
		b.startHost(t, f.activatePolicy(t, b, a.actors.active.NetworkID))
		if a.actors.active.PolicyID == b.actors.active.PolicyID || a.actors.active.GroupID == b.actors.active.GroupID {
			t.Fatal("two Nodes merged their independent default policies or Groups")
		}
		f.requireIndependentOriginals(t)
		for i, n := range f.nodes {
			originals[i] = n.identities(t)
			for index := 0; index < 4; index++ {
				actors = append(actors, ownerGroupsCrossOriginalActor(t, n, originals[i], index))
			}
		}
		if f.current.Management != appcore.ManagementUnavailable || f.current.Canvas.State != appcore.CanvasNoAuthorization || f.current.Account.RootState != appcore.RootStateActive {
			t.Fatal("identity flow required general Control authority")
		}
		ownerGroupsCrossFacts(t, "C1_ScopedEnrollmentAndOriginals", map[string]bool{"one_Hub_Owner_device": true, "both_scoped_private_ACK": true, "independent_policies_same_Network": true, "two_Nodes_eight_original_Threads": true, "Control_off": true})
	}) {
		return
	}
	if !t.Run("C2_ExplicitOwnerGroups", func(t *testing.T) {
		g = f.change(t, actors[0], wire.OwnerEndpointGroupsCreateGroup, "", "SYNTHETIC cross-Node G")
		h = f.change(t, actors[0], wire.OwnerEndpointGroupsCreateGroup, "", "SYNTHETIC cross-Node H")
		if g == "" || h == "" || g == h || g == a.actors.active.GroupID || h == b.actors.active.GroupID {
			t.Fatal("two explicit Groups were merged or replaced with a default Group")
		}
		for _, edge := range []struct {
			actor int
			group string
		}{{0, g}, {1, g}, {4, g}, {0, h}, {4, h}} {
			f.change(t, actors[edge.actor], wire.OwnerEndpointGroupsAddEndpoint, edge.group, "")
			f.relation(t, actors[edge.actor], edge.group, "ACTIVE")
		}
		f.edges(t, actors, g, h, false)
		ownerGroupsCrossFacts(t, "C2_ExplicitOwnerGroups", map[string]bool{"actual_CREATE_ADD_reviews": true, "exact_G_A0_A1_B0_H_A0_B0": true, "all_five_edges_key_ready": true, "other_originals_no_implicit_edges": true})
	}) {
		return
	}
	if !t.Run("C3_BidirectionalNative", func(t *testing.T) {
		for i, pair := range [][2]int{{0, 4}, {4, 0}} {
			e := prepareOwnerGroupsCrossExchange(t, actors[pair[0]], actors[pair[1]], g, []string{"cross-forward", "cross-reverse"}[i])
			e.sendASK(t)
			e.receiveReply(t)
		}
		ownerGroupsCrossFacts(t, "C3_BidirectionalNative", map[string]bool{"A_to_B_request_reply": true, "B_to_A_request_reply": true, "exact_original_native_each_once": true})
	}) {
		return
	}
	if !t.Run("C4_AppClosedCommunication", func(t *testing.T) {
		f.closeApp(t)
		e := prepareOwnerGroupsCrossExchange(t, actors[0], actors[4], h, "cross-App-closed")
		e.sendASK(t)
		e.receiveReply(t)
		if f.app.running() {
			t.Fatal("communication silently restarted the App")
		}
		ownerGroupsCrossFacts(t, "C4_AppClosedCommunication", map[string]bool{"same_App_closed_normally": true, "native_request_reply_without_App": true})
	}) {
		return
	}
	if !t.Run("C5_OriginalOfflineRecovery", func(t *testing.T) {
		e := prepareOwnerGroupsCrossExchange(t, actors[0], actors[4], g, "cross-offline-original")
		b.process.kill(t)
		if b.process.running() {
			t.Fatal("offline fault did not stop the original receiving Node")
		}
		e.sendASK(t)
		if e.operation == "" {
			t.Fatal("offline original ASK lacks its original durable operation ID")
		}
		immutable := ownerGroupsCrossOutbox(t, e)
		checkpoint := b.host.command(t, ownerGroupsHostCommand{Action: "checkpoint", Actor: 0})
		if count, known := checkpoint.QueuePosts[e.question]; !known || count != 0 {
			t.Fatal("offline original ASK was already injected before the retained restart")
		}
		request, operation := e.request, e.operation
		b.restartRetained(t)
		e.receiveReply(t)
		if e.request != request || e.operation != operation || immutable != ownerGroupsCrossOutbox(t, e) || f.app.running() || !reflect.DeepEqual(originals[1], b.identities(t)) {
			t.Fatal("offline recovery replaced its original request, outbox, Node root or native identities")
		}
		ownerGroupsCrossFacts(t, "C5_OriginalOfflineRecovery", map[string]bool{"receiver_armed_before_offline": true, "one_original_ASK_no_resend": true, "same_Node_root_key_binding_SIDs": true, "same_request_reply_native_once": true, "App_remained_closed": true})
	}) {
		return
	}
	if !t.Run("C6_RemoveOnlyB0G", func(t *testing.T) {
		f.resumeApp(t)
		f.selectNode(t, b)
		f.change(t, actors[4], wire.OwnerEndpointGroupsRemoveEndpoint, g, "")
		f.relation(t, actors[4], g, "REMOVED")
		f.edges(t, actors, g, h, true)
		refused = ownerGroupsCrossRefusedASK(t, actors[0], actors[4], g)
		ownerGroupsCrossFacts(t, "C6_RemoveOnlyB0G", map[string]bool{"same_App_profile_explicit_B_selection": true, "only_B0_G_removed": true, "fresh_B0_G_definitive_refusal": true, "native_injection_zero": true})
	}) {
		return
	}
	if !t.Run("C7_SurvivingGroupsAndOriginals", func(t *testing.T) {
		a.host.roundtrip(t, "cross-surviving-G", g, 0, 1, originals[0])
		for i, pair := range [][2]int{{0, 4}, {4, 0}} {
			e := prepareOwnerGroupsCrossExchange(t, actors[pair[0]], actors[pair[1]], h, []string{"cross-surviving-H-ab", "cross-surviving-H-ba"}[i])
			e.sendASK(t)
			e.receiveReply(t)
		}
		ownerGroupsCrossNativeZero(t, actors[4], refused)
		var before, after []ownerGroupsIdentity
		for i, n := range f.nodes {
			got := n.identities(t)
			if !reflect.DeepEqual(originals[i], got) {
				t.Fatal("Group-only changes replaced an original native identity or key")
			}
			before = append(before, originals[i]...)
			after = append(after, got...)
		}
		f.requireIndependentOriginals(t)
		t.Log("OWNER_GROUPS_CROSS_IDENTITIES " + string(must(json.Marshal(map[string]any{"before": before, "after_group_operations": after}))))
		for _, n := range f.nodes {
			n.host.finish(t)
		}
		f.closeApp(t)
		ownerGroupsCrossFacts(t, "C7_SurvivingGroupsAndOriginals", map[string]bool{"A0_A1_G_survives": true, "A0_B0_H_bidirectional_survives": true, "refused_G_still_native_zero": true, "eight_original_identities_keys_unchanged": true, "both_Hosts_clean_no_models": true})
	}) {
		return
	}
}
