//go:build linux && cicada_scoped_app_integration

package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

// This witness reuses the real Hub database rather than interpreting a CLI
// error or a transport status as proof that no remote admission occurred.
// Witnesses exclude request receipts, transport counters and heartbeat times,
// which may change on valid denied requests. Slot expiry is authority and stays
// in the hash, along with registrations, class, policy and Group key grants.
type threadCollaborationHubWitness struct {
	BusinessRows    map[string]int    `json:"business_rows"`
	AuthoritySHA256 map[string]string `json:"authority_sha256"`
	ControlCalls    int               `json:"control_calls"`
}

func threadCollaborationWitness(t *testing.T, hub *nodeHubLifecycleHub) threadCollaborationHubWitness {
	t.Helper()
	path := filepath.Join(filepath.Dir(hub.native.file), "cicada.sqlite3")
	result := threadCollaborationBusinessWitness(t, path)
	hub.mu.Lock()
	result.ControlCalls = hub.control
	hub.mu.Unlock()
	return result
}

func threadCollaborationBusinessWitness(t *testing.T, path string) threadCollaborationHubWitness {
	t.Helper()
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	result := threadCollaborationHubWitness{BusinessRows: make(map[string]int), AuthoritySHA256: make(map[string]string)}
	// Every identifier is a fixed fixture-owned schema name, never caller SQL.
	for _, selection := range []struct{ table, columns string }{
		{"principals", "id,kind,owner_id,trust_domain_id,name,display_name,status,version"},
		{"fabric_endpoints", "id,principal_id,group_id,binding_id,machine_id,harness,native_session_id,workspace,name,role,status,migration_state"},
		{"memberships", "id,principal_id,group_id,role,roles_json,grants_json,authorization_json,status,revision,version"},
		{"session_bindings", "id,endpoint_id,principal_id,group_id,epoch,status,credential_hash_version,mode,context_continuity"},
		{"endpoint_group_memberships", "endpoint_id,group_id,status,revision"},
		{"network_memberships_v2", "id,network_id,principal_id,grants_json,status,revision"},
		{"endpoint_network_memberships_v2", "network_id,endpoint_id,status,revision,nickname,discoverable"},
		{"group_endpoint_key_grants_v2", "id,hub_id,owner_id,group_id,endpoint_id,owner_key_id,manifest_digest"},
		{"shared_tasks_v2", "id,group_id,status,owner_principal_id,owner_endpoint_id,revision,owner_epoch"},
		{"resource_v2_authority", "resource_id,fencing_epoch,state,current_lease_id"},
		{"resource_v2_leases", "id,resource_id,holder_group_id,holder_task_id,holder_principal_id,fencing_epoch,state"},
		{"hub_local_domains_v1", "policy_id,hub_id,owner_id,node_id,local_user_scope,network_id,group_id,epoch,policy_json,state,revision,terminal_reason"},
		{"hub_local_domain_members_v1", "member_id,policy_id,owner_id,node_id,native_session_id,endpoint_id,principal_id,binding_id,access_id,runtime,workspace,member_json,state,revision,attempt_id,join_operation_id,join_sequence,key_grant_json"},
		{"hub_endpoint_groups_registrations_v1", "endpoint_id,owner_id,node_id,network_id,native_digest,registration_digest,registration_revision,binding_id,binding_epoch,origin_policy_id,origin_member_id,anchor_json,relations_revision"},
		{"hub_endpoint_groups_listings_v1", "owner_id,node_id,network_id,revision"},
		{"hub_endpoint_groups_heads_v1", "native_digest,group_id,mode,revision,deny_reason,policy_id,policy_epoch"},
		{"hub_endpoint_groups_relations_v1", "endpoint_id,group_id,native_digest,revision,default_stamp,default_withdrawn"},
		{"hub_endpoint_groups_policies_v1", "policy_id,native_digest,endpoint_id,group_id,epoch,policy_json,state,contribution_revision,grant_json"},
		{"thread_classifications_v1", "registration_id,source_epoch,endpoint_id,owner_id,node_id,network_id,classification,revision"},
		{"group_coordination_policies_v1", "group_id,owner_id,network_id,policy_id,revision,state,policy_json"},
		{"group_lock_slots_v1", "group_id,slot,state,version,generation,holder_json,note,expires_at"},
	} {
		rows, err := tx.Query("SELECT " + selection.columns + " FROM " + selection.table)
		if err != nil {
			t.Fatal("required real Hub authority columns unavailable", selection.table, err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var encoded []string
		for rows.Next() {
			values, targets := make([]any, len(columns)), make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if err := rows.Scan(targets...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			raw, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			encoded = append(encoded, string(raw))
			clear(raw)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(encoded)
		raw, err := json.Marshal(struct {
			Columns string
			Rows    []string
		}{selection.columns, encoded})
		if err != nil {
			t.Fatal("required real Hub witness table unavailable", selection.table, err)
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		result.BusinessRows[selection.table] = len(encoded)
		result.AuthoritySHA256[selection.table] = hex.EncodeToString(digest[:])
	}
	return result
}

// Prove that the oracle catches a same-count authority UPDATE, while retaining
// only digests rather than raw SID/workspace/grants in exported evidence.
func TestAcceptanceThreadAuthorityWitnessDetectsSameCountMutation(t *testing.T) {
	path := filepath.Join(privateLocalNodeRoot(t), "SYNTHETIC-authority.sqlite3")
	db, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p, err := db.CreatePrincipal(store.Principal{Kind: store.PrincipalKindHuman, Name: "SYNTHETIC witness", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	before := threadCollaborationBusinessWitness(t, path)
	if _, err := db.RevokePrincipal(p.ID, "SYNTHETIC authority oracle test"); err != nil {
		t.Fatal(err)
	}
	after := threadCollaborationBusinessWitness(t, path)
	if before.BusinessRows["principals"] != after.BusinessRows["principals"] || before.AuthoritySHA256["principals"] == after.AuthoritySHA256["principals"] {
		t.Fatal("same-count authority mutation escaped witness")
	}
}

func threadCollaborationCacheDigest(t *testing.T, c LocalNodeConnection, thread nodeHubAcceptanceThread) string {
	t.Helper()
	cache, err := newMCPSessionStateStore(c.Pin.MCPSessionStateFile).load(c.Pin.APIOrigin, harness.SessionContext{Harness: "codex", NativeSessionID: thread.native, MachineID: c.Pin.NodeID, Workspace: thread.workspace})
	if err != nil || cache == nil {
		t.Fatal("original private MCP cache unavailable", err)
	}
	raw, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func threadCollaborationEvidence(t *testing.T, value any) {
	t.Helper()
	if root := os.Getenv("CICADA_THREAD_SCOPE_OUTPUT"); root != "" {
		path := filepath.Join(root, "carrier-observations.jsonl")
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		encodeErr := json.NewEncoder(file).Encode(value)
		closeErr := file.Close()
		if encodeErr != nil || closeErr != nil {
			t.Fatal(encodeErr, closeErr)
		}
	}
}

// The two Hubs use the existing real NPT, TLS, Owner Controller, persistent
// databases, production Node manager and current CLI/Hook/MCP carriers. Only
// visibly synthetic owned Host records and the existing inert queue executable
// fixture are used; no Codex model, resident Hub or installed Runtime runs.
func TestAcceptanceThreadSameSIDRejectsSecondHubBeforeRemoteAdmission(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	a := f.add(0)
	ga := f.activateGroup(0)
	b := f.add(1)
	gb := f.activateGroup(1)
	if ga.NetworkID == gb.NetworkID || ga.GroupID == gb.GroupID {
		t.Fatal("independent actual Hub scopes collided")
	}
	thread := nodeHubSyntheticThread(t, "single-network-acceptance")
	f.register(a, thread)
	original := threadCollaborationCacheDigest(t, a, thread)
	before := threadCollaborationWitness(t, f.hubs[1])
	var output bytes.Buffer
	err := nativeThreadOperatorCommand("join", []string{"--thread", thread.native, "--name", "SYNTHETIC original Thread", "--user-root", f.root, "--hub", "SYNTHETIC-B"}, &output)
	clear(output.Bytes())
	after := threadCollaborationWitness(t, f.hubs[1])
	unchangedCache := original == threadCollaborationCacheDigest(t, a, thread)
	closedConflict := errors.Is(err, nodeinbox.ErrNativeContextScopeConflict)
	if err != nil {
		closedConflict = closedConflict || strings.Contains(err.Error(), "THREAD_NETWORK_CONFLICT") || strings.Contains(err.Error(), nodeinbox.ErrNativeContextScopeConflict.Error())
	}
	threadCollaborationEvidence(t, struct {
		Test, Expected                string
		Conflict, OriginalCacheStable bool
		Before, After                 threadCollaborationHubWitness
	}{t.Name(), "second-Hub admission refused before remote business mutation", closedConflict, unchangedCache, before, after})
	if !closedConflict {
		t.Error("same actual Thread did not receive a closed Network-conflict refusal")
	}
	if !reflect.DeepEqual(before, after) {
		t.Error("second-Hub attempt changed remote registration/membership/key/task/resource counts")
	}
	if !unchangedCache {
		t.Error("second-Hub attempt rewrote the first original private session")
	}
	// A separate actual Thread on the same physical Node is the positive
	// control; this must not be implemented as a machine-wide Network limit.
	independent := nodeHubSyntheticThread(t, "independent-network-acceptance")
	second := f.register(b, independent)
	if second.EndpointGroupsVersion != 1 || second.GroupID != "" {
		t.Fatal("independent registration did not preserve explicit Group selection")
	}
	m, err := newRoutedLocalNodeMCPServer(f.root, ListVerifiedLocalNodeConnections)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.codexFacade.close(); close(m.stop) })
	if _, err := f.tool(m, independent, "cicada_groups", map[string]any{}); err != nil {
		t.Fatal("actual independent Thread Hook/MCP view failed", err)
	}
	// Registration stores identity, not a default Group. The independent
	// positive control selects its exact current Group through real MCP.
	f.selectGroup(m, independent, b.Pin, gb)
	if _, err := f.tool(m, thread, "cicada_groups", map[string]any{}); err != nil {
		t.Error("second-Hub refusal damaged original Thread Hook/MCP access", err)
	}
	for _, hub := range f.hubs {
		if witness := threadCollaborationWitness(t, hub); witness.ControlCalls != 0 {
			t.Error("headless protocol carrier entered Control inference")
		}
	}
}

// A genuinely applied Join with its response withheld must retain the original
// Network through a cold Node-manager reopen. No synthetic recovery row is
// inserted and no unsigned HTTP refusal is treated as authenticated no-effect.
func TestAcceptanceThreadLostJoinResponseFencesSecondHubAcrossRestart(t *testing.T) {
	f := newNodeHubLifecycleAcceptance(t)
	a := f.add(0)
	ga := f.activateGroup(0)
	b := f.add(1)
	f.activateGroup(1)
	thread := nodeHubSyntheticThread(t, "lost-join-network-acceptance")
	join := func(alias string) error {
		var output bytes.Buffer
		err := nativeThreadOperatorCommand("join", []string{"--thread", thread.native, "--name", "SYNTHETIC original Thread", "--user-root", f.root, "--hub", alias}, &output)
		clear(output.Bytes())
		return err
	}
	f.hubs[0].mu.Lock()
	f.hubs[0].dropPath = "/v2/node/control/rpc"
	f.hubs[0].dropOperation = wire.OperationLocalDomainNodeJoin
	f.hubs[0].mu.Unlock()
	if err := join("SYNTHETIC-A"); err == nil {
		t.Fatal("lost real Join response was reported complete")
	}
	f.hubs[0].mu.Lock()
	committed := f.hubs[0].droppedStatus == http.StatusOK && f.hubs[0].droppedDigest != ([32]byte{})
	f.hubs[0].mu.Unlock()
	if !committed {
		t.Fatal("fault did not withhold a genuinely successful real Guard/Store Join")
	}
	accepted := threadCollaborationWitness(t, f.hubs[0])
	if accepted.BusinessRows["fabric_endpoints"] != 1 {
		t.Fatal("withheld response had no unique actual Endpoint")
	}
	before := threadCollaborationWitness(t, f.hubs[1])
	registryState := func() (string, string, int) {
		t.Helper()
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(a.Pin.WriterRoot, "node-native-context-history.sqlite3"))}
		db, err := sql.Open("sqlite", u.String()+"?mode=ro&_busy_timeout=5000")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var state, pending string
		var rows int
		if err = db.QueryRow(`SELECT count(*) FROM node_thread_network_reservations_v1`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if err = db.QueryRow(`SELECT state,pending_reservation_id FROM node_thread_network_authority_v1`).Scan(&state, &pending); err != nil {
			t.Fatal(err)
		}
		return state, pending, rows
	}
	state, pending, claims := registryState()
	if (state != nodeinbox.ThreadNetworkUnresolved && state != nodeinbox.ThreadNetworkReserved) || pending == "" || claims != 1 {
		t.Fatal("lost Join did not retain one durable unresolved original")
	}
	originalPending := pending
	f.stop()
	f.start()
	f.eventually("cold original two-Hub connections ready", 12*time.Second, func() bool {
		v, err := ListVerifiedLocalNodeConnections(f.ctx, f.root)
		return err == nil && len(v) == 2
	})
	state, pending, claims = registryState()
	if claims != 1 || ((state == nodeinbox.ThreadNetworkUnresolved || state == nodeinbox.ThreadNetworkReserved) && pending != originalPending) || (state != nodeinbox.ThreadNetworkUnresolved && state != nodeinbox.ThreadNetworkReserved && state != nodeinbox.ThreadNetworkCurrent) {
		t.Fatal("cold reopen reset or replaced the original Join")
	}
	// A production startup may already have authenticated the original result.
	// Either pending or settled is safe; UNASSIGNED/another scope never is.
	if state == nodeinbox.ThreadNetworkCurrent {
		u := url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(a.Pin.WriterRoot, "node-native-context-history.sqlite3"))}
		db, err := sql.Open("sqlite", u.String()+"?mode=ro&_busy_timeout=5000")
		if err != nil {
			t.Fatal(err)
		}
		var hub, network, originalState, response, acceptedDigest string
		err = db.QueryRow(`SELECT a.hub_id,a.network_id,r.state,r.response_digest,r.accepted_result_digest FROM node_thread_network_authority_v1 a JOIN node_thread_network_reservations_v1 r ON r.identity_digest=a.identity_digest WHERE r.reservation_id=?`, originalPending).Scan(&hub, &network, &originalState, &response, &acceptedDigest)
		_ = db.Close()
		if err != nil || pending != "" || hub != a.Pin.HubID || network != ga.NetworkID || originalState != nodeinbox.ThreadNetworkAccepted || len(response) != 64 || len(acceptedDigest) != 64 {
			t.Fatal("cold settled state has no matching original accepted evidence")
		}
	}
	if err := join("SYNTHETIC-B"); err == nil || (!errors.Is(err, nodeinbox.ErrNativeContextScopeConflict) && !errors.Is(err, nodeinbox.ErrThreadNetworkUnresolved) && !strings.Contains(err.Error(), "THREAD_NETWORK_CONFLICT") && !strings.Contains(err.Error(), nodeinbox.ErrNativeContextScopeConflict.Error())) {
		t.Error("second Hub did not return a typed Network-conflict refusal for the unresolved original")
	}
	after := threadCollaborationWitness(t, f.hubs[1])
	if !reflect.DeepEqual(before, after) {
		t.Error("uncertain first Join allowed second-Hub business mutation")
	}
	restored := f.register(a, thread)
	recovered := threadCollaborationWitness(t, f.hubs[0])
	// Key completion may activate Group/Network relations after Owner consent.
	// The original physical identity/member/binding must remain unique.
	for _, table := range []string{"principals", "fabric_endpoints", "session_bindings", "hub_local_domain_members_v1"} {
		if accepted.BusinessRows[table] != recovered.BusinessRows[table] {
			t.Errorf("original recovery duplicated %s", table)
		}
	}
	state, pending, _ = registryState()
	if state != nodeinbox.ThreadNetworkCurrent || pending != "" {
		t.Fatal("authenticated exact recovery did not settle original reservation")
	}
	if retry := f.register(a, thread); retry.EndpointID != restored.EndpointID {
		t.Fatal("duplicate Join replaced original Endpoint")
	}
	independent := nodeHubSyntheticThread(t, "lost-join-independent-network-acceptance")
	f.register(b, independent)
	threadCollaborationEvidence(t, struct {
		Test                                                    string
		LostCommitted, ColdOriginalRetained, SecondHubUnchanged bool
	}{t.Name(), committed, true, reflect.DeepEqual(before, after)})
}

func acceptanceGroupLockBoard(t *testing.T, value any) wire.GroupSlotView {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var view wire.GroupSlotView
	if json.Unmarshal(raw, &view) != nil || wire.ValidateGroupSlotView(view) != nil {
		t.Fatal("actual common Group lock view invalid")
	}
	return view
}

type acceptanceGroupLockOperation struct {
	OperationID string                                    `json:"operation_id"`
	Status      string                                    `json:"status"`
	Receipt     *wire.GroupLockReceipt                    `json:"receipt"`
	Evidence    *localThreadCollaborationOriginalEvidence `json:"evidence"`
}

func acceptanceGroupLockResult(t *testing.T, value any, status, outcome string) acceptanceGroupLockOperation {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result acceptanceGroupLockOperation
	if json.Unmarshal(raw, &result) != nil || result.Status != status || result.OperationID == "" {
		t.Fatal("actual lock outbox did not retain expected status", status)
	}
	if status == mcpOutboxStatusSent && (result.Receipt == nil || result.Evidence == nil || wire.ValidateGroupLockReceipt(*result.Receipt) != nil || result.Receipt.Outcome != outcome || result.Evidence.Outcome != localThreadCollaborationApplied || result.Receipt.OperationID != result.OperationID || result.Evidence.Original.OperationID != result.OperationID || result.Receipt.RequestDigest != result.Evidence.Original.RequestDigest) {
		t.Fatal("actual lock outbox completion lacks authenticated exact original evidence")
	}
	return result
}

func (f *nodeHubLifecycleAcceptance) enableGroupCoordination(connection LocalNodeConnection, endpoint, group string) {
	f.t.Helper()
	var hub *nodeHubLifecycleHub
	for _, candidate := range f.hubs {
		if candidate.native.d.Claims.Hub.HubID == connection.Pin.HubID {
			hub = candidate
		}
	}
	if hub == nil {
		f.t.Fatal("exact policy Owner Hub missing")
	}
	read := func() *appcore.GroupLockBoardView {
		snapshot := hub.app.Snapshot()
		hub.dispatch(appcore.Action{Kind: appcore.ActionReadThreadGroups, ThreadGroups: appcore.ThreadGroupAction{GestureID: snapshot.ThreadGroups.GestureID}})
		snapshot = hub.app.Snapshot()
		var card appcore.GroupThreadView
		for _, candidate := range snapshot.ThreadGroups.Threads {
			if candidate.EndpointID == endpoint {
				card = candidate
			}
		}
		if card.EndpointID == "" {
			f.t.Fatal("actual policy directory omitted registered Thread")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionReadThreadRelations, ThreadGroups: appcore.ThreadGroupAction{GestureID: card.GestureID, EndpointID: endpoint}})
		selected := hub.app.Snapshot().ThreadGroups.Selected
		if selected == nil {
			f.t.Fatal("actual policy Thread selection missing")
		}
		var relation appcore.ThreadGroupRelation
		for _, candidate := range selected.Relations {
			if candidate.GroupID == group {
				relation = candidate
			}
		}
		if relation.GroupID == "" || relation.CoordinationGestureID == "" {
			f.t.Fatal("actual active Group offered no coordination gesture")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionReadGroupCoordination, Coordination: appcore.CoordinationAction{GroupID: group, GestureID: relation.CoordinationGestureID}})
		selected = hub.app.Snapshot().ThreadGroups.Selected
		for _, candidate := range selected.Relations {
			if candidate.GroupID == group && candidate.Locks != nil && candidate.Locks.Current {
				return candidate.Locks
			}
		}
		f.t.Fatal("actual App returned no current Group coordination board")
		return nil
	}
	board := read()
	if board.PolicyState != "ENABLED" {
		if !board.CanEnable {
			f.t.Fatal("actual App offered no explicit coordination enable")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionPrepareCoordination, Coordination: appcore.CoordinationAction{Change: wire.ThreadCollaborationEnableGroupPolicy, GroupID: group, GestureID: board.GestureID}})
		review := hub.app.Snapshot().Coordination.Review
		if review == nil || !review.CanApply {
			f.t.Fatal("actual Group policy review missing")
		}
		hub.dispatch(appcore.Action{Kind: appcore.ActionApplyCoordination, Coordination: appcore.CoordinationAction{GestureID: review.GestureID, Confirm: true}})
		board = read()
	}
	if board.PolicyState != "ENABLED" || len(board.Slots) != 8 {
		f.t.Fatal("explicit real Owner Apply did not enable exactly eight protocol slots")
	}
}

func TestAcceptanceGroupLocksActualHostOwnerLifecycle(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "nominal"
		if lost {
			name = "lost-acquire-cold-manager"
		}
		t.Run(name, func(t *testing.T) {
			f := newNodeHubLifecycleAcceptance(t)
			a := f.add(0)
			group := f.activateGroup(0)
			var thread nodeHubAcceptanceThread
			var registered *mcpCachedSession
			if lost {
				thread = nodeHubSyntheticThread(t, "actual-group-lock-lifecycle-fault")
				registered = f.registerAs(a, thread, wire.ThreadClassificationWorker)
			} else {
				// The same real Owner App must sustain the requested five
				// classifications; only the explicit first participant is Advisor.
				for i := 0; i < 5; i++ {
					candidate := nodeHubSyntheticThread(t, fmt.Sprintf("actual-group-lock-participant-%d", i))
					class := wire.ThreadClassificationWorker
					if i == 0 {
						class = wire.ThreadClassificationAdvisor
					}
					current := f.registerAs(a, candidate, class)
					if i == 1 {
						thread, registered = candidate, current
					}
				}
			}
			f.enableGroupCoordination(a, registered.EndpointID, group.GroupID)
			m, err := newLocalNodeMCPServer(LocalNodeSelection{UserRoot: f.root, HubID: a.Pin.HubID, NodeID: a.Pin.NodeID})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if m != nil {
					closeCodexMCPChild(m)
				}
			})
			if _, err = f.tool(m, thread, "cicada_groups", map[string]any{}); err != nil {
				t.Fatal("actual current Groups", err)
			}
			f.selectGroup(m, thread, a.Pin, group)
			value, err := f.tool(m, thread, "cicada_thread_scope", map[string]any{})
			if err != nil {
				t.Fatal("actual native scope", err)
			}
			raw, _ := json.Marshal(value)
			var source wire.ThreadScopeView
			if json.Unmarshal(raw, &source) != nil || wire.ValidateThreadScopeView(source) != nil || source.Classification != wire.ThreadClassificationWorker || source.ActiveGroupCount != 1 {
				t.Fatal("ordinary real Worker scope missing")
			}
			read := func() wire.GroupSlotView {
				t.Helper()
				value, err := f.tool(m, thread, "cicada_group_locks", map[string]any{})
				if err != nil {
					t.Fatal("actual Group slot read", err)
				}
				return acceptanceGroupLockBoard(t, value)
			}
			before := threadCollaborationWitness(t, f.hubs[0])
			free := read()
			slot := free.Slots[0]
			if len(free.Slots) != 8 || slot.State != "FREE" {
				t.Fatal("actual initial eight slots unavailable")
			}
			acquire := map[string]any{"slot": 1, "expected_version": slot.Version, "ttl_seconds": 3600, "idempotency_key": "SYNTHETIC-actual-acquire", "note": "SYNTHETIC generic protocol coordination"}
			if lost {
				f.hubs[0].mu.Lock()
				f.hubs[0].dropPath = "/v2/node/control/rpc"
				f.hubs[0].dropOperation = wire.OperationGroupLocksAcquire
				f.hubs[0].mu.Unlock()
			}
			value, err = f.tool(m, thread, "cicada_group_lock_acquire", acquire)
			if err != nil {
				t.Fatal("actual acquire carrier", err)
			}
			originalID := ""
			droppedDigest := [32]byte{}
			if lost {
				unknown := acceptanceGroupLockResult(t, value, mcpOutboxStatusUnknown, "")
				originalID = unknown.OperationID
				f.hubs[0].mu.Lock()
				droppedDigest = f.hubs[0].droppedDigest
				committed := f.hubs[0].droppedStatus == http.StatusOK && droppedDigest != ([32]byte{})
				f.hubs[0].mu.Unlock()
				if !committed {
					t.Fatal("fault did not withhold an actually committed acquire response")
				}
				closeCodexMCPChild(m)
				m = nil
				f.stop()
				identityPath, statePath := machineNodeControlPaths(a.Pin.StateDir, a.Pin.NodeID)
				keyBefore, err := os.ReadFile(identityPath)
				if err != nil {
					t.Fatal(err)
				}
				keyDigest := sha256.Sum256(keyBefore)
				clear(keyBefore)
				machineNodeControlClients.Delete(statePath)
				f.start()
				f.eventually("cold original Node ready", 12*time.Second, func() bool {
					v, err := ListVerifiedLocalNodeConnections(f.ctx, f.root)
					return err == nil && len(v) == 1 && v[0].Pin == a.Pin
				})
				keyAfter, err := os.ReadFile(identityPath)
				if err != nil {
					t.Fatal(err)
				}
				sameIdentity := sha256.Sum256(keyAfter) == keyDigest
				clear(keyAfter)
				if !sameIdentity {
					t.Fatal("cold manager regenerated the original Node identity")
				}
				m, err = newLocalNodeMCPServer(LocalNodeSelection{UserRoot: f.root, HubID: a.Pin.HubID, NodeID: a.Pin.NodeID})
				if err != nil {
					t.Fatal(err)
				}
				recoverArgs := map[string]any{}
				for k, v := range acquire {
					recoverArgs[k] = v
				}
				recoverArgs["recover"] = true
				value, err = f.tool(m, thread, "cicada_group_lock_acquire", recoverArgs)
				if err != nil {
					t.Fatal("actual fresh Host original acquire recovery", err)
				}
			}
			acquired := acceptanceGroupLockResult(t, value, mcpOutboxStatusSent, "ACQUIRED")
			if lost && (acquired.OperationID != originalID || acquired.Evidence.RequestPacketDigest != hex.EncodeToString(droppedDigest[:])) {
				t.Fatal("recovery replaced the actually committed original")
			}
			// App closure is not revocation and cannot free an otherwise live slot.
			if err = f.hubs[0].app.Close(); err != nil {
				t.Fatal("actual App close", err)
			}
			held := read().Slots[0]
			if held.State != "HELD" || held.Holder == nil || held.Holder.EndpointID != registered.EndpointID || held.Holder.Source != source.Source || held.Version != acquired.Receipt.AppliedVersion || held.Generation != acquired.Receipt.Generation {
				t.Fatal("App close changed the live original holder")
			}
			value, err = f.tool(m, thread, "cicada_group_lock_renew", map[string]any{"slot": 1, "expected_version": held.Version, "generation": held.Generation, "ttl_seconds": 3600, "idempotency_key": "SYNTHETIC-actual-renew"})
			if err != nil {
				t.Fatal("actual renew", err)
			}
			renewed := acceptanceGroupLockResult(t, value, mcpOutboxStatusSent, "RENEWED")
			current := read().Slots[0]
			if current.Version != renewed.Receipt.AppliedVersion || current.Generation != held.Generation || current.ExpiresAt != renewed.Receipt.ExpiresAt {
				t.Fatal("actual renewal lost original generation/time evidence")
			}
			value, err = f.tool(m, thread, "cicada_group_lock_release", map[string]any{"slot": 1, "expected_version": current.Version, "generation": current.Generation, "idempotency_key": "SYNTHETIC-actual-release"})
			if err != nil {
				t.Fatal("actual release", err)
			}
			released := acceptanceGroupLockResult(t, value, mcpOutboxStatusSent, "RELEASED")
			final := read().Slots[0]
			if final.State != "FREE" || final.Holder != nil || final.ExpiresAt != "" || final.Note != "" || final.Version != released.Receipt.AppliedVersion || final.Generation != held.Generation {
				t.Fatal("actual release did not clear only the original protocol occupancy")
			}
			after := threadCollaborationWitness(t, f.hubs[0])
			for _, table := range []string{"shared_tasks_v2", "resource_v2_authority", "resource_v2_leases"} {
				if before.BusinessRows[table] != after.BusinessRows[table] || before.AuthoritySHA256[table] != after.AuthoritySHA256[table] {
					t.Fatal("generic protocol lock created or changed Task/physical Resource authority", table)
				}
			}
			if after.ControlCalls != 0 {
				t.Fatal("actual lifecycle entered Control inference")
			}
			threadCollaborationEvidence(t, struct {
				Test                                                               string
				LostOriginalRecovered, AppCloseIndependent, NoTaskResourceMutation bool
				Before, After                                                      threadCollaborationHubWitness
			}{t.Name(), lost, true, true, before, after})
		})
	}
}
