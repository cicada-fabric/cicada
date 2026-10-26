package n3_test

import (
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func prepareOwnerGroupsEndpointChange(t *testing.T, v *codexProductFixture, actors nativePeerActors, identity ownerGroupsIdentity, group, change, duration string) ownerGroupsPanel {
	t.Helper()
	panel := selectOwnerGroupsThread(t, v, actors.active.NetworkID, identity)
	if change == wire.OwnerEndpointGroupsAddEndpoint {
		panel = ownerGroupsCandidates(t, v, panel)
	}
	return prepareOwnerGroupsChange(t, v, panel, change, group, "", duration)
}

func submitOwnerGroupsReview(t *testing.T, v *codexProductFixture, review ownerGroupsPanel, outcome string) ownerGroupsPanel {
	t.Helper()
	reply, panel, trace := applyOwnerGroupsReview(t, v, review)
	ex := oneOwnerGroupsExchange(t, trace, wire.OperationOwnerEndpointGroupsApply)
	if reply.ActionFailed || panel.Pending || panel.Current || panel.Review != nil || panel.ErrorCode != "" ||
		panel.Outcome != outcome || !ex.Forwarded || ex.Status != 200 || len(ex.response) == 0 {
		t.Fatal("actual App did not retain the reviewed mutation as a historical result")
	}
	return panel
}

func requireOwnerGroupsOriginalIdentities(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, before []ownerGroupsIdentity) {
	t.Helper()
	after := ownerGroupsStoredIdentities(t, v, actors, host.originalSIDs)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("Group mutation replaced an original SID, Endpoint, principal, key, binding or workspace")
	}
	host.command(t, ownerGroupsHostCommand{Action: "checkpoint"})
}

// All positive mutations below are actions of the actual fixture App. The TCP
// proxy changes only delivery. Rejected/uncertain HTTP responses cannot discard
// an original or create an alternative target. No parent signer or SQL grant.
func exerciseOwnerGroupsM1(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity) string {
	t.Helper()
	if len(original) != 4 {
		t.Fatal("M1 requires four actual original native actors")
	}
	d := original[3]
	g2 := exerciseOwnerGroupsCreateRecovery(t, v, actors, d)
	credential := originalOwnerGroupsRESTCredential(t, v, d, actors.active.GroupID)
	router := startOwnerGroupsFabricRouter(t, v)
	defer router.process.kill(t)
	router.requireActor(t, credential, actors.active.GroupID)
	panel := prepareOwnerGroupsEndpointChange(t, v, actors, d, g2, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
	entered, release := armOwnerGroupsFault(t, v.f.proxy, "complete-held-before-forward")
	defer release()
	submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
	select {
	case <-entered:
	case <-time.After(75 * time.Second):
		t.Fatal("actual Node did not reach its exact Group key-completion barrier")
	}
	pending := selectOwnerGroupsThread(t, v, actors.active.NetworkID, d)
	var manualPending bool
	for _, relation := range pending.Selected.Relations {
		if relation.GroupID != g2 {
			continue
		}
		if relation.State != "PENDING_KEY" || relation.OwnerMode != "DEFAULT" || relation.DenyReason != "NONE" || relation.KeyState == "CURRENT" {
			t.Fatal("actual pending manual ADD took over Owner control or exposed completed authority")
		}
		for _, source := range relation.Contributions {
			if source.Source == "OWNER_EXPLICIT" {
				if source.State != "PENDING_KEY" || source.Effective || source.KeyState == "CURRENT" {
					t.Fatal("actual PENDING_KEY contribution granted usable authority")
				}
				manualPending = true
			}
		}
	}
	if !manualPending || ownerGroupsRelationCount(t, v, d.Endpoint, g2) != 0 {
		t.Fatal("actual pending manual contribution created an ACTIVE Endpoint Group edge")
	}
	// The production worker holds its local RPC mutex around the held
	// completion. Verify pending authority at the real Hub Guard while this
	// network fault is active; a concurrent Hook cannot establish a lock SLA.
	status, raw := router.request(t, credential, g2, http.MethodGet, "/v2/fabric/whoami", nil)
	clear(raw)
	if status != http.StatusForbidden {
		t.Fatal("actual pending G2 acquired business authority before key completion")
	}
	router.requireActor(t, credential, actors.active.GroupID)
	nodeDB := nodePairReadOnlyDB(t, filepath.Join(ownerGroupsNodeRoot(v), "node-crypto-state.sqlite"))
	var grants int
	err := nodeDB.QueryRow(`SELECT count(*) FROM node_endpoint_group_sources_v1 WHERE endpoint_id=? AND group_id=? AND source='OWNER_EXPLICIT' AND json_extract(CAST(relation_json AS TEXT),'$.state')='ACTIVE'`, d.Endpoint, g2).Scan(&grants)
	nodeDB.Close()
	if err != nil || grants != 0 {
		t.Fatal("pending completion already persisted an active Node Group grant")
	}
	release()
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	selected := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: 3, Label: "m1-explicit-original-g1", Tool: "cicada_use_group",
		Arguments: map[string]any{"group_id": actors.active.GroupID}, ObserveFields: []string{"group_id"}})
	if selected.Public["group_id"] != actors.active.GroupID {
		t.Fatal("completed ADD prevented explicit original G1 selection")
	}
	host.groups(t, 3, "m1-completed-d", actors.active.NetworkID, actors.active.GroupID, map[string]string{actors.active.GroupID: "DEFAULT_POLICY", g2: "OWNER_EXPLICIT"})
	// Exercise both unauthenticated denial and cryptographic response corruption
	// after actual Hub commits. Each restarts/reconciles the exact original.
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, g2, wire.OwnerEndpointGroupsRemoveEndpoint, "")
	exerciseOwnerGroupsLostApply(t, v, panel, "apply-unsigned403", false)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "REMOVED", "OWNER")
	panel = prepareOwnerGroupsEndpointChange(t, v, actors, d, g2, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
	exerciseOwnerGroupsLostApply(t, v, panel, "apply-corrupt-response", false)
	awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, d, g2, "ACTIVE", "OWNER")
	if ownerGroupsNamedGroupCount(t, v, actors.active.NetworkID, "Synthetic Owner Group G2") != 1 || ownerGroupsRelationCount(t, v, d.Endpoint, g2) != 1 {
		t.Fatal("original mutation recovery created duplicate G2 or exact D relations")
	}
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M1_G2OriginalMutation", map[string]bool{
		"actual_App_Owner_review": true, "one_G2_one_relation": true, "PENDING_KEY_zero_new_rights": true,
		"same_original_packet_after_loss": true, "restart_recovers_original_receipt": true, "identity_and_keys_unchanged": true,
	})
	return g2
}

// Extend the SAME original four native Threads to both Groups. Every new
// relation has its own actual Owner review; selecting/asking never performs Join.
func exerciseOwnerGroupsM2(t *testing.T, v *codexProductFixture, actors nativePeerActors, host *ownerGroupsHost, original []ownerGroupsIdentity, g2 string) {
	t.Helper()
	if len(original) != 4 {
		t.Fatal("M2 requires the original four native Threads")
	}
	database := filepath.Join(v.f.dir, "synthetic-hub", "cicada.sqlite3")
	var before []peerSharedAccessAudit
	var originalG1 []string
	for _, identity := range original {
		before = append(before, peerSharedAccessState(t, database, actors.active.NetworkID, identity.Endpoint))
		originalG1 = append(originalG1, ownerGroupsRelationAuthorityHash(t, v, identity.Endpoint, actors.active.GroupID))
	}
	for index := 0; index < 3; index++ {
		panel := prepareOwnerGroupsEndpointChange(t, v, actors, original[index], g2, wire.OwnerEndpointGroupsAddEndpoint, "until_revoked")
		submitOwnerGroupsReview(t, v, panel, "ADD_SUBMITTED")
		awaitOwnerGroupsRelation(t, v, actors.active.NetworkID, original[index], g2, "ACTIVE", "OWNER")
	}
	var originalG2 []string
	for index, identity := range original {
		selected := host.command(t, ownerGroupsHostCommand{Action: "call", Actor: index, Label: "m2-explicit-original-g1-" + string(rune('a'+index)), Tool: "cicada_use_group",
			Arguments: map[string]any{"group_id": actors.active.GroupID}, ObserveFields: []string{"group_id"}})
		if selected.Public["group_id"] != actors.active.GroupID {
			t.Fatal("exact G2 add prevented explicit authorized G1 selection")
		}
		host.groups(t, index, "m2-self-"+string(rune('a'+index)), actors.active.NetworkID, actors.active.GroupID,
			map[string]string{actors.active.GroupID: "DEFAULT_POLICY", g2: "OWNER_EXPLICIT"})
		if ownerGroupsRelationCount(t, v, identity.Endpoint, actors.active.GroupID) != 1 || ownerGroupsRelationCount(t, v, identity.Endpoint, g2) != 1 {
			t.Fatal("actual original native Endpoint does not retain two independent active Group edges")
		}
		originalG2 = append(originalG2, ownerGroupsRelationAuthorityHash(t, v, identity.Endpoint, g2))
		after := peerSharedAccessState(t, database, actors.active.NetworkID, identity.Endpoint)
		if after.Access != before[index].Access || after.Membership != before[index].Membership || after.Endpoint != before[index].Endpoint ||
			after.AccessRows != before[index].AccessRows || after.MembershipRows != before[index].MembershipRows || after.EndpointRows != before[index].EndpointRows ||
			ownerGroupsRelationAuthorityHash(t, v, identity.Endpoint, actors.active.GroupID) != originalG1[index] {
			t.Fatal("exact Group add replaced shared Network authority for an original native Endpoint")
		}
	}
	host.roundtrip(t, "m2-g2-db", g2, 3, 1, original)
	host.roundtrip(t, "m2-g2-ac", g2, 0, 2, original)
	host.roundtrip(t, "m2-g1-da", actors.active.GroupID, 3, 0, original)
	host.roundtrip(t, "m2-g1-bc", actors.active.GroupID, 1, 2, original)
	for index, identity := range original {
		if ownerGroupsRelationAuthorityHash(t, v, identity.Endpoint, actors.active.GroupID) != originalG1[index] ||
			ownerGroupsRelationAuthorityHash(t, v, identity.Endpoint, g2) != originalG2[index] {
			t.Fatal("explicit Group selection or communication mutated original shared grants or credentials")
		}
	}
	requireOwnerGroupsOriginalIdentities(t, v, actors, host, original)
	observeOwnerGroupsCase(t, "M2_ExactMultiGroup", map[string]bool{
		"four_original_native_threads": true, "original_SID_Endpoint_key_workspace": true,
		"fresh_OWNER_ENDPOINT_GROUPS_V1": true, "explicit_group_selection": true,
		"Cicada_request_reply_correlation": true, "Group_grants_independent": true,
	})
}
