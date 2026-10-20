package store

import (
	"fmt"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestNodeAvailableNativePairsFiltersBeforeLimit(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, seal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, seal); err != nil {
		t.Fatal(err)
	}
	// The current partial unique index normally permits only one nonterminal
	// Pair per Owner/Node. This disposable cardinality probe deliberately lifts
	// that index, inserts 64 unusable old candidates and retains the real signed
	// Pair. No forged candidate may reach proof verification or hide the valid one.
	if _, err := f.f.db.db.Exec(`DROP INDEX hub_native_pairs_v1_nonterminal`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		id := fmt.Sprintf("000-old-%02d", i)
		if _, err := f.f.db.db.Exec(`INSERT INTO hub_native_pairs_v1
(pair_id,hub_id,account_id,owner_id,device_id,node_id,network_id,group_id,scope_json,bootstrap_json,bootstrap_owner_proof,state,control_revision,plan_id,prepare_operation_id,proof_expires_at,join_until,peer_expires_at,created_at,terminal_reason,account_hub_identity_json)
SELECT ?,hub_id,account_id,owner_id,device_id,node_id,?,?,scope_json,bootstrap_json,bootstrap_owner_proof,state,control_revision,plan_id,prepare_operation_id,proof_expires_at,join_until,peer_expires_at,created_at,terminal_reason,account_hub_identity_json FROM hub_native_pairs_v1 WHERE pair_id=?`, id, "net-"+id, "group-"+id, ch.Bootstrap.PairID); err != nil {
			t.Fatal(err)
		}
	}
	var digest string
	if err := f.f.db.db.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=?`, f.scope.Node.OwnerBindingID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	b, err := f.f.db.NodeControlKeyForCredential(digest, f.scope.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	in := endpointRPC(t, f.f.db, b, digest, nodewire.NativePairAvailableOperation, 1)
	result, err := f.f.db.AvailableNodeNativePairs(in, f.f.nodeControl.Public())
	if err != nil || result.Truncated || len(result.Pairs) != 1 || result.Pairs[0].PairID != ch.Bootstrap.PairID || len(result.Pairs[0].Slots) != 2 {
		t.Fatal("old unusable candidates hid valid signed Pair", err)
	}
	if _, err = f.f.db.RevokeNodeDeviceBinding(f.scope.Actor.OwnerID, b.OwnerBindingID, int64(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.AvailableNodeNativePairs(in, f.f.nodeControl.Public()); err == nil {
		t.Fatal("revoked Node enumerated Owner Pair slots")
	}
}
