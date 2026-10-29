package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Two different Owner intents compete for the same reviewed authority snapshot.
// This is not the existing duplicate-Complete or direct/reconcile race.
func TestEndpointGroupsIndependentAddRemoveSameCASHasSingleEffect(t *testing.T) {
	domain := localDomainStore(t)
	d := domain.activate(t)
	join, _ := domain.join(t, d, "synthetic-add-remove-original")
	otherJoin, _ := domain.join(t, d, "synthetic-add-remove-unaffected")
	for _, original := range []wire.LocalDomainNodeJoinResult{join, otherJoin} {
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		domain.keyReady(t, d, original, key)
	}
	f := domain.f.f
	endpointGroupsOwnerTestInitialize(t, f)
	at := f.now.Add(10 * time.Second)
	var requests [2]wire.OwnerEndpointGroupsApplyRequest
	var inputs [2]HubEndpointGroupsInput
	var seals [2]HubEndpointGroupsSeal
	var reviews [2]wire.OwnerEndpointGroupsReview
	for i, action := range []string{wire.OwnerEndpointGroupsAddEndpoint, wire.OwnerEndpointGroupsRemoveEndpoint} {
		body := wire.OwnerEndpointGroupsPrepareBody{Action: action, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, GroupID: d.Policy.GroupID, EndpointID: join.Member.EndpointID}
		if i == 0 {
			body.Duration = "until_revoked"
		}
		q, prepared, review := endpointGroupsOwnerTestPrepareBusiness(t, f, body, at)
		apply, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope, q, prepared.Packet, review, f.owner, at.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		requests[i], reviews[i] = apply, review
		inputs[i], seals[i] = endpointGroupsOwnerTestInput(t, f, apply, at.Add(time.Second))
	}
	if requests[0].Context.RequestID == requests[1].Context.RequestID || reviews[0].ReviewID == reviews[1].ReviewID || reviews[0].Expected != reviews[1].Expected {
		t.Fatal("competition lacks distinct intents/reviews at the same complete CAS")
	}
	// These rows are authority/identity, not transport or replay bookkeeping.
	stable := func(s *Store) []byte {
		t.Helper()
		var snapshot []any
		for _, query := range []string{
			`SELECT id,principal_id,group_id,role,revision,grants_json FROM memberships ORDER BY id`,
			`SELECT * FROM fabric_endpoints ORDER BY id`,
			`SELECT * FROM endpoint_key_candidates_v2 ORDER BY endpoint_id`,
		} {
			rows, err := s.db.Query(query)
			if err != nil {
				t.Fatal(err)
			}
			columns, err := rows.Columns()
			if err != nil {
				t.Fatal(err)
			}
			var values [][]any
			for rows.Next() {
				row, pointers := make([]any, len(columns)), make([]any, len(columns))
				for i := range row {
					pointers[i] = &row[i]
				}
				if err := rows.Scan(pointers...); err != nil {
					t.Fatal(err)
				}
				values = append(values, row)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			snapshot = append(snapshot, values)
		}
		raw, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := stable(f.db)
	other, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	stores := [2]*Store{f.db, other}
	var receipts [2][]byte
	var failures [2]error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			receipts[i], failures[i] = stores[i].ProcessHubEndpointGroups(inputs[i], seals[i])
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	defaultHead := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	for i := range receipts {
		if failures[i] != nil {
			t.Fatal("independent CAS request failed before an authenticated result", failures[i])
		}
		result := endpointGroupsOwnerTestOpen(t, f, inputs[i], receipts[i])
		if result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(reviews[i], inputs[i].Packet, *result.Operation, &defaultHead) != nil {
			t.Fatal("independent result lost its original approved scope")
		}
		switch result.State {
		case "COMPLETED":
			if winner != -1 || result.ErrorCode != "" || result.Operation.Effect == nil {
				t.Fatal("more than one effect committed")
			}
			winner = i
		case "REJECTED_FENCED":
			if result.ErrorCode != "CAS_CONFLICT" || result.Operation.Effect != nil {
				t.Fatal("loser did not return a zero-effect authenticated CAS conflict")
			}
		default:
			t.Fatal("independent CAS outcome remains uncertain")
		}
		var consumed, state string
		if err := f.db.db.QueryRow(`SELECT state,consumed_operation_id FROM hub_endpoint_groups_reviews_v1 WHERE review_id=?`, reviews[i].ReviewID).Scan(&state, &consumed); err != nil || state != "CONSUMED" || consumed != requests[i].Context.RequestID {
			t.Fatal("review was not consumed by its own original", err)
		}
	}
	if winner < 0 {
		t.Fatal("neither independently approved operation committed")
	}
	// Reopen the durable Store, then replay both byte-identical originals. The
	// rejected ADD cannot later erase REMOVE's deny; rejected REMOVE cannot apply.
	reopened, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for i := range inputs {
		if retry, err := reopened.ProcessHubEndpointGroups(inputs[i], seals[i]); err != nil || !bytes.Equal(retry, receipts[i]) {
			t.Fatal("reopen changed an original exact receipt", err)
		}
	}
	read := func(endpoint string) wire.OwnerEndpointGroupsRelationCard {
		t.Helper()
		q, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "RELATIONS", NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, EndpointID: endpoint}, f.owner, at.Add(2*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		in, seal := endpointGroupsOwnerTestInput(t, f, q, at.Add(2*time.Second))
		raw, err := reopened.ProcessHubEndpointGroups(in, seal)
		if err != nil {
			t.Fatal(err)
		}
		out := endpointGroupsOwnerTestOpen(t, f, in, raw)
		for _, card := range out.Relations {
			if card.GroupID == d.Policy.GroupID {
				return card
			}
		}
		t.Fatal("original relation disappeared")
		return wire.OwnerEndpointGroupsRelationCard{}
	}
	card := read(join.Member.EndpointID)
	if winner == 0 {
		pending := false
		for _, c := range card.Contributions {
			if c.Source == "OWNER_EXPLICIT" && c.State == "PENDING_KEY" && !c.Effective {
				pending = true
			}
		}
		if card.State != "ACTIVE" || card.OwnerControl != defaultHead || !pending {
			t.Fatal("winning ADD activated keys or removed the surviving default")
		}
	} else if card.State != "REMOVED" || card.OwnerControl.Mode != "OWNER" || card.OwnerControl.DenyReason != "REMOVED" {
		t.Fatal("winning REMOVE lost its permanent deny")
	}
	unaffected := read(otherJoin.Member.EndpointID)
	if unaffected.State != "ACTIVE" || unaffected.OwnerControl != defaultHead || !reflect.DeepEqual(before, stable(reopened)) {
		t.Fatal("race changed original identities, keys or shared Principal authority")
	}
	t.Logf("CLOSED_INDEPENDENT_ADD_REMOVE same_CAS=true independent_reviews=2 effects=1 conflict_zero_effects=1 exact_reopen_receipts=2 other_endpoint_identity_keys_membership_preserved=true winner=%s", reviews[winner].Action)
}
