package nodeinbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// These independent acceptance cases express the newly confirmed one-Network
// requirement through the existing production registry APIs and real on-disk
// SQLite. They deliberately fail against the old permissive group_scoped rule.
// No new reservation API, trusted Host event, Leave, remote Join, Worker grant
// or external Runtime is simulated here; those require their actual carriers.
func acceptanceThreadScopeInput(enrollment bool) NativeContextScopeInput {
	in := NativeContextScopeInput{
		AccountID: "SYNTHETIC-verified-account", Harness: "codex", NativeSessionID: "SYNTHETIC-original-thread",
		HubID: "SYNTHETIC-hub-a", NetworkID: "SYNTHETIC-network-a", GroupID: "SYNTHETIC-group-a",
		ContextPolicy: NativeContextPolicyGroupScoped, EndpointID: "SYNTHETIC-endpoint-a",
		BindingID: "SYNTHETIC-binding-a", BindingEpoch: 1,
	}
	if enrollment {
		in.GroupID, in.ContextPolicy = "", ""
	}
	return in
}

func acceptanceOpenThreadRegistry(t *testing.T, path string) *NativeContextRegistry {
	t.Helper()
	r, err := OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal("open real disposable registry", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func acceptanceThreadRegistryPath(t *testing.T) string {
	t.Helper()
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(private, "SYNTHETIC-native-context.sqlite3")
}

func acceptanceRecordThreadScope(r *NativeContextRegistry, in NativeContextScopeInput, enrollment bool) (*NativeContextScopeDecision, error) {
	if enrollment {
		return r.CheckAndRecordNetworkEnrollmentContext(context.Background(), in)
	}
	return r.CheckAndRecordNativeContext(context.Background(), in)
}

func acceptanceRequireThreadScope(t *testing.T, r *NativeContextRegistry, in NativeContextScopeInput, enrollment bool) {
	t.Helper()
	decision, err := acceptanceRecordThreadScope(r, in, enrollment)
	if err != nil || decision == nil || !decision.Accepted {
		t.Fatal("valid original registry scope refused", err)
	}
}

type acceptanceThreadHistoryRow struct {
	Identity, Account, Harness, Hub, Network, Group, Policy, Endpoint, Binding string
	Epoch                                                                      uint64
}

func acceptanceThreadHistory(t *testing.T, r *NativeContextRegistry) []acceptanceThreadHistoryRow {
	t.Helper()
	rows, err := r.db.Query(`SELECT identity_digest,account_digest,harness,hub_id,network_id,group_id,context_policy,endpoint_id,binding_id,binding_epoch
FROM node_native_context_history_v1 ORDER BY identity_digest,hub_id,network_id,group_id,context_policy,endpoint_id,binding_id,binding_epoch`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []acceptanceThreadHistoryRow
	for rows.Next() {
		var row acceptanceThreadHistoryRow
		if err := rows.Scan(&row.Identity, &row.Account, &row.Harness, &row.Hub, &row.Network, &row.Group, &row.Policy, &row.Endpoint, &row.Binding, &row.Epoch); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

var acceptanceThreadEvidenceMu sync.Mutex

func acceptanceThreadObservation(t *testing.T, expected string, err error, before, after []acceptanceThreadHistoryRow) {
	t.Helper()
	message := ""
	if err != nil {
		message = err.Error()
	}
	record := struct {
		Test, Expected, Error string
		Before, After         []acceptanceThreadHistoryRow
	}{t.Name(), expected, message, before, after}
	if directory := os.Getenv("CICADA_THREAD_SCOPE_OUTPUT"); directory != "" {
		acceptanceThreadEvidenceMu.Lock()
		defer acceptanceThreadEvidenceMu.Unlock()
		file, openErr := os.OpenFile(filepath.Join(directory, "registry-observations.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if openErr != nil {
			t.Fatal(openErr)
		}
		encodeErr := json.NewEncoder(file).Encode(record)
		closeErr := file.Close()
		if encodeErr != nil || closeErr != nil {
			t.Fatal(encodeErr, closeErr)
		}
	}
	t.Logf("expected=%s error=%q before_rows=%d after_rows=%d", expected, message, len(before), len(after))
}

func acceptanceRefuseThreadScope(t *testing.T, r *NativeContextRegistry, in NativeContextScopeInput, enrollment bool) {
	t.Helper()
	before := acceptanceThreadHistory(t, r)
	decision, err := acceptanceRecordThreadScope(r, in, enrollment)
	after := acceptanceThreadHistory(t, r)
	acceptanceThreadObservation(t, "scope conflict without business-history mutation", err, before, after)
	if !errors.Is(err, ErrNativeContextScopeConflict) || decision != nil && decision.Accepted {
		t.Error("same actual Thread accepted a second Network or changed its verified account")
	}
	if !reflect.DeepEqual(before, after) {
		t.Error("refused scope attempt changed authoritative registry history")
	}
}

func TestAcceptanceNativeThreadNetworkIsolation(t *testing.T) {
	for _, firstRoute := range []string{"group", "enrollment"} {
		for _, nextRoute := range []string{"group", "enrollment"} {
			for _, mutation := range []string{"same-hub-other-network", "other-hub-same-network-name", "other-hub-other-network", "changed-account-same-network"} {
				t.Run(firstRoute+"/"+nextRoute+"/"+mutation, func(t *testing.T) {
					r := acceptanceOpenThreadRegistry(t, acceptanceThreadRegistryPath(t))
					first := acceptanceThreadScopeInput(firstRoute == "enrollment")
					acceptanceRequireThreadScope(t, r, first, firstRoute == "enrollment")
					next := acceptanceThreadScopeInput(nextRoute == "enrollment")
					next.EndpointID, next.BindingID, next.BindingEpoch = "SYNTHETIC-endpoint-b", "SYNTHETIC-binding-b", 2
					switch mutation {
					case "same-hub-other-network":
						next.NetworkID = "SYNTHETIC-network-b"
					case "other-hub-same-network-name":
						next.HubID = "SYNTHETIC-hub-b"
					case "other-hub-other-network":
						next.HubID, next.NetworkID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b"
					case "changed-account-same-network":
						next.AccountID = "SYNTHETIC-different-account-declaration"
					}
					acceptanceRefuseThreadScope(t, r, next, nextRoute == "enrollment")
				})
			}
		}
	}
}

func TestAcceptanceNativeThreadSameNetworkMultipleGroups(t *testing.T) {
	r := acceptanceOpenThreadRegistry(t, acceptanceThreadRegistryPath(t))
	enrollment := acceptanceThreadScopeInput(true)
	acceptanceRequireThreadScope(t, r, enrollment, true)
	first := acceptanceThreadScopeInput(false)
	acceptanceRequireThreadScope(t, r, first, false)
	second := first
	second.GroupID = "SYNTHETIC-group-b"
	acceptanceRequireThreadScope(t, r, second, false)
	// This is registry metadata only. It does not grant a Worker permission to
	// join another Group; the independently current class/Group Guard still runs.
	rows := acceptanceThreadHistory(t, r)
	for _, row := range rows {
		if row.Hub != first.HubID || row.Network != first.NetworkID || row.Endpoint != first.EndpointID {
			t.Fatal("same-Network metadata changed the original coordinates")
		}
	}
	acceptanceThreadObservation(t, "same Network may contain separately authorized Groups", nil, nil, rows)
}

func TestAcceptanceNativeThreadDifferentSIDsMayUseDifferentNetworks(t *testing.T) {
	r := acceptanceOpenThreadRegistry(t, acceptanceThreadRegistryPath(t))
	first := acceptanceThreadScopeInput(true)
	acceptanceRequireThreadScope(t, r, first, true)
	second := first
	second.NativeSessionID = "SYNTHETIC-independent-thread"
	second.HubID, second.NetworkID, second.EndpointID, second.BindingID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b", "SYNTHETIC-endpoint-b", "SYNTHETIC-binding-b"
	acceptanceRequireThreadScope(t, r, second, true)
	rows := acceptanceThreadHistory(t, r)
	if len(rows) != 2 || rows[0].Identity == rows[1].Identity {
		t.Fatal("different actual Threads were combined into one identity")
	}
	acceptanceThreadObservation(t, "different native Threads may choose different Networks", nil, nil, rows)
}

func TestAcceptanceNativeThreadNetworkHistorySurvivesColdReopen(t *testing.T) {
	for _, route := range []string{"group", "enrollment"} {
		t.Run(route, func(t *testing.T) {
			path := acceptanceThreadRegistryPath(t)
			r := acceptanceOpenThreadRegistry(t, path)
			first := acceptanceThreadScopeInput(route == "enrollment")
			acceptanceRequireThreadScope(t, r, first, route == "enrollment")
			before := acceptanceThreadHistory(t, r)
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			r = acceptanceOpenThreadRegistry(t, path)
			if !reflect.DeepEqual(before, acceptanceThreadHistory(t, r)) {
				t.Fatal("cold reopen lost original scope history")
			}
			next := first
			next.HubID, next.NetworkID, next.EndpointID, next.BindingID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b", "SYNTHETIC-endpoint-b", "SYNTHETIC-binding-b"
			acceptanceRefuseThreadScope(t, r, next, route == "enrollment")
		})
	}
}

func TestAcceptanceNativeThreadConcurrentNetworkClaim(t *testing.T) {
	for _, route := range []string{"group", "enrollment"} {
		t.Run(route, func(t *testing.T) {
			path := acceptanceThreadRegistryPath(t)
			a, b := acceptanceOpenThreadRegistry(t, path), acceptanceOpenThreadRegistry(t, path)
			inputs := [2]NativeContextScopeInput{acceptanceThreadScopeInput(route == "enrollment"), acceptanceThreadScopeInput(route == "enrollment")}
			inputs[1].HubID, inputs[1].NetworkID, inputs[1].EndpointID, inputs[1].BindingID = "SYNTHETIC-hub-b", "SYNTHETIC-network-b", "SYNTHETIC-endpoint-b", "SYNTHETIC-binding-b"
			start := make(chan struct{})
			var wg sync.WaitGroup
			var outcomes [2]error
			for i, r := range []*NativeContextRegistry{a, b} {
				wg.Add(1)
				go func(i int, r *NativeContextRegistry) {
					defer wg.Done()
					<-start
					_, outcomes[i] = acceptanceRecordThreadScope(r, inputs[i], route == "enrollment")
				}(i, r)
			}
			close(start)
			wg.Wait()
			winners := 0
			for _, err := range outcomes {
				if err == nil {
					winners++
				} else if !errors.Is(err, ErrNativeContextScopeConflict) {
					t.Errorf("contention produced an unrelated storage error: %v", err)
				}
			}
			rows := acceptanceThreadHistory(t, a)
			acceptanceThreadObservation(t, "one committed Network winner across real SQLite handles", nil, nil, rows)
			if winners != 1 || len(rows) != 1 {
				t.Errorf("concurrent same-Thread claims: winners=%d authoritative_rows=%d; want one", winners, len(rows))
			}
		})
	}
}
