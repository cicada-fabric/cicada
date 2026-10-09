//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// Synthetic callbacks isolate the production immutable-snapshot batch planner.
// They do not stand in for durable Store delivery or Node Runtime consumption.
func TestStressGroupBroadcast32RecipientPagination(t *testing.T) {
	request, snapshot, _ := validGroupBroadcastFixture(t, groupBroadcastMaxRecipients)
	samples := make([]time.Duration, 0, 40)
	var remoteCalls int
	for sweep := 0; sweep < 10; sweep++ {
		seen := make(map[string]struct{}, len(snapshot.Recipients))
		offset := 0
		for offset < len(snapshot.Recipients) {
			pageRequest := request
			pageRequest.Offset = offset
			started := time.Now()
			result, err := fanoutGroupBroadcastBatch(pageRequest, snapshot, "node-local",
				func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
					remoteCalls++
					messageID, _, err := localSealedRPCIDs(operationID)
					return messageID, err
				},
				func(recipient store.SameGroupBroadcastV2Endpoint, operationID string) (string, error) {
					remoteCalls++
					messageID, _, err := localSealedRPCIDs(operationID)
					return messageID, err
				})
			samples = append(samples, time.Since(started))
			if err != nil || result.Offset != offset || len(result.Recipients) != groupBroadcastBatchSize ||
				result.RecipientCount != groupBroadcastMaxRecipients || result.NextOffset != offset+groupBroadcastBatchSize ||
				result.Complete != (result.NextOffset == groupBroadcastMaxRecipients) {
				t.Fatalf("batch offset=%d result=%+v err=%v", offset, result, err)
			}
			for _, recipient := range result.Recipients {
				if recipient.State != "ACCEPTED" || recipient.MessageID == "" {
					t.Fatalf("synthetic child was not correlated: %+v", recipient)
				}
				if _, duplicate := seen[recipient.EndpointID]; duplicate {
					t.Fatalf("endpoint appeared in multiple pages: %s", recipient.EndpointID)
				}
				seen[recipient.EndpointID] = struct{}{}
			}
			offset = result.NextOffset
		}
		if len(seen) != groupBroadcastMaxRecipients {
			t.Fatalf("sweep delivered %d unique endpoints, want %d", len(seen), groupBroadcastMaxRecipients)
		}
	}
	metric := map[string]any{
		"schema": "cicada.v01.stress.metric.v1", "stage": "broadcast_batch_planning",
		"recipients_per_sweep": groupBroadcastMaxRecipients, "batch_size": groupBroadcastBatchSize,
		"sweeps": 10, "page_samples": len(samples), "synthetic_child_callbacks": remoteCalls,
		"elapsed_ms": durationSum(samples).Milliseconds(), "throughput_page_ops_s": ratePerSecondFloat(float64(len(samples)), durationSum(samples)),
		"latency_p50_ms": durationPercentileMs(samples, 0.50), "latency_p95_ms": durationPercentileMs(samples, 0.95),
	}
	emitCommandStressMetric(t, metric)

	overLimitRequest, overLimitSnapshot, _ := validGroupBroadcastFixture(t, groupBroadcastMaxRecipients+1)
	called := 0
	started := time.Now()
	if _, err := fanoutGroupBroadcastBatch(overLimitRequest, overLimitSnapshot, "node-local",
		func(store.SameGroupBroadcastV2Endpoint, string) (string, error) { called++; return "", nil },
		func(store.SameGroupBroadcastV2Endpoint, string) (string, error) { called++; return "", nil }); err == nil {
		t.Fatal("33-recipient snapshot passed the production batch planner")
	}
	if called != 0 {
		t.Fatalf("over-limit snapshot called delivery callback %d times", called)
	}
	emitCommandStressMetric(t, map[string]any{
		"schema": "cicada.v01.stress.metric.v1", "stage": "broadcast_batch_over_limit",
		"requested_recipients": groupBroadcastMaxRecipients + 1, "callbacks": called,
		"elapsed_ms": time.Since(started).Milliseconds(), "rejected": true,
	})
}

// This uses the real authenticated Fabric HTTP handler for Node joins,
// directory reads, and ambiguity resolution. The owner and Group rows are
// fixture bootstrap; every Endpoint and both Group relations are created by
// the guarded Node-join route. Directory has a bounded Limit but no cursor,
// so this records 100/500/1000 response boundaries without claiming callers
// can page beyond the 1000-row API ceiling.
func TestStressFabricHTTPDirectory1001JoinBoundaryAndAlias(t *testing.T) {
	const (
		ownerID = "PUBLIC_SYNTHETIC_stress_directory_owner"
		groupID = "PUBLIC_SYNTHETIC_stress_directory_group"
		nodeID  = "PUBLIC_SYNTHETIC_stress_directory_node"
		alias   = "stress-duplicate-alias"
	)
	persistence, err := store.New(filepath.Join(t.TempDir(), "PUBLIC_SYNTHETIC_fabric.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	owner, err := persistence.CreatePrincipal(store.Principal{ID: ownerID,
		Kind: store.PrincipalKindHuman, OwnerID: ownerID, TrustDomainID: ownerID,
		Name: ownerID, Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.CreateGroup(store.Group{ID: groupID, Name: groupID,
		OwnerPrincipalID: owner.ID, TrustDomainID: owner.TrustDomainID,
		State: store.GroupStateActive}); err != nil {
		t.Fatal(err)
	}
	nodeToken, err := bindNativeE2ETestNode(persistence, ownerID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(persistence, ownerID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	hub := httptest.NewServer(serverpkg.NewFabricHandler(service, ""))
	t.Cleanup(hub.Close)
	client := &http.Client{Timeout: 10 * time.Second}
	join := func(index int, endpointName string) fabric.JoinResult {
		t.Helper()
		nativeID := fmt.Sprintf("PUBLIC_SYNTHETIC_native_%04d", index)
		requestBody, err := json.Marshal(map[string]any{
			"group_id": groupID, "endpoint_name": endpointName, "harness": "codex",
			"native_session_id": nativeID, "lease_seconds": 3600,
		})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, hub.URL+"/v2/fabric/node/join", bytes.NewReader(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "CicadaNode "+nodeToken)
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("guarded Node join %d: %v", index, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			_, _ = io.Copy(io.Discard, response.Body)
			t.Fatalf("guarded Node join %d status=%d, want 201", index, response.StatusCode)
		}
		var joined fabric.JoinResult
		if err := json.NewDecoder(response.Body).Decode(&joined); err != nil ||
			joined.Endpoint.ID == "" || joined.Endpoint.GroupID != groupID ||
			joined.SessionToken == "" || joined.BindingID == "" || joined.BindingEpoch == 0 {
			t.Fatalf("guarded Node join %d returned incomplete binding, err=%v", index, err)
		}
		return joined
	}
	first := join(0, alias)

	unauthorized, err := http.NewRequest(http.MethodGet, hub.URL+"/v2/fabric/members?limit=100", nil)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Header.Set("Cicada-Group-Scope", groupID)
	unauthorizedResponse, err := client.Do(unauthorized)
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorizedResponse.Body.Close()
	if unauthorizedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated directory request status=%d, want 401", unauthorizedResponse.StatusCode)
	}

	// Store timestamps have second precision. Separate the old alias from the
	// remaining 1000 legal joins so it is deterministically outside the newest
	// 1000-row response, while retaining the exact same alias.
	boundary := time.Now().UTC().Truncate(time.Second).Add(time.Second + 20*time.Millisecond)
	time.Sleep(time.Until(boundary))
	seedStarted := time.Now()
	for index := 1; index <= 999; index++ {
		join(index, fmt.Sprintf("PUBLIC_SYNTHETIC_filler_%04d", index))
	}
	newAlias := join(1000, alias)
	seedElapsed := time.Since(seedStarted)

	directoryGET := func(limit int) ([]fabric.NetworkCard, time.Duration) {
		t.Helper()
		started := time.Now()
		request, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("%s/v2/fabric/members?limit=%d", hub.URL, limit), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "CicadaSession "+first.SessionToken)
		request.Header.Set("Cicada-Group-Scope", groupID)
		response, err := client.Do(request)
		elapsed := time.Since(started)
		if err != nil {
			t.Fatalf("authenticated directory limit=%d: %v", limit, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, response.Body)
			t.Fatalf("authenticated directory limit=%d status=%d, want 200", limit, response.StatusCode)
		}
		var body struct {
			Endpoints []fabric.NetworkCard `json:"endpoints"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode authenticated directory limit=%d: %v", limit, err)
		}
		if len(body.Endpoints) != limit {
			t.Fatalf("directory limit=%d returned %d endpoints", limit, len(body.Endpoints))
		}
		seen := make(map[string]struct{}, len(body.Endpoints))
		for _, card := range body.Endpoints {
			if card.EndpointID == "" || card.GroupID != groupID || card.BindingID == "" || card.BindingEpoch == 0 {
				t.Fatal("directory returned an incomplete or cross-Group card")
			}
			if _, duplicate := seen[card.EndpointID]; duplicate {
				t.Fatal("directory page repeated an Endpoint")
			}
			seen[card.EndpointID] = struct{}{}
		}
		return body.Endpoints, elapsed
	}

	for _, limit := range []int{100, 500, 1000} {
		latencies := make([]time.Duration, 10)
		var rows int
		for sample := range latencies {
			cards, elapsed := directoryGET(limit)
			latencies[sample] = elapsed
			rows = len(cards)
		}
		total := durationSum(latencies)
		emitCommandStressMetric(t, map[string]any{
			"stage": "authenticated_fabric_http_directory_list",
			"limit": limit, "records_per_response": rows, "samples": len(latencies),
			"elapsed_ms": total.Milliseconds(), "throughput_ops_s": ratePerSecondFloat(float64(len(latencies)), total),
			"latency_p50_ms": durationPercentileMs(latencies, 0.50),
			"latency_p95_ms": durationPercentileMs(latencies, 0.95),
		})
	}

	page, _ := directoryGET(1000)
	oldVisible, newVisible := false, false
	for _, card := range page {
		oldVisible = oldVisible || card.EndpointID == first.Endpoint.ID
		newVisible = newVisible || card.EndpointID == newAlias.Endpoint.ID
	}
	if oldVisible || !newVisible {
		t.Fatalf("directory boundary fixture invalid: old_visible=%t new_visible=%t", oldVisible, newVisible)
	}
	resolveBody, err := json.Marshal(fabric.ResolveInput{Query: alias})
	if err != nil {
		t.Fatal(err)
	}
	resolveRequest, err := http.NewRequest(http.MethodPost, hub.URL+"/v2/fabric/resolve", bytes.NewReader(resolveBody))
	if err != nil {
		t.Fatal(err)
	}
	resolveRequest.Header.Set("Authorization", "CicadaSession "+first.SessionToken)
	resolveRequest.Header.Set("Cicada-Group-Scope", groupID)
	resolveRequest.Header.Set("Content-Type", "application/json")
	resolveResponse, err := client.Do(resolveRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer resolveResponse.Body.Close()
	if resolveResponse.StatusCode != http.StatusConflict {
		_, _ = io.Copy(io.Discard, resolveResponse.Body)
		t.Fatalf("active HTTP resolver status=%d, want 409 for duplicate alias", resolveResponse.StatusCode)
	}
	var conflict struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resolveResponse.Body).Decode(&conflict); err != nil ||
		!strings.Contains(strings.ToLower(conflict.Error), "ambiguous") {
		t.Fatal("active HTTP resolver did not report an ambiguity conflict")
	}
	emitCommandStressMetric(t, map[string]any{
		"stage":            "authenticated_fabric_http_resolve_duplicate_alias",
		"legal_node_joins": 1001, "bounded_directory_limit": 1000,
		"old_match_outside_page": true, "new_match_inside_page": true,
		"ambiguous_conflict": true, "seed_elapsed_ms": seedElapsed.Milliseconds(),
	})
}

func emitCommandStressMetric(t *testing.T, fields map[string]any) {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err == nil {
		fields["process_peak_rss_kib"] = usage.Maxrss
		fields["process_user_cpu_ms"] = usage.Utime.Sec*1000 + usage.Utime.Usec/1000
		fields["process_system_cpu_ms"] = usage.Stime.Sec*1000 + usage.Stime.Usec/1000
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encode command stress metric: %v", err)
	}
	t.Logf("CICADA_STRESS_METRIC %s", encoded)
}

func durationSum(samples []time.Duration) time.Duration {
	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	return total
}

func durationPercentileMs(samples []time.Duration, percentile float64) float64 {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return float64(ordered[index].Microseconds()) / 1000
}

func ratePerSecondFloat(count float64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return count / elapsed.Seconds()
}
