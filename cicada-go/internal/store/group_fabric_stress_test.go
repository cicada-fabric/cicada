//go:build linux

package store

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"syscall"
	"testing"
	"time"
)

// These bounded PUBLIC_SYNTHETIC stress tests exercise the real Store APIs.
// They measure storage/query work only; they do not model Hub+Node deployment
// memory, live Runtime consumption, or provider throughput.
func TestStressGroupDirectoryAndMembershipLimits(t *testing.T) {
	f := newSameGroupSealedV1Fixture(t)
	owner := f.ownerID

	seedStart := time.Now()
	for i := 0; i < 999; i++ { // the fixture already has one owner Group
		groupID := fmt.Sprintf("grp_stress_%04d", i)
		if _, err := f.store.CreateGroup(Group{ID: groupID, OwnerPrincipalID: owner,
			TrustDomainID: owner, Name: groupID, State: GroupStateActive}); err != nil {
			t.Fatalf("create synthetic Group %d: %v", i, err)
		}
	}
	for i := 0; i < 997; i++ { // the fixture already has three active Group memberships
		principalID := fmt.Sprintf("pr_stress_member_%04d", i)
		if _, err := f.store.CreatePrincipal(Principal{ID: principalID, Kind: PrincipalKindAgent,
			OwnerID: owner, TrustDomainID: owner, Name: principalID, Status: PrincipalStatusActive}); err != nil {
			t.Fatalf("create synthetic member Principal %d: %v", i, err)
		}
		if _, err := f.store.CreateMembership(Membership{PrincipalID: principalID, GroupID: f.groupID,
			Role: "member", Grants: []string{"message.receive"}, Status: MembershipStatusActive}); err != nil {
			t.Fatalf("create synthetic Group membership %d: %v", i, err)
		}
	}
	seedElapsed := time.Since(seedStart)

	for _, limit := range []int{100, 500, 1000} {
		latencies := make([]time.Duration, 12)
		var records int
		for sample := range latencies {
			started := time.Now()
			groups, err := f.store.ListGroups(GroupFilter{Owner: owner, Limit: limit})
			latencies[sample] = time.Since(started)
			if err != nil {
				t.Fatalf("ListGroups limit=%d: %v", limit, err)
			}
			if len(groups) != limit {
				t.Fatalf("ListGroups limit=%d returned %d of 1000 owner Groups", limit, len(groups))
			}
			records = len(groups)
		}
		emitStoreStressMetric(t, "group_directory_list", map[string]any{
			"requested_limit": limit, "records_per_operation": records,
			"samples": len(latencies), "elapsed_ms": totalDuration(latencies).Milliseconds(),
			"throughput_ops_s": groupRatePerSecond(len(latencies), totalDuration(latencies)),
			"latency_p50_ms":   percentileMilliseconds(latencies, 0.50),
			"latency_p95_ms":   percentileMilliseconds(latencies, 0.95),
		})
	}

	for _, limit := range []int{100, 500, 1000} {
		latencies := make([]time.Duration, 12)
		for sample := range latencies {
			started := time.Now()
			members, err := f.store.ListMemberships(MembershipFilter{GroupID: f.groupID, Limit: limit})
			latencies[sample] = time.Since(started)
			if err != nil || len(members) != limit {
				t.Fatalf("ListMemberships limit=%d returned=%d err=%v", limit, len(members), err)
			}
		}
		emitStoreStressMetric(t, "group_membership_list", map[string]any{
			"requested_limit": limit, "records_per_operation": limit,
			"samples": len(latencies), "elapsed_ms": totalDuration(latencies).Milliseconds(),
			"throughput_ops_s": groupRatePerSecond(len(latencies), totalDuration(latencies)),
			"latency_p50_ms":   percentileMilliseconds(latencies, 0.50),
			"latency_p95_ms":   percentileMilliseconds(latencies, 0.95),
		})
	}
	emitStoreStressMetric(t, "group_fixture_seed", map[string]any{
		"groups": 1000, "active_memberships_in_target_group": 1000,
		"elapsed_ms": seedElapsed.Milliseconds(),
	})
}

func TestStressSameGroupBroadcastSnapshotCapAndRevocation(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	seedStart := time.Now()
	created := make([]sameGroupSealedV1EndpointFixture, 0, 31)
	for i := 0; i < 31; i++ {
		endpointID := fmt.Sprintf("ep_stress_broadcast_%02d", i)
		endpoint := createSameGroupBroadcastV2Endpoint(t, f.sealed, endpointID,
			f.sealed.target.nodeID, f.sealed.groupID, true)
		f.sealed.grant(t, endpoint.id)
		created = append(created, endpoint)
	}
	seedElapsed := time.Since(seedStart)

	// The base fixture has two recipients; 31 more exceeds the exact cap of 32.
	tooLargeStarted := time.Now()
	_, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_stress_over_cap_33"))
	if err != ErrSameGroupBroadcastV2RecipientLimit {
		t.Fatalf("33-recipient snapshot error=%v, want fail-closed limit", err)
	}
	emitStoreStressMetric(t, "group_broadcast_over_cap_rejection", map[string]any{
		"requested_recipients": SameGroupBroadcastV2MaxRecipients + 1,
		"elapsed_ms":           time.Since(tooLargeStarted).Milliseconds(), "rejected": true,
	})

	// Revoke one member to reach exactly 32; another revoke below tests fresh
	// snapshot visibility after a prior successful immutable snapshot.
	if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(created[30].principal,
		f.sealed.groupID, "synthetic stress revoke before exact-cap snapshot"); err != nil {
		t.Fatal(err)
	}
	latencies := make([]time.Duration, 8)
	for sample := range latencies {
		started := time.Now()
		snapshot := f.snapshot(t, fmt.Sprintf("bc_stress_exact_%02d", sample))
		latencies[sample] = time.Since(started)
		if len(snapshot.Recipients) != SameGroupBroadcastV2MaxRecipients {
			t.Fatalf("exact-cap snapshot recipients=%d", len(snapshot.Recipients))
		}
	}
	emitStoreStressMetric(t, "group_broadcast_snapshot_32", map[string]any{
		"recipients": SameGroupBroadcastV2MaxRecipients, "samples": len(latencies),
		"elapsed_ms":       totalDuration(latencies).Milliseconds(),
		"throughput_ops_s": groupRatePerSecond(len(latencies), totalDuration(latencies)),
		"latency_p50_ms":   percentileMilliseconds(latencies, 0.50),
		"latency_p95_ms":   percentileMilliseconds(latencies, 0.95),
	})
	// Revoke one active recipient after a valid snapshot. New snapshots must
	// exclude it, while the prior immutable snapshot remains unchanged.
	if _, err := f.sealed.store.RevokeMembershipForPrincipalGroup(created[0].principal,
		f.sealed.groupID, "synthetic stress revoke after snapshot"); err != nil {
		t.Fatal(err)
	}
	postRevokeStarted := time.Now()
	postRevoke := f.snapshot(t, "bc_stress_after_revoke")
	if len(postRevoke.Recipients) != SameGroupBroadcastV2MaxRecipients-1 {
		t.Fatalf("post-revocation recipients=%d", len(postRevoke.Recipients))
	}
	for _, recipient := range postRevoke.Recipients {
		if recipient.EndpointID == created[0].id {
			t.Fatal("revoked membership remained in a fresh broadcast snapshot")
		}
	}
	emitStoreStressMetric(t, "group_broadcast_after_revoke", map[string]any{
		"recipients": len(postRevoke.Recipients), "revoked_excluded": true,
		"elapsed_ms": time.Since(postRevokeStarted).Milliseconds(),
	})
	emitStoreStressMetric(t, "group_broadcast_fixture_seed", map[string]any{
		"recipient_endpoints_seeded": len(created), "elapsed_ms": seedElapsed.Milliseconds(),
	})
}

func emitStoreStressMetric(t *testing.T, stage string, fields map[string]any) {
	t.Helper()
	fields["schema"] = "cicada.v01.stress.metric.v1"
	fields["stage"] = stage
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err == nil {
		fields["process_peak_rss_kib"] = usage.Maxrss
		fields["process_user_cpu_ms"] = usage.Utime.Sec*1000 + usage.Utime.Usec/1000
		fields["process_system_cpu_ms"] = usage.Stime.Sec*1000 + usage.Stime.Usec/1000
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encode stress metric: %v", err)
	}
	t.Logf("CICADA_STRESS_METRIC %s", encoded)
}

func percentileMilliseconds(samples []time.Duration, percentile float64) float64 {
	copySamples := append([]time.Duration(nil), samples...)
	sort.Slice(copySamples, func(i, j int) bool { return copySamples[i] < copySamples[j] })
	if len(copySamples) == 0 {
		return 0
	}
	index := int(math.Ceil(percentile*float64(len(copySamples)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(copySamples) {
		index = len(copySamples) - 1
	}
	return float64(copySamples[index].Microseconds()) / 1000
}

func totalDuration(samples []time.Duration) time.Duration {
	var total time.Duration
	for _, sample := range samples {
		total += sample
	}
	return total
}

func groupRatePerSecond(count int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}
