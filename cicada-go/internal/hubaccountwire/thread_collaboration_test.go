package hubaccountwire

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func threadCollaborationFixture() (GroupLockScope, GroupLockHolder, GroupLockAcquireRequest) {
	scope := GroupLockScope{"synthetic-hub", "synthetic-network", "synthetic-group"}
	holder := GroupLockHolder{"synthetic-node", "synthetic-endpoint", "synthetic-principal", ThreadRegistrationSource{"synthetic-original-registration", 1}}
	request := GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 1, Original: contractGroupLockOriginal("a", "b"), Note: "SYNTHETIC arbitrary Group note"}
	return scope, holder, request
}

func contractGroupLockOriginal(a, b string) ThreadCollaborationOriginal {
	prefix := fmt.Sprintf("%012x", time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC).UnixMilli())
	return ThreadCollaborationOriginal{prefix + strings.Repeat(a, 20), prefix + strings.Repeat(b, 20), strings.Repeat("0", 64)}
}

func TestThreadCollaborationContractClosedInventoryAndInactiveLocks(t *testing.T) {
	if len(ThreadCollaborationProfiles()) != 2 || len(ThreadCollaborationOwnerOperations()) != 5 || len(ThreadCollaborationNativeOperations()) != 5 {
		t.Fatal("contract inventory changed")
	}
	paths := map[string]bool{}
	for _, op := range ThreadCollaborationOwnerOperations() {
		path := ThreadCollaborationHTTPPath(op)
		if path == "" || paths[path] {
			t.Fatal("owner routes are not closed and unique")
		}
		paths[path] = true
	}
	for _, op := range append(ThreadCollaborationNativeOperations(), "owner.endpoint_groups.apply", "arbitrary") {
		if ThreadCollaborationHTTPPath(op) != "" {
			t.Fatal("another carrier borrowed Owner HTTP")
		}
	}
	v := ThreadCollaborationCapabilities{Format: ThreadCollaborationCapabilitiesFormat, ContractRevision: ThreadCollaborationContractRevision, HubID: "synthetic-hub", HubFingerprint: strings.Repeat("a", 64), ServeMode: "--hub-nodes-only", ThreadScopeRoleAvailable: true, DisconnectPolicy: GroupLockDisconnectPolicyFiniteLease, SlotCount: 8, DefaultTTLSeconds: 300, MinTTLSeconds: 1, MaxTTLSeconds: 3600}
	if ValidateThreadCollaborationCapabilities(v) != nil {
		t.Fatal("independent Thread/Role profile requires Control or live locks")
	}
	v.DefaultTTLSeconds = 0
	if ValidateThreadCollaborationCapabilities(v) == nil {
		t.Fatal("finite lease bounds missing")
	}
}

func TestThreadCollaborationContractOwnerReadAndClosedActions(t *testing.T) {
	// No Host, native session or Thread caller credential appears in this read.
	read := ThreadCollaborationOwnerReadBody{View: "GROUP_LOCKS", NetworkID: "synthetic-network", GroupID: "synthetic-group"}
	raw, _ := json.Marshal(read)
	if _, err := DecodeThreadCollaborationOwnerReadBody(raw); err != nil {
		t.Fatal(err)
	}
	read.NodeID = "pretend-host"
	if ValidateThreadCollaborationOwnerReadBody(read) == nil {
		t.Fatal("Owner Group read smuggled a native selector")
	}
	_, holder, _ := threadCollaborationFixture()
	role := ThreadCollaborationOwnerPrepareBody{Action: ThreadCollaborationSetClassification, Role: &ThreadRoleChange{NetworkID: "synthetic-network", NodeID: holder.NodeID, EndpointID: holder.EndpointID, Source: holder.Source, Classification: ThreadClassificationWorker, ExpectedRelationsRevision: 1, RegistrationDigest: strings.Repeat("a", 64)}}
	policy := ThreadCollaborationOwnerPrepareBody{Action: ThreadCollaborationCreateGroupWithPolicy, Policy: &GroupPolicyChange{NetworkID: "synthetic-network", Name: "Synthetic Group", SlotCount: 8, Rights: GroupCoordinationRights()}}
	for _, body := range []ThreadCollaborationOwnerPrepareBody{role, policy} {
		raw, _ := json.Marshal(body)
		if _, err := DecodeThreadCollaborationOwnerPrepareBody(raw); err != nil {
			t.Fatal("known independent Owner action rejected", err)
		}
	}
	role.Policy = policy.Policy
	if ValidateThreadCollaborationOwnerPrepareBody(role) == nil {
		t.Fatal("multi-action Owner request accepted")
	}
	role.Policy = nil
	role.Role.Classification = "control"
	if ValidateThreadCollaborationOwnerPrepareBody(role) == nil {
		t.Fatal("Control service label became an independent privileged class")
	}
	policy.Policy.SlotCount = 9
	if ValidateThreadCollaborationOwnerPrepareBody(policy) == nil {
		t.Fatal("Owner silently changed eight generic slots")
	}
}

func TestThreadCollaborationContractCurrentRoleCountAndPagedAdvisor(t *testing.T) {
	_, h, _ := threadCollaborationFixture()
	v := ThreadScopeView{Format: ThreadScopeFormat, HubID: "synthetic-hub", NetworkID: "synthetic-network", NodeID: h.NodeID, EndpointID: h.EndpointID, Source: h.Source, ScopeRevision: 1, RegistrationDigest: strings.Repeat("a", 64), State: "CURRENT", Classification: ThreadClassificationWorker, ClassificationRevision: 1, RelationsRevision: 1, ActiveGroupIDs: []string{"group-A"}, ActiveGroupCount: 1, HistoryCoverage: "CICADA_KNOWN_ONLY"}
	if ValidateThreadScopeView(v) != nil {
		t.Fatal("single worker Group refused")
	}
	v.ActiveGroupIDs = append(v.ActiveGroupIDs, "group-B")
	v.ActiveGroupCount = 2
	if ValidateThreadScopeView(v) == nil {
		t.Fatal("current worker has two Groups")
	}
	v.Classification = ThreadClassificationAdvisor
	v.ActiveGroupCount = 100
	v.GroupsCursor = "synthetic-page-2"
	if ValidateThreadScopeView(v) != nil {
		t.Fatal("pagination created a product Group quota for Advisor")
	}
	v.Classification = ""
	v.ClassificationRevision = 0
	if ValidateThreadScopeView(v) == nil {
		t.Fatal("anonymous member silently became a current class")
	}
	v.State = "CLASSIFICATION_REQUIRED"
	if ValidateThreadScopeView(v) != nil {
		t.Fatal("retained unclassified state cannot be reported")
	}
}

func TestThreadCollaborationContractPreAdmissionAndConflictShapes(t *testing.T) {
	base := ThreadScopeView{Format: ThreadScopeFormat, NodeID: "synthetic-node", ActiveGroupIDs: []string{}, HistoryCoverage: "CICADA_KNOWN_ONLY"}
	unassigned := base
	unassigned.State = "UNASSIGNED"
	unassigned.HubID = "synthetic-target-hub"
	if ValidateThreadScopeView(unassigned) != nil {
		t.Fatal("unassigned native context requires fabricated registration")
	}
	for _, state := range []string{"RESERVED", "UNRESOLVED"} {
		t.Run(state, func(t *testing.T) {
			v := base
			v.State = state
			v.HubID = "synthetic-target-hub"
			v.NetworkID = "synthetic-target-network"
			v.ScopeRevision = 1
			v.ReservationID = "synthetic-original-reservation"
			if ValidateThreadScopeView(v) != nil {
				t.Fatal("before-effect reservation requires fake Endpoint/source")
			}
			bad := v
			bad.EndpointID = "fabricated-endpoint"
			bad.Source = ThreadRegistrationSource{"fabricated-registration", 1}
			if ValidateThreadScopeView(bad) == nil {
				t.Fatal("pre-admission shape accepted invented registration")
			}
			bad = v
			bad.ReservationID = ""
			if ValidateThreadScopeView(bad) == nil {
				t.Fatal("reservation has no original durable reference")
			}
			bad = v
			bad.State = "CURRENT"
			if ValidateThreadScopeView(bad) == nil {
				t.Fatal("reserved scope became current without real registration")
			}
		})
	}
	conflict := base
	conflict.State = "NETWORK_CONFLICT"
	conflict.ScopeRevision = 2
	conflict.Conflict = &ThreadNetworkConflict{Kind: "MULTIPLE_NETWORKS", KnownNetworkCount: 2}
	if ValidateThreadScopeView(conflict) != nil {
		t.Fatal("conflict requires choosing a winning Network")
	}
	bad := conflict
	bad.HubID = "first-hub"
	bad.NetworkID = "first-network"
	if ValidateThreadScopeView(bad) == nil {
		t.Fatal("conflict silently chose first historical scope")
	}
	bad = conflict
	bad.Conflict = &ThreadNetworkConflict{Kind: "MULTIPLE_NETWORKS", KnownNetworkCount: 1}
	if ValidateThreadScopeView(bad) == nil {
		t.Fatal("contradictory conflict count accepted")
	}
	conflict.Conflict = &ThreadNetworkConflict{Kind: "UNRESOLVED_HISTORY"}
	if ValidateThreadScopeView(conflict) != nil {
		t.Fatal("unresolved legacy history needs a fake Network ID")
	}
}

func TestThreadCollaborationContractSlotSnapshotAndStableHolder(t *testing.T) {
	scope, holder, _ := threadCollaborationFixture()
	view := GroupSlotView{Format: GroupSlotViewFormat, Scope: scope, ObservedAt: "2026-11-05T12:00:00Z", PolicyRevision: 1, PolicyState: "ENABLED", Slots: []GroupLockSlot{}}
	for i := 1; i <= 8; i++ {
		view.Slots = append(view.Slots, GroupLockSlot{Slot: uint8(i), State: "FREE", Version: 1})
	}
	raw, _ := json.Marshal(view)
	if _, err := DecodeGroupSlotView(raw); err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(raw)
	if ValidateGroupSlotView(view) != nil {
		t.Fatal("read snapshot invalid")
	}
	after, _ := json.Marshal(view)
	if !bytes.Equal(before, after) {
		t.Fatal("pure snapshot codec changed a free row")
	}
	view.ObservedAt = ""
	if ValidateGroupSlotView(view) == nil {
		t.Fatal("unobserved free cache accepted")
	}
	view.ObservedAt = "2026-11-05T12:00:00Z"
	view.Slots[0] = GroupLockSlot{Slot: 1, State: "HELD", Version: 2, Generation: 1, Holder: &holder, Note: "SYNTHETIC note", ExpiresAt: "2026-11-05T12:05:00Z", HolderName: "Synthetic holder", HolderNameState: "VISIBLE"}
	request := GroupLockReleaseRequest{Scope: scope, Slot: 1, ExpectedVersion: 2, Generation: 1, Original: contractGroupLockOriginal("c", "d")}
	if ValidateGroupSlotView(view) != nil || ValidateGroupLockReleaseHolder(scope, holder, view.Slots[0], request) != nil {
		t.Fatal("same original registration cold recovery cannot release")
	}
	newThread := holder
	newThread.Source.SourceEpoch++
	if ValidateGroupLockReleaseHolder(scope, newThread, view.Slots[0], request) == nil {
		t.Fatal("new Thread borrowed holder through same Endpoint/Principal")
	}
	newThread = holder
	newThread.Source.RegistrationID = "another-registration"
	if ValidateGroupLockReleaseHolder(scope, newThread, view.Slots[0], request) == nil {
		t.Fatal("replacement registration borrowed old hold")
	}
	request.Generation++
	if ValidateGroupLockReleaseHolder(scope, holder, view.Slots[0], request) == nil {
		t.Fatal("stale generation accepted")
	}
	view.Slots = append(view.Slots, GroupLockSlot{Slot: 9, State: "FREE", Version: 1})
	if ValidateGroupSlotView(view) == nil {
		t.Fatal("ninth slot accepted")
	}
}

func TestThreadCollaborationContractOriginalDigestAndStrictCodec(t *testing.T) {
	_, caller, request := threadCollaborationFixture()
	digest, err := GroupLockRequestDigest(OperationGroupLocksAcquire, caller, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Original.RequestDigest = digest
	if VerifyGroupLockRequestDigest(OperationGroupLocksAcquire, caller, request) != nil {
		t.Fatal("server recomputation differs")
	}
	raw, _ := json.Marshal(request)
	decoded, err := DecodeGroupLockAcquireRequest(raw)
	if err != nil || !reflect.DeepEqual(decoded, request) {
		t.Fatal("typed original changed", err)
	}
	for name, change := range map[string]func(*GroupLockAcquireRequest){"id": func(v *GroupLockAcquireRequest) { v.Original.OperationID = "other-original" }, "key": func(v *GroupLockAcquireRequest) { v.Original.IdempotencyKey = "other-key" }, "note": func(v *GroupLockAcquireRequest) { v.Note = "other bytes" }, "scope": func(v *GroupLockAcquireRequest) { v.Scope.GroupID = "other-group" }} {
		t.Run(name, func(t *testing.T) {
			changed := request
			change(&changed)
			if VerifyGroupLockRequestDigest(OperationGroupLocksAcquire, caller, changed) == nil {
				t.Fatal("client digest substituted for server original check")
			}
		})
	}
	other := caller
	other.Source.SourceEpoch++
	if VerifyGroupLockRequestDigest(OperationGroupLocksAcquire, other, request) == nil {
		t.Fatal("new Thread source borrowed original request")
	}
	for name, bad := range map[string][]byte{"unknown": []byte(strings.Replace(string(raw), `"slot":1`, `"task_id":"synthetic-forbidden","slot":1`, 1)), "duplicate": []byte(strings.Replace(string(raw), `"slot":1`, `"slot":1,"slot":1`, 1)), "trailing": append(bytes.Clone(raw), []byte(`{}`)...), "oversize": bytes.Repeat([]byte(" "), MaxThreadCollaborationNodeBodyBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGroupLockAcquireRequest(bad); err == nil {
				t.Fatal("non-closed body accepted")
			}
		})
	}
	request.Note = strings.Repeat("x", MaxGroupLockNoteBytes+1)
	if ValidateGroupLockAcquireRequest(request) == nil {
		t.Fatal("unbounded note accepted")
	}
}

func TestThreadCollaborationContractFiniteTTL(t *testing.T) {
	_, caller, q := threadCollaborationFixture()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	end, err := GroupLockLeaseExpiry(nil, now)
	if err != nil || end != "2026-11-05T12:05:00Z" {
		t.Fatal("omitted TTL is not default 300")
	}
	for _, seconds := range []uint32{1, 3600} {
		q.TTLSeconds = &seconds
		raw, _ := json.Marshal(q)
		if _, err := DecodeGroupLockAcquireRequest(raw); err != nil {
			t.Fatal(err)
		}
		end, err := GroupLockLeaseExpiry(&seconds, now)
		if err != nil || end != formatUTC(now.Add(time.Duration(seconds)*time.Second)) {
			t.Fatal("expiry not original server now plus TTL")
		}
	}
	q.TTLSeconds = nil
	raw, _ := json.Marshal(q)
	for name, value := range map[string]string{"zero": "0", "negative": "-1", "high": "3601", "float": "1.5", "string": "\"300\"", "overflow": "4294967296", "null": "null"} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Replace(raw, []byte(`"slot":1`), []byte(`"slot":1,"ttl_seconds":`+value), 1)
			if _, err := DecodeGroupLockAcquireRequest(bad); err == nil {
				t.Fatal("invalid explicit TTL accepted")
			}
		})
	}
	renew := GroupLockRenewRequest{Scope: q.Scope, Slot: 1, ExpectedVersion: 2, Generation: 1, Original: q.Original}
	d, err := GroupLockRequestDigest(OperationGroupLocksRenew, caller, renew)
	if err != nil {
		t.Fatal(err)
	}
	renew.Original.RequestDigest = d
	raw, _ = json.Marshal(renew)
	if _, err := DecodeGroupLockRenewRequest(raw); err != nil || VerifyGroupLockRequestDigest(OperationGroupLocksRenew, caller, renew) != nil {
		t.Fatal("renew original invalid", err)
	}
	x := uint32(3600)
	renew.TTLSeconds = &x
	if VerifyGroupLockRequestDigest(OperationGroupLocksRenew, caller, renew) == nil {
		t.Fatal("TTL change reused original digest")
	}
}

func TestThreadCollaborationContractOriginalRecoveryWindow(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 123000000, time.UTC)
	o, err := NewGroupLockOriginal(now)
	if err != nil {
		t.Fatal(err)
	}
	created, err := GroupLockOriginalTime(o.OperationID)
	if err != nil || created.UnixMilli() != now.UnixMilli() {
		t.Fatal("48-bit original timestamp")
	}
	if len(o.OperationID) != 32 || len(o.IdempotencyKey) != 32 || o.OperationID == o.IdempotencyKey || o.OperationID[:12] != o.IdempotencyKey[:12] {
		t.Fatal("original entropy/time binding")
	}
	if ValidateGroupLockOriginalWindow(o, now.Add(24*time.Hour-time.Millisecond)) != nil {
		t.Fatal("live recovery window refused")
	}
	if ValidateGroupLockOriginalWindow(o, now.Add(24*time.Hour)) == nil || ValidateGroupLockOriginalWindow(o, now.Add(-31*time.Second)) == nil {
		t.Fatal("expired/future original admitted")
	}
	other, _ := NewGroupLockOriginal(now.Add(time.Millisecond))
	o.IdempotencyKey = other.IdempotencyKey
	if threadCollaborationOriginal(o) {
		t.Fatal("changed creation time hid key reuse")
	}
}

type contractOwnerClient struct{}

var _ ThreadCollaborationOwnerClient = contractOwnerClient{}

func (contractOwnerClient) Read(context.Context, ThreadCollaborationOwnerReadRequest) (ThreadCollaborationOwnerReadResult, error) {
	return ThreadCollaborationOwnerReadResult{}, nil
}
func (contractOwnerClient) Prepare(context.Context, ThreadCollaborationOwnerPrepareRequest) (ThreadCollaborationOwnerReview, error) {
	return ThreadCollaborationOwnerReview{}, nil
}
func (contractOwnerClient) Apply(context.Context, ThreadCollaborationOwnerApplyRequest) (ThreadCollaborationOwnerResult, error) {
	return ThreadCollaborationOwnerResult{}, nil
}
func (contractOwnerClient) Status(context.Context, ThreadCollaborationOwnerStatusRequest) (ThreadCollaborationOwnerResult, error) {
	return ThreadCollaborationOwnerResult{}, nil
}
func (contractOwnerClient) Reconcile(context.Context, ThreadCollaborationOwnerReconcileRequest) (ThreadCollaborationOwnerResult, error) {
	return ThreadCollaborationOwnerResult{}, nil
}
