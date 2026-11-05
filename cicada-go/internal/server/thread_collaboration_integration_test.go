package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"net/http"
	"testing"
	"time"
)

func threadCollaborationOwnerHTTP(t *testing.T, f *endpointGroupsHTTPFixture, q any) ([]byte, wire.ThreadCollaborationOwnerResult) {
	t.Helper()
	a := f.a
	packet, err := wire.SealClientRequest(a.device, a.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := wire.NewClientRoute(a.f.hub, q, a.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	status, reply := n3HTTP(t, a.f, http.MethodPost, wire.ThreadCollaborationHTTPPath(route.Operation), "", packet)
	if status != http.StatusOK {
		t.Fatal("Owner HTTP status", route.Operation, status, string(reply))
	}
	var result wire.ThreadCollaborationOwnerResult
	if wire.OpenThreadCollaborationOwnerResponse(a.device, a.f.hub, packet, reply, &result) != nil || wire.VerifyThreadCollaborationOwnerResult(q, packet, result, a.f.hub) != nil {
		t.Fatal("Owner response authentication/correlation", route.Operation, string(reply))
	}
	return packet, result
}
func threadCollaborationOwnerApply(t *testing.T, f *endpointGroupsHTTPFixture, body wire.ThreadCollaborationOwnerPrepareBody) ([]byte, wire.ThreadCollaborationOwnerResult) {
	t.Helper()
	a := f.a
	q, err := wire.NewThreadCollaborationOwnerPrepare(a.session, a.scope.Actor, body, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	original, prepared := threadCollaborationOwnerHTTP(t, f, q)
	if prepared.Review == nil || wire.ValidateThreadCollaborationOwnerReview(q, original, *prepared.Review, a.f.hub, time.Now().UTC()) != nil {
		t.Fatal("Owner review rejected", prepared.State, prepared.ErrorCode)
	}
	apply, err := wire.NewThreadCollaborationOwnerApply(a.session, a.scope.Actor, q, original, *prepared.Review, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, result := threadCollaborationOwnerHTTP(t, f, apply)
	if result.State != "COMPLETED" || wire.VerifyThreadCollaborationOwnerOperation(*prepared.Review, apply, packet, result, a.f.hub) != nil {
		t.Fatal("Owner apply effect", result.State, result.ErrorCode)
	}
	return packet, result
}
func threadCollaborationNodeHTTP(t *testing.T, f *endpointGroupsHTTPFixture, op string, body any, out any, wantError string) ([]byte, []byte) {
	t.Helper()
	f.sequence++
	if wire.ValidateThreadCollaborationNodeBody(op, body) != nil {
		t.Fatal("typed Node body")
	}
	plain, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	b := f.a.nodeBinding()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	r := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: f.sequence, OperationID: id, Operation: op, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	packet, err := nodewire.SealRequest(f.a.node, b.HubKey, b, r, plain)
	if err != nil {
		t.Fatal(err)
	}
	status, reply := n3HTTP(t, f.a.f, http.MethodPost, "/v2/node/control/rpc", f.a.nodeToken, packet)
	if status != http.StatusOK {
		t.Fatal("Node HTTP", op, status, string(reply))
	}
	threadCollaborationOpenNode(t, f, packet, reply, out, wantError)
	return packet, reply
}
func threadCollaborationOpenNode(t *testing.T, f *endpointGroupsHTTPFixture, original, response []byte, out any, wantError string) {
	t.Helper()
	b := f.a.nodeBinding()
	p, err := nodewire.DecodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodewire.OpenResponse(f.a.node, b.HubKey, b, response)
	if err != nil {
		t.Fatal(err)
	}
	want := p.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	if opened.Route != want {
		t.Fatal("Node response route")
	}
	var reply struct {
		nativePairNodeReply
		OriginalEvidence *wire.ThreadCollaborationNodeEvidence `json:"original_evidence"`
	}
	d := json.NewDecoder(bytes.NewReader(opened.Plaintext))
	d.DisallowUnknownFields()
	if d.Decode(&reply) != nil || reply.OperationID != p.Route.OperationID || reply.Sequence != p.Route.Sequence || reply.ErrorCode != wantError || reply.OK != (wantError == "") {
		t.Fatal("Node result", p.Route.Operation, reply.ErrorCode, wantError)
	}
	if out != nil && json.Unmarshal(reply.Result, out) != nil {
		t.Fatal("typed Node result")
	}
	if p.Route.Operation == wire.OperationGroupLocksAcquire || p.Route.Operation == wire.OperationGroupLocksRenew || p.Route.Operation == wire.OperationGroupLocksRelease {
		e := reply.OriginalEvidence
		sum := sha256.Sum256(original)
		if e == nil || e.Operation != p.Route.Operation || e.RequestPacketDigest != hex.EncodeToString(sum[:]) || e.ErrorCode != wantError {
			t.Fatal("missing exact authenticated original evidence")
		}
		wantOutcome := wire.ThreadCollaborationOutcomeRejectedFenced
		if wantError == "" {
			wantOutcome = wire.ThreadCollaborationOutcomeApplied
		}
		if wantError == wire.ThreadCollaborationErrorReceiptUnavailable || wantError == wire.ThreadCollaborationErrorAuthorizationRequired || wantError == wire.ThreadCollaborationErrorClassificationRequired || wantError == wire.ThreadCollaborationErrorOriginalConflict {
			wantOutcome = wire.ThreadCollaborationOutcomeUnknown
		}
		if e.Outcome != wantOutcome {
			t.Fatal("transport observation misclassified original outcome", e.Outcome, wantOutcome)
		}
	} else if reply.OriginalEvidence != nil {
		t.Fatal("read minted mutation evidence")
	}
}

func TestThreadCollaborationHTTPFiniteLeaseAndOwnerPolicy(t *testing.T) {
	f := endpointGroupsRealHTTPBeforeKeys(t, func(f *endpointGroupsHTTPFixture, i int) {
		threadCollaborationClassifyBeforeKeys(t, f, i, wire.ThreadClassificationWorker)
	})
	a := f.a
	if a.f.http.Config.Handler.(*hubNodesHandler).base.control != nil {
		t.Fatal("Control must be absent")
	}
	group, network := f.domain.Policy.GroupID, f.domain.Policy.NetworkID
	scope := wire.GroupLockScope{HubID: a.f.hub.HubID, NetworkID: network, GroupID: group}
	var views [2]wire.ThreadScopeView
	for i := 0; i < 2; i++ {
		var original wire.EndpointGroupsNodeDescribeResult
		f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: f.joins[i].Member.EndpointID, NetworkID: network, Limit: 64}, &original)
		threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: f.joins[i].Member.EndpointID, NetworkID: network}, &views[i], "")
		if views[i].State != "CURRENT" || views[i].Classification != wire.ThreadClassificationWorker || views[i].ActiveGroupCount != 1 {
			t.Fatal("explicitly classified original member lost its effective source", views[i])
		}
	}
	read, err := wire.NewThreadCollaborationOwnerRead(a.session, a.scope.Actor, wire.ThreadCollaborationOwnerReadBody{View: "GROUP_LOCKS", NetworkID: network, GroupID: group}, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, before := threadCollaborationOwnerHTTP(t, f, read)
	if before.Read == nil || before.Read.Group == nil || before.Read.Group.GroupVersion == 0 || before.Read.GroupPolicy != nil || before.Read.GroupSlots != nil {
		t.Fatal("read fabricated policy or slots")
	}
	policyOriginal, policy := threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationEnableGroupPolicy, Policy: &wire.GroupPolicyChange{NetworkID: network, GroupID: group, ExpectedGroupVersion: before.Read.Group.GroupVersion, SlotCount: 8, Rights: wire.GroupCoordinationRights()}})
	if policy.Policy == nil || policy.Policy.Revision != 1 {
		t.Fatal("policy not persisted")
	}
	status, err := wire.NewThreadCollaborationOwnerStatus(a.session, a.scope.Actor, policyOriginal, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, recovered := threadCollaborationOwnerHTTP(t, f, status)
	if recovered.State != "ORIGINAL_RECEIPT" || len(recovered.ReceiptPacket) == 0 {
		t.Fatal("lost apply response not recovered")
	}
	var originalPolicy wire.ThreadCollaborationOwnerResult
	if wire.OpenThreadCollaborationOwnerResponse(a.device, a.f.hub, policyOriginal, recovered.ReceiptPacket, &originalPolicy) != nil || originalPolicy.OriginalPacketDigest != policy.OriginalPacketDigest {
		t.Fatal("original response not exact")
	}
	// Close an authenticated never-submitted Apply. Both its original packet
	// and a newly signed Apply borrowing that review must remain no-effect.
	unusedPrepare, err := wire.NewThreadCollaborationOwnerPrepare(a.session, a.scope.Actor, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationEnableGroupPolicy, Policy: &wire.GroupPolicyChange{NetworkID: network, GroupID: group, ExpectedGroupVersion: before.Read.Group.GroupVersion, ExpectedPolicyRevision: 1, SlotCount: 8, Rights: wire.GroupCoordinationRights()}}, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	unusedOriginal, unusedReview := threadCollaborationOwnerHTTP(t, f, unusedPrepare)
	if unusedReview.Review == nil {
		t.Fatal("unused review")
	}
	unusedApply, err := wire.NewThreadCollaborationOwnerApply(a.session, a.scope.Actor, unusedPrepare, unusedOriginal, *unusedReview.Review, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	unsubmitted, err := wire.SealClientRequest(a.device, a.f.hub, unusedApply)
	if err != nil {
		t.Fatal(err)
	}
	reconcile, err := wire.NewThreadCollaborationOwnerReconcile(a.session, a.scope.Actor, unsubmitted, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, closed := threadCollaborationOwnerHTTP(t, f, reconcile)
	var noEffect wire.ThreadCollaborationOwnerResult
	if closed.State != "ORIGINAL_RECEIPT" || wire.OpenThreadCollaborationOwnerResponse(a.device, a.f.hub, unsubmitted, closed.ReceiptPacket, &noEffect) != nil || noEffect.State != "ORIGINAL_NOT_APPLIED" || noEffect.Policy != nil {
		t.Fatal("reconcile executed unseen original")
	}
	lateStatus, latePacket := n3HTTP(t, a.f, http.MethodPost, wire.ThreadCollaborationHTTPPath(wire.OperationThreadCollaborationOwnerApply), "", unsubmitted)
	var late wire.ThreadCollaborationOwnerResult
	if lateStatus != http.StatusOK || wire.OpenThreadCollaborationOwnerResponse(a.device, a.f.hub, unsubmitted, latePacket, &late) != nil || wire.VerifyThreadCollaborationOwnerResult(unusedApply, unsubmitted, late, a.f.hub) != nil {
		t.Fatal("exact original fence response")
	}
	if late.State != "ORIGINAL_NOT_APPLIED" || late.Policy != nil {
		t.Fatal("late original bypassed no-effect fence")
	}
	borrowed, err := wire.NewThreadCollaborationOwnerApply(a.session, a.scope.Actor, unusedPrepare, unusedOriginal, *unusedReview.Review, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, denied := threadCollaborationOwnerHTTP(t, f, borrowed)
	if denied.State != "REJECTED" || denied.Policy != nil {
		t.Fatal("reconciled one-time review reused")
	}
	var free wire.GroupSlotView
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: views[0].EndpointID, Scope: scope}, &free, "")
	if len(free.Slots) != 8 || free.Slots[0].Version != 1 || free.Slots[0].Generation != 0 {
		t.Fatal("initial eight slots")
	}
	staleID, _ := wire.NewGroupLockOriginal(time.Now().UTC().Add(-25 * time.Hour))
	oldRequest := wire.GroupLockAcquireRequest{Scope: scope, Slot: 8, ExpectedVersion: 1, Original: staleID}
	oldCaller := wire.GroupLockHolder{NodeID: views[0].NodeID, EndpointID: views[0].EndpointID, PrincipalID: f.joins[0].Member.PrincipalID, Source: views[0].Source}
	oldRequest.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, oldCaller, oldRequest)
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksAcquire, wire.GroupLocksNodeAcquire{EndpointID: oldCaller.EndpointID, Request: oldRequest}, nil, wire.ThreadCollaborationErrorReceiptUnavailable)
	original, err := wire.NewGroupLockOriginal(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ttl := uint32(30)
	q := wire.GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 1, Original: original, Note: "SYNTHETIC arbitrary note", TTLSeconds: &ttl}
	holder := wire.GroupLockHolder{NodeID: views[0].NodeID, EndpointID: views[0].EndpointID, PrincipalID: f.joins[0].Member.PrincipalID, Source: views[0].Source}
	q.Original.RequestDigest, err = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, holder, q)
	if err != nil {
		t.Fatal(err)
	}
	var held wire.GroupLockReceipt
	acquirePacket, acquireReply := threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksAcquire, wire.GroupLocksNodeAcquire{EndpointID: holder.EndpointID, Request: q}, &held, "")
	var observed wire.GroupSlotView
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: holder.EndpointID, Scope: scope}, &observed, "")
	if observed.Slots[0].HolderName != "Synthetic original Thread" || observed.Slots[0].ExpiresAt != held.ExpiresAt {
		t.Fatal("held name/expiry absent", observed.Slots[0])
	}
	var exact wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksAcquire, wire.GroupLocksNodeAcquire{EndpointID: holder.EndpointID, Request: q}, &exact, "")
	if exact != held {
		t.Fatal("semantic exact retry extended/reapplied lease")
	}
	renewOriginal, _ := wire.NewGroupLockOriginal(time.Now().UTC())
	renewTTL := uint32(1)
	renew := wire.GroupLockRenewRequest{Scope: scope, Slot: 1, ExpectedVersion: held.AppliedVersion, Generation: held.Generation, Original: renewOriginal, TTLSeconds: &renewTTL}
	renew.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksRenew, holder, renew)
	var renewed wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRenew, wire.GroupLocksNodeRenew{EndpointID: holder.EndpointID, Request: renew}, &renewed, "")
	if renewed.Outcome != "RENEWED" || renewed.AppliedVersion != 3 || renewed.Generation != held.Generation {
		t.Fatal("active explicit renew")
	}
	var exactRenew wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRenew, wire.GroupLocksNodeRenew{EndpointID: holder.EndpointID, Request: renew}, &exactRenew, "")
	if exactRenew != renewed {
		t.Fatal("renew retry shifted expiry")
	}
	end, err := time.Parse(time.RFC3339Nano, renewed.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(end.Add(20 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: views[1].EndpointID, Scope: scope}, &observed, "")
	if observed.Slots[0].State != "FREE" || observed.Slots[0].Version != 4 || observed.Slots[0].Generation != 1 {
		t.Fatal("expiry did not preserve generation/advance once", observed.Slots[0])
	}
	expired := renew
	expired.ExpectedVersion = renewed.AppliedVersion
	expired.Original, _ = wire.NewGroupLockOriginal(time.Now().UTC())
	expired.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksRenew, holder, expired)
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRenew, wire.GroupLocksNodeRenew{EndpointID: holder.EndpointID, Request: expired}, nil, wire.ThreadCollaborationErrorLeaseExpired)
	original, err = wire.NewGroupLockOriginal(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	other := wire.GroupLockHolder{NodeID: views[1].NodeID, EndpointID: views[1].EndpointID, PrincipalID: f.joins[1].Member.PrincipalID, Source: views[1].Source}
	long := uint32(3600)
	successor := wire.GroupLockAcquireRequest{Scope: scope, Slot: 1, ExpectedVersion: 4, Original: original, TTLSeconds: &long}
	successor.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, other, successor)
	var acquired wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksAcquire, wire.GroupLocksNodeAcquire{EndpointID: other.EndpointID, Request: successor}, &acquired, "")
	staleOriginal, _ := wire.NewGroupLockOriginal(time.Now().UTC())
	stale := wire.GroupLockReleaseRequest{Scope: scope, Slot: 1, ExpectedVersion: held.AppliedVersion, Generation: held.Generation, Original: staleOriginal}
	stale.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksRelease, holder, stale)
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRelease, wire.GroupLocksNodeRelease{EndpointID: holder.EndpointID, Request: stale}, nil, wire.ThreadCollaborationErrorGenerationStale)
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: other.EndpointID, Scope: scope}, &observed, "")
	if observed.Slots[0].Generation != 2 || observed.Slots[0].Version != acquired.AppliedVersion || observed.Slots[0].ExpiresAt != acquired.ExpiresAt || *observed.Slots[0].Holder != other {
		t.Fatal("old release changed successor")
	}
	_, cleared := threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationClearOneSlot, Clear: &wire.GroupLockOwnerClear{Scope: scope, Slot: 1, ExpectedVersion: acquired.AppliedVersion, Generation: acquired.Generation, ExpectedHolder: other}})
	if cleared.Lock == nil || cleared.Lock.Outcome != "OWNER_CLEARED" || cleared.Lock.Generation != 2 {
		t.Fatal("explicit exact Owner clear")
	}
	second := successor
	second.Slot = 2
	second.ExpectedVersion = 1
	second.Original, _ = wire.NewGroupLockOriginal(time.Now().UTC())
	second.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksAcquire, other, second)
	var secondHeld wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksAcquire, wire.GroupLocksNodeAcquire{EndpointID: other.EndpointID, Request: second}, &secondHeld, "")
	releaseOriginal, _ := wire.NewGroupLockOriginal(time.Now().UTC())
	release := wire.GroupLockReleaseRequest{Scope: scope, Slot: 2, ExpectedVersion: secondHeld.AppliedVersion, Generation: secondHeld.Generation, Original: releaseOriginal}
	release.Original.RequestDigest, _ = wire.GroupLockRequestDigest(wire.OperationGroupLocksRelease, other, release)
	var released wire.GroupLockReceipt
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRelease, wire.GroupLocksNodeRelease{EndpointID: other.EndpointID, Request: release}, &released, "")
	if released.Outcome != "RELEASED" || released.Generation != secondHeld.Generation || released.ExpiresAt != "" {
		t.Fatal("normal holder release")
	}
	threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationRevokeGroupPolicy, Policy: &wire.GroupPolicyChange{NetworkID: network, GroupID: group, ExpectedGroupVersion: before.Read.Group.GroupVersion, ExpectedPolicyRevision: 1, SlotCount: 8, Rights: wire.GroupCoordinationRights()}})
	httpStatus, reply := n3HTTP(t, a.f, http.MethodPost, "/v2/node/control/rpc", a.nodeToken, acquirePacket)
	if httpStatus != http.StatusServiceUnavailable {
		t.Fatal("current denial must not impersonate original no-effect result", httpStatus)
	}
	threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationEnableGroupPolicy, Policy: &wire.GroupPolicyChange{NetworkID: network, GroupID: group, ExpectedGroupVersion: before.Read.Group.GroupVersion, ExpectedPolicyRevision: 2, SlotCount: 8, Rights: wire.GroupCoordinationRights()}})
	httpStatus, reply = n3HTTP(t, a.f, http.MethodPost, "/v2/node/control/rpc", a.nodeToken, acquirePacket)
	if httpStatus != http.StatusOK || !bytes.Equal(reply, acquireReply) {
		t.Fatal("current denial overwrote the historical original receipt")
	}
	threadCollaborationOpenNode(t, f, acquirePacket, reply, &exact, "")
	if exact != held {
		t.Fatal("historical recovery was reapplied")
	}
}

func threadCollaborationClassifyBeforeKeys(t *testing.T, f *endpointGroupsHTTPFixture, i int, classification string) {
	t.Helper()
	m := f.joins[i].Member
	var d wire.EndpointGroupsNodeDescribeResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: m.EndpointID, NetworkID: f.domain.Policy.NetworkID, Limit: 64}, &d)
	var v wire.ThreadScopeView
	threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: m.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &v, "")
	if v.State != "CLASSIFICATION_REQUIRED" || v.ActiveGroupCount != 0 {
		t.Fatal("zero admission silently gained classification or business rights")
	}
	threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationSetClassification, Role: &wire.ThreadRoleChange{NetworkID: v.NetworkID, NodeID: v.NodeID, EndpointID: v.EndpointID, Source: v.Source, Classification: classification, ExpectedClassificationRevision: v.ClassificationRevision, ExpectedRelationsRevision: v.RelationsRevision, RegistrationDigest: v.RegistrationDigest}})
}
