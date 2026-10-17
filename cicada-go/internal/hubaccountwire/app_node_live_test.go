package hubaccountwire

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
)

func TestAppNodeLiveGrantBindingAndSignedReadExpiredNode(t *testing.T) {
	f := appNodeCrypto(t)
	_, _, ch := appNodePreparedCrypto(t, f)
	s, err := NewAppNodeStatus(f.session, ch.Claims.GrantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, s)
	if err != nil {
		t.Fatal(err)
	}
	b, r, _ := NewClientRoute(f.hub, s, f.device.Public())
	a := AppNodeAuthoritySnapshot{Scope: ch.Claims.Scope, GrantID: ch.Claims.GrantID, State: AppNodeActive, Profile: AppNodeProfileInitial, CurrentHeadVersion: 1, LatestGrantID: ch.Claims.GrantID, RootState: RootActiveState, AllowedOperations: AppNodeAllowedOperations(), RemainingConfirmations: 1, LeaseExpiresAt: ch.Claims.LeaseExpiresAt, Counters: AppNodeClientCounters{SessionEpoch: 1, NextResponseSequence: 1}}
	v := AppNodeResult{Format: AppNodeResultFormat, Operation: OperationAppNodeStatus, RequestID: s.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(original), State: AppNodeCompleted, Authority: a, ObservedAt: formatUTC(f.now)}
	if err := ValidateAppNodeLiveResult(v, ch.Claims, f.hub, f.now); err != nil {
		t.Fatal(err)
	}
	foreign := v
	foreign.Authority.Scope.AccountEpoch++
	if ValidateAppNodeLiveResult(foreign, ch.Claims, f.hub, f.now) == nil {
		t.Fatal("different signed account epoch replaced retained grant")
	}
	if ValidateAppNodeLiveResult(v, ch.Claims, f.hub, f.now.Add(15*time.Minute)) == nil {
		t.Fatal("historical snapshot regained current authority")
	}
	v.State, v.ErrorCode = AppNodeReadExpired, AppNodeReadExpired
	v.Authority.AllowedOperations = []string{}
	v.Authority.RemainingConfirmations = 0
	n := ch.Claims.Candidate
	v.Node = &AppNodeObservation{NodeID: n.NodeID, NodeName: n.NodeName, BindingID: "synthetic-binding", BindingVersion: 1, CredentialVersion: 1, NodeKeyID: n.NodePublic.ID, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyEpoch: 1, BindingState: "ACTIVE", Authorized: true, Connectivity: "CONNECTED", Known: true, Source: "store.machines.last_seen", LastHeartbeatAt: formatUTC(f.now), ObservedAt: formatUTC(f.now), FreshUntil: formatUTC(f.now.Add(AppNodeObservationStaleAfter))}
	assertRejected := func(v AppNodeResult) {
		t.Helper()
		plain, _ := json.Marshal(v)
		inner, err := clientwire.SealResponseWithLimits(f.hubPrivate, f.device.Public(), b, responseRoute(r), plain, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
		if err != nil {
			t.Fatal(err)
		}
		var packet clientwire.Packet
		_ = json.Unmarshal(inner, &packet)
		raw, _ := json.Marshal(Packet{Format: PacketFormat, Version: PacketVersion, SenderPublicIdentity: f.hub.Public, Packet: packet})
		var got AppNodeResult
		if OpenClientResponse(f.device, f.hub, original, raw, &got) == nil {
			t.Fatal("genuine Hub signature admitted unsafe Node observation")
		}
	}
	assertRejected(v)
	live := v
	live.State = AppNodeCompleted
	live.ErrorCode = ""
	nodeCopy := *v.Node
	live.Node = &nodeCopy
	live.Node.LastHeartbeatAt = formatUTC(f.now.Add(time.Second))
	live.Node.FreshUntil = formatUTC(f.now.Add(time.Second + AppNodeObservationStaleAfter))
	assertRejected(live)
	live.Node.LastHeartbeatAt = formatUTC(f.now)
	live.Node.FreshUntil = formatUTC(f.now.Add(AppNodeObservationStaleAfter))
	live.Node.BindingState = "REVOKED"
	assertRejected(live)
	v.Node = nil
	if ValidateAppNodeLiveResult(v, ch.Claims, f.hub, f.now) == nil {
		t.Fatal("read settlement became live authority")
	}
}
