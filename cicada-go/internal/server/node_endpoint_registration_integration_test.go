package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func endpointNodeReply(t *testing.T, a *nativePairTCPActor, request, response []byte) nativePairNodeReply {
	t.Helper()
	p, err := nodewire.DecodePacket(request)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodewire.OpenResponse(a.node, a.nodeBinding().HubKey, a.nodeBinding(), response)
	if err != nil {
		t.Fatal(err)
	}
	want := p.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	var out nativePairNodeReply
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &out) != nil || out.OperationID != p.Route.OperationID || out.Sequence != p.Route.Sequence {
		t.Fatal("response did not bind original Node request")
	}
	return out
}

func TestNodeEndpointRealTCPRegistrationPairReuseLeaveAndExactRetry(t *testing.T) {
	a := nativePairTCP(t)
	ch := a.completePair(t)
	in := nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: "synthetic-registered-original", Name: "合成原线程", Workspace: "/synthetic/registered/private"}
	packet := a.nodeSeal(t, nodewire.EndpointRegisterOperation, 1, in)
	response := a.nodePost(t, packet, http.StatusOK)
	reply := endpointNodeReply(t, a, packet, response)
	var registered nodewire.EndpointRegistrationResult
	if !reply.OK || json.Unmarshal(reply.Result, &registered) != nil || registered.Reused || registered.Presence != "offline" {
		t.Fatal("registration was not private/offline", reply.ErrorCode)
	}
	availablePacket := a.nodeSeal(t, nodewire.NativePairAvailableOperation, 2, struct{}{})
	availableReply := endpointNodeReply(t, a, availablePacket, a.nodePost(t, availablePacket, http.StatusOK))
	var available nodewire.AvailableNativePairs
	if !availableReply.OK || json.Unmarshal(availableReply.Result, &available) != nil || available.Truncated || len(available.Pairs) != 1 || available.Pairs[0].PairID != ch.Bootstrap.PairID || available.Pairs[0].Label == "" || len(available.Pairs[0].Slots) != 2 {
		t.Fatal("current Pair discovery", availableReply.ErrorCode)
	}
	description := a.describePair(t, ch, 3)
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: ch.Bootstrap.PairID, Slot: "A", ExpectedGeneration: description.SlotAGeneration, BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: in.Harness, NativeSessionID: in.NativeSessionID, Workspace: in.Workspace, EndpointName: "must preserve registration name"}
	joinPacket := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 4, q)
	joinReply := a.nodeOpen(t, joinPacket, a.nodePost(t, joinPacket, http.StatusOK))
	var joined fabric.JoinResult
	if !joinReply.OK || json.Unmarshal(joinReply.Result, &joined) != nil || joined.Endpoint.ID != registered.EndpointID || joined.Endpoint.Name != in.Name {
		t.Fatal("Pair replaced zero-rights identity", joinReply.ErrorCode)
	}
	member, err := a.f.db.GetMembershipByPrincipalGroup(joined.Endpoint.PrincipalID, ch.Bootstrap.GroupID)
	if err != nil || len(member.Grants) != 0 {
		t.Fatal("Pair reuse added communication rights", err)
	}
	if again := a.nodePost(t, packet, http.StatusOK); !bytes.Equal(again, response) {
		t.Fatal("old registration response replay was not exact")
	}
	currentPacket := a.nodeSeal(t, nodewire.EndpointRegisterOperation, 5, in)
	currentReply := endpointNodeReply(t, a, currentPacket, a.nodePost(t, currentPacket, http.StatusOK))
	var current nodewire.EndpointRegistrationResult
	if !currentReply.OK || json.Unmarshal(currentReply.Result, &current) != nil {
		t.Fatal("self reconciliation")
	}
	leave := nodewire.EndpointLeave{Harness: in.Harness, NativeSessionID: in.NativeSessionID, StateDigest: current.StateDigest}
	leavePacket := a.nodeSeal(t, nodewire.EndpointLeaveOperation, 6, leave)
	leaveResponse := a.nodePost(t, leavePacket, http.StatusOK)
	leftReply := endpointNodeReply(t, a, leavePacket, leaveResponse)
	if !leftReply.OK {
		t.Fatal("explicit endpoint leave", leftReply.ErrorCode)
	}
	if again := a.nodePost(t, leavePacket, http.StatusOK); !bytes.Equal(again, leaveResponse) {
		t.Fatal("leave replay redispatched")
	}
	old, err := a.f.db.GetSessionBinding(joined.BindingID)
	if err != nil || old.Status != "revoked" || old.Epoch != joined.BindingEpoch+1 {
		t.Fatal("leave retained Group lease", err)
	}
	enrollment, err := a.f.db.GetEndpointNetworkMembership(ch.Bootstrap.NetworkID, joined.Endpoint.ID)
	if err != nil || enrollment.Status != "revoked" {
		t.Fatal("leave retained Network permission", err)
	}
	registerAgain := a.nodeSeal(t, nodewire.EndpointRegisterOperation, 7, in)
	last := endpointNodeReply(t, a, registerAgain, a.nodePost(t, registerAgain, http.StatusOK))
	var terminal nodewire.EndpointRegistrationResult
	if !last.OK || json.Unmarshal(last.Result, &terminal) != nil || terminal.Presence != "left" || terminal.EndpointID != registered.EndpointID {
		t.Fatal("old SID revived after leave")
	}
	q.Slot = "B"
	q.ExpectedGeneration = description.SlotBGeneration
	move := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 8, q)
	if r := a.nodeOpen(t, move, a.nodePost(t, move, http.StatusOK)); r.OK {
		t.Fatal("left SID moved to another slot")
	}
}

func TestNodeEndpointRealTCPStrictInputAndTerminalError(t *testing.T) {
	a := nativePairTCP(t)
	for i, input := range []any{
		map[string]any{"harness": "codex", "native_session_id": "synthetic-invalid", "name": "synthetic", "workspace": "/synthetic/private", "owner_id": "forged"},
		nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: "synthetic-invalid", Name: "synthetic", Workspace: ""},
	} {
		packet := a.nodeSeal(t, nodewire.EndpointRegisterOperation, uint64(i+1), input)
		response := a.nodePost(t, packet, http.StatusOK)
		reply := endpointNodeReply(t, a, packet, response)
		if reply.OK || reply.ErrorCode != nodewire.ErrEndpointContext.Error() || len(reply.Result) != 0 {
			t.Fatal("bad context was not a bounded terminal refusal")
		}
		if again := a.nodePost(t, packet, http.StatusOK); !bytes.Equal(again, response) {
			t.Fatal("terminal refusal was not retained")
		}
	}
}
