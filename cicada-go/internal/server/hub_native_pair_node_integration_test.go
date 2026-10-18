package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nativePairNodeReply struct {
	OK          bool            `json:"ok"`
	OperationID string          `json:"operation_id"`
	Sequence    uint64          `json:"sequence"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   string          `json:"error_code"`
}

func (a *nativePairTCPActor) nodeBinding() nodewire.Binding {
	n := a.scope.Node
	return nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
}
func (a *nativePairTCPActor) nodeSeal(t *testing.T, op string, seq uint64, body any) []byte {
	t.Helper()
	b := a.nodeBinding()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	r := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: seq, OperationID: id, Operation: op, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := nodewire.SealRequest(a.node, b.HubKey, b, r, raw)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func (a *nativePairTCPActor) nodePost(t *testing.T, raw []byte, want int) []byte {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, a.f.http.URL+"/v2/node/control/rpc", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "CicadaNode "+a.nodeToken)
	r.Header.Set("Origin", a.f.setup.Origin)
	start := time.Now()
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	packet, err := io.ReadAll(io.LimitReader(response.Body, wire.MaxNativePairNodeReconcilePacketBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := wire.DecodeNativePairNodePacket(raw)
	t.Logf("synthetic Node PQ operation=%s request_bytes=%d response_bytes=%d elapsed_us=%d status=%d", p.Route.Operation, len(raw), len(packet), time.Since(start).Microseconds(), response.StatusCode)
	if response.StatusCode != want {
		t.Fatal("Node RPC status", response.StatusCode, "wanted", want)
	}
	return packet
}
func (a *nativePairTCPActor) nodeOpen(t *testing.T, original, reply []byte) nativePairNodeReply {
	t.Helper()
	p, err := wire.DecodeNativePairNodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodewire.OpenResponse(a.node, a.nodeBinding().HubKey, a.nodeBinding(), reply)
	if err != nil {
		t.Fatal(err)
	}
	want := p.Route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	if opened.Route != want {
		t.Fatal("Node response moved original route")
	}
	var out nativePairNodeReply
	d := json.NewDecoder(bytes.NewReader(opened.Plaintext))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || out.OperationID != p.Route.OperationID || out.Sequence != p.Route.Sequence {
		t.Fatal("Node response wrapper moved original")
	}
	return out
}
func (a *nativePairTCPActor) completePair(t *testing.T) wire.NativePairBootstrapChallenge {
	t.Helper()
	q := a.preview(t)
	original := a.seal(t, q)
	reply := a.post(t, wire.OperationNativePairBootstrapPrepare, original)
	var ch wire.NativePairBootstrapChallenge
	if wire.OpenClientResponse(a.device, a.f.hub, original, reply, &ch) != nil {
		t.Fatal("prepare failed")
	}
	c := a.context(t)
	proof, err := e2ee.SignOwnerNativePair(a.owner, e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairBootstrapCommit, Scope: ch.Scope, RequestID: c.RequestID, Nonce: hex.EncodeToString(c.ClientNonce), IssuedAt: c.IssuedAt, ExpiresAt: ch.ProofExpiresAt, Bootstrap: &ch.Bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	complete := wire.NativePairBootstrapComplete{Format: wire.NativePairFormat, Context: c, SessionToken: a.session.Token, OwnerProof: proof}
	packet := a.seal(t, complete)
	reply = a.post(t, wire.OperationNativePairBootstrapComplete, packet)
	var result wire.NativePairResult
	if wire.OpenClientResponse(a.device, a.f.hub, packet, reply, &result) != nil || result.State != wire.NativePairWaitingJoin {
		t.Fatal("complete failed")
	}
	return ch
}
func (a *nativePairTCPActor) describePair(t *testing.T, ch wire.NativePairBootstrapChallenge, seq uint64) wire.NativePairNodeDescription {
	t.Helper()
	packet := a.nodeSeal(t, wire.OperationNativePairNodeDescribe, seq, wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: ch.Bootstrap.PairID})
	result := a.nodeOpen(t, packet, a.nodePost(t, packet, http.StatusOK))
	if !result.OK {
		t.Fatal("describe refused", result.ErrorCode)
	}
	d, err := wire.DecodeNativePairNodeDescription(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wire.VerifyNativePairNodeDescription(d, a.owner.Public(), ch.Bootstrap.PairID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return d
}
func (a *nativePairTCPActor) reconcileNode(t *testing.T, pair string, original []byte) wire.NativePairNodeReconciled {
	t.Helper()
	p, err := wire.DecodeNativePairNodePacket(original)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairNodeReconcile{ContractRevision: wire.NativePairContractRevision, PairID: pair, Nonce: nonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), OriginalPacket: original}
	packet := a.nodeSeal(t, wire.OperationNativePairNodeReconcile, p.Route.Sequence, q)
	reply := a.nodeOpen(t, packet, a.nodePost(t, packet, http.StatusOK))
	if !reply.OK {
		t.Fatal("diagnostic refused")
	}
	r, err := wire.DecodeNativePairNodeReconciled(reply.Result)
	if err != nil || wire.ValidateNativePairNodeReconcileTarget(r, pair, original) != nil {
		t.Fatal("diagnostic original changed", err)
	}
	return r
}

func TestNativePairNodeRealTCPZeroJoinExactAndRecovery(t *testing.T) {
	a := nativePairTCP(t)
	ch := a.completePair(t)
	description := a.describePair(t, ch, 1)
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: ch.Bootstrap.PairID, Slot: "A", ExpectedGeneration: description.SlotAGeneration, BootstrapProofDigest: wire.NativePairProofDigest(description.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: "synthetic-node-native-a", Workspace: "/synthetic/private-a", EndpointName: "Synthetic A"}
	packet := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 2, q)
	reply := a.nodePost(t, packet, http.StatusOK)
	result := a.nodeOpen(t, packet, reply)
	var joined fabric.JoinResult
	if !result.OK || json.Unmarshal(result.Result, &joined) != nil || joined.Endpoint.NativeSessionID != q.NativeSessionID || joined.Endpoint.Workspace != q.Workspace || joined.BindingEpoch != 1 || joined.SessionToken == "" || joined.NetworkCard.GroupID != ch.Bootstrap.GroupID {
		t.Fatal("zero Join lost original identity/context", result.ErrorCode)
	}
	member, err := a.f.db.GetMembershipByPrincipalGroup(joined.Endpoint.PrincipalID, ch.Bootstrap.GroupID)
	if err != nil || len(member.Grants) != 0 || member.Revision != 1 {
		t.Fatal("zero Join acquired peer grants", err)
	}
	if retry := a.nodePost(t, packet, http.StatusOK); !bytes.Equal(reply, retry) {
		t.Fatal("exact Node retry changed epoch/credential/receipt")
	}
	recovered := a.reconcileNode(t, q.PairID, packet)
	if recovered.State != "COMPLETED" || !bytes.Equal(recovered.ReceiptPacket, reply) {
		t.Fatal("Node outcome was guessed instead of retained")
	}
	// A competing original takes the next sequence but cannot replace slot A.
	third := q
	third.NativeSessionID = "synthetic-node-native-third"
	third.Workspace = "/synthetic/private-third"
	competing := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 3, third)
	rejected := a.nodeOpen(t, competing, a.nodePost(t, competing, http.StatusOK))
	if rejected.OK || rejected.ErrorCode != wire.NativePairNodeJoinFenceCode || len(rejected.Result) != 0 {
		t.Fatal("occupied slot returned credentials or no permanent fence")
	}
	b := q
	b.Slot = "B"
	b.NativeSessionID = "synthetic-node-native-b"
	b.Workspace = "/synthetic/private-b"
	b.EndpointName = "Synthetic B"
	second := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 4, b)
	br := a.nodeOpen(t, second, a.nodePost(t, second, http.StatusOK))
	if !br.OK {
		t.Fatal("second original Thread refused", br.ErrorCode)
	}
	var other fabric.JoinResult
	if json.Unmarshal(br.Result, &other) != nil || other.Endpoint.ID == joined.Endpoint.ID || other.Endpoint.NativeSessionID != b.NativeSessionID || other.Endpoint.Workspace != b.Workspace {
		t.Fatal("two Threads collapsed their context")
	}
	missing, err := a.f.db.GetEndpointV2BySession("codex", third.NativeSessionID)
	if err != nil || missing != nil {
		t.Fatal("losing caller left an Endpoint", err)
	}
	for _, v := range []fabric.JoinResult{joined, other} {
		m, e := a.f.db.GetMembershipByPrincipalGroup(v.Endpoint.PrincipalID, ch.Bootstrap.GroupID)
		if e != nil || len(m.Grants) != 0 {
			t.Fatal("Join alone supplied peer rights")
		}
	}
}

func TestNativePairNodeRealTCPDetachedFenceAndLateOriginal(t *testing.T) {
	a := nativePairTCP(t)
	ch := a.completePair(t)
	d := a.describePair(t, ch, 1)
	q := wire.NativePairNodeJoin{ContractRevision: wire.NativePairContractRevision, PairID: ch.Bootstrap.PairID, Slot: "A", ExpectedGeneration: 1, BootstrapProofDigest: wire.NativePairProofDigest(d.BootstrapOwnerProof), Runtime: "codex", NativeSessionID: "synthetic-held-original-a", Workspace: "/synthetic/held-a"}
	held := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 2, q)
	r := a.reconcileNode(t, q.PairID, held)
	if r.State != "REJECTED_FENCED" {
		t.Fatal("unadmitted Join was replayed")
	}
	rejected := a.nodeOpen(t, held, r.ReceiptPacket)
	if rejected.OK || rejected.ErrorCode != wire.NativePairNodeJoinFenceCode {
		t.Fatal("inner fence not authenticated against original")
	}
	if late := a.nodePost(t, held, http.StatusOK); !bytes.Equal(late, r.ReceiptPacket) {
		t.Fatal("late Join escaped durable fence")
	}
	fresh := a.nodeSeal(t, wire.OperationNativePairNodeJoin, 3, q)
	reply := a.nodeOpen(t, fresh, a.nodePost(t, fresh, http.StatusOK))
	if !reply.OK {
		t.Fatal("new intent after a proven no-effect fence refused")
	}
	heldRead := a.nodeSeal(t, wire.OperationNativePairNodeDescribe, 4, wire.NativePairNodeDescribe{ContractRevision: wire.NativePairContractRevision, PairID: q.PairID})
	expired := a.reconcileNode(t, q.PairID, heldRead)
	if expired.State != "READ_EXPIRED" || len(expired.ReceiptPacket) != 0 {
		t.Fatal("detached read executed or claimed a business effect")
	}
	lateReadPacket := a.nodePost(t, heldRead, http.StatusOK)
	lateRead := a.nodeOpen(t, heldRead, lateReadPacket)
	if lateRead.OK || lateRead.ErrorCode != "RESULT_EXPIRED" {
		t.Fatal("late Describe acquired a new observation")
	}
	if again := a.nodePost(t, heldRead, http.StatusOK); !bytes.Equal(again, lateReadPacket) {
		t.Fatal("expired Describe exact receipt changed")
	}
	a.describePair(t, ch, 5) // Diagnostic IDs never consume an additional sequence.
}
