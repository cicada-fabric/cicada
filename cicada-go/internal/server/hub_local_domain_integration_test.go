package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func localDomainOwnerHTTP(t *testing.T, a *nativePairTCPActor, op string, q any, out any) ([]byte, []byte) {
	t.Helper()
	packet, e := wire.SealClientRequest(a.device, a.f.hub, q)
	if e != nil {
		t.Fatal(e)
	}
	status, reply := n3HTTP(t, a.f, http.MethodPost, wire.LocalDomainHTTPPath(op), "", packet)
	if status != http.StatusOK || wire.OpenLocalDomainResponse(a.device, a.f.hub, packet, reply, out) != nil {
		t.Fatal("domain Owner HTTP authentication", op, status)
	}
	t.Logf("synthetic domain Owner operation=%s request_bytes=%d response_bytes=%d", op, len(packet), len(reply))
	return packet, reply
}

func localDomainNodeHTTP(t *testing.T, a *nativePairTCPActor, op string, seq uint64, q any, out any) ([]byte, []byte) {
	t.Helper()
	packet := a.nodeSeal(t, op, seq, q)
	reply := localDomainNodePost(t, a, packet)
	p, e := wire.DecodeLocalDomainNodePacket(packet)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := nodewire.OpenResponse(a.node, a.nodeBinding().HubKey, a.nodeBinding(), reply)
	if e != nil || opened.Route.Operation != op || opened.Route.OperationID != p.Route.OperationID || opened.Route.Sequence != seq {
		t.Fatal("domain Node response moved its route", e)
	}
	var result nativePairNodeReply
	if json.Unmarshal(opened.Plaintext, &result) != nil || !result.OK || result.OperationID != p.Route.OperationID || result.Sequence != seq {
		t.Fatal("domain Node business refusal", op, result.ErrorCode)
	}
	if out != nil && json.Unmarshal(result.Result, out) != nil {
		t.Fatal("domain Node typed result", op)
	}
	t.Logf("synthetic domain Node operation=%s request_bytes=%d response_bytes=%d", op, len(packet), len(reply))
	return packet, reply
}

func localDomainNodePost(t *testing.T, a *nativePairTCPActor, packet []byte) []byte {
	t.Helper()
	r, e := http.NewRequest(http.MethodPost, a.f.http.URL+"/v2/node/control/rpc", bytes.NewReader(packet))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Authorization", "CicadaNode "+a.nodeToken)
	r.Header.Set("Origin", a.f.setup.Origin)
	response, e := (&http.Client{Timeout: 10 * time.Second}).Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, wire.MaxLocalDomainNodeReconcilePacketBytes+1))
	if e != nil || response.StatusCode != http.StatusOK {
		t.Fatal("actual local-domain Node service status", response.StatusCode, e)
	}
	return raw
}

func localDomainProjectedResponse(t *testing.T, a *nativePairTCPActor, packet []byte, result any) []byte {
	t.Helper()
	p, e := nodewire.DecodePacket(packet)
	if e != nil {
		t.Fatal(e)
	}
	body, e := json.Marshal(map[string]any{"ok": true, "operation_id": p.Route.OperationID, "sequence": p.Route.Sequence, "result": result})
	if e != nil {
		t.Fatal(e)
	}
	r := p.Route
	r.Direction = nodewire.DirectionResponse
	r.SenderKeyID, r.ReceiverKeyID = r.ReceiverKeyID, r.SenderKeyID
	r.SenderKeyVersion, r.ReceiverKeyVersion = r.ReceiverKeyVersion, r.SenderKeyVersion
	raw, e := nodewire.SealResponse(a.f.ids.NodeControl, a.node.Public(), a.nodeBinding(), r, body)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("actual synthetic PQ projected operation=%s plaintext_bytes=%d complete_packet_bytes=%d", p.Route.Operation, len(body), len(raw))
	return raw
}

// Actual Hub-Nodes-only HTTP service with real N2/N3 enrollment, immutable
// Owner/Node keys, real PQ proof chain and the existing Relay. Native SIDs are
// synthetic locators and are never submitted to a native Runtime here.
func TestLocalDomainRealTCPActivationDelegationDeliveryAndRevocation(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) { localDomainRealTCP(t, false) })
	t.Run("maximum-native-fields", func(t *testing.T) { localDomainRealTCP(t, true) })
}

func localDomainRealTCP(t *testing.T, maximum bool) {
	var a *nativePairTCPActor
	if maximum {
		a = nativePeerTCP(t, strings.Repeat("n", 128), strings.Repeat("&", 128))
	} else {
		a = nativePairTCP(t)
	}
	now := time.Now().UTC()
	status, raw := n3HTTP(t, a.f, http.MethodGet, wire.LocalDomainCapabilitiesPath, "", nil)
	caps, e := wire.DecodeLocalDomainCapabilities(raw)
	if status != 200 || e != nil || !caps.Available {
		t.Fatal("domain capabilities", status, e)
	}
	nonce, e := wire.NewNonce()
	if e != nil {
		t.Fatal(e)
	}
	n := a.scope.Node
	r := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: n.HubID, NodeID: n.NodeID, OwnerBindingID: n.OwnerBindingID, NodeKeyEpoch: n.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	proof, e := e2ee.SignLocalDomainUserReport(a.node, r)
	if e != nil {
		t.Fatal(e)
	}
	var available wire.LocalDomainNodeAvailableResult
	localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeAvailable, 1, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: r.LocalUserScope, LocalUserReport: proof}, &available)
	if len(available.Policies) != 0 {
		t.Fatal("new policy was auto-created")
	}
	networkName, groupName := "Synthetic HTTP local Network", "Synthetic HTTP local Group"
	if maximum {
		networkName = strings.Repeat("&", 128)
		groupName = strings.Repeat("&", 128)
	}
	prepare, e := wire.NewLocalDomainPrepare(a.session, a.scope.Actor, e2ee.LocalDomainTarget{Node: n, NewNetworkName: networkName, GroupName: groupName}, a.owner, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var ch wire.LocalDomainChallenge
	original, _ := localDomainOwnerHTTP(t, a, wire.OperationLocalDomainPrepare, prepare, &ch)
	activate, e := wire.NewLocalDomainActivate(a.session, a.scope.Actor, prepare, original, ch, a.owner, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var activated wire.LocalDomainResult
	activationPacket, activationReply := localDomainOwnerHTTP(t, a, wire.OperationLocalDomainActivate, activate, &activated)
	if activated.Description == nil || wire.ValidateLocalDomainResultTarget(activate, activationPacket, activated, a.f.hub) != nil {
		t.Fatal("domain activation target")
	}
	status, exact := n3HTTP(t, a.f, http.MethodPost, wire.LocalDomainHTTPPath(wire.OperationLocalDomainActivate), "", activationPacket)
	if status != 200 || !bytes.Equal(exact, activationReply) {
		t.Fatal("lost activation response was not exactly recoverable")
	}
	d := *activated.Description
	s, e := wire.LocalDomainSelectionForPolicy(d.Policy)
	if e != nil {
		t.Fatal(e)
	}
	var joins [2]wire.LocalDomainNodeJoinResult
	var keys [2]*e2ee.Identity
	sequence := uint64(1)
	for i, sid := range []string{"synthetic-domain-http-A", "synthetic-domain-http-B"} {
		workspace, name := "/synthetic/local-domain", "Synthetic HTTP Thread"
		if maximum {
			sid = strings.Repeat("s", 127) + string(rune('a'+i))
			workspace = "/" + strings.Repeat("&", 1023)
			name = strings.Repeat("&", 128)
		}
		attempt, e := wire.NewRequestID()
		if e != nil {
			t.Fatal(e)
		}
		sequence++
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeJoin, sequence, wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: s, LocalUserScope: r.LocalUserScope, AttemptID: attempt, Runtime: "codex", NativeSessionID: sid, Workspace: workspace, EndpointName: name}, &joins[i])
		j := joins[i]
		m := j.Member
		if !maximum {
			assertNativeDirectoryStatus(t, a, d.Policy.GroupID, j.SessionToken, http.StatusForbidden)
		}
		self := a.pairHTTP(t, http.MethodGet, "/v2/fabric/whoami", "CicadaSession "+j.SessionToken, d.Policy.GroupID, nil, http.StatusOK)
		var card fabric.NetworkCard
		if json.Unmarshal(self, &card) != nil || card.EndpointID != m.EndpointID || card.NativeSessionID != sid || card.BindingEpoch != m.BindingEpoch {
			t.Fatal("domain zero self changed tuple")
		}
		keys[i], e = e2ee.NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		attestation, e := keys[i].SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
		if e != nil {
			t.Fatal(e)
		}
		a.pairHTTP(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+j.SessionToken, d.Policy.GroupID, map[string]any{"attestation": json.RawMessage(attestation)}, http.StatusOK)
		sequence++
		var challenge wire.LocalDomainKeyChallenge
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeKeyPrepare, sequence, wire.LocalDomainNodeKeyPrepare{ContractRevision: wire.LocalDomainContractRevision, Selection: s, MemberID: m.MemberID, ExpectedRevision: m.Revision}, &challenge)
		nodeProof, e := e2ee.SignLocalDomainEndpointKey(a.node, d.Policy, challenge.Claims)
		if e != nil {
			t.Fatal(e)
		}
		sequence++
		var completed wire.LocalDomainNodeKeyResult
		complete := wire.LocalDomainNodeKeyComplete{ContractRevision: wire.LocalDomainContractRevision, Selection: s, MemberID: m.MemberID, ExpectedRevision: m.Revision, ChallengeID: challenge.ChallengeID, NodeProof: nodeProof}
		projectionRequest := a.nodeSeal(t, wire.OperationLocalDomainNodeKeyComplete, sequence, complete)
		projectedDescription := d
		projectedDescription.MemberCount = uint64(i + 1)
		projectedDescription.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		projection := wire.LocalDomainNodeKeyResult{ContractRevision: wire.LocalDomainContractRevision, Description: projectedDescription, Member: challenge.Member, Grant: wire.LocalDomainEndpointKeyGrant{ContractRevision: wire.LocalDomainContractRevision, Member: challenge.Member, Manifest: challenge.Manifest, PolicyProof: d.PolicyProof, NodeProof: nodeProof}}
		projected := localDomainProjectedResponse(t, a, projectionRequest, projection)
		projectedOriginal, _ := nodewire.DecodePacket(projectionRequest)
		probeNonce, e := wire.NewNonce()
		if e != nil {
			t.Fatal(e)
		}
		probeReconcile := wire.LocalDomainNodeReconcile{ContractRevision: wire.LocalDomainContractRevision, Nonce: probeNonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), OriginalPacket: projectionRequest}
		probeResult := wire.LocalDomainNodeReconciled{ContractRevision: wire.LocalDomainContractRevision, OriginalOperation: projectedOriginal.Route.Operation, OriginalOperationID: projectedOriginal.Route.OperationID, OriginalSequence: projectedOriginal.Route.Sequence, OriginalPacketDigest: wire.LocalDomainPacketDigest(projectionRequest), State: wire.AppNodeCompleted, ReceiptPacket: projected, ObservedAt: probeReconcile.IssuedAt}
		_ = localDomainProjectedResponse(t, a, a.nodeSeal(t, wire.OperationLocalDomainNodeReconcile, sequence, probeReconcile), probeResult)
		if len(projected) > wire.MaxLocalDomainNodeReceiptBytes {
			t.Fatalf("valid native-field key_complete measured %d exceeds new-domain receipt bound %d", len(projected), wire.MaxLocalDomainNodeReceiptBytes)
		}
		original, receipt := localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeKeyComplete, sequence, complete, &completed)
		if _, e = wire.VerifyLocalDomainEndpointKeyGrant(completed.Grant, a.f.hub, d.Policy.OwnerID, a.owner.Public(), time.Now().UTC()); e != nil {
			t.Fatal("HTTP complete delegation", e)
		}
		old, _ := nodewire.DecodePacket(original)
		nonce, e := wire.NewNonce()
		if e != nil {
			t.Fatal(e)
		}
		reconcile := wire.LocalDomainNodeReconcile{ContractRevision: wire.LocalDomainContractRevision, Nonce: nonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), OriginalPacket: original}
		projectedReconcile := wire.LocalDomainNodeReconciled{ContractRevision: wire.LocalDomainContractRevision, OriginalOperation: old.Route.Operation, OriginalOperationID: old.Route.OperationID, OriginalSequence: old.Route.Sequence, OriginalPacketDigest: wire.LocalDomainPacketDigest(original), State: wire.AppNodeCompleted, ReceiptPacket: receipt, ObservedAt: reconcile.IssuedAt}
		if raw := localDomainProjectedResponse(t, a, a.nodeSeal(t, wire.OperationLocalDomainNodeReconcile, sequence, reconcile), projectedReconcile); len(raw) > wire.MaxLocalDomainNodeReconcilePacketBytes {
			t.Fatalf("valid nested key_complete reconcile measured %d exceeds new-domain reconcile bound %d", len(raw), wire.MaxLocalDomainNodeReconcilePacketBytes)
		}
		var reconciled wire.LocalDomainNodeReconciled
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeReconcile, sequence, reconcile, &reconciled)
		if !bytes.Equal(reconciled.ReceiptPacket, receipt) || reconciled.OriginalSequence != old.Route.Sequence || reconciled.OriginalOperationID != old.Route.OperationID {
			t.Fatal("nested reconciliation lost the exact original key receipt")
		}
		if i == 0 && !maximum {
			sequence++
			localDomainLargeRejectedOriginalRecovery(t, a, sequence, complete)
		}
	}
	if !maximum {
		want := make(map[string]nativeDirectoryExpected)
		for _, j := range joins {
			want[j.Member.EndpointID] = nativeDirectoryExpected{name: j.Endpoint.Name, workspace: j.Member.Workspace, node: j.Member.NodeID}
		}
		assertNativeDirectoryHTTP(t, a, d.Policy.GroupID, joins[0].SessionToken, want)
	}
	query := url.Values{"group_id": {d.Policy.GroupID}, "source_endpoint_id": {joins[0].Member.EndpointID}, "target_endpoint_id": {joins[1].Member.EndpointID}}
	peerRaw := a.pairHTTP(t, http.MethodGet, "/v2/relay/nodes/"+url.PathEscape(n.NodeID)+"/group/sealed/peer-key?"+query.Encode(), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
	var peer store.SameGroupSealedV1PeerKey
	if json.Unmarshal(peerRaw, &peer) != nil || peer.LocalDomainCurrent == nil || peer.Sender.LocalDomainGrant == nil || peer.Receiver.LocalDomainGrant == nil || peer.NativePairEvidence != nil {
		t.Fatal("HTTP delegated peer carrier")
	}
	const msg = "synthetic-domain-http-send"
	context := e2ee.EndpointMessageContext{MessageID: msg, Kind: "SEND", SenderEndpointID: peer.Sender.EndpointID, SenderPrincipalID: peer.Sender.PrincipalID, SenderOwnerID: peer.Sender.OwnerID, SenderGroupID: d.Policy.GroupID, SenderMembershipRevision: peer.Sender.MembershipRevision, SenderBindingEpoch: peer.Sender.BindingEpoch, SenderKeyID: keys[0].Public().ID, ReceiverEndpointID: peer.Receiver.EndpointID, ReceiverPrincipalID: peer.Receiver.PrincipalID, ReceiverOwnerID: peer.Receiver.OwnerID, ReceiverGroupID: d.Policy.GroupID, ReceiverMembershipRevision: peer.Receiver.MembershipRevision, ReceiverBindingEpoch: peer.Receiver.BindingEpoch, ReceiverKeyID: keys[1].Public().ID, TransportHubID: a.f.hub.HubID}
	ciphertext, e := e2ee.SealEndpointMessage(keys[0], keys[1].Public(), context, []byte("synthetic HTTP local-domain SEND"), 1)
	if e != nil {
		t.Fatal(e)
	}
	a.pairHTTP(t, http.MethodPost, "/v2/relay/nodes/"+url.PathEscape(n.NodeID)+"/group/sealed/send", "CicadaNode "+a.nodeToken, "", fabric.NodeSameGroupSealedV1SendInput{GroupID: d.Policy.GroupID, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: msg, DataScope: store.SameGroupSealedV1DataScope, Ciphertext: ciphertext}, http.StatusAccepted)
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	claimRaw := a.pairHTTP(t, http.MethodPost, "/v2/relay/nodes/"+url.PathEscape(n.NodeID)+"/group/sealed/claim", "CicadaNode "+a.nodeToken, "", fabric.NodeClaimInput{ConsumerID: "synthetic-domain-consumer", Limit: 1}, http.StatusOK)
	if json.Unmarshal(claimRaw, &claimed) != nil || len(claimed.Deliveries) != 1 {
		t.Fatal("HTTP domain claim")
	}
	path := "/v2/relay/nodes/" + url.PathEscape(n.NodeID) + "/group/sealed/deliveries/" + msg + "/authorization?attempt_id=" + url.QueryEscape(claimed.Deliveries[0].AttemptID)
	var authorization store.SameGroupSealedV1DeliveryAuthorization
	if json.Unmarshal(a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusOK), &authorization) != nil || authorization.LocalDomainCurrent == nil || authorization.LocalDomainCurrent.AttemptID != claimed.Deliveries[0].AttemptID {
		t.Fatal("HTTP fresh final authorization")
	}
	revoke, e := wire.NewLocalDomainRevoke(a.session, a.scope.Actor, d, a.owner, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	var revoked wire.LocalDomainResult
	localDomainOwnerHTTP(t, a, wire.OperationLocalDomainRevoke, revoke, &revoked)
	a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	if !maximum {
		assertNativeDirectoryStatus(t, a, d.Policy.GroupID, joins[0].SessionToken, http.StatusForbidden)
	}
}

// Exercise a large, authenticated, typed original and its exact rejection
// receipt. The deliberately invalid inner signature is synthetic padding in a
// defined byte field; it can never authorize a candidate or change membership.
func localDomainLargeRejectedOriginalRecovery(t *testing.T, a *nativePairTCPActor, sequence uint64, complete wire.LocalDomainNodeKeyComplete) {
	t.Helper()
	var proof e2ee.LocalDomainEndpointKeyProof
	if err := json.Unmarshal(complete.NodeProof, &proof); err != nil {
		t.Fatal(err)
	}
	proof.Signature = bytes.Repeat([]byte{0x53}, 13000)
	rawProof, err := json.Marshal(proof)
	if err != nil || len(rawProof) > e2ee.MaxLocalDomainProofBytes {
		t.Fatal("synthetic inner proof exceeded its existing cap", err)
	}
	complete.NodeProof = rawProof
	body, err := wire.CanonicalLocalDomainNodeRequest(wire.OperationLocalDomainNodeKeyComplete, complete)
	if err != nil {
		t.Fatal("large original was not a typed request", err)
	}
	unknown := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"unknown_padding":true}`)...)
	if _, err := wire.DecodeLocalDomainNodeRequest(wire.OperationLocalDomainNodeKeyComplete, unknown); err == nil {
		t.Fatal("unknown DTO padding was accepted")
	}
	original := a.nodeSeal(t, wire.OperationLocalDomainNodeKeyComplete, sequence, complete)
	if len(original) <= 48<<10 || len(original) > wire.MaxLocalDomainNodeOriginalBytes {
		t.Fatalf("boundary fixture original size=%d", len(original))
	}
	receipt := localDomainNodePost(t, a, original)
	opened, err := nodewire.OpenResponse(a.node, a.nodeBinding().HubKey, a.nodeBinding(), receipt)
	var refused nativePairNodeReply
	if err != nil || json.Unmarshal(opened.Plaintext, &refused) != nil || refused.OK || refused.ErrorCode != "LOCAL_DOMAIN_REJECTED" {
		t.Fatal("invalid proof did not produce its durable signed rejection", err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	q := wire.LocalDomainNodeReconcile{ContractRevision: wire.LocalDomainContractRevision, Nonce: nonce, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), OriginalPacket: original}
	reconcileBody, err := wire.CanonicalLocalDomainNodeRequest(wire.OperationLocalDomainNodeReconcile, q)
	if err != nil || len(reconcileBody) <= nodewire.MaxRequestPlaintextBytes || len(reconcileBody) > wire.MaxLocalDomainNodeReconcileBodyBytes {
		t.Fatalf("large reconcile body size=%d err=%v", len(reconcileBody), err)
	}
	packet := a.nodeSeal(t, wire.OperationLocalDomainNodeReconcile, sequence, q)
	if len(packet) > nodewire.MaxRequestPacketBytes {
		t.Fatal("reconciliation enlarged generic Node request packet limit")
	}
	var result wire.LocalDomainNodeReconciled
	localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeReconcile, sequence, q, &result)
	if result.State != wire.AppNodeRejectedFenced || !bytes.Equal(result.ReceiptPacket, receipt) || result.OriginalPacketDigest != wire.LocalDomainPacketDigest(original) {
		t.Fatal("large original rejection was not recovered byte for byte")
	}
	if exact := localDomainNodePost(t, a, original); !bytes.Equal(exact, receipt) {
		t.Fatal("large rejected original was re-executed on retry")
	}
	t.Logf("synthetic rejected original_bytes=%d reconcile_plaintext_bytes=%d reconcile_packet_bytes=%d", len(original), len(reconcileBody), len(packet))
}
