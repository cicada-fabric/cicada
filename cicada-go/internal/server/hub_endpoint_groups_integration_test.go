package server

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

type endpointGroupsHTTPFixture struct {
	a        *nativePairTCPActor
	domain   wire.LocalDomainDescription
	joins    [2]wire.LocalDomainNodeJoinResult
	keys     [2]*e2ee.Identity
	sequence uint64
}

func endpointGroupsOwnerHTTP(t *testing.T, a *nativePairTCPActor, operation string, body any) ([]byte, []byte, wire.OwnerEndpointGroupsResult) {
	t.Helper()
	packet, err := wire.SealClientRequest(a.device, a.f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	status, reply := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(operation), "", packet)
	if status != http.StatusOK {
		t.Fatal("Owner Endpoint Groups HTTP status", operation, status)
	}
	var result wire.OwnerEndpointGroupsResult
	if err = wire.OpenOwnerEndpointGroupsResponse(a.device, a.f.hub, packet, reply, &result); err != nil || wire.VerifyOwnerEndpointGroupsResult(body, packet, result, a.f.hub) != nil {
		t.Fatal("Owner Endpoint Groups authenticated target binding", operation, err)
	}
	t.Logf("synthetic Owner Group HTTP operation=%s request_bytes=%d response_bytes=%d", operation, len(packet), len(reply))
	return packet, reply, result
}

func (f *endpointGroupsHTTPFixture) nodeHTTP(t *testing.T, operation string, body any, out any) ([]byte, []byte) {
	t.Helper()
	f.sequence++
	plain, err := wire.CanonicalEndpointGroupsNodeRequest(operation, body)
	if err != nil {
		t.Fatal(err)
	}
	b := f.a.nodeBinding()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: f.sequence, OperationID: id, Operation: operation, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	packet, err := nodewire.SealRequest(f.a.node, b.HubKey, b, route, plain)
	if err != nil {
		t.Fatal(err)
	}
	status, reply := n3HTTP(t, f.a.f, http.MethodPost, "/v2/node/control/rpc", f.a.nodeToken, packet)
	if status != http.StatusOK {
		t.Fatal("Endpoint Groups Node HTTP status", operation, status)
	}
	if _, err = wire.DecodeEndpointGroupsNodePacket(reply); err != nil {
		t.Fatal("Endpoint Groups Node response bounds", err)
	}
	opened, err := nodewire.OpenResponse(f.a.node, b.HubKey, b, reply)
	want := route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
	if err != nil || opened.Route != want {
		t.Fatal("Endpoint Groups Node response route", err)
	}
	var result nativePairNodeReply
	decoder := json.NewDecoder(bytes.NewReader(opened.Plaintext))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || !result.OK || result.OperationID != id || result.Sequence != f.sequence {
		t.Fatal("Endpoint Groups Node authenticated business refusal", operation, result.ErrorCode)
	}
	if out != nil && json.Unmarshal(result.Result, out) != nil {
		t.Fatal("Endpoint Groups Node typed response", operation)
	}
	t.Logf("synthetic Node Group HTTP operation=%s request_bytes=%d response_bytes=%d", operation, len(packet), len(reply))
	return packet, reply
}

// The fixture enrolls every account/Owner/Node and original candidate through
// the actual isolated TCP Router. It never installs test grants or invokes a
// Runtime; new Endpoint Group requests use their real SDK and PQ envelopes.
func endpointGroupsRealHTTP(t *testing.T) *endpointGroupsHTTPFixture {
	t.Helper()
	f := &endpointGroupsHTTPFixture{a: nativePairTCP(t)}
	a := f.a
	h := a.f.http.Config.Handler.(*hubNodesHandler)
	if h.base.control != nil {
		t.Fatal("Owner authentication created a Control inference dependency")
	}
	status, raw := n3HTTP(t, a.f, http.MethodGet, wire.OwnerEndpointGroupsCapabilitiesPath, "", nil)
	caps, err := wire.DecodeOwnerEndpointGroupsCapabilities(raw, a.f.hub)
	if status != http.StatusOK || err != nil || caps.Available || caps.NativeSelfGroups {
		t.Fatal("pre-availability checkpoint changed its public capabilities", status, err)
	}
	now := time.Now().UTC()
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	n := a.scope.Node
	report := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: n.HubID, NodeID: n.NodeID, OwnerBindingID: n.OwnerBindingID, NodeKeyEpoch: n.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: hex.EncodeToString(nonce)}
	proof, err := e2ee.SignLocalDomainUserReport(a.node, report)
	if err != nil {
		t.Fatal(err)
	}
	f.sequence++
	var available wire.LocalDomainNodeAvailableResult
	localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeAvailable, f.sequence, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: report.LocalUserScope, LocalUserReport: proof}, &available)
	prepare, err := wire.NewLocalDomainPrepare(a.session, a.scope.Actor, e2ee.LocalDomainTarget{Node: n, NewNetworkName: "Synthetic Owner HTTP Network", GroupName: "Synthetic original Group"}, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var challenge wire.LocalDomainChallenge
	original, _ := localDomainOwnerHTTP(t, a, wire.OperationLocalDomainPrepare, prepare, &challenge)
	activate, err := wire.NewLocalDomainActivate(a.session, a.scope.Actor, prepare, original, challenge, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var activated wire.LocalDomainResult
	localDomainOwnerHTTP(t, a, wire.OperationLocalDomainActivate, activate, &activated)
	if activated.Description == nil {
		t.Fatal("actual original LocalDomain was not created", activated.ErrorCode)
	}
	f.domain = *activated.Description
	selection, err := wire.LocalDomainSelectionForPolicy(f.domain.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for i, sid := range []string{"synthetic-owner-http-original-A", "synthetic-owner-http-original-B"} {
		attempt, err := wire.NewRequestID()
		if err != nil {
			t.Fatal(err)
		}
		f.sequence++
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeJoin, f.sequence, wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, LocalUserScope: report.LocalUserScope, AttemptID: attempt, Runtime: "codex", NativeSessionID: sid, Workspace: "/synthetic/owner-http", EndpointName: "Synthetic original Thread"}, &f.joins[i])
		m := f.joins[i].Member
		f.keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := f.keys[i].SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		a.pairHTTP(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+f.joins[i].SessionToken, f.domain.Policy.GroupID, map[string]any{"attestation": json.RawMessage(attestation)}, http.StatusOK)
		f.sequence++
		var keyChallenge wire.LocalDomainKeyChallenge
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeKeyPrepare, f.sequence, wire.LocalDomainNodeKeyPrepare{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, MemberID: m.MemberID, ExpectedRevision: m.Revision}, &keyChallenge)
		nodeProof, err := e2ee.SignLocalDomainEndpointKey(a.node, f.domain.Policy, keyChallenge.Claims)
		if err != nil {
			t.Fatal(err)
		}
		f.sequence++
		var ready wire.LocalDomainNodeKeyResult
		localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeKeyComplete, f.sequence, wire.LocalDomainNodeKeyComplete{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, MemberID: m.MemberID, ExpectedRevision: m.Revision, ChallengeID: keyChallenge.ChallengeID, NodeProof: nodeProof}, &ready)
		if _, err = wire.VerifyLocalDomainEndpointKeyGrant(ready.Grant, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil {
			t.Fatal("original HTTP Node key chain", err)
		}
	}
	return f
}

func (f *endpointGroupsHTTPFixture) prepare(t *testing.T, body wire.OwnerEndpointGroupsPrepareBody) (wire.OwnerEndpointGroupsPrepareRequest, []byte, []byte, wire.OwnerEndpointGroupsReview) {
	t.Helper()
	body.NodeID, body.NetworkID = f.domain.Policy.Node.NodeID, f.domain.Policy.NetworkID
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.a.session, f.a.scope.Actor, body, f.a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, reply, result := endpointGroupsOwnerHTTP(t, f.a, wire.OperationOwnerEndpointGroupsPrepare, q)
	if result.State != "PREPARED" || result.Review == nil || wire.ValidateOwnerEndpointGroupsReview(q, packet, *result.Review, f.a.f.hub, time.Now().UTC()) != nil {
		t.Fatal("HTTP reviewed intent refused", result.ErrorCode)
	}
	return q, packet, reply, *result.Review
}

func (f *endpointGroupsHTTPFixture) apply(t *testing.T, prepare wire.OwnerEndpointGroupsPrepareRequest, prepared []byte, review wire.OwnerEndpointGroupsReview, head *e2ee.EndpointGroupOwnerControl) (wire.OwnerEndpointGroupsApplyRequest, []byte, []byte, wire.OwnerEndpointGroupsResult) {
	t.Helper()
	q, err := wire.NewOwnerEndpointGroupsApply(f.a.session, f.a.scope.Actor, prepare, prepared, review, f.a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	packet, reply, result := endpointGroupsOwnerHTTP(t, f.a, wire.OperationOwnerEndpointGroupsApply, q)
	if result.State != "COMPLETED" || result.Operation == nil || wire.VerifyOwnerEndpointGroupsOperation(review, packet, *result.Operation, head) != nil {
		t.Fatal("HTTP exact approved operation refused", result.ErrorCode)
	}
	return q, packet, reply, result
}

func (f *endpointGroupsHTTPFixture) recover(t *testing.T, originalBody any, original, receipt []byte) {
	t.Helper()
	q, err := wire.NewOwnerEndpointGroupsReconcile(f.a.session, f.a.scope.Actor, original, f.a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, result := endpointGroupsOwnerHTTP(t, f.a, wire.OperationOwnerEndpointGroupsReconcile, q)
	if result.State != "COMPLETED" || result.NodeID != f.domain.Policy.Node.NodeID || !bytes.Equal(result.ReceiptPacket, receipt) {
		t.Fatal("READ/PREPARE lost-response recovery lost its exact original Node scope")
	}
	var historical wire.OwnerEndpointGroupsResult
	if wire.OpenOwnerEndpointGroupsResponse(f.a.device, f.a.f.hub, original, result.ReceiptPacket, &historical) != nil || wire.VerifyOwnerEndpointGroupsResult(originalBody, original, historical, f.a.f.hub) != nil {
		t.Fatal("READ/PREPARE independently opened original receipt")
	}
}

func (f *endpointGroupsHTTPFixture) activate(t *testing.T, group string, i int) wire.EndpointGroupsNodeKeyResult {
	t.Helper()
	a := f.a
	q, original, _, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, GroupID: group, EndpointID: f.joins[i].Member.EndpointID, Duration: "until_revoked"})
	_, _, _, applied := f.apply(t, q, original, review, nil)
	if applied.CurrentRelation == nil || applied.CurrentRelation.State != "PENDING_KEY" || applied.CurrentRelation.OwnerControl.Mode != "DEFAULT" {
		t.Fatal("HTTP Owner apply silently activated Node keys or replaced the old head")
	}
	var described wire.EndpointGroupsNodeDescribeResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: f.joins[i].Member.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &described)
	if wire.ValidateEndpointGroupsNodeDescribeResult(described, a.f.hub, time.Now().UTC()) != nil || described.Registration.Registration.NativeSessionID != f.joins[i].Member.NativeSessionID || !reflect.DeepEqual(described.Registration.CandidatePublic, f.keys[i].Public()) {
		t.Fatal("HTTP Node describe replaced the retained native tuple or key")
	}
	var prepared wire.EndpointGroupsNodeKeyResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeKeyPrepare, wire.EndpointGroupsNodeKeyPrepare{PolicyID: review.Policy.PolicyID, PolicyEpoch: review.Policy.Epoch, EndpointID: f.joins[i].Member.EndpointID, GroupID: group, ExpectedRelationRevision: applied.CurrentRelation.RelationRevision}, &prepared)
	if _, err := wire.ValidateEndpointGroupsNodeKeyResult(prepared, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil || prepared.Challenge == nil {
		t.Fatal("HTTP exact Node key review", err)
	}
	claims, err := wire.EndpointGroupKeyClaimsForChallenge(*prepared.Challenge, *review.Policy)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.SignEndpointGroupKey(a.node, *review.Policy, claims)
	if err != nil {
		t.Fatal(err)
	}
	var completed wire.EndpointGroupsNodeKeyResult
	complete := wire.EndpointGroupsNodeKeyComplete{PolicyID: review.Policy.PolicyID, PolicyEpoch: review.Policy.Epoch, EndpointID: f.joins[i].Member.EndpointID, GroupID: group, ExpectedRelationRevision: prepared.Challenge.Expected.RelationRevision, ChallengeID: prepared.Challenge.ChallengeID, NodeProof: proof}
	original, receipt := f.nodeHTTP(t, wire.OperationEndpointGroupsNodeKeyComplete, complete, &completed)
	if _, err := wire.ValidateEndpointGroupsNodeKeyResult(completed, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil || completed.Grant == nil {
		t.Fatal("HTTP exact Node key completion", err)
	}
	status, retry := n3HTTP(t, a.f, http.MethodPost, "/v2/node/control/rpc", a.nodeToken, original)
	if status != http.StatusOK || !bytes.Equal(retry, receipt) {
		t.Fatal("HTTP lost key completion response was not exactly recoverable", status)
	}
	return completed
}

func endpointGroupsHTTPPeerPath(f *endpointGroupsHTTPFixture, group string) string {
	query := url.Values{"group_id": {group}, "source_endpoint_id": {f.joins[0].Member.EndpointID}, "target_endpoint_id": {f.joins[1].Member.EndpointID}}
	return "/v2/relay/nodes/" + url.PathEscape(f.domain.Policy.Node.NodeID) + "/group/sealed/peer-key?" + query.Encode()
}

func TestEndpointGroupsHTTPRealOwnerNodeRelayAndActiveRemove(t *testing.T) {
	f := endpointGroupsRealHTTP(t)
	a := f.a
	read, err := wire.NewOwnerEndpointGroupsRead(a.session, a.scope.Actor, wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID}, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	readPacket, readReceipt, inventory := endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsRead, read)
	if inventory.State != "COMPLETED" || len(inventory.Threads) != 2 {
		t.Fatal("HTTP inventory did not expose exactly the enrolled original Threads", inventory.ErrorCode)
	}
	f.recover(t, read, readPacket, readReceipt)
	create, prepared, prepareReceipt, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic second HTTP Group"})
	f.recover(t, create, prepared, prepareReceipt)
	_, _, _, created := f.apply(t, create, prepared, review, nil)
	group := created.Operation.Target.GroupID
	var activated [2]wire.EndpointGroupsNodeKeyResult
	for i := range activated {
		activated[i] = f.activate(t, group, i)
	}
	peerBytes := a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
	var peer store.SameGroupSealedV1PeerKey
	if json.Unmarshal(peerBytes, &peer) != nil || peer.EndpointGroupCurrent == nil || peer.Sender.EndpointGroupGrant == nil || peer.Receiver.EndpointGroupGrant == nil || peer.LocalDomainCurrent != nil || peer.NativePairEvidence != nil || peer.Sender.EndpointID != f.joins[0].Member.EndpointID || peer.Receiver.EndpointID != f.joins[1].Member.EndpointID {
		t.Fatal("HTTP peer key did not select the independent exact Owner sources")
	}
	if wire.ValidateEndpointGroupCurrent(*peer.EndpointGroupCurrent, "peer_key", peer.EndpointGroupCurrent.AttemptID, time.Now().UTC()) != nil {
		t.Fatal("HTTP current peer proof was not independently verifiable")
	}
	for _, side := range []struct {
		grant *wire.EndpointGroupDelegatedGrant
		now   wire.EndpointGroupCurrentEndpoint
	}{{peer.Sender.EndpointGroupGrant, peer.EndpointGroupCurrent.Sender}, {peer.Receiver.EndpointGroupGrant, peer.EndpointGroupCurrent.Receiver}} {
		if _, err := wire.VerifyEndpointGroupPeerSource(wire.EndpointGroupPeerSource{EndpointGroupGrant: side.grant}, side.now, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil {
			t.Fatal("HTTP exact peer source verification", err)
		}
	}
	messageID, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	context := e2ee.EndpointMessageContext{MessageID: messageID, Kind: "SEND", SenderEndpointID: peer.Sender.EndpointID, SenderPrincipalID: peer.Sender.PrincipalID, SenderOwnerID: peer.Sender.OwnerID, SenderGroupID: group, SenderMembershipRevision: peer.Sender.MembershipRevision, SenderBindingEpoch: peer.Sender.BindingEpoch, SenderKeyID: f.keys[0].Public().ID, ReceiverEndpointID: peer.Receiver.EndpointID, ReceiverPrincipalID: peer.Receiver.PrincipalID, ReceiverOwnerID: peer.Receiver.OwnerID, ReceiverGroupID: group, ReceiverMembershipRevision: peer.Receiver.MembershipRevision, ReceiverBindingEpoch: peer.Receiver.BindingEpoch, ReceiverKeyID: f.keys[1].Public().ID, TransportHubID: a.f.hub.HubID}
	ciphertext, err := e2ee.SealEndpointMessage(f.keys[0], f.keys[1].Public(), context, []byte("synthetic Owner Group HTTP SEND"), 1)
	if err != nil {
		t.Fatal(err)
	}
	base := "/v2/relay/nodes/" + url.PathEscape(f.domain.Policy.Node.NodeID) + "/group/sealed/"
	a.pairHTTP(t, http.MethodPost, base+"send", "CicadaNode "+a.nodeToken, "", fabric.NodeSameGroupSealedV1SendInput{GroupID: group, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: messageID, DataScope: store.SameGroupSealedV1DataScope, Ciphertext: ciphertext}, http.StatusAccepted)
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	claim := a.pairHTTP(t, http.MethodPost, base+"claim", "CicadaNode "+a.nodeToken, "", fabric.NodeClaimInput{ConsumerID: "synthetic-owner-http-consumer", Limit: 1}, http.StatusOK)
	if json.Unmarshal(claim, &claimed) != nil || len(claimed.Deliveries) != 1 {
		t.Fatal("HTTP manual Group delivery was not claimed")
	}
	path := base + "deliveries/" + messageID + "/authorization?attempt_id=" + url.QueryEscape(claimed.Deliveries[0].AttemptID)
	var authorization store.SameGroupSealedV1DeliveryAuthorization
	if json.Unmarshal(a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusOK), &authorization) != nil || authorization.EndpointGroupCurrent == nil || wire.ValidateEndpointGroupCurrent(*authorization.EndpointGroupCurrent, "native_delivery", claimed.Deliveries[0].AttemptID, time.Now().UTC()) != nil {
		t.Fatal("HTTP final authorization omitted the actual original attempt/source")
	}
	service := a.f.http.Config.Handler.(*hubNodesHandler).base.fabricService
	actor, err := service.AuthenticateForGroup(f.joins[0].SessionToken, group)
	if err != nil {
		t.Fatal("actual managed actor authentication", err)
	}
	for _, action := range []string{"task.read", "space.read", "membership.manage"} {
		if !errors.Is(service.Authorize(actor, action), fabric.ErrPermissionDenied) {
			t.Fatal("actual managed Actor Guard escaped its five-right source cap", action)
		}
	}
	scope := store.NativeActorScope{PrincipalID: actor.PrincipalID, EndpointID: actor.EndpointID, GroupID: actor.GroupID, NetworkID: actor.NetworkID, MembershipID: actor.MembershipID, MembershipRevision: actor.MembershipRevision, BindingID: actor.BindingID, BindingEpoch: actor.BindingEpoch, LeaseOwner: actor.LeaseOwner}
	if _, err = a.f.db.ListSharedTasksForActor(scope, 1); !errors.Is(err, store.ErrNetworkPermission) {
		t.Fatal("actual Store action Guard exposed unrelated task data", err)
	}
	// Expire only the original retained leases in this disposable database.
	// Active Group source proofs alone must not permit stale native delivery.
	db, err := sql.Open("sqlite", a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	anchor := activated[0].Registration
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	if _, err = db.Exec(`UPDATE session_bindings SET lease_expires_at=? WHERE id=?`, past, anchor.BindingID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE network_access_sessions_v2 SET lease_expires_at=? WHERE id=?`, past, anchor.NetworkAccessBindingID); err != nil {
		t.Fatal(err)
	}
	a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	before := time.Now().UTC()
	var renewed wire.EndpointGroupsNodeRenewResult
	f.nodeHTTP(t, wire.OperationEndpointGroupsNodeRenew, wire.EndpointGroupsNodeRenew{EndpointID: anchor.Registration.EndpointID, RegistrationDigest: anchor.RegistrationDigest, ExpectedBindingID: anchor.BindingID, ExpectedBindingEpoch: anchor.BindingEpoch}, &renewed)
	end, err := time.Parse(time.RFC3339Nano, renewed.Registration.LeaseExpiresAt)
	if err != nil || end.Before(before.Add(5*time.Minute)) || end.After(time.Now().UTC().Add(5*time.Minute)) || renewed.Registration.Registration != anchor.Registration || renewed.Registration.BindingID != anchor.BindingID || renewed.Registration.BindingEpoch != anchor.BindingEpoch || renewed.Registration.CandidateVersion != anchor.CandidateVersion || !reflect.DeepEqual(renewed.Registration.CandidatePublic, anchor.CandidatePublic) {
		t.Fatal("HTTP cold renewal exceeded five minutes or replaced original identity/key", err)
	}
	a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
	remove, removePacket, _, removeReview := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: f.joins[0].Member.EndpointID})
	head := activated[0].OwnerControl
	_, originalRemove, removeReceipt, removed := f.apply(t, remove, removePacket, removeReview, &head)
	if removed.CurrentRelation == nil || removed.CurrentRelation.State != "REMOVED" || removed.CurrentRelation.OwnerControl.PolicyID != head.PolicyID || removed.CurrentRelation.OwnerControl.PolicyEpoch != head.PolicyEpoch {
		t.Fatal("HTTP ACTIVE REMOVE lost its last activated policy head")
	}
	status, retry := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply), "", originalRemove)
	if status != http.StatusOK || !bytes.Equal(retry, removeReceipt) {
		t.Fatal("HTTP ACTIVE REMOVE response loss repeated an effect", status)
	}
	a.pairHTTP(t, http.MethodGet, path, "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+a.nodeToken, "", nil, http.StatusNotFound)
	a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, f.domain.Policy.GroupID), "CicadaNode "+a.nodeToken, "", nil, http.StatusOK)
}

func TestEndpointGroupsHTTPConflictUncertaintyAndRevokedHistory(t *testing.T) {
	f := endpointGroupsRealHTTP(t)
	a := f.a
	prepare, prepared, _, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic HTTP immutable original"})
	apply, original, receipt, _ := f.apply(t, prepare, prepared, review, nil)
	changed, err := wire.SealClientRequest(a.device, a.f.hub, apply)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply), "", changed)
	if status != http.StatusConflict {
		t.Fatal("HTTP same ID/different ciphertext did not map to fixed 409", status)
	}
	revoked, err := a.f.db.RevokeOwnerApprovalKeyLocal(a.scope.Actor.OwnerID, a.owner.Public().ID, int64(a.scope.Actor.OwnerKeyVersion))
	if err != nil {
		t.Fatal(err)
	}
	status, retry := n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply), "", original)
	if status != http.StatusOK || !bytes.Equal(retry, receipt) {
		t.Fatal("HTTP revocation changed the original durable encrypted receipt", status)
	}
	a.scope.Actor.OwnerKeyVersion = uint64(revoked.Version)
	q, err := wire.NewOwnerEndpointGroupsStatus(a.session, a.scope.Actor, original, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, historical := endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsStatus, q)
	if historical.Operation == nil || historical.Operation.OperationID != apply.Context.RequestID || !bytes.Equal(historical.ReceiptPacket, receipt) || historical.CurrentGroup != nil || historical.CurrentRelation != nil {
		t.Fatal("HTTP historical receipt borrowed revoked Root for current state")
	}
	denied, err := wire.NewOwnerEndpointGroupsPrepare(a.session, a.scope.Actor, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID, Name: "Synthetic forbidden post-revocation action"}, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, rejection := endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsPrepare, denied)
	if rejection.State != "REJECTED_FENCED" || rejection.ErrorCode != "OWNER_AUTHORITY_REQUIRED" || rejection.Review != nil {
		t.Fatal("HTTP account login/revoked Owner proof created a new review")
	}
	a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, f.domain.Policy.GroupID), "CicadaNode "+a.nodeToken, "", nil, http.StatusUnauthorized)
	// Deliberate disposable incomplete-restore fault: an existing immutable
	// floor without its receipt must retain pending, never become unseen/fenced.
	db, err := sql.Open("sqlite", a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`DROP TRIGGER hub_endpoint_groups_owner_operations_v1_no_delete;DELETE FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?`, apply.Context.RequestID); err != nil {
		t.Fatal(err)
	}
	status, _ = n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply), "", original)
	if status != http.StatusServiceUnavailable {
		t.Fatal("HTTP missing exact receipt did not map to fixed 503", status)
	}
	q, err = wire.NewOwnerEndpointGroupsStatus(a.session, a.scope.Actor, original, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	queryPacket, queryReceipt, uncertain := endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsStatus, q)
	if uncertain.State != "COMPLETED" || uncertain.ErrorCode != "OUTCOME_UNCERTAIN" || uncertain.Operation != nil || len(uncertain.ReceiptPacket) != 0 {
		t.Fatal("HTTP incomplete restore invented a terminal original receipt")
	}
	// A lost query response has its own exact retry. Re-login then permits a
	// new explicit query of the same original APPLY, never a replacement APPLY.
	login := n2Login(t, a.f, a.device, a.session.DeviceID, "synthetic-pair-tcp", "synthetic pair fixture password")
	a.session.Token, a.session.AccountEpoch, a.session.DeviceEpoch = login.SessionToken, login.AccountEpoch, login.DeviceEpoch
	accountStatus, err := wire.NewAppNodeStatus(a.session, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, current := n3Authority(t, a.f, a.device, accountStatus)
	if current.Result == nil {
		t.Fatal("re-login did not recover the retained diagnostic account scope")
	}
	a.scope.Actor = current.Result.Authority.Scope
	// This Owner profile binds current account/device security, independently
	// of the diagnostic N3 grant head; its frozen request proof requires zero.
	a.scope.Actor.HeadVersion = 0
	status, retry = n3HTTP(t, a.f, http.MethodPost, wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsStatus), "", queryPacket)
	if status != http.StatusOK || !bytes.Equal(retry, queryReceipt) {
		t.Fatal("re-login changed the exact lost query response", status)
	}
	fresh, err := wire.NewOwnerEndpointGroupsStatus(a.session, a.scope.Actor, original, a.owner, time.Now().UTC())
	if err != nil || fresh.Context.RequestID == q.Context.RequestID || fresh.Body.OperationID != apply.Context.RequestID {
		t.Fatal("new authenticated query replaced its original pending mutation", err)
	}
	_, _, stillUnknown := endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsStatus, fresh)
	if stillUnknown.State != "COMPLETED" || stillUnknown.ErrorCode != "OUTCOME_UNCERTAIN" || stillUnknown.Operation != nil || len(stillUnknown.ReceiptPacket) != 0 {
		t.Fatal("re-login inferred an original result from a completed wrapper")
	}
	denied, err = wire.NewOwnerEndpointGroupsPrepare(a.session, a.scope.Actor, denied.Body, a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, _, rejection = endpointGroupsOwnerHTTP(t, a, wire.OperationOwnerEndpointGroupsPrepare, denied)
	if rejection.State != "REJECTED_FENCED" || rejection.ErrorCode != "OWNER_AUTHORITY_REQUIRED" || rejection.Review != nil {
		t.Fatal("account re-login silently restored revoked Root")
	}
	var floors, operations int
	if err = db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1 WHERE operation_id=?),(SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?)`, apply.Context.RequestID, apply.Context.RequestID).Scan(&floors, &operations); err != nil || floors != 1 || operations != 0 {
		t.Fatal("unknown original was overwritten after query recovery/re-login", err)
	}
}
