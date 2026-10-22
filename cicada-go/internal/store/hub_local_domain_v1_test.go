package store

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localDomainStoreFixture struct {
	f        *nativePairStoreFixture
	sequence uint64
}

func localDomainStore(t *testing.T) *localDomainStoreFixture {
	t.Helper()
	f := nativePairStore(t)
	// The generic candidate service samples wall time; backdate this synthetic
	// Store admission window so its membership is already effective there.
	f.at = time.Now().UTC().Add(-10 * time.Second)
	return &localDomainStoreFixture{f: f}
}

func (f *localDomainStoreFixture) ownerInput(t *testing.T, body any, at time.Time) (HubLocalDomainInput, HubLocalDomainSeal) {
	t.Helper()
	base := f.f.f
	raw, err := wire.SealClientRequest(base.device, base.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := wire.NewClientRoute(base.hub, body, base.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened any
	switch body.(type) {
	case wire.LocalDomainPrepare:
		opened = &wire.LocalDomainPrepare{}
	case wire.LocalDomainActivate:
		opened = &wire.LocalDomainActivate{}
	case wire.LocalDomainStatusRequest:
		opened = &wire.LocalDomainStatusRequest{}
	case wire.LocalDomainRevoke:
		opened = &wire.LocalDomainRevoke{}
	case wire.LocalDomainReconcileRequest:
		opened = &wire.LocalDomainReconcileRequest{}
	default:
		t.Fatal("unexpected typed domain request")
	}
	pub := base.device.Public()
	if wire.OpenRequestAt(base.hubPrivate, &pub, b, r, raw, opened, time.Time{}) != nil {
		t.Fatal("domain Owner PQ request failed authentication")
	}
	in := HubLocalDomainInput{Hub: base.hub, NodeControlPublic: base.nodeControl.Public(), Device: pub, Packet: raw, Body: reflect.ValueOf(opened).Elem().Interface(), At: at}
	return in, func(body any) ([]byte, error) { return wire.SealResponse(base.hubPrivate, pub, r, body) }
}

func (f *localDomainStoreFixture) nodeInput(t *testing.T, operation string, body any, at time.Time) (HubLocalDomainNodeInput, HubLocalDomainNodeSeal) {
	t.Helper()
	f.sequence++
	sequence := f.sequence
	base := f.f.f
	n := f.f.scope.Node
	b := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	r := nodewire.Route{Version: 1, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.BindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: f.sequence, OperationID: id, Operation: operation, SenderKeyID: b.NodeKey.ID, SenderKeyVersion: b.NodeKeyVersion, ReceiverKeyID: b.HubKey.ID, ReceiverKeyVersion: b.HubKeyVersion}
	plain, err := wire.CanonicalLocalDomainNodeRequest(operation, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nodewire.SealRequest(base.node, b.HubKey, b, r, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodewire.OpenRequest(base.nodeControl, b.NodeKey, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := wire.DecodeLocalDomainNodeRequest(operation, opened.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	in := HubLocalDomainNodeInput{Hub: base.hub, NodeControlPublic: base.nodeControl.Public(), CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Packet: raw, Body: decoded, At: at, SessionToken: "SYNTHETIC-DOMAIN-SESSION-" + id}
	return in, func(out HubLocalDomainNodeOutput) ([]byte, error) {
		response := map[string]any{"ok": out.ErrorCode == "", "operation_id": id, "sequence": sequence}
		if out.ErrorCode != "" {
			response["error_code"] = out.ErrorCode
		} else {
			response["result"] = out.Result
		}
		plaintext, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		route := r
		route.Direction = nodewire.DirectionResponse
		route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
		route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
		return nodewire.SealResponse(base.nodeControl, b.NodeKey, b, route, plaintext)
	}
}

func (f *localDomainStoreFixture) report(t *testing.T, at time.Time) {
	t.Helper()
	n := f.f.scope.Node
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	r := e2ee.LocalDomainUserReport{Version: 1, Purpose: e2ee.LocalDomainUserReportPurpose, HubID: n.HubID, NodeID: n.NodeID, OwnerBindingID: n.OwnerBindingID, NodeKeyEpoch: n.NodeKeyEpoch, LocalUserScope: "uid:1000", IssuedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(at.Add(5 * time.Minute)), Nonce: hex.EncodeToString(nonce)}
	raw, err := e2ee.SignLocalDomainUserReport(f.f.f.node, r)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeAvailable, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: r.LocalUserScope, LocalUserReport: raw}, at)
	packet, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal)
	if err != nil {
		t.Fatal("domain report", err)
	}
	opened, err := nodewire.OpenResponse(f.f.f.node, n.HubNodeControlPublic, nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}, packet)
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		OK    bool   `json:"ok"`
		Error string `json:"error_code"`
	}
	if json.Unmarshal(opened.Plaintext, &reply) != nil || !reply.OK {
		t.Fatal("domain report business refusal", reply.Error)
	}
}

func (f *localDomainStoreFixture) activate(t *testing.T) wire.LocalDomainDescription {
	t.Helper()
	f.report(t, f.f.at)
	base := f.f.f
	target := e2ee.LocalDomainTarget{Node: f.f.scope.Node, NewNetworkName: "Synthetic private local Network", GroupName: "Synthetic local Group"}
	prepare, err := wire.NewLocalDomainPrepare(base.session, base.scope, target, base.owner, f.f.at)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.ownerInput(t, prepare, f.f.at)
	reply, err := base.db.ProcessHubLocalDomain(in, seal)
	if err != nil {
		t.Fatal("domain prepare", err)
	}
	var ch wire.LocalDomainChallenge
	if wire.OpenLocalDomainResponse(base.device, base.hub, in.Packet, reply, &ch) != nil {
		var refusal wire.LocalDomainResult
		if wire.OpenLocalDomainResponse(base.device, base.hub, in.Packet, reply, &refusal) == nil {
			t.Fatal("prepare refused", refusal.ErrorCode)
		}
		t.Fatal("domain challenge decode")
	}
	complete, err := wire.NewLocalDomainActivate(base.session, base.scope, prepare, in.Packet, ch, base.owner, f.f.at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ci, cs := f.ownerInput(t, complete, f.f.at.Add(time.Second))
	packet, err := base.db.ProcessHubLocalDomain(ci, cs)
	if err != nil {
		t.Fatal("domain activate", err)
	}
	var result wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(base.device, base.hub, ci.Packet, packet, &result) != nil || wire.ValidateLocalDomainResultTarget(complete, ci.Packet, result, base.hub) != nil || result.State != wire.AppNodeCompleted || result.Description == nil {
		t.Fatal("domain activation not completed", result.ErrorCode)
	}
	return *result.Description
}

func TestLocalDomainStorePersistentActivationAndOwnerRecovery(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	if d.State != wire.LocalDomainActive || d.Policy.ExpiresAt != "" {
		t.Fatal("unexpected finite/absent domain")
	}
	q, err := wire.NewLocalDomainStatusForNode(f.f.f.session, f.f.f.scope, d.Policy.Node.NodeID, "", f.f.f.owner, f.f.at.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.ownerInput(t, q, f.f.at.Add(2*time.Second))
	reply, err := f.f.f.db.ProcessHubLocalDomain(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var result wire.LocalDomainResult
	if wire.OpenLocalDomainResponse(f.f.f.device, f.f.f.hub, in.Packet, reply, &result) != nil || wire.ValidateLocalDomainResultTarget(q, in.Packet, result, f.f.f.hub) != nil || len(result.Policies) != 1 || result.Policies[0].Policy.PolicyID != d.Policy.PolicyID {
		t.Fatal("new App-like empty policy cache could not recover exact Node policy")
	}
	if repeat, err := f.f.f.db.ProcessHubLocalDomain(in, seal); err != nil || !bytes.Equal(reply, repeat) {
		t.Fatal("exact Owner read retry changed its original observation", err)
	}
}

func TestLocalDomainStoreJoinRetainsStableNativeIdentityOnRetry(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	selection, err := wire.LocalDomainSelectionForPolicy(d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, LocalUserScope: d.Policy.LocalUserScope, AttemptID: strings.Repeat("a", 32), Runtime: "codex", NativeSessionID: "synthetic-domain-native-thread", Workspace: "/synthetic/domain/workspace", EndpointName: "Synthetic local Thread"}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeJoin, q, f.f.at.Add(2*time.Second))
	type outcome struct {
		packet []byte
		err    error
	}
	start, results := make(chan struct{}), make(chan outcome, 4)
	for i := 0; i < cap(results); i++ {
		go func() {
			<-start
			packet, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal)
			results <- outcome{packet, err}
		}()
	}
	close(start)
	var packet []byte
	for i := 0; i < cap(results); i++ {
		r := <-results
		if r.err != nil {
			t.Fatal("concurrent domain zero join", r.err)
		}
		if packet == nil {
			packet = r.packet
		} else if !bytes.Equal(packet, r.packet) {
			t.Fatal("concurrent original Join returned different identity/token receipts")
		}
	}
	if err := f.f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	f.f.f.db, err = New(f.f.f.path)
	if err != nil {
		t.Fatal("reopen original Hub state", err)
	}
	if retry, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal); err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("persisted exact Node join retry changed packet or identity", err)
	}
	var endpoint, member string
	if f.f.f.db.db.QueryRow(`SELECT endpoint_id,member_id FROM hub_local_domain_members_v1 WHERE policy_id=? AND native_session_id=?`, d.Policy.PolicyID, q.NativeSessionID).Scan(&endpoint, &member) != nil || endpoint == "" || member == "" {
		t.Fatal("explicit native registration was not persisted")
	}
	var count int
	if f.f.f.db.db.QueryRow(`SELECT count(*) FROM fabric_endpoints WHERE native_session_id=?`, q.NativeSessionID).Scan(&count) != nil || count != 1 {
		t.Fatal("native retry fabricated another Endpoint")
	}
}

func (f *localDomainStoreFixture) nodeResult(t *testing.T, in HubLocalDomainNodeInput, seal HubLocalDomainNodeSeal, out any) []byte {
	t.Helper()
	packet, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal)
	if err != nil {
		t.Fatal("domain Node operation", err)
	}
	n := f.f.scope.Node
	b := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	opened, err := nodewire.OpenResponse(f.f.f.node, n.HubNodeControlPublic, b, packet)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error_code"`
	}
	if json.Unmarshal(opened.Plaintext, &body) != nil || !body.OK {
		t.Fatal("domain Node business refusal", body.Error)
	}
	if json.Unmarshal(body.Result, out) != nil {
		t.Fatal("domain Node typed result failed")
	}
	return packet
}

func (f *localDomainStoreFixture) join(t *testing.T, d wire.LocalDomainDescription, sid string) (wire.LocalDomainNodeJoinResult, HubLocalDomainNodeInput) {
	t.Helper()
	selection, err := wire.LocalDomainSelectionForPolicy(d.Policy)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	q := wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, LocalUserScope: d.Policy.LocalUserScope, AttemptID: attempt, Runtime: "codex", NativeSessionID: sid, Workspace: "/synthetic/domain/workspace", EndpointName: "Synthetic local Thread"}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeJoin, q, f.f.at.Add(2*time.Second))
	var result wire.LocalDomainNodeJoinResult
	f.nodeResult(t, in, seal, &result)
	return result, in
}

func (f *localDomainStoreFixture) keyReady(t *testing.T, d wire.LocalDomainDescription, join wire.LocalDomainNodeJoinResult, key *e2ee.Identity) wire.LocalDomainNodeKeyResult {
	t.Helper()
	m := join.Member
	var membership string
	if f.f.f.db.db.QueryRow(`SELECT id FROM memberships WHERE principal_id=? AND group_id=?`, m.PrincipalID, d.Policy.GroupID).Scan(&membership) != nil {
		t.Fatal("membership fixture")
	}
	attestation, err := key.SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	scope := NativeActorScope{PrincipalID: m.PrincipalID, EndpointID: m.EndpointID, GroupID: d.Policy.GroupID, NetworkID: d.Policy.NetworkID, MembershipID: membership, MembershipRevision: int64(m.MembershipRevision), BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, LeaseOwner: m.LeaseOwner}
	if _, err = f.f.f.db.RegisterEndpointKeyCandidateForActor(scope, attestation); err != nil {
		t.Fatal("existing candidate service", err)
	}
	prepare := wire.LocalDomainNodeKeyPrepare{ContractRevision: wire.LocalDomainContractRevision, Selection: m.Selection, MemberID: m.MemberID, ExpectedRevision: m.Revision}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeKeyPrepare, prepare, f.f.at.Add(3*time.Second))
	var ch wire.LocalDomainKeyChallenge
	packet := f.nodeResult(t, in, seal, &ch)
	if exact, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal); err != nil || !bytes.Equal(packet, exact) {
		t.Fatal("key prepare retry changed its original challenge", err)
	}
	proof, err := e2ee.SignLocalDomainEndpointKey(f.f.f.node, d.Policy, ch.Claims)
	if err != nil {
		t.Fatal(err)
	}
	complete := wire.LocalDomainNodeKeyComplete{ContractRevision: wire.LocalDomainContractRevision, Selection: m.Selection, ChallengeID: ch.ChallengeID, MemberID: m.MemberID, ExpectedRevision: ch.ExpectedRevision, NodeProof: proof}
	ci, cs := f.nodeInput(t, wire.OperationLocalDomainNodeKeyComplete, complete, f.f.at.Add(4*time.Second))
	var result wire.LocalDomainNodeKeyResult
	f.nodeResult(t, ci, cs, &result)
	if _, err := wire.VerifyLocalDomainEndpointKeyGrant(result.Grant, f.f.f.hub, d.Policy.OwnerID, f.f.f.owner.Public(), f.f.at.Add(4*time.Second)); err != nil {
		t.Fatal("complete delegated Owner/Node/Endpoint chain", err)
	}
	return result
}

func TestLocalDomainStoreDelegatedKeyChainAndAppIndependentPolicy(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	join, _ := f.join(t, d, "synthetic-domain-key-thread")
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	active := f.keyReady(t, d, join, key)
	if active.Member.State != wire.LocalDomainMemberActive || active.Member.Revision != 2 || active.Grant.Manifest.ExpiresAt != "" {
		t.Fatal("delegation did not activate exact original member")
	}
	// Simulate ordinary session termination, an inactive creator App, and the
	// expiration of the short report/login. Policy authority uses neither.
	if _, err = f.f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED'`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.f.db.db.Exec(`UPDATE client_devices_v2 SET state='REVOKED' WHERE owner_id=? AND device_id=?`, d.Policy.OwnerID, f.f.f.scope.DeviceID); err != nil {
		t.Fatal(err)
	}
	q := wire.LocalDomainNodeDescribe{ContractRevision: wire.LocalDomainContractRevision, Selection: join.Member.Selection, LocalUserScope: d.Policy.LocalUserScope}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeDescribe, q, f.f.at.Add(20*time.Minute))
	var current wire.LocalDomainDescription
	f.nodeResult(t, in, seal, &current)
	if current.State != wire.LocalDomainActive || current.Policy.PolicyID != d.Policy.PolicyID {
		t.Fatal("persistent policy depended on creator App/report/login lease")
	}
}

func TestLocalDomainStoreLeaveExplicitRejoinRetainsSIDAndHistory(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	old, original := f.join(t, d, "synthetic-rejoin-native-thread")
	m := old.Member
	if err := f.f.f.db.LeaveEndpointAllGroups(m.EndpointID, m.BindingID, m.BindingEpoch, "synthetic explicit leave"); err != nil {
		t.Fatal(err)
	}
	next, _ := f.join(t, d, m.NativeSessionID)
	if next.Member.MemberID == m.MemberID || next.Member.EndpointID != m.EndpointID || next.Member.PrincipalID != m.PrincipalID || next.Member.NativeSessionID != m.NativeSessionID || next.Member.Workspace != m.Workspace || next.Member.BindingEpoch <= m.BindingEpoch || next.Member.NetworkAccessEpoch <= m.NetworkAccessEpoch {
		t.Fatal("explicit rejoin replaced native identity or revived terminal history")
	}
	var state string
	if f.f.f.db.db.QueryRow(`SELECT state FROM hub_local_domain_members_v1 WHERE member_id=?`, m.MemberID).Scan(&state) != nil || state != wire.LocalDomainMemberLeft {
		t.Fatal("old member did not stay terminal")
	}
	// Reconcile/retry the original operation still returns its original member,
	// and must not create a new current membership or update the old receipt.
	var packet nodewire.Packet
	if json.Unmarshal(original.Packet, &packet) != nil {
		t.Fatal("synthetic packet")
	}
	var receipt []byte
	if f.f.f.db.db.QueryRow(`SELECT response_packet FROM hub_local_domain_node_operations_v1 WHERE operation_id=?`, packet.Route.OperationID).Scan(&receipt) != nil {
		t.Fatal("missing original immutable receipt")
	}
	if got, err := f.f.f.db.ProcessHubLocalDomainNode(original, func(HubLocalDomainNodeOutput) ([]byte, error) { t.Fatal("exact retry reexecuted"); return nil, nil }); err != nil || !bytes.Equal(got, receipt) {
		t.Fatal("original terminal retry changed", err)
	}
	// A fresh signed packet from an old worker is different from exact receipt
	// recovery. Its retained old AttemptID must not even renew the new member.
	readLeases := func() [2]string {
		var leases [2]string
		if err := f.f.f.db.db.QueryRow(`SELECT b.lease_expires_at,a.lease_expires_at FROM session_bindings b JOIN network_access_sessions_v2 a ON a.id=? WHERE b.id=?`, next.Member.NetworkAccessBindingID, next.Member.BindingID).Scan(&leases[0], &leases[1]); err != nil {
			t.Fatal(err)
		}
		return leases
	}
	before := readLeases()
	stale, staleSeal := f.nodeInput(t, wire.OperationLocalDomainNodeJoin, original.Body, f.f.at.Add(2*time.Minute))
	if _, err := f.f.f.db.ProcessHubLocalDomainNode(stale, staleSeal); err != nil {
		t.Fatal("stale worker did not receive a durable no-effect receipt", err)
	}
	var stalePacket nodewire.Packet
	if json.Unmarshal(stale.Packet, &stalePacket) != nil {
		t.Fatal("stale-worker packet fixture")
	}
	var outcome string
	if err := f.f.f.db.db.QueryRow(`SELECT state FROM hub_local_domain_node_operations_v1 WHERE operation_id=?`, stalePacket.Route.OperationID).Scan(&outcome); err != nil || outcome != wire.AppNodeRejectedFenced {
		t.Fatal("old AttemptID became authority over a newer member", err)
	}
	if after := readLeases(); after != before {
		t.Fatal("stale worker extended the later admission's native or Access lease")
	}
}

func TestLocalDomainStoreExplicitRejoinReattestsOriginalEndpointKey(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	first, _ := f.join(t, d, "synthetic-key-rejoin")
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	old := f.keyReady(t, d, first, key)
	if err = f.f.f.db.LeaveEndpointAllGroups(first.Member.EndpointID, first.Member.BindingID, first.Member.BindingEpoch, "synthetic explicit key rejoin"); err != nil {
		t.Fatal(err)
	}
	next, _ := f.join(t, d, first.Member.NativeSessionID)
	current := f.keyReady(t, d, next, key)
	if current.Member.BindingEpoch <= old.Member.BindingEpoch || current.Member.CandidateKeyID != old.Member.CandidateKeyID || current.Member.CandidateFingerprint != old.Member.CandidateFingerprint {
		t.Fatal("explicit rejoin changed original Endpoint key identity")
	}
}

func TestLocalDomainStorePeerGuardChecksCurrentDomainWithoutPair(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	a, _ := f.join(t, d, "synthetic-domain-peer-A")
	b, _ := f.join(t, d, "synthetic-domain-peer-B")
	for _, j := range []wire.LocalDomainNodeJoinResult{a, b} {
		key, e := e2ee.NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		f.keyReady(t, d, j, key)
	}
	tx, e := f.f.f.db.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	pair, e := readSameGroupSealedV1PairTx(tx, d.Policy.GroupID, a.Member.EndpointID, b.Member.EndpointID, time.Now().UTC())
	if e != nil {
		tx.Rollback()
		t.Fatal("delegated peer Guard", e)
	}
	if pair.nativeEvidence != nil || pair.domainCurrent == nil || pair.sender.Grant != nil || pair.sender.LocalDomainGrant == nil {
		tx.Rollback()
		t.Fatal("domain was disguised as old Pair/Owner grant")
	}
	peer, e := sameGroupSealedV1PeerCarrierTx(tx, pair)
	tx.Rollback()
	if e != nil || peer.Receiver.NativeSessionID != "" || peer.LocalDomainCurrent.Receiver.NativeSessionID != b.Member.NativeSessionID {
		t.Fatal("complete current peer evidence", e)
	}
	q, e := wire.NewLocalDomainRevoke(f.f.f.session, f.f.f.scope, d, f.f.f.owner, f.f.at.Add(5*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	in, seal := f.ownerInput(t, q, f.f.at.Add(5*time.Second))
	if _, e = f.f.f.db.ProcessHubLocalDomain(in, seal); e != nil {
		t.Fatal(e)
	}
	tx, e = f.f.f.db.db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = readSameGroupSealedV1PairTx(tx, d.Policy.GroupID, a.Member.EndpointID, b.Member.EndpointID, time.Now().UTC()); e == nil {
		t.Fatal("cached proof bypassed domain revocation")
	}
}

func TestLocalDomainStoreDeliveryFinalAuthorizationFencesRevocation(t *testing.T) {
	for _, revokeBefore := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-final-authorize", false: "after-final-authorize"}[revokeBefore], func(t *testing.T) {
			f := localDomainStore(t)
			d := f.activate(t)
			a, _ := f.join(t, d, "synthetic-domain-delivery-A")
			b, _ := f.join(t, d, "synthetic-domain-delivery-B")
			ka, e := e2ee.NewIdentity()
			if e != nil {
				t.Fatal(e)
			}
			kb, e := e2ee.NewIdentity()
			if e != nil {
				t.Fatal(e)
			}
			f.keyReady(t, d, a, ka)
			f.keyReady(t, d, b, kb)
			credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			msg := "synthetic-domain-send"
			peer, e := f.f.f.db.GetSameGroupSealedV1PeerKey(credential, d.Policy.GroupID, a.Member.EndpointID, b.Member.EndpointID)
			if e != nil {
				t.Fatal(e)
			}
			pair := sameGroupEndpointPair{hubID: d.Policy.HubID, groupID: d.Policy.GroupID, sender: peer.Sender, receiver: peer.Receiver}
			ciphertext, e := e2ee.SealEndpointMessage(ka, kb.Public(), sameGroupSealedV1Context(pair, msg, "SEND", "", ""), []byte("synthetic bounded domain payload"), 1)
			if e != nil {
				t.Fatal(e)
			}
			send := SameGroupSealedV1Send{NodeCredentialDigest: credential, GroupID: d.Policy.GroupID, SourceEndpointID: a.Member.EndpointID, TargetEndpointID: b.Member.EndpointID, MessageID: msg, DataScope: SameGroupSealedV1DataScope, Ciphertext: ciphertext}
			if _, e = f.f.f.db.EnqueueSameGroupSealedV1Send(send); e != nil {
				t.Fatal("domain SEND", e)
			}
			claims, e := f.f.f.db.ClaimSameGroupSealedV1Inbox(credential, RelayClaimInput{RecipientEndpointID: b.Member.EndpointID, ConsumerID: "synthetic-domain-receiver", BindingID: b.Member.BindingID, BindingEpoch: b.Member.BindingEpoch, Limit: 1})
			if e != nil || len(claims) != 1 {
				t.Fatal("domain claim", e, len(claims))
			}
			var authorized *SameGroupSealedV1DeliveryAuthorization
			if !revokeBefore {
				authorized, e = f.f.f.db.AuthorizeClaimedSameGroupSealedV1Delivery(credential, msg, claims[0].AttemptID)
				if e != nil || authorized.LocalDomainCurrent == nil || authorized.LocalDomainCurrent.AttemptID != claims[0].AttemptID || authorized.LocalDomainCurrent.Operation != "native_delivery" {
					t.Fatal("fresh final authorization", e)
				}
			}
			q, e := wire.NewLocalDomainRevoke(f.f.f.session, f.f.f.scope, d, f.f.f.owner, f.f.at.Add(5*time.Second))
			if e != nil {
				t.Fatal(e)
			}
			in, seal := f.ownerInput(t, q, f.f.at.Add(5*time.Second))
			if _, e = f.f.f.db.ProcessHubLocalDomain(in, seal); e != nil {
				t.Fatal(e)
			}
			if _, e = f.f.f.db.AuthorizeClaimedSameGroupSealedV1Delivery(credential, msg, claims[0].AttemptID); !errors.Is(e, ErrSameGroupSealedV1Denied) {
				t.Fatal("revoked queued/claimed attempt got new final authority", e)
			}
			if authorized != nil {
				c := authorized.LocalDomainCurrent
				if wire.ValidateLocalDomainCurrent(*c, d.Policy, authorized.Sender.LocalDomainGrant.Member, authorized.Receiver.LocalDomainGrant.Member, "native_delivery", claims[0].AttemptID, time.Now().UTC()) != nil {
					t.Fatal("prior committed attempt lost its original bounded in-flight observation")
				}
			}
		})
	}
}

func TestLocalDomainStoreColdLeaseRecoveryDoesNotNeedAppOrNewIdentity(t *testing.T) {
	f := localDomainStore(t)
	d := f.activate(t)
	j, original := f.join(t, d, "synthetic-domain-cold-lease")
	if _, e := f.f.f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET state='REVOKED'`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.f.f.db.db.Exec(`UPDATE client_devices_v2 SET state='REVOKED'`); e != nil {
		t.Fatal(e)
	}
	q := original.Body.(wire.LocalDomainNodeJoin)
	q.AttemptID = strings.Repeat("e", 32)
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeJoin, q, f.f.at.Add(20*time.Minute))
	var recovered wire.LocalDomainNodeJoinResult
	f.nodeResult(t, in, seal, &recovered)
	if !reflect.DeepEqual(recovered.Member, j.Member) || recovered.SessionToken != "" || recovered.LeaseExpiresAt == j.LeaseExpiresAt {
		t.Fatal("cold resume renewed identity/token/member instead of the original lease")
	}
	end, e := time.Parse(time.RFC3339Nano, recovered.LeaseExpiresAt)
	if e != nil || !end.After(in.At) || end.After(in.At.Add(5*time.Minute)) {
		t.Fatal("cold resume was not a short lease")
	}
}

func TestLocalDomainStoreAvailableReadCacheExpiresWithoutRepublishing(t *testing.T) {
	f := localDomainStore(t)
	f.report(t, f.f.at)
	var original []byte
	if f.f.f.db.db.QueryRow(`SELECT report FROM hub_local_domain_user_reports_v1`).Scan(&original) != nil {
		t.Fatal("initial report missing")
	}
	var signed e2ee.LocalDomainUserReportProof
	if json.Unmarshal(original, &signed) != nil {
		t.Fatal("initial signed report")
	}
	q := wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: signed.Report.LocalUserScope, LocalUserReport: original}
	in, seal := f.nodeInput(t, wire.OperationLocalDomainNodeAvailable, q, f.f.at.Add(time.Second))
	var out wire.LocalDomainNodeAvailableResult
	f.nodeResult(t, in, seal, &out)
	in.At = f.f.at.Add(6 * time.Minute)
	packet, err := f.f.f.db.ProcessHubLocalDomainNode(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	n := f.f.scope.Node
	binding := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	opened, err := nodewire.OpenResponse(f.f.f.node, n.HubNodeControlPublic, binding, packet)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		OK    bool   `json:"ok"`
		Error string `json:"error_code"`
	}
	if json.Unmarshal(opened.Plaintext, &envelope) != nil || envelope.OK || envelope.Error != "READ_EXPIRED" {
		t.Fatal("old expired report read reexecuted")
	}
	var after []byte
	var count, permanent int
	if f.f.f.db.db.QueryRow(`SELECT report FROM hub_local_domain_user_reports_v1`).Scan(&after) != nil || !bytes.Equal(after, original) {
		t.Fatal("expired exact read replaced current signed report")
	}
	if f.f.f.db.db.QueryRow(`SELECT count(*) FROM hub_local_domain_user_reports_v1`).Scan(&count) != nil || count != 1 || f.f.f.db.db.QueryRow(`SELECT count(*) FROM hub_local_domain_node_operations_v1`).Scan(&permanent) != nil || permanent != 0 {
		t.Fatal("periodic reports appended permanent policy/operation history")
	}
}
