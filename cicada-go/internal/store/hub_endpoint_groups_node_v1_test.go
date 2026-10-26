package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type endpointGroupsNodeFixture struct {
	f        *n3StoreFixture
	domain   wire.LocalDomainDescription
	join     wire.LocalDomainNodeJoinResult
	sequence uint64
	at       time.Time
}

func endpointGroupsNodeTestFixture(t *testing.T) *endpointGroupsNodeFixture {
	t.Helper()
	f, d, j := endpointGroupsOwnerTestBusinessFixture(t)
	var sequence uint64
	if err := f.db.db.QueryRow(`SELECT last_sequence FROM node_control_rpc_sequences_v1 WHERE owner_binding_id=? AND node_key_epoch=?`, d.Policy.Node.OwnerBindingID, d.Policy.Node.NodeKeyEpoch).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	// Candidate admission uses wall time. Start protocol operations after all
	// real fixture writes, including under the slower race cryptography.
	return &endpointGroupsNodeFixture{f: f, domain: d, join: j, sequence: sequence, at: time.Now().UTC().Add(10 * time.Second)}
}
func (f *endpointGroupsNodeFixture) input(t *testing.T, op string, body any, at time.Time) (HubEndpointGroupsNodeInput, HubEndpointGroupsNodeSeal) {
	t.Helper()
	f.sequence++
	n := f.domain.Policy.Node
	r := nodewire.Route{Version: 1, Direction: nodewire.DirectionRequest, HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, Sequence: f.sequence, Operation: op, SenderKeyID: n.NodePublic.ID, SenderKeyVersion: n.NodeKeyVersion, ReceiverKeyID: n.HubNodeControlPublic.ID, ReceiverKeyVersion: n.HubNodeControlKeyVersion}
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	r.OperationID = id
	return f.routedInput(t, r, body, at)
}
func (f *endpointGroupsNodeFixture) routedInput(t *testing.T, r nodewire.Route, body any, at time.Time) (HubEndpointGroupsNodeInput, HubEndpointGroupsNodeSeal) {
	t.Helper()
	n := f.domain.Policy.Node
	b := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	plain, err := wire.CanonicalEndpointGroupsNodeRequest(r.Operation, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := nodewire.SealRequest(f.f.node, b.HubKey, b, r, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := nodewire.OpenRequest(f.f.nodeControl, b.NodeKey, b, raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := wire.DecodeEndpointGroupsNodeRequest(r.Operation, opened.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	in := HubEndpointGroupsNodeInput{Hub: f.f.hub, NodeControlPublic: f.f.nodeControl.Public(), CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)), Packet: raw, Body: decoded, At: at}
	return in, func(out HubEndpointGroupsNodeOutput) ([]byte, error) {
		response := map[string]any{"ok": out.ErrorCode == "", "operation_id": r.OperationID, "sequence": r.Sequence}
		if out.ErrorCode != "" {
			response["error_code"] = out.ErrorCode
		} else {
			response["result"] = out.Result
		}
		raw, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}
		rr := r
		rr.Direction = nodewire.DirectionResponse
		rr.SenderKeyID, rr.ReceiverKeyID = rr.ReceiverKeyID, rr.SenderKeyID
		rr.SenderKeyVersion, rr.ReceiverKeyVersion = rr.ReceiverKeyVersion, rr.SenderKeyVersion
		return nodewire.SealResponse(f.f.nodeControl, b.NodeKey, b, rr, raw)
	}
}
func (f *endpointGroupsNodeFixture) open(t *testing.T, in HubEndpointGroupsNodeInput, packet []byte, out any) string {
	t.Helper()
	p, err := wire.DecodeEndpointGroupsNodePacket(in.Packet)
	if err != nil {
		t.Fatal(err)
	}
	n := f.domain.Policy.Node
	b := nodewire.Binding{HubID: n.HubID, NodeID: n.NodeID, BindingID: n.OwnerBindingID, BindingVersion: n.BindingVersion, NodeKeyEpoch: n.NodeKeyEpoch, HubKeyVersion: n.HubNodeControlKeyVersion, NodeKeyVersion: n.NodeKeyVersion, NodeKey: n.NodePublic, HubKey: n.HubNodeControlPublic}
	opened, err := nodewire.OpenResponse(f.f.node, b.HubKey, b, packet)
	if err != nil {
		t.Fatal("synthetic authenticated response", err)
	}
	expectedRoute := p.Route
	expectedRoute.Direction = nodewire.DirectionResponse
	expectedRoute.SenderKeyID, expectedRoute.ReceiverKeyID = expectedRoute.ReceiverKeyID, expectedRoute.SenderKeyID
	expectedRoute.SenderKeyVersion, expectedRoute.ReceiverKeyVersion = expectedRoute.ReceiverKeyVersion, expectedRoute.SenderKeyVersion
	if !reflect.DeepEqual(opened.Route, expectedRoute) {
		t.Fatal("synthetic nested route differs from exact original")
	}
	var response struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error_code"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(opened.Plaintext, &response) != nil {
		t.Fatal("synthetic response decode")
	}
	if response.OK && out != nil {
		if err = json.Unmarshal(response.Result, out); err != nil {
			t.Fatal(err)
		}
	}
	return response.Error
}
func (f *endpointGroupsNodeFixture) result(t *testing.T, in HubEndpointGroupsNodeInput, seal HubEndpointGroupsNodeSeal, out any) []byte {
	t.Helper()
	packet, err := f.f.db.ProcessHubEndpointGroupsNode(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.open(t, in, packet, out); code != "" {
		t.Fatal("synthetic Endpoint Group business refusal", code)
	}
	return packet
}
func (f *endpointGroupsNodeFixture) describe(t *testing.T, at time.Time) wire.EndpointGroupsNodeDescribeResult {
	t.Helper()
	in, seal := f.input(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: f.join.Member.EndpointID, NetworkID: f.domain.Policy.NetworkID}, at)
	var r wire.EndpointGroupsNodeDescribeResult
	f.result(t, in, seal, &r)
	if err := wire.ValidateEndpointGroupsNodeDescribeResult(r, f.f.hub, at); err != nil {
		t.Fatal(err)
	}
	return r
}
func (f *endpointGroupsNodeFixture) add(t *testing.T, group string, at time.Time) wire.OwnerEndpointGroupsReview {
	t.Helper()
	q, in, review := endpointGroupsOwnerTestPrepareBusiness(t, f.f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID, GroupID: group, EndpointID: f.join.Member.EndpointID, Duration: "until_revoked"}, at)
	endpointGroupsOwnerTestApplyBusiness(t, f.f, q, in, review, at.Add(time.Second), nil)
	return review
}
func (f *endpointGroupsNodeFixture) create(t *testing.T, at time.Time) string {
	t.Helper()
	q, in, review := endpointGroupsOwnerTestPrepareBusiness(t, f.f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID, Name: "Synthetic manual Group"}, at)
	endpointGroupsOwnerTestApplyBusiness(t, f.f, q, in, review, at.Add(time.Second), nil)
	return review.Target.GroupID
}
func (f *endpointGroupsNodeFixture) prepare(t *testing.T, review wire.OwnerEndpointGroupsReview, at time.Time) (wire.EndpointGroupsNodeKeyResult, HubEndpointGroupsNodeInput, HubEndpointGroupsNodeSeal) {
	t.Helper()
	var revision uint64
	if err := f.f.db.db.QueryRow(`SELECT revision FROM hub_endpoint_groups_relations_v1 WHERE endpoint_id=? AND group_id=?`, f.join.Member.EndpointID, review.Target.GroupID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	in, seal := f.input(t, wire.OperationEndpointGroupsNodeKeyPrepare, wire.EndpointGroupsNodeKeyPrepare{PolicyID: review.Policy.PolicyID, PolicyEpoch: review.Policy.Epoch, EndpointID: f.join.Member.EndpointID, GroupID: review.Target.GroupID, ExpectedRelationRevision: revision}, at)
	var result wire.EndpointGroupsNodeKeyResult
	f.result(t, in, seal, &result)
	if _, err := wire.ValidateEndpointGroupsNodeKeyResult(result, f.f.hub, f.f.scope.OwnerID, f.f.owner.Public(), at); err != nil {
		t.Fatal(err)
	}
	return result, in, seal
}
func (f *endpointGroupsNodeFixture) completeInput(t *testing.T, review wire.OwnerEndpointGroupsReview, ch wire.EndpointGroupKeyPrepareResult, at time.Time) (HubEndpointGroupsNodeInput, HubEndpointGroupsNodeSeal) {
	t.Helper()
	claims, err := wire.EndpointGroupKeyClaimsForChallenge(ch, *review.Policy)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.SignEndpointGroupKey(f.f.node, *review.Policy, claims)
	if err != nil {
		t.Fatal(err)
	}
	return f.input(t, wire.OperationEndpointGroupsNodeKeyComplete, wire.EndpointGroupsNodeKeyComplete{PolicyID: review.Policy.PolicyID, PolicyEpoch: review.Policy.Epoch, EndpointID: f.join.Member.EndpointID, GroupID: review.Target.GroupID, ExpectedRelationRevision: ch.Expected.RelationRevision, ChallengeID: ch.ChallengeID, NodeProof: proof}, at)
}

func TestEndpointGroupsNodeActualCompleteRollbackExactReceiptAndRestart(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	original := f.describe(t, f.at)
	group := f.create(t, f.at.Add(time.Second))
	review := f.add(t, group, f.at.Add(3*time.Second))
	ready, pi, ps := f.prepare(t, review, f.at.Add(5*time.Second))
	if ready.Challenge == nil || ready.OwnerControl.Mode != "DEFAULT" {
		t.Fatal("pending changed the current Owner control")
	}
	var heads, rights int
	if err := f.f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_heads_v1 WHERE group_id=?),(SELECT count(*) FROM memberships WHERE group_id=? AND principal_id=?)`, group, group, f.join.Member.PrincipalID).Scan(&heads, &rights); err != nil || heads != 0 || rights != 0 {
		t.Fatal("prepare installed business authority", err)
	}
	ci, cs := f.completeInput(t, review, *ready.Challenge, f.at.Add(6*time.Second))
	failure := errors.New("synthetic seal failure")
	if _, err := f.f.db.ProcessHubEndpointGroupsNode(ci, func(HubEndpointGroupsNodeOutput) ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal("seal failure not atomic", err)
	}
	var state string
	if err := f.f.db.db.QueryRow(`SELECT state FROM hub_endpoint_groups_policies_v1 WHERE policy_id=?`, review.Policy.PolicyID).Scan(&state); err != nil || state != "PENDING_KEY" {
		t.Fatal("seal failure committed authority", err)
	}
	var complete wire.EndpointGroupsNodeKeyResult
	packet := f.result(t, ci, cs, &complete)
	if complete.Grant == nil || complete.OwnerControl.Mode != "OWNER" || complete.OwnerControl.Revision != 1 || complete.Grant.Relation.ContributionRevision != 2 {
		t.Fatal("Complete failed to install exactly one authority transition")
	}
	if _, err := wire.ValidateEndpointGroupsNodeKeyResult(complete, f.f.hub, f.f.scope.OwnerID, f.f.owner.Public(), ci.At); err != nil {
		t.Fatal(err)
	}
	after := f.describe(t, f.at.Add(7*time.Second))
	if len(after.Authorities) != 2 || !reflect.DeepEqual(original.Registration, after.Registration) {
		t.Fatal("manual activation replaced original identity or borrowed default")
	}
	var count int
	if err := f.f.db.db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_node_operations_v1 WHERE operation_id=?`, mustEndpointGroupsNodeRoute(t, ci).OperationID).Scan(&count); err != nil || count != 1 {
		t.Fatal(err)
	}
	if err := f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.f.db = reopened
	defer reopened.Close()
	if retry, err := f.f.db.ProcessHubEndpointGroupsNode(ci, cs); err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("restart changed exact mutation receipt", err)
	}
	changed, changedSeal := f.routedInput(t, mustEndpointGroupsNodeRoute(t, ci), ci.Body, ci.At)
	if _, err := f.f.db.ProcessHubEndpointGroupsNode(changed, changedSeal); !errors.Is(err, ErrNodeControlRPCConflict) {
		t.Fatal("re-encryption was treated as exact retry", err)
	}
	pi.At = f.at.Add(6 * time.Minute)
	expired, err := f.f.db.ProcessHubEndpointGroupsNode(pi, ps)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.open(t, pi, expired, nil); code != "READ_EXPIRED" {
		t.Fatal("expired prepare created fresh challenge", code)
	}
}
func mustEndpointGroupsNodeRoute(t *testing.T, in HubEndpointGroupsNodeInput) nodewire.Route {
	t.Helper()
	p, err := wire.DecodeEndpointGroupsNodePacket(in.Packet)
	if err != nil {
		t.Fatal(err)
	}
	return p.Route
}

func TestEndpointGroupsNodeReconcileUnseenMutationNeverRunsAndPermanentFloor(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	d := f.describe(t, f.at)
	q := wire.EndpointGroupsNodeRenew{EndpointID: d.Registration.Registration.EndpointID, RegistrationDigest: d.Registration.RegistrationDigest, ExpectedBindingID: d.Registration.BindingID, ExpectedBindingEpoch: d.Registration.BindingEpoch}
	original, originalSeal := f.input(t, wire.OperationEndpointGroupsNodeRenew, q, f.at.Add(time.Second))
	route := mustEndpointGroupsNodeRoute(t, original)
	route.Operation = wire.OperationEndpointGroupsNodeReconcile
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	route.OperationID = id
	in, seal := f.routedInput(t, route, wire.EndpointGroupsNodeReconcile{OriginalPacket: original.Packet}, f.at.Add(2*time.Second))
	in.Original = &original
	in.OriginalSeal = originalSeal
	var result wire.EndpointGroupsNodeReconciled
	f.result(t, in, seal, &result)
	if result.State != "REJECTED_FENCED" || wire.ValidateEndpointGroupsNodeReconcileTarget(result, original.Packet) != nil {
		t.Fatal("unseen mutation manufactured success")
	}
	if code := f.open(t, original, result.ReceiptPacket, nil); code != "TARGET_NOT_AUTHORIZED" {
		t.Fatal("wrong original fence", code)
	}
	if retry, err := f.f.db.ProcessHubEndpointGroupsNode(original, originalSeal); err != nil || !bytes.Equal(retry, result.ReceiptPacket) {
		t.Fatal("late original executed after fence", err)
	}
	var lease string
	if err := f.f.db.db.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=?`, d.Registration.BindingID).Scan(&lease); err != nil || lease != d.Registration.LeaseExpiresAt {
		t.Fatal("reconcile executed registration renew", err)
	}
	// Retained transport authentication recovers the receipt after Root revoke.
	if _, err := f.f.db.db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED',version=version+1 WHERE owner_id=?`, f.f.scope.OwnerID); err != nil {
		t.Fatal(err)
	}
	original.At = f.at.Add(20 * time.Minute)
	if retry, err := f.f.db.ProcessHubEndpointGroupsNode(original, originalSeal); err != nil || !bytes.Equal(retry, result.ReceiptPacket) {
		t.Fatal("historical exact receipt needed current Root", err)
	}
}

func TestEndpointGroupsNodeColdRenewSurvivesDefaultTerminalAndLastGroupRemove(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	before := f.describe(t, f.at)
	group := f.create(t, f.at.Add(time.Second))
	review := f.add(t, group, f.at.Add(3*time.Second))
	ready, _, _ := f.prepare(t, review, f.at.Add(5*time.Second))
	ci, cs := f.completeInput(t, review, *ready.Challenge, f.at.Add(6*time.Second))
	var key wire.EndpointGroupsNodeKeyResult
	f.result(t, ci, cs, &key)
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	p, err := readLocalDomain(tx, f.domain.Policy.PolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if err = localDomainTerminateTx(tx, p, wire.LocalDomainRevoked, "SYNTHETIC_OWNER_REVOKE", f.at.Add(8*time.Second)); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	live := f.describe(t, f.at.Add(9*time.Second))
	if len(live.Authorities) != 1 || live.Authorities[0].Relation.GroupID != group {
		t.Fatal("default terminal erased independent manual authority")
	}
	var credential string
	if err = f.f.db.db.QueryRow(`SELECT credential_hash FROM session_bindings WHERE id=?`, before.Registration.BindingID).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	at := f.at.Add(7 * time.Minute)
	q := wire.EndpointGroupsNodeRenew{EndpointID: before.Registration.Registration.EndpointID, RegistrationDigest: before.Registration.RegistrationDigest, ExpectedBindingID: before.Registration.BindingID, ExpectedBindingEpoch: before.Registration.BindingEpoch}
	in, seal := f.input(t, wire.OperationEndpointGroupsNodeRenew, q, at)
	var renewed wire.EndpointGroupsNodeRenewResult
	receipt := f.result(t, in, seal, &renewed)
	oldAnchor, newAnchor := before.Registration, renewed.Registration
	oldAnchor.LeaseExpiresAt = newAnchor.LeaseExpiresAt
	if !reflect.DeepEqual(oldAnchor, newAnchor) || newAnchor.LeaseExpiresAt != appNodeStamp(at.Add(5*time.Minute)) {
		t.Fatal("cold renew changed identity or did not renew liveness")
	}
	var retained string
	if err = f.f.db.db.QueryRow(`SELECT credential_hash FROM session_bindings WHERE id=? AND epoch=?`, newAnchor.BindingID, newAnchor.BindingEpoch).Scan(&retained); err != nil || retained != credential {
		t.Fatal("cold renew rotated original credential", err)
	}
	if retry, err := f.f.db.ProcessHubEndpointGroupsNode(in, seal); err != nil || !bytes.Equal(receipt, retry) {
		t.Fatal("renew lacked permanent exact receipt", err)
	}
	// Owner review remains fresh at this synthetic time while App is still live.
	rq, rp, rr := endpointGroupsOwnerTestPrepareBusiness(t, f.f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, NodeID: f.domain.Policy.Node.NodeID, NetworkID: f.domain.Policy.NetworkID, GroupID: group, EndpointID: f.join.Member.EndpointID}, at.Add(time.Second))
	head := key.OwnerControl
	endpointGroupsOwnerTestApplyBusiness(t, f.f, rq, rp, rr, at.Add(2*time.Second), &head)
	after := f.describe(t, at.Add(3*time.Second))
	if len(after.Authorities) != 0 || after.Registration.State != "REGISTERED" {
		t.Fatal("last Group removal destroyed registration or restored default")
	}
	for _, card := range after.Relations {
		if card.GroupID == group && (card.OwnerControl.Mode != "OWNER" || card.OwnerControl.DenyReason != "REMOVED") {
			t.Fatal("remove lost permanent Owner control")
		}
	}
}

func TestEndpointGroupsNodeCompletionRechecksLiveCASRootAndChallenge(t *testing.T) {
	for _, kind := range []string{"group_changed", "Root_revoked", "challenge_expired"} {
		t.Run(kind, func(t *testing.T) {
			f := endpointGroupsNodeTestFixture(t)
			f.describe(t, f.at)
			group := f.create(t, f.at.Add(time.Second))
			review := f.add(t, group, f.at.Add(3*time.Second))
			ready, _, _ := f.prepare(t, review, f.at.Add(5*time.Second))
			in, seal := f.completeInput(t, review, *ready.Challenge, f.at.Add(6*time.Second))
			var err error
			switch kind {
			case "group_changed":
				_, err = f.f.db.db.Exec(`UPDATE groups SET version=version+1,revision=revision+1 WHERE id=?`, group)
			case "Root_revoked":
				_, err = f.f.db.db.Exec(`UPDATE owner_approval_keys_v2 SET state='REVOKED',version=version+1 WHERE owner_id=?`, f.f.scope.OwnerID)
			case "challenge_expired":
				in.At, _ = time.Parse(time.RFC3339Nano, ready.Challenge.ExpiresAt)
			}
			if err != nil {
				t.Fatal(err)
			}
			packet, err := f.f.db.ProcessHubEndpointGroupsNode(in, seal)
			if err != nil {
				t.Fatal(err)
			}
			if code := f.open(t, in, packet, nil); code != "TARGET_NOT_AUTHORIZED" {
				t.Fatal("stale authority activated", code)
			}
			if retry, err := f.f.db.ProcessHubEndpointGroupsNode(in, seal); err != nil || !bytes.Equal(retry, packet) {
				t.Fatal("negative mutation outcome was not exact", err)
			}
			var state string
			var heads int
			if err := f.f.db.db.QueryRow(`SELECT state,(SELECT count(*) FROM hub_endpoint_groups_heads_v1 WHERE group_id=?) FROM hub_endpoint_groups_policies_v1 WHERE policy_id=?`, group, review.Policy.PolicyID).Scan(&state, &heads); err != nil || state != "PENDING_KEY" || heads != 0 {
				t.Fatal("failed Complete modified authority", err)
			}
		})
	}
}

func TestEndpointGroupsNodeConcurrentExactCompleteHasOneTransition(t *testing.T) {
	f := endpointGroupsNodeTestFixture(t)
	f.describe(t, f.at)
	group := f.create(t, f.at.Add(time.Second))
	review := f.add(t, group, f.at.Add(3*time.Second))
	ready, _, _ := f.prepare(t, review, f.at.Add(5*time.Second))
	in, seal := f.completeInput(t, review, *ready.Challenge, f.at.Add(6*time.Second))
	other, err := New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	type answer struct {
		packet []byte
		err    error
	}
	out := make(chan answer, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, db := range []*Store{f.f.db, other} {
		wg.Add(1)
		go func(s *Store) {
			defer wg.Done()
			<-start
			packet, err := s.ProcessHubEndpointGroupsNode(in, seal)
			out <- answer{packet, err}
		}(db)
	}
	close(start)
	wg.Wait()
	close(out)
	var packet []byte
	for got := range out {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if packet == nil {
			packet = got.packet
		} else if !bytes.Equal(packet, got.packet) {
			t.Fatal("concurrent exact mutation returned different receipts")
		}
	}
	var result wire.EndpointGroupsNodeKeyResult
	if code := f.open(t, in, packet, &result); code != "" {
		t.Fatal(code)
	}
	var contribution, head, aggregate uint64
	if err := f.f.db.db.QueryRow(`SELECT p.contribution_revision,h.revision,r.revision FROM hub_endpoint_groups_policies_v1 p JOIN hub_endpoint_groups_heads_v1 h ON h.native_digest=p.native_digest AND h.group_id=p.group_id JOIN hub_endpoint_groups_relations_v1 r ON r.endpoint_id=p.endpoint_id AND r.group_id=p.group_id WHERE p.policy_id=?`, review.Policy.PolicyID).Scan(&contribution, &head, &aggregate); err != nil || contribution != 2 || head != 1 || aggregate != ready.Challenge.Expected.RelationRevision+1 {
		t.Fatal("concurrent claim advanced more than once", err)
	}
}
