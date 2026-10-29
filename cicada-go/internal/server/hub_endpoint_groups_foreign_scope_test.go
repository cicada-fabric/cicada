package server

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Extend the TCP fixture using the existing Store pairing approval API (the
// same path as node_control_recovery_test), not a second N3 INITIAL grant. The
// original enrolled Owner/device authorizes the exact PQ-proven candidate; no
// authority rows are installed. This does not claim a second N3 enrollment flow.
func endpointGroupsSecondApprovedNode(t *testing.T, a *nativePairTCPActor) *nativePairTCPActor {
	t.Helper()
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	token, digest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	const id = "synthetic-scope-node-b"
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: a.f.hub.HubID, NodeID: id, RequestNonce: nonce, CredentialDigest: digest, NodePublicIdentity: node.Public(), HubPublicIdentity: a.nodeHub.PublicIdentity, HubKeyVersion: a.nodeHub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, a.nodeHub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := nodeControlPairingInput{NodeID: id, NodeName: "Synthetic scope Node B", CredentialDigest: digest, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: a.f.hub.HubID, HubPublicIdentity: a.nodeHub.PublicIdentity, HubKeyVersion: a.nodeHub.KeyVersion, HubFingerprint: a.nodeHub.Fingerprint}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := n3HTTP(t, a.f, http.MethodPost, "/v2/nodes/device-code", "", raw)
	var code nodebinding.DeviceCode
	if status != http.StatusCreated || json.Unmarshal(raw, &code) != nil {
		t.Fatal("second real Node possession proof rejected")
	}
	codeDigest, err := wire.AppNodeCodeDigest(a.f.hub.HubID, code.UserCode)
	if err != nil {
		t.Fatal("second Node displayed code normalization failed", err)
	}
	candidate, err := a.f.db.PreviewNodeControlKeyRequest(a.scope.Actor.OwnerID, a.session.DeviceID, codeDigest)
	if err != nil || candidate == nil || candidate.NodeID != id || candidate.NodeKeyID != node.Public().ID {
		t.Fatal("second Node exact approved-device preview failed", err)
	}
	approved, err := a.f.db.ConfirmNodeControlKeyRequest(a.scope.Actor.OwnerID, a.session.DeviceID, codeDigest, candidate.Version, candidate.CandidateDigest, a.nodeHub.KeyID, a.nodeHub.Fingerprint)
	if err != nil || approved == nil || approved.NodeID != id || approved.ApprovedCandidateDigest != candidate.CandidateDigest || approved.ApprovedRequestID != candidate.RequestID || approved.OwnerID != a.scope.Actor.OwnerID || approved.ClientDeviceID != a.session.DeviceID || approved.State != "ACTIVE" {
		t.Fatal("second Node exact Owner/device approval failed", err)
	}
	// Copy the actual returned binding using the production public DTO mapping;
	// the Actor remains the original valid App, without adopting a new N3 head.
	v := *approved
	binding := e2ee.OwnerAppNodeBinding{OwnerBindingID: v.OwnerBindingID, OwnerID: v.OwnerID, HubID: v.HubID, NodeID: v.NodeID, NodeName: v.NodeName, ClientDeviceID: v.ClientDeviceID, OwnerKeyID: v.OwnerKeyID, CredentialVersion: v.NodeCredentialVersion, BindingVersion: v.BindingVersion, NodePublic: v.NodePublicIdentity, NodeKeyFingerprint: v.NodeKeyFingerprint, NodeKeyVersion: v.NodeKeyVersion, NodeKeyEpoch: v.NodeKeyEpoch, HubNodeControlPublic: v.HubPublicIdentity, HubNodeControlFingerprint: v.HubKeyFingerprint, HubNodeControlKeyVersion: v.HubKeyVersion, ApprovedRequestID: v.ApprovedRequestID, ApprovedRequestVersion: uint64(v.ApprovedRequestVersion), ApprovedCandidateDigest: v.ApprovedCandidateDigest, ApprovedAt: v.ApprovedAt, State: v.State}
	return &nativePairTCPActor{f: a.f, owner: a.owner, device: a.device, node: node, nodeToken: token, nodeHub: a.nodeHub, scope: e2ee.OwnerNativePairScope{Actor: a.scope.Actor, Node: binding}, session: a.session}
}

func endpointGroupsSecondDomain(t *testing.T, a *nativePairTCPActor) *endpointGroupsHTTPFixture {
	t.Helper()
	f := &endpointGroupsHTTPFixture{a: a}
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
	localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeAvailable, f.sequence, wire.LocalDomainNodeAvailable{ContractRevision: wire.LocalDomainContractRevision, LocalUserScope: report.LocalUserScope, LocalUserReport: proof}, &wire.LocalDomainNodeAvailableResult{})
	prepare, err := wire.NewLocalDomainPrepare(a.session, a.scope.Actor, e2ee.LocalDomainTarget{Node: n, NewNetworkName: "Synthetic independent scope Network B", GroupName: "Synthetic independent default B"}, a.owner, time.Now().UTC())
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
	if activated.Description == nil || activated.Description.State != wire.LocalDomainActive {
		t.Fatal("second real Network did not activate")
	}
	f.domain = *activated.Description
	selection, err := wire.LocalDomainSelectionForPolicy(f.domain.Policy)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	f.sequence++
	localDomainNodeHTTP(t, a, wire.OperationLocalDomainNodeJoin, f.sequence, wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, LocalUserScope: report.LocalUserScope, AttemptID: attempt, Runtime: "codex", NativeSessionID: "synthetic-independent-scope-B", Workspace: "/synthetic/independent/B", EndpointName: "Synthetic independent B"}, &f.joins[0])
	m := f.joins[0].Member
	f.keys[0], err = e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := f.keys[0].SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	a.pairHTTP(t, http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+f.joins[0].SessionToken, f.domain.Policy.GroupID, map[string]any{"attestation": json.RawMessage(attestation)}, http.StatusOK)
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
	if _, err := wire.VerifyLocalDomainEndpointKeyGrant(ready.Grant, a.f.hub, a.scope.Actor.OwnerID, a.owner.Public(), time.Now().UTC()); err != nil {
		t.Fatal("second original key chain invalid", err)
	}
	return f
}

// Existing interfaces carry policy references in an authenticated Node request;
// the Hub resolves their full enrolled Owner/Node chain. Both source domains
// are first verified valid. Negatives use new correctly signed envelopes,
// never damaged signatures, unknown IDs or a 404 as the authorization oracle.
func TestEndpointGroupsHTTPValidSourcesCannotBorrowAnotherCallScope(t *testing.T) {
	a := endpointGroupsRealHTTP(t)
	b := endpointGroupsSecondDomain(t, endpointGroupsSecondApprovedNode(t, a.a))
	create := func(f *endpointGroupsHTTPFixture, name string) (string, wire.EndpointGroupsNodeKeyResult) {
		t.Helper()
		q, original, _, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: name})
		_, _, _, result := f.apply(t, q, original, review, nil)
		group := result.Operation.Target.GroupID
		return group, f.activate(t, group, 0)
	}
	groupA, activeA := create(a, "Synthetic scope Group A")
	groupOther, _ := create(a, "Synthetic other valid Group A")
	groupB, activeB := create(b, "Synthetic scope Group B")
	if a.domain.Policy.NetworkID == b.domain.Policy.NetworkID || a.a.scope.Node.NodeID == b.a.scope.Node.NodeID || groupA == groupOther {
		t.Fatal("positive domains did not differ")
	}
	positive := func(f *endpointGroupsHTTPFixture, group string, active wire.EndpointGroupsNodeKeyResult) wire.EndpointGroupsNodeKeyPrepare {
		t.Helper()
		var described wire.EndpointGroupsNodeDescribeResult
		f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: active.Registration.Registration.EndpointID, NetworkID: active.Registration.NetworkID}, &described)
		if wire.ValidateEndpointGroupsNodeDescribeResult(described, f.a.f.hub, time.Now().UTC()) != nil {
			t.Fatal("correct-scope Describe did not validate")
		}
		var revision uint64
		for _, card := range described.Relations {
			if card.GroupID == group {
				revision = card.RelationRevision
			}
		}
		if revision == 0 {
			t.Fatal("positive original Group absent")
		}
		q := wire.EndpointGroupsNodeKeyPrepare{PolicyID: active.OwnerControl.PolicyID, PolicyEpoch: active.OwnerControl.PolicyEpoch, EndpointID: active.Registration.Registration.EndpointID, GroupID: group, ExpectedRelationRevision: revision}
		var proof wire.EndpointGroupsNodeKeyResult
		f.nodeHTTP(t, wire.OperationEndpointGroupsNodeKeyPrepare, q, &proof)
		if _, err := wire.ValidateEndpointGroupsNodeKeyResult(proof, f.a.f.hub, f.a.scope.Actor.OwnerID, f.a.owner.Public(), time.Now().UTC()); err != nil || proof.Grant == nil || proof.Challenge != nil {
			t.Fatal("original domain is not a valid signed ACTIVE source", err)
		}
		return q
	}
	qa, qb := positive(a, groupA, activeA), positive(b, groupB, activeB)
	db, err := sql.Open("sqlite", a.a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	snapshot := func() []byte {
		t.Helper()
		var result []any
		for _, table := range []string{"hub_endpoint_groups_registrations_v1", "hub_endpoint_groups_heads_v1", "hub_endpoint_groups_relations_v1", "hub_endpoint_groups_policies_v1", "hub_endpoint_groups_key_challenges_v1", "fabric_endpoints", "memberships", "endpoint_group_memberships", "endpoint_key_candidates_v2"} {
			rows, err := db.Query("SELECT * FROM " + table + " ORDER BY rowid")
			if err != nil {
				t.Fatal(err)
			}
			columns, err := rows.Columns()
			if err != nil {
				t.Fatal(err)
			}
			var values [][]any
			for rows.Next() {
				row, pointers := make([]any, len(columns)), make([]any, len(columns))
				for i := range row {
					pointers[i] = &row[i]
				}
				if err := rows.Scan(pointers...); err != nil {
					t.Fatal(err)
				}
				values = append(values, row)
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			result = append(result, values)
		}
		out, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, scope := range []string{"Node", "Network", "Group"} {
		t.Run(scope, func(t *testing.T) {
			qa, qb = positive(a, groupA, activeA), positive(b, groupB, activeB)
			operation, body := wire.OperationEndpointGroupsNodeKeyPrepare, any(qb)
			if scope == "Network" {
				operation, body = wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: qa.EndpointID, NetworkID: b.domain.Policy.NetworkID}
			}
			if scope == "Group" {
				changed := qa
				changed.GroupID = groupOther
				body = changed
			}
			before := snapshot()
			a.sequence++
			// The original valid B policy is unchanged in the Node case; A is a
			// different approved caller. Group changes only the call's Group.
			packet := a.a.nodeSeal(t, operation, a.sequence, body)
			status, receipt := n3HTTP(t, a.a.f, http.MethodPost, "/v2/node/control/rpc", a.a.nodeToken, packet)
			if status != http.StatusOK {
				t.Fatal("negative did not reach an authenticated business refusal", status)
			}
			opened, err := nodewire.OpenResponse(a.a.node, a.a.nodeBinding().HubKey, a.a.nodeBinding(), receipt)
			request, decodeErr := wire.DecodeEndpointGroupsNodePacket(packet)
			want := request.Route
			want.Direction = nodewire.DirectionResponse
			want.SenderKeyID, want.ReceiverKeyID = want.ReceiverKeyID, want.SenderKeyID
			want.SenderKeyVersion, want.ReceiverKeyVersion = want.ReceiverKeyVersion, want.SenderKeyVersion
			var refused nativePairNodeReply
			if err != nil || decodeErr != nil || opened.Route != want || json.Unmarshal(opened.Plaintext, &refused) != nil || refused.OK || refused.ErrorCode != "TARGET_NOT_AUTHORIZED" || refused.OperationID != want.OperationID || refused.Sequence != want.Sequence || len(refused.Result) != 0 {
				t.Fatal("valid foreign scope was not refused by its real Guard", err)
			}
			clear(opened.Plaintext)
			if !bytes.Equal(before, snapshot()) {
				t.Fatal("foreign-scope rejection changed authority, identity or keys")
			}
			status, retry := n3HTTP(t, a.a.f, http.MethodPost, "/v2/node/control/rpc", a.a.nodeToken, packet)
			if status != http.StatusOK || !bytes.Equal(retry, receipt) || !bytes.Equal(before, snapshot()) {
				t.Fatal("exact refused request gained an effect on replay")
			}
			positive(a, groupA, activeA)
			positive(b, groupB, activeB)
			t.Logf("CLOSED_VALID_FOREIGN_SCOPE scope=%s original_domains_authenticated=true correct_caller_signature=true typed_refusal=TARGET_NOT_AUTHORIZED business_effects=0 identity_keys_grants_heads_preserved=true exact_refusal_replay=true", scope)
		})
	}
}
