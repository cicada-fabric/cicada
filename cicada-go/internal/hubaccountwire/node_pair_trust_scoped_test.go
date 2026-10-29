package hubaccountwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type scopedPairFixture struct {
	old                            nodePairFixture
	c                              NodePairTrustScopedContext
	a                              NodePairTrustScopedApproval
	g                              e2ee.OwnerAppNodeScopedGrantClaims
	o                              string
	grant, confirm, proof, capsule []byte
}

func newScopedPairFixture(t *testing.T) scopedPairFixture {
	t.Helper()
	f := nodePairCrypto(t)
	old, err := e2ee.VerifyOwnerAppNodeGrant(f.f.owner.Public(), f.grant, f.f.now)
	if err != nil {
		t.Fatal(err)
	}
	s := scopedScopeFixture(t, old.Scope, f.c.Candidate.NodeID)
	g := scopedFixtureValue[e2ee.OwnerAppNodeScopedGrantClaims](t, old, map[string]any{"scope": s, "purpose": e2ee.OwnerAppNodeScopedGrantPurpose})
	grant, err := e2ee.SignOwnerAppNodeScopedGrant(f.f.owner, g)
	if err != nil {
		t.Fatal(err)
	}
	confirm, err := SealAppNodeScopedConfirmation(f.f.device, f.f.hub, g, "23456789ABCD", 1, f.f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := scopedFixtureValue[NodePairTrustScopedContext](t, f.c, map[string]any{"format": NodePairTrustScopedFormat, "scope_version": 2, "authority_node_id": s.AuthorityNodeID})
	d, err := NodePairTrustScopedContextDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	o, err := NodePairTrustScopedOOBCommitment(d, f.s)
	if err != nil {
		t.Fatal(err)
	}
	a := scopedFixtureValue[NodePairTrustScopedApproval](t, f.a, map[string]any{"format": NodePairTrustScopedFormat, "scope": s, "context_digest": d, "oob_commitment": o, "grant_proof_digest": AppNodeScopedProofDigest(grant), "confirmation_packet_digest": AppNodeScopedPacketDigest(confirm)})
	if err := ValidateNodePairTrustScopedInitialAuthorization(c, a, grant, confirm, f.f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	proof, capsule, err := SealNodePairTrustScopedApproval(f.f.owner, c, o, a, f.s, f.x, f.f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return scopedPairFixture{f, c, a, g, o, grant, confirm, proof, capsule}
}

func TestNodePairTrustScopedCodeApprovalAndPrivateACK(t *testing.T) {
	f := newScopedPairFixture(t)
	now := f.old.f.now.Add(time.Second)
	text, err := EncodeNodePairTrustScopedCode(f.c, "23456789ABCD", f.old.s)
	if err != nil || !strings.HasPrefix(text, NodePairTrustScopedCodePrefix) {
		t.Fatal("new local code", err)
	}
	code, err := DecodeNodePairTrustScopedCode(text, now)
	if err != nil || code.AuthorityNodeID != f.c.AuthorityNodeID {
		t.Fatal("code lost exact Node", err)
	}
	o, err := MatchNodePairTrustScopedCode(code, f.c, f.old.f.hub, f.old.nc.Public(), f.c.Origin, f.c.DescriptorDigest, now)
	if err != nil || o != f.o {
		t.Fatal("independent context/secret match", err)
	}
	if _, err := DecodeNodePairTrustCode(text, now); err == nil {
		t.Fatal("legacy decoder accepted scoped code")
	}
	opened, err := OpenNodePairTrustScopedCapsule(f.old.node, f.c, f.o, f.proof, f.capsule, f.old.s, now)
	if err != nil || !reflect.DeepEqual(opened.Approval, f.a) || !bytes.Equal(opened.ACKNonce, f.old.x) {
		t.Fatal("private Node trust", err)
	}
	ack := NodePairTrustScopedACK{Format: NodePairTrustScopedFormat, Context: f.c, OOBCommitment: f.o, PollPacketDigest: strings.Repeat("1", 64), PollReceiptDigest: strings.Repeat("2", 64), OwnerProofDigest: NodePairTrustScopedProofDigest(f.proof), CapsuleDigest: NodePairTrustScopedCapsuleDigest(f.capsule), ACKNonce: f.old.x, IssuedAt: formatUTC(now)}
	if err := VerifyNodePairTrustScopedACK(f.c, f.o, f.proof, f.capsule, ack, now); err != nil {
		t.Fatal(err)
	}
	ack.Context.AuthorityNodeID = "synthetic-other-node"
	if err := VerifyNodePairTrustScopedACK(f.c, f.o, f.proof, f.capsule, ack, now); err == nil {
		t.Fatal("ACK changed Node")
	}
	q := NodePairTrustScopedOwnerPrepare{Format: NodePairTrustScopedFormat, SessionToken: f.old.f.session.Token, Scope: f.g.Scope, Context: f.c, OOBCommitment: f.o, GrantProof: f.grant, ConfirmationPacket: f.confirm, IssuedAt: formatUTC(now)}
	h := NodePairTrustScopedPacket{Operation: OperationOwnerNodePairTrustScopedPrepare, RequestID: strings.Repeat("7", 32), AttemptID: f.c.AttemptID}
	raw, err := SealNodePairTrustScopedRequest(f.old.f.device, f.old.f.hub, h, q, now)
	if err != nil {
		t.Fatal(err)
	}
	var out NodePairTrustScopedOwnerPrepare
	if _, err := OpenNodePairTrustScopedRequest(f.old.f.hubPrivate, f.old.f.hub, raw, h.Operation, &out, now); err != nil || !reflect.DeepEqual(out, q) {
		t.Fatal("Owner request PQ round trip", err)
	}
	var legacy NodePairTrustOwnerPrepare
	if _, err := OpenNodePairTrustRequest(f.old.f.hubPrivate, f.old.f.hub, raw, OperationOwnerNodePairTrustPrepare, &legacy, now); err == nil {
		t.Fatal("legacy packet reader accepted scoped request")
	}
}

func TestNodePairTrustScopedRejectsMixedContextAndBorrowedConfirmation(t *testing.T) {
	f := newScopedPairFixture(t)
	now := f.old.f.now.Add(time.Second)
	for _, c := range []NodePairTrustScopedContext{
		scopedFixtureValue[NodePairTrustScopedContext](t, f.c, map[string]any{"scope_version": 1}),
		scopedFixtureValue[NodePairTrustScopedContext](t, f.c, map[string]any{"authority_node_id": ""}),
		scopedFixtureValue[NodePairTrustScopedContext](t, f.c, map[string]any{"authority_node_id": "synthetic-other-node"}),
	} {
		if ValidateNodePairTrustScopedContext(c, now) == nil {
			t.Fatal("mixed/missing/substituted scope accepted")
		}
		if _, err := OpenNodePairTrustScopedCapsule(f.old.node, c, f.o, f.proof, f.capsule, f.old.s, now); err == nil {
			t.Fatal("capsule accepted substituted context")
		}
	}
	a := f.a
	a.Scope.AuthorityNodeID = "synthetic-other-node"
	if ValidateNodePairTrustScopedApproval(a, f.c, f.o, now) == nil {
		t.Fatal("approval borrowed another Node head")
	}
	if ValidateNodePairTrustScopedInitialAuthorization(f.c, f.a, f.old.grant, f.confirm, now) == nil {
		t.Fatal("legacy grant borrowed scoped confirmation")
	}
	if ValidateNodePairTrustScopedInitialAuthorization(f.c, f.a, f.grant, f.old.confirm, now) == nil {
		t.Fatal("legacy confirmation borrowed scoped grant")
	}
	var proof NodePairTrustScopedOwnerProof
	if json.Unmarshal(f.proof, &proof) != nil {
		t.Fatal("fixture")
	}
	if proof.Claims.Version != 2 {
		t.Fatal("scoped owner proof version")
	}
	d := nodePairScopedClaimsCommitment(proof.Claims)
	if e2ee.VerifyNodePairTrustOwner(f.old.f.owner.Public(), d, proof.Signature) == nil {
		t.Fatal("Owner signature domains overlap")
	}
	wrongSecret := bytes.Repeat([]byte{0x99}, 32)
	if _, err := OpenNodePairTrustScopedCapsule(f.old.node, f.c, f.o, f.proof, f.capsule, wrongSecret, now); err == nil {
		t.Fatal("missing independently transferred secret accepted")
	}
}

func TestNodePairTrustScopedClosedOperationsAndExactRecoveredReceipt(t *testing.T) {
	f := newScopedPairFixture(t)
	now := f.old.f.now.Add(2 * time.Second)
	issued := formatUTC(now)
	commit := NodePairTrustScopedCommit{NodePairTrustScopedFormat, f.c, f.o, issued}
	status := NodePairTrustScopedOwnerStatus{NodePairTrustScopedFormat, f.old.f.session.Token, f.a.Scope, f.c, f.o, issued}
	ack := NodePairTrustScopedACK{NodePairTrustScopedFormat, f.c, f.o, strings.Repeat("1", 64), strings.Repeat("2", 64), NodePairTrustScopedProofDigest(f.proof), NodePairTrustScopedCapsuleDigest(f.capsule), f.old.x, issued}
	items := []struct {
		op    string
		body  any
		actor *e2ee.Identity
	}{
		{OperationNodePairTrustScopedCommit, commit, f.old.node}, {OperationNodePairTrustScopedPoll, commit, f.old.node}, {OperationNodePairTrustScopedCancel, commit, f.old.node}, {OperationNodePairTrustScopedACK, ack, f.old.node},
		{OperationOwnerNodePairTrustScopedLookup, NodePairTrustScopedOwnerLookup{NodePairTrustScopedFormat, status.SessionToken, f.a.Scope, "23456789ABCD", f.a.ContextDigest, issued}, f.old.f.device},
		{OperationOwnerNodePairTrustScopedPrepare, NodePairTrustScopedOwnerPrepare{NodePairTrustScopedFormat, status.SessionToken, f.a.Scope, f.c, f.o, f.grant, f.confirm, issued}, f.old.f.device},
		{OperationOwnerNodePairTrustScopedComplete, NodePairTrustScopedOwnerComplete{NodePairTrustScopedFormat, status.SessionToken, f.a.Scope, f.c, f.o, f.proof, f.capsule, issued}, f.old.f.device},
		{OperationOwnerNodePairTrustScopedStatus, status, f.old.f.device}, {OperationOwnerNodePairTrustScopedCancel, status, f.old.f.device},
	}
	for _, item := range items {
		t.Run(item.op, func(t *testing.T) {
			h := NodePairTrustScopedPacket{Operation: item.op, RequestID: strings.Repeat("7", 32), AttemptID: f.c.AttemptID}
			raw, err := SealNodePairTrustScopedRequest(item.actor, f.old.f.hub, h, item.body, now)
			if err != nil {
				t.Fatal(err)
			}
			out := NewNodePairTrustScopedRequestBody(item.op)
			if _, err := OpenNodePairTrustScopedRequest(f.old.f.hubPrivate, f.old.f.hub, raw, item.op, out, now); err != nil || !reflect.DeepEqual(dereference(out), item.body) {
				t.Fatal("closed request", err)
			}
			if _, err := OpenNodePairTrustScopedRequest(f.old.f.hubPrivate, f.old.f.hub, raw, item.op, NewNodePairTrustScopedRequestBody(item.op), now.Add(2*time.Minute)); err == nil {
				t.Fatal("stale request admitted fresh")
			}
			a, err := AuthenticateNodePairTrustScopedOriginal(f.old.f.hubPrivate, f.old.f.hub, raw, NewNodePairTrustScopedRequestBody(item.op))
			if err != nil || a.PacketDigest != NodePairTrustScopedPacketDigest(raw) {
				t.Fatal("historical authentication", err)
			}
		})
	}
	h := NodePairTrustScopedPacket{Operation: OperationNodePairTrustScopedPoll, RequestID: strings.Repeat("7", 32), AttemptID: f.c.AttemptID}
	raw, err := SealNodePairTrustScopedRequest(f.old.node, f.old.f.hub, h, commit, now)
	if err != nil {
		t.Fatal(err)
	}
	r := NodePairTrustScopedResult{Format: NodePairTrustScopedFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustScopedPacketDigest(raw), State: NodePairTrustScopedOwnerApproved, Context: &f.c, OOBCommitment: f.o, OwnerProof: f.proof, TrustCapsule: f.capsule, ObservedAt: issued}
	receipt, err := SealNodePairTrustScopedResponse(f.old.f.hubPrivate, f.old.f.hub, raw, commit, r)
	if err != nil {
		t.Fatal(err)
	}
	query := NodePairTrustScopedReconcile{NodePairTrustScopedFormat, raw, NodePairTrustScopedPacketDigest(raw), issued}
	rh := h
	rh.Operation = OperationNodePairTrustScopedReconcile
	rh.RequestID = strings.Repeat("8", 32)
	request, err := SealNodePairTrustScopedRequest(f.old.node, f.old.f.hub, rh, query, now)
	if err != nil {
		t.Fatal(err)
	}
	recovered := NodePairTrustScopedResult{Format: NodePairTrustScopedFormat, Operation: rh.Operation, RequestID: rh.RequestID, AttemptID: rh.AttemptID, RequestPacketDigest: NodePairTrustScopedPacketDigest(request), State: NodePairTrustScopedRecovered, ObservedAt: issued, OriginalPacketDigest: query.OriginalPacketDigest, OriginalReceipt: receipt}
	response, err := SealNodePairTrustScopedResponse(f.old.f.hubPrivate, f.old.f.hub, request, query, recovered)
	if err != nil {
		t.Fatal(err)
	}
	got, exact, err := OpenNodePairTrustScopedRecoveredResponse(f.old.node, f.old.f.hub, request, response, query, commit)
	if err != nil || !bytes.Equal(exact, receipt) || !reflect.DeepEqual(got, r) {
		t.Fatal("exact original receipt", err)
	}
}

func TestNodePairTrustScopedOriginalStartAndExistingRemainDistinct(t *testing.T) {
	f := newScopedPairFixture(t)
	now := f.old.f.now
	n := f.c.Candidate
	b := NodePairTrustScopedStart{ScopeVersion: 2, Format: NodePairTrustScopedFormat, Hub: f.c.Hub, Origin: f.c.Origin, DescriptorDigest: f.c.DescriptorDigest, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)), RequestNonce: bytes.Repeat([]byte{0x4c}, 32), HubNodeControlPublic: f.old.nc.Public(), HubNodeControlKeyVersion: 1, IssuedAt: f.c.IssuedAt, ExpiresAt: f.c.ExpiresAt}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: b.Hub.HubID, NodeID: b.NodeID, RequestNonce: b.RequestNonce, CredentialDigest: b.CredentialDigest, NodePublicIdentity: f.old.node.Public(), HubPublicIdentity: f.old.nc.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	b.PairingProof, err = e2ee.Seal(f.old.node, f.old.nc.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	h := NodePairTrustScopedPacket{Operation: OperationNodePairTrustScopedStart, RequestID: strings.Repeat("7", 32), AttemptID: f.c.AttemptID}
	if _, err := SealNodePairTrustScopedRequest(f.old.node, f.old.f.hub, h, b, now); err != nil || ValidateNodePairTrustScopedStartProof(f.old.nc, f.old.node.Public(), b) != nil {
		t.Fatal("actual original Node proof", err)
	}
	b.ScopeVersion = 1
	if _, err := SealNodePairTrustScopedRequest(f.old.node, f.old.f.hub, h, b, now); err == nil {
		t.Fatal("start lost scope version")
	}
	binding := e2ee.OwnerAppNodeBinding{OwnerBindingID: "nbind_SYNTHETIC", OwnerID: f.a.Scope.OwnerID, HubID: f.c.Hub.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: f.a.Scope.DeviceID, OwnerKeyID: f.a.Scope.OwnerPublic.ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: 1, ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: formatUTC(now.Add(-time.Hour)), State: "ACTIVE"}
	c := f.c
	c.Mode = NodePairTrustScopedExisting
	c.Candidate = nil
	c.Binding = &binding
	d, err := NodePairTrustScopedContextDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := NodePairTrustScopedOOBCommitment(d, f.old.s)
	a := f.a
	a.ContextDigest = d
	a.OOBCommitment = o
	a.GrantID = ""
	a.GrantProofDigest = ""
	a.ConfirmationPacketDigest = ""
	if ValidateNodePairTrustScopedInitialAuthorization(c, a, nil, nil, now.Add(time.Second)) != nil {
		t.Fatal("existing binding requires no INITIAL")
	}
	if ValidateNodePairTrustScopedInitialAuthorization(c, a, f.grant, f.confirm, now.Add(time.Second)) == nil {
		t.Fatal("existing binding accepted INITIAL payload")
	}
	q := NodePairTrustScopedExistingStart{Format: NodePairTrustScopedFormat, Context: c, IssuedAt: formatUTC(now)}
	h.Operation = OperationNodePairTrustScopedExisting
	if _, err := SealNodePairTrustScopedRequest(f.old.node, f.old.f.hub, h, q, now); err != nil {
		t.Fatal(err)
	}
	g := f.g
	g.Profile = AppNodeScopedProfileStatus
	g.Purpose = e2ee.OwnerAppNodeScopedStatusGrantPurpose
	g.Candidate = nil
	g.Binding = &binding
	g.PreviousGrantID = strings.Repeat("9", 32)
	g.ConfirmationProvenanceID = strings.Repeat("8", 32)
	g.ConfirmationLimit = 0
	g.AllowedOperations = []string{}
	if ValidateAppNodeScopedGrantClaims(g, f.old.f.hub, now) != nil {
		t.Fatal("scoped READ_EXISTING")
	}
	if _, err := e2ee.SignOwnerAppNodeScopedGrant(f.old.f.owner, g); err != nil {
		t.Fatal(err)
	}
	g.Scope.AuthorityNodeID = "synthetic-other-node"
	if _, err := e2ee.SignOwnerAppNodeScopedGrant(f.old.f.owner, g); err == nil {
		t.Fatal("READ borrowed another Node binding")
	}
}
