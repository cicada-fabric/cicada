package hubaccountwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type nodePairFixture struct {
	f                                    appNodeCryptoFixture
	node, nc                             *e2ee.Identity
	c                                    NodePairTrustContext
	a                                    NodePairTrustApproval
	o                                    string
	s, x, grant, confirm, proof, capsule []byte
}

func nodePairCrypto(t *testing.T) nodePairFixture {
	t.Helper()
	f := appNodeCrypto(t)
	_, _, ch := appNodePreparedCrypto(t, f)
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	nc, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := *ch.Claims.Candidate
	n.NodePublic = node.Public()
	n.NodeKeyFingerprint = nodewire.IdentityFingerprint(node.Public())
	n.HubNodeControlPublic = nc.Public()
	n.HubNodeControlFingerprint = nodewire.IdentityFingerprint(nc.Public())
	n.HubNodeControlKeyVersion = 1
	n.CodeDigest, _ = AppNodeCodeDigest(f.hub.HubID, "2345-6789-ABCD")
	g := ch.Claims
	g.Candidate = &n
	grant, err := e2ee.SignOwnerAppNodeGrant(f.owner, g)
	if err != nil {
		t.Fatal(err)
	}
	confirm, err := SealAppNodeConfirmation(f.device, f.hub, g, "2345-6789-ABCD", 1, f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := NodePairTrustContext{NodePairTrustFormat, strings.Repeat("2a", 16), f.hub, g.Scope.Origin, strings.Repeat("3b", 32), strings.Repeat("4c", 32), NodePairTrustInitial, &n, nil, formatUTC(f.now), n.ExpiresAt}
	d, err := NodePairTrustContextDigest(c)
	if err != nil {
		t.Fatal("context", err)
	}
	s, x := bytes.Repeat([]byte{0x53}, 32), bytes.Repeat([]byte{0x58}, 32)
	o, err := NodePairTrustOOBCommitment(d, s)
	if err != nil {
		t.Fatal(err)
	}
	end := f.now.Add(2 * time.Minute)
	for _, text := range []string{c.ExpiresAt, g.ProofExpiresAt, g.Scope.AccountSessionExpiresAt} {
		limit, _ := parseCanonicalUTC(text)
		if limit.Before(end) {
			end = limit
		}
	}
	a := NodePairTrustApproval{NodePairTrustFormat, d, o, g.Scope, g.GrantID, AppNodeProofDigest(grant), AppNodePacketDigest(confirm), strings.Repeat("5d", 16), NodePairTrustPacketDigest([]byte("CICADA SYNTHETIC OWNER PREPARE PACKET")), strings.Repeat("6e", 32), formatUTC(f.now.Add(time.Second)), formatUTC(end)}
	if ValidateNodePairTrustInitialAuthorization(c, a, grant, confirm, f.now.Add(time.Second)) != nil {
		t.Fatal("original INITIAL authorization differs")
	}
	proof, capsule, err := SealNodePairTrustApproval(f.owner, c, o, a, s, x, f.now.Add(time.Second))
	if err != nil {
		t.Fatal("approval", err)
	}
	return nodePairFixture{f, node, nc, c, a, o, s, x, grant, confirm, proof, capsule}
}
func nodePairClone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func nodePairHeaderFor(f nodePairFixture, operation string, actor *e2ee.Identity) NodePairTrustPacket {
	return NodePairTrustPacket{Operation: operation, RequestID: strings.Repeat("71", 16), AttemptID: f.c.AttemptID, SenderPublic: actor.Public()}
}
func nodePairACK(f nodePairFixture) NodePairTrustACK {
	return NodePairTrustACK{NodePairTrustFormat, f.c, f.o, NodePairTrustPacketDigest([]byte("CICADA SYNTHETIC ORIGINAL POLL")), NodePairTrustPacketDigest([]byte("CICADA SYNTHETIC ORIGINAL POLL RECEIPT")), NodePairTrustProofDigest(f.proof), NodePairTrustCapsuleDigest(f.capsule), f.x, formatUTC(f.f.now.Add(2 * time.Second))}
}

func TestNodePairTrustIndependentCodeCapsuleACKAndOriginalPacket(t *testing.T) {
	f := nodePairCrypto(t)
	now := f.f.now.Add(2 * time.Second)
	code, err := EncodeNodePairTrustCode(f.c, "2345-6789-ABCD", f.s)
	if err != nil || len(code) > 1024 {
		t.Fatal("one local code", err)
	}
	decoded, err := DecodeNodePairTrustCode(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(decoded.OOBSecret)
	o, err := MatchNodePairTrustCode(decoded, f.c, f.f.hub, f.nc.Public(), f.c.Origin, f.c.DescriptorDigest, now)
	if err != nil || o != f.o {
		t.Fatal("independent App match", err)
	}
	opened, err := OpenNodePairTrustCapsule(f.node, f.c, f.o, f.proof, f.capsule, f.s, now)
	if err != nil || !bytes.Equal(opened.OOBSecret, f.s) || !bytes.Equal(opened.ACKNonce, f.x) {
		t.Fatal("private capsule", err)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	ack := nodePairACK(f)
	if VerifyNodePairTrustACK(f.c, f.o, f.proof, f.capsule, ack, now) != nil {
		t.Fatal("private ACK")
	}
	raw, err := SealNodePairTrustRequest(f.node, f.f.hub, nodePairHeaderFor(f, OperationNodePairTrustACK, f.node), ack, now)
	if err != nil {
		t.Fatal(err)
	}
	var got NodePairTrustACK
	if _, err = OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, OperationNodePairTrustACK, &got, now); err != nil || !reflect.DeepEqual(got, ack) {
		t.Fatal("Node signed PQ ACK", err)
	}
	if VerifyNodePairTrustACK(f.c, f.o, f.proof, f.capsule, got, now) != nil {
		t.Fatal("opened ACK")
	}
	if bytes.Contains(f.proof, []byte(`"oob_secret"`)) || bytes.Contains(f.proof, []byte(base64.RawURLEncoding.EncodeToString(f.s))) {
		t.Fatal("S entered public proof")
	}
	for _, secret := range []any{decoded, opened, ack} {
		if !strings.Contains(fmt.Sprintf("%v %#v", secret, secret), "redacted") {
			t.Fatal("secret diagnostic escaped redaction")
		}
	}
	if InstallationPublicAvailable || NodePairTrustPublicAvailable || InstallationContractRevision != "installation-registration-v1.1" {
		t.Fatal("pure checkpoint changed availability or C0")
	}
}

func TestNodePairTrustHubSelfSignedOwnerCannotEstablishTrust(t *testing.T) {
	f := nodePairCrypto(t)
	attacker, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := f.a
	a.Scope.OwnerPublic = attacker.Public()
	wrong := bytes.Repeat([]byte{0x41}, 32)
	plain, _ := json.Marshal(NodePairTrustCapsule{NodePairTrustFormat, a, attacker.Public(), wrong, f.x})
	defer clear(plain)
	aad, _ := nodePairCapsuleAAD(a)
	capsule, err := e2ee.Seal(attacker, f.node.Public(), plain, aad, 1)
	if err != nil {
		t.Fatal(err)
	}
	ack, _ := NodePairTrustACKCommitment(a, f.x)
	claims := NodePairTrustOwnerClaims{1, NodePairTrustOwnerPurpose, a, NodePairTrustCapsuleDigest(capsule), ack}
	sig, err := e2ee.SignNodePairTrustOwner(attacker, nodePairClaimsCommitment(claims))
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(NodePairTrustOwnerProof{claims, sig})
	if _, err = VerifyNodePairTrustOwnerProof(attacker.Public(), f.c, f.o, proof, f.f.now.Add(2*time.Second)); err != nil {
		t.Fatal("attack must be cryptographically self-consistent", err)
	}
	if _, err = OpenNodePairTrustCapsule(f.node, f.c, f.o, proof, capsule, f.s, f.f.now.Add(2*time.Second)); err == nil {
		t.Fatal("Hub certified its invented Owner without S")
	}
}

func TestNodePairTrustMutationsAndFreshTrustDeadlineReject(t *testing.T) {
	f := nodePairCrypto(t)
	now := f.f.now.Add(2 * time.Second)
	for _, kind := range []string{"attempt", "descriptor", "node", "HubNC", "origin", "mode", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			c := nodePairClone(f.c)
			switch kind {
			case "attempt":
				c.AttemptID = strings.Repeat("9a", 16)
			case "descriptor":
				c.DescriptorDigest = strings.Repeat("9a", 32)
			case "node":
				c.Candidate.NodeID += "-other"
			case "HubNC":
				c.Candidate.HubNodeControlPublic = f.node.Public()
			case "origin":
				c.Origin = "https://other.synthetic.invalid"
			case "mode":
				c.Mode = NodePairTrustExisting
			case "expiry":
				c.ExpiresAt = formatUTC(f.f.now.Add(time.Second))
			}
			if _, err := OpenNodePairTrustCapsule(f.node, c, f.o, f.proof, f.capsule, f.s, now); err == nil {
				t.Fatal("changed retained context accepted")
			}
		})
	}
	for _, at := range []time.Time{{}, f.f.now.Add(-time.Minute), mustNodePairTime(f.a.AcceptBefore)} {
		if _, err := OpenNodePairTrustCapsule(f.node, f.c, f.o, f.proof, f.capsule, f.s, at); err == nil {
			t.Fatal("fresh trust accepted historical/invalid time")
		}
	}
	ack := nodePairACK(f)
	ack.ACKNonce = []byte(f.a.ContextDigest[:32])
	if VerifyNodePairTrustACK(f.c, f.o, f.proof, f.capsule, ack, now) == nil {
		t.Fatal("public digest replaced capsule-only ACK")
	}
	code, _ := EncodeNodePairTrustCode(f.c, "2345-6789-ABCD", f.s)
	for _, bad := range []string{strings.ToUpper(code), code + "=", code + "\n", strings.Repeat("x", 1025), strings.Replace(code, NodePairTrustCodePrefix, "cicada-ir1.", 1)} {
		if _, err := DecodeNodePairTrustCode(bad, now); err == nil {
			t.Fatal("alternate/foreign code accepted")
		}
	}
	wrongHub := f.f.hub
	wrongHub.HubID += "-other"
	ticket, _ := DecodeNodePairTrustCode(code, now)
	defer clear(ticket.OOBSecret)
	if _, err := MatchNodePairTrustCode(ticket, f.c, wrongHub, f.nc.Public(), f.c.Origin, f.c.DescriptorDigest, now); err == nil {
		t.Fatal("App changed its existing Hub pin")
	}
}
func mustNodePairTime(s string) time.Time { at, _ := parseCanonicalUTC(s); return at }

func TestNodePairTrustClosedPacketsResponsesAndHistoricalOriginal(t *testing.T) {
	f := nodePairCrypto(t)
	now := f.f.now.Add(2 * time.Second)
	issued := formatUTC(now)
	commit := NodePairTrustCommit{NodePairTrustFormat, f.c, f.o, issued}
	ownerStatus := NodePairTrustOwnerStatus{NodePairTrustFormat, bytes.Repeat([]byte{7}, 32), f.a.Scope, f.c, f.o, issued}
	items := []struct {
		op    string
		body  any
		actor *e2ee.Identity
	}{
		{OperationNodePairTrustCommit, commit, f.node}, {OperationNodePairTrustPoll, commit, f.node}, {OperationNodePairTrustCancel, commit, f.node}, {OperationNodePairTrustACK, nodePairACK(f), f.node},
		{OperationOwnerNodePairTrustPrepare, NodePairTrustOwnerPrepare{NodePairTrustFormat, ownerStatus.SessionToken, f.a.Scope, f.c, f.o, f.grant, f.confirm, issued}, f.f.device},
		{OperationOwnerNodePairTrustComplete, NodePairTrustOwnerComplete{NodePairTrustFormat, ownerStatus.SessionToken, f.a.Scope, f.c, f.o, f.proof, f.capsule, issued}, f.f.device},
		{OperationOwnerNodePairTrustStatus, ownerStatus, f.f.device}, {OperationOwnerNodePairTrustCancel, ownerStatus, f.f.device},
	}
	for _, item := range items {
		t.Run(item.op, func(t *testing.T) {
			raw, err := SealNodePairTrustRequest(item.actor, f.f.hub, nodePairHeaderFor(f, item.op, item.actor), item.body, now)
			if err != nil {
				t.Fatal(err)
			}
			out := nodePairBody(item.op)
			if _, err = OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, item.op, out, now); err != nil || !reflect.DeepEqual(dereference(out), item.body) {
				t.Fatal("typed roundtrip", err)
			}
			bad := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"secret":"must-reject"}`)...)
			if _, err = OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, bad, item.op, nodePairBody(item.op), now); err == nil {
				t.Fatal("unknown outer field accepted")
			}
			if _, err = OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, item.op, nodePairBody(item.op), now.Add(2*time.Minute)); err == nil {
				t.Fatal("expired original admitted fresh")
			}
			old, err := AuthenticateNodePairTrustOriginal(f.f.hubPrivate, f.f.hub, raw, nodePairBody(item.op))
			if err != nil || old.PacketDigest != NodePairTrustPacketDigest(raw) {
				t.Fatal("original authentication lost", err)
			}
		})
	}
	h := nodePairHeaderFor(f, OperationNodePairTrustPoll, f.node)
	raw, err := SealNodePairTrustRequest(f.node, f.f.hub, h, commit, now)
	if err != nil {
		t.Fatal(err)
	}
	r := NodePairTrustResult{Format: NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(raw), State: NodePairTrustOwnerApproved, Context: &f.c, OOBCommitment: f.o, OwnerProof: f.proof, TrustCapsule: f.capsule, ObservedAt: issued}
	sealed, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, commit, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenNodePairTrustResponse(f.node, f.f.hub, raw, sealed, commit)
	if err != nil || !bytes.Equal(got.TrustCapsule, f.capsule) {
		t.Fatal("poll recipient receipt", err)
	}
	wrong := commit
	wrong.OOBCommitment = strings.Repeat("ca", 32)
	if _, err := OpenNodePairTrustResponse(f.node, f.f.hub, raw, sealed, wrong); err == nil {
		t.Fatal("receipt changed original O")
	}
	if _, err := OpenNodePairTrustResponse(f.nc, f.f.hub, raw, sealed, commit); err == nil {
		t.Fatal("wrong Node opened receipt")
	}
	reconcile := NodePairTrustReconcile{NodePairTrustFormat, raw, NodePairTrustPacketDigest(raw), issued}
	rh := nodePairHeaderFor(f, OperationNodePairTrustReconcile, f.node)
	rh.RequestID = strings.Repeat("81", 16)
	if _, err := SealNodePairTrustRequest(f.node, f.f.hub, rh, reconcile, now); err != nil {
		t.Fatal("own original reconcile", err)
	}
	recoveryPacket, err := SealNodePairTrustRequest(f.node, f.f.hub, rh, reconcile, now)
	if err != nil {
		t.Fatal(err)
	}
	recovery := NodePairTrustResult{Format: NodePairTrustFormat, Operation: rh.Operation, RequestID: rh.RequestID, AttemptID: rh.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(recoveryPacket), State: NodePairTrustRecovered, ObservedAt: issued, OriginalPacketDigest: NodePairTrustPacketDigest(raw), OriginalReceipt: sealed}
	recoveryReceipt, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recoveryPacket, reconcile, recovery)
	if err != nil {
		t.Fatal(err)
	}
	old, exact, err := OpenNodePairTrustRecoveredResponse(f.node, f.f.hub, recoveryPacket, recoveryReceipt, reconcile, commit)
	if err != nil || old.RequestPacketDigest != NodePairTrustPacketDigest(raw) || !bytes.Equal(exact, sealed) {
		t.Fatal("original poll response not recovered exactly", err)
	}
	for _, kind := range []string{"operation", "request", "digest", "recipient", "projection"} {
		t.Run("recovery-"+kind, func(t *testing.T) {
			bad := nodePairClone(recovery)
			switch kind {
			case "operation":
				bad.Operation = OperationNodePairTrustACK
			case "request":
				bad.RequestID = strings.Repeat("99", 16)
			case "digest":
				bad.OriginalPacketDigest = strings.Repeat("99", 32)
			case "recipient":
				if _, _, e := OpenNodePairTrustRecoveredResponse(f.f.device, f.f.hub, recoveryPacket, recoveryReceipt, reconcile, commit); e == nil {
					t.Fatal("foreign recipient accepted old receipt")
				}
				return
			case "projection":
				bad.Context = &f.c
				bad.State = NodePairTrustACKed
			}
			if _, e := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recoveryPacket, reconcile, bad); e == nil {
				t.Fatal("confused original recovery accepted")
			}
		})
	}
	recursive := NodePairTrustReconcile{NodePairTrustFormat, recoveryPacket, NodePairTrustPacketDigest(recoveryPacket), issued}
	if _, e := SealNodePairTrustRequest(f.node, f.f.hub, rh, recursive, now); e == nil {
		t.Fatal("recursive recovery admitted")
	}
	if _, _, e := OpenNodePairTrustRecoveredResponse(f.node, f.f.hub, recoveryPacket, recoveryReceipt, recursive, commit); e == nil {
		t.Fatal("recovered helper admitted recursive original")
	}
	fenced := NodePairTrustResult{Format: NodePairTrustFormat, Operation: rh.Operation, RequestID: rh.RequestID, AttemptID: rh.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(recoveryPacket), State: NodePairTrustFenced, ErrorCode: "FENCED", ObservedAt: issued}
	if _, e := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recoveryPacket, reconcile, fenced); e != nil {
		t.Fatal("durable no-effect fence", e)
	}
	for _, code := range []string{"OUTCOME_UNCERTAIN", "UNAVAILABLE", "NOT_FOUND", "ACK_REQUIRED"} {
		bad := fenced
		bad.ErrorCode = code
		if _, e := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recoveryPacket, reconcile, bad); e == nil {
			t.Fatal("temporary/unknown result became terminal fence", code)
		}
	}
	if _, err := SealNodePairTrustRequest(f.node, f.f.hub, nodePairHeaderFor(f, "node.pair-trust.unknown", f.node), commit, now); err == nil {
		t.Fatal("unknown operation")
	}
}

func TestNodePairTrustLookupMatchesRetainedDescriptorAndContext(t *testing.T) {
	f := nodePairCrypto(t)
	now := f.f.now.Add(2 * time.Second)
	digest, _ := NodePairTrustContextDigest(f.c)
	code, err := EncodeNodePairTrustCode(f.c, "23456789ABCD", f.s)
	if err != nil {
		t.Fatal(err)
	}
	local, err := DecodeNodePairTrustCode(code, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(local.OOBSecret)
	q := NodePairTrustOwnerLookup{NodePairTrustFormat, bytes.Repeat([]byte{7}, 32), f.a.Scope, local.Selector, local.ContextDigest, formatUTC(now)}
	h := nodePairHeaderFor(f, OperationOwnerNodePairTrustLookup, f.f.device)
	raw, err := SealNodePairTrustRequest(f.f.device, f.f.hub, h, q, now)
	if err != nil {
		t.Fatal(err)
	}
	var got NodePairTrustOwnerLookup
	if _, e := OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, h.Operation, &got, now); e != nil || got.ContextDigest != digest || bytes.Contains(raw, []byte(base64.RawURLEncoding.EncodeToString(f.s))) {
		t.Fatal("lookup did not preserve secret boundary", e)
	}
	r := NodePairTrustResult{Format: NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(raw), State: NodePairTrustPending, Context: &f.c, OOBCommitment: f.o, ObservedAt: formatUTC(now)}
	sealed, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, q, r)
	if err != nil {
		t.Fatal(err)
	}
	result, err := OpenNodePairTrustResponse(f.f.device, f.f.hub, raw, sealed, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := MatchNodePairTrustCode(local, *result.Context, f.f.hub, f.nc.Public(), f.c.Origin, f.c.DescriptorDigest, now); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"origin", "CA", "SPKI", "epoch"} {
		t.Run(kind, func(t *testing.T) {
			c := nodePairClone(f.c)
			if kind == "origin" {
				c.Origin = "https://other.synthetic.invalid"
			} else {
				c.DescriptorDigest = NodePairTrustDescriptorDigest("CICADA SYNTHETIC CHANGED " + kind)
			}
			changedCode, e := EncodeNodePairTrustCode(c, local.Selector, f.s)
			if e != nil {
				t.Fatal(e)
			}
			changed, e := DecodeNodePairTrustCode(changedCode, now)
			if e != nil {
				t.Fatal(e)
			}
			defer clear(changed.OOBSecret)
			if _, e := MatchNodePairTrustCode(changed, c, f.f.hub, f.nc.Public(), f.c.Origin, f.c.DescriptorDigest, now); e == nil {
				t.Fatal("same CC/NC silently replaced retained transport")
			}
		})
	}
	bad := q
	bad.ContextDigest = strings.Repeat("cd", 32)
	if _, e := OpenNodePairTrustResponse(f.f.device, f.f.hub, raw, sealed, bad); e == nil {
		t.Fatal("lookup accepted another ContextDigest")
	}
	bad = q
	bad.Selector = "3456789ABCDE"
	if _, e := OpenNodePairTrustResponse(f.f.device, f.f.hub, raw, sealed, bad); e == nil {
		t.Fatal("lookup accepted another selector")
	}
}

func TestNodePairTrustMaximumRecoveryReceiptUsesDedicatedBudget(t *testing.T) {
	f := nodePairCrypto(t)
	now := f.f.now.Add(2 * time.Second)
	q := NodePairTrustCommit{NodePairTrustFormat, f.c, f.o, formatUTC(now)}
	h := nodePairHeaderFor(f, OperationNodePairTrustPoll, f.node)
	raw, err := SealNodePairTrustRequest(f.node, f.f.hub, h, q, now)
	if err != nil {
		t.Fatal(err)
	}
	// Poll transports opaque Owner ciphertext; first trust still independently
	// decrypts and validates S. Exercise its largest permitted ciphertext bound.
	opaque := bytes.Repeat([]byte("SYNTHETIC CIPHERTEXT SIZE ONLY "), (MaxNodePairTrustCapsuleBytes/30)+1)[:MaxNodePairTrustCapsuleBytes]
	var p NodePairTrustOwnerProof
	if json.Unmarshal(f.proof, &p) != nil {
		t.Fatal("proof")
	}
	p.Claims.CapsuleDigest = NodePairTrustCapsuleDigest(opaque)
	p.Signature, err = e2ee.SignNodePairTrustOwner(f.f.owner, nodePairClaimsCommitment(p.Claims))
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(p)
	r := NodePairTrustResult{Format: NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(raw), State: NodePairTrustOwnerApproved, Context: &f.c, OOBCommitment: f.o, OwnerProof: proof, TrustCapsule: opaque, ObservedAt: formatUTC(now)}
	oldReceipt, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, q, r)
	if err != nil {
		t.Fatal(err)
	}
	rec := NodePairTrustReconcile{NodePairTrustFormat, raw, NodePairTrustPacketDigest(raw), formatUTC(now)}
	rh := nodePairHeaderFor(f, OperationNodePairTrustReconcile, f.node)
	rh.RequestID = strings.Repeat("91", 16)
	recPacket, err := SealNodePairTrustRequest(f.node, f.f.hub, rh, rec, now)
	if err != nil {
		t.Fatal(err)
	}
	rr := NodePairTrustResult{Format: NodePairTrustFormat, Operation: rh.Operation, RequestID: rh.RequestID, AttemptID: rh.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(recPacket), State: NodePairTrustRecovered, ObservedAt: formatUTC(now), OriginalPacketDigest: rec.OriginalPacketDigest, OriginalReceipt: oldReceipt}
	receipt, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recPacket, rec, rr)
	if err != nil {
		t.Fatal("large original recovery seal", err)
	}
	_, exact, err := OpenNodePairTrustRecoveredResponse(f.node, f.f.hub, recPacket, receipt, rec, q)
	if err != nil || !bytes.Equal(exact, oldReceipt) {
		t.Fatal("large original recovery open", err)
	}
	// Independently exercise the closed outer bound with its full 1MiB opaque
	// original slot. Double opening must still reject unauthenticated contents.
	rr.OriginalReceipt = bytes.Repeat([]byte{0x53}, MaxNodePairTrustOriginalReceiptBytes)
	maxReceipt, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recPacket, rec, rr)
	if err != nil {
		t.Fatal("max 1MiB raw original slot", err)
	}
	outer, err := OpenNodePairTrustResponse(f.node, f.f.hub, recPacket, maxReceipt, rec)
	if err != nil || len(outer.OriginalReceipt) != MaxNodePairTrustOriginalReceiptBytes || len(maxReceipt) <= MaxNodePairTrustResponsePacketBytes || len(maxReceipt) > MaxNodePairTrustReconcileResponsePacketBytes {
		t.Fatal("dedicated exact budget", err)
	}
	if _, _, err := OpenNodePairTrustRecoveredResponse(f.node, f.f.hub, recPacket, maxReceipt, rec, q); err == nil {
		t.Fatal("opaque size probe became authenticated original")
	}
	rr.OriginalReceipt = append(rr.OriginalReceipt, 0)
	if _, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, recPacket, rec, rr); err == nil {
		t.Fatal("oversized original slot accepted")
	}
}

func TestNodePairTrustStartOriginalNodeProofAndExistingBindingRemainDistinct(t *testing.T) {
	f := nodePairCrypto(t)
	nonce := bytes.Repeat([]byte{0x4c}, 32)
	b := NodePairTrustStart{NodePairTrustFormat, f.f.hub, f.c.Origin, f.c.DescriptorDigest, f.c.Candidate.NodeID, f.c.Candidate.NodeName, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)), nonce, f.nc.Public(), 1, nil, f.c.IssuedAt, f.c.ExpiresAt}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: f.f.hub.HubID, NodeID: b.NodeID, RequestNonce: nonce, CredentialDigest: b.CredentialDigest, NodePublicIdentity: f.node.Public(), HubPublicIdentity: f.nc.Public(), HubKeyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	b.PairingProof, err = e2ee.Seal(f.node, f.nc.Public(), transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealNodePairTrustRequest(f.node, f.f.hub, nodePairHeaderFor(f, OperationNodePairTrustStart, f.node), b, f.f.now)
	if err != nil {
		t.Fatal(err)
	}
	var out NodePairTrustStart
	if _, err := OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, OperationNodePairTrustStart, &out, f.f.now); err != nil || ValidateNodePairTrustStartProof(f.nc, f.node.Public(), out) != nil {
		t.Fatal("existing Node-Control proof", err)
	}
	out.CredentialDigest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	if ValidateNodePairTrustStartProof(f.nc, f.node.Public(), out) == nil {
		t.Fatal("changed original credential digest")
	}
	if _, err := SealNodePairTrustRequest(f.node, f.f.hub, nodePairHeaderFor(f, OperationNodePairTrustExisting, f.node), b, f.f.now); err == nil {
		t.Fatal("existing route accepted INITIAL start body")
	}
	c := nodePairClone(f.c)
	n := c.Candidate
	n.CandidateDigest, err = nodewire.PairingCandidateDigest(nodewire.PairingCandidateBasis{RequestID: n.RequestID, Version: int64(n.Version), Mode: n.Mode, HubID: n.HubID, NodeID: n.NodeID, NodeName: n.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: n.CodeDigest, NodePublicIdentity: n.NodePublic, NodeFingerprint: n.NodeKeyFingerprint, HubPublicIdentity: n.HubNodeControlPublic, HubKeyVersion: n.HubNodeControlKeyVersion, HubFingerprint: n.HubNodeControlFingerprint, NodeKeyEpoch: n.NodeKeyEpoch, ExpiresAt: n.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	h := nodePairHeaderFor(f, OperationNodePairTrustStart, f.node)
	r := NodePairTrustResult{Format: NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(raw), State: NodePairTrustPending, Context: &c, Selector: "2345-6789-ABCD", ObservedAt: formatUTC(f.f.now)}
	response, err := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, b, r)
	if err != nil {
		t.Fatal("original START tuple", err)
	}
	if _, e := OpenNodePairTrustResponse(f.node, f.f.hub, raw, response, b); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"credential", "public", "request", "version"} {
		t.Run(kind, func(t *testing.T) {
			changed := nodePairClone(r)
			original := b
			switch kind {
			case "credential":
				original.CredentialDigest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
			case "public":
				changed.Context.Candidate.NodePublic = f.nc.Public()
				changed.Context.Candidate.NodeKeyFingerprint = nodewire.IdentityFingerprint(f.nc.Public())
			case "request":
				changed.Context.Candidate.RequestID += "-other"
			case "version":
				changed.Context.Candidate.Version++
			}
			if _, e := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, original, changed); e == nil {
				t.Fatal("START accepted changed original tuple")
			}
		})
	}
}

func TestNodePairTrustExistingTrustOnlyCannotCreateInitialAuthority(t *testing.T) {
	f := nodePairCrypto(t)
	n := f.c.Candidate
	b := e2ee.OwnerAppNodeBinding{OwnerBindingID: "nbind_SYNTHETIC", OwnerID: f.a.Scope.OwnerID, HubID: f.c.Hub.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: f.a.Scope.DeviceID, OwnerKeyID: f.a.Scope.OwnerPublic.ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch, HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: 1, ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: formatUTC(f.f.now.Add(-time.Hour)), State: "ACTIVE"}
	c := f.c
	c.Mode = NodePairTrustExisting
	c.Candidate = nil
	c.Binding = &b
	d, e := NodePairTrustContextDigest(c)
	if e != nil {
		t.Fatal(e)
	}
	o, _ := NodePairTrustOOBCommitment(d, f.s)
	a := f.a
	a.ContextDigest = d
	a.OOBCommitment = o
	a.GrantID = ""
	a.GrantProofDigest = ""
	a.ConfirmationPacketDigest = ""
	if ValidateNodePairTrustInitialAuthorization(c, a, nil, nil, f.f.now.Add(time.Second)) != nil {
		t.Fatal("exact existing trust-only authority")
	}
	proof, capsule, e := SealNodePairTrustApproval(f.f.owner, c, o, a, f.s, f.x, f.f.now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	opened, e := OpenNodePairTrustCapsule(f.node, c, o, proof, capsule, f.s, f.f.now.Add(2*time.Second))
	if e != nil {
		t.Fatal(e)
	}
	clear(opened.OOBSecret)
	clear(opened.ACKNonce)
	if ValidateNodePairTrustAccepted(c, a, b) != nil {
		t.Fatal("exact existing binding changed")
	}
	other := b
	other.BindingVersion++
	if ValidateNodePairTrustAccepted(c, a, other) == nil {
		t.Fatal("trust-only replaced original binding")
	}
	bad := a
	bad.GrantID = f.a.GrantID
	if ValidateNodePairTrustApproval(bad, c, o, f.f.now.Add(time.Second)) == nil {
		t.Fatal("trust-only gained INITIAL confirmation")
	}
	revoked := nodePairClone(c)
	revoked.Binding.State = "REVOKED"
	if ValidateNodePairTrustContext(revoked, f.f.now) == nil {
		t.Fatal("trust-only revived revoked binding")
	}
	code, e := EncodeNodePairTrustCode(c, "", f.s)
	if e != nil {
		t.Fatal(e)
	}
	local, e := DecodeNodePairTrustCode(code, f.f.now)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(local.OOBSecret)
	if local.Selector != "" {
		t.Fatal("trust-only fabricated old INITIAL code")
	}
	q := NodePairTrustExistingStart{NodePairTrustFormat, c, formatUTC(f.f.now)}
	h := nodePairHeaderFor(f, OperationNodePairTrustExisting, f.node)
	raw, e := SealNodePairTrustRequest(f.node, f.f.hub, h, q, f.f.now)
	if e != nil {
		t.Fatal(e)
	}
	var got NodePairTrustExistingStart
	if _, e := OpenNodePairTrustRequest(f.f.hubPrivate, f.f.hub, raw, h.Operation, &got, f.f.now); e != nil {
		t.Fatal(e)
	}
}

func TestNodePairTrustFreshObservationsAllowExpiredContextOnly(t *testing.T) {
	f := nodePairCrypto(t)
	end, _ := time.Parse(time.RFC3339Nano, f.c.ExpiresAt)
	now := end.Add(time.Minute)
	for _, op := range []string{OperationNodePairTrustPoll, OperationNodePairTrustCancel, OperationOwnerNodePairTrustStatus, OperationOwnerNodePairTrustCancel} {
		t.Run(op, func(t *testing.T) {
			key := f.node
			var body any = NodePairTrustPoll{NodePairTrustFormat, f.c, f.o, formatUTC(now)}
			if nodePairOperationOwner(op) {
				key = f.f.device
				body = NodePairTrustOwnerStatus{NodePairTrustFormat, f.f.session.Token, f.a.Scope, f.c, f.o, formatUTC(now)}
			}
			h := nodePairHeaderFor(f, op, key)
			if _, e := SealNodePairTrustRequest(key, f.f.hub, h, body, now); e != nil {
				t.Fatal("fresh observation blocked by old context", e)
			}
			if _, e := SealNodePairTrustRequest(key, f.f.hub, h, body, now.Add(2*time.Minute)); e == nil {
				t.Fatal("old observation request became timeless")
			}
		})
	}
	ack := nodePairACK(f)
	ack.IssuedAt = formatUTC(now)
	if _, e := SealNodePairTrustRequest(f.node, f.f.hub, nodePairHeaderFor(f, OperationNodePairTrustACK, f.node), ack, now); e == nil {
		t.Fatal("late ACK accepted expired context")
	}
}

func TestNodePairTrustCancelReturnsExistingTerminalWithoutRenewal(t *testing.T) {
	f := nodePairCrypto(t)
	q := NodePairTrustCancel{NodePairTrustFormat, f.c, f.o, formatUTC(f.f.now)}
	h := nodePairHeaderFor(f, OperationNodePairTrustCancel, f.node)
	raw, e := SealNodePairTrustRequest(f.node, f.f.hub, h, q, f.f.now)
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range []string{NodePairTrustCancelled, NodePairTrustExpired, NodePairTrustRevoked, NodePairTrustFenced} {
		r := NodePairTrustResult{Format: NodePairTrustFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: NodePairTrustPacketDigest(raw), State: state, Context: &f.c, OOBCommitment: f.o, ObservedAt: formatUTC(f.f.now)}
		sealed, e := SealNodePairTrustResponse(f.f.hubPrivate, f.f.hub, raw, q, r)
		if e != nil {
			t.Fatal("terminal cancel result", state, e)
		}
		opened, e := OpenNodePairTrustResponse(f.node, f.f.hub, raw, sealed, q)
		if e != nil || opened.State != state || len(opened.ConfirmationResponse) != 0 {
			t.Fatal("cancel changed terminal or settled old Client", e)
		}
	}
}
