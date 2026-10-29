package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairScopedOriginalStartAndReconcileLossColdRecovery(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	c, s, err := beginMachineNodePairScoped(context.Background(), f.f.state, f.f.node, f.f.node, f.f.address, "", false, f.f.native.text)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(s.Secret)
	bodyAny, err := machineNodePairScopedTypedBody(s.StartOperation, s.StartBody)
	if err != nil {
		t.Fatal(err)
	}
	body := bodyAny.(wire.NodePairTrustScopedStart)
	issued := time.Now().UTC().Add(-55 * time.Second)
	body.IssuedAt, body.ExpiresAt = issued.Format(time.RFC3339Nano), issued.Add(10*time.Minute).Format(time.RFC3339Nano)
	s.StartBody, _ = json.Marshal(body)
	if err := newMachineNodePairScopedRequest(f.f.state, c.identity, s, f.f.native.d.Claims.Hub, s.StartOperation, body); err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(s.PendingPacket)
	f.mu.Lock()
	f.drop[s.StartOperation] = 1
	f.mu.Unlock()
	if _, err := machineNodePairScopedPOST(context.Background(), f.f.http, f.f.native.d.Claims.Origin, s.StartOperation, s.PendingPacket); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("START loss was not uncertain", err)
	}
	f.mu.Lock()
	f.drop[wire.OperationNodePairTrustScopedReconcile] = 1
	f.mu.Unlock()
	if _, _, err := sendMachineNodePairScopedPending(context.Background(), f.f.state, c.identity, s, f.f.native.d, f.f.http); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("reconcile loss was not uncertain", err)
	}
	query := bytes.Clone(s.ReconcilePacket)
	if len(query) == 0 || !bytes.Equal(original, s.PendingPacket) {
		t.Fatal("query replaced original")
	}
	machineNodeControlClients.Delete(c.statePath)
	c, cold := f.load(t)
	defer clear(cold.Secret)
	if !bytes.Equal(original, cold.PendingPacket) || !bytes.Equal(query, cold.ReconcilePacket) || !bytes.Equal(s.Secret, cold.Secret) {
		t.Fatal("cold reopen lost exact request/secret/query")
	}
	r, receipt, err := sendMachineNodePairScopedPending(context.Background(), f.f.state, c.identity, cold, f.f.native.d, f.f.http)
	if err != nil {
		t.Fatal("original recovery failed", err)
	}
	f.mu.Lock()
	originalReceipt := bytes.Clone(f.cache[wire.NodePairTrustScopedPacketDigest(original)])
	queries := f.requests[wire.OperationNodePairTrustScopedReconcile]
	starts := f.requests[wire.OperationNodePairTrustScopedStart]
	f.mu.Unlock()
	if !bytes.Equal(receipt, originalReceipt) || len(queries) != 2 || !bytes.Equal(queries[0], queries[1]) || len(starts) != 1 {
		t.Fatal("recovery changed original receipt/query or redispatched aged START")
	}
	if err := applyMachineNodePairScopedResult(f.f.state, c, cold, f.f.native.d, r, receipt); err != nil || cold.Stage != "COMMIT" || cold.Context.AuthorityNodeID != f.f.node {
		t.Fatal("recovered START did not settle", err)
	}
	t.Log("CLOSED_SCOPED_RECOVERY original_START_loss=true diagnostic_response_loss=true cold_reopen=true identical_original_receipt=true identical_query=true aged_START_redispatch=0 carrier=NOT_RUN")
}

func TestNodePairScopedSecretJournalProtectionAndFamilyBinding(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	path := machineNodePairScopedStatePath(f.f.state, f.f.node)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(s.Secret))) || bytes.Contains(raw, []byte("oob_secret")) {
		t.Fatal("S escaped sealed journal")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("scoped journal not private", err)
	}
	var wrong machineNodePairLocalEnvelope
	if json.Unmarshal(raw, &wrong) != nil {
		t.Fatal("scoped envelope")
	}
	wrong.Format = machineNodePairLocalFormat
	altered, _ := json.Marshal(wrong)
	if err := os.WriteFile(path, altered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMachineNodePairScopedState(f.f.state, f.f.node, c.identity); err == nil {
		t.Fatal("legacy format accepted as scoped")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMachineNodePairScopedState(f.f.state, f.f.node, c.identity); err == nil {
		t.Fatal("public scoped secret accepted")
	}
	if err := saveMachineNodePairScopedState(f.f.state, c.identity, s); err == nil {
		t.Fatal("public journal silently repaired")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	moved := path + ".original"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMachineNodePairScopedState(f.f.state, f.f.node, c.identity); err == nil {
		t.Fatal("scoped symlink followed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	bad := *s
	copied := *s.Context
	bad.Context = &copied
	bad.Context.ScopeVersion = 1
	if err := saveMachineNodePairScopedState(f.f.state, c.identity, &bad); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMachineNodePairScopedState(f.f.state, f.f.node, c.identity); err == nil {
		t.Fatal("scope1 context parsed from scoped journal")
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// A bound Node with no NPT marker is still an existing Node, never a fresh
	// Scope2 candidate. Explicit profile choice cannot erase that distinction.
	c.mu.Lock()
	c.state.BindingID = "synthetic-retained-binding"
	c.state.NodePairTrustAttemptID = ""
	err = c.persistLocked()
	c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, filepath.Join(filepath.Dir(path), "scoped-fixture-retained")); err != nil {
		t.Fatal(err)
	}
	before, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	if _, _, err := selectMachineNodePairProfile(context.Background(), f.f.state, f.f.node, f.f.address, "", false, "scoped"); err == nil {
		t.Fatal("bound Node with empty marker became INITIAL")
	}
	after, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	if before != after {
		t.Fatal("profile selection changed retained state")
	}
}

func TestNodePairScopedACKedExpiredEnrollmentUsesOriginalBinding(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	// Build an authenticated saved ceremony from a historical test clock. This
	// is an already-verified trust fact fixture, never production first trust
	// authorized by a historical Hub observation.
	past := time.Now().UTC().Add(-20 * time.Minute)
	s.Context.IssuedAt = past.Format(time.RFC3339Nano)
	s.Context.ExpiresAt = past.Add(10 * time.Minute).Format(time.RFC3339Nano)
	s.Context.Candidate.ExpiresAt = s.Context.ExpiresAt
	digest, _ := wire.NodePairTrustScopedContextDigest(*s.Context)
	s.OOB, _ = wire.NodePairTrustScopedOOBCommitment(digest, s.Secret)
	f.approve(t, s, past.Add(time.Second)) // replace the time-bearing fields below before signing
	a := f.approval
	a.Scope.AccountSessionExpiresAt = past.Add(15 * time.Minute).Format(time.RFC3339Nano)
	a.PreparedAt = past.Add(time.Second).Format(time.RFC3339Nano)
	a.AcceptBefore = past.Add(2 * time.Minute).Format(time.RFC3339Nano)
	proof, capsule, err := wire.SealNodePairTrustScopedApproval(f.owner, *s.Context, s.OOB, a, s.Secret, bytes.Repeat([]byte{0x58}, 32), past.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptMachineNodePairScopedCapsule(f.f.state, c, s, wire.NodePairTrustScopedResult{OwnerProof: proof, TrustCapsule: capsule}, past.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	q := wire.NodePairTrustScopedACK{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, PollPacketDigest: strings.Repeat("a", 64), PollReceiptDigest: strings.Repeat("b", 64), OwnerProofDigest: wire.NodePairTrustScopedProofDigest(proof), CapsuleDigest: wire.NodePairTrustScopedCapsuleDigest(capsule), ACKNonce: bytes.Repeat([]byte{0x58}, 32), IssuedAt: past.Add(2 * time.Second).Format(time.RFC3339Nano)}
	id, _ := wire.NewRequestID()
	packet, err := wire.SealNodePairTrustScopedRequest(c.identity, f.f.native.d.Claims.Hub, wire.NodePairTrustScopedPacket{Operation: wire.OperationNodePairTrustScopedACK, RequestID: id, AttemptID: s.AttemptID}, q, past.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	b := f.binding
	b.ApprovedAt = past.Add(2 * time.Second).Format(time.RFC3339Nano)
	r := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: wire.OperationNodePairTrustScopedACK, RequestID: id, AttemptID: s.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(packet), State: wire.NodePairTrustScopedACKed, Context: s.Context, OOBCommitment: s.OOB, Binding: &b, ObservedAt: past.Add(2 * time.Second).Format(time.RFC3339Nano)}
	receipt, err := wire.SealNodePairTrustScopedResponse(f.ids.ClientControl, f.f.native.d.Claims.Hub, packet, q, r)
	if err != nil {
		t.Fatal(err)
	}
	s.ACKPacket, s.ACKBody, s.ACKReceipt, s.Binding, s.Stage = packet, &q, receipt, &b, wire.NodePairTrustScopedACKed
	clearMachineNodePairScopedPending(s)
	if err := saveMachineNodePairScopedState(f.f.state, c.identity, s); err != nil {
		t.Fatal(err)
	}
	if err := installMachineNodePairScopedBinding(f.f.state, c, s, f.f.native.d); err != nil {
		t.Fatal("historical ACK binding failed", err)
	}
	before, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	binding := c.state.BindingID
	public := c.identity.Public()
	f.mu.Lock()
	f.available = false
	requests := len(f.requests[wire.OperationNodePairTrustScopedACK])
	f.mu.Unlock()
	if err := machineNodePairACKMarker(f.f.state, f.f.node, c); err != nil {
		t.Fatal("expired ceremony rejected on/off fact", err)
	}
	if err := f.run(t); err != nil {
		t.Fatal("expired ACKED ceremony demanded enrollment", err)
	}
	after, _ := recoveryTreeDigest(machineNodeStateDir(f.f.state, f.f.node))
	f.mu.Lock()
	defer f.mu.Unlock()
	if before != after || binding != c.state.BindingID || !reflect.DeepEqual(public, c.identity.Public()) || requests != len(f.requests[wire.OperationNodePairTrustScopedACK]) {
		t.Fatal("ACKED expiration caused mutation or POST")
	}
}
