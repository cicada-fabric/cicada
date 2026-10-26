package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func endpointGroupsOwnerTestFixture(t *testing.T) *n3StoreFixture {
	t.Helper()
	f := n3Fixture(t, true)
	endpointGroupsOwnerTestInitialize(t, f)
	return f
}

func endpointGroupsOwnerTestInitialize(t *testing.T, f *n3StoreFixture) {
	t.Helper()
	var exists int
	if err := f.db.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='hub_endpoint_groups_reviews_v1'`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists == 0 {
		if err := f.db.initializeHubEndpointGroupsOwnerSchema(); err != nil {
			t.Fatal(err)
		}
	}
	// The shared row is the frozen production writer boundary. These ledger
	// tests do not create a fake business service or an authorized Group.
	if _, err := f.db.db.Exec(`CREATE TABLE IF NOT EXISTS hub_endpoint_groups_guard_v1(id INTEGER PRIMARY KEY CHECK(id=1),touched_at TEXT NOT NULL);INSERT OR IGNORE INTO hub_endpoint_groups_guard_v1 VALUES(1,'')`); err != nil {
		t.Fatal(err)
	}
}

func endpointGroupsOwnerTestInput(t *testing.T, f *n3StoreFixture, body any, at time.Time) (HubEndpointGroupsInput, HubEndpointGroupsSeal) {
	t.Helper()
	packet, err := wire.SealClientRequest(f.device, f.hub, body)
	if err != nil {
		t.Fatal(err)
	}
	binding, route, err := wire.NewClientRoute(f.hub, body, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var out any
	switch body.(type) {
	case wire.OwnerEndpointGroupsReadRequest:
		out = &wire.OwnerEndpointGroupsReadRequest{}
	case wire.OwnerEndpointGroupsPrepareRequest:
		out = &wire.OwnerEndpointGroupsPrepareRequest{}
	case wire.OwnerEndpointGroupsApplyRequest:
		out = &wire.OwnerEndpointGroupsApplyRequest{}
	case wire.OwnerEndpointGroupsStatusRequest:
		out = &wire.OwnerEndpointGroupsStatusRequest{}
	case wire.OwnerEndpointGroupsReconcileRequest:
		out = &wire.OwnerEndpointGroupsReconcileRequest{}
	default:
		t.Fatal("unexpected synthetic Owner Group request")
	}
	public := f.device.Public()
	if err := wire.OpenRequestAt(f.hubPrivate, &public, binding, route, packet, out, time.Time{}); err != nil {
		t.Fatal("synthetic PQ input", err)
	}
	in := HubEndpointGroupsInput{Hub: f.hub, NodeControlPublic: f.nodeControl.Public(), Device: public, Packet: packet, Body: reflect.ValueOf(out).Elem().Interface(), At: at}
	return in, func(v any) ([]byte, error) { return wire.SealResponse(f.hubPrivate, public, route, v) }
}

func endpointGroupsOwnerTestUnreviewedApply(t *testing.T, f *n3StoreFixture, at time.Time) wire.OwnerEndpointGroupsApplyRequest {
	t.Helper()
	seed, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network"}, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	body := wire.OwnerEndpointGroupsApplyBody{ReviewID: strings.Repeat("a", 32), ReviewDigest: strings.Repeat("b", 64), PreparePacketDigest: strings.Repeat("c", 64)}
	digest, err := wire.OwnerEndpointGroupsBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	end := at.Add(e2ee.EndpointGroupsRequestLifetime)
	sessionEnd, _ := time.Parse(time.RFC3339Nano, f.scope.AccountSessionExpiresAt)
	if sessionEnd.Before(end) {
		end = sessionEnd
	}
	claims := e2ee.OwnerEndpointGroupsRequestClaims{Version: 1, Purpose: wire.OwnerEndpointGroupsOwnerPurpose(wire.OperationOwnerEndpointGroupsApply), Scope: f.scope, RequestID: seed.Context.RequestID, Nonce: hex.EncodeToString(seed.Context.ClientNonce), IssuedAt: seed.Context.IssuedAt, ExpiresAt: appNodeStamp(end), BodyDigest: digest}
	proof, err := e2ee.SignOwnerEndpointGroupsRequest(f.owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	return wire.OwnerEndpointGroupsApplyRequest{Format: wire.OwnerEndpointGroupsFormat, Context: seed.Context, SessionToken: append([]byte(nil), f.session.Token...), OwnerProof: proof, Body: body}
}

func endpointGroupsOwnerTestOpen(t *testing.T, f *n3StoreFixture, in HubEndpointGroupsInput, packet []byte) wire.OwnerEndpointGroupsResult {
	t.Helper()
	var result wire.OwnerEndpointGroupsResult
	if err := wire.OpenOwnerEndpointGroupsResponse(f.device, f.hub, in.Packet, packet, &result); err != nil {
		t.Fatal("authenticated Owner Group response", err)
	}
	if err := wire.VerifyOwnerEndpointGroupsResult(in.Body, in.Packet, result, f.hub); err != nil {
		t.Fatal("Owner Group response request/target binding", err)
	}
	return result
}

func TestEndpointGroupsOwnerReconcileUnseenApplyPermanentlyFencesOriginal(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	q, err := wire.NewOwnerEndpointGroupsReconcile(f.session, f.scope, original.Packet, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
	in.Original = &original
	in.OriginalSeal = originalSeal
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	result := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if result.State != "COMPLETED" || result.Operation != nil || result.NodeID != "" || len(result.ReceiptPacket) == 0 || result.CurrentGroup != nil || result.CurrentRelation != nil {
		t.Fatal("outer response manufactured an apply outcome")
	}
	fence := endpointGroupsOwnerTestOpen(t, f, original, result.ReceiptPacket)
	if fence.State != "REJECTED_FENCED" || fence.ErrorCode != wire.OwnerEndpointGroupsOriginalNotAdmitted || fence.Operation != nil || fence.NodeID != "" || fence.Review != nil || len(fence.Threads)+len(fence.Groups)+len(fence.Relations)+len(fence.ReceiptPacket) != 0 || fence.CurrentGroup != nil || fence.CurrentRelation != nil {
		t.Fatal("unseen original did not receive the unique targetless zero-effect fence")
	}
	if err := wire.VerifyOwnerEndpointGroupsOriginalFence(apply, original.Packet, fence, f.hub); err != nil {
		t.Fatal("independent original fence verification", err)
	}
	for _, at := range []time.Time{f.now.Add(2 * time.Second), f.now.Add(10 * time.Minute)} {
		original.At = at
		retry, err := f.db.ProcessHubEndpointGroups(original, originalSeal)
		if err != nil || !bytes.Equal(retry, result.ReceiptPacket) {
			t.Fatal("exact original retry changed the durable fence", err)
		}
	}
	var floors, operations, reviews int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1 WHERE operation_id=?),(SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?),(SELECT count(*) FROM hub_endpoint_groups_reviews_v1)`, apply.Context.RequestID, apply.Context.RequestID).Scan(&floors, &operations, &reviews); err != nil || floors != 1 || operations != 1 || reviews != 0 {
		t.Fatal("zero-effect original was not recorded atomically", err)
	}
	// Re-encrypting the same typed request is a changed original, never an
	// exact retry. It cannot replace or consume the first original's history.
	changed, changedSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now.Add(3*time.Second))
	if bytes.Equal(changed.Packet, original.Packet) {
		t.Fatal("synthetic encryption reused ciphertext")
	}
	if _, err := f.db.ProcessHubEndpointGroups(changed, changedSeal); !errors.Is(err, ErrHubEndpointGroupsPacketConflict) {
		t.Fatal("same ID changed ciphertext was not a permanent conflict", err)
	}
}

func TestEndpointGroupsOwnerDirectAndReconcileSerializeAcrossStoreHandles(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	other, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	q, err := wire.NewOwnerEndpointGroupsReconcile(f.session, f.scope, original.Packet, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	reconcile, reconcileSeal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
	reconcile.Original = &original
	reconcile.OriginalSeal = originalSeal
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var directPacket, reconcilePacket []byte
	var directErr, reconcileErr error
	go func() {
		defer wg.Done()
		<-start
		directPacket, directErr = f.db.ProcessHubEndpointGroups(original, originalSeal)
	}()
	go func() {
		defer wg.Done()
		<-start
		reconcilePacket, reconcileErr = other.ProcessHubEndpointGroups(reconcile, reconcileSeal)
	}()
	close(start)
	wg.Wait()
	if directErr != nil || reconcileErr != nil {
		t.Fatal("writer serialization failed", directErr, reconcileErr)
	}
	r := endpointGroupsOwnerTestOpen(t, f, reconcile, reconcilePacket)
	if !bytes.Equal(directPacket, r.ReceiptPacket) {
		t.Fatal("concurrent paths allocated two original responses")
	}
	var count int
	if err := f.db.db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?`, apply.Context.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent claims produced multiple durable originals", err)
	}
}

func TestEndpointGroupsOwnerMissingOperationPreservesUncertainty(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	if _, err := f.db.ProcessHubEndpointGroups(original, originalSeal); err != nil {
		t.Fatal(err)
	}
	// Disposable fault injection models an incomplete restore. Production
	// no-delete triggers remain intact in normal operation and are tested below.
	if _, err := f.db.db.Exec(`DROP TRIGGER hub_endpoint_groups_owner_operations_v1_no_delete;DELETE FROM hub_endpoint_groups_owner_operations_v1`); err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewOwnerEndpointGroupsStatus(f.session, f.scope, original.Packet, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.State != "COMPLETED" || r.ErrorCode != "OUTCOME_UNCERTAIN" || r.Operation != nil || len(r.ReceiptPacket) != 0 || r.CurrentGroup != nil || r.CurrentRelation != nil {
		t.Fatal("partial history was repaired into a false outcome")
	}
	original.At = f.now.Add(2 * time.Second)
	if retry, err := f.db.ProcessHubEndpointGroups(original, originalSeal); !errors.Is(err, ErrHubEndpointGroupsOutcomeUncertain) || len(retry) != 0 {
		t.Fatal("unknown direct APPLY manufactured a targetless original response", err)
	}
	recovery, err := wire.NewOwnerEndpointGroupsReconcile(f.session, f.scope, original.Packet, f.owner, f.now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	recoveryInput, recoverySeal := endpointGroupsOwnerTestInput(t, f, recovery, f.now.Add(3*time.Second))
	recoveryInput.Original = &original
	recoveryInput.OriginalSeal = originalSeal
	unknownPacket, err := f.db.ProcessHubEndpointGroups(recoveryInput, recoverySeal)
	if err != nil {
		t.Fatal(err)
	}
	unknown := endpointGroupsOwnerTestOpen(t, f, recoveryInput, unknownPacket)
	if unknown.State != "COMPLETED" || unknown.ErrorCode != "OUTCOME_UNCERTAIN" || len(unknown.ReceiptPacket) != 0 || unknown.Operation != nil {
		t.Fatal("reconcile embedded an unsettled temporary original")
	}
	var operations, floors int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?),(SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1 WHERE operation_id=?)`, apply.Context.RequestID, apply.Context.RequestID).Scan(&operations, &floors); err != nil || operations != 0 || floors != 1 {
		t.Fatal("uncertain original history was modified", err)
	}
}

func TestEndpointGroupsOwnerSealFailureRollsBackFenceAndNonce(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	q, err := wire.NewOwnerEndpointGroupsReconcile(f.session, f.scope, original.Packet, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
	in.Original = &original
	in.OriginalSeal = originalSeal
	failed := errors.New("synthetic response persistence failure")
	if _, err := f.db.ProcessHubEndpointGroups(in, func(any) ([]byte, error) { return nil, failed }); !errors.Is(err, failed) {
		t.Fatal("synthetic sealing failure disappeared", err)
	}
	var count int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1)+(SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1)+(SELECT count(*) FROM hub_endpoint_groups_owner_reads_v1)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("half of the no-effect fence committed", err)
	}
	if _, err := f.db.ProcessHubEndpointGroups(in, seal); err != nil {
		t.Fatal("exact retry after complete rollback failed", err)
	}
}

func TestEndpointGroupsOwnerHistoricalReceiptSurvivesRootRevocation(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	packet, err := f.db.ProcessHubEndpointGroups(original, originalSeal)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := f.db.RevokeOwnerApprovalKeyLocal(f.scope.OwnerID, f.owner.Public().ID, int64(f.scope.OwnerKeyVersion))
	if err != nil {
		t.Fatal(err)
	}
	original.At = f.now.Add(10 * time.Minute)
	if retry, err := f.db.ProcessHubEndpointGroups(original, originalSeal); err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("Root revocation redispatched or erased historical ciphertext", err)
	}
	f.scope.OwnerKeyVersion = uint64(revoked.Version)
	q, err := wire.NewOwnerEndpointGroupsStatus(f.session, f.scope, original.Packet, f.owner, f.now.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(11*time.Minute))
	response, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, response)
	if !bytes.Equal(r.ReceiptPacket, packet) || r.CurrentGroup != nil || r.CurrentRelation != nil || r.Operation != nil {
		t.Fatal("history lookup borrowed current Root authority")
	}
	read, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network"}, f.owner, f.now.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	readInput, readSeal := endpointGroupsOwnerTestInput(t, f, read, f.now.Add(11*time.Minute))
	denied, err := f.db.ProcessHubEndpointGroups(readInput, readSeal)
	if err != nil {
		t.Fatal(err)
	}
	page := endpointGroupsOwnerTestOpen(t, f, readInput, denied)
	if page.State == "COMPLETED" || len(page.Threads)+len(page.Groups)+len(page.Relations) != 0 || page.ScopeActions != nil {
		t.Fatal("retained Owner proof became new inventory authority")
	}
}

func TestEndpointGroupsOwnerSchemaRejectsHistoryMutation(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	in, seal := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	if _, err := f.db.ProcessHubEndpointGroups(in, seal); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`UPDATE hub_endpoint_groups_owner_operations_v1 SET state='COMPLETED'`, `DELETE FROM hub_endpoint_groups_owner_operations_v1`, `UPDATE hub_endpoint_groups_owner_nonces_v1 SET request_digest='` + strings.Repeat("0", 64) + `'`, `DELETE FROM hub_endpoint_groups_owner_nonces_v1`} {
		if _, err := f.db.db.Exec(query); err == nil {
			t.Fatal("immutable exact history changed")
		}
	}
}

func TestEndpointGroupsOwnerAccountSessionCannotCompletePendingEnrollment(t *testing.T) {
	f := n3Fixture(t, false)
	endpointGroupsOwnerTestInitialize(t, f)
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network", Name: "Synthetic forbidden group"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now)
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.State != "REJECTED_FENCED" || r.ErrorCode != "OWNER_AUTHORITY_REQUIRED" || r.Review != nil || r.Operation != nil || r.CurrentGroup != nil || r.CurrentRelation != nil {
		t.Fatal("account/Owner possession bypassed pending device enrollment")
	}
	var reviews int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_reviews_v1`).Scan(&reviews); err != nil || reviews != 0 {
		t.Fatal("unproven App created an actionable review", err)
	}
}

func TestEndpointGroupsOwnerNeverBootstrapsTrustFromArrivingProof(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	q := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(q.OwnerProof, &proof) != nil {
		t.Fatal("synthetic Owner proof decode")
	}
	unregistered, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof.Claims.Scope.OwnerPublic = unregistered.Public()
	q.OwnerProof, err = e2ee.SignOwnerEndpointGroupsRequest(unregistered, proof.Claims)
	if err != nil {
		t.Fatal(err)
	}
	// This is a real current account/device envelope with a valid signature
	// by a different, unregistered Owner key. Its arriving public key is not a pin.
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now)
	if _, err := f.db.ProcessHubEndpointGroups(in, seal); !errors.Is(err, ErrHubAccountRejected) {
		t.Fatal("account device bootstrapped a replacement Owner identity", err)
	}
	var count int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1)+(SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1)+(SELECT count(*) FROM hub_endpoint_groups_reviews_v1)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unknown Owner proof established durable authority", err)
	}
}

func TestEndpointGroupsOwnerTrustedNowRunsAfterWriterLock(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	other, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network", Name: "Synthetic queued request"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now)
	actual := f.now.Add(10 * time.Minute)
	sampled := make(chan struct{}, 1)
	in.Now = func() time.Time {
		sampled <- struct{}{}
		return actual
	}
	writer, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err = writer.Exec(`UPDATE hub_endpoint_groups_guard_v1 SET touched_at=touched_at WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	type result struct {
		packet []byte
		err    error
	}
	started, done := make(chan struct{}), make(chan result, 1)
	go func() {
		close(started)
		packet, processErr := other.ProcessHubEndpointGroups(in, seal)
		done <- result{packet, processErr}
	}()
	<-started
	select {
	case <-sampled:
		t.Fatal("trusted time was sampled before the SQLite writer was acquired")
	case <-time.After(50 * time.Millisecond):
	}
	if err = writer.Commit(); err != nil {
		t.Fatal(err)
	}
	var response result
	select {
	case response = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queued writer failed to resume")
	}
	if response.err != nil {
		t.Fatal(response.err)
	}
	if len(sampled) != 1 {
		t.Fatal("trusted time was not sampled exactly once after admission lock")
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, response.packet)
	if r.State != "REJECTED_FENCED" || r.ErrorCode != "REVIEW_EXPIRED" || r.CapturedAt != appNodeStamp(actual) || r.Review != nil {
		t.Fatal("queued request reused arrival time as fresh authorization")
	}
	var reviews int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_reviews_v1`).Scan(&reviews); err != nil || reviews != 0 {
		t.Fatal("expired queued request created a live review", err)
	}
}

func TestEndpointGroupsOwnerNonceReplayCannotUseNewRequestID(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	first := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	original, originalSeal := endpointGroupsOwnerTestInput(t, f, first, f.now)
	if _, err := f.db.ProcessHubEndpointGroups(original, originalSeal); err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network", Name: "Synthetic nonce replay"}, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var proof e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(q.OwnerProof, &proof) != nil {
		t.Fatal("synthetic Owner proof decode")
	}
	q.Context.ClientNonce = append([]byte(nil), first.Context.ClientNonce...)
	proof.Claims.Nonce = hex.EncodeToString(q.Context.ClientNonce)
	q.OwnerProof, err = e2ee.SignOwnerEndpointGroupsRequest(f.owner, proof.Claims)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.State != "REJECTED_FENCED" || r.ErrorCode != "ORIGINAL_PACKET_CONFLICT" || r.Review != nil {
		t.Fatal("a new request ID admitted a consumed Owner nonce")
	}
	if retry, err := f.db.ProcessHubEndpointGroups(in, seal); err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("negative nonce receipt was not exact and durable", err)
	}
	var floors, nonceClaims, reviews int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1),(SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1 WHERE nonce_digest!=''),(SELECT count(*) FROM hub_endpoint_groups_reviews_v1)`).Scan(&floors, &nonceClaims, &reviews); err != nil || floors != 2 || nonceClaims != 1 || reviews != 0 {
		t.Fatal("nonce replay changed its permanent request floor or review", err)
	}
}

func TestEndpointGroupsOwnerReconcileUnseenReadOnlyNeverRefreshes(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	read, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-owner-group-node", NetworkID: "synthetic-owner-group-network", Name: "Synthetic unseen prepare"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	apply := endpointGroupsOwnerTestUnreviewedApply(t, f, f.now)
	applyInput, _ := endpointGroupsOwnerTestInput(t, f, apply, f.now)
	status, err := wire.NewOwnerEndpointGroupsStatus(f.session, f.scope, applyInput.Packet, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body any
		node string
	}{{"read", read, read.Body.NodeID}, {"prepare", prepare, prepare.Body.NodeID}, {"status", status, ""}} {
		t.Run(test.name, func(t *testing.T) {
			original, originalSeal := endpointGroupsOwnerTestInput(t, f, test.body, f.now)
			q, err := wire.NewOwnerEndpointGroupsReconcile(f.session, f.scope, original.Packet, f.owner, f.now.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			in, seal := endpointGroupsOwnerTestInput(t, f, q, f.now.Add(time.Second))
			in.Original, in.OriginalSeal = &original, originalSeal
			packet, err := f.db.ProcessHubEndpointGroups(in, seal)
			if err != nil {
				t.Fatal(err)
			}
			wrapper := endpointGroupsOwnerTestOpen(t, f, in, packet)
			if wrapper.State != "COMPLETED" || len(wrapper.ReceiptPacket) == 0 || wrapper.Operation != nil || wrapper.CurrentGroup != nil || wrapper.CurrentRelation != nil {
				t.Fatal("unseen original recovery invented an operation or current state")
			}
			r := endpointGroupsOwnerTestOpen(t, f, original, wrapper.ReceiptPacket)
			if r.State != "READ_EXPIRED" || r.ErrorCode != "" || r.NodeID != test.node || r.Review != nil || r.Operation != nil || r.ScopeActions != nil || r.CurrentGroup != nil || r.CurrentRelation != nil || len(r.Threads)+len(r.Groups)+len(r.Relations)+len(r.ReceiptPacket) != 0 {
				t.Fatal("unseen read/prepare/status was refreshed instead of fenced")
			}
			original.At = f.now.Add(10 * time.Minute)
			if retry, err := f.db.ProcessHubEndpointGroups(original, originalSeal); err != nil || !bytes.Equal(retry, wrapper.ReceiptPacket) {
				t.Fatal("fenced read-only original became a new request", err)
			}
		})
	}
	var reviews int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_endpoint_groups_reviews_v1`).Scan(&reviews); err != nil || reviews != 0 {
		t.Fatal("reconcile admitted an unseen prepare", err)
	}
}

func endpointGroupsOwnerTestBusinessFixture(t *testing.T) (*n3StoreFixture, wire.LocalDomainDescription, wire.LocalDomainNodeJoinResult) {
	t.Helper()
	domain := localDomainStore(t)
	description := domain.activate(t)
	join, _ := domain.join(t, description, "synthetic-owner-groups-original-sid")
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	domain.keyReady(t, description, join, key)
	f := domain.f.f
	endpointGroupsOwnerTestInitialize(t, f)
	return f, description, join
}

func endpointGroupsOwnerTestPrepareBusiness(t *testing.T, f *n3StoreFixture, body wire.OwnerEndpointGroupsPrepareBody, at time.Time) (wire.OwnerEndpointGroupsPrepareRequest, HubEndpointGroupsInput, wire.OwnerEndpointGroupsReview) {
	t.Helper()
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, body, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, at)
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.State != "PREPARED" || r.Review == nil {
		t.Fatal("real business prepare refused", r.ErrorCode)
	}
	if err = wire.ValidateOwnerEndpointGroupsReview(q, in.Packet, *r.Review, f.hub, at); err != nil {
		t.Fatal("real business review binding", err)
	}
	return q, in, *r.Review
}

func endpointGroupsOwnerTestApplyBusiness(t *testing.T, f *n3StoreFixture, q wire.OwnerEndpointGroupsPrepareRequest, prepared HubEndpointGroupsInput, review wire.OwnerEndpointGroupsReview, at time.Time, head *e2ee.EndpointGroupOwnerControl) (HubEndpointGroupsInput, HubEndpointGroupsSeal, wire.OwnerEndpointGroupsResult, []byte) {
	t.Helper()
	apply, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope, q, prepared.Packet, review, f.owner, at)
	if err != nil {
		t.Fatal("real business apply construction", err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, apply, at)
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal("real business apply", err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.State != "COMPLETED" || r.Operation == nil {
		t.Fatal("real business apply refused", r.ErrorCode)
	}
	if err = wire.VerifyOwnerEndpointGroupsOperation(review, in.Packet, *r.Operation, head); err != nil {
		t.Fatal("real business operation effect binding", err)
	}
	return in, seal, r, packet
}

func TestEndpointGroupsOwnerRealCreateAtomicSealRollbackAndExactRecovery(t *testing.T) {
	f, d, _ := endpointGroupsOwnerTestBusinessFixture(t)
	at := f.now.Add(10 * time.Second)
	q, prepared, review := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, Name: "Synthetic independently reviewed Group"}, at)
	apply, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope, q, prepared.Packet, review, f.owner, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, apply, at.Add(time.Second))
	failure := errors.New("synthetic CREATE response loss before transaction commit")
	if _, err = f.db.ProcessHubEndpointGroups(in, func(any) ([]byte, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal("CREATE response seal failure disappeared", err)
	}
	var groups, operations int
	var state string
	if err = f.db.db.QueryRow(`SELECT (SELECT count(*) FROM groups WHERE id=?),(SELECT count(*) FROM hub_endpoint_groups_owner_operations_v1 WHERE operation_id=?),(SELECT state FROM hub_endpoint_groups_reviews_v1 WHERE review_id=?)`, review.Target.GroupID, apply.Context.RequestID, review.ReviewID).Scan(&groups, &operations, &state); err != nil || groups != 0 || operations != 0 || state != "PREPARED" {
		t.Fatal("CREATE effects/review committed before exact sealed response", err)
	}
	packet, err := f.db.ProcessHubEndpointGroups(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, in, packet)
	if r.Operation == nil || r.State != "COMPLETED" || r.CurrentGroup == nil || r.CurrentGroup.GroupID != review.Target.GroupID || wire.VerifyOwnerEndpointGroupsOperation(review, in.Packet, *r.Operation, nil) != nil {
		t.Fatal("CREATE did not commit its exact approved operation")
	}
	var members int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM memberships WHERE group_id=?`, review.Target.GroupID).Scan(&members); err != nil || members != 1 {
		t.Fatal("CREATE enrolled an unreviewed agent", err)
	}
	// A new Store handle models receipt recovery after the caller lost the
	// committed response. Original packet bytes remain the only retry identity.
	other, err := New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	in.At = at.Add(10 * time.Minute)
	if retry, err := other.ProcessHubEndpointGroups(in, seal); err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("durable CREATE recovery changed its exact original receipt", err)
	}
	revoked, err := f.db.RevokeOwnerApprovalKeyLocal(f.scope.OwnerID, f.owner.Public().ID, int64(f.scope.OwnerKeyVersion))
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := other.ProcessHubEndpointGroups(in, seal); err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("Root revocation changed a completed CREATE receipt", err)
	}
	f.scope.OwnerKeyVersion = uint64(revoked.Version)
	status, err := wire.NewOwnerEndpointGroupsStatus(f.session, f.scope, in.Packet, f.owner, at.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	statusInput, statusSeal := endpointGroupsOwnerTestInput(t, f, status, at.Add(11*time.Minute))
	statusPacket, err := f.db.ProcessHubEndpointGroups(statusInput, statusSeal)
	if err != nil {
		t.Fatal(err)
	}
	history := endpointGroupsOwnerTestOpen(t, f, statusInput, statusPacket)
	if history.Operation == nil || history.Operation.OperationID != apply.Context.RequestID || !bytes.Equal(history.ReceiptPacket, packet) || history.CurrentGroup != nil || history.CurrentRelation != nil {
		t.Fatal("historical completed receipt borrowed revoked Root for a current snapshot")
	}
}

func TestEndpointGroupsOwnerRealAddPendingThenRemoveKeepsOriginalIdentity(t *testing.T) {
	f, d, join := endpointGroupsOwnerTestBusinessFixture(t)
	at := f.now.Add(10 * time.Second)
	create, ci, cr := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, Name: "Synthetic second scope"}, at)
	endpointGroupsOwnerTestApplyBusiness(t, f, create, ci, cr, at.Add(time.Second), nil)
	body := wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsAddEndpoint, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, GroupID: cr.Target.GroupID, EndpointID: join.Member.EndpointID, Duration: "1d"}
	q, prepared, review := endpointGroupsOwnerTestPrepareBusiness(t, f, body, at.Add(2*time.Second))
	in, seal, r, packet := endpointGroupsOwnerTestApplyBusiness(t, f, q, prepared, review, at.Add(3*time.Second), nil)
	if r.Operation.Effect.ContributionState != "PENDING_KEY" || r.Operation.Effect.OwnerControl == nil || r.Operation.Effect.OwnerControl.Mode != "DEFAULT" || r.Operation.Effect.OwnerControl.Revision != 0 || r.CurrentRelation == nil || r.CurrentRelation.State != "PENDING_KEY" {
		t.Fatal("Owner apply activated pending keys or changed the previous Owner head")
	}
	if retry, err := f.db.ProcessHubEndpointGroups(in, seal); err != nil || !bytes.Equal(retry, packet) {
		t.Fatal("lost ADD response installed a second contribution", err)
	}
	head := r.CurrentRelation.OwnerControl
	body.Action, body.Duration = wire.OwnerEndpointGroupsRemoveEndpoint, ""
	remove, ri, rr := endpointGroupsOwnerTestPrepareBusiness(t, f, body, at.Add(4*time.Second))
	_, _, removed, _ := endpointGroupsOwnerTestApplyBusiness(t, f, remove, ri, rr, at.Add(5*time.Second), &head)
	if removed.CurrentRelation == nil || removed.CurrentRelation.State != "REMOVED" || removed.CurrentRelation.OwnerControl.PolicyID != head.PolicyID || removed.CurrentRelation.OwnerControl.PolicyEpoch != head.PolicyEpoch || removed.Operation.Effect.RelationRevision == nil || *removed.Operation.Effect.RelationRevision != rr.Expected.RelationRevision+1 {
		t.Fatal("REMOVE lost its exact aggregate revision or adopted an unactivated policy")
	}
	var originalSID string
	var candidates int
	if err := f.db.db.QueryRow(`SELECT native_session_id FROM fabric_endpoints WHERE id=?`, join.Member.EndpointID).Scan(&originalSID); err != nil || originalSID != join.Member.NativeSessionID {
		t.Fatal("scoped removal replaced the native identity", err)
	}
	if err := f.db.db.QueryRow(`SELECT count(*) FROM endpoint_key_candidates_v2 WHERE endpoint_id=?`, join.Member.EndpointID).Scan(&candidates); err != nil || candidates != 1 {
		t.Fatal("scoped removal replaced or erased the original candidate", err)
	}
	read, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "RELATIONS", NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, EndpointID: join.Member.EndpointID}, f.owner, at.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	readInput, readSeal := endpointGroupsOwnerTestInput(t, f, read, at.Add(6*time.Second))
	readPacket, err := f.db.ProcessHubEndpointGroups(readInput, readSeal)
	if err != nil {
		t.Fatal(err)
	}
	current := endpointGroupsOwnerTestOpen(t, f, readInput, readPacket)
	states := map[string]string{}
	for _, card := range current.Relations {
		states[card.GroupID] = card.State
	}
	if current.State != "COMPLETED" || states[d.Policy.GroupID] != "ACTIVE" || states[cr.Target.GroupID] != "REMOVED" {
		t.Fatal("removing the second Group changed the original Group's exact source")
	}
}

func TestEndpointGroupsOwnerRealRemovePreviouslyUnrelatedGroupIsExactlyZeroToOne(t *testing.T) {
	f, d, join := endpointGroupsOwnerTestBusinessFixture(t)
	at := f.now.Add(10 * time.Second)
	create, ci, cr := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, Name: "Synthetic first removal"}, at)
	endpointGroupsOwnerTestApplyBusiness(t, f, create, ci, cr, at.Add(time.Second), nil)
	remove, ri, review := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, GroupID: cr.Target.GroupID, EndpointID: join.Member.EndpointID}, at.Add(2*time.Second))
	if review.Expected.RelationRevision != 0 || review.Expected.DecisionRevision != 0 {
		t.Fatal("zero-history REMOVE review invented an existing aggregate")
	}
	head := e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	_, _, r, _ := endpointGroupsOwnerTestApplyBusiness(t, f, remove, ri, review, at.Add(3*time.Second), &head)
	if r.CurrentRelation == nil || r.CurrentRelation.RelationRevision != 1 || r.CurrentRelation.DecisionRevision != 1 || r.CurrentRelation.State != "REMOVED" {
		t.Fatal("first exact REMOVE was rejected or incremented its aggregate twice")
	}
}

func TestEndpointGroupsOwnerRealCASRejectConsumesReviewWithoutEffects(t *testing.T) {
	f, d, _ := endpointGroupsOwnerTestBusinessFixture(t)
	at := f.now.Add(10 * time.Second)
	q, prepared, review := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, Name: "Synthetic stale Network CAS"}, at)
	// Model a separately committed Network configuration change after review.
	if _, err := f.db.db.Exec(`UPDATE networks_v2 SET version=version+1 WHERE id=?`, d.Policy.NetworkID); err != nil {
		t.Fatal(err)
	}
	var firstID string
	for attempt := 0; attempt < 2; attempt++ {
		apply, err := wire.NewOwnerEndpointGroupsApply(f.session, f.scope, q, prepared.Packet, review, f.owner, at.Add(time.Duration(attempt+1)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		in, seal := endpointGroupsOwnerTestInput(t, f, apply, at.Add(time.Duration(attempt+1)*time.Second))
		packet, err := f.db.ProcessHubEndpointGroups(in, seal)
		if err != nil {
			t.Fatal(err)
		}
		r := endpointGroupsOwnerTestOpen(t, f, in, packet)
		if r.State != "REJECTED_FENCED" || r.ErrorCode != "CAS_CONFLICT" || r.Operation == nil || r.Operation.Effect != nil || wire.VerifyOwnerEndpointGroupsOperation(review, in.Packet, *r.Operation, nil) != nil {
			t.Fatal("stale Network CAS produced effects or lost its retained review target")
		}
		if retry, err := f.db.ProcessHubEndpointGroups(in, seal); err != nil || !bytes.Equal(retry, packet) {
			t.Fatal("business rejection did not retain its exact original response", err)
		}
		if attempt == 0 {
			firstID = apply.Context.RequestID
		}
	}
	var state, consumed string
	var groups int
	if err := f.db.db.QueryRow(`SELECT state,consumed_operation_id,(SELECT count(*) FROM groups WHERE id=?) FROM hub_endpoint_groups_reviews_v1 WHERE review_id=?`, review.Target.GroupID, review.ReviewID).Scan(&state, &consumed, &groups); err != nil || state != "CONSUMED" || consumed != firstID || groups != 0 {
		t.Fatal("a new apply ID reused the one-use rejected review", err)
	}
}

func TestEndpointGroupsOwnerRealInventoryPaginationRejectsStaleCursor(t *testing.T) {
	f, d, join := endpointGroupsOwnerTestBusinessFixture(t)
	at := f.now.Add(10 * time.Second)
	read := func(body wire.OwnerEndpointGroupsReadBody, offset time.Duration) wire.OwnerEndpointGroupsResult {
		t.Helper()
		q, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, body, f.owner, at.Add(offset))
		if err != nil {
			t.Fatal(err)
		}
		in, seal := endpointGroupsOwnerTestInput(t, f, q, at.Add(offset))
		packet, err := f.db.ProcessHubEndpointGroups(in, seal)
		if err != nil {
			t.Fatal(err)
		}
		return endpointGroupsOwnerTestOpen(t, f, in, packet)
	}
	body := wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID}
	threads := read(body, 0)
	if threads.State != "COMPLETED" || len(threads.Threads) != 1 || threads.Threads[0].EndpointID != join.Member.EndpointID || threads.Threads[0].PrincipalID != join.Member.PrincipalID || len(threads.Threads[0].Relations) != 1 || threads.Threads[0].Relations[0].State != "ACTIVE" {
		t.Fatal("private Thread inventory lost the original enrolled identity/source", threads.ErrorCode)
	}
	create := func(name string, offset time.Duration) {
		q, prepared, review := endpointGroupsOwnerTestPrepareBusiness(t, f, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: d.Policy.Node.NodeID, NetworkID: d.Policy.NetworkID, Name: name}, at.Add(offset))
		endpointGroupsOwnerTestApplyBusiness(t, f, q, prepared, review, at.Add(offset+time.Second), nil)
	}
	create("Synthetic paginated Group one", time.Second)
	body.View, body.EndpointID, body.Limit = "CANDIDATE_GROUPS", join.Member.EndpointID, 1
	first := read(body, 3*time.Second)
	if first.State != "COMPLETED" || len(first.Groups) != 1 || first.NextCursor == "" {
		t.Fatal("candidate Group inventory did not paginate current ACTIVE Groups", first.ErrorCode)
	}
	body.Cursor = first.NextCursor
	second := read(body, 4*time.Second)
	if second.State != "COMPLETED" || len(second.Groups) != 1 || second.Groups[0].GroupID == first.Groups[0].GroupID || second.NextCursor != "" {
		t.Fatal("candidate Group pagination duplicated or skipped its exact snapshot", second.ErrorCode)
	}
	create("Synthetic paginated Group two", 5*time.Second)
	stale := read(body, 7*time.Second)
	if stale.State != "REJECTED_FENCED" || stale.ErrorCode != "CURSOR_STALE" || len(stale.Groups) != 0 || stale.ScopeActions != nil {
		t.Fatal("changed Group inventory accepted an old scope-bound cursor")
	}
	body.View, body.Cursor, body.Limit = "RELATIONS", "", 64
	relations := read(body, 8*time.Second)
	if relations.State != "COMPLETED" || relations.RelationPage == nil || !relations.RelationPage.Complete || len(relations.Relations) != 1 || relations.Relations[0].GroupID != d.Policy.GroupID {
		t.Fatal("relation pages lost explicit terminal-state scope", relations.ErrorCode)
	}
}
