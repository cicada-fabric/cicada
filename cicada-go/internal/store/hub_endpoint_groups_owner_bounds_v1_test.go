package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These helpers test only ledger retention/capacity. They do not invoke or
// substitute the separately implemented business authorization helpers.
func endpointGroupsOwnerTestCacheRead(t *testing.T, f *n3StoreFixture, at time.Time) (wire.OwnerEndpointGroupsReadRequest, HubEndpointGroupsInput, error) {
	t.Helper()
	q, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, wire.OwnerEndpointGroupsReadBody{View: "THREADS", NodeID: "synthetic-ledger-node", NetworkID: "synthetic-ledger-network"}, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := endpointGroupsOwnerTestInput(t, f, q, at)
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	request, err := endpointGroupsOwnerInput(tx, in)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerResult(in, request, "COMPLETED", "")
	r.ScopeActions = &wire.OwnerEndpointGroupsScopeActions{NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID}
	packet, err := seal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = endpointGroupsOwnerSaveReadTx(tx, in, request, r, packet); err != nil {
		return q, in, err
	}
	err = tx.Commit()
	return q, in, err
}

func TestEndpointGroupsOwnerReadPayloadEvictionKeepsPermanentExactFloor(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	var first wire.OwnerEndpointGroupsReadRequest
	var original HubEndpointGroupsInput
	for i := 0; i < 128; i++ {
		q, in, err := endpointGroupsOwnerTestCacheRead(t, f, f.now.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatal("bounded read cache fill", err)
		}
		if i == 0 {
			first, original = q, in
		}
	}
	if _, _, err := endpointGroupsOwnerTestCacheRead(t, f, f.now.Add(time.Minute)); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("live cache saturation evicted an original", err)
	}
	// Advance beyond the actual 300 second cache boundary. The exact old
	// request gets READ_EXPIRED and cannot be executed as a new read.
	_, route, err := wire.NewClientRoute(f.hub, first, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	original.At = f.now.Add(301 * time.Second)
	seal := func(v any) ([]byte, error) { return wire.SealResponse(f.hubPrivate, f.device.Public(), route, v) }
	packet, err := f.db.ProcessHubEndpointGroups(original, seal)
	if err != nil {
		t.Fatal(err)
	}
	r := endpointGroupsOwnerTestOpen(t, f, original, packet)
	if r.State != "READ_EXPIRED" || r.ScopeActions != nil || len(r.Threads)+len(r.Groups)+len(r.Relations) != 0 {
		t.Fatal("expired read was silently refreshed")
	}
	if _, _, err := endpointGroupsOwnerTestCacheRead(t, f, f.now.Add(302*time.Second)); err != nil {
		t.Fatal("expired payload cache did not reclaim bounded space", err)
	}
	var cached, floors int
	if err := f.db.db.QueryRow(`SELECT (SELECT count(*) FROM hub_endpoint_groups_owner_reads_v1),(SELECT count(*) FROM hub_endpoint_groups_owner_nonces_v1)`).Scan(&cached, &floors); err != nil || cached != 1 || floors != 129 {
		t.Fatal("cache cleanup removed permanent request floors", err)
	}
	changed, err := wire.NewOwnerEndpointGroupsRead(f.session, f.scope, first.Body, f.owner, f.now.Add(303*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	changed.Context.RequestID = first.Context.RequestID
	// Re-sign fresh request claims with the old ID. A fresh proof or login
	// cannot reset that ID's old ciphertext binding after cache eviction.
	changed = endpointGroupsOwnerTestResignReadID(t, f, changed, first.Context.RequestID)
	changedInput, changedSeal := endpointGroupsOwnerTestInput(t, f, changed, f.now.Add(303*time.Second))
	if _, err := f.db.ProcessHubEndpointGroups(changedInput, changedSeal); !errors.Is(err, ErrHubEndpointGroupsPacketConflict) {
		t.Fatal("fresh proof reused an evicted original ID", err)
	}
}

func endpointGroupsOwnerTestResignReadID(t *testing.T, f *n3StoreFixture, q wire.OwnerEndpointGroupsReadRequest, id string) wire.OwnerEndpointGroupsReadRequest {
	t.Helper()
	var p e2ee.OwnerEndpointGroupsRequestProof
	if json.Unmarshal(q.OwnerProof, &p) != nil {
		t.Fatal("synthetic Owner proof decode")
	}
	q.Context.RequestID, p.Claims.RequestID = id, id
	proof, err := e2ee.SignOwnerEndpointGroupsRequest(f.owner, p.Claims)
	if err != nil {
		t.Fatal(err)
	}
	q.OwnerProof = proof
	return q
}

func endpointGroupsOwnerTestInsertReview(t *testing.T, f *n3StoreFixture, at time.Time) wire.OwnerEndpointGroupsReview {
	t.Helper()
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-ledger-node", NetworkID: "synthetic-ledger-network", Name: "Synthetic bounded review"}, f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := endpointGroupsOwnerTestInput(t, f, q, at)
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	r := wire.OwnerEndpointGroupsReview{ReviewID: id, RequestID: q.Context.RequestID, RequestPacketDigest: wire.OwnerEndpointGroupsPacketDigest(in.Packet), Action: q.Body.Action, Target: wire.OwnerEndpointGroupsTarget{HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, GroupID: "synthetic-group-" + id, Name: q.Body.Name, ContextPolicy: "group_scoped"}, Expected: wire.OwnerEndpointGroupsCAS{OwnerKeyVersion: f.scope.OwnerKeyVersion, NodeOwnerBindingID: "synthetic-ledger-binding", NodeOwnerBindingVersion: 1, NodeKeyEpoch: 1, NetworkVersion: 1}, Projection: wire.OwnerEndpointGroupsProjection{GroupID: "synthetic-group-" + id, Name: q.Body.Name, ContextPolicy: "group_scoped", OwnerManagementOnly: &yes}, ObservedAt: appNodeStamp(at), ExpiresAt: appNodeStamp(at.Add(5 * time.Minute))}
	r.ReviewDigest, err = wire.OwnerEndpointGroupsReviewDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if wire.ValidateOwnerEndpointGroupsReview(q, in.Packet, r, f.hub, at) != nil {
		t.Fatal("synthetic bounded review is not structurally valid")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.db.Exec(`INSERT INTO hub_endpoint_groups_reviews_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.ReviewID, f.scope.OwnerID, f.scope.AccountID, f.scope.DeviceID, f.scope.AccountEpoch, f.scope.DeviceEpoch, f.scope.OwnerKeyVersion, q.Context.RequestID, r.RequestPacketDigest, q.OwnerProof, string(raw), r.ExpiresAt, "PREPARED", "", appNodeStamp(at))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEndpointGroupsOwnerReviewBoundExpiryAndImmutableCoordinates(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	var first wire.OwnerEndpointGroupsReview
	for i := 0; i < 64; i++ {
		r := endpointGroupsOwnerTestInsertReview(t, f, f.now)
		if i == 0 {
			first = r
		}
	}
	q, err := wire.NewOwnerEndpointGroupsPrepare(f.session, f.scope, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, NodeID: "synthetic-ledger-node", NetworkID: "synthetic-ledger-network", Name: "Synthetic extra review"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := endpointGroupsOwnerTestInput(t, f, q, f.now)
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	request, err := endpointGroupsOwnerInput(tx, in)
	if err != nil {
		t.Fatal(err)
	}
	if err = endpointGroupsOwnerReviewCapacityTx(tx, request, f.now); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("live review cap was not 64", err)
	}
	tx.Rollback()
	for _, query := range []string{`UPDATE hub_endpoint_groups_reviews_v1 SET review_json='{}' WHERE review_id=?`, `UPDATE hub_endpoint_groups_reviews_v1 SET expires_at='2999-01-01T00:00:00Z' WHERE review_id=?`, `DELETE FROM hub_endpoint_groups_reviews_v1 WHERE review_id=?`} {
		if _, err := f.db.db.Exec(query, first.ReviewID); err == nil {
			t.Fatal("review coordinates/history changed")
		}
	}
	tx, err = f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = endpointGroupsOwnerReviewCapacityTx(tx, request, f.now.Add(301*time.Second)); err != nil {
		t.Fatal("expired reviews continued blocking new intent", err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var live, expired int
	if err = f.db.db.QueryRow(`SELECT sum(state='PREPARED'),sum(state='EXPIRED') FROM hub_endpoint_groups_reviews_v1`).Scan(&live, &expired); err != nil || live != 0 || expired != 64 {
		t.Fatal("review expiry did not preserve immutable history", err)
	}
	if _, err = f.db.db.Exec(`UPDATE hub_endpoint_groups_reviews_v1 SET state='PREPARED' WHERE review_id=?`, first.ReviewID); err == nil {
		t.Fatal("expired review was revived")
	}
}

func TestEndpointGroupsOwnerRateBoundDoesNotResetWithRequestIDs(t *testing.T) {
	f := endpointGroupsOwnerTestFixture(t)
	for i := 0; i < 128; i++ {
		tx, err := f.db.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err = endpointGroupsOwnerRateTx(tx, f.scope, f.now); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = endpointGroupsOwnerRateTx(tx, f.scope, f.now); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("profile rate exceeded 128 per authority epoch", err)
	}
	tx.Rollback()
	tx, err = f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = endpointGroupsOwnerRateTx(tx, f.scope, f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = f.db.db.QueryRow(`SELECT requests FROM hub_endpoint_groups_owner_rates_v1 WHERE owner_id=? AND device_id=?`, f.scope.OwnerID, f.scope.DeviceID).Scan(&count); err != nil || count != 1 {
		t.Fatal("bounded rate window did not advance", err)
	}
}
