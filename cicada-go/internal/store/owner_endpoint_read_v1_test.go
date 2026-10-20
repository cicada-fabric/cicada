package store

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func ownerReadFixtureEndpoint(t *testing.T, f *nativePairStoreFixture, sid, name, workspace string, seq uint64) *nodewire.EndpointRegistrationResult {
	t.Helper()
	var digest string
	if err := f.f.db.db.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=?`, f.scope.Node.OwnerBindingID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	b, err := f.f.db.NodeControlKeyForCredential(digest, f.scope.Node.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.f.db.RegisterNodeEndpoint(endpointRPC(t, f.f.db, b, digest, nodewire.EndpointRegisterOperation, seq), nodewire.EndpointRegistration{Harness: "codex", NativeSessionID: sid, Name: name, Workspace: workspace})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ownerReadInput(t *testing.T, f *nativePairStoreFixture, cursor string, limit int, at time.Time) (OwnerEndpointReadInput, HubAppNodeSeal) {
	t.Helper()
	q, err := wire.NewOwnerEndpointRead(f.f.session, f.scope.Actor, f.scope.Node, cursor, limit, f.f.owner, at)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(f.f.device, f.f.hub, q)
	if err != nil {
		t.Fatal(err)
	}
	p, err := wire.DecodePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	return OwnerEndpointReadInput{Hub: f.f.hub, NodeControlPublic: f.f.nodeControl.Public(), Device: f.f.device.Public(), Packet: packet, Request: q, At: at}, func(body any) ([]byte, error) {
		return wire.SealResponse(f.f.hubPrivate, f.f.device.Public(), p.Packet.Route, body)
	}
}

func ownerReadResult(t *testing.T, f *nativePairStoreFixture, in OwnerEndpointReadInput, seal HubAppNodeSeal) (wire.OwnerEndpointReadResult, []byte) {
	t.Helper()
	raw, err := f.f.db.ReadOwnerEndpoints(in, seal)
	if err != nil {
		t.Fatal(err)
	}
	var out wire.OwnerEndpointReadResult
	if wire.OpenClientResponse(f.f.device, in.Hub, in.Packet, raw, &out) != nil || wire.VerifyOwnerEndpointReadResult(out, in.Request, in.Packet) != nil {
		t.Fatal("Owner read did not bind original proof/packet")
	}
	return out, raw
}

func TestOwnerEndpointReadZeroRightsPagingLongPathsAndExactRetry(t *testing.T) {
	f := nativePairStore(t)
	for i := 0; i < 16; i++ {
		ownerReadFixtureEndpoint(t, f, fmt.Sprintf("synthetic-private-%02d", i), fmt.Sprintf("原线程%02d", i), "/synthetic/"+strings.Repeat("long-path", 420), uint64(i+1))
	}
	if f.f.db.CheckAppLease(f.scope.Actor.OwnerID, f.scope.Actor.DeviceID, "nodes.list") == nil {
		t.Fatal("synthetic old N2 lease should already be expired")
	}
	in, seal := ownerReadInput(t, f, "", 64, f.at)
	first, original := ownerReadResult(t, f, in, seal)
	if first.State != wire.AppNodeCompleted || len(first.Endpoints) == 0 || len(first.Endpoints) >= 16 || first.NextCursor != first.Endpoints[len(first.Endpoints)-1].EndpointID {
		t.Fatal("long path page did not end at last actual row")
	}
	for _, card := range first.Endpoints {
		if card.Presence != "offline" {
			t.Fatal("zero registration claimed online native lease")
		}
	}
	if repeat, err := f.f.db.ReadOwnerEndpoints(in, seal); err != nil || !bytes.Equal(original, repeat) {
		t.Fatal("lost-response exact retry changed snapshot", err)
	}
	secondInput, secondSeal := ownerReadInput(t, f, first.NextCursor, 64, f.at.Add(time.Second))
	second, _ := ownerReadResult(t, f, secondInput, secondSeal)
	if len(second.Endpoints) == 0 || second.Endpoints[0].EndpointID <= first.NextCursor {
		t.Fatal("stable cursor repeated an earlier row")
	}
	var permissions int
	if err := f.f.db.db.QueryRow(`SELECT (SELECT count(*) FROM memberships)+(SELECT count(*) FROM endpoint_group_memberships)+(SELECT count(*) FROM endpoint_network_memberships_v2)+(SELECT count(*) FROM session_bindings)+(SELECT count(*) FROM endpoint_key_candidates_v2)`).Scan(&permissions); err != nil || permissions != 0 {
		t.Fatal("read or registration created business authority", permissions, err)
	}
	if f.f.db.CheckAppLease(f.scope.Actor.OwnerID, f.scope.Actor.DeviceID, "nodes.list") == nil {
		t.Fatal("new Owner read renewed old N2 operations")
	}
	// Restart retains original private receipt, without re-signing authority.
	if err := f.f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.f.db, err = New(f.f.path)
	if err != nil {
		t.Fatal(err)
	}
	if repeat, err := f.f.db.ReadOwnerEndpoints(in, seal); err != nil || !bytes.Equal(original, repeat) {
		t.Fatal("restart changed exact read receipt", err)
	}
	if _, err = f.f.db.RevokeNodeDeviceBinding(f.scope.Actor.OwnerID, f.scope.Node.OwnerBindingID, int64(f.scope.Node.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err = f.f.db.ReadOwnerEndpoints(in, seal); err == nil {
		t.Fatal("revocation returned cached private paths")
	}
}

func TestOwnerEndpointReadRequestFencesAndExpiredProof(t *testing.T) {
	f := nativePairStore(t)
	ownerReadFixtureEndpoint(t, f, "synthetic-own", "原线程", "/synthetic/own", 1)
	in, seal := ownerReadInput(t, f, "", 64, f.at)
	changed := in
	changed.Request.Context.RequestID = strings.Repeat("1", 32)
	if _, err := f.f.db.ReadOwnerEndpoints(changed, seal); err == nil {
		t.Fatal("Owner proof moved to a new request")
	}
	changed = in
	changed.Now = func() time.Time { return f.at.Add(2 * time.Minute) }
	expired, _ := ownerReadResult(t, f, changed, seal)
	if expired.State != wire.AppNodeReadExpired || len(expired.Endpoints) != 0 || expired.NextCursor != "" {
		t.Fatal("expired one-shot proof read fresh paths")
	}
	wrongCursor, wrongSeal := ownerReadInput(t, f, "endpoint-of-another-node", 64, f.at.Add(time.Second))
	if _, err := f.f.db.ReadOwnerEndpoints(wrongCursor, wrongSeal); err == nil {
		t.Fatal("foreign/stale cursor accepted")
	}
	if _, err := wire.NewOwnerEndpointRead(f.f.session, f.scope.Actor, f.scope.Node, "", 65, f.f.owner, f.at); err == nil {
		t.Fatal("unbounded page signed")
	}
	if _, err := wire.NewOwnerEndpointRead(f.f.session, f.scope.Actor, f.scope.Node, "", 64, f.f.device, f.at); err == nil {
		t.Fatal("App device key substituted for Owner")
	}
}

func TestOwnerEndpointReadCacheBackpressureIsTemporary(t *testing.T) {
	f := nativePairStore(t)
	tx, err := f.f.db.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	c := wire.AppNodeRequestContext{OwnerID: f.scope.Actor.OwnerID, DeviceID: f.scope.Actor.DeviceID}
	for i := 0; i < 128; i++ {
		c.RequestID = fmt.Sprintf("%032x", i+1)
		if err = appNodeSaveRead(tx, c, wire.OperationOwnerEndpointRead, strings.Repeat("a", 64), wire.AppNodeCompleted, []byte("synthetic retained PQ receipt"), f.at); err != nil {
			t.Fatal(err)
		}
	}
	c.RequestID = strings.Repeat("f", 32)
	if err = appNodeSaveRead(tx, c, wire.OperationAppNodeStatus, strings.Repeat("b", 64), wire.AppNodeCompleted, []byte("synthetic status receipt"), f.at.Add(time.Second)); !errors.Is(err, ErrHubOwnerDiagnosticsFull) {
		t.Fatal("live exact receipt was evicted", err)
	}
	if err = appNodeSaveRead(tx, c, wire.OperationAppNodeStatus, strings.Repeat("b", 64), wire.AppNodeCompleted, []byte("synthetic status receipt"), f.at.Add(91*time.Second)); err != nil {
		t.Fatal("read capacity became a lifetime quota", err)
	}
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=?`, c.OwnerID, c.DeviceID).Scan(&n); err != nil || n != 128 {
		t.Fatal("read cache bound changed", n, err)
	}
}
