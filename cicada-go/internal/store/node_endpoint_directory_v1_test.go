package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/nodewire"
)

func TestNodeEndpointDirectoryOwnScopeSelfReadAndRevocation(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	self, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, 1), endpointRegistration())
	if err != nil {
		t.Fatal(err)
	}
	// Disposable metadata rows exercise filtering before LIMIT. This fixture
	// does not represent a second approved production Node or Owner ceremony.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := insertNetworkNativeEndpointTx(tx, b.OwnerID, "", "foreign-node-name", "codex", "synthetic-other-node", "other-node", "/private/other-node", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := insertNetworkNativeEndpointTx(tx, "foreign-owner", "", "foreign-owner-name", "codex", "synthetic-other-owner", b.NodeID, "/private/other-owner", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE fabric_endpoints SET id='000-other-node' WHERE id=?`, other); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE fabric_endpoints SET id='001-other-owner' WHERE id=?`, foreign); err != nil {
		t.Fatal(err)
	}
	other = "000-other-node"
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	page, err := s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 2), nodewire.EndpointDirectoryRequest{Limit: 1})
	if err != nil || len(page.Endpoints) != 1 || page.Endpoints[0].EndpointID != self.EndpointID || page.NextCursor != "" || page.Freshness != "SNAPSHOT_ONLY" {
		t.Fatal("Node scope was not applied before bound", err)
	}
	encoded, _ := json.Marshal(page)
	if strings.Contains(string(encoded), "/private/other") {
		t.Fatal("other Node/Owner metadata leaked")
	}
	if _, err = s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 3), nodewire.EndpointDirectoryRequest{Cursor: other}); !errors.Is(err, nodewire.ErrEndpointUnavailable) {
		t.Fatal("foreign cursor accepted", err)
	}
	q := nodewire.EndpointDirectoryRequest{Harness: "codex", NativeSessionID: endpointRegistration().NativeSessionID, Limit: 1}
	current, err := s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 4), q)
	if err != nil || len(current.Endpoints) != 1 || current.Endpoints[0].StateDigest != self.StateDigest || current.Endpoints[0].Presence != "offline" {
		t.Fatal("exact self state changed authority", err)
	}
	var before, after int
	if err = s.db.QueryRow(`SELECT count(*) FROM fabric_endpoints`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	q.NativeSessionID = "synthetic-not-registered"
	absent, err := s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 5), q)
	if err = s.db.QueryRow(`SELECT count(*) FROM fabric_endpoints`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err != nil || len(absent.Endpoints) != 0 || before != after {
		t.Fatal("self lookup created an Endpoint", err)
	}
	pending := endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 6)
	if _, err = s.RevokeNodeDeviceBinding(b.OwnerID, b.OwnerBindingID, int64(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ListNodeEndpoints(pending, nodewire.EndpointDirectoryRequest{}); err == nil {
		t.Fatal("admitted read survived committed revocation")
	}
}

func TestNodeEndpointDirectoryLongPathsAndStableCursor(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	for i := 0; i < 16; i++ {
		q := endpointRegistration()
		q.NativeSessionID = fmt.Sprintf("synthetic-page-%02d", i)
		q.Workspace = "/synthetic/" + strings.Repeat("private-path", 330)
		if _, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, nodewire.EndpointRegisterOperation, uint64(i+1)), q); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 17), nodewire.EndpointDirectoryRequest{Limit: 64})
	if err != nil || len(page.Endpoints) == 0 || len(page.Endpoints) >= 16 || page.NextCursor != page.Endpoints[len(page.Endpoints)-1].EndpointID {
		t.Fatal("long-path page cursor", err)
	}
	raw, _ := json.Marshal(page)
	if len(raw) > nodewire.MaxEndpointDirectoryBytes {
		t.Fatal("complete page exceeded byte limit")
	}
	next, err := s.ListNodeEndpoints(endpointRPC(t, s, b, digest, nodewire.EndpointDirectoryOperation, 18), nodewire.EndpointDirectoryRequest{Cursor: page.NextCursor, Limit: 64})
	if err != nil || len(next.Endpoints) == 0 || next.Endpoints[0].EndpointID <= page.NextCursor {
		t.Fatal("cursor repeated previous rows", err)
	}
}
