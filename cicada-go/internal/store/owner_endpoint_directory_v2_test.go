package store

import (
	"errors"
	"testing"
)

func TestOwnerEndpointDirectoryPrivateBoundedAndCurrentGuard(t *testing.T) {
	s, b, digest := recoveryStoreFixture(t)
	for i, sid := range []string{"synthetic-own-a", "synthetic-own-b"} {
		in := endpointRegistration()
		in.NativeSessionID = sid
		if _, err := s.RegisterNodeEndpoint(endpointRPC(t, s, b, digest, "node.endpoint.register", uint64(i+1)), in); err != nil {
			t.Fatal(err)
		}
	}
	// Private foreign rows sort first; SQL must restrict Owner before LIMIT.
	if _, err := s.CreatePrincipal(Principal{ID: "foreign-owner", OwnerID: "foreign-owner", Kind: PrincipalKindHuman, Name: "foreign", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(Principal{ID: "foreign-agent", OwnerID: "foreign-owner", Kind: PrincipalKindAgent, Name: "foreign", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEndpointV2(Endpoint{ID: "000-foreign", Owner: "foreign-owner", PrincipalID: "foreign-agent", Name: "private foreign name", Harness: "codex", NativeSessionID: "synthetic-foreign", Workspace: "/foreign/private", Status: "offline"}); err != nil {
		t.Fatal(err)
	}
	req := clientTopologyAdmissionRequest(t, s, "topology.snapshot", 30)
	rows, truncated, err := s.ListClientOwnerEndpointMetadata(b.OwnerID, req, 1)
	if err != nil || !truncated || len(rows) != 1 || rows[0].Owner != b.OwnerID || rows[0].Workspace != endpointRegistration().Workspace {
		t.Fatal("Owner projection/paging", truncated, err)
	}
	if _, _, err = s.ListClientOwnerEndpointMetadata("foreign-owner", req, 1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("owner selector substituted", err)
	}
	if _, _, err = s.ListClientOwnerEndpointMetadata(b.OwnerID, "", 1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("missing accepted request admitted", err)
	}
	wrong := clientTopologyAdmissionRequest(t, s, "network.directory", 31)
	if _, _, err = s.ListClientOwnerEndpointMetadata(b.OwnerID, wrong, 1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("wrong operation accepted", err)
	}
	if _, err = s.db.Exec(`UPDATE client_devices_v2 SET state='REVOKED' WHERE owner_id=?`, b.OwnerID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ListClientOwnerEndpointMetadata(b.OwnerID, req, 1); !errors.Is(err, ErrNetworkPermission) {
		t.Fatal("revoked device retained private directory", err)
	}
}
