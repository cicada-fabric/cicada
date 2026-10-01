package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/store"
)

func ownedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := write(filepath.Join(root, ".native-network-owned"), []byte("cicada.native-network.disposable.v1\nsynthetic-test\n")); err != nil {
		t.Fatal(err)
	}
	return root
}
func TestBootstrapCreatesSyntheticAuthorityWithoutEndpoint(t *testing.T) {
	root := ownedRoot(t)
	if err := bootstrap(root); err != nil {
		t.Fatal(err)
	}
	if err := bootstrap(root); err == nil {
		t.Fatal("bootstrap replaced existing fixture")
	}
	m, err := load(root)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(root, "hub-state", "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.GetNetwork(m.NetworkID)
	if err != nil || n.OwnerID != m.OwnerID {
		t.Fatal("synthetic Network owner mismatch")
	}
	endpoints, err := s.ListEndpointsV2(store.EndpointV2Filter{})
	if err != nil || len(endpoints) != 0 {
		t.Fatal("bootstrap invented Endpoint")
	}
	bindings, err := s.ListNodeDeviceBindings(m.OwnerID)
	if err != nil || len(bindings) != 1 || bindings[0].NodeID != m.NodeID {
		t.Fatal("synthetic current Node missing")
	}
	if err := rpc(root, m, "http://127.0.0.1:8787", "topology.delegation_issue", ""); err == nil {
		t.Fatal("operator allowed delegation")
	}
}
func TestPrivateInputsRejectSymlinkAndBroadPermissions(t *testing.T) {
	root := ownedRoot(t)
	path := filepath.Join(root, "private.json")
	if err := write(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := private(alias); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := private(path); err == nil {
		t.Fatal("public file accepted")
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := validate(root); err == nil {
		t.Fatal("public fixture root accepted")
	}
}

func TestDirectoryGrantWorkaroundIsNotAnOperatorAction(t *testing.T) {
	root := ownedRoot(t)
	if err := bootstrap(root); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"grant-group-directory", "--fixture", root}); err == nil || err.Error() != "unknown fixture action" {
		t.Fatalf("removed permission workaround is still exposed: %v", err)
	}
}
