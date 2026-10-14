package hubidentity

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func identityPaths(state, peer string) []string {
	if peer == "" {
		peer = filepath.Join(state, "e2ee", "identity.json")
	}
	return []string{peer, filepath.Join(state, "e2ee", "client-control-identity.json"), filepath.Join(state, "e2ee", "node-control-identity.json")}
}
func TestHubIdentityExistingFilesAndPeerOverrideArePreserved(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	peer := filepath.Join(root, "custom", "peer.json")
	first, err := LoadOrCreate(state, peer)
	if err != nil {
		t.Fatal(err)
	}
	paths := identityPaths(state, peer)
	saved := make([][]byte, len(paths))
	for i, p := range paths {
		saved[i], err = os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	second, err := LoadOrCreate(state, peer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Peer.Public(), second.Peer.Public()) || !reflect.DeepEqual(first.ClientControl.Public(), second.ClientControl.Public()) || !reflect.DeepEqual(first.NodeControl.Public(), second.NodeControl.Public()) {
		t.Fatal("existing Hub identities changed")
	}
	for i, p := range paths {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, saved[i]) {
			t.Fatal("existing private file bytes changed")
		}
	}
	if _, err := os.Stat(filepath.Join(state, "e2ee", "identity.json")); !os.IsNotExist(err) {
		t.Fatal("custom peer path silently replaced by default")
	}
	if _, err := os.Stat(filepath.Join(state, "workspace-snapshots")); !os.IsNotExist(err) {
		t.Fatal("identity loader created business workspace")
	}
}
func TestHubIdentityConcurrentCreationKeepsOneKeySet(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	var wg sync.WaitGroup
	sets := make(chan Set, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids, err := LoadOrCreate(state, "")
			if err != nil {
				errs <- err
				return
			}
			sets <- ids
		}()
	}
	wg.Wait()
	close(sets)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first *Set
	for ids := range sets {
		if first == nil {
			copy := ids
			first = &copy
			continue
		}
		if !reflect.DeepEqual(first.Peer.Public(), ids.Peer.Public()) || !reflect.DeepEqual(first.ClientControl.Public(), ids.ClientControl.Public()) || !reflect.DeepEqual(first.NodeControl.Public(), ids.NodeControl.Public()) {
			t.Fatal("concurrent load rotated an identity")
		}
	}
	if first == nil {
		t.Fatal("no identity set loaded")
	}
	leftovers, _ := filepath.Glob(filepath.Join(state, "e2ee", "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatal("temporary private files remain")
	}
}
func TestHubIdentityFailureDoesNotRepairOrRotateExistingState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_, err := LoadOrCreate(state, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := identityPaths(state, "")
	saved := map[string][]byte{}
	for _, p := range paths {
		saved[p], err = os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	bad := []byte("PUBLIC SYNTHETIC TEST — corrupt existing key must not rotate")
	if err := os.WriteFile(paths[1], bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(state, ""); err == nil {
		t.Fatal("corrupt identity was silently repaired")
	}
	for _, p := range paths {
		got, e := os.ReadFile(p)
		want := saved[p]
		if p == paths[1] {
			want = bad
		}
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("read failure changed retained key state")
		}
	}
	if err := os.WriteFile(paths[1], saved[paths[1]], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths[0]+".lock", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(state, ""); err == nil {
		t.Fatal("unsafe lock file accepted")
	}
	got, _ := os.ReadFile(paths[0])
	if !bytes.Equal(got, saved[paths[0]]) {
		t.Fatal("unsafe lock failure rotated peer")
	}
}
