package nodekeys

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestLoadOrCreatePersistsIdentityPerEndpoint(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "node-state")
	first, err := LoadOrCreate(stateDir, "ep_alpha")
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(stateDir, "ep_alpha")
	if err != nil {
		t.Fatal(err)
	}
	if first.Public().ID != second.Public().ID {
		t.Fatalf("reopen changed identity: %q != %q", first.Public().ID, second.Public().ID)
	}
	other, err := LoadOrCreate(stateDir, "ep_beta")
	if err != nil {
		t.Fatal(err)
	}
	if first.Public().ID == other.Public().ID {
		t.Fatal("different Endpoints received the same identity")
	}
	keyDir := filepath.Join(stateDir, keyDirectoryName)
	dirInfo, err := os.Stat(keyDir)
	if err != nil || dirInfo.Mode().Perm() != keyDirectoryMode {
		t.Fatalf("key directory mode=%v err=%v, want 0700", dirInfo, err)
	}
	fileInfo, err := os.Stat(identityPath(keyDir, "ep_alpha"))
	if err != nil || fileInfo.Mode().Perm() != keyFileMode {
		t.Fatalf("identity file mode=%v err=%v, want 0600", fileInfo, err)
	}
}

func TestLoadOrCreateConcurrentCallersKeepOneIdentity(t *testing.T) {
	const callers = 8
	stateDir := filepath.Join(t.TempDir(), "node-state")
	start := make(chan struct{})
	type result struct {
		id  string
		err error
	}
	results := make(chan result, callers)
	var wait sync.WaitGroup
	for i := 0; i < callers; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			identity, err := LoadOrCreate(stateDir, "ep_race")
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{id: identity.Public().ID}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var winner string
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if winner == "" {
			winner = result.id
		} else if result.id != winner {
			t.Fatalf("concurrent callers observed different identities: %q and %q", winner, result.id)
		}
	}
}

func TestLoadOrCreateRejectsTraversalAndEndpointMismatch(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "node-state")
	for _, endpointID := range []string{"", "..", "../ep_escape", "ep/a", `ep\a`, " ep_a"} {
		if _, err := LoadOrCreate(stateDir, endpointID); err == nil {
			t.Errorf("accepted unsafe Endpoint ID %q", endpointID)
		}
	}
	stateTraversal := t.TempDir() + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escaped"
	if _, err := LoadOrCreate(stateTraversal, "ep_a"); err == nil {
		t.Fatal("accepted state directory with parent traversal")
	}

	if _, err := LoadOrCreate(stateDir, "ep_original"); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(stateDir, keyDirectoryName)
	original := identityPath(keyDir, "ep_original")
	misrouted := identityPath(keyDir, "ep_other")
	data, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(misrouted, data, keyFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(stateDir, "ep_other"); err == nil {
		t.Fatal("accepted identity record belonging to another Endpoint")
	}
}

func TestLoadOrCreateRejectsCorruptStateWithoutReplacingIt(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "node-state")
	keyDir := filepath.Join(stateDir, keyDirectoryName)
	if err := os.MkdirAll(keyDir, keyDirectoryMode); err != nil {
		t.Fatal(err)
	}
	path := identityPath(keyDir, "ep_corrupt")
	corrupt := []byte(`{"version":`)
	if err := os.WriteFile(path, corrupt, keyFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(stateDir, "ep_corrupt"); err == nil {
		t.Fatal("accepted corrupt identity record")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, corrupt) {
		t.Fatalf("corrupt identity was replaced: data=%q err=%v", got, err)
	}
}

func TestLoadOrCreateRejectsSymlinksAndInsecureModes(t *testing.T) {
	t.Run("state directory symlink", func(t *testing.T) {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "state-link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := LoadOrCreate(link, "ep_a"); err == nil {
			t.Fatal("accepted symlink state directory")
		}
	})

	t.Run("key directory symlink", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "node-state")
		if err := os.MkdirAll(stateDir, keyDirectoryMode); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if err := os.Symlink(target, filepath.Join(stateDir, keyDirectoryName)); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := LoadOrCreate(stateDir, "ep_a"); err == nil {
			t.Fatal("accepted symlink key directory")
		}
	})

	t.Run("identity file symlink", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "node-state")
		keyDir := filepath.Join(stateDir, keyDirectoryName)
		if err := os.MkdirAll(keyDir, keyDirectoryMode); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "private.json")
		if err := os.WriteFile(target, []byte("{}"), keyFileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, identityPath(keyDir, "ep_a")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := LoadOrCreate(stateDir, "ep_a"); err == nil {
			t.Fatal("accepted symlink identity file")
		}
	})

	t.Run("insecure state directory", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "node-state")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stateDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(stateDir, "ep_a"); err == nil {
			t.Fatal("accepted group/world-writable state directory")
		}
	})

	t.Run("insecure key directory", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "node-state")
		keyDir := filepath.Join(stateDir, keyDirectoryName)
		if err := os.MkdirAll(keyDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(stateDir, "ep_a"); err == nil {
			t.Fatal("accepted group/world-accessible key directory")
		}
	})

	t.Run("insecure identity file", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "node-state")
		keyDir := filepath.Join(stateDir, keyDirectoryName)
		if err := os.MkdirAll(keyDir, keyDirectoryMode); err != nil {
			t.Fatal(err)
		}
		identity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		private, err := identity.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(identityRecord{Version: diskVersion, EndpointID: "ep_a",
			Public: identity.Public(), Private: private})
		if err != nil {
			t.Fatal(err)
		}
		path := identityPath(keyDir, "ep_a")
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(stateDir, "ep_a"); err == nil {
			t.Fatal("accepted group/world-readable identity file")
		}
	})
}
