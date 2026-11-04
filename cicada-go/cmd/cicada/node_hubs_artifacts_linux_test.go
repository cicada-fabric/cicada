package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installRetainedArtifactEntry(t *testing.T, p LocalNodeConnectionPin) nodeHubRegistryEntry {
	t.Helper()
	ctx := context.Background()
	if err := initializeNodeHubRegistry(ctx, p.UserRoot); err != nil {
		t.Fatal(err)
	}
	e := nodeHubRegistryEntry{ConnectionID: p.ConnectionID, Alias: "synthetic-retained", HubID: p.HubID, NodeID: p.NodeID, NodeName: "Synthetic Node", HubAddress: p.HubDialAddress, Origin: p.APIOrigin, StateDir: p.StateDir, WriterRoot: p.WriterRoot, MCPSessionStateFile: p.MCPSessionStateFile, MCPOutboxStateFile: p.MCPOutboxStateFile, DesiredState: "ENABLED", LocalFence: p.ConnectionEpoch}
	if e.HubAddress == "" {
		e.HubAddress = "127.0.0.1:20000"
	}
	if _, err := mutateNodeHubRegistry(ctx, p.UserRoot, func(_ *os.Root, r *nodeHubRegistry) error {
		r.NodeID = p.NodeID
		r.WriterRoot = p.WriterRoot
		r.Connections = []nodeHubRegistryEntry{e}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeNodeHubStateReference(ctx, p.UserRoot, e); err != nil {
		t.Fatal(err)
	}
	if p.ConnectionEpoch > 1 {
		previous := e
		previous.DesiredState = "REMOVING"
		previous.LocalFence--
		retired := nodeHubRetired{"cicada.node-hub-retired.v1", previous, LocalNodeHubRemoval{Format: LocalNodeHubRemovalFormat, ConnectionID: p.ConnectionID, HubID: p.HubID, NodeID: p.NodeID, LocalFence: previous.LocalFence, State: "LOCAL_STOPPED", RemoteRevocation: "NOT_REQUESTED"}}
		r, _, err := nodeHubRoot(ctx, p.UserRoot, false)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if err = saveNodeHubRetired(r, retired); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestRetainedLocalNodeArtifactsManagedStorageOnly(t *testing.T) {
	ctx := context.Background()
	root := privateLocalNodeRoot(t)
	current := syntheticLocalNodePin(t, root, "synthetic-node")
	current.ConnectionID = strings.Repeat("c", 32)
	current.ConnectionEpoch = 3
	e := installRetainedArtifactEntry(t, current)
	historical := current
	historical.ConnectionEpoch = 1
	if ValidateRetainedLocalNodeArtifacts(ctx, historical, current) == nil {
		t.Fatal("configured metadata accepted without live pin")
	}
	mockLocalNode(t, current, nil, false)
	for _, path := range []string{current.MCPSessionStateFile, current.MCPOutboxStateFile, current.MCPOutboxStateFile + "-wal"} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("SYNTHETIC retained raw bytes\x00\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateRetainedLocalNodeArtifacts(ctx, historical, current); err != nil {
		t.Fatal("retained original storage refused", err)
	}
	if sameLocalNodeAuthority(historical, current) {
		t.Fatal("storage validation widened live authority equality")
	}
	if _, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: root, HubID: current.HubID, NodeID: current.NodeID}, &historical); err == nil {
		t.Fatal("old live pin became usable")
	}
	if checkManagedLocalNodePin(ctx, historical) == nil {
		t.Fatal("old caller epoch became current")
	}
	for name, change := range map[string]func(*LocalNodeConnectionPin){
		"other connection": func(p *LocalNodeConnectionPin) { p.ConnectionID = strings.Repeat("d", 32) },
		"other Hub":        func(p *LocalNodeConnectionPin) { p.HubID = "synthetic-other" },
		"binding epoch":    func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyEpoch++ },
		"binding version":  func(p *LocalNodeConnectionPin) { p.Binding.BindingVersion++ },
		"key version":      func(p *LocalNodeConnectionPin) { p.Binding.NodeKeyVersion++ },
		"outbox path":      func(p *LocalNodeConnectionPin) { p.MCPOutboxStateFile = filepath.Join(root, "other.sqlite3") },
		"future epoch":     func(p *LocalNodeConnectionPin) { p.ConnectionEpoch = 5 },
		"unproved Pin0":    func(p *LocalNodeConnectionPin) { p.ConnectionID = ""; p.ConnectionEpoch = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := historical
			change(&bad)
			if ValidateRetainedLocalNodeArtifacts(ctx, bad, current) == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
	// Modify all receipt indexes consistently: the validator must require stop
	// success and the immediate re-add successor, not merely a matching CID.
	files, err := filepath.Glob(filepath.Join(root, "node-hub-retired-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatal("retirement indexes missing")
	}
	saved := map[string][]byte{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		saved[p] = b
	}
	for _, kind := range []string{"pending", "wrong successor", "changed private path"} {
		t.Run(kind, func(t *testing.T) {
			for path, b := range saved {
				var r nodeHubRetired
				if json.Unmarshal(b, &r) != nil {
					t.Fatal("invalid fixture")
				}
				switch kind {
				case "pending":
					r.Removal.State = "STOP_PENDING"
				case "wrong successor":
					r.Entry.LocalFence = 1
					r.Removal.LocalFence = 1
				case "changed private path":
					r.Entry.MCPOutboxStateFile = filepath.Join(root, "other.sqlite3")
				}
				changed, _ := json.Marshal(r)
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if ValidateRetainedLocalNodeArtifacts(ctx, historical, current) == nil {
				t.Fatal("unproved stop/re-add accepted")
			}
			for path, b := range saved {
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if _, err = mutateNodeHubRegistry(ctx, root, func(_ *os.Root, r *nodeHubRegistry) error { r.Connections[0].DesiredState = "REMOVING"; return nil }); err != nil {
		t.Fatal(err)
	}
	if ValidateRetainedLocalNodeArtifacts(ctx, historical, current) == nil {
		t.Fatal("REMOVING entry reused storage")
	}
	if _, err = mutateNodeHubRegistry(ctx, root, func(_ *os.Root, r *nodeHubRegistry) error { r.Connections[0] = e; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current.MCPSessionStateFile, current.MCPOutboxStateFile, current.MCPOutboxStateFile + "-wal"} {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, []byte("SYNTHETIC retained raw bytes\x00\n")) {
			t.Fatal("storage validation changed original artifact", err)
		}
	}
}

func TestRetainedLocalNodeArtifactsPin0ProvenanceAndLiveFence(t *testing.T) {
	for _, epoch := range []uint64{1, 3} {
		t.Run(string(rune('0'+epoch)), func(t *testing.T) {
			f := newNodeLifecycleFixture(t)
			f.save(t)
			old, err := nodeHubOriginalPin(f.c, f.s)
			if err != nil {
				t.Fatal(err)
			}
			originalRaw, err := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(originalRaw)
			current := old
			current.ConnectionID = strings.Repeat("e", 32)
			current.ConnectionEpoch = epoch
			e := installRetainedArtifactEntry(t, current)
			adopted := current
			adopted.ConnectionEpoch = 1
			proof := nodeHubAdoptionReceipt{"cicada.node-hub-adoption.v1", hex.EncodeToString(digest[:]), nodeServiceUnit(f.c, f.s), 0, old, adopted}
			r, _, err := nodeHubRoot(context.Background(), f.c.UserRoot, false)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			b, _ := json.Marshal(proof)
			if err = writeNodeHubAtomic(r, nodeHubAdoptionName(e.ConnectionID), b, nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err = ensureNodeHubAdoptionService(r, f.c.UserRoot, f.c, proof.OriginalConfigDigest, nodeHubServiceConfig{}, originalRaw, false); err != nil {
				t.Fatal(err)
			}
			mockLocalNode(t, current, nil, false)
			keyPath, _ := machineNodeControlPaths(f.s.state, f.s.id)
			before, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			if err = ValidateRetainedLocalNodeArtifacts(context.Background(), old, current); err != nil {
				t.Fatal("original adopted storage refused", err)
			}
			if sameLocalNodeAuthority(old, current) || checkManagedLocalNodePin(context.Background(), old) == nil {
				t.Fatal("Pin0 gained live authority")
			}
			if epoch == 3 {
				if _, err = ResolveAdoptedLocalNodeConnection(context.Background(), old); err == nil {
					t.Fatal("adoption resolver widened past epoch1")
				}
			}
			proof.OriginalPID = 123
			b, _ = json.Marshal(proof)
			if err = os.WriteFile(filepath.Join(f.c.UserRoot, nodeHubAdoptionName(e.ConnectionID)), b, 0600); err != nil {
				t.Fatal(err)
			}
			if ValidateRetainedLocalNodeArtifacts(context.Background(), old, current) == nil {
				t.Fatal("forged adoption provenance accepted")
			}
			after, err := os.ReadFile(keyPath)
			defer clear(after)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("storage validation replaced original identity", err)
			}
			if !errors.Is(ValidateRetainedLocalNodeArtifacts(nil, old, current), ErrLocalNodeBindingChanged) {
				t.Fatal("nil context accepted")
			}
		})
	}
}
