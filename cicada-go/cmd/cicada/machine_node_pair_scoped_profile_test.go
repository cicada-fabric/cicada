package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairScopedUnavailableCreatesNoSecretStateOrPOST(t *testing.T) {
	for _, kind := range []string{"false", "unknown", "malformed", "wrong_scope", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodePairLocalFixture(t)
			actual := f.server.Config.Handler
			var posts atomic.Int32
			// Install before this fixture's first request; the actual private TLS
			// descriptor and legacy Hub stay intact. No scoped carrier is mocked
			// as successful in this refusal gate.
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				if r.URL.Path != wire.NodePairTrustScopedCapabilitiesPath {
					actual.ServeHTTP(w, r)
					return
				}
				switch kind {
				case "false":
					c := wire.NodePairTrustScopedContractCapabilities()
					c.Available = false
					raw, _ := json.Marshal(c)
					_, _ = w.Write(raw)
				case "unknown":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "malformed":
					_, _ = w.Write([]byte(`{"available":false}`))
				case "wrong_scope":
					c := wire.NodePairTrustScopedContractCapabilities()
					c.Available, c.ScopeVersion = true, 1
					raw, _ := json.Marshal(c)
					_, _ = w.Write(raw)
				case "timeout":
					<-r.Context().Done()
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			profile := "auto"
			if kind == "false" {
				profile = "scoped"
			}
			err := runMachineAgentWithContext(ctx, []string{"--hub-address", f.address, "--state-dir", f.state, "--id", f.node, "--relay-only", "--once", "--pairing-profile", profile}, nil)
			if err == nil || posts.Load() != 0 {
				t.Fatal("unavailable discovery issued a secret POST", posts.Load())
			}
			key, state := machineNodeControlPaths(f.state, f.node)
			for _, path := range []string{machineNodePairScopedStatePath(f.state, f.node), machineNodePairStatePath(f.state, f.node), key, state, machineNodeCredentialPath(f.state, f.node)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unavailable discovery initialized secret state")
				}
			}
		})
	}
}

func TestNodePairScopedSavedFamilyCannotBeChangedByFlag(t *testing.T) {
	f := newNodePairLocalFixture(t)
	c, s := f.pending(t) // explicit legacy compatibility fixture
	defer clear(s.Secret)
	before, err := os.ReadFile(machineNodePairStatePath(f.state, f.node))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectMachineNodePairProfile(context.Background(), f.state, f.node, f.address, "", false, "scoped"); err == nil {
		t.Fatal("saved v1 state was reclassified")
	}
	// A retained independent scoped journal selects only its own family, even
	// before any Context or approval exists. It cannot be parsed as legacy.
	if err := os.Remove(machineNodePairStatePath(f.state, f.node)); err != nil {
		t.Fatal(err)
	}
	scoped := &machineNodePairScopedState{Version: 1, NodeID: f.node, AttemptID: strings.Repeat("b", 32), DescriptorText: f.native.text, DialAddress: f.address, Secret: append([]byte(nil), s.Secret...), Stage: "NEW"}
	defer clear(scoped.Secret)
	if err := saveMachineNodePairScopedState(f.state, c.identity, scoped); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(machineNodePairScopedStatePath(f.state, f.node))
	if _, _, err := selectMachineNodePairProfile(context.Background(), f.state, f.node, f.address, "", false, "legacy"); err == nil {
		t.Fatal("legacy flag discarded a scoped fence")
	}
	after, _ := os.ReadFile(machineNodePairScopedStatePath(f.state, f.node))
	if string(raw) != string(after) {
		t.Fatal("profile rejection changed original scoped bytes")
	}
	if err := os.WriteFile(machineNodePairStatePath(f.state, f.node), before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := machineNodePairSavedProfile(f.state, f.node); err == nil {
		t.Fatal("ambiguous two-family journals accepted")
	}
}

func TestNodePairScopedAutoRecognizesExactUnavailableLegacyHub(t *testing.T) {
	f := newNodePairLocalFixture(t)
	actual := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == wire.NodePairTrustScopedCapabilitiesPath {
			c := wire.NodePairTrustScopedContractCapabilities()
			c.Available = false
			raw, _ := json.Marshal(c)
			_, _ = w.Write(raw)
			return
		}
		actual.ServeHTTP(w, r)
	})
	err := runMachineAgentWithContext(context.Background(), []string{"--hub-address", f.address, "--state-dir", f.state, "--id", f.node, "--relay-only", "--once"}, nil)
	if !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("exact unavailable scoped profile did not select available legacy", err)
	}
	profile, err := machineNodePairSavedProfile(f.state, f.node)
	if err != nil || profile != "legacy" {
		t.Fatal("auto created the wrong family", err)
	}
}
