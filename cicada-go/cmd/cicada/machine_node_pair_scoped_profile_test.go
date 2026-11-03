package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestNodePairScopedUnavailableCreatesNoSecretStateOrPOST(t *testing.T) {
	for _, kind := range []string{"false", "false_scoped", "404", "unknown", "malformed", "wrong_scope", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodePairLocalFixture(t)
			actual := f.server.Config.Handler
			var posts, legacyGets atomic.Int32
			// Install before this fixture's first request; the actual private TLS
			// descriptor and legacy Hub stay intact. No scoped carrier is mocked
			// as successful in this refusal gate.
			f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts.Add(1)
				}
				if r.URL.Path == wire.NodePairTrustCapabilitiesPath {
					legacyGets.Add(1)
					c := wire.NodePairTrustContractCapabilities()
					c.Available = true // An old Hub still advertising v1 cannot cause fallback.
					_ = json.NewEncoder(w).Encode(c)
					return
				}
				if r.URL.Path != wire.NodePairTrustScopedCapabilitiesPath {
					actual.ServeHTTP(w, r)
					return
				}
				switch kind {
				case "false", "false_scoped":
					c := wire.NodePairTrustScopedContractCapabilities()
					c.Available = false
					raw, _ := json.Marshal(c)
					_, _ = w.Write(raw)
				case "404":
					w.WriteHeader(http.StatusNotFound)
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
			if kind == "false_scoped" {
				profile = "scoped"
			}
			err := runMachineAgentWithContext(ctx, []string{"--hub-address", f.address, "--state-dir", f.state, "--id", f.node, "--relay-only", "--once", "--pairing-profile", profile}, nil)
			if !errors.Is(err, errMachineNodePairScopedUnavailable) || posts.Load() != 0 || legacyGets.Load() != 0 {
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

func TestNodePairScopedCurrentExplicitRetryKeepsOriginalIdentity(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, old := f.load(t)
	defer clear(old.Secret)
	keyPath, _ := machineNodeControlPaths(f.f.state, f.f.node)
	keyBefore, _ := os.ReadFile(keyPath)
	credentialBefore, _ := os.ReadFile(machineNodeCredentialPath(f.f.state, f.f.node))
	actual := f.f.server.Config.Handler
	var legacyRequests atomic.Int32
	f.f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == wire.NodePairTrustCapabilitiesPath || strings.HasPrefix(req.URL.Path, "/v2/node/pair-trust/") && req.Method == http.MethodPost {
			legacyRequests.Add(1)
		}
		if req.URL.Path == wire.NodePairTrustScopedHTTPPath(wire.OperationNodePairTrustScopedPoll) {
			raw, err := io.ReadAll(req.Body)
			if err != nil {
				t.Error("read synthetic original poll")
				return
			}
			var header wire.NodePairTrustScopedPacket
			_ = json.Unmarshal(raw, &header)
			if header.AttemptID == old.AttemptID {
				body := wire.NewNodePairTrustScopedRequestBody(wire.OperationNodePairTrustScopedPoll)
				h, err := wire.OpenNodePairTrustScopedRequest(f.ids.ClientControl, f.f.native.d.Claims.Hub, raw, wire.OperationNodePairTrustScopedPoll, body, time.Now().UTC())
				if err != nil {
					t.Error("authenticate original scoped poll")
					return
				}
				r := wire.NodePairTrustScopedResult{Format: wire.NodePairTrustScopedFormat, Operation: h.Operation, RequestID: h.RequestID, AttemptID: h.AttemptID, RequestPacketDigest: wire.NodePairTrustScopedPacketDigest(raw), State: wire.NodePairTrustScopedExpired, Context: old.Context, OOBCommitment: old.OOB, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
				receipt, err := wire.SealNodePairTrustScopedResponse(f.ids.ClientControl, f.f.native.d.Claims.Hub, raw, body, r)
				if err != nil {
					t.Error("seal synthetic terminal observation")
					return
				}
				_, _ = w.Write(receipt)
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(raw))
		}
		actual.ServeHTTP(w, req)
	})
	err := prepareMachineNodePairTrust(context.Background(), f.f.state, f.f.node, f.f.node, f.f.address, "", false, true, true, io.Discard, nil, "auto")
	if !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("current explicit retry did not produce the new pending attempt", err)
	}
	_, next := f.load(t)
	defer clear(next.Secret)
	archive, err := loadMachineNodePairScopedStateAtPath(machineNodePairScopedArchivePath(f.f.state, f.f.node, old.AttemptID), f.f.node, c.identity)
	if err != nil {
		t.Fatal("original scoped journal was not archived")
	}
	defer clear(archive.Secret)
	keyAfter, _ := os.ReadFile(keyPath)
	credentialAfter, _ := os.ReadFile(machineNodeCredentialPath(f.f.state, f.f.node))
	if legacyRequests.Load() != 0 || next.AttemptID == old.AttemptID || next.PreviousAttemptID != old.AttemptID || bytes.Equal(next.Secret, old.Secret) || !bytes.Equal(archive.Secret, old.Secret) || !machineNodePairScopedTerminalRetry(archive, c.identity) || !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(credentialBefore, credentialAfter) || next.DescriptorText != old.DescriptorText || next.StartOperation != old.StartOperation || machineNodePairScopedCredentialDigest(next) != machineNodePairScopedCredentialDigest(old) {
		t.Fatal("retry downgraded, replaced identity or lost its authenticated original")
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
	for _, requested := range []string{"auto", "scoped", "legacy"} {
		if _, _, err := selectMachineNodePairProfile(context.Background(), f.state, f.node, f.address, "", false, requested); !errors.Is(err, errMachineNodePairLegacyUnsupported) {
			t.Fatal("saved v1 state was resumed or reclassified")
		}
	}
	afterLegacy, _ := os.ReadFile(machineNodePairStatePath(f.state, f.node))
	if string(before) != string(afterLegacy) {
		t.Fatal("unsupported legacy state was modified")
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

func TestNodePairScopedExplicitLegacyCreatesNoStateOrPOST(t *testing.T) {
	f := newNodePairLocalFixture(t)
	var requests atomic.Int32
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := runMachineAgentWithContext(context.Background(), []string{"--hub-address", f.address, "--state-dir", f.state, "--id", f.node, "--relay-only", "--once", "--pairing-profile", "legacy"}, nil)
	if !errors.Is(err, errMachineNodePairLegacyUnsupported) || requests.Load() != 0 {
		t.Fatal("explicit legacy pairing was not refused before discovery")
	}
	key, state := machineNodeControlPaths(f.state, f.node)
	for _, path := range []string{machineNodePairScopedStatePath(f.state, f.node), machineNodePairStatePath(f.state, f.node), key, state, machineNodeCredentialPath(f.state, f.node)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("explicit legacy initialized secret state")
		}
	}
}

func TestNodePairScopedTerminalRetryHintOnlyForAuthenticatedTerminal(t *testing.T) {
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	for _, stage := range []string{wire.NodePairTrustScopedExpired, wire.NodePairTrustScopedCancelled, wire.NodePairTrustScopedRevoked, wire.NodePairTrustScopedFenced, "UNKNOWN"} {
		s.Stage = stage
		if err := saveMachineNodePairScopedState(f.f.state, c.identity, s); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(machineNodePairScopedStatePath(f.f.state, f.f.node))
		err := f.run(t)
		wantHint := stage != wire.NodePairTrustScopedFenced && stage != "UNKNOWN"
		if err == nil || !strings.Contains(err.Error(), "Node pairing is "+stage+"; original identity and pending evidence retained") || strings.Contains(err.Error(), "Run the same command with --retry-pairing to request a new device code.") != wantHint {
			t.Fatal("terminal guidance was missing or encouraged retry of an unknown outcome")
		}
		after, _ := os.ReadFile(machineNodePairScopedStatePath(f.f.state, f.f.node))
		if !bytes.Equal(before, after) {
			t.Fatal("terminal guidance modified the original evidence")
		}
	}
}
