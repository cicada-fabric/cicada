package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestCodexConsumedContextProfileHasNoPartialOrUnknownFallback(t *testing.T) {
	selection := wire.LocalDomainSelection{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("b", 64)}
	for _, test := range []struct {
		name            string
		context         localCodexContext
		domain, allowed bool
	}{
		{"legacy-wire", localCodexContext{}, false, true},
		{"explicit-strict", localCodexContext{VerificationProfile: LocalCodexContextProfileLegacy}, false, true},
		{"domain", localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: selection}, true, true},
		{"version-only", localCodexContext{LocalDomainVersion: 1}, false, false},
		{"selector-without-profile", localCodexContext{LocalDomain: selection}, false, false},
		{"strict-selector", localCodexContext{VerificationProfile: LocalCodexContextProfileLegacy, LocalDomain: selection}, false, false},
		{"unknown", localCodexContext{VerificationProfile: "FUTURE_PROFILE"}, false, false},
		{"domain-without-version", localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomain: selection}, false, false},
		{"domain-without-selector", localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1}, false, false},
		{"domain-future-version", localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 2, LocalDomain: selection}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, domain, err := codexContextDomain(test.context)
			if (err == nil) != test.allowed || domain != test.domain {
				t.Fatal("consumed profile did not preserve its exact authority boundary")
			}
			if test.allowed && test.domain && actual != selection {
				t.Fatal("consumed selection changed")
			}
		})
	}
}

func TestCodexDomainMCPConsumesBeforeCacheAndNeverBorrowsOtherProfile(t *testing.T) {
	for _, kind := range []string{"matching-domain", "legacy-cache", "different-policy", "unknown-profile", "missing-selector"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			var card any
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/v2/fabric/heartbeat" {
					_ = json.NewEncoder(w).Encode(map[string]any{"endpoint_id": "synthetic-endpoint-synthetic-thread", "group_id": "synthetic-group-synthetic-thread", "binding_id": "synthetic-binding-synthetic-thread", "binding_epoch": 7})
					return
				}
				_ = json.NewEncoder(w).Encode(card)
			}))
			defer hub.Close()
			base := filepath.Join(t.TempDir(), "mcp", "sessions.json")
			ctx, cache, networkCard := codexConsumerCache(t, hub.URL, base, "synthetic-thread")
			card = networkCard
			binding := syntheticCodexDomainBinding()
			if kind != "legacy-cache" {
				state := newMCPSessionStateStore(base)
				if err := state.remove(cache.Scope); err != nil {
					t.Fatal(err)
				}
				cache.codexDomainBinding = binding
				if kind == "different-policy" {
					cache.LocalDomain.PolicyEpoch++
				}
				if err := state.save(cache); err != nil {
					t.Fatal(err)
				}
			}
			m := newMCPServer(hub.URL, "", base)
			m.hubStateDir = shortLocalJoinStateDir(t)
			if err := m.enableCodexContext(cache.NodeID); err != nil {
				t.Fatal(err)
			}
			defer m.stopCodexHeartbeat()
			profile := localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: binding.LocalDomain}
			if kind == "unknown-profile" {
				profile.VerificationProfile = "FUTURE"
			}
			if kind == "missing-selector" {
				profile.LocalDomain = wire.LocalDomainSelection{}
			}
			var authority localCodexContextAuthority
			q := syntheticCodexContextIssue()
			q.APIOrigin, q.NativeSessionID, q.Workspace, q.ConnectionNonce, q.ToolName = hub.URL, ctx.NativeSessionID, ctx.Workspace, m.codexContext.nonce, "cicada_whoami"
			q.ArgumentsDigest, _ = codexArgumentsDigest(map[string]any{})
			issued := codexConsumerIssueProfile(t, &authority, q, profile)
			if issued == nil {
				t.Fatal("fixture issue")
			}
			codexConsumerNode(t, m.hubStateDir, cache.NodeID, func(c net.Conn, raw json.RawMessage) {
				var query localCodexContextConsume
				_ = json.Unmarshal(raw, &query)
				consumed, err := authority.consume(query, "synthetic-node-binding", time.Now())
				response := localJoinResponse{Version: 1, CodexContextConsume: consumed}
				if err != nil {
					response.Error = "synthetic denied"
				}
				_ = json.NewEncoder(c).Encode(response)
			})
			_, err := m.callTool("cicada_whoami", map[string]any{codexMCPContextArgument: map[string]any{"connection_nonce": m.codexContext.nonce, "ticket": issued.Ticket}})
			if kind == "matching-domain" {
				if err != nil || requests.Load() != 3 || m.sessionDomain != binding {
					t.Fatal("matched domain failed current whoami/heartbeat restoration", err, requests.Load())
				}
			} else if err == nil || requests.Load() != 0 {
				t.Fatal("foreign/unknown profile reached cached credential or Hub", err, requests.Load())
			}
			saved, err := newMCPSessionStateStore(base).load(hub.URL, ctx)
			if err != nil || saved == nil || *saved != cache {
				t.Fatal("profile guard rewrote durable original", err)
			}
		})
	}
}

func TestCodexPairRequiresStrictConsumedContext(t *testing.T) {
	for _, context := range []localCodexContext{{}, {VerificationProfile: LocalCodexContextProfileLegacy}} {
		m := &mcpServer{codexContext: &codexMCPContextState{activeVerification: &context}}
		if err := m.requireStrictCodexContext(); err != nil {
			t.Fatal("original strict context rejected", err)
		}
	}
	value := localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: wire.LocalDomainSelection{PolicyID: strings.Repeat("a", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("b", 64)}}
	m := &mcpServer{codexContext: &codexMCPContextState{activeVerification: &value}}
	if m.requireStrictCodexContext() == nil {
		t.Fatal("domain ticket accepted by old Pair consumer")
	}
	m.codexContext.activeVerification = nil
	if m.requireStrictCodexContext() == nil {
		t.Fatal("Pair consumed an absent context")
	}
}
