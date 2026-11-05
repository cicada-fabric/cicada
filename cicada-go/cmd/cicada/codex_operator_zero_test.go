package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// Scripted private Node replies exercise consumer state/correlation only.
// Actual ZERO attestation, Owner classification and key completion have their
// separate real Node/Hub gate; no synthetic reply grants a deployed identity.
func syntheticCodexZeroProgress(q localEndpointRequest, hub, node, state string) *localEndpointResult {
	return &localEndpointResult{RequestID: q.RequestID, IntentDigest: codexOperatorDigest(q, false), HubID: hub, NodeID: node, Operation: q.Operation, State: state,
		Registration: &nodewire.EndpointRegistrationResult{EndpointID: "SYNTHETIC-zero-endpoint", Workspace: q.Workspace, Name: q.Name, Presence: "offline", StateDigest: strings.Repeat("a", 64)}}
}

func TestCodexZeroProgressRemainsOriginalAndUnacknowledged(t *testing.T) {
	for _, state := range []string{"CLASSIFICATION_REQUIRED", "GROUP_CONFLICT", "NETWORK_CONFLICT", "UNRESOLVED", "RESERVED"} {
		t.Run(state, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, "SYNTHETIC-zero-node")
			q := syntheticCodexOperatorTemplate()
			q.APIOrigin = pin.APIOrigin
			q.LocalDomainVersion, q.LocalDomain = 1, syntheticCodexDomainBinding().LocalDomain
			path := filepath.Join(root, "scope", "operator-intent.json")
			client, err := openCodexOperatorIntent(path)
			if err != nil {
				t.Fatal(err)
			}
			original, err := client.prepareWithConnectionPin(q, pin.NodeID, &pin)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			progressErr := errors.New(state)
			calls := 0
			exchange := func(_ string, request localEndpointRequest) (*localEndpointResult, error) {
				calls++
				if request != original {
					t.Fatal("Owner classification wait replaced original Join")
				}
				return syntheticCodexZeroProgress(request, pin.HubID, pin.NodeID, state), progressErr
			}
			client.exchange = exchange
			result, err := client.callWithConnectionPin(pin.SocketPath, q, pin.NodeID, &pin)
			if err != progressErr || result == nil || result.State != state {
				t.Fatal("authenticated registration progress became response-invalid or success", err)
			}
			if err := client.ack(original.RequestID, result.IntentDigest); !errors.Is(err, errCodexOperatorIntentConflict) {
				t.Fatal("registration-only response could be acknowledged", err)
			}
			restarted, err := openCodexOperatorIntent(path)
			if err != nil {
				t.Fatal(err)
			}
			restarted.exchange = exchange
			if result, err := restarted.callWithConnectionPin(pin.SocketPath, q, pin.NodeID, &pin); err != progressErr || result == nil || calls != 2 {
				t.Fatal("restart cached progress or changed the original", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("nonterminal reply changed durable pending/cache/ack state", err)
			}
			var disk codexOperatorIntentDisk
			if json.Unmarshal(after, &disk) != nil || disk.Pending == nil || disk.Pending.Request != original || disk.Pending.Result != nil || disk.Pending.ResponseError != "" || disk.LastAck != nil {
				t.Fatal("registration-only progress was cached as a completed receipt")
			}
		})
	}
}

func TestCodexZeroProgressRejectsForeignOrAuthorityBearingReply(t *testing.T) {
	q := syntheticLocalEndpointRequest("endpoint_register")
	q.LocalDomainVersion, q.LocalDomain = 1, syntheticCodexDomainBinding().LocalDomain
	for _, test := range []struct {
		name   string
		change func(*codexOperatorPending, *localEndpointResult, *error)
	}{
		{"request", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.RequestID = strings.Repeat("b", 32) }},
		{"intent", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.IntentDigest = strings.Repeat("b", 64)
		}},
		{"hub", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.HubID = "SYNTHETIC-other-hub" }},
		{"node", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.NodeID = "SYNTHETIC-other-node" }},
		{"operation", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Operation = "endpoint_leave" }},
		{"no-error", func(_ *codexOperatorPending, _ *localEndpointResult, e *error) { *e = nil }},
		{"transport-error", func(_ *codexOperatorPending, _ *localEndpointResult, e *error) {
			*e = errors.New("SYNTHETIC unsigned HTTP failure")
		}},
		{"unknown-state", func(_ *codexOperatorPending, r *localEndpointResult, e *error) {
			r.State = "FUTURE_STATE"
			*e = errors.New(r.State)
		}},
		{"legacy-profile", func(p *codexOperatorPending, _ *localEndpointResult, _ *error) {
			p.Request.LocalDomainVersion = 0
			p.Request.LocalDomain = wire.LocalDomainSelection{}
		}},
		{"missing-registration", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Registration = nil }},
		{"workspace", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.Registration.Workspace = "/SYNTHETIC-other-work"
		}},
		{"endpoint", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Registration.EndpointID = "" }},
		{"digest", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Registration.StateDigest = "bad" }},
		{"left", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Registration.Presence = "left" }},
		{"join", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.Join = &fabric.JoinResult{} }},
		{"grant", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.LocalDomain = &wire.LocalDomainNodeKeyResult{}
		}},
		{"groups", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.EndpointGroups = &wire.EndpointGroupsNodeDescribeResult{}
		}},
		{"scope", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.NativeContextScope = &nodeinbox.NativeContextScopeDecision{Accepted: true}
		}},
		{"directory", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.Directory = &nodewire.EndpointDirectoryResult{}
		}},
		{"pairs", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) {
			r.Pairs = &nodewire.AvailableNativePairs{}
		}},
		{"offline", func(_ *codexOperatorPending, r *localEndpointResult, _ *error) { r.EndpointGroupsLocalOffline = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := codexOperatorPending{Request: q, NodeID: "SYNTHETIC-node", IntentDigest: codexOperatorDigest(q, false), ConnectionPin: &LocalNodeConnectionPin{HubID: "SYNTHETIC-hub"}}
			r := syntheticCodexZeroProgress(q, p.ConnectionPin.HubID, p.NodeID, "CLASSIFICATION_REQUIRED")
			var responseErr error = errors.New(r.State)
			test.change(&p, r, &responseErr)
			// Isolate profile checks from the exact intent correlation check.
			p.IntentDigest = codexOperatorDigest(p.Request, false)
			if test.name == "legacy-profile" {
				r.IntentDigest = p.IntentDigest
			}
			if codexOperatorUnconfirmedResult(p, r, responseErr) {
				t.Fatal("foreign, malformed or authority-bearing progress was accepted")
			}
		})
	}
}

func TestCodexZeroProgressLaterCompletedReceiptRetainsOriginal(t *testing.T) {
	q, completed := syntheticCodexDomainAdmission(t, syntheticCodexOperatorTemplate())
	path := filepath.Join(privateLocalNodeRoot(t), "scope", "operator-intent.json")
	client, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	original, err := client.prepare(q, completed.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	client.exchange = func(_ string, request localEndpointRequest) (*localEndpointResult, error) {
		return syntheticCodexZeroProgress(request, completed.HubID, completed.NodeID, "CLASSIFICATION_REQUIRED"), errors.New("CLASSIFICATION_REQUIRED")
	}
	if result, err := client.call("SYNTHETIC-socket", q, completed.NodeID); result == nil || err == nil || errors.Is(err, errCodexOperatorIntentResponse) {
		t.Fatal("ZERO registration was not retained as unconfirmed", err)
	}
	restarted, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.exchange = func(_ string, request localEndpointRequest) (*localEndpointResult, error) {
		if request != original {
			t.Fatal("classification created a replacement Join")
		}
		completed.RequestID, completed.IntentDigest = request.RequestID, codexOperatorDigest(request, false)
		return completed, nil
	}
	result, err := restarted.call("SYNTHETIC-socket", q, completed.NodeID)
	if err != nil || result != completed {
		t.Fatal("exact later completion failed validation", err)
	}
	if err := restarted.ack(result.RequestID, result.IntentDigest); err != nil {
		t.Fatal("verified completion could not be acknowledged", err)
	}
}
