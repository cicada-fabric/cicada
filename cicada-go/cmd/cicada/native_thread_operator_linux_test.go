//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestTerminalThreadSelectorUsesOnlyExactOwnedRecord(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CODEX_HOME", root)
	workspace := t.TempDir()
	directory := filepath.Join(root, "sessions", "2026", "10", "26")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	const sid = "synthetic-terminal-original-thread"
	path := filepath.Join(directory, "rollout-2026-10-26T00-00-00-"+sid+".jsonl")
	write := func(id, source string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": id, "cwd": workspace, "source": source, "originator": "codex-tui"}})
		if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(sid, "vscode")
	actual, cwd, err := nativeThreadOperatorRecord(sid)
	if err != nil || actual != path || cwd != workspace {
		t.Fatal("exact owned record selector rejected", err)
	}
	for _, bad := range []string{"../" + sid, sid + "*", sid + "?", "[" + sid + "]", "synthetic-ancestor-thread"} {
		if _, _, err := nativeThreadOperatorRecord(bad); err == nil {
			t.Fatal("selector accepted glob/path/ancestor identity")
		}
	}
	write("synthetic-other-thread", "vscode")
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("filename substituted for actual record identity")
	}
	write(sid, "unknown-source")
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("unknown record source entered terminal operator")
	}
	write(sid, "vscode")
	duplicate := filepath.Join(directory, "rollout-2026-10-26T00-00-01-"+sid+".jsonl")
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(duplicate, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := nativeThreadOperatorRecord(sid); err == nil {
		t.Fatal("ambiguous records were first-match selected")
	}
}

// The trusted Node/Host boundary is scripted here. The scoped TLS integration
// separately verifies the real original Join and registration proof chain.
func TestTerminalCompletedJoinCachesAuthenticatedRegistrationWithoutGroupSelection(t *testing.T) {
	for _, originalJoin := range []bool{true, false} {
		name := "registered-again"
		if originalJoin {
			name = "original-zero-join"
		}
		t.Run(name, func(t *testing.T) {
			root := privateLocalNodeRoot(t)
			pin := syntheticLocalNodePin(t, root, "synthetic-node")
			connection := LocalNodeConnection{Pin: pin}
			profile := syntheticEndpointGroupsContext()
			profile.NativeSessionID, profile.Workspace = "synthetic-terminal-current", t.TempDir()
			binding, err := codexContextBinding(profile)
			if err != nil {
				t.Fatal(err)
			}
			q := localEndpointGroupsRequest{APIOrigin: pin.APIOrigin, Harness: "codex", NativeSessionID: profile.NativeSessionID, Workspace: profile.Workspace, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding}
			a := wire.EndpointGroupsRegistrationAnchor{Profile: LocalCodexContextProfileEndpointGroups, RegistrationSource: wire.EndpointGroupsRegistrationSource, Registration: e2ee.EndpointGroupRegistration{HubID: pin.HubID, OwnerID: "synthetic-owner", NodeID: pin.NodeID, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-principal"}, RegistrationDigest: q.RegistrationDigest, RegistrationRevision: q.RegistrationRevision, BindingID: q.RegistrationBindingID, BindingEpoch: q.RegistrationBindingEpoch, NodeKeyEpoch: q.RegistrationNodeKeyEpoch, State: "REGISTERED", LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
			self := &localEndpointGroupsResult{LocalAccessRevision: 1, Description: wire.EndpointGroupsNodeDescribeResult{Registration: a}, SessionToken: "synthetic-original-session"}
			completed := &localEndpointResult{HubID: pin.HubID, NodeID: pin.NodeID, State: "COMPLETED", Operation: "endpoint_register", Registration: &nodewire.EndpointRegistrationResult{EndpointID: a.Registration.EndpointID, Workspace: q.Workspace}}
			if originalJoin {
				completed.Join = &fabric.JoinResult{Endpoint: store.Endpoint{ID: a.Registration.EndpointID, PrincipalID: a.Registration.PrincipalID, Owner: a.Registration.OwnerID, GroupID: "synthetic-original-group"}, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, SessionToken: self.SessionToken}
			} else {
				completed.EndpointGroups = &self.Description
			}
			entry, err := nativeThreadEndpointGroupsCache(connection, &pin, q, self, completed)
			if err != nil {
				t.Fatal(err)
			}
			cache := newMCPSessionStateStore(pin.MCPSessionStateFile)
			if err := cache.saveEndpointGroupsAuthenticated(entry); err != nil {
				t.Fatal(err)
			}
			loaded, err := cache.load(q.APIOrigin, harness.SessionContext{Harness: q.Harness, NativeSessionID: q.NativeSessionID, MachineID: pin.NodeID, Workspace: q.Workspace})
			if err != nil || loaded == nil || loaded.EndpointGroupsVersion != 1 || loaded.LocalDomainVersion != 0 || loaded.EndpointID != a.Registration.EndpointID || loaded.SessionToken != self.SessionToken || loaded.ConnectionPin == nil || *loaded.ConnectionPin != pin || loaded.GroupID != "" || loaded.EndpointGroupAuthority != (wire.EndpointGroupCurrentEndpoint{}) {
				t.Fatal("completed original lost identity or silently selected a Group", err)
			}
			for label, mutate := range map[string]func(*localEndpointGroupsResult, *localEndpointResult){
				"another-endpoint": func(s *localEndpointGroupsResult, _ *localEndpointResult) {
					s.Description.Registration.Registration.EndpointID = "synthetic-other"
				},
				"another-Hub": func(s *localEndpointGroupsResult, _ *localEndpointResult) {
					s.Description.Registration.Registration.HubID = "synthetic-other"
				},
				"another-binding": func(s *localEndpointGroupsResult, _ *localEndpointResult) { s.Description.Registration.BindingEpoch++ },
				"another-source": func(s *localEndpointGroupsResult, _ *localEndpointResult) {
					s.Description.Registration.RegistrationDigest = strings.Repeat("e", 64)
				},
				"another-native": func(s *localEndpointGroupsResult, _ *localEndpointResult) {
					s.Description.Registration.Registration.NativeSessionID = "synthetic-other"
				},
				"missing-access-revision": func(s *localEndpointGroupsResult, _ *localEndpointResult) { s.LocalAccessRevision = 0 },
				"unconfirmed":             func(_ *localEndpointGroupsResult, c *localEndpointResult) { c.State = "UNKNOWN" },
				"revoked": func(s *localEndpointGroupsResult, _ *localEndpointResult) {
					s.Description.Registration.State = "REVOKED"
				},
			} {
				t.Run(label, func(t *testing.T) {
					raw, _ := json.Marshal(self)
					var changedSelf localEndpointGroupsResult
					_ = json.Unmarshal(raw, &changedSelf)
					raw, _ = json.Marshal(completed)
					var changedCompleted localEndpointResult
					_ = json.Unmarshal(raw, &changedCompleted)
					mutate(&changedSelf, &changedCompleted)
					if _, err := nativeThreadEndpointGroupsCache(connection, &pin, q, &changedSelf, &changedCompleted); err == nil {
						t.Fatal("unrelated or unavailable registration cached")
					}
				})
			}
		})
	}
}
