package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

// This fixture tests scope projection from a scripted private Node result.
// Its visibly synthetic key-evidence markers are not signature-chain fixtures
// and never claim Hub/Node domain admission. The production Node owns that gate.
func syntheticCodexDomainAdmission(t *testing.T, q localEndpointRequest) (localEndpointRequest, *localEndpointResult) {
	t.Helper()
	f := newNativePairConsumerFixture(t)
	actor := f.scope.Actor
	policy := e2ee.LocalDomainPolicy{Version: 1, PolicyID: strings.Repeat("a", 32), Epoch: 1, Origin: q.APIOrigin, HubID: actor.HubID, HubFingerprint: actor.HubFingerprint, OwnerID: actor.OwnerID, OwnerPublic: actor.OwnerPublic, OwnerKeyVersion: 1, Node: f.scope.Node, NodeControlBindingVersion: 7, CredentialCommitment: strings.Repeat("b", 64), LocalUserScope: "uid:4242", NetworkID: "synthetic-domain-network", NetworkName: "Synthetic local Network", CreateNetwork: true, GroupID: "synthetic-domain-group", GroupName: "Synthetic local Group", Rights: e2ee.LocalDomainRights(), IssuedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), PrepareRequestID: strings.Repeat("c", 32), PreparePacketDigest: strings.Repeat("d", 64), ServerNonce: strings.Repeat("e", 64)}
	selection, err := wire.LocalDomainSelectionForPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	q.LocalDomainVersion, q.LocalDomain = 1, selection
	member := wire.LocalDomainMember{MemberID: "synthetic-member", Selection: selection, Revision: 2, State: wire.LocalDomainMemberActive, NodeID: policy.Node.NodeID, LocalUserScope: policy.LocalUserScope, NativeSessionID: q.NativeSessionID, Runtime: q.Harness, Workspace: q.Workspace, EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-principal", BindingID: "synthetic-native-binding", BindingEpoch: 1, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: 1, CandidateKeyID: policy.Node.NodePublic.ID, CandidateFingerprint: "sha256:" + strings.Repeat("f", 64), CandidateProofDigest: strings.Repeat("1", 64)}
	manifest := wire.LocalDomainKeyManifest{Version: 1, HubID: policy.HubID, OwnerID: policy.OwnerID, PrincipalID: member.PrincipalID, GroupID: policy.GroupID, EndpointID: member.EndpointID, NodeID: member.NodeID, BindingID: member.BindingID, BindingEpoch: member.BindingEpoch, MembershipRevision: 1, EndpointJoinRevision: 1, CandidateVersion: 1, CandidateKeyID: member.CandidateKeyID, CandidatePublicIdentity: policy.Node.NodePublic, CandidateFingerprint: member.CandidateFingerprint, CandidateProofDigest: member.CandidateProofDigest, OwnerKeyID: policy.OwnerPublic.ID, Digest: strings.Repeat("2", 64)}
	description := wire.LocalDomainDescription{ContractRevision: wire.LocalDomainContractRevision, Policy: policy, State: wire.LocalDomainActive, Revision: 2, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	evidence := &wire.LocalDomainNodeKeyResult{ContractRevision: wire.LocalDomainContractRevision, Description: description, Member: member, Grant: wire.LocalDomainEndpointKeyGrant{ContractRevision: wire.LocalDomainContractRevision, Member: member, Manifest: manifest, PolicyProof: []byte("SYNTHETIC_NODE_VERIFIED_POLICY_MARKER"), NodeProof: []byte("SYNTHETIC_NODE_VERIFIED_CANDIDATE_MARKER")}}
	joined := &fabric.JoinResult{SessionToken: "cicada_session_synthetic_domain", BindingID: member.BindingID, BindingEpoch: member.BindingEpoch, LeaseExpiresAt: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano), Endpoint: store.Endpoint{ID: member.EndpointID, GroupID: policy.GroupID, PrincipalID: member.PrincipalID, Owner: policy.OwnerID, MachineID: member.NodeID, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace, Name: q.Name}}
	r := &localEndpointResult{RequestID: q.RequestID, IntentDigest: codexOperatorDigest(q, false), HubID: policy.HubID, NodeID: member.NodeID, Operation: q.Operation, State: "COMPLETED", Registration: &nodewire.EndpointRegistrationResult{EndpointID: member.EndpointID, Workspace: q.Workspace, Name: q.Name, Presence: "offline", StateDigest: strings.Repeat("3", 64)}, Join: joined, LocalDomain: evidence, NativeContextScope: &nodeinbox.NativeContextScopeDecision{Accepted: true}}
	return q, r
}

func TestCodexDomainResultRejectsSubstitutedScopeAndIncompleteAdmission(t *testing.T) {
	q, result := syntheticCodexDomainAdmission(t, syntheticLocalEndpointRequest("endpoint_register"))
	pending := codexOperatorPending{NodeID: result.NodeID, Request: q, IntentDigest: codexOperatorDigest(q, false)}
	if err := validateCodexOperatorResult(pending, result, nil); err != nil {
		t.Fatal("complete Node scope projection rejected", err)
	}
	node := result.LocalDomain.Description.Policy.Node
	if node.BindingVersion != 1 || result.LocalDomain.Description.Policy.NodeControlBindingVersion != 7 {
		t.Fatal("fixture must distinguish owner binding v1 from control row v7")
	}
	pin := LocalNodeConnectionPin{HubID: result.HubID, NodeID: result.NodeID, APIOrigin: q.APIOrigin, Binding: LocalNodeBinding{BindingID: node.OwnerBindingID, BindingVersion: 1, NodeKeyEpoch: node.NodeKeyEpoch, NodeKeyVersion: node.NodeKeyVersion, HubKeyVersion: node.HubNodeControlKeyVersion, NodeKeyID: node.NodePublic.ID, NodeKeyFingerprint: node.NodeKeyFingerprint, HubKeyID: node.HubNodeControlPublic.ID, HubFingerprint: node.HubNodeControlFingerprint}}
	pending.ConnectionPin = &pin
	if err := validateCodexOperatorResult(pending, result, nil); err != nil {
		t.Fatal("Node-Control pin was confused with the independent App Hub pin", err)
	}
	pin.Binding.BindingVersion = 7
	if validateCodexOperatorResult(pending, result, nil) == nil {
		t.Fatal("control row revision was accepted as the owner binding version")
	}
	pin.Binding.BindingVersion = 1
	pin.Binding.BindingID = "synthetic-different-owner-binding"
	if validateCodexOperatorResult(pending, result, nil) == nil {
		t.Fatal("different owner binding was accepted")
	}
	pin.Binding.BindingID = node.OwnerBindingID
	pin.Binding.HubFingerprint = result.LocalDomain.Description.Policy.HubFingerprint
	if validateCodexOperatorResult(pending, result, nil) == nil {
		t.Fatal("App Hub fingerprint replaced the Node-Control pin")
	}
	pin.Binding.HubFingerprint = node.HubNodeControlFingerprint
	for _, test := range []struct {
		name   string
		change func(*localEndpointResult)
	}{
		{"unaccepted", func(r *localEndpointResult) { r.NativeContextScope.Accepted = false }},
		{"zero-only", func(r *localEndpointResult) { r.Join = nil; r.LocalDomain = nil }},
		{"missing-key-result", func(r *localEndpointResult) { r.LocalDomain = nil }},
		{"different-policy", func(r *localEndpointResult) { r.LocalDomain.Description.Policy.GroupName = "Another scope" }},
		{"wrong-user", func(r *localEndpointResult) { r.LocalDomain.Member.LocalUserScope = "uid:9999" }},
		{"wrong-member-selector", func(r *localEndpointResult) { r.LocalDomain.Member.Selection.PolicyEpoch++ }},
		{"zero-member", func(r *localEndpointResult) { r.LocalDomain.Member.State = wire.LocalDomainMemberJoinedZero }},
		{"wrong-thread", func(r *localEndpointResult) { r.Join.Endpoint.NativeSessionID = "other-thread" }},
		{"wrong-workspace", func(r *localEndpointResult) { r.Join.Endpoint.Workspace = "/other/work" }},
		{"wrong-group", func(r *localEndpointResult) { r.Join.Endpoint.GroupID = "another-group" }},
		{"wrong-binding", func(r *localEndpointResult) { r.Join.BindingEpoch++ }},
		{"wrong-registration", func(r *localEndpointResult) { r.Registration.EndpointID = "another-endpoint" }},
		{"missing-node-proof", func(r *localEndpointResult) { r.LocalDomain.Grant.NodeProof = nil }},
		{"mixed-grant-member", func(r *localEndpointResult) { r.LocalDomain.Grant.Member.Revision++ }},
		{"mixed-manifest", func(r *localEndpointResult) { r.LocalDomain.Grant.Manifest.BindingEpoch++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, _ := json.Marshal(result)
			var changed localEndpointResult
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture decode")
			}
			test.change(&changed)
			if validateCodexOperatorResult(pending, &changed, nil) == nil {
				t.Fatal("foreign or incomplete admission became a confirmed result")
			}
		})
	}
}

func TestCodexDomainLiteralJoinUsesNodeTicketAndRetainsLostOriginal(t *testing.T) {
	root := t.TempDir()
	stateDir := shortLocalJoinStateDir(t)
	workspace := filepath.Join(root, "workspace")
	base := filepath.Join(root, "mcp", "sessions.json")
	home := filepath.Join(root, "codex")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	q := syntheticLocalEndpointRequest("endpoint_register")
	q.Workspace = workspace
	q, result := syntheticCodexDomainAdmission(t, q)
	t.Setenv("CODEX_HOME", home)
	t.Setenv("CICADA_NODE_STATE_DIR", stateDir)
	t.Setenv("CICADA_MACHINE_ID", result.NodeID)
	t.Setenv("CICADA_API_URL", q.APIOrigin)
	t.Setenv("CICADA_MCP_SESSION_STATE_FILE", base)
	transcript := filepath.Join(home, "sessions", "synthetic-rollout.jsonl")
	if err := os.MkdirAll(filepath.Dir(transcript), 0700); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": q.NativeSessionID, "cwd": workspace, "source": "exec", "originator": "codex_exec"}})
	if err := os.WriteFile(transcript, append(metadata, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := mcpTestContext("codex", q.NativeSessionID, result.NodeID, workspace)
	scope, _, _ := mcpSessionScope(q.APIOrigin, ctx)
	intentPath := filepath.Join(filepath.Dir(base), "scopes", scope, "operator-intent.json")
	var calls atomic.Int32
	var original atomic.Pointer[localEndpointRequest]
	profile := localCodexContext{VerificationProfile: LocalCodexContextProfileDomain, LocalDomainVersion: 1, LocalDomain: q.LocalDomain}
	codexConsumerOperatorNode(t, stateDir, result.NodeID, profile, func(c net.Conn, raw json.RawMessage) {
		var actual localEndpointRequest
		if json.Unmarshal(raw, &actual) != nil {
			t.Error("request decode")
			return
		}
		saved, err := os.ReadFile(intentPath)
		var disk codexOperatorIntentDisk
		if err != nil || json.Unmarshal(saved, &disk) != nil || disk.Pending == nil || disk.Pending.Request != actual {
			t.Error("Node operation preceded exact private intent persistence")
			return
		}
		if calls.Add(1) == 1 {
			original.Store(&actual)
			return
		}
		first := original.Load()
		if first == nil || actual != *first || actual.LocalDomain != q.LocalDomain {
			t.Error("retry replaced original request or selector")
			return
		}
		copy := *result
		copy.RequestID, copy.IntentDigest = actual.RequestID, codexOperatorDigest(actual, false)
		_ = json.NewEncoder(c).Encode(localJoinResponse{Version: localJoinProtocolVersion, EndpointOperation: &copy})
	})
	event := codexHookInput{Event: "UserPromptSubmit", SessionID: q.NativeSessionID, CWD: workspace, TranscriptPath: transcript, Prompt: "cicada join " + q.Name}
	var output bytes.Buffer
	if err := codexUserPrompt(event, &output); err != nil || !strings.Contains(output.String(), "unconfirmed") {
		t.Fatal("lost response claimed success", err)
	}
	if cached, err := newMCPSessionStateStore(base).load(q.APIOrigin, ctx); err != nil || cached != nil {
		t.Fatal("lost response created a session")
	}
	output.Reset()
	writer := codexConsumerWriter(func(raw []byte) (int, error) {
		cached, err := newMCPSessionStateStore(base).load(q.APIOrigin, ctx)
		if err != nil || cached == nil || cached.LocalDomainVersion != 1 || cached.LocalDomain != q.LocalDomain || cached.BindingID != result.Join.BindingID {
			t.Error("visible result preceded bound private cache save")
		}
		return output.Write(raw)
	})
	if err := codexUserPrompt(event, io.Writer(writer)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "admission is saved") || strings.Contains(output.String(), result.Join.SessionToken) || calls.Load() != 2 {
		t.Fatal("admission output or retry count invalid")
	}
	saved, err := os.ReadFile(intentPath)
	var disk codexOperatorIntentDisk
	first := original.Load()
	if err != nil || json.Unmarshal(saved, &disk) != nil || disk.Pending != nil || disk.LastAck == nil || first == nil || disk.LastAck.RequestID != first.RequestID {
		t.Fatal("confirmed output did not acknowledge its original intent")
	}
}
