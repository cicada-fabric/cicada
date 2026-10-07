//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fabric "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

// This assertion is called by the distribution gate after the current
// OwnerDevice authority has been activated and the shipped Hub plus checked
// Node transport are live. It exercises only bounded MCP metadata, with no
// model, provider, native-runtime, or message-consumption activity.
func assertPQProtectedMCPMetadata(t *testing.T, sealed *machineSealedReceiveFixture,
	current distributionTLSFixture, db *store.Store, logicalOrigin string, nodeContext context.Context) {
	t.Helper()
	nodeID := sealed.sourceNodeID
	node := current.nodes[nodeID]
	workspace := filepath.Join(current.root, "mcp-workspace")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal("create private synthetic native workspace")
	}
	codexHome := filepath.Join(current.root, "codex-home")
	writeCodexSessionRecord(t, codexHome, "native-mcp-pqtls-current", workspace)
	t.Setenv("CODEX_HOME", codexHome)
	service, err := fabric.NewService(db, node.Binding.OwnerID, node.Binding.OwnerID)
	if err != nil {
		t.Fatal("create fixture-scoped Fabric service")
	}
	joined, err := service.JoinForNodeCredential(sealed.sourceToken, fabric.JoinInput{
		GroupID: sealed.link.SourceGroupID, Harness: "codex", NativeSessionID: "native-mcp-pqtls-current",
		Workspace: workspace, Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"},
	})
	if err != nil || joined == nil || joined.SessionToken == "" {
		t.Fatal("join isolated native fixture session")
	}
	bridge, err := startMachineAgentJoinBridge(nodeContext, node.StateRoot, logicalOrigin, nodeID, sealed.sourceToken)
	if err != nil {
		t.Fatal("start owner-local Agent bridge")
	}
	t.Cleanup(func() { _ = bridge.Close() })
	trusted := mcpTrustedContext{Harness: "codex", NativeSessionID: "native-mcp-pqtls-current",
		NodeID: nodeID, Workspace: workspace}
	public := mcpPublicJoinResult{Endpoint: joined.Endpoint, NetworkCard: joined.NetworkCard,
		BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt}
	scope, _, err := mcpSessionScope(logicalOrigin, harness.SessionContext{
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID,
		MachineID: trusted.NodeID, Workspace: trusted.Workspace,
	})
	if err != nil {
		t.Fatal("derive exact fixture MCP scope")
	}
	mcp := newMCPServer(logicalOrigin, joined.Endpoint.ID, "")
	mcp.pqtlsSelected = true
	mcp.hubStateDir = node.StateRoot
	mcp.setSession(joined.SessionToken, joined.Endpoint.ID, joined.NetworkCard.GroupID, trusted, scope, public)
	t.Cleanup(func() { close(mcp.stop) })
	whoami, err := mcp.apiForGroup(http.MethodGet, "/v2/fabric/whoami", nil, joined.NetworkCard.GroupID)
	if err != nil {
		t.Fatal("protected PQ whoami through original Node UDS bridge")
	}
	card, err := networkCardFromResult(whoami)
	if err != nil || card.EndpointID != joined.Endpoint.ID || card.BindingID != joined.BindingID || card.NativeSessionID != trusted.NativeSessionID {
		t.Fatal("protected PQ whoami did not return the exact current native binding")
	}
	find, err := mcp.apiForGroup(http.MethodPost, "/v2/fabric/find", fabric.ResolveInput{Query: joined.Endpoint.ID}, joined.NetworkCard.GroupID)
	if err != nil {
		t.Fatal("protected PQ Directory find through original Node UDS bridge")
	}
	resolved, err := networkCardFromResult(find)
	if err != nil || resolved.EndpointID != joined.Endpoint.ID || resolved.GroupID != joined.NetworkCard.GroupID {
		t.Fatal("protected PQ find returned an unexpected card")
	}
	resolve, err := mcp.apiForGroup(http.MethodPost, "/v2/fabric/resolve",
		fabric.ResolveInput{Query: joined.Endpoint.ID}, joined.NetworkCard.GroupID)
	if err != nil {
		t.Fatal("protected PQ resolve through original Node UDS bridge")
	}
	resolved, err = networkCardFromResult(resolve)
	if err != nil || resolved.EndpointID != joined.Endpoint.ID || resolved.GroupID != joined.NetworkCard.GroupID {
		t.Fatal("protected PQ resolve returned an unexpected card")
	}
	if _, err := mcp.apiForGroup(http.MethodPost, "/v2/fabric/heartbeat", nil, joined.NetworkCard.GroupID); err != nil {
		t.Fatal("protected PQ heartbeat through original Node UDS bridge")
	}
	t.Log("protected PQ MCP whoami/find/resolve/heartbeat succeeded through the original Node UDS bridge")

	baseRequest := localMCPMetadataRequest{Version: localJoinProtocolVersion, Operation: "mcp_metadata_whoami",
		Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
		Workspace: trusted.Workspace, APIOrigin: logicalOrigin, SessionToken: joined.SessionToken,
		EndpointID: joined.Endpoint.ID, PrincipalID: joined.NetworkCard.PrincipalID,
		GroupID: joined.NetworkCard.GroupID, BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch}
	for _, mutate := range []func(*localMCPMetadataRequest){
		func(r *localMCPMetadataRequest) { r.APIOrigin = "https://wrong.invalid" },
		func(r *localMCPMetadataRequest) { r.NativeSessionID = "foreign-native-thread" },
		func(r *localMCPMetadataRequest) { r.BindingID = "binding_foreign" },
		func(r *localMCPMetadataRequest) { r.BindingEpoch++ },
	} {
		request := baseRequest
		mutate(&request)
		if _, err := requestMachineAgentMCPMetadata(bridge.path, request); err == nil {
			t.Fatal("protected metadata bridge accepted a mismatched origin, native session, or Group")
		}
	}
	// Mutating/read-list operations retain the same checked binding preflight.
	for _, operation := range []string{"mcp_metadata_leave_group", "mcp_metadata_members"} {
		protected := baseRequest
		protected.Operation = operation
		if operation == "mcp_metadata_members" {
			protected.Limit = 2
		}
		for _, mutate := range []func(*localMCPMetadataRequest){
			func(r *localMCPMetadataRequest) { r.NativeSessionID = "foreign-native-thread" },
			func(r *localMCPMetadataRequest) { r.BindingID = "binding_foreign" },
			func(r *localMCPMetadataRequest) { r.BindingEpoch++ },
		} {
			request := protected
			mutate(&request)
			if _, err := requestMachineAgentMCPMetadata(bridge.path, request); err == nil {
				t.Fatal("new checked route accepted mismatched native binding")
			}
		}
		for _, mutate := range []func(*localMCPMetadataRequest){
			func(r *localMCPMetadataRequest) { r.GroupID = "group_foreign" },
			func(r *localMCPMetadataRequest) { r.SessionToken = "cicada_session_synthetic_wrong" },
		} {
			request := protected
			mutate(&request)
			response, err := requestMachineAgentMCPMetadata(bridge.path, request)
			if err != nil || response == nil || response.StatusCode < 400 {
				t.Fatal("new checked route accepted foreign Group or wrong token")
			}
		}
	}
	wrongGroup := baseRequest
	wrongGroup.GroupID = "group_foreign"
	groupResponse, err := requestMachineAgentMCPMetadata(bridge.path, wrongGroup)
	if err != nil || groupResponse == nil || groupResponse.StatusCode < 400 {
		t.Fatal("protected metadata bridge accepted a foreign Group")
	}
	noTLSRoot := filepath.Join(current.root, "without-pqtls")
	if err := os.MkdirAll(noTLSRoot, 0700); err != nil {
		t.Fatal("create isolated no-transport state root")
	}
	noTLSContext := withMachineHubContext(context.Background(), machineHubContext{
		HubID: node.Binding.HubID, Origin: logicalOrigin, NodeID: nodeID, StateDir: noTLSRoot,
		Token: sealed.sourceToken, WriterRoot: node.WriterRoot,
	})
	noTLSBridge, err := startMachineAgentJoinBridge(noTLSContext, noTLSRoot, logicalOrigin, nodeID, sealed.sourceToken)
	if err != nil {
		t.Fatal("start isolated no-transport Node bridge")
	}
	t.Cleanup(func() { _ = noTLSBridge.Close() })
	noTLS, err := requestMachineAgentMCPMetadata(noTLSBridge.path, baseRequest)
	if err == nil || noTLS != nil {
		t.Fatal("protected metadata bridge used a Node without its checked PQ transport")
	}
	wrongToken := baseRequest
	wrongToken.SessionToken = "cicada_session_synthetic_wrong"
	unauthorized, err := requestMachineAgentMCPMetadata(bridge.path, wrongToken)
	if err != nil || unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatal("protected metadata bridge did not preserve stale-token status")
	}
	if _, err := db.RevokeSessionBinding(joined.BindingID, joined.BindingEpoch, "synthetic MCP bridge revocation test"); err != nil {
		t.Fatal("revoke isolated synthetic session binding")
	}
	if _, err := mcp.apiForGroup(http.MethodGet, "/v2/fabric/whoami", nil, joined.NetworkCard.GroupID); err == nil || mcp.currentSessionToken() != "" {
		t.Fatal("revoked current binding remained usable through the protected MCP bridge")
	}
	t.Log("wrong origin/native/binding/epoch/Group/token and revoked-session checks rejected")

	// A separate synthetic native session exercises the actual MCP callTool ->
	// owner-local UDS -> checked PQ Node -> real Hub route, not a direct Hub leave.
	const multiSID = "native-mcp-pqtls-multigroup"
	writeCodexSessionRecord(t, codexHome, multiSID, workspace)
	primary, err := db.GetGroup(sealed.link.SourceGroupID)
	if err != nil {
		t.Fatal("read authorized primary Group")
	}
	secondary, err := db.CreateGroup(store.Group{ID: "grp_mcp_pqtls_secondary", Name: "synthetic MCP secondary",
		OwnerPrincipalID: primary.OwnerPrincipalID, TrustDomainID: primary.TrustDomainID,
		State: store.GroupStateActive, ContextPolicy: "group_scoped"})
	if err != nil {
		t.Fatal("create individually authorized synthetic secondary Group")
	}
	first, err := service.JoinForNodeCredential(sealed.sourceToken, fabric.JoinInput{
		GroupID: primary.ID, Harness: "codex", NativeSessionID: multiSID, Workspace: workspace,
		Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}})
	if err != nil {
		t.Fatal("first real native Group Join")
	}
	if _, err := db.CreateMembership(store.Membership{PrincipalID: first.Endpoint.PrincipalID,
		GroupID: secondary.ID, Role: "member", Grants: []string{"directory.read", "message.send", "message.ask", "message.reply", "message.receive"}}); err != nil {
		t.Fatal("authorize exact existing native Principal for second Group")
	}
	second, err := service.JoinForNodeCredential(sealed.sourceToken, fabric.JoinInput{
		GroupID: secondary.ID, EndpointID: first.Endpoint.ID, Harness: "codex", NativeSessionID: multiSID,
		Workspace: workspace, Capabilities: map[string]any{"local_peer_delivery": "sealed_v1"}})
	if err != nil || second.Endpoint.ID != first.Endpoint.ID || second.Endpoint.NativeSessionID != multiSID {
		t.Fatal("second Join replaced original native identity")
	}
	multiTrusted := trusted
	multiTrusted.NativeSessionID = multiSID
	multiPublic := mcpPublicJoinResult{Endpoint: second.Endpoint, NetworkCard: second.NetworkCard,
		BindingID: second.BindingID, BindingEpoch: second.BindingEpoch, LeaseExpiresAt: second.LeaseExpiresAt}
	multiScope, _, err := mcpSessionScope(logicalOrigin, harness.SessionContext{Harness: "codex", NativeSessionID: multiSID, MachineID: nodeID, Workspace: workspace})
	if err != nil {
		t.Fatal("derive second synthetic native scope")
	}
	multi := newMCPServer(logicalOrigin, second.Endpoint.ID, "")
	multi.pqtlsSelected = true
	multi.hubStateDir = node.StateRoot
	multi.setSession(second.SessionToken, second.Endpoint.ID, secondary.ID, multiTrusted, multiScope, multiPublic)
	t.Cleanup(func() { close(multi.stop) })
	if _, err := multi.callTool("cicada_use_group", map[string]any{"group_id": primary.ID}); err != nil {
		t.Fatal("select primary through checked MCP")
	}
	members, err := multi.callTool("cicada_members", map[string]any{"limit": 10})
	if err != nil {
		t.Fatal("current Group members through checked MCP")
	}
	encoded, _ := json.Marshal(members)
	var roster struct {
		Endpoints []fabric.NetworkCard `json:"endpoints"`
	}
	if err := decodeStrictJSON(encoded, &roster); err != nil || len(roster.Endpoints) == 0 {
		t.Fatal("missing scoped members")
	}
	for _, card := range roster.Endpoints {
		if card.GroupID != primary.ID || card.NativeSessionID != "" {
			t.Fatal("members leaked foreign scope or native ID")
		}
	}
	left, err := multi.callTool("cicada_leave_group", map[string]any{"reason": "synthetic leave primary"})
	if err != nil {
		t.Fatal("actual checked PQ MCP leave primary")
	}
	leftMap, ok := left.(map[string]any)
	if !ok || leftMap["remaining_group_id"] != secondary.ID || multi.sessionGroupID != secondary.ID || !multi.isJoined() {
		t.Fatal("leave primary failed to retain second Group")
	}
	remaining, err := multi.callTool("cicada_whoami", nil)
	if err != nil {
		t.Fatal("remaining Group checked whoami")
	}
	retained, err := networkCardFromResult(remaining)
	if err != nil || retained.EndpointID != first.Endpoint.ID || retained.NativeSessionID != multiSID || retained.GroupID != secondary.ID || retained.BindingID != second.BindingID {
		t.Fatal("leave replaced original Endpoint/native session/binding")
	}
	if _, err := multi.callTool("cicada_use_group", map[string]any{"group_id": primary.ID}); err == nil {
		t.Fatal("left Group remained usable")
	}
	if !multi.isJoined() || multi.sessionGroupID != secondary.ID || multi.currentSessionToken() != second.SessionToken {
		t.Fatal("left Group denial cleared the live remaining Group session")
	}
	if _, err := multi.callTool("cicada_leave_group", nil); err != nil || multi.isJoined() {
		t.Fatal("last Group leave did not clear MCP session")
	}
	if _, err := service.AuthenticateForGroup(second.SessionToken, secondary.ID); err == nil {
		t.Fatal("last Group leave did not fence original native binding")
	}
	t.Log("checked PQ MCP members and leave-group preserve remaining native scope; last leave fences")
}

func assertMeasuredPQDiagnosticRoutes(t *testing.T, path string, requiredRoutes, requiredEvents []string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open opt-in private PQTLS diagnostic", err)
	}
	defer file.Close()
	seenRoutes := make(map[string]bool)
	observations := make(map[string]bool)
	seenEvents := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 16*1024)
	for scanner.Scan() {
		var record machinePQDiagnosticRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal("invalid bounded PQTLS diagnostic JSON line")
		}
		if record.SchemaVersion != 1 || record.ObservationID == "" || record.Route == "" || strings.Contains(string(scanner.Bytes()), "Authorization") || strings.Contains(string(scanner.Bytes()), "ciphertext") {
			t.Fatal("diagnostic omitted connection correlation or exposed sensitive field names")
		}
		if record.Event == "ready" || record.Event == "wake" {
			seenEvents[record.Event] = true
			if !observations[record.ObservationID] {
				t.Fatal("Relay event is not linked to a measured connection")
			}
		}
		if record.Event == "got-conn" {
			if record.TLSVersion != "TLSv1.3" || record.Group != "MLKEM768" || record.CipherSuite != "TLS_AES_256_GCM_SHA384" ||
				record.PeerSignature != "ML-DSA-65" || record.ALPN != "http/1.1" || record.VerificationResult != 0 ||
				!record.HostnameVerified || record.PeerKind != "hub" || record.LocalNodeID == "" || len(record.CertificateSHA256) != 64 || len(record.SPKISHA256) != 64 {
				t.Fatal("actual protected route did not report the strict measured PQTLS profile")
			}
			observations[record.ObservationID] = true
			seenRoutes[record.Route] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal("read bounded PQTLS diagnostic", err)
	}
	for _, route := range requiredRoutes {
		if !seenRoutes[route] {
			t.Fatal("missing actual checked PQTLS route evidence", route)
		}
	}
	for _, event := range requiredEvents {
		if !seenEvents[event] {
			t.Fatal("missing actual Node SSE event evidence", event)
		}
	}
	t.Logf("measured protected PQTLS route records=%d SSE events=%d", len(seenRoutes), len(seenEvents))
}
