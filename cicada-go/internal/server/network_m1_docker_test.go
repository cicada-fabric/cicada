package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestNetworkM1DockerHub exercises Network operator, migration, and peer HTTP
// flows against the separately owned real-TCP Hub started by the interop
// runner. The one-way activation requires a fresh StateDir for every run.
func TestNetworkM1DockerHub(t *testing.T) {
	baseURL := os.Getenv("CICADA_TEST_HUB_URL")
	dbPath := os.Getenv("CICADA_TEST_HUB_DB")
	managerToken := os.Getenv("CICADA_TEST_HUB_TOKEN")
	if baseURL == "" || dbPath == "" || managerToken == "" {
		t.Skip("requires the isolated disposable Network M1 Docker Hub")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	managerAuth := "Bearer " + managerToken

	call := func(method, path string, body any, headers map[string]string) (int, []byte) {
		t.Helper()
		var encoded []byte
		if body != nil {
			var err error
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal("encode synthetic HTTP request")
			}
		}
		request, err := http.NewRequest(method, baseURL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal("create synthetic HTTP request")
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("request %s %s failed: %v", method, path, err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
		if err != nil || len(data) > 256*1024 {
			t.Fatalf("read response for %s %s", method, path)
		}
		return response.StatusCode, data
	}
	expect := func(method, path string, body any, headers map[string]string, status int) []byte {
		t.Helper()
		got, data := call(method, path, body, headers)
		if got != status {
			t.Fatalf("%s %s returned status %d, want %d", method, path, got, status)
		}
		return data
	}
	expectDenied := func(method, path string, body any, headers map[string]string) int {
		t.Helper()
		status, _ := call(method, path, body, headers)
		if status != http.StatusUnauthorized && status != http.StatusForbidden &&
			status != http.StatusNotFound && status != http.StatusConflict {
			t.Fatalf("%s %s returned unexpected denial status %d", method, path, status)
		}
		return status
	}
	managementHeaders := map[string]string{"Authorization": managerAuth}

	var owner e2ee.PublicIdentity
	if err := json.Unmarshal(expect(http.MethodGet, "/v1/identity", nil,
		managementHeaders, http.StatusOK), &owner); err != nil || owner.ID == "" {
		t.Fatal("could not load synthetic Hub owner identity")
	}
	var hub struct {
		HubID                 string              `json:"hub_id"`
		ControlPublicIdentity e2ee.PublicIdentity `json:"control_public_identity"`
	}
	if err := json.Unmarshal(expect(http.MethodGet, "/v2/client/identity", nil,
		nil, http.StatusOK), &hub); err != nil || hub.HubID == "" {
		t.Fatal("could not load synthetic Hub identity")
	}

	createGroup := func(name string) store.Group {
		t.Helper()
		var group store.Group
		if err := json.Unmarshal(expect(http.MethodPost, "/v1/groups", map[string]string{"name": name},
			managementHeaders, http.StatusCreated), &group); err != nil || group.ID == "" || group.Version <= 0 {
			t.Fatal("could not create a synthetic legacy Group")
		}
		return group
	}
	groupA := createGroup("m1-network-a-legacy")
	groupB := createGroup("m1-network-b-legacy")
	groupPending := createGroup("m1-network-pending-legacy")

	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("create synthetic Owner approval key")
	}
	ownerDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("create synthetic Client device key")
	}
	const (
		nodeID        = "network-m1-synthetic-node"
		deviceID      = "network-m1-synthetic-owner-device"
		nativePrimary = "network-m1-native-primary"
		nativePending = "network-m1-native-pending"
		nativeSecond  = "network-m1-native-second"
		nativeBeta    = "network-m1-native-beta-only"
		alias         = "network-m1-shared-alias"
		networkA      = "network_m1_alpha"
		networkB      = "network_m1_beta"
	)
	ownerPrivate, err := ownerKey.MarshalBinary()
	if err != nil {
		t.Fatal("serialize synthetic Owner approval key")
	}
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal("create private synthetic credential directory")
	}
	ownerPrivatePath := filepath.Join(privateDir, "owner.key")
	if err := os.WriteFile(ownerPrivatePath, ownerPrivate, 0o600); err != nil {
		t.Fatal("write synthetic Owner key")
	}
	if err := os.Chmod(ownerPrivatePath, 0o600); err != nil {
		t.Fatal("protect synthetic Owner key")
	}
	// Bootstrap only the existing Hub Owner approval and owner-bound Node
	// fixture locally. Network creation and all mapping/activation decisions use
	// the compiled operator CLI below; Join and peer actions use HTTP.
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal("open only the disposable Hub StateDir")
	}
	if err := persistence.EnsureLocalOwnerPrincipal(owner.ID); err != nil {
		_ = persistence.Close()
		t.Fatal("ensure synthetic Owner principal")
	}
	registeredOwnerKey, err := persistence.RegisterOwnerApprovalKeyLocal(owner.ID, ownerKey.Public())
	if err != nil {
		_ = persistence.Close()
		t.Fatal("register synthetic Owner approval key")
	}
	dbHubID, err := persistence.GetClientHubID()
	if err != nil || dbHubID != hub.HubID {
		_ = persistence.Close()
		t.Fatal("Hub identity did not match its isolated SQLite state")
	}
	now := time.Now().UTC()
	deviceGrant, err := ownerKey.SignOwnerDeviceGrant(owner.ID, deviceID, ownerDevice.Public(),
		hub.HubID, e2ee.OwnerDevicePurposeControl, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		_ = persistence.Close()
		t.Fatal("sign synthetic Owner device grant")
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: owner.ID, OwnerKeyID: registeredOwnerKey.KeyID, DeviceID: deviceID,
		DevicePublic: ownerDevice.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		_ = persistence.Close()
		t.Fatal("register synthetic Owner Client device")
	}
	nodeToken, nodeDigest, err := fabric.NewNodeCredential()
	if err != nil {
		_ = persistence.Close()
		t.Fatal("create synthetic Node credential")
	}
	codeHash := sha256.Sum256([]byte("synthetic-network-m1-owner-confirmation-code"))
	codeDigest := hex.EncodeToString(codeHash[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, "M1 Synthetic Node",
		nodeDigest, codeDigest, now.Add(10*time.Minute)); err != nil {
		_ = persistence.Close()
		t.Fatal("create synthetic Node owner-binding request")
	}
	if _, err := persistence.ConfirmPendingNodeDeviceBinding(owner.ID, deviceID, codeDigest); err != nil {
		_ = persistence.Close()
		t.Fatal("confirm synthetic Node owner binding")
	}
	if err := persistence.Close(); err != nil {
		t.Fatal("close synthetic bootstrap Store")
	}

	nodeHeaders := map[string]string{"Authorization": "CicadaNode " + nodeToken}
	joinLegacy := func(groupID, sessionID, endpointName string) fabric.JoinResult {
		t.Helper()
		var result fabric.JoinResult
		body := map[string]any{"group_id": groupID, "harness": "codex",
			"native_session_id": sessionID, "endpoint_name": endpointName,
			"workspace": "/tmp/cicada-network-m1"}
		if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/join", body,
			nodeHeaders, http.StatusCreated), &result); err != nil || result.Endpoint.ID == "" || result.SessionToken == "" {
			t.Fatal("could not establish synthetic legacy Group session")
		}
		return result
	}
	primaryLegacy := joinLegacy(groupA.ID, nativePrimary, alias)
	pendingLegacy := joinLegacy(groupPending.ID, nativePending, "pending-only")
	if primaryLegacy.Endpoint.ID == pendingLegacy.Endpoint.ID {
		t.Fatal("distinct synthetic native sessions reused one Endpoint")
	}

	runOperator := func(operation string, args ...string) []byte {
		t.Helper()
		allArgs := append([]string{"network", operation}, args...)
		command := exec.Command("/out/cicada", allArgs...)
		output, err := command.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("synthetic Network operator command %q exited %d", operation, exitErr.ExitCode())
			}
			t.Fatalf("could not run synthetic Network operator command %q", operation)
		}
		return bytes.TrimSpace(output)
	}
	dbArg := []string{"--db", dbPath}
	var createdA store.Network
	if err := json.Unmarshal(runOperator("create", append(append([]string{}, dbArg...),
		"--hub", hub.HubID, "--network", networkA, "--name", "M1 Alpha", "--owner", owner.ID)...),
		&createdA); err != nil || createdA.ID != networkA || createdA.HubID != hub.HubID {
		t.Fatal("operator CLI could not create Network A")
	}
	var createdB store.Network
	if err := json.Unmarshal(runOperator("create", append(append([]string{}, dbArg...),
		"--hub", hub.HubID, "--network", networkB, "--name", "M1 Beta", "--owner", owner.ID)...),
		&createdB); err != nil || createdB.ID != networkB || createdB.HubID != hub.HubID {
		t.Fatal("operator CLI could not create Network B")
	}
	mapGroup := func(group store.Group, networkID string, approve bool) {
		t.Helper()
		mappingArgs := append(append([]string{}, dbArg...), "--group", group.ID,
			"--network", networkID, "--expected-version", strconv.FormatInt(group.Version, 10))
		runOperator("map-prepare", append(mappingArgs, "--reason", "synthetic explicit M1 mapping")...)
		if approve {
			runOperator("map-approve", mappingArgs...)
		}
	}
	mapGroup(groupA, networkA, true)
	mapGroup(groupB, networkB, true)
	mapGroup(groupPending, networkA, false)
	var report store.NetworkMigrationReport
	dryRunOutput := runOperator("migration-dry-run", dbArg...)
	if err := json.Unmarshal(dryRunOutput, &report); err != nil ||
		report.Phase != store.NetworkModePreparing || report.PendingCount != 1 ||
		report.ApprovedCount != 2 || report.UnmappedCount != 0 {
		t.Fatal("migration dry-run did not report two explicit assignments and one pending quarantine")
	}
	if bytes.Contains(dryRunOutput, []byte(nodeToken)) || bytes.Contains(dryRunOutput, ownerPrivate) {
		t.Fatal("migration dry-run exposed a synthetic credential or private key")
	}
	runOperator("activate", dbArg...)
	var activation struct {
		Phase string `json:"phase"`
	}
	if err := json.Unmarshal(runOperator("list", dbArg...), &activation); err != nil || activation.Phase != store.NetworkModeActive {
		t.Fatal("operator CLI did not persist one-way Network activation")
	}

	// Activation preserves the existing pending Group and legacy endpoint data.
	persistence, err = store.New(dbPath)
	if err != nil {
		t.Fatal("reopen disposable Hub state after activation")
	}
	pendingAfter, pendingErr := persistence.GetGroup(groupPending.ID)
	primaryAfter, primaryErr := persistence.GetEndpointV2(primaryLegacy.Endpoint.ID)
	pendingMembership, pendingMembershipErr := persistence.GetMembershipByPrincipalGroup(
		pendingLegacy.Endpoint.PrincipalID, groupPending.ID)
	pendingBinding, pendingBindingErr := persistence.GetActiveSessionBinding(pendingLegacy.Endpoint.ID)
	if pendingErr != nil || pendingAfter.NetworkID != "" || pendingAfter.Version != groupPending.Version ||
		primaryErr != nil || primaryAfter.ID != primaryLegacy.Endpoint.ID ||
		pendingMembershipErr != nil || pendingMembership.Status != store.MembershipStatusActive ||
		pendingBindingErr != nil || pendingBinding.ID != pendingLegacy.BindingID {
		_ = persistence.Close()
		t.Fatal("one-way activation rewrote or removed pending Group or legacy Endpoint state")
	}
	if err := persistence.Close(); err != nil {
		t.Fatal("close post-activation state snapshot")
	}
	groupHeaders := map[string]string{"Authorization": "CicadaSession " + pendingLegacy.SessionToken,
		"Cicada-Group-Scope": groupPending.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders)

	const discoverGrants = "directory.discover,directory.publish"
	const directGrants = "directory.discover,directory.publish,direct.send,direct.receive"
	const adminGrants = "directory.discover,directory.publish,direct.send,direct.receive,network.admin.invite"
	issueAndJoin := func(networkID, sessionID, endpointName, grants string) fabric.NetworkJoinResult {
		t.Helper()
		invitationPath := filepath.Join(privateDir, networkID+"-"+sessionID+"-invite")
		proofPath := filepath.Join(privateDir, networkID+"-"+sessionID+"-proof")
		runOperator("invite", append(append([]string{}, dbArg...), "--network", networkID,
			"--target-owner", owner.ID, "--invitation-file", invitationPath, "--grants", grants,
			"--ttl", "15m")...)
		runOperator("consent-sign", "--owner-private", ownerPrivatePath,
			"--proof-file", proofPath, "--invitation-file", invitationPath,
			"--owner", owner.ID, "--hub", hub.HubID, "--network", networkID,
			"--node", nodeID, "--session", sessionID, "--grants", grants, "--discoverable")
		invitation, err := os.ReadFile(invitationPath)
		if err != nil {
			t.Fatal("read private synthetic invitation")
		}
		proof, err := os.ReadFile(proofPath)
		if err != nil {
			t.Fatal("read private synthetic Owner consent")
		}
		if len(invitation) == 0 || len(proof) == 0 {
			t.Fatal("operator CLI produced an empty synthetic invitation or consent")
		}
		body := fabric.NetworkJoinInput{NetworkID: networkID,
			InvitationToken: string(bytes.TrimSpace(invitation)),
			OwnerJoinProof:  string(bytes.TrimSpace(proof)), Harness: "codex",
			NativeSessionID: sessionID, EndpointName: endpointName}
		var result fabric.NetworkJoinResult
		if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/join", body,
			nodeHeaders, http.StatusCreated), &result); err != nil || result.Endpoint.ID == "" || result.SessionToken == "" {
			t.Fatal("Network Join did not return the scoped synthetic Endpoint")
		}
		if err := os.Remove(invitationPath); err != nil {
			t.Fatal("remove consumed synthetic invitation")
		}
		if err := os.Remove(proofPath); err != nil {
			t.Fatal("remove consumed synthetic Owner proof")
		}
		return result
	}

	primaryA := issueAndJoin(networkA, nativePrimary, alias, adminGrants)
	primaryB := issueAndJoin(networkB, nativePrimary, alias, discoverGrants)
	secondA := issueAndJoin(networkA, nativeSecond, alias, directGrants)
	betaOnly := issueAndJoin(networkB, nativeBeta, "beta-only", discoverGrants)
	if primaryA.Endpoint.ID != primaryLegacy.Endpoint.ID || primaryB.Endpoint.ID != primaryA.Endpoint.ID ||
		primaryA.Endpoint.PrincipalID != primaryB.Endpoint.PrincipalID || primaryA.BindingID == primaryB.BindingID ||
		secondA.Endpoint.ID == primaryA.Endpoint.ID {
		t.Fatal("per-Network Join changed the stable Endpoint or reused a scoped access binding")
	}

	persistence, err = store.New(dbPath)
	if err != nil {
		t.Fatal("open disposable Hub state for scope checks")
	}
	groupBindingAfter, bindingErr := persistence.GetActiveSessionBinding(primaryA.Endpoint.ID)
	groupMembershipAfter, membershipErr := persistence.GetMembershipByPrincipalGroup(primaryA.Endpoint.PrincipalID, groupA.ID)
	_, secondGroupErr := persistence.GetMembershipByPrincipalGroup(secondA.Endpoint.PrincipalID, groupA.ID)
	if bindingErr != nil || groupBindingAfter.ID != primaryLegacy.BindingID ||
		groupBindingAfter.Epoch != primaryLegacy.BindingEpoch || groupBindingAfter.CredentialHash != fabric.HashSessionCredential(primaryLegacy.SessionToken) ||
		membershipErr != nil || groupMembershipAfter.Status != store.MembershipStatusActive ||
		!errors.Is(secondGroupErr, store.ErrMembershipNotFound) {
		_ = persistence.Close()
		t.Fatal("Network Join changed the Group writer or granted Group membership implicitly")
	}
	primaryPrincipal := primaryA.Endpoint.PrincipalID
	primaryMembership, err := persistence.GetNetworkMembership(networkA, primaryPrincipal)
	if err != nil || primaryMembership.Status != "active" {
		_ = persistence.Close()
		t.Fatal("Network A membership was not established")
	}
	secondMembership, err := persistence.GetNetworkMembership(networkA, secondA.Endpoint.PrincipalID)
	if err != nil || secondMembership.Status != "active" {
		_ = persistence.Close()
		t.Fatal("second synthetic Network A membership was not established")
	}
	if err := persistence.Close(); err != nil {
		t.Fatal("close scope-check Store")
	}

	primaryAHeaders := map[string]string{"Authorization": "Cicada-Network-Session " + primaryA.SessionToken}
	primaryBHeaders := map[string]string{"Authorization": "Cicada-Network-Session " + primaryB.SessionToken}
	secondAHeaders := map[string]string{"Authorization": "Cicada-Network-Session " + secondA.SessionToken}
	pathA := "/v2/fabric/networks/" + networkA + "/directory"
	pathB := "/v2/fabric/networks/" + networkB + "/directory"
	var directoryA, directoryB struct {
		Endpoints []fabric.NetworkEndpointCard `json:"endpoints"`
	}
	if err := json.Unmarshal(expect(http.MethodGet, pathA, nil, primaryAHeaders, http.StatusOK), &directoryA); err != nil || len(directoryA.Endpoints) != 2 {
		t.Fatal("Network A directory did not contain its two discoverable endpoints")
	}
	if err := json.Unmarshal(expect(http.MethodGet, pathB, nil, primaryBHeaders, http.StatusOK), &directoryB); err != nil || len(directoryB.Endpoints) != 2 {
		t.Fatal("Network B directory exposed a cross-Network Endpoint")
	}
	seenBetaOnlyInA := false
	for _, card := range directoryA.Endpoints {
		if card.EndpointID == betaOnly.Endpoint.ID {
			seenBetaOnlyInA = true
		}
	}
	seenBetaOnlyInB := false
	for _, card := range directoryB.Endpoints {
		if card.EndpointID == betaOnly.Endpoint.ID {
			seenBetaOnlyInB = true
		}
	}
	if seenBetaOnlyInA || !seenBetaOnlyInB {
		t.Fatal("Network A directory did not filter the Beta-only Endpoint")
	}
	if status := expectDenied(http.MethodGet, pathA, nil, nil); status != http.StatusUnauthorized {
		t.Fatal("an unjoined caller received Network directory data")
	}
	wrongScopeStatus := expectDenied(http.MethodGet, pathB, nil, primaryAHeaders)
	unknownScopeStatus := expectDenied(http.MethodGet, "/v2/fabric/networks/network_m1_unknown/directory", nil, primaryAHeaders)
	if wrongScopeStatus != unknownScopeStatus {
		t.Fatal("Network scope mismatch exposed whether a different Network exists")
	}

	resolve := func(networkID, query string, headers map[string]string) (int, fabric.NetworkEndpointCard) {
		t.Helper()
		status, data := call(http.MethodPost, "/v2/fabric/networks/"+networkID+"/resolve",
			map[string]string{"query": query}, headers)
		var result fabric.NetworkEndpointCard
		if status == http.StatusOK {
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal("decode scoped Network resolve result")
			}
		}
		return status, result
	}
	if status, _ := resolve(networkA, alias, primaryAHeaders); status != http.StatusConflict {
		t.Fatalf("duplicate alias in Network A returned status %d, want 409", status)
	}
	if status, card := resolve(networkB, alias, primaryBHeaders); status != http.StatusOK || card.EndpointID != primaryA.Endpoint.ID {
		t.Fatal("Network B alias resolution was not filtered to its own Endpoint")
	}
	if status, _ := resolve(networkA, "beta-only", primaryAHeaders); status != http.StatusNotFound {
		t.Fatalf("Network A resolved a Beta-only nickname with status %d", status)
	}
	if status, card := resolve(networkB, "beta-only", primaryBHeaders); status != http.StatusOK || card.EndpointID != betaOnly.Endpoint.ID {
		t.Fatal("Network B could not resolve its own unique alias")
	}

	// Only the narrowly granted NetworkAdmin operation succeeds. A Group or
	// management bearer is not a substitute, and a Network A grant cannot act in B.
	invitationBody := map[string]any{"target_owner_id": "network-m1-invite-target",
		"grants": []string{"directory.discover"}, "ttl_seconds": 900}
	invitationStatus, invitationResponse := call(http.MethodPost,
		"/v2/fabric/networks/"+networkA+"/invitations", invitationBody, primaryAHeaders)
	var adminInvitation struct {
		NetworkID string `json:"network_id"`
		Token     string `json:"invitation_token"`
	}
	if invitationStatus != http.StatusCreated || json.Unmarshal(invitationResponse, &adminInvitation) != nil ||
		adminInvitation.NetworkID != networkA || adminInvitation.Token == "" {
		t.Fatal("NetworkAdmin grant could not issue its named Network invitation")
	}
	expectDenied(http.MethodPost, "/v2/fabric/networks/"+networkB+"/invitations",
		invitationBody, primaryBHeaders)
	if status := expectDenied(http.MethodPost, "/v2/fabric/networks/"+networkA+"/invitations",
		invitationBody, managementHeaders); status != http.StatusUnauthorized {
		t.Fatal("management bearer was accepted as NetworkAdmin")
	}
	unsignedInvitePath := filepath.Join(privateDir, "unsigned-owner-invite")
	runOperator("invite", append(append([]string{}, dbArg...), "--network", networkA,
		"--target-owner", owner.ID, "--invitation-file", unsignedInvitePath,
		"--grants", discoverGrants, "--ttl", "15m")...)
	unsignedInvite, err := os.ReadFile(unsignedInvitePath)
	if err != nil {
		t.Fatal("read private invitation for negative Owner consent check")
	}
	status, _ := call(http.MethodPost, "/v2/fabric/node/networks/join", fabric.NetworkJoinInput{
		NetworkID: networkA, InvitationToken: string(bytes.TrimSpace(unsignedInvite)),
		OwnerJoinProof: "{}", Harness: "codex", NativeSessionID: "network-m1-unapproved-session",
		EndpointName: "must-not-join",
	}, nodeHeaders)
	if status != http.StatusForbidden {
		t.Fatalf("NetworkAdmin/Node credential adopted an Endpoint without Owner proof: status %d", status)
	}
	// Even a valid Owner proof cannot let an unjoined caller choose a different
	// native Thread or assert a Node ID in the HTTP body.
	const approvedUnjoinedSession = "network-m1-approved-unjoined"
	proof, err := ownerKey.SignOwnerNetworkJoinGrant(owner.ID, hub.HubID, networkA,
		nodeID, approvedUnjoinedSession,
		store.NetworkInvitationDigest(string(bytes.TrimSpace(unsignedInvite))),
		registeredOwnerKey.KeyID, []string{"directory.discover", "directory.publish"}, true,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal("sign synthetic scoped negative Join proof")
	}
	forgedJoin := fabric.NetworkJoinInput{NetworkID: networkA,
		InvitationToken: string(bytes.TrimSpace(unsignedInvite)), OwnerJoinProof: string(proof),
		Harness: "codex", NativeSessionID: "forged-other-thread", EndpointName: "must-not-join"}
	if status, _ := call(http.MethodPost, "/v2/fabric/node/networks/join", forgedJoin, nodeHeaders); status != http.StatusForbidden {
		t.Fatalf("valid Owner proof authorized a different unjoined Thread: %d", status)
	}
	if status, _ := call(http.MethodPost, "/v2/fabric/node/networks/join", map[string]any{
		"network_id": networkA, "invitation_token": string(bytes.TrimSpace(unsignedInvite)),
		"owner_join_proof": string(proof), "harness": "codex",
		"native_session_id": approvedUnjoinedSession, "endpoint_name": "must-not-join",
		"node_id": "forged-node",
	}, nodeHeaders); status != http.StatusBadRequest {
		t.Fatalf("caller-asserted Node ID passed strict Network Join schema: %d", status)
	}
	if err := os.Remove(unsignedInvitePath); err != nil {
		t.Fatal("remove unused synthetic invitation")
	}
	groupHeaders = map[string]string{"Authorization": "CicadaSession " + primaryLegacy.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expect(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders, http.StatusOK)
	networkOnlyGroupHeaders := map[string]string{"Authorization": "CicadaSession " + secondA.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, networkOnlyGroupHeaders)

	// A Network access credential is only a discovery/Network-management
	// credential. It cannot impersonate a Group session, Node, Client device,
	// or global operator, even when selectors name resources in its Network.
	for _, path := range []string{"/v2/fabric/whoami", "/v2/fabric/tasks", "/v1/groups", "/v1/approvals"} {
		if status := expectDenied(http.MethodGet, path, nil, primaryAHeaders); status != http.StatusUnauthorized {
			t.Fatalf("Network credential reached %s with status %d", path, status)
		}
	}
	if status := expectDenied(http.MethodPost, "/v2/fabric/send", map[string]string{"body": "must not send"}, primaryAHeaders); status != http.StatusUnauthorized {
		t.Fatalf("Network-only credential reached legacy Group send: %d", status)
	}
	if status := expectDenied(http.MethodPost, "/v2/relay/nodes/"+nodeID+"/claim", nil, primaryAHeaders); status != http.StatusUnauthorized {
		t.Fatalf("Network credential reached Node claim: %d", status)
	}
	if status := expectDenied(http.MethodGet, pathA, nil, groupHeaders); status != http.StatusUnauthorized {
		t.Fatalf("Group credential was accepted as Network access: %d", status)
	}
	spoofedGroupHeaders := map[string]string{"Authorization": groupHeaders["Authorization"],
		"Cicada-Group-Scope": groupB.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, spoofedGroupHeaders)
	spoofedNetworkHeaders := map[string]string{"Authorization": primaryAHeaders["Authorization"],
		"Cicada-Group-Scope": groupB.ID}
	expect(http.MethodGet, pathA, nil, spoofedNetworkHeaders, http.StatusOK)
	expectDenied(http.MethodGet, pathB, nil, spoofedNetworkHeaders)
	if status, _ := call(http.MethodPost, "/v2/fabric/node/networks/renew",
		fabric.NetworkRenewInput{NetworkID: networkA, EndpointID: primaryA.Endpoint.ID,
			Harness: "codex", NativeSessionID: "forged-other-thread"}, nodeHeaders); status != http.StatusForbidden {
		t.Fatalf("Node credential renewed a different native Thread: %d", status)
	}
	if status, _ := call(http.MethodPost, "/v2/fabric/node/networks/renew",
		map[string]any{"network_id": networkA, "endpoint_id": primaryA.Endpoint.ID,
			"harness": "codex", "native_session_id": nativePrimary, "node_id": "forged-node"}, nodeHeaders); status != http.StatusBadRequest {
		t.Fatalf("caller-asserted Node ID passed the strict Network Renew schema: %d", status)
	}
	if status, _ := call(http.MethodPost, "/v2/fabric/send", map[string]string{"target": secondA.Endpoint.ID,
		"body": "retired plaintext path"}, groupHeaders); status != http.StatusGone {
		t.Fatalf("authenticated legacy plaintext send returned %d, want 410", status)
	}

	// Renewal rotates only A's access credential. Neither B nor the original
	// Group writer may be replaced by a Network access epoch.
	var renewedA fabric.NetworkJoinResult
	if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/renew",
		fabric.NetworkRenewInput{NetworkID: networkA, EndpointID: primaryA.Endpoint.ID,
			Harness: "codex", NativeSessionID: nativePrimary}, nodeHeaders, http.StatusCreated), &renewedA); err != nil ||
		renewedA.Endpoint.ID != primaryA.Endpoint.ID || renewedA.BindingID != primaryA.BindingID ||
		renewedA.BindingEpoch <= primaryA.BindingEpoch || renewedA.SessionToken == primaryA.SessionToken {
		t.Fatal("Network A renewal did not rotate only its access session")
	}
	if status := expectDenied(http.MethodGet, pathA, nil, primaryAHeaders); status != http.StatusUnauthorized {
		t.Fatalf("old Network A credential survived renewal: %d", status)
	}
	primaryAHeaders = map[string]string{"Authorization": "Cicada-Network-Session " + renewedA.SessionToken}
	expect(http.MethodGet, pathA, nil, primaryAHeaders, http.StatusOK)
	expect(http.MethodGet, pathB, nil, primaryBHeaders, http.StatusOK)
	expect(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders, http.StatusOK)

	// A separate no-Group Thread now exchanges Endpoint-encrypted messages
	// over the real Node HTTP route. Both key grants travel through the same
	// accepted encrypted Client device protocol as production Owner consent.
	clientBinding := clientwire.Binding{HubID: hub.HubID, OwnerID: owner.ID,
		DeviceID: deviceID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	var clientSequence uint64
	clientRPC := func(operation string, payload any, target any) {
		t.Helper()
		clientSequence++
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		route := clientwire.Route{Version: clientwire.Version,
			Direction: clientwire.DirectionRequest, HubID: hub.HubID,
			OwnerID: owner.ID, DeviceID: deviceID, SessionEpoch: 1,
			Sequence: clientSequence, OperationID: fmt.Sprintf("synthetic-network-direct-%d", clientSequence),
			Operation: operation, SenderKeyID: ownerDevice.Public().ID, SenderKeyVersion: 1,
			ReceiverKeyID: hub.ControlPublicIdentity.ID, ReceiverKeyVersion: 1}
		packet, err := clientwire.SealRequest(ownerDevice, hub.ControlPublicIdentity,
			clientBinding, route, body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, baseURL+"/v2/client/rpc",
			bytes.NewReader(packet))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("encrypted %s HTTP=%d", operation, response.StatusCode)
		}
		ciphertext, err := io.ReadAll(io.LimitReader(response.Body, 256*1024+1))
		if err != nil || len(ciphertext) > 256*1024 {
			t.Fatal("read encrypted Client result")
		}
		opened, err := clientwire.OpenResponse(ownerDevice, hub.ControlPublicIdentity,
			clientBinding, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			OK     bool            `json:"ok"`
			Result json.RawMessage `json:"result"`
			Error  string          `json:"error"`
		}
		if err := json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK {
			t.Fatalf("encrypted %s result denied: %s %v", operation, result.Error, err)
		}
		if target != nil && json.Unmarshal(result.Result, target) != nil {
			t.Fatalf("decode encrypted %s result", operation)
		}
	}
	var ownerTopology struct {
		Networks []struct {
			NetworkID string `json:"network_id"`
		} `json:"networks"`
	}
	clientRPC("topology.snapshot", map[string]any{}, &ownerTopology)
	if len(ownerTopology.Networks) != 2 {
		t.Fatal("encrypted Client topology did not project both Owner Networks")
	}
	directPath := "/v2/fabric/networks/" + networkA + "/direct/"
	publishKey := func(join fabric.NetworkJoinResult, headers map[string]string,
		identity *e2ee.Identity, nativeID string) {
		t.Helper()
		var binding store.NetworkDirectNativeBinding
		if err := json.Unmarshal(expect(http.MethodPost, directPath+"native-binding", nil,
			headers, http.StatusOK), &binding); err != nil || binding.ID == "" ||
			binding.NativeSessionID != nativeID {
			t.Fatalf("Network native binding: %#v %v", binding, err)
		}
		attestation, err := identity.SignNetworkDirectKeyAttestation(hub.HubID, networkA,
			join.Endpoint.ID, join.Endpoint.PrincipalID, nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		expect(http.MethodPost, directPath+"key-candidate", map[string]any{
			"attestation": attestation}, headers, http.StatusCreated)
		var manifest store.NetworkDirectKeyManifest
		clientRPC("network.key_manifest", map[string]any{"network_id": networkA,
			"endpoint_id": join.Endpoint.ID, "owner_key_id": registeredOwnerKey.KeyID}, &manifest)
		if manifest.NativeSessionID != nativeID ||
			manifest.NativeSessionDigest != e2ee.NetworkDirectNativeSessionDigest(nativeID) {
			t.Fatal("Owner manifest did not bind the native Thread")
		}
		proof, err := ownerKey.SignOwnerNetworkDirectKeyGrant(hub.HubID, networkA,
			join.Endpoint.ID, owner.ID, manifest.Digest, time.Now().UTC().Add(-time.Minute),
			time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		clientRPC("network.key_grant", map[string]any{"network_id": networkA,
			"endpoint_id": join.Endpoint.ID, "signed_proof": proof}, nil)
	}
	primaryDirectKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondDirectKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publishKey(renewedA, primaryAHeaders, primaryDirectKey, nativePrimary)
	publishKey(secondA, secondAHeaders, secondDirectKey, nativeSecond)
	var directBundle store.NetworkDirectPeerBundle
	if err := json.Unmarshal(expect(http.MethodPost, directPath+"peer-key",
		map[string]string{"target_endpoint_id": secondA.Endpoint.ID}, primaryAHeaders,
		http.StatusOK), &directBundle); err != nil ||
		directBundle.Sender.Manifest.NativeSessionID != "" ||
		directBundle.Receiver.Manifest.NativeSessionID != "" {
		t.Fatal("Network peer bundle leaked native locator")
	}
	sendID := "msg_synthetic_http_direct_send"
	sendContext := store.NetworkDirectContext(&directBundle, sendID, "SEND", "", "")
	sendWire, err := e2ee.SealNetworkDirectMessage(primaryDirectKey, secondDirectKey.Public(),
		sendContext, []byte("synthetic HTTP direct SEND"), 1)
	if err != nil {
		t.Fatal(err)
	}
	var sent store.RelaySealedV1Record
	if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/direct/send",
		fabric.NetworkDirectSendInput{NetworkID: networkA,
			NetworkSessionToken: renewedA.SessionToken, TargetEndpointID: secondA.Endpoint.ID,
			MessageID: sendID, IdempotencyKey: "synthetic-http-once", Ciphertext: sendWire},
		nodeHeaders, http.StatusAccepted), &sent); err != nil || sent.Route.MessageID != sendID {
		t.Fatal("real HTTP Network direct SEND not accepted")
	}
	claimDirect := func() []fabric.NetworkDirectDelivery {
		t.Helper()
		var claimed struct {
			Deliveries []fabric.NetworkDirectDelivery `json:"deliveries"`
		}
		if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/direct/claim",
			map[string]any{"node_id": nodeID, "consumer_id": "synthetic-http-direct-consumer", "limit": 10},
			nodeHeaders, http.StatusOK), &claimed); err != nil {
			t.Fatal(err)
		}
		return claimed.Deliveries
	}
	firstClaims := claimDirect()
	if len(firstClaims) != 1 || firstClaims[0].MessageID != sendID {
		t.Fatal("Node claim missed exact Network direct SEND")
	}
	var sendAuthorization store.NetworkDirectDeliveryAuthorization
	if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/direct/authorize",
		map[string]string{"message_id": sendID, "attempt_id": firstClaims[0].AttemptID},
		nodeHeaders, http.StatusOK), &sendAuthorization); err != nil ||
		sendAuthorization.NativeSessionID != nativeSecond {
		t.Fatal("Node authorize changed native target")
	}
	if _, _, err := e2ee.OpenNetworkDirectMessage(secondDirectKey, primaryDirectKey.Public(),
		sendAuthorization.Context, firstClaims[0].Ciphertext); err != nil {
		t.Fatal(err)
	}
	firstReceipt := fabric.NodeReceiptInput{AttemptID: firstClaims[0].AttemptID, MessageID: sendID,
		Digest: firstClaims[0].Digest, EndpointID: secondA.Endpoint.ID,
		BindingID: firstClaims[0].BindingID, BindingEpoch: firstClaims[0].BindingEpoch,
		Layer: store.RelayReceiptNodeReceived}
	expect(http.MethodPost, "/v2/fabric/node/networks/direct/receipt", firstReceipt,
		nodeHeaders, http.StatusOK)
	requestID, askID := "rq_synthetic_http_direct", "msg_synthetic_http_direct_ask"
	askContext := store.NetworkDirectContext(&directBundle, askID, "REQUEST", requestID, "")
	askWire, err := e2ee.SealNetworkDirectMessage(primaryDirectKey, secondDirectKey.Public(),
		askContext, []byte("synthetic HTTP direct ASK"), 2)
	if err != nil {
		t.Fatal(err)
	}
	expect(http.MethodPost, "/v2/fabric/node/networks/direct/ask",
		fabric.NetworkDirectAskInput{NetworkID: networkA, NetworkSessionToken: renewedA.SessionToken,
			TargetEndpointID: secondA.Endpoint.ID, MessageID: askID, RequestID: requestID,
			IdempotencyKey: "synthetic-http-ask", ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
			Ciphertext: askWire}, nodeHeaders, http.StatusAccepted)
	askClaims := claimDirect()
	if len(askClaims) != 1 || askClaims[0].MessageID != askID {
		t.Fatal("Node claim missed Network direct ASK")
	}
	var replyRoute store.NetworkDirectReplyRoute
	if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/direct/reply-route",
		map[string]string{"network_id": networkA, "network_session_token": secondA.SessionToken,
			"request_id": requestID}, nodeHeaders, http.StatusOK), &replyRoute); err != nil ||
		replyRoute.RequestMessageID != askID {
		t.Fatal("trusted reply route did not correlate original ASK")
	}
	replyID := "msg_synthetic_http_direct_reply"
	replyContext := store.NetworkDirectContext(replyRoute.Bundle, replyID, "REPLY", requestID, askID)
	replyWire, err := e2ee.SealNetworkDirectMessage(secondDirectKey, primaryDirectKey.Public(),
		replyContext, []byte("synthetic HTTP direct REPLY"), 1)
	if err != nil {
		t.Fatal(err)
	}
	expect(http.MethodPost, "/v2/fabric/node/networks/direct/reply",
		fabric.NetworkDirectReplyInput{NetworkID: networkA, NetworkSessionToken: secondA.SessionToken,
			RequestID: requestID, MessageID: replyID, IdempotencyKey: "synthetic-http-reply",
			Ciphertext: replyWire}, nodeHeaders, http.StatusAccepted)
	replyClaims := claimDirect()
	if len(replyClaims) != 1 || replyClaims[0].MessageID != replyID {
		t.Fatal("Node claim missed Network direct REPLY")
	}
	var replyAuthorization store.NetworkDirectDeliveryAuthorization
	if err := json.Unmarshal(expect(http.MethodPost, "/v2/fabric/node/networks/direct/authorize",
		map[string]string{"message_id": replyID, "attempt_id": replyClaims[0].AttemptID},
		nodeHeaders, http.StatusOK), &replyAuthorization); err != nil ||
		replyAuthorization.NativeSessionID != nativePrimary {
		t.Fatal("Network direct REPLY native target mismatch")
	}
	if _, _, err := e2ee.OpenNetworkDirectMessage(primaryDirectKey, secondDirectKey.Public(),
		replyAuthorization.Context, replyClaims[0].Ciphertext); err != nil {
		t.Fatal(err)
	}
	var requestStatus store.FabricRequest
	if err := json.Unmarshal(expect(http.MethodGet, directPath+"request-status?request_id="+requestID,
		nil, primaryAHeaders, http.StatusOK), &requestStatus); err != nil ||
		requestStatus.State != store.FabricRequestReplied {
		t.Fatal("Network direct request status was not REPLIED")
	}

	// The same ACTIVE Store also serves authorized collaboration over HTTP
	// with Control deliberately absent. A trusted management bearer cannot
	// turn that Fabric-only handler into a planner or topology manager.
	isolatedStore, err := store.New(dbPath)
	if err != nil {
		t.Fatal("open disposable ACTIVE Store for Control-free HTTP check")
	}
	ownerPrincipal, err := isolatedStore.GetPrincipal(owner.ID)
	if err != nil {
		_ = isolatedStore.Close()
		t.Fatal("load synthetic Owner for Control-free Fabric service")
	}
	isolatedFabric, err := fabric.NewService(isolatedStore, owner.ID, ownerPrincipal.TrustDomainID)
	if err != nil {
		_ = isolatedStore.Close()
		t.Fatal("construct Control-free Fabric service")
	}
	isolatedHTTP := httptest.NewServer(NewFabricHandler(isolatedFabric, "synthetic-operator"))
	standaloneStatus := func(path string, headers map[string]string) int {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, isolatedHTTP.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		result, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer result.Body.Close()
		return result.StatusCode
	}
	standaloneCall := func(path string, payload any, headers map[string]string, wanted int, target any) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, isolatedHTTP.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != wanted {
			t.Fatalf("Control-free %s returned %d, want %d", path, response.StatusCode, wanted)
		}
		if target != nil && json.NewDecoder(response.Body).Decode(target) != nil {
			t.Fatalf("decode Control-free %s", path)
		}
	}
	if standaloneStatus(pathB, primaryBHeaders) != http.StatusOK ||
		standaloneStatus(directPath+"request-status?request_id="+requestID, primaryAHeaders) != http.StatusOK ||
		standaloneStatus("/v2/fabric/whoami", groupHeaders) != http.StatusOK ||
		standaloneStatus("/v2/fabric/members", groupHeaders) != http.StatusOK ||
		standaloneStatus("/v1/groups", map[string]string{"Authorization": "Bearer synthetic-operator"}) != http.StatusServiceUnavailable {
		isolatedHTTP.Close()
		_ = isolatedStore.Close()
		t.Fatal("ACTIVE Fabric HTTP collaboration depended on Control business availability")
	}
	// Exercise a fresh encrypted ASK/REPLY chain through only the Fabric
	// service. The prior status check alone would merely read old state.
	const isolatedRequestID = "rq_synthetic_control_free_direct"
	const isolatedAskID = "msg_synthetic_control_free_ask"
	const isolatedReplyID = "msg_synthetic_control_free_reply"
	isolatedAskContext := store.NetworkDirectContext(&directBundle, isolatedAskID,
		"REQUEST", isolatedRequestID, "")
	isolatedAskWire, err := e2ee.SealNetworkDirectMessage(primaryDirectKey,
		secondDirectKey.Public(), isolatedAskContext, []byte("control-free ASK"), 3)
	if err != nil {
		t.Fatal(err)
	}
	standaloneCall("/v2/fabric/node/networks/direct/ask", fabric.NetworkDirectAskInput{
		NetworkID: networkA, NetworkSessionToken: renewedA.SessionToken,
		TargetEndpointID: secondA.Endpoint.ID, MessageID: isolatedAskID,
		RequestID: isolatedRequestID, IdempotencyKey: "synthetic-control-free-ask",
		ExpiresAt:  time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
		Ciphertext: isolatedAskWire}, nodeHeaders, http.StatusAccepted, nil)
	var isolatedClaims struct {
		Deliveries []fabric.NetworkDirectDelivery `json:"deliveries"`
	}
	standaloneCall("/v2/fabric/node/networks/direct/claim",
		map[string]any{"node_id": nodeID, "consumer_id": "synthetic-control-free", "limit": 10},
		nodeHeaders, http.StatusOK, &isolatedClaims)
	if len(isolatedClaims.Deliveries) != 1 || isolatedClaims.Deliveries[0].MessageID != isolatedAskID {
		t.Fatal("Control-free Node did not claim its ASK")
	}
	var isolatedAskAuth store.NetworkDirectDeliveryAuthorization
	standaloneCall("/v2/fabric/node/networks/direct/authorize",
		map[string]string{"message_id": isolatedAskID, "attempt_id": isolatedClaims.Deliveries[0].AttemptID},
		nodeHeaders, http.StatusOK, &isolatedAskAuth)
	if isolatedAskAuth.NativeSessionID != nativeSecond {
		t.Fatal("Control-free ASK authorized the wrong native Thread")
	}
	if _, _, err := e2ee.OpenNetworkDirectMessage(secondDirectKey, primaryDirectKey.Public(),
		isolatedAskAuth.Context, isolatedClaims.Deliveries[0].Ciphertext); err != nil {
		t.Fatal(err)
	}
	var isolatedReplyRoute store.NetworkDirectReplyRoute
	standaloneCall("/v2/fabric/node/networks/direct/reply-route",
		map[string]string{"network_id": networkA, "network_session_token": secondA.SessionToken,
			"request_id": isolatedRequestID}, nodeHeaders, http.StatusOK, &isolatedReplyRoute)
	if isolatedReplyRoute.Bundle == nil || isolatedReplyRoute.RequestMessageID != isolatedAskID {
		t.Fatal("Control-free reply route lost its original ASK")
	}
	isolatedReplyContext := store.NetworkDirectContext(isolatedReplyRoute.Bundle,
		isolatedReplyID, "REPLY", isolatedRequestID, isolatedAskID)
	isolatedReplyWire, err := e2ee.SealNetworkDirectMessage(secondDirectKey,
		primaryDirectKey.Public(), isolatedReplyContext, []byte("control-free REPLY"), 2)
	if err != nil {
		t.Fatal(err)
	}
	standaloneCall("/v2/fabric/node/networks/direct/reply", fabric.NetworkDirectReplyInput{
		NetworkID: networkA, NetworkSessionToken: secondA.SessionToken,
		RequestID: isolatedRequestID, MessageID: isolatedReplyID,
		IdempotencyKey: "synthetic-control-free-reply", Ciphertext: isolatedReplyWire},
		nodeHeaders, http.StatusAccepted, nil)
	isolatedClaims.Deliveries = nil
	standaloneCall("/v2/fabric/node/networks/direct/claim",
		map[string]any{"node_id": nodeID, "consumer_id": "synthetic-control-free", "limit": 10},
		nodeHeaders, http.StatusOK, &isolatedClaims)
	if len(isolatedClaims.Deliveries) != 1 || isolatedClaims.Deliveries[0].MessageID != isolatedReplyID {
		t.Fatal("Control-free Node did not claim its REPLY")
	}
	var isolatedReplyAuth store.NetworkDirectDeliveryAuthorization
	standaloneCall("/v2/fabric/node/networks/direct/authorize",
		map[string]string{"message_id": isolatedReplyID, "attempt_id": isolatedClaims.Deliveries[0].AttemptID},
		nodeHeaders, http.StatusOK, &isolatedReplyAuth)
	if isolatedReplyAuth.NativeSessionID != nativePrimary {
		t.Fatal("Control-free REPLY authorized the wrong native Thread")
	}
	if _, _, err := e2ee.OpenNetworkDirectMessage(primaryDirectKey, secondDirectKey.Public(),
		isolatedReplyAuth.Context, isolatedClaims.Deliveries[0].Ciphertext); err != nil {
		t.Fatal(err)
	}
	if standaloneStatus(directPath+"request-status?request_id="+isolatedRequestID,
		primaryAHeaders) != http.StatusOK {
		t.Fatal("Control-free ASK/REPLY has no readable current status")
	}
	isolatedHTTP.Close()
	if err := isolatedStore.Close(); err != nil {
		t.Fatal("close Control-free ACTIVE Store")
	}

	// The same native Thread has both A and B registrations. Leaving A must
	// preserve B, and it must not release the original Group writer.
	expect(http.MethodPost, "/v2/fabric/networks/"+networkA+"/leave",
		map[string]string{"reason": "synthetic scoped leave"}, primaryAHeaders, http.StatusOK)
	expectDenied(http.MethodGet, pathA, nil, primaryAHeaders)
	expect(http.MethodGet, pathB, nil, primaryBHeaders, http.StatusOK)

	// Revoke a different A member to prove an operator revocation cannot
	// restore an exited A access session or reach the sibling B registration.
	runOperator("member-revoke", append(append([]string{}, dbArg...), "--network", networkA,
		"--principal", secondA.Endpoint.PrincipalID, "--expected-version", strconv.FormatInt(secondMembership.Revision, 10))...)
	expectDenied(http.MethodGet, pathA, nil, secondAHeaders)
	expect(http.MethodGet, pathB, nil, primaryBHeaders, http.StatusOK)
	groupHeaders = map[string]string{"Authorization": "CicadaSession " + primaryLegacy.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders)
	expectDenied(http.MethodGet, pathA, nil, secondAHeaders)
	persistence, err = store.New(dbPath)
	if err != nil {
		t.Fatal("reopen disposable Hub state after scoped Network lifecycle")
	}
	writerAfter, writerErr := persistence.GetActiveSessionBinding(primaryLegacy.Endpoint.ID)
	if writerErr != nil || writerAfter.ID != primaryLegacy.BindingID || writerAfter.Epoch != primaryLegacy.BindingEpoch {
		_ = persistence.Close()
		t.Fatal("Network renew/leave/revoke changed the original native Group writer")
	}
	if err := persistence.Close(); err != nil {
		t.Fatal("close scoped Network lifecycle snapshot")
	}
}
