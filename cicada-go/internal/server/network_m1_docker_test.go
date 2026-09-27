package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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
		HubID string `json:"hub_id"`
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
	const adminGrants = "directory.discover,directory.publish,network.admin.invite"
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
	secondA := issueAndJoin(networkA, nativeSecond, alias, discoverGrants)
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
	if err := os.Remove(unsignedInvitePath); err != nil {
		t.Fatal("remove unused synthetic invitation")
	}
	groupHeaders = map[string]string{"Authorization": "CicadaSession " + primaryLegacy.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expect(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders, http.StatusOK)
	networkOnlyGroupHeaders := map[string]string{"Authorization": "CicadaSession " + secondA.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, networkOnlyGroupHeaders)

	// A revoke is scoped to its Network and is checked on subsequent reads;
	// the sibling Network registration and old native writer remain distinct.
	runOperator("member-revoke", append(append([]string{}, dbArg...), "--network", networkA,
		"--principal", primaryPrincipal, "--expected-version", strconv.FormatInt(primaryMembership.Revision, 10))...)
	expectDenied(http.MethodGet, pathA, nil, primaryAHeaders)
	expect(http.MethodGet, pathB, nil, primaryBHeaders, http.StatusOK)
	groupHeaders = map[string]string{"Authorization": "CicadaSession " + primaryLegacy.SessionToken,
		"Cicada-Group-Scope": groupA.ID}
	expectDenied(http.MethodGet, "/v2/fabric/whoami", nil, groupHeaders)
	expect(http.MethodGet, pathA, nil, secondAHeaders, http.StatusOK)
}
