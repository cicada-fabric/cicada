package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/gofrs/flock"
)

func TestNetworkConsentSignBindsExactScopeAndKeepsProofPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "owner.key")
	invitationPath := filepath.Join(dir, "invite")
	proofPath := filepath.Join(dir, "proof.json")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invitationPath, []byte("synthetic-network-invitation-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = networkConsentSign([]string{
		"--owner-private", privatePath, "--proof-file", proofPath,
		"--invitation-file", invitationPath, "--owner", "owner_synthetic",
		"--hub", "hub_synthetic", "--network", "network_synthetic",
		"--node", "node_synthetic", "--session", "thread_synthetic",
		"--grants", "directory.publish,directory.discover", "--discoverable",
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "synthetic-network-invitation-token") || strings.Contains(output.String(), "\"signature\"") {
		t.Fatal("consent CLI printed invitation or proof")
	}
	info, err := os.Lstat(proofPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("proof file mode: %v, %v", info, err)
	}
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	var grant e2ee.OwnerNetworkJoinGrant
	if err := json.Unmarshal(proof, &grant); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic-network-invitation-token"))
	expected := e2ee.OwnerNetworkJoinGrant{HubID: "hub_synthetic", NetworkID: "network_synthetic",
		OwnerID: "owner_synthetic", NodeID: "node_synthetic", NativeSessionID: "thread_synthetic",
		InvitationDigest: hex.EncodeToString(digest[:]), Grants: []string{"directory.discover", "directory.publish"},
		Discoverable: true}
	if _, err := e2ee.VerifyOwnerNetworkJoinGrant(proof, identity.Public(), expected, time.Now().UTC()); err != nil {
		t.Fatalf("signed exact Join grant rejected: %v", err)
	}
	expected.NetworkID = "other_network"
	if _, err := e2ee.VerifyOwnerNetworkJoinGrant(proof, identity.Public(), expected, time.Now().UTC()); err == nil {
		t.Fatal("Join grant authorized a different Network")
	}
}

func TestNetworkCredentialHTTPClientRefusesRedirect(t *testing.T) {
	var targetRequests int
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		targetRequests++
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Location", target.URL+"/capture")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	request, err := http.NewRequest(http.MethodGet, source.URL+"/v2/fabric/networks/net_a/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Cicada-Network-Session synthetic-secret")
	result, err := networkHTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusTemporaryRedirect || targetRequests != 0 {
		t.Fatalf("Network credential followed redirect: status=%d target_requests=%d", result.StatusCode, targetRequests)
	}
}

func TestNetworkMCPStateSeparatesNativeThreadsAndLocksCredentialWrites(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	first, _, err := mcpSessionScope("https://hub.synthetic", harness.SessionContext{
		Harness: "codex", NativeSessionID: "thread_first", MachineID: "node_same", Workspace: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := mcpSessionScope("https://hub.synthetic", harness.SessionContext{
		Harness: "codex", NativeSessionID: "thread_second", MachineID: "node_same", Workspace: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two native Threads shared an MCP scope")
	}
	firstDir, err := privateNetworkScopeDir(root, first, true)
	if err != nil {
		t.Fatal(err)
	}
	secondDir, err := privateNetworkScopeDir(root, second, true)
	if err != nil {
		t.Fatal(err)
	}
	firstPath, _ := mcpNetworkFile(firstDir, "net_same", ".session.json")
	secondPath, _ := mcpNetworkFile(secondDir, "net_same", ".session.json")
	if firstPath == secondPath {
		t.Fatal("Network session state collided across native Threads")
	}
	writeLock, err := lockNetworkMCPState(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	otherWriter := flock.New(firstPath+".lock", flock.SetPermissions(0o600))
	if acquired, err := otherWriter.TryLock(); err != nil || acquired {
		t.Fatalf("concurrent writer entered locked Network session: acquired=%t err=%v", acquired, err)
	}
	if err := writeLock.Unlock(); err != nil {
		t.Fatal(err)
	}
	if acquired, err := otherWriter.TryLock(); err != nil || !acquired {
		t.Fatalf("Network session lock did not release: acquired=%t err=%v", acquired, err)
	}
	if err := otherWriter.Unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkMigrationDryRunLeavesDatabaseBytesUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.sqlite3")
	persistence, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := networkOperatorCommand("migration-dry-run", []string{"--db", path}, &output); err != nil {
		t.Fatal(err)
	}
	var report store.NetworkMigrationReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Phase != store.NetworkModePreparing {
		t.Fatalf("unexpected read-only report: %v, %v", report.Phase, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("Network dry-run changed the Hub database")
	}
	// An older database must be rejected in read-only mode; Store.New would
	// silently migrate it and thereby violate the dry-run contract.
	oldPath := filepath.Join(t.TempDir(), "old.sqlite3")
	if err := os.WriteFile(oldPath, []byte("not an initialized Hub database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := networkOperatorCommand("migration-dry-run", []string{"--db", oldPath}, &bytes.Buffer{}); err == nil {
		t.Fatal("uninitialized Hub database was accepted")
	}
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil || string(oldBytes) != "not an initialized Hub database" {
		t.Fatal(fmt.Errorf("dry-run modified invalid legacy source: %v", err))
	}
}

func TestMCPInitializeReportsBuildVersion(t *testing.T) {
	response, send := newMCPServer("http://127.0.0.1:8787", "", "").handle(mcpRequest{Method: "initialize"})
	if !send {
		t.Fatal("initialize response suppressed")
	}
	result, ok := response.Result.(map[string]any)
	if !ok {
		t.Fatal("initialize result has unexpected shape")
	}
	serverInfo, ok := result["serverInfo"].(map[string]any)
	if !ok || serverInfo["version"] != buildinfo.Version {
		t.Fatalf("MCP version differs from build version: %v", result["serverInfo"])
	}
}
