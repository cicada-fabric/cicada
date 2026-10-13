package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/ownersigner"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestHubSetupExportsPinnedConnectionBeforeServeAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	workspaceRoot := filepath.Join(root, "workspace")
	configFile := filepath.Join(root, "hub-connection.json")
	if err := hubSetupCommand([]string{"--owner-label", "Bad\x1b[31mLabel", "--origin", "https://hub.example.test",
		"--public-config", filepath.Join(root, "unsafe-connection.json"), "--state-dir", stateDir, "--workspace-root", workspaceRoot}, &bytes.Buffer{}); err == nil {
		t.Fatal("Hub setup accepted terminal controls in the human Owner label")
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("unsafe label touched Hub StateDir: %v", err)
	}
	args := []string{"--owner-label", "Primary owner", "--origin", "https://hub.example.test", "--public-config", configFile,
		"--state-dir", stateDir, "--workspace-root", workspaceRoot}
	config := control.DefaultConfig()
	config.StateDir, config.WorkspaceRoot = stateDir, workspaceRoot
	if err := checkHubServeReadiness(config); err == nil || !strings.Contains(err.Error(), "hub setup") {
		t.Fatalf("pristine serve check error = %v, want setup refusal", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "e2ee", "identity.json")); !os.IsNotExist(err) {
		t.Fatalf("serve readiness check created the peer identity: %v", err)
	}

	var output bytes.Buffer
	if err := hubSetupCommand(args, &output); err != nil {
		t.Fatal(err)
	}
	var first struct {
		State      string                     `json:"state"`
		Connection ownersigner.ConnectionFile `json:"public_connection"`
	}
	if err := json.Unmarshal(output.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.State != "HUB_READY" || first.Connection.Validate() != nil || first.Connection.OwnerID == "" || first.Connection.AccountID == "" {
		t.Fatalf("invalid Hub setup output: %+v", first)
	}
	info, err := os.Stat(configFile)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("connection file mode = %v, err=%v; want 0644", modeOf(info), err)
	}
	var saved ownersigner.ConnectionFile
	if err := readStrictPublicJSON(configFile, 64*1024, &saved); err != nil || !reflect.DeepEqual(saved, first.Connection) {
		t.Fatalf("saved public connection does not equal the verified Hub identity: err=%v", err)
	}
	if err := checkHubServeReadiness(config); err != nil {
		t.Fatalf("configured Hub failed readiness check: %v", err)
	}
	identityBytes, err := os.ReadFile(filepath.Join(stateDir, "e2ee", "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := e2ee.UnmarshalIdentity(identityBytes)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Public().ID == first.Connection.OwnerID {
		t.Fatal("crypto identity ID was reused as the stable human Owner ID")
	}

	output.Reset()
	if err := hubSetupCommand(args, &output); err != nil {
		t.Fatalf("idempotent setup retry: %v", err)
	}
	var second struct {
		Connection ownersigner.ConnectionFile `json:"public_connection"`
	}
	if err := json.Unmarshal(output.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second.Connection, first.Connection) {
		t.Fatal("setup retry changed the stable Owner or Hub identity")
	}
}

func TestHubSetupRequiresSafeOutputModesAndExactCandidateContext(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "pair.json")
	if err := os.WriteFile(privatePath, []byte("same bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateExclusiveOrSame(privatePath, []byte("same bytes")); err == nil {
		t.Fatal("existing permissive pairing file was accepted as mode 0600")
	}
	publicPath := filepath.Join(root, "connection.json")
	if err := os.WriteFile(publicPath, []byte("same bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePublicExclusiveOrSame(publicPath, []byte("same bytes")); err == nil {
		t.Fatal("existing private-mode public connection was accepted as mode 0644")
	}

	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	candidate := ownersigner.PublicManifest{Format: "cicada.owner-signer-public.v1", AccountID: "account_test", OwnerID: "owner_test",
		OwnerPublic: identity.Public(), Fingerprint: ownerbootstrap.Fingerprint(identity.Public()), Origin: "https://hub.example.test",
		Hub: clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: "hub_test", Public: hubIdentity.Public(), KeyVersion: 1, Suite: clientoperator.Suite}}
	if err := candidateConnectionMatches(candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Origin = "http://127.0.0.1:8787"
	if err := candidateConnectionMatches(candidate); err == nil {
		t.Fatal("candidate manifest accepted loopback HTTP without explicit policy")
	}
	candidate.Origin = "https://hub.example.test/path"
	if err := candidateConnectionMatches(candidate); err == nil {
		t.Fatal("candidate manifest accepted a non-origin URL path")
	}

	unsafeOutput := &bytes.Buffer{}
	candidate.AccountID = "account\x1b[31mspoof"
	if err := hubBootstrapIssueReview(strings.NewReader("approve\n"), unsafeOutput, candidate); err == nil {
		t.Fatal("Hub candidate review accepted terminal controls in a displayed account ID")
	}
	if unsafeOutput.Len() != 0 {
		t.Fatal("unsafe Hub candidate metadata was rendered before validation")
	}
}

func TestOwnerSignerReviewsRejectTerminalControlsBeforeRendering(t *testing.T) {
	var output bytes.Buffer
	bootstrap := ownersigner.BootstrapReview{AccountID: "account_test", OwnerID: "owner_test", HubID: "hub_test",
		Origin: "https://hub.example.test", Purpose: ownerbootstrap.Purpose, AuthorityID: "root_test", OperationID: "operation_test",
		Fingerprint: strings.Repeat("a", 64), ExpiresAt: "2025-01-01T00:00:00Z"}
	bootstrap.OperationID = "operation\u202etest"
	if err := ownerSignerBootstrapReview(strings.NewReader("approve\n"), &output)(bootstrap); err == nil {
		t.Fatal("Owner bootstrap review accepted bidi controls in an operation ID")
	}
	if output.Len() != 0 {
		t.Fatal("unsafe Owner bootstrap metadata was rendered before validation")
	}

	grant := ownersigner.GrantReview{AccountID: "account_test", OwnerID: "owner_test", OwnerKeyID: "owner_key_test",
		HubID: "hub_test", DeviceID: "device\x1b[31mspoof", DeviceKeyID: "device_key_test",
		DeviceFingerprint: strings.Repeat("b", 64), Purpose: e2ee.OwnerDevicePurposeControl,
		IssuedAt: "2025-01-01T00:00:00Z", ExpiresAt: "2025-01-01T01:00:00Z"}
	output.Reset()
	if err := ownerSignerGrantReview(strings.NewReader("approve\n"), &output)(grant); err == nil {
		t.Fatal("Owner grant review accepted terminal controls in a device ID")
	}
	if output.Len() != 0 {
		t.Fatal("unsafe Client manifest metadata was rendered before validation")
	}
}

func modeOf(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

func TestHubOwnerIssuePristinePreflightPreservesLaterSetup(t *testing.T) {
	root := t.TempDir()
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	hub, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	candidate := ownersigner.PublicManifest{Format: "cicada.owner-signer-public.v1", AccountID: "account_synthetic_other", OwnerID: "human_synthetic_other", OwnerPublic: owner.Public(), Fingerprint: ownerbootstrap.Fingerprint(owner.Public()), Origin: "https://synthetic.invalid", Hub: clientoperator.HubIdentity{Contract: "android-hub-v1", HubID: "hub_synthetic_other", Public: hub.Public(), KeyVersion: 1, Suite: clientoperator.Suite}}
	encoded, e := json.Marshal(candidate)
	if e != nil {
		t.Fatal(e)
	}
	candidateFile := filepath.Join(root, "public-candidate.json")
	if e = os.WriteFile(candidateFile, encoded, 0644); e != nil {
		t.Fatal(e)
	}
	state, workspace := filepath.Join(root, "wrong-pristine-state"), filepath.Join(root, "workspace")
	args := []string{"--candidate-manifest", candidateFile, "--candidate-fingerprint", candidate.Fingerprint, "--pair-file", filepath.Join(root, "pair.json"), "--state-dir", state, "--workspace-root", workspace}
	if e = hubOwnerBootstrapIssueCommand(args, strings.NewReader("approve\n"), &bytes.Buffer{}); !errors.Is(e, store.ErrOwnerBootstrapRejected) {
		t.Fatalf("pristine issue did not fail at readiness: %v", e)
	}
	for _, path := range []string{filepath.Join(state, "e2ee"), workspace, filepath.Join(root, "pair.json")} {
		if _, e = os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("rejected issue created identities, workspace or pairing")
		}
	}
	db, e := store.New(filepath.Join(state, "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	setup, e := db.GetHubOwnerSetup()
	if e != nil || setup != nil {
		t.Fatal("rejected issue created a compatibility account")
	}
	principals, e := db.ListPrincipals(store.PrincipalFilter{})
	if e != nil || len(principals) != 0 {
		t.Fatal("rejected issue created a compatibility human")
	}
	machines, e := db.ListMachines()
	if e != nil || len(machines) != 0 {
		t.Fatal("rejected issue created local machines")
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	if e = hubSetupCommand([]string{"--owner-label", "Synthetic correct owner", "--origin", "https://synthetic.invalid", "--public-config", filepath.Join(root, "correct-public-connection.json"), "--state-dir", state, "--workspace-root", workspace}, &bytes.Buffer{}); e != nil {
		t.Fatalf("legitimate setup after rejected issue was stranded: %v", e)
	}

	// A restored StateDir remains quarantined before schema, key or machine writes.
	source, archive, target := filepath.Join(root, "source"), filepath.Join(root, "archive"), filepath.Join(root, "held-target")
	db, e = store.New(filepath.Join(source, "cicada.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = store.BackupStateDir(source, archive); e != nil {
		t.Fatal(e)
	}
	if _, e = store.RestoreStateDir(archive, target); e != nil {
		t.Fatal(e)
	}
	args[len(args)-3] = target
	if e = hubOwnerBootstrapIssueCommand(args, strings.NewReader("approve\n"), &bytes.Buffer{}); !errors.Is(e, store.ErrStateRestoreQuarantined) {
		t.Fatalf("issue bypassed restore quarantine: %v", e)
	}
}
