package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestOwnerKeyLocalBootstrapRequiresExactOutOfBandKeyID(t *testing.T) {
	directory := t.TempDir()
	dbPath := filepath.Join(directory, "cicada.sqlite3")
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := json.Marshal(identity.Public())
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "owner-public.json")
	if err := os.WriteFile(publicPath, publicData, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	register := []string{"register", "--db", dbPath, "--owner-id", "owner_a",
		"--public", publicPath, "--expect-key-id", identity.Public().ID}
	wrong := append([]string(nil), register...)
	wrong[len(wrong)-1] = "pq1-wrong"
	if err := ownerKeyLocalCommand(wrong, &output); err == nil {
		t.Fatal("unverified key ID was accepted")
	}
	if output.Len() != 0 {
		t.Fatal("failed registration emitted a trusted result")
	}
	if err := ownerKeyLocalCommand(register, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		OwnerID string `json:"owner_id"`
		KeyID   string `json:"key_id"`
		State   string `json:"state"`
		Version int64  `json:"version"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OwnerID != "owner_a" || result.KeyID != identity.Public().ID ||
		result.State != store.OwnerApprovalKeyActive || result.Version != 1 {
		t.Fatalf("unexpected registered key metadata: %#v", result)
	}
	registered, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registered.GetPrincipal("owner_a")
	if err != nil || principal == nil || principal.Kind != store.PrincipalKindHuman || principal.OwnerID != "owner_a" ||
		principal.Status != store.PrincipalStatusActive {
		t.Fatalf("trusted guest owner Principal was not registered: %#v err=%v", principal, err)
	}
	if err := registered.Close(); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := ownerKeyLocalCommand([]string{"revoke", "--db", dbPath,
		"--owner-id", "owner_a", "--key-id", result.KeyID,
		"--expected-version", "1"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != store.OwnerApprovalKeyRevoked || result.Version != 2 {
		t.Fatalf("unexpected revoked key metadata: %#v", result)
	}
	if err := ownerKeyLocalCommand(register, &output); !errors.Is(err, store.ErrOwnerApprovalKeyConflict) {
		t.Fatalf("revoked key was reactivated: %v", err)
	}
}

func TestOwnerKeyGenerationKeepsPrivateIdentityOffHubAndNeverOverwrites(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "client-private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(privateDir, "owner.json")
	publicPath := filepath.Join(root, "owner-public.json")
	var output bytes.Buffer
	if err := ownerKeyLocalCommand([]string{"generate", "--private", privatePath,
		"--public", publicPath}, &output); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil || privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key file mode: info=%v err=%v", privateInfo, err)
	}
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.UnmarshalIdentity(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var public e2ee.PublicIdentity
	if err := json.Unmarshal(publicBytes, &public); err != nil || public.ID != identity.Public().ID {
		t.Fatalf("generated public identity mismatch: err=%v", err)
	}
	if bytes.Contains(output.Bytes(), privateBytes) {
		t.Fatal("key generation printed private identity")
	}
	if err := ownerKeyLocalCommand([]string{"generate", "--private", privatePath,
		"--public", publicPath}, &output); err == nil {
		t.Fatal("key generation overwrote an existing private identity")
	}
	storedPrivate, err := os.ReadFile(privatePath)
	if err != nil || !bytes.Equal(storedPrivate, privateBytes) {
		t.Fatalf("existing private identity changed: err=%v", err)
	}
	otherPrivate := filepath.Join(privateDir, "other-owner.json")
	if err := ownerKeyLocalCommand([]string{"generate", "--private", otherPrivate,
		"--public", publicPath}, &output); err == nil {
		t.Fatal("key generation overwrote an existing public identity")
	}
	if _, err := os.Lstat(otherPrivate); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed public preflight created an orphan private identity: %v", err)
	}
}
