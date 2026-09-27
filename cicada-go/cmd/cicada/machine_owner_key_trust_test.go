package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestMachineOwnerKeyTrustRequiresOutOfBandFingerprintAndPersistsRevocation(t *testing.T) {
	stateDir := t.TempDir()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public := identity.Public()
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "owner-public.json")
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--id", "node-a", "--state-dir", stateDir,
		"--owner-id", "owner-a", "--public", path,
		"--expect-key-id", public.ID, "--expect-fingerprint", fingerprint}
	wrongFingerprint := append([]string(nil), args...)
	wrongFingerprint[len(wrongFingerprint)-1] = fingerprint[:7] + "0" + fingerprint[8:]
	if wrongFingerprint[len(wrongFingerprint)-1] == fingerprint {
		wrongFingerprint[len(wrongFingerprint)-1] = fingerprint[:7] + "1" + fingerprint[8:]
	}
	if err := machineOwnerKeyTrustCommand("trust-owner-key", wrongFingerprint, &bytes.Buffer{}); err == nil {
		t.Fatal("unverified Owner fingerprint was accepted")
	}
	wrongKey := append([]string(nil), args...)
	wrongKey[len(wrongKey)-3] = "wrong-key-id"
	if err := machineOwnerKeyTrustCommand("trust-owner-key", wrongKey, &bytes.Buffer{}); err == nil {
		t.Fatal("unverified Owner key ID was accepted")
	}
	var output bytes.Buffer
	if err := machineOwnerKeyTrustCommand("trust-owner-key", args, &output); err != nil {
		t.Fatal(err)
	}
	if err := machineOwnerKeyTrustCommand("trust-owner-key", args, &bytes.Buffer{}); err != nil {
		t.Fatalf("same trusted key was not idempotent: %v", err)
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := state.GetNodeOwnerKeyTrustLocal("owner-a", public.ID)
	if err != nil || trusted.ExpectedFingerprint != fingerprint ||
		trusted.State != nodekeys.NodeOwnerKeyTrustActive {
		t.Fatalf("Node did not persist verified Owner key: trust=%#v err=%v", trusted, err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	revoke := []string{"--id", "node-a", "--state-dir", stateDir,
		"--owner-id", "owner-a", "--key-id", public.ID,
		"--expected-version", strconv.FormatInt(trusted.Version, 10)}
	if err := machineOwnerKeyTrustCommand("revoke-owner-key", revoke, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := machineOwnerKeyTrustCommand("trust-owner-key", args, &bytes.Buffer{}); !errors.Is(err, nodekeys.ErrNodeOwnerKeyTrustRevoked) {
		t.Fatalf("revoked Owner key was reinstalled: %v", err)
	}
	if bytes.Contains(output.Bytes(), []byte("KEMPrivate")) || bytes.Contains(output.Bytes(), []byte("private_identity")) {
		t.Fatal("Node trust command exposed private key material")
	}
}

func TestMachineOwnerKeyTrustWriterWaitsForOfflineMaintenance(t *testing.T) {
	stateDir := t.TempDir()
	const nodeID = "node-owner-lock-test"
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public := identity.Public()
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(t.TempDir(), "owner-public.json")
	encoded, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--id", nodeID, "--state-dir", stateDir, "--owner-id", "owner-a",
		"--public", publicPath, "--expect-key-id", public.ID, "--expect-fingerprint", fingerprint}

	offline, err := nodelock.AcquireMaintenanceExclusive(stateDir, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer offline.Close()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- machineOwnerKeyTrustCommand("trust-owner-key", args, &bytes.Buffer{})
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("Node owner-key writer bypassed exclusive maintenance: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(machineNodeStateDir(stateDir, nodeID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked writer created the Node subtree: %v", err)
	}
	if err := offline.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("owner-key writer failed after maintenance ended: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner-key writer did not resume after maintenance ended")
	}
}
