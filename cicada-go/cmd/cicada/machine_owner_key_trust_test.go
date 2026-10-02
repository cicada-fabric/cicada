package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func privateRecoveryTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMachineOwnerKeyTrustRespectsCommonWriterRootExclusive(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(strconv.FormatBool(separate), func(t *testing.T) {
			state := privateRecoveryTestDir(t)
			writer := state
			if separate {
				writer = privateRecoveryTestDir(t)
			}
			exclusive, err := nodelock.AcquireWriterRootExclusive(writer)
			if err != nil {
				t.Fatal(err)
			}
			defer exclusive.Close()
			key, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := nodekeys.PeerKeyFingerprint(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "synthetic-public.json")
			raw, _ := json.Marshal(key.Public())
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--id", "synthetic-lock", "--state-dir", state, "--writer-root", writer, "--owner-id", "synthetic-owner", "--public", path, "--expect-key-id", key.Public().ID, "--expect-fingerprint", fingerprint}
			if err := machineOwnerKeyTrustCommand("trust-owner-key", args, &bytes.Buffer{}); !errors.Is(err, nodelock.ErrBusy) {
				t.Fatalf("writer exclusion bypassed: %v", err)
			}
			if _, err := os.Lstat(machineNodeStateDir(state, "synthetic-lock")); !os.IsNotExist(err) {
				t.Fatal("blocked trust writer created crypto/key state")
			}
		})
	}
}

func TestMachineOwnerKeyTrustRequiresOutOfBandFingerprintAndPersistsRevocation(t *testing.T) {
	stateDir := privateRecoveryTestDir(t)
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

func TestMachineOwnerKeyTrustRejectsRecoveryBeforeWritableOpen(t *testing.T) {
	for _, hold := range []string{"node", "registration", "writer-root"} {
		t.Run(hold, func(t *testing.T) {
			root := privateRecoveryTestDir(t)
			const nodeID = "synthetic-trust-quarantine"
			key, err := e2ee.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			public := key.Public()
			fingerprint, err := nodekeys.PeerKeyFingerprint(public)
			if err != nil {
				t.Fatal(err)
			}
			publicPath := filepath.Join(t.TempDir(), "synthetic-owner.json")
			raw, _ := json.Marshal(public)
			if err := os.WriteFile(publicPath, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--id", nodeID, "--state-dir", root, "--owner-id", "synthetic-owner", "--public", publicPath, "--expect-key-id", public.ID, "--expect-fingerprint", fingerprint}
			if err := machineOwnerKeyTrustCommand("trust-owner-key", args, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(machineNodeStateDir(root, nodeID), "recovery-pending.json")
			if hold == "registration" {
				path = filepath.Join(root, "nodes", ".recovery-pending", "node-"+nodeID+".json")
			}
			if hold == "writer-root" {
				path = filepath.Join(root, ".writer-root-recovery-pending.json")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			// Malformed and read-only holds are still quarantine; never normalize.
			if err := os.WriteFile(path, []byte("synthetic malformed pending hold"), 0400); err != nil {
				t.Fatal(err)
			}
			before, err := recoveryTreeDigest(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"trust-owner-key", "revoke-owner-key"} {
				input := args
				if operation == "revoke-owner-key" {
					input = []string{"--id", nodeID, "--state-dir", root, "--owner-id", "synthetic-owner", "--key-id", public.ID, "--expected-version", "1"}
				}
				var output bytes.Buffer
				if err := machineOwnerKeyTrustCommand(operation, input, &output); err == nil || !strings.Contains(err.Error(), "quarantine") || output.Len() != 0 {
					t.Fatalf("write did not fail at quarantine: %v", err)
				}
			}
			after, err := recoveryTreeDigest(root)
			if err != nil || before != after {
				t.Fatal("denial changed trust/counters/hold bytes or modes")
			}
		})
	}
}

func TestMachineOwnerKeyTrustWriterWaitsForOfflineMaintenance(t *testing.T) {
	stateDir := privateRecoveryTestDir(t)
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
