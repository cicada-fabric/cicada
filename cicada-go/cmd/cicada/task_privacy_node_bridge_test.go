package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

func privacyFixtureFiles(t *testing.T, root string) map[string]any {
	t.Helper()
	result := map[string]any{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			result[relative] = []any{hex.EncodeToString(digest[:]), info.Mode()}
		} else if info.IsDir() {
			result[relative] = info.Mode()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestTaskPeerPrivacyReadonlyBodyRequiresActualCryptoAndRetainsState(t *testing.T) {
	f := newTaskPeerPrivacyFixture(t)
	task, err := f.store.CreateSharedTaskPeerShell(f.groupID, "synthetic-manager-bearer", store.SharedTaskPeerShellInput{PublisherEndpointID: f.targetMCP.endpointID, ResultRecipientEndpointID: f.targetMCP.endpointID})
	if err != nil {
		t.Fatal(err)
	}
	selectPrivacySession(t, f.targetMCP)
	sent, err := f.targetMCP.callTool("cicada_task_define", map[string]any{"task_id": task.ID, "expected_revision": task.Revision, "owner_epoch": task.OwnerEpoch, "assignment_version": int64(1), "content_version": int64(1), "target_endpoint_id": f.sourceMCP.endpointID, "objective": "synthetic private objective", "acceptance_criteria": "synthetic private criteria", "artifact_refs": []any{}, "idempotency_key": "synthetic-body-binding"})
	if err != nil {
		t.Fatal(err)
	}
	ref := decodePrivacyRegisteredRef(t, sent)
	deliverPrivacyCandidate(t, f, f.sourceMCP, ref.MessageID)
	selectPrivacySession(t, f.sourceMCP)
	scope, err := f.sourceMCP.currentMCPOutboxScope()
	if err != nil {
		t.Fatal(err)
	}
	before := privacyFixtureFiles(t, f.stateDir)
	if _, err = f.sourceMCP.readLocalRegisteredTaskPacket(scope, ref); err != nil {
		t.Fatal("actual cached crypto body unavailable", err)
	}
	if !reflect.DeepEqual(before, privacyFixtureFiles(t, f.stateDir)) {
		after := privacyFixtureFiles(t, f.stateDir)
		changed := []string{}
		for path, value := range after {
			if !reflect.DeepEqual(value, before[path]) {
				changed = append(changed, path)
			}
		}
		for path := range before {
			if _, exists := after[path]; !exists {
				changed = append(changed, path)
			}
		}
		t.Fatalf("read-only Task body changed files: %v", changed)
	}
	for _, fault := range []string{"forged-plaintext", "missing-crypto", "corrupt-ciphertext", "corrupt-replay", "corrupt-both-sequences", "revoked-pin", "crypto-special-mode"} {
		t.Run(fault, func(t *testing.T) {
			faultRoot := t.TempDir()
			copyPrivacyFixtureTree(t, f.stateDir, faultRoot)
			f.sourceMCP.hubStateDir = faultRoot
			t.Cleanup(func() { f.sourceMCP.hubStateDir = "" })
			nodeDir := machineNodeStateDir(faultRoot, f.nodeID)
			cryptoPath := filepath.Join(nodeDir, "node-crypto-state.sqlite")
			mutate := func(path, query string, args ...any) {
				t.Helper()
				db, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.Exec(query, args...); err != nil {
					db.Close()
					t.Fatal(err)
				}
				if err = db.Close(); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "forged-plaintext":
				// This has the correct immutable message ID/digest/tuple but different
				// local prose. Inbox.Save's label is insufficient: pure crypto must fail.
				inbox, err := nodeinbox.OpenReadOnly(machineNodeInboxPath(faultRoot, f.nodeID))
				if err != nil {
					t.Fatal(err)
				}
				delivery, err := inbox.Get(context.Background(), ref.MessageID)
				inbox.Close()
				if err != nil {
					t.Fatal(err)
				}
				packet, err := decodeSealedTaskObjectPacket(string(delivery.Payload))
				if err != nil {
					t.Fatal(err)
				}
				packet.Objective = "forged different private objective"
				data, err := json.Marshal(packet)
				if err != nil {
					t.Fatal(err)
				}
				mutate(machineNodeInboxPath(faultRoot, f.nodeID), `UPDATE node_inbox_deliveries SET payload=? WHERE message_id=?`, data, ref.MessageID)
			case "missing-crypto":
				if err = os.Remove(cryptoPath); err != nil {
					t.Fatal(err)
				}
			case "corrupt-ciphertext":
				mutate(cryptoPath, `UPDATE node_crypto_inbox SET envelope=? WHERE message_id=?`, []byte("synthetic corrupt ciphertext"), ref.MessageID)
			case "corrupt-replay":
				mutate(cryptoPath, `UPDATE node_crypto_replay SET sequence=sequence+100 WHERE message_id=?`, ref.MessageID)
			case "corrupt-both-sequences":
				mutate(cryptoPath, `UPDATE node_crypto_replay SET sequence=sequence+100 WHERE message_id=?`, ref.MessageID)
				mutate(cryptoPath, `UPDATE node_crypto_inbox SET sequence=sequence+100 WHERE message_id=?`, ref.MessageID)
			case "revoked-pin":
				mutate(cryptoPath, `UPDATE node_crypto_peer_pins SET revoked_at='synthetic revoked pin' WHERE local_endpoint_id=? AND peer_endpoint_id=?`, ref.ReaderEndpointID, ref.SenderEndpointID)
			case "crypto-special-mode":
				if err = os.Chmod(cryptoPath, os.ModeSetgid|0600); err != nil {
					t.Fatal(err)
				}
			}
			faultBefore := privacyFixtureFiles(t, faultRoot)
			if _, err = f.sourceMCP.readLocalRegisteredTaskPacket(scope, ref); err == nil {
				t.Fatal("unverified/tampered local body obtained Task authority")
			}
			if !reflect.DeepEqual(faultBefore, privacyFixtureFiles(t, faultRoot)) {
				t.Fatal("fail-closed body read normalized, repaired or mutated state")
			}
		})
	}
	if !reflect.DeepEqual(before, privacyFixtureFiles(t, f.stateDir)) {
		t.Fatal("separate negative fixtures changed original crypto state")
	}
}
