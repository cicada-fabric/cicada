package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func nodeBindingTestCredentialDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func nodeBindingTestCodeDigest(value string) string {
	sum := sha256.Sum256([]byte("test-node-code\x00" + value))
	return hex.EncodeToString(sum[:])
}

func TestNodeDeviceBindingRequiresActiveOwnerAuthorizedClientAndConsumesCode(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	credentialDigest := nodeBindingTestCredentialDigest("node bearer candidate")
	codeDigest := nodeBindingTestCodeDigest("ABCD-EFGH-JKLM")
	request, err := s.CreatePendingNodeDeviceBinding("gpu-node-1", "GPU Node 1",
		credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if request.State != NodeDeviceBindingPending || request.HubID == "" || request.NodeCredentialDigest == "" {
		t.Fatalf("bad pending record: %+v", request)
	}
	if _, err := s.GetNodeCredentialByHash(credentialDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("pending Node credential became active before owner confirmation: %v", err)
	}
	if _, _, err := s.GetOwnerBoundNodeCredentialByHash(credentialDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("pending digest passed the owner-bound Relay check: %v", err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", "not-this-device", codeDigest); !errors.Is(err, ErrNodeDeviceBindingUnauthorized) {
		t.Fatalf("unregistered Client device confirmed pairing: %v", err)
	}

	binding, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if binding.State != "ACTIVE" || binding.OwnerID != "owner_a" || binding.ClientDeviceID != device.DeviceID ||
		binding.HubID != request.HubID || binding.NodeID != request.NodeID || binding.NodeCredentialVersion != 1 || !binding.Authorized {
		t.Fatalf("owner/Hub/Node binding was not retained: %+v", binding)
	}
	credential, err := s.GetNodeCredentialByHash(credentialDigest)
	if err != nil || credential.NodeID != request.NodeID || credential.Version != binding.NodeCredentialVersion {
		t.Fatalf("confirmed Node credential not active: %#v err=%v", credential, err)
	}
	boundCredential, boundState, err := s.GetOwnerBoundNodeCredentialByHash(credentialDigest)
	if err != nil || boundCredential.NodeID != request.NodeID || boundState.OwnerID != "owner_a" || boundState.ID != binding.ID {
		t.Fatalf("owner-bound Relay credential lookup failed: credential=%#v binding=%#v err=%v", boundCredential, boundState, err)
	}
	var retainedCandidate string
	if err := s.db.QueryRow(`SELECT node_credential_digest FROM node_device_binding_requests_v2 WHERE id=?`, request.ID).Scan(&retainedCandidate); err != nil {
		t.Fatal(err)
	}
	if retainedCandidate != "" {
		t.Fatal("confirmed request retained its candidate credential digest")
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); !errors.Is(err, ErrNodeDeviceBindingExpired) {
		t.Fatalf("one-time code was accepted twice: %v", err)
	}
}

func TestOwnerBoundNodeCredentialLookupRejectsLegacyUnboundCredential(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	digest := nodeBindingTestCredentialDigest("legacy unbound credential")
	if _, err := s.RotateNodeCredential("legacy-node", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNodeCredentialByHash(digest); err != nil {
		t.Fatalf("legacy credential fixture is not active: %v", err)
	}
	if _, _, err := s.GetOwnerBoundNodeCredentialByHash(digest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("legacy credential was treated as owner-bound: %v", err)
	}
}

func TestNodeDeviceBindingCodeExpiresAndCannotBeClaimedAcrossHub(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	credentialDigest := nodeBindingTestCredentialDigest("expired node credential")
	codeDigest := nodeBindingTestCodeDigest("expired")
	request, err := s.CreatePendingNodeDeviceBinding("node-expired", "expired",
		credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET expires_at=? WHERE id=?`,
		time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), request.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); !errors.Is(err, ErrNodeDeviceBindingExpired) {
		t.Fatalf("expired code was accepted: %v", err)
	}
	if _, err := s.GetNodeCredentialByHash(credentialDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("expired pairing activated a credential: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE client_device_hub_config_v2 SET hub_id='hub-replaced' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding("node-hub-mismatch", "node",
		nodeBindingTestCredentialDigest("other"), nodeBindingTestCodeDigest("hub-mismatch"),
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET hub_id='another-hub' WHERE node_id='node-hub-mismatch'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID,
		nodeBindingTestCodeDigest("hub-mismatch")); !errors.Is(err, ErrNodeDeviceBindingExpired) {
		t.Fatalf("request created for another Hub was accepted: %v", err)
	}
}

func TestNodeDeviceCodeRateLimitAndReissueRules(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	nodeID := "node-rate-limit"
	firstDigest := nodeBindingTestCredentialDigest("rate-limited credential")
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "node", firstDigest,
		nodeBindingTestCodeDigest("first rate code"), time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "node", firstDigest,
		nodeBindingTestCodeDigest("too soon"), time.Now().UTC().Add(10*time.Minute)); !errors.Is(err, ErrNodeDeviceBindingRateLimited) {
		t.Fatalf("same Node rapidly reissued a public device code: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET created_at=? WHERE node_id=?`,
		time.Now().UTC().Add(-2*nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "node", firstDigest,
		nodeBindingTestCodeDigest("recovery code"), time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatalf("same Node credential could not recover after the cooldown: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET created_at=? WHERE node_id=? AND state='PENDING'`,
		time.Now().UTC().Add(-2*nodeDeviceBindingReissueCooldown).Format(time.RFC3339Nano), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "node",
		nodeBindingTestCredentialDigest("different credential"), nodeBindingTestCodeDigest("foreign digest"),
		time.Now().UTC().Add(10*time.Minute)); !errors.Is(err, ErrNodeDeviceBindingConflict) {
		t.Fatalf("different Node credential replaced a pending owner code: %v", err)
	}
}

func TestNodeDeviceBindingRejectsReservedLocalMachineIDs(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	for _, nodeID := range []string{"control-local", "worker-local", "CONTROL-LOCAL", "Worker-Local"} {
		if _, err := s.CreatePendingNodeDeviceBinding(nodeID, "reserved",
			nodeBindingTestCredentialDigest("reserved-"+nodeID), nodeBindingTestCodeDigest("reserved-"+nodeID),
			time.Now().UTC().Add(10*time.Minute)); err == nil {
			t.Errorf("reserved local machine id %q was accepted for Node binding", nodeID)
		}
	}
}

func TestNodeDeviceBindingBoundsGlobalPendingCapacity(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	baseTime := time.Now().UTC()
	expiresAt := baseTime.Add(10 * time.Minute).Format(time.RFC3339Nano)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < nodeDeviceBindingMaxPending; index++ {
		createdAt := baseTime.Add(-time.Minute).Format(time.RFC3339Nano)
		if index == 0 {
			// Keep one unexpired request outside the rolling creation window so
			// this assertion exercises the active-pending cap specifically.
			createdAt = baseTime.Add(-nodeDeviceBindingCreateWindow - time.Minute).Format(time.RFC3339Nano)
		}
		if _, err := tx.Exec(`INSERT INTO node_device_binding_requests_v2
(id, hub_id, node_id, node_name, node_credential_digest, code_digest, state, version, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 1, ?, ?)`,
			NewID("test-node-code"), hubID, fmt.Sprintf("node-cap-%03d", index), "node",
			nodeBindingTestCredentialDigest(fmt.Sprintf("credential-%03d", index)),
			nodeBindingTestCodeDigest(fmt.Sprintf("code-%03d", index)), expiresAt, createdAt); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding("node-cap-next", "next",
		nodeBindingTestCredentialDigest("capacity candidate"), nodeBindingTestCodeDigest("capacity code"),
		baseTime.Add(10*time.Minute)); !errors.Is(err, ErrNodeDeviceBindingRateLimited) {
		t.Fatalf("global pending limit did not reject the next request: %v", err)
	}
}

func TestNodeDeviceBindingConcurrentConfirmationHasSingleWinner(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	codeDigest := nodeBindingTestCodeDigest("concurrent")
	if _, err := s.CreatePendingNodeDeviceBinding("node-concurrent", "node",
		nodeBindingTestCredentialDigest("concurrent credential"), codeDigest,
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	const contenders = 12
	var wait sync.WaitGroup
	wins := make(chan error, contenders)
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest)
			wins <- err
		}()
	}
	wait.Wait()
	close(wins)
	accepted := 0
	for err := range wins {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrNodeDeviceBindingExpired) && !errors.Is(err, ErrNodeDeviceBindingConflict) {
			t.Fatalf("unexpected confirmation result: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent confirmations accepted %d times, want exactly once", accepted)
	}
}

func TestNodeDeviceBindingRevocationFencesCredentialAndOwnerViews(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	credentialDigest := nodeBindingTestCredentialDigest("revocable Node credential")
	codeDigest := nodeBindingTestCodeDigest("revoke")
	if _, err := s.CreatePendingNodeDeviceBinding("node-revoke", "revocable",
		credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	binding, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListNodeDeviceBindings("owner_b"); err != nil {
		t.Fatal(err)
	}
	foreign, err := s.RevokeNodeDeviceBinding("owner_b", binding.ID, binding.Version)
	if foreign != nil || !errors.Is(err, ErrNodeDeviceBindingNotFound) {
		t.Fatalf("foreign owner accessed binding: %#v %v", foreign, err)
	}
	if _, err := s.RevokeNodeDeviceBinding("owner_a", binding.ID, binding.Version-1); !errors.Is(err, ErrNodeDeviceBindingVersion) {
		t.Fatalf("stale binding version revoked Node: %v", err)
	}
	revoked, err := s.RevokeNodeDeviceBinding("owner_a", binding.ID, binding.Version)
	if err != nil || revoked.State != "REVOKED" || revoked.Version != binding.Version+1 {
		t.Fatalf("revoke Node binding: %#v err=%v", revoked, err)
	}
	if _, err := s.GetNodeCredentialByHash(credentialDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("revoked Node bearer remained active: %v", err)
	}
	bindings, err := s.ListNodeDeviceBindings("owner_a")
	if err != nil || len(bindings) != 1 || bindings[0].State != "REVOKED" || bindings[0].Authorized {
		t.Fatalf("owner view omitted revoked history: %#v err=%v", bindings, err)
	}
}

func TestNodeBindingOwnerViewDoesNotShowRevokedOwnerKeyAsAuthorized(t *testing.T) {
	s, owner, _, device := newClientDeviceFixture(t)
	digest := nodeBindingTestCredentialDigest("owner-key-revocation")
	code := nodeBindingTestCodeDigest("owner-key-revocation")
	if _, err := s.CreatePendingNodeDeviceBinding("node-owner-key", "node", digest, code,
		time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, code); err != nil {
		t.Fatal(err)
	}
	bindings, err := s.ListNodeDeviceBindings("owner_a")
	if err != nil || len(bindings) != 1 || !bindings[0].Authorized {
		t.Fatalf("confirmed binding was not authorized: %#v err=%v", bindings, err)
	}
	if _, err := s.RevokeOwnerApprovalKeyLocal("owner_a", owner.Public().ID, 1); err != nil {
		t.Fatal(err)
	}
	bindings, err = s.ListNodeDeviceBindings("owner_a")
	if err != nil || len(bindings) != 1 || bindings[0].State != "ACTIVE" || bindings[0].Authorized {
		t.Fatalf("revoked owner key remained effectively authorized: %#v err=%v", bindings, err)
	}
}

func TestLegacyNodeCredentialRotationCannotBypassOwnerBinding(t *testing.T) {
	s, _, _, device := newClientDeviceFixture(t)
	firstDigest := nodeBindingTestCredentialDigest("bound Node credential")
	codeDigest := nodeBindingTestCodeDigest("legacy rotate")
	if _, err := s.CreatePendingNodeDeviceBinding("node-legacy-rotate", "node",
		firstDigest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	rotatedDigest := nodeBindingTestCredentialDigest("legacy rotated credential")
	credential, err := s.RotateNodeCredential("node-legacy-rotate", rotatedDigest)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Status != NodeCredentialRevoked {
		t.Fatalf("legacy rotation returned an active unbound Node credential: %+v", credential)
	}
	if _, err := s.GetNodeCredentialByHash(rotatedDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("legacy Node rotation bypassed owner confirmation: %v", err)
	}
	if _, _, err := s.GetOwnerBoundNodeCredentialByHash(firstDigest); !errors.Is(err, ErrNodeCredentialNotFound) {
		t.Fatalf("stale owner binding remained authorized after legacy rotation: %v", err)
	}
	bindings, err := s.ListNodeDeviceBindings("owner_a")
	if err != nil || len(bindings) != 1 || bindings[0].State != "REVOKED" {
		t.Fatalf("credential rotation did not revoke stale owner binding: %#v err=%v", bindings, err)
	}
}

func TestNodeDeviceBindingRejectsInactiveClientOrOwnerGrant(t *testing.T) {
	for _, revokeOwnerKey := range []bool{false, true} {
		t.Run(fmt.Sprintf("owner_key_revoked_%t", revokeOwnerKey), func(t *testing.T) {
			s, owner, _, device := newClientDeviceFixture(t)
			credentialDigest := nodeBindingTestCredentialDigest("inactive Client candidate")
			codeDigest := nodeBindingTestCodeDigest(fmt.Sprintf("inactive-%t", revokeOwnerKey))
			if _, err := s.CreatePendingNodeDeviceBinding("node-inactive", "node",
				credentialDigest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
				t.Fatal(err)
			}
			if revokeOwnerKey {
				if _, err := s.RevokeOwnerApprovalKeyLocal("owner_a", owner.Public().ID, 1); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.RevokeClientDevice("owner_a", device.DeviceID, device.Version); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest); !errors.Is(err, ErrNodeDeviceBindingUnauthorized) {
				t.Fatalf("inactive owner authorization confirmed pairing: %v", err)
			}
		})
	}
}

func TestNodeDeviceBindingSchemaDoesNotPersistPlaintextCodeOrCredential(t *testing.T) {
	s, _, _, _ := newClientDeviceFixture(t)
	code := "ABCD-EFGH-JKLM"
	credential := "cicada_node_plaintext_secret"
	credentialDigest := nodeBindingTestCredentialDigest(credential)
	codeDigest := nodeBindingTestCodeDigest(code)
	if _, err := s.CreatePendingNodeDeviceBinding("node-secret", "secret node", credentialDigest,
		codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var storedCode, storedCredential string
	if err := s.db.QueryRow(`SELECT code_digest, node_credential_digest FROM node_device_binding_requests_v2 WHERE node_id='node-secret'`).Scan(&storedCode, &storedCredential); err != nil {
		t.Fatal(err)
	}
	if storedCode == code || storedCredential == credential || storedCode == "" || storedCredential != credentialDigest {
		t.Fatalf("pairing persisted plaintext or lost digest: code=%q credential=%q", storedCode, storedCredential)
	}
}

func TestNodeDeviceBindingMigrationRollsBackAllObjectsAndResumes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite3")
	seedLegacyV1State(t, path)
	injected := errors.New("interrupt Node device binding migration")
	failed, err := openStoreWithMigrationHook(path, func(migrationID, phase string) error {
		if migrationID == "v2.node.owner_device_code_bindings" && phase == "after_apply" {
			return injected
		}
		return nil
	})
	if failed != nil {
		_ = failed.Close()
	}
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected migration failure, got %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var objectCount int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name IN
('node_device_binding_requests_v2', 'node_owner_bindings_v2', 'node_owner_binding_credential_fence_v2')`).Scan(&objectCount); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if objectCount != 0 {
		t.Fatalf("failed migration left %d partial Node binding objects", objectCount)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entry, err := reopened.readV2Migration(20)
	if err != nil || entry == nil || entry.State != v2MigrationApplied || entry.Attempts != 2 {
		t.Fatalf("Node binding migration did not resume: %#v err=%v", entry, err)
	}
}
