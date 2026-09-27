package nodekeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	_ "modernc.org/sqlite"
)

func TestPinVerifiedPeerKeyRequiresApprovalAndValidAttestation(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		"different-key-id", fingerprint, candidate); !errors.Is(err, ErrPeerPinApprovalMismatch) {
		t.Fatalf("mismatched expected key ID error = %v", err)
	}
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, changedFingerprint(fingerprint), candidate); !errors.Is(err, ErrPeerPinApprovalMismatch) {
		t.Fatalf("mismatched expected fingerprint error = %v", err)
	}

	forged := candidate
	forged.Attestation = append([]byte(nil), candidate.Attestation...)
	forged.Attestation[len(forged.Attestation)-1] ^= 1
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, forged); !errors.Is(err, ErrPeerPinUnverified) {
		t.Fatalf("forged candidate attestation error = %v", err)
	}
	mismatchedClaims := candidate
	mismatchedClaims.BindingID = "binding_other"
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, mismatchedClaims); !errors.Is(err, ErrPeerPinUnverified) {
		t.Fatalf("attestation claim mismatch error = %v", err)
	}
	if _, err := state.GetPeerPin(context.Background(), scope, peer); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("failed approvals created a pin: %v", err)
	}
	crossScope := scope
	crossScope.LocalGroupID = "group_local"
	crossPeer := peer
	crossPeer.GroupID = "group_peer"
	crossScope.PeerGroupID = crossPeer.GroupID
	crossScope.CommunicationLinkID = "link_1"
	if _, err := state.PinVerifiedPeerKey(context.Background(), crossScope, crossPeer,
		candidate.Public.ID, fingerprint, candidate); !errors.Is(err, ErrPeerPinCrossGroupGrantRequired) {
		t.Fatalf("legacy cross-Group pin API error = %v", err)
	}

	pin, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if pin.Version != 1 || pin.KeyID != candidate.Public.ID || pin.Fingerprint != fingerprint {
		t.Fatalf("verified pin = %+v", pin)
	}
}

func TestPeerPinLookupRequiresExactScopeAndPeerIdentity(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, _ := PeerKeyFingerprint(candidate.Public)
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate); err != nil {
		t.Fatal(err)
	}

	otherScope := scope
	otherScope.PeerGroupID = "group_other"
	otherScope.LocalGroupID = "group_other"
	otherPeer := peer
	otherPeer.GroupID = otherScope.PeerGroupID
	if _, err := state.GetPeerPin(context.Background(), otherScope, otherPeer); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("cross-Group lookup error = %v", err)
	}
	withoutLink := scope
	withoutLink.LocalGroupID = "group_local"
	withoutLink.PeerGroupID = "group_peer"
	crossPeer := peer
	crossPeer.GroupID = withoutLink.PeerGroupID
	withoutLink.CommunicationLinkID = ""
	if _, err := state.GetPeerPin(context.Background(), withoutLink, crossPeer); !errors.Is(err, ErrPeerPinCrossGroupLinkRequired) {
		t.Fatalf("cross-Group scope without CommunicationLink error = %v", err)
	}
	sameGroupScope := scope
	sameGroupScope.LocalGroupID = peer.GroupID
	sameGroupScope.CommunicationLinkID = ""
	first, err := state.PinVerifiedPeerKey(context.Background(), sameGroupScope, peer,
		candidate.Public.ID, fingerprint, candidate)
	if err != nil {
		t.Fatalf("same-Group pin without CommunicationLink: %v", err)
	}
	retried, err := state.PinVerifiedPeerKey(context.Background(), sameGroupScope, peer,
		candidate.Public.ID, fingerprint, candidate)
	if err != nil || retried.Version != first.Version {
		t.Fatalf("same-Group empty-link retry: pin=%+v err=%v", retried, err)
	}
	otherScope = scope
	otherScope.CommunicationLinkID = "link_other"
	if _, err := state.GetPeerPin(context.Background(), otherScope, peer); !errors.Is(err, ErrPeerPinNotFound) {
		t.Fatalf("cross-link lookup error = %v", err)
	}
	wrongPeer := peer
	wrongPeer.OwnerID = "owner_other"
	if _, err := state.GetPeerPin(context.Background(), scope, wrongPeer); !errors.Is(err, ErrPeerPinIdentityMismatch) {
		t.Fatalf("peer owner substitution on lookup error = %v", err)
	}
	if _, err := state.VerifyPeerPin(context.Background(), scope, peer,
		candidate.Public.ID, changedFingerprint(fingerprint)); !errors.Is(err, ErrPeerPinApprovalMismatch) {
		t.Fatalf("wrong approved key on verify error = %v", err)
	}
}

func TestPeerPinRejectsKeyAndOwnerSubstitutionWhileActive(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, _ := PeerKeyFingerprint(candidate.Public)
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate); err != nil {
		t.Fatal(err)
	}

	replacement := signedPeerCandidate(t, peer, "node_peer", "binding_peer", 3)
	replacementFingerprint, _ := PeerKeyFingerprint(replacement.Public)
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		replacement.Public.ID, replacementFingerprint, replacement); !errors.Is(err, ErrPeerPinConflict) {
		t.Fatalf("key substitution error = %v", err)
	}

	otherOwner := peer
	otherOwner.OwnerID = "owner_other"
	ownerCandidate := candidate
	ownerCandidate.OwnerID = otherOwner.OwnerID
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, otherOwner,
		candidate.Public.ID, fingerprint, ownerCandidate); !errors.Is(err, ErrPeerPinConflict) {
		t.Fatalf("owner substitution error = %v", err)
	}
}

func TestPeerPinRevocationUsesVersionAndIsTerminal(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, _ := PeerKeyFingerprint(candidate.Public)
	first, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.RevokePeerPin(context.Background(), scope, peer, first.Version+1); !errors.Is(err, ErrPeerPinVersionConflict) {
		t.Fatalf("wrong-version revocation error = %v", err)
	}
	revoked, err := state.RevokePeerPin(context.Background(), scope, peer, first.Version)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Version != first.Version+1 || revoked.RevokedAt == "" {
		t.Fatalf("revoked pin = %+v", revoked)
	}
	if _, err := state.GetPeerPin(context.Background(), scope, peer); !errors.Is(err, ErrPeerPinRevoked) {
		t.Fatalf("lookup of revoked pin error = %v", err)
	}
	if _, err := state.RevokePeerPin(context.Background(), scope, peer, first.Version); !errors.Is(err, ErrPeerPinRevoked) {
		t.Fatalf("repeat stale revocation error = %v", err)
	}

	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate); !errors.Is(err, ErrPeerPinRevoked) {
		t.Fatalf("stale approval reactivating revoked pin error = %v", err)
	}
}

func TestPeerPinSurvivesRestart(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, _ := PeerKeyFingerprint(candidate.Public)
	pin, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	loaded, err := state.VerifyPeerPin(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Version != pin.Version || loaded.KeyID != pin.KeyID || loaded.Peer.OwnerID != peer.OwnerID {
		t.Fatalf("pin after restart = %+v, before = %+v", loaded, pin)
	}
}

func TestCryptoStateV1UpgradePreservesSequenceOutboxAndReplay(t *testing.T) {
	stateDir := t.TempDir()
	wire := []byte("legacy opaque envelope")
	digest := sha256.Sum256(wire)
	createV1CryptoState(t, filepath.Join(stateDir, cryptoStateDBName), wire, digest[:])

	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var version int
	if err := state.db.QueryRow(`SELECT version FROM node_crypto_schema WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("migrated schema version = %d, want 5", version)
	}
	sequence, err := state.ReserveOutboundSequence(context.Background(), "ep_legacy", "key_legacy")
	if err != nil || sequence != 12 {
		t.Fatalf("sequence after v1 migration = %d, err = %v", sequence, err)
	}
	loaded, err := state.GetOutbound(context.Background(), "op_legacy", "key_legacy")
	if err != nil || !bytes.Equal(loaded.Envelope, wire) {
		t.Fatalf("outbox after v1 migration = %+v, err = %v", loaded, err)
	}
	duplicate, err := state.AcceptInbound(context.Background(), "ep_receiver", "key_sender",
		"msg_legacy", 7, wire)
	if !errors.Is(err, ErrInboundRecoveryRequired) || duplicate {
		t.Fatalf("legacy replay without ciphertext was treated as recoverable: duplicate=%v err=%v", duplicate, err)
	}
	if _, err := state.GetInbound(context.Background(), "ep_receiver", "key_sender", "msg_legacy"); !errors.Is(err, ErrInboundRecoveryRequired) {
		t.Fatalf("legacy replay without ciphertext lookup error = %v", err)
	}
}

func TestCryptoStateV2UpgradePreservesPeerPinAndRequiresLegacyInboxReconciliation(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer, candidate.Public.ID, fingerprint, candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AcceptInbound(context.Background(), "ep_receiver", "sender_key", "msg_v2", 4, []byte("old opaque envelope")); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// A v2 database had replay metadata and pins but no durable ciphertext
	// inbox. Simulate that exact schema boundary without altering the replay.
	db, err := sql.Open("sqlite", filepath.Join(stateDir, cryptoStateDBName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE node_crypto_inbox;
UPDATE node_crypto_schema SET version = 2 WHERE singleton = 1`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if _, err := state.VerifyPeerPin(context.Background(), scope, peer, candidate.Public.ID, fingerprint); err != nil {
		t.Fatalf("v2 pin lost during v3 migration: %v", err)
	}
	if duplicate, err := state.AcceptInbound(context.Background(), "ep_receiver", "sender_key", "msg_v2", 4, []byte("old opaque envelope")); !errors.Is(err, ErrInboundRecoveryRequired) || duplicate {
		t.Fatalf("v2 replay-only row was silently treated as delivered: duplicate=%v err=%v", duplicate, err)
	}
	if duplicate, err := state.AcceptInbound(context.Background(), "ep_receiver", "sender_key", "msg_new", 5, []byte("new opaque envelope")); err != nil || duplicate {
		t.Fatalf("v3 inbound after v2 migration: duplicate=%v err=%v", duplicate, err)
	}
}

func TestCryptoStateV3UpgradePreservesPinsAndAddsLinkGrantBinding(t *testing.T) {
	stateDir := t.TempDir()
	state, err := OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, err := PeerKeyFingerprint(candidate.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.PinVerifiedPeerKey(context.Background(), scope, peer,
		candidate.Public.ID, fingerprint, candidate); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	// Restore the exact v3 peer-pin column boundary while preserving its row.
	db, err := sql.Open("sqlite", filepath.Join(stateDir, cryptoStateDBName))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`ALTER TABLE node_crypto_peer_pins DROP COLUMN target_grant_expires_at;
ALTER TABLE node_crypto_peer_pins DROP COLUMN source_grant_expires_at;
ALTER TABLE node_crypto_peer_pins DROP COLUMN link_expires_at;
ALTER TABLE node_crypto_peer_pins DROP COLUMN manifest_digest;
ALTER TABLE node_crypto_peer_pins DROP COLUMN link_version;
UPDATE node_crypto_schema SET version = 3 WHERE singleton = 1`)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenCryptoState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	loaded, err := state.VerifyPeerPin(context.Background(), scope, peer, candidate.Public.ID, fingerprint)
	if err != nil {
		t.Fatalf("v3 same-Group pin lost during schema upgrade: %v", err)
	}
	if loaded.LinkVersion != 0 || loaded.ManifestDigest != "" {
		t.Fatalf("legacy v3 pin unexpectedly gained cross-Group authorization: %+v", loaded)
	}
	var version int
	if err := state.db.QueryRow(`SELECT version FROM node_crypto_schema WHERE singleton=1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("schema after v3 migration = %d, want 5", version)
	}
}

func TestPeerPinConcurrentHandlesCreateOneActivePin(t *testing.T) {
	stateDir := t.TempDir()
	states := make([]*CryptoState, 2)
	for i := range states {
		state, err := OpenCryptoState(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		states[i] = state
	}
	defer states[0].Close()
	defer states[1].Close()

	scope, peer, candidate := testPeerCandidate(t)
	fingerprint, _ := PeerKeyFingerprint(candidate.Public)
	const attempts = 12
	var wait sync.WaitGroup
	errCh := make(chan error, attempts)
	versions := make(chan int64, attempts)
	for i := 0; i < attempts; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			pin, err := states[i%len(states)].PinVerifiedPeerKey(context.Background(), scope,
				peer, candidate.Public.ID, fingerprint, candidate)
			if err != nil {
				errCh <- err
				return
			}
			versions <- pin.Version
		}(i)
	}
	wait.Wait()
	close(errCh)
	close(versions)
	for err := range errCh {
		t.Errorf("concurrent pin failed: %v", err)
	}
	for version := range versions {
		if version != 1 {
			t.Errorf("concurrent active pin version = %d, want 1", version)
		}
	}
}

func testPeerCandidate(t *testing.T) (PeerPinScope, PeerPinIdentity, PeerKeyCandidate) {
	t.Helper()
	peer := PeerPinIdentity{EndpointID: "ep_peer", GroupID: "group_local",
		PrincipalID: "pr_peer", OwnerID: "owner_peer"}
	scope := PeerPinScope{LocalEndpointID: "ep_local", LocalGroupID: "group_local",
		PeerEndpointID: peer.EndpointID, PeerGroupID: peer.GroupID}
	return scope, peer, signedPeerCandidate(t, peer, "node_peer", "binding_peer", 3)
}

func signedPeerCandidate(t *testing.T, peer PeerPinIdentity, nodeID, bindingID string, epoch uint64) PeerKeyCandidate {
	t.Helper()
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(peer.EndpointID, peer.PrincipalID,
		nodeID, bindingID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	return PeerKeyCandidate{EndpointID: peer.EndpointID, PrincipalID: peer.PrincipalID,
		OwnerID: peer.OwnerID, NodeID: nodeID, Public: identity.Public(),
		BindingID: bindingID, BindingEpoch: epoch, Attestation: proof}
}

func changedFingerprint(fingerprint string) string {
	last := fingerprint[len(fingerprint)-1]
	if last == '0' {
		return fingerprint[:len(fingerprint)-1] + "1"
	}
	return fingerprint[:len(fingerprint)-1] + "0"
}

func createV1CryptoState(t *testing.T, dbPath string, wire, digest []byte) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE node_crypto_schema (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), version INTEGER NOT NULL);
INSERT INTO node_crypto_schema(singleton, version) VALUES (1, 1);
CREATE TABLE node_crypto_sequences (
 endpoint_id TEXT NOT NULL, source_key_id TEXT NOT NULL,
 last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0),
 PRIMARY KEY (endpoint_id, source_key_id)
) WITHOUT ROWID;
CREATE TABLE node_crypto_outbox (
 operation_id TEXT NOT NULL, source_endpoint_id TEXT NOT NULL, source_key_id TEXT NOT NULL,
 digest BLOB NOT NULL CHECK (length(digest) = 32), envelope BLOB NOT NULL CHECK (length(envelope) > 0),
 PRIMARY KEY (operation_id, source_key_id)
) WITHOUT ROWID;
CREATE TABLE node_crypto_replay (
 receiver_endpoint_id TEXT NOT NULL, sender_key_id TEXT NOT NULL, message_id TEXT NOT NULL,
 digest BLOB NOT NULL CHECK (length(digest) = 32), sequence INTEGER NOT NULL CHECK (sequence > 0),
 PRIMARY KEY (receiver_endpoint_id, sender_key_id, message_id),
 UNIQUE (receiver_endpoint_id, sender_key_id, sequence)
) WITHOUT ROWID;
INSERT INTO node_crypto_sequences(endpoint_id, source_key_id, last_sequence) VALUES ('ep_legacy', 'key_legacy', 11);
INSERT INTO node_crypto_outbox(operation_id, source_endpoint_id, source_key_id, digest, envelope)
VALUES ('op_legacy', 'ep_legacy', 'key_legacy', ?, ?);
INSERT INTO node_crypto_replay(receiver_endpoint_id, sender_key_id, message_id, digest, sequence)
VALUES ('ep_receiver', 'key_sender', 'msg_legacy', ?, 7);`, digest, wire, digest)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create v1 database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
