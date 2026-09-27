package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestInboundPeerMessageIsAtomicAndTransportIdempotent(t *testing.T) {
	persistence, err := New(t.TempDir() + "/state/cicada.sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	peer, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	contact, err := persistence.CreateContact(Contact{Label: "peer", Identity: peer.Public()})
	if err != nil {
		t.Fatal(err)
	}
	input := PeerMessage{
		TransportID: "remote-message-1", ContactID: contact.ID,
		SenderID: peer.Public().ID, RecipientID: "local", Sequence: 7,
		Envelope: json.RawMessage(`{"ciphertext":"opaque"}`), AAD: "Z29hbA",
	}
	stored, created, err := persistence.AcceptInboundPeerMessage(input)
	if err != nil || !created || stored.TransportID != input.TransportID {
		t.Fatalf("first inbound message failed: message=%#v created=%v err=%v", stored, created, err)
	}
	duplicate, created, err := persistence.AcceptInboundPeerMessage(input)
	if err != nil || created || duplicate.ID != stored.ID {
		t.Fatalf("transport retry was not idempotent: message=%#v created=%v err=%v", duplicate, created, err)
	}
	input.TransportID = "remote-message-2"
	if _, _, err := persistence.AcceptInboundPeerMessage(input); !errors.Is(err, ErrPeerReplay) {
		t.Fatalf("sequence replay under a new transport id was accepted: %v", err)
	}
	messages, err := persistence.ListPeerMessages(contact.ID)
	if err != nil || len(messages) != 1 || messages[0].ID != stored.ID {
		t.Fatalf("unexpected inbound rows: messages=%#v err=%v", messages, err)
	}
	resolved, err := persistence.GetContactByRemoteID(peer.Public().ID)
	if err != nil || resolved == nil || resolved.ID != contact.ID {
		t.Fatalf("remote identity was not mapped: contact=%#v err=%v", resolved, err)
	}
	if _, err := persistence.CreateContact(Contact{Label: "duplicate", Identity: peer.Public()}); err == nil {
		t.Fatal("duplicate remote identity was accepted")
	}
}

func TestFederationSchemaMigratesExistingContactsAndMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cicada.sqlite3")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
CREATE TABLE contacts (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, identity_json TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'trusted', send_sequence INTEGER NOT NULL DEFAULT 0,
 received_sequences_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE peer_messages (
 id TEXT PRIMARY KEY, contact_id TEXT NOT NULL, direction TEXT NOT NULL,
 sender_id TEXT NOT NULL, recipient_id TEXT NOT NULL, sequence INTEGER NOT NULL,
 envelope_json TEXT NOT NULL, aad TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'queued',
 created_at TEXT NOT NULL, delivered_at TEXT
);`)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	identityJSON, _ := json.Marshal(peer.Public())
	_, err = database.Exec(`INSERT INTO contacts
(id, label, identity_json, status, created_at, updated_at)
VALUES ('contact_legacy', 'legacy', ?, 'trusted', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, string(identityJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	contact, err := upgraded.GetContactByRemoteID(peer.Public().ID)
	if err != nil || contact == nil || contact.ID != "contact_legacy" {
		t.Fatalf("legacy contact remote identity was not backfilled: contact=%#v err=%v", contact, err)
	}
	message, err := upgraded.CreatePeerMessage(PeerMessage{
		TransportID: "transport-after-upgrade", ContactID: contact.ID,
		Direction: "outbound", SenderID: "local", RecipientID: peer.Public().ID,
		Sequence: 1, Envelope: json.RawMessage(`{"ciphertext":"opaque"}`),
	})
	if err != nil || message.TransportID != "transport-after-upgrade" {
		t.Fatalf("peer transport column was not migrated: message=%#v err=%v", message, err)
	}
}
