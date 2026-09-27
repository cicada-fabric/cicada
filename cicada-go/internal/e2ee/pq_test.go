package e2ee

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestPostQuantumEnvelopeRoundTripAndPersistence(t *testing.T) {
	alice, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if alice.Public().ID == bob.Public().ID {
		t.Fatal("identities must have different IDs")
	}
	secret, err := alice.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalIdentity(secret)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Public().ID != alice.Public().ID {
		t.Fatalf("restored identity changed ID: %s != %s", restored.Public().ID, alice.Public().ID)
	}

	plaintext := []byte("Cicada peer message: evidence is ready")
	aad := []byte("contact=bob;goal=goal_demo")
	envelope, err := Seal(restored, bob.Public(), plaintext, aad, 7)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("plaintext was embedded in the envelope")
	}
	guard := NewReplayGuard()
	opened, sequence, err := OpenWithReplayGuard(bob, restored.Public(), envelope, aad, guard)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 7 || !bytes.Equal(opened, plaintext) {
		t.Fatalf("unexpected plaintext/sequence: %q/%d", opened, sequence)
	}
	if _, _, err := OpenWithReplayGuard(bob, restored.Public(), envelope, aad, guard); err != ErrReplay {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestPostQuantumEnvelopeRejectsTamperingAndWrongContact(t *testing.T) {
	alice, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(alice, bob.Public(), []byte("classified"), []byte("goal"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(bob, mallory.Public(), envelope, []byte("goal")); err != ErrWrongSender {
		t.Fatalf("expected wrong-sender rejection, got %v", err)
	}
	var decoded Envelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.Ciphertext[0] ^= 1
	tampered, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(bob, alice.Public(), tampered, []byte("goal")); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestSignedContactAnnouncementRequiresKeyPossession(t *testing.T) {
	alice, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	announcement, err := alice.SignContactAnnouncement("Alice")
	if err != nil {
		t.Fatal(err)
	}
	identity, label, err := VerifyContactAnnouncement(announcement)
	if err != nil || identity.ID != alice.Public().ID || label != "Alice" {
		t.Fatalf("valid announcement was rejected: identity=%#v label=%q err=%v", identity, label, err)
	}
	announcement[len(announcement)-2] ^= 1
	if _, _, err := VerifyContactAnnouncement(announcement); err == nil {
		t.Fatal("tampered announcement was accepted")
	}
	if _, err := alice.SignContactAnnouncement(""); err == nil {
		t.Fatal("empty announcement label was accepted")
	}
}

func TestReplayGuardDoesNotConsumeFailedCiphertext(t *testing.T) {
	sender, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(sender, recipient.Public(), []byte("hello"), nil, 7)
	if err != nil {
		t.Fatal(err)
	}
	var parsed Envelope
	if err := json.Unmarshal(envelope, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Ciphertext[0] ^= 0xff
	tampered, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	guard := NewReplayGuard()
	if _, _, err := OpenWithReplayGuard(recipient, sender.Public(), tampered, nil, guard); err == nil {
		t.Fatal("tampered ciphertext unexpectedly opened")
	}
	opened, sequence, err := OpenWithReplayGuard(recipient, sender.Public(), envelope, nil, guard)
	if err != nil || string(opened) != "hello" || sequence != 7 {
		t.Fatalf("valid envelope was rejected after failed ciphertext: plaintext=%q sequence=%d err=%v", opened, sequence, err)
	}
}
