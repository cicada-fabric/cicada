package e2ee

import (
	"errors"
	"testing"
)

func TestRatchetOfferRoundTripAndRotation(t *testing.T) {
	alice, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	offer, root, err := NewSessionOffer(alice, bob.Public(), 1)
	if err != nil {
		t.Fatal(err)
	}
	epoch, bobRoot, err := AcceptSessionOffer(bob, alice.Public(), offer)
	if err != nil || epoch != 1 || string(root) != string(bobRoot) {
		t.Fatalf("session roots differ epoch=%d err=%v", epoch, err)
	}
	aliceState, err := NewRatchetState(1, root, alice.Public().ID, bob.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealRatchet(alice, bob.Public(), aliceState, 1, offer, []byte("first"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	bobPlain, bobState, err := OpenRatchet(bob, alice.Public(), envelope, []byte("aad"), nil)
	if err != nil || string(bobPlain) != "first" {
		t.Fatalf("first ratchet message plain=%q err=%v", bobPlain, err)
	}
	envelope, err = SealRatchet(alice, bob.Public(), aliceState, 2, nil, []byte("second"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	bobPlain, _, err = OpenRatchet(bob, alice.Public(), envelope, []byte("aad"), bobState)
	if err != nil || string(bobPlain) != "second" {
		t.Fatalf("second ratchet message plain=%q err=%v", bobPlain, err)
	}
	if _, _, err = OpenRatchet(bob, alice.Public(), envelope, []byte("aad"), bobState); !errors.Is(err, ErrReplay) {
		t.Fatalf("ratchet replay was accepted: %v", err)
	}
}

func TestRatchetOfferRejectsWrongRecipient(t *testing.T) {
	alice, _ := NewIdentity()
	bob, _ := NewIdentity()
	carol, _ := NewIdentity()
	offer, _, err := NewSessionOffer(alice, bob.Public(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcceptSessionOffer(carol, alice.Public(), offer); err == nil {
		t.Fatal("session offer for another recipient was accepted")
	}
}
