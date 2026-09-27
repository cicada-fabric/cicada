package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func ownerLinkGrantTestDigest() string {
	digest := sha256.Sum256([]byte("canonical CommunicationLink contract"))
	return hex.EncodeToString(digest[:])
}

func signOwnerLinkGrantForTest(t *testing.T, identity *Identity, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	proof, err := identity.SignOwnerLinkGrant(
		"owner_a", "link_a", ownerLinkGrantTestDigest(), 9,
		OwnerLinkGrantSideSource, issuedAt, expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestOwnerLinkGrantVerifiesExactOwnerSideAndContract(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	proof := signOwnerLinkGrantForTest(t, owner, now.Add(-time.Minute), now.Add(time.Hour))
	grant, err := VerifyOwnerLinkGrant(proof, owner.Public(), "owner_a", "link_a",
		ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource, now)
	if err != nil {
		t.Fatalf("valid owner grant rejected: %v", err)
	}
	if grant.Version != OwnerLinkGrantVersion || grant.Side != OwnerLinkGrantSideSource ||
		grant.OwnerID != "owner_a" || grant.LinkID != "link_a" || grant.ExpectedLinkVersion != 9 ||
		len(grant.Nonce) != 64 || grant.Signature == nil {
		t.Fatalf("verified grant has unexpected claims: %+v", grant)
	}

	wrongOwner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkGrant(proof, wrongOwner.Public(), "owner_a", "link_a",
		ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource, now); err == nil {
		t.Fatal("grant verified with a different trusted owner identity")
	}
	for name, expected := range map[string]struct {
		ownerID, linkID, digest string
		version                 uint64
		side                    OwnerLinkGrantSide
	}{
		"owner":   {"owner_b", "link_a", ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource},
		"link":    {"owner_a", "link_b", ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource},
		"digest":  {"owner_a", "link_a", strings.Repeat("0", 64), 9, OwnerLinkGrantSideSource},
		"version": {"owner_a", "link_a", ownerLinkGrantTestDigest(), 10, OwnerLinkGrantSideSource},
		"side":    {"owner_a", "link_a", ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideTarget},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOwnerLinkGrant(proof, owner.Public(), expected.ownerID,
				expected.linkID, expected.digest, expected.version, expected.side, now); err == nil {
				t.Fatal("grant verified against different expected contract claims")
			}
		})
	}
}

func TestOwnerLinkGrantRejectsTamperingAndNoncanonicalWire(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	proof := signOwnerLinkGrantForTest(t, owner, now.Add(-time.Minute), now.Add(time.Hour))
	var grant OwnerLinkGrant
	if err := json.Unmarshal(proof, &grant); err != nil {
		t.Fatal(err)
	}
	grant.Side = OwnerLinkGrantSideTarget
	tampered, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkGrant(tampered, owner.Public(), "owner_a", "link_a",
		ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideTarget, now); err == nil {
		t.Fatal("grant accepted a tampered side")
	}

	for name, data := range map[string][]byte{
		"whitespace": append([]byte(" "), proof...),
		"trailing":   append(append([]byte(nil), proof...), []byte(" {}")...),
		"duplicate":  append([]byte(strings.TrimSuffix(string(proof), "}")), []byte(`,"version":1}`)...),
		"unknown":    append([]byte(strings.TrimSuffix(string(proof), "}")), []byte(`,"extra":true}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOwnerLinkGrant(data, owner.Public(), "owner_a", "link_a",
				ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource, now); err == nil {
				t.Fatal("noncanonical or extended grant wire was accepted")
			}
		})
	}
}

func TestOwnerLinkGrantRejectsExpiredFutureAndInvalidClaims(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	for name, bounds := range map[string]struct{ issued, expires time.Time }{
		"expired":         {now.Add(-2 * time.Hour), now.Add(-time.Second)},
		"future issuance": {now.Add(time.Second), now.Add(time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			proof := signOwnerLinkGrantForTest(t, owner, bounds.issued, bounds.expires)
			if _, err := VerifyOwnerLinkGrant(proof, owner.Public(), "owner_a", "link_a",
				ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource, now); err == nil {
				t.Fatal("grant accepted outside its validity period")
			}
		})
	}

	for name, claims := range map[string]struct {
		ownerID, linkID, digest string
		version                 uint64
		side                    OwnerLinkGrantSide
	}{
		"bad owner token": {"../owner", "link_a", ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource},
		"bad link token":  {"owner_a", "", ownerLinkGrantTestDigest(), 9, OwnerLinkGrantSideSource},
		"bad digest":      {"owner_a", "link_a", strings.Repeat("A", 64), 9, OwnerLinkGrantSideSource},
		"zero version":    {"owner_a", "link_a", ownerLinkGrantTestDigest(), 0, OwnerLinkGrantSideSource},
		"bad side":        {"owner_a", "link_a", ownerLinkGrantTestDigest(), 9, "BOTH"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := owner.SignOwnerLinkGrant(claims.ownerID, claims.linkID,
				claims.digest, claims.version, claims.side, now, now.Add(time.Hour)); err == nil {
				t.Fatal("signer accepted invalid grant claims")
			}
		})
	}
}

func TestOwnerLinkGrantNoncesAreUnique(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	first := signOwnerLinkGrantForTest(t, owner, now, now.Add(time.Hour))
	second := signOwnerLinkGrantForTest(t, owner, now, now.Add(time.Hour))
	var firstGrant, secondGrant OwnerLinkGrant
	if err := json.Unmarshal(first, &firstGrant); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second, &secondGrant); err != nil {
		t.Fatal(err)
	}
	if firstGrant.Nonce == secondGrant.Nonce {
		t.Fatal("separate grants reused a nonce")
	}
}
