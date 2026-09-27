package e2ee

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOwnerLinkKeyGrantRequiresCurrentKeyManifestAndTrustedOwner(t *testing.T) {
	owner, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	contract := strings.Repeat("a", 64)
	manifest := strings.Repeat("b", 64)
	proof, err := owner.SignOwnerLinkKeyGrant("owner_a", "link_a", contract,
		manifest, 9, OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := VerifyOwnerLinkKeyGrant(proof, owner.Public(), "owner_a", "link_a",
		contract, manifest, 9, OwnerLinkGrantSideSource, now)
	if err != nil || grant.Version != OwnerLinkKeyGrantVersion || grant.KeyBindingDigest != manifest {
		t.Fatalf("valid key-bound grant failed: grant=%#v err=%v", grant, err)
	}
	for name, change := range map[string]func(*string, *string, *string, *string, *uint64, *OwnerLinkGrantSide){
		"owner":    func(owner, _, _, _ *string, _ *uint64, _ *OwnerLinkGrantSide) { *owner = "owner_b" },
		"link":     func(_, link, _, _ *string, _ *uint64, _ *OwnerLinkGrantSide) { *link = "link_b" },
		"contract": func(_, _, contract, _ *string, _ *uint64, _ *OwnerLinkGrantSide) { *contract = strings.Repeat("c", 64) },
		"manifest": func(_, _, _, manifest *string, _ *uint64, _ *OwnerLinkGrantSide) { *manifest = strings.Repeat("c", 64) },
		"version":  func(_, _, _, _ *string, version *uint64, _ *OwnerLinkGrantSide) { *version = 10 },
		"side":     func(_, _, _, _ *string, _ *uint64, side *OwnerLinkGrantSide) { *side = OwnerLinkGrantSideTarget },
	} {
		t.Run(name, func(t *testing.T) {
			o, l, c, m, v, s := "owner_a", "link_a", contract, manifest, uint64(9), OwnerLinkGrantSideSource
			change(&o, &l, &c, &m, &v, &s)
			if _, err := VerifyOwnerLinkKeyGrant(proof, owner.Public(), o, l, c, m, v, s, now); err == nil {
				t.Fatal("changed key-bound claim verified")
			}
		})
	}
	if _, err := VerifyOwnerLinkKeyGrant(proof, other.Public(), "owner_a", "link_a",
		contract, manifest, 9, OwnerLinkGrantSideSource, now); err == nil {
		t.Fatal("untrusted owner key verified")
	}
	if _, err := VerifyOwnerLinkKeyGrant(proof, owner.Public(), "owner_a", "link_a",
		contract, manifest, 9, OwnerLinkGrantSideSource, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired key-bound grant verified")
	}
	var decoded OwnerLinkKeyGrant
	if err := json.Unmarshal(proof, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.KeyBindingDigest = strings.Repeat("c", 64)
	tampered, _ := json.Marshal(decoded)
	if _, err := VerifyOwnerLinkKeyGrant(tampered, owner.Public(), "owner_a", "link_a",
		contract, decoded.KeyBindingDigest, 9, OwnerLinkGrantSideSource, now); err == nil {
		t.Fatal("tampered key binding digest verified")
	}
	legacy, err := owner.SignOwnerLinkGrant("owner_a", "link_a", contract, 9,
		OwnerLinkGrantSideSource, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOwnerLinkKeyGrant(legacy, owner.Public(), "owner_a", "link_a",
		contract, manifest, 9, OwnerLinkGrantSideSource, now); err == nil {
		t.Fatal("legacy key-unbound grant verified as v2")
	}
}
