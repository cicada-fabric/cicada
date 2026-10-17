package e2ee

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func syntheticNativePairClaims(t *testing.T) (*Identity, []OwnerNativePairClaims, time.Time) {
	t.Helper()
	keys := make([]*Identity, 4)
	for i := range keys {
		var err error
		keys[i], err = NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	stamp := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }
	scope := OwnerNativePairScope{Actor: OwnerAppNodeScope{Version: 1, Origin: "https://synthetic-pair.invalid", HubID: "synthetic-hub", HubFingerprint: strings.Repeat("a", 64), AccountID: "synthetic-account", AccountSessionID: "synthetic-session", AccountSessionExpiresAt: stamp(15 * time.Minute), OwnerID: "synthetic-owner", OwnerPublic: keys[0].Public(), OwnerKeyVersion: 1, DeviceID: "synthetic-app", DevicePublic: keys[1].Public(), AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: "HTTPS_ONLY"}, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("b", 64), NodeTupleDigest: strings.Repeat("c", 64)}
	scope.Node = OwnerAppNodeBinding{OwnerBindingID: "synthetic-owner-binding", OwnerID: scope.Actor.OwnerID, HubID: scope.Actor.HubID, NodeID: "synthetic-node", ClientDeviceID: scope.Actor.DeviceID, OwnerKeyID: keys[0].Public().ID, CredentialVersion: 1, BindingVersion: 1, NodePublic: keys[2].Public(), NodeKeyFingerprint: strings.Repeat("d", 64), NodeKeyVersion: 1, NodeKeyEpoch: 1, HubNodeControlPublic: keys[3].Public(), HubNodeControlFingerprint: strings.Repeat("e", 64), HubNodeControlKeyVersion: 1, ApprovedRequestID: "synthetic-approved", ApprovedRequestVersion: 1, ApprovedCandidateDigest: strings.Repeat("f", 64), ApprovedAt: stamp(-time.Minute), State: "ACTIVE"}
	base := OwnerNativePairClaims{Version: 1, Scope: scope, RequestID: strings.Repeat("1", 32), Nonce: strings.Repeat("2", 64), IssuedAt: stamp(0), ExpiresAt: stamp(time.Minute)}
	preview := base
	preview.Purpose = OwnerNativePairBootstrapPreview
	preview.Bootstrap = &NativePairBootstrapClaims{GroupLabel: "Synthetic bounded pair", Runtime: "codex", SlotCount: 2, Policy: NativePairFixedPeerPolicy()}
	commit := base
	commit.Purpose = OwnerNativePairBootstrapCommit
	b := *preview.Bootstrap
	commit.Bootstrap = &b
	b.PairID = strings.Repeat("3", 32)
	b.NetworkID = "synthetic-network"
	b.GroupID = "synthetic-group"
	b.PreparedAt = stamp(0)
	b.JoinUntil = stamp(10 * time.Minute)
	b.PeerExpiresAt = stamp(time.Hour)
	b.PrepareRequestID = strings.Repeat("4", 32)
	b.PreparePacketDigest = strings.Repeat("5", 64)
	b.ServerNonce = strings.Repeat("6", 64)
	plan := base
	plan.Purpose = OwnerNativePairConsentPreview
	plan.Consent = &NativePairConsentClaims{PairID: b.PairID, ExpectedRevision: 1, SlotADigest: strings.Repeat("7", 64), SlotBDigest: strings.Repeat("8", 64), PeerExpiresAt: b.PeerExpiresAt}
	consent := base
	consent.Purpose = OwnerNativePairSlotConsent
	c := *plan.Consent
	consent.Consent = &c
	c.PlanID = strings.Repeat("9", 32)
	c.PlanDigest = strings.Repeat("a", 64)
	c.Slot = "A"
	c.SlotGeneration = 1
	c.SlotAttemptID = strings.Repeat("b", 32)
	c.NativeSessionID = "synthetic-sid-a"
	c.PeerNativeSessionID = "synthetic-sid-b"
	c.ActivateWhenBoth = true
	c.PlanExpiresAt = stamp(5 * time.Minute)
	reject := base
	reject.Purpose = OwnerNativePairSlotReject
	reject.Reject = &NativePairRejectClaims{PairID: b.PairID, ExpectedRevision: 1, Slot: "A", SlotGeneration: 1, SlotAttemptID: c.SlotAttemptID, SlotDigest: plan.Consent.SlotADigest}
	revoke := base
	revoke.Purpose = OwnerNativePairRevoke
	revoke.Revoke = &NativePairRevokeClaims{PairID: b.PairID, ExpectedRevision: 1, PairTargetDigest: strings.Repeat("c", 64)}
	return keys[0], []OwnerNativePairClaims{preview, commit, plan, consent, reject, revoke}, now
}

func TestOwnerNativePairSixPurposeRealSignatures(t *testing.T) {
	owner, all, now := syntheticNativePairClaims(t)
	for _, c := range all {
		t.Run(c.Purpose, func(t *testing.T) {
			raw, err := SignOwnerNativePair(owner, c)
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyOwnerNativePair(owner.Public(), raw, c.Purpose, now)
			if err != nil || !reflect.DeepEqual(got, c) {
				t.Fatalf("roundtrip: %v", err)
			}
			t.Logf("real_mldsa65_proof_bytes=%d", len(raw))
			for _, other := range all {
				if other.Purpose != c.Purpose {
					if _, e := VerifyOwnerNativePair(owner.Public(), raw, other.Purpose, now); e == nil {
						t.Fatal("cross-purpose accepted")
					}
				}
			}
			if _, e := VerifyOwnerAppNodeGrant(owner.Public(), raw, now); e == nil {
				t.Fatal("native pair accepted as N3")
			}
			if _, e := VerifyOwnerAppNodePreview(owner.Public(), raw, now); e == nil {
				t.Fatal("native pair accepted as N3 preview")
			}
			if _, e := VerifyOwnerDeviceGrant(raw, owner.Public(), c.Scope.Actor.DevicePublic, c.Scope.Actor.OwnerID, owner.Public().ID, c.Scope.Actor.DeviceID, c.Scope.Actor.HubID, OwnerDevicePurposeControl, now); e == nil {
				t.Fatal("native pair accepted as N2 enrollment")
			}
			if _, e := VerifyOwnerNativePair(owner.Public(), append(raw, ' '), c.Purpose, now); e == nil {
				t.Fatal("noncanonical proof accepted")
			}
			unknown := append([]byte(`{"unknown":0,`), raw[1:]...)
			if _, e := VerifyOwnerNativePair(owner.Public(), unknown, c.Purpose, now); e == nil {
				t.Fatal("unknown field accepted")
			}
			duplicate := bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
			if _, e := VerifyOwnerNativePair(owner.Public(), duplicate, c.Purpose, now); e == nil {
				t.Fatal("duplicate field accepted")
			}
			var p OwnerNativePairProof
			_ = json.Unmarshal(raw, &p)
			p.Claims.Scope.Node.NodeKeyEpoch++
			bad, _ := json.Marshal(p)
			if _, e := VerifyOwnerNativePair(owner.Public(), bad, c.Purpose, now); e == nil {
				t.Fatal("changed epoch accepted")
			}
			p.Claims = c
			p.Signature[0] ^= 1
			bad, _ = json.Marshal(p)
			if _, e := VerifyOwnerNativePair(owner.Public(), bad, c.Purpose, now); e == nil {
				t.Fatal("changed signature accepted")
			}
			if _, e := VerifyOwnerNativePair(owner.Public(), raw, c.Purpose, now.Add(time.Minute)); e == nil {
				t.Fatal("exclusive expiry accepted")
			}
			if _, e := VerifyOwnerNativePair(owner.Public(), raw, c.Purpose, now.Add(-31*time.Second)); e == nil {
				t.Fatal("future proof accepted")
			}
			if _, e := VerifyOwnerNativePair(owner.Public(), raw, c.Purpose, time.Time{}); e != nil {
				t.Fatal("historical proof unavailable")
			}
		})
	}
}

func TestOwnerNativePairProofRejectsMalformedAuthority(t *testing.T) {
	owner, all, now := syntheticNativePairClaims(t)
	wrong, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignOwnerNativePair(owner, all[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, e := VerifyOwnerNativePair(wrong.Public(), raw, all[0].Purpose, now); e == nil {
		t.Fatal("untrusted Owner accepted")
	}
	if _, e := SignOwnerNativePair(wrong, all[0]); e == nil {
		t.Fatal("wrong signing identity accepted")
	}
	cases := []struct {
		name  string
		index int
		edit  func(*OwnerNativePairClaims)
	}{
		{"preview_reserved_id", 0, func(c *OwnerNativePairClaims) { c.Bootstrap.PairID = strings.Repeat("3", 32) }},
		{"two_variants", 0, func(c *OwnerNativePairClaims) { c.Revoke = all[5].Revoke }},
		{"expanded_budget", 0, func(c *OwnerNativePairClaims) { c.Bootstrap.Policy.MaxRootAsks++ }},
		{"borrow_n3_head", 0, func(c *OwnerNativePairClaims) { c.Scope.Actor.HeadVersion = 1 }},
		{"replacement_device", 0, func(c *OwnerNativePairClaims) { c.Scope.Node.ClientDeviceID = "another-app" }},
		{"deadline_extended", 1, func(c *OwnerNativePairClaims) {
			c.Bootstrap.PeerExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano)
		}},
		{"same_prepare_id", 1, func(c *OwnerNativePairClaims) { c.Bootstrap.PrepareRequestID = c.RequestID }},
		{"same_sid", 3, func(c *OwnerNativePairClaims) { c.Consent.PeerNativeSessionID = c.Consent.NativeSessionID }},
		{"bad_sid_path", 3, func(c *OwnerNativePairClaims) { c.Consent.NativeSessionID = "../escape" }},
		{"no_both_consent", 3, func(c *OwnerNativePairClaims) { c.Consent.ActivateWhenBoth = false }},
		{"plan_past_peer", 3, func(c *OwnerNativePairClaims) {
			c.Consent.PlanExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano)
		}},
		{"generation_overflow", 4, func(c *OwnerNativePairClaims) { c.Reject.SlotGeneration = 17 }},
		{"nonce_upper", 5, func(c *OwnerNativePairClaims) { c.Nonce = strings.Repeat("A", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(all[tc.index])
			var c OwnerNativePairClaims
			_ = json.Unmarshal(b, &c)
			tc.edit(&c)
			if _, e := SignOwnerNativePair(owner, c); e == nil {
				t.Fatal("invalid authority was signed")
			}
		})
	}
}
