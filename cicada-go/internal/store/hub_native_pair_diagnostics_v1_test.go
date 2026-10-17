package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestHubNativePairRevokeCASAndTerminalRecovery(t *testing.T) {
	for _, complete := range []bool{false, true} {
		name := "prepared"
		if complete {
			name = "waiting_join"
		}
		t.Run(name, func(t *testing.T) {
			f := nativePairStore(t)
			_, _, ch := f.prepare(t)
			expected := uint64(1)
			var late HubNativePairInput
			var lateSeal HubNativePairSeal
			_, late, lateSeal = f.complete(t, ch)
			if complete {
				if _, err := f.f.db.ProcessHubNativePair(late, lateSeal); err != nil {
					t.Fatal(err)
				}
				expected = 2
				_, late, lateSeal = f.complete(t, ch)
			}
			revoke := func(revision uint64) (wire.NativePairRevoke, HubNativePairInput, HubNativePairSeal) {
				c := f.context(t, f.at.Add(2*time.Second))
				claims := f.claims(c, e2ee.OwnerNativePairRevoke)
				claims.Scope = ch.Scope
				digest, err := wire.NativePairRevokeTargetDigest(ch.Scope, ch.Bootstrap.PairID, revision)
				if err != nil {
					t.Fatal(err)
				}
				claims.Revoke = &e2ee.NativePairRevokeClaims{PairID: ch.Bootstrap.PairID, ExpectedRevision: revision, PairTargetDigest: digest}
				proof, err := e2ee.SignOwnerNativePair(f.f.owner, claims)
				if err != nil {
					t.Fatal(err)
				}
				q := wire.NativePairRevoke{Format: wire.NativePairFormat, Context: c, SessionToken: f.f.session.Token, OwnerProof: proof}
				in, seal := f.input(t, q, f.at.Add(2*time.Second))
				return q, in, seal
			}
			bad, badIn, badSeal := revoke(expected + 1)
			badPacket, err := f.f.db.ProcessHubNativePair(badIn, badSeal)
			if err != nil {
				t.Fatal(err)
			}
			var fence wire.NativePairRejectionFence
			if wire.OpenClientResponse(f.f.device, f.f.hub, badIn.Packet, badPacket, &fence) != nil || wire.ValidateNativePairRejectionTarget(fence, bad, badIn.Packet) != nil {
				t.Fatal("wrong CAS was not permanently fenced")
			}
			_, in, seal := revoke(expected)
			packet, err := f.f.db.ProcessHubNativePair(in, seal)
			if err != nil {
				t.Fatal(err)
			}
			var result wire.NativePairResult
			if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &result) != nil || result.State != wire.NativePairRevoked || result.ControlRevision != expected+1 || result.AdministrativePermission || result.SlotA != nil || result.SlotB != nil {
				t.Fatal("revoke changed scope or retained live permission")
			}
			late.At = in.At
			rejected, err := f.f.db.ProcessHubNativePair(late, lateSeal)
			if err != nil {
				t.Fatal(err)
			}
			if wire.OpenClientResponse(f.f.device, f.f.hub, late.Packet, rejected, &fence) != nil || !fence.NoEffect {
				t.Fatal("terminal pair admitted an unadmitted old completion")
			}
			var domains, slots int
			if f.f.db.db.QueryRow(`SELECT count(*) FROM networks_v2 WHERE id=?`, ch.Bootstrap.NetworkID).Scan(&domains) != nil || domains != int(expected-1) {
				t.Fatal("revocation created/replaced a Network")
			}
			if f.f.db.db.QueryRow(`SELECT count(*) FROM hub_native_pair_slots_v1 WHERE pair_id=?`, ch.Bootstrap.PairID).Scan(&slots) != nil || slots != 2*int(expected-1) {
				t.Fatal("revocation invented or erased slot history")
			}
			if err = f.f.db.Close(); err != nil {
				t.Fatal(err)
			}
			f.f.db, err = New(f.f.path)
			if err != nil {
				t.Fatal(err)
			}
			in.At = f.at.Add(2 * time.Hour)
			recovered, err := f.f.db.ProcessHubNativePair(in, seal)
			if err != nil || !bytes.Equal(packet, recovered) {
				t.Fatal("terminal exact receipt did not survive reopen/expiry", err)
			}
			badIn.At = in.At
			recovered, err = f.f.db.ProcessHubNativePair(badIn, badSeal)
			if err != nil || !bytes.Equal(badPacket, recovered) {
				t.Fatal("old CAS fence was reinterpreted after terminal state", err)
			}
		})
	}
}

func TestHubNativePairStatusCurrentContextAndHistoricalExpiry(t *testing.T) {
	f := nativePairStore(t)
	_, _, ch := f.prepare(t)
	_, complete, completeSeal := f.complete(t, ch)
	if _, err := f.f.db.ProcessHubNativePair(complete, completeSeal); err != nil {
		t.Fatal(err)
	}
	status := func(t *testing.T, c wire.NativePairRequestContext, token []byte, at time.Time) (HubNativePairInput, HubNativePairSeal, []byte, wire.NativePairResult) {
		t.Helper()
		q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: c, SessionToken: token, PairID: ch.Bootstrap.PairID}
		in, seal := f.input(t, q, at)
		packet, err := f.f.db.ProcessHubNativePair(in, seal)
		if err != nil {
			t.Fatal(err)
		}
		var result wire.NativePairResult
		if wire.OpenClientResponse(f.f.device, f.f.hub, in.Packet, packet, &result) != nil {
			t.Fatal("status receipt failed exact authentication")
		}
		return in, seal, packet, result
	}
	at := f.at.Add(2 * time.Second)
	original, seal, packet, result := status(t, f.context(t, at), f.f.session.Token, at)
	if !result.AdministrativePermission || result.Outcome != "COMPLETED" {
		t.Fatal("current exact session did not expose current administration")
	}
	for _, change := range []struct {
		name string
		edit func(*wire.NativePairRequestContext)
	}{
		{"session", func(c *wire.NativePairRequestContext) { c.AccountSessionID = "synthetic-unrelated-session" }},
		{"account_epoch", func(c *wire.NativePairRequestContext) { c.AccountEpoch++ }},
		{"device_epoch", func(c *wire.NativePairRequestContext) { c.DeviceEpoch++ }},
		{"client_epoch", func(c *wire.NativePairRequestContext) { c.ClientSessionEpoch++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := f.context(t, at)
			change.edit(&c)
			_, _, _, r := status(t, c, f.f.session.Token, at)
			if r.AdministrativePermission {
				t.Fatal("mismatched query context advertised current administration")
			}
		})
	}
	_, _, _, result = status(t, f.context(t, at), nil, at)
	if result.AdministrativePermission {
		t.Fatal("retained device-only history supplied current administration")
	}
	original.At = at.Add(3 * time.Minute)
	cached, err := f.f.db.ProcessHubNativePair(original, seal)
	if err != nil || !bytes.Equal(packet, cached) {
		t.Fatal("bounded historical read retry was not exact", err)
	}
	original.At = at.Add(6 * time.Minute)
	expired, err := f.f.db.ProcessHubNativePair(original, seal)
	if err != nil {
		t.Fatal(err)
	}
	if wire.OpenClientResponse(f.f.device, f.f.hub, original.Packet, expired, &result) != nil || result.Outcome != "READ_EXPIRED" || result.AdministrativePermission || result.SlotA != nil || result.SlotB != nil {
		t.Fatal("aged pure read became current authority or mutation settlement")
	}
}
