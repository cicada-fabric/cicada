package nodekeys

import (
	"context"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Local policy-verifier test only. The constructed Current is not evidence of
// real Hub dual consent or a live native Runtime; TCP acceptance is separate.
func TestNativePairGroupCurrentRequiredBeforeUsingHistoricalReservation(t *testing.T) {
	f := newNativePairStateFixture(t, true)
	f.require(t)
	ctx := context.Background()
	p := f.evidence.Plan
	convert := func(s wire.NativePairSlot) wire.NativePairCurrentSlot {
		return wire.NativePairCurrentSlot{Slot: s.Slot, Generation: s.Generation, AttemptID: s.AttemptID, NativeSessionID: s.NativeSessionID, NetworkAccessBindingID: s.NetworkAccessBindingID, NetworkAccessEpoch: s.NetworkAccessEpoch, NetworkMembershipRevision: s.NetworkMembershipRevision, EndpointNetworkRevision: s.EndpointNetworkRevision, LeaseOwner: s.LeaseOwner, LeaseCeiling: s.LeaseCeiling}
	}
	current := wire.NativePairPeerCurrent{State: "CURRENT", ControlRevision: p.ExpectedRevision, ObservedAt: f.now.Format("2006-01-02T15:04:05.999999999Z07:00"), Sender: convert(p.SlotA), Receiver: convert(p.SlotB)}
	check := func(e *wire.NativePairPeerEvidence, c *wire.NativePairPeerCurrent) (bool, error) {
		return f.state.VerifyNativePairGroupAuthorization(ctx, p.GroupID, e, c, p.SlotA.EndpointID, p.SlotB.EndpointID, f.now)
	}
	if required, err := check(&f.evidence, &current); !required || err != nil {
		t.Fatalf("valid constructed Current: %t %v", required, err)
	}
	m := f.message(0, false)
	if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, m, f.now); existing || err != nil {
		t.Fatalf("first reservation: %t %v", existing, err)
	}
	for _, missing := range []string{"current", "evidence", "both", "different-current-sid"} {
		t.Run(missing, func(t *testing.T) {
			e, c := &f.evidence, &current
			switch missing {
			case "current":
				c = nil
			case "evidence":
				e = nil
			case "both":
				e, c = nil, nil
			case "different-current-sid":
				copy := current
				copy.Receiver.NativeSessionID = "synthetic-replaced-sid"
				c = &copy
			}
			if required, err := check(e, c); !required || err == nil {
				t.Fatalf("required policy accepted %s: %t %v", missing, required, err)
			}
		})
	}
	trust, err := f.state.GetNodeOwnerKeyTrustLocal(f.scope.Actor.OwnerID, f.owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.state.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); err != nil {
		t.Fatal(err)
	}
	if existing, err := f.state.ReserveNativePairMessage(ctx, f.evidence, m, f.now); !existing || err != nil {
		t.Fatalf("exact history was not retained: %t %v", existing, err)
	}
	if required, err := check(&f.evidence, &current); !required || err == nil {
		t.Fatal("historical reservation revived revoked independent Owner pin")
	}
	if required, err := f.state.VerifyNativePairGroupAuthorization(ctx, "synthetic-ordinary-group", nil, nil, "", "", f.now); required || err != nil {
		t.Fatal("ordinary Group was changed", err)
	}
	if _, err := f.state.VerifyNativePairGroupAuthorization(ctx, "synthetic-ordinary-group", &f.evidence, &current, p.SlotA.EndpointID, p.SlotB.EndpointID, f.now); err == nil {
		t.Fatal("peer bundle selected its own required Group")
	}
}
