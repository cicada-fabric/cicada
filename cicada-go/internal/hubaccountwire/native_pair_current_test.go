package hubaccountwire

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// These values are an independent synthetic observation for validator tests.
// Production must read every current coordinate from its live transaction.
func nativePairTestCurrentSlot(s NativePairSlot) NativePairCurrentSlot {
	return NativePairCurrentSlot{Slot: s.Slot, Generation: s.Generation, AttemptID: s.AttemptID,
		NativeSessionID: s.NativeSessionID, NetworkAccessBindingID: s.NetworkAccessBindingID,
		NetworkAccessEpoch: s.NetworkAccessEpoch, NetworkMembershipRevision: s.NetworkMembershipRevision,
		EndpointNetworkRevision: s.EndpointNetworkRevision, LeaseOwner: s.LeaseOwner, LeaseCeiling: s.LeaseCeiling}
}

// Exported only in the test build so an external test can measure the actual
// Store DTOs with this same maximum real-PQ fixture, without a production API.
func NativePairCarrierFixtureForTest(t *testing.T, maximum bool) (HubIdentity, e2ee.PublicIdentity, NativePairPeerEvidence, NativePairPeerCurrent, time.Time) {
	t.Helper()
	f := nativePairSizedFixture(t, maximum)
	c := NativePairPeerCurrent{State: "CURRENT", ControlRevision: f.plan.ExpectedRevision,
		ObservedAt: formatUTC(f.f.now), Sender: nativePairTestCurrentSlot(f.plan.SlotA), Receiver: nativePairTestCurrentSlot(f.plan.SlotB)}
	return f.f.hub, f.f.owner.Public(), f.evidence, c, f.f.now
}

func TestNativePairPeerCurrentIndependentCoordinatesAndDirection(t *testing.T) {
	hub, owner, evidence, current, now := NativePairCarrierFixtureForTest(t, false)
	verify := func(c NativePairPeerCurrent, sender, receiver string) error {
		return VerifyNativePairPeerAuthorization(true, &evidence, &c, hub, owner, evidence.Plan.Scope.NodeTupleDigest, sender, receiver, now)
	}
	a, b := evidence.Plan.SlotA.EndpointID, evidence.Plan.SlotB.EndpointID
	if err := verify(current, a, b); err != nil {
		t.Fatal(err)
	}
	reverse := current
	reverse.Sender, reverse.Receiver = reverse.Receiver, reverse.Sender
	if err := verify(reverse, b, a); err != nil {
		t.Fatal(err)
	}
	if verify(current, b, a) == nil {
		t.Fatal("reversed endpoints accepted without reversed actual slots")
	}
	mutations := map[string]func(*NativePairPeerCurrent){
		"state":              func(c *NativePairPeerCurrent) { c.State = "ACTIVE" },
		"revision":           func(c *NativePairPeerCurrent) { c.ControlRevision-- },
		"slot":               func(c *NativePairPeerCurrent) { c.Sender.Slot = "B" },
		"generation":         func(c *NativePairPeerCurrent) { c.Sender.Generation++ },
		"attempt":            func(c *NativePairPeerCurrent) { c.Sender.AttemptID = strings.Repeat("f", 32) },
		"native":             func(c *NativePairPeerCurrent) { c.Receiver.NativeSessionID += "-other" },
		"network_binding":    func(c *NativePairPeerCurrent) { c.Sender.NetworkAccessBindingID += "-other" },
		"network_epoch":      func(c *NativePairPeerCurrent) { c.Sender.NetworkAccessEpoch++ },
		"network_member":     func(c *NativePairPeerCurrent) { c.Sender.NetworkMembershipRevision++ },
		"network_endpoint":   func(c *NativePairPeerCurrent) { c.Sender.EndpointNetworkRevision++ },
		"lease_owner":        func(c *NativePairPeerCurrent) { c.Sender.LeaseOwner += "-other" },
		"ceiling":            func(c *NativePairPeerCurrent) { c.Sender.LeaseCeiling = formatUTC(now.Add(2 * time.Hour)) },
		"future_observation": func(c *NativePairPeerCurrent) { c.ObservedAt = formatUTC(now.Add(time.Hour)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := current
			mutate(&changed)
			if verify(changed, a, b) == nil {
				t.Fatal("independent current coordinate drift was accepted")
			}
		})
	}
}

func TestNativePairPeerCurrentMandatoryAndStrict(t *testing.T) {
	hub, owner, evidence, current, now := NativePairCarrierFixtureForTest(t, false)
	verify := func(required bool, e *NativePairPeerEvidence, c *NativePairPeerCurrent) error {
		return VerifyNativePairPeerAuthorization(required, e, c, hub, owner, evidence.Plan.Scope.NodeTupleDigest,
			evidence.Plan.SlotA.EndpointID, evidence.Plan.SlotB.EndpointID, now)
	}
	if verify(false, nil, nil) != nil || verify(true, nil, nil) == nil ||
		verify(true, &evidence, nil) == nil || verify(true, nil, &current) == nil ||
		verify(false, &evidence, &current) == nil {
		t.Fatal("required evidence/current was downgraded or leaked onto legacy carrier")
	}
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeNativePairPeerCurrent(raw); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unexpected":true}`)...)
	if _, err = DecodeNativePairPeerCurrent(unknown); err == nil {
		t.Fatal("unknown current field accepted")
	}
	if _, err = DecodeNativePairPeerCurrent(append(raw, []byte(strings.Repeat(" ", MaxNativePairPeerCurrentBytes))...)); err == nil {
		t.Fatal("oversized current body accepted")
	}
}
