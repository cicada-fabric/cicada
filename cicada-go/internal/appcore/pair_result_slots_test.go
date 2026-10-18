package appcore

import (
	"bytes"
	"math"
	"strings"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestPairResultSlotsHistoricalProjectionBoundaries(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	base := f.result
	fresh := func() wire.NativePairResult {
		r := base
		a, b := *base.SlotA, *base.SlotB
		r.SlotA, r.SlotB = &a, &b
		return r
	}
	for _, state := range []wire.NativePairState{wire.NativePairWaitingJoin, wire.NativePairWaitingConsent, wire.NativePairRevoked, wire.NativePairExpired} {
		t.Run(string(state), func(t *testing.T) {
			r := fresh()
			r.State, r.AdministrativePermission = state, false
			r.SlotAState, r.SlotBState = wire.NativePairSlotJoinedZero, wire.NativePairSlotJoinedZero
			clearPairActorCandidate(r.SlotA)
			clearPairActorCandidate(r.SlotB)
			if state == wire.NativePairRevoked || state == wire.NativePairExpired {
				r.SlotAState = wire.NativePairSlotActive
				r.SlotA.MembershipRevision++
				r.SlotA.NetworkMembershipRevision++
			}
			if err := validatePairResultSlots(r, f.bootstrap.Scope); err != nil {
				t.Fatal("legal original tuple without current candidate rejected", err)
			}
		})
	}
	bad := map[string]func(*wire.NativePairResult){
		"active":   func(r *wire.NativePairResult) { r.State = wire.NativePairActive },
		"prepared": func(r *wire.NativePairResult) { r.State = wire.NativePairPrepared },
		"candidate-ready": func(r *wire.NativePairResult) {
			r.State, r.SlotAState = wire.NativePairWaitingConsent, wire.NativePairSlotCandidateReady
		},
		"consent-recorded": func(r *wire.NativePairResult) {
			r.State, r.SlotAState = wire.NativePairWaitingConsent, wire.NativePairSlotConsentRecorded
		},
		"waiting-active": func(r *wire.NativePairResult) {
			r.State, r.SlotAState = wire.NativePairWaitingJoin, wire.NativePairSlotActive
		},
		"terminal-authority":       func(r *wire.NativePairResult) { r.AdministrativePermission = true },
		"terminal-candidate-ready": func(r *wire.NativePairResult) { r.SlotAState = wire.NativePairSlotCandidateReady },
		"missing-occupied-slot":    func(r *wire.NativePairResult) { r.SlotA = nil },
		"slot-position":            func(r *wire.NativePairResult) { r.SlotA.Slot = "B" },
		"generation-zero":          func(r *wire.NativePairResult) { r.SlotA.Generation = 0 },
		"generation-limit":         func(r *wire.NativePairResult) { r.SlotA.Generation = wire.MaxNativePairSlotGenerations + 1 },
		"attempt":                  func(r *wire.NativePairResult) { r.SlotA.AttemptID = strings.Repeat("A", 32) },
		"runtime":                  func(r *wire.NativePairResult) { r.SlotA.Runtime = "other" },
		"node":                     func(r *wire.NativePairResult) { r.SlotA.NodeID = "other-node" },
		"sid":                      func(r *wire.NativePairResult) { r.SlotA.NativeSessionID = "bad/sid" },
		"endpoint":                 func(r *wire.NativePairResult) { r.SlotA.EndpointID = "" },
		"principal":                func(r *wire.NativePairResult) { r.SlotA.PrincipalID = strings.Repeat("a", 129) },
		"network-binding":          func(r *wire.NativePairResult) { r.SlotA.NetworkAccessBindingID = "." },
		"group-binding":            func(r *wire.NativePairResult) { r.SlotA.BindingID = ".." },
		"lease-owner":              func(r *wire.NativePairResult) { r.SlotA.LeaseOwner = "owner\n" },
		"network-epoch":            func(r *wire.NativePairResult) { r.SlotA.NetworkAccessEpoch = 0 },
		"network-revision":         func(r *wire.NativePairResult) { r.SlotA.NetworkMembershipRevision = math.MaxInt64 },
		"endpoint-network":         func(r *wire.NativePairResult) { r.SlotA.EndpointNetworkRevision = 0 },
		"binding-epoch":            func(r *wire.NativePairResult) { r.SlotA.BindingEpoch = math.MaxUint64 },
		"membership":               func(r *wire.NativePairResult) { r.SlotA.MembershipRevision = 0 },
		"endpoint-join":            func(r *wire.NativePairResult) { r.SlotA.EndpointJoinRevision = 0 },
		"lease-ceiling":            func(r *wire.NativePairResult) { r.SlotA.LeaseCeiling = f.n.stamp(f.n.n2.now) },
		"mixed-version":            func(r *wire.NativePairResult) { r.SlotA.CandidateVersion = 1 },
		"mixed-public-id":          func(r *wire.NativePairResult) { r.SlotA.CandidatePublic.ID = base.SlotA.CandidatePublic.ID },
		"mixed-public-kem":         func(r *wire.NativePairResult) { r.SlotA.CandidatePublic.KEMPublic = []byte{1} },
		"mixed-public-signing":     func(r *wire.NativePairResult) { r.SlotA.CandidatePublic.SigningPublic = []byte{1} },
		"mixed-fingerprint":        func(r *wire.NativePairResult) { r.SlotA.CandidateFingerprint = base.SlotA.CandidateFingerprint },
		"mixed-proof":              func(r *wire.NativePairResult) { r.SlotA.CandidateProofDigest = base.SlotA.CandidateProofDigest },
		"mixed-attestation":        func(r *wire.NativePairResult) { r.SlotA.CandidateAttestation = base.SlotA.CandidateAttestation },
		"bad-complete-candidate": func(r *wire.NativePairResult) {
			a := *base.SlotA
			r.SlotA = &a
			r.SlotA.CandidateAttestation = []byte{1}
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := fresh()
			r.State, r.AdministrativePermission = wire.NativePairRevoked, false
			r.SlotAState, r.SlotBState = wire.NativePairSlotJoinedZero, wire.NativePairSlotJoinedZero
			clearPairActorCandidate(r.SlotA)
			clearPairActorCandidate(r.SlotB)
			mutate(&r)
			if validatePairResultSlots(r, f.bootstrap.Scope) == nil {
				t.Fatal("invalid historical projection accepted")
			}
		})
	}
}

func TestPairControllerLostRevokeRecoversOriginalHistoricalTuple(t *testing.T) {
	f := newPairActorFixture(t)
	f.prepareSlots()
	for _, slot := range []string{"A", "B"} {
		if err := f.approve(slot); err != nil {
			t.Fatal(err)
		}
	}
	before := f.c.Snapshot()
	owner, device := f.c.owner.Public().ID, f.c.device.Public().ID
	f.drop = wire.OperationNativePairRevoke
	if f.dispatch(Action{Kind: ActionRevokePair, Pair: PairAction{PairID: before.Pair.PairID, ReviewID: before.Pair.StateReviewID, ConfirmRevoke: true}}) == nil || !f.c.hasPairPending() {
		t.Fatal("lost revoke receipt was reported as a settled operation")
	}
	original := bytes.Clone(f.c.pairOriginal.Packet)
	defer clear(original)
	f.deny = wire.OperationNativePairRevoke
	if err := f.dispatch(Action{Kind: ActionRecoverPair}); err != nil {
		t.Fatal(err)
	}
	requests := f.posts[wire.OperationNativePairRevoke]
	s := f.c.Snapshot()
	if len(requests) != 2 || !bytes.Equal(requests[0], original) || !bytes.Equal(requests[1], original) ||
		len(f.posts[wire.OperationNativePairReconcile]) != 1 || f.c.hasPairPending() || s.Pair.State != "REVOKED" ||
		s.Pair.ControlRevision != before.Pair.ControlRevision+1 || s.Pair.Current || s.Pair.AdministrativePermission {
		t.Fatal("revoke recovery replaced its original, trusted unsigned HTTP, or restored authority")
	}
	for i, slot := range s.Pair.Slots {
		prior := before.Pair.Slots[i]
		if slot.NativeSessionID != prior.NativeSessionID || slot.AttemptID != prior.AttemptID || slot.Generation != prior.Generation ||
			slot.BindingID != prior.BindingID || slot.BindingEpoch != prior.BindingEpoch || slot.NetworkBindingID != prior.NetworkBindingID ||
			slot.NetworkEpoch != prior.NetworkEpoch || slot.EndpointID != prior.EndpointID || slot.PrincipalID != prior.PrincipalID ||
			slot.LeaseOwner != prior.LeaseOwner || slot.LeaseCeiling != prior.LeaseCeiling || slot.MembershipRevision != prior.MembershipRevision+1 ||
			slot.NetworkMembership != prior.NetworkMembership+1 || slot.CandidateKeyID != "" || slot.CandidateVersion != 0 {
			t.Fatal("terminal projection changed the original tuple or invented a current candidate")
		}
	}
	f.n.reopen(t)
	f.c = f.n.c
	if f.c.hasPairPending() || f.c.Snapshot().Pair.State != "REVOKED" || f.c.Snapshot().Pair.AdministrativePermission ||
		f.c.owner.Public().ID != owner || f.c.device.Public().ID != device {
		t.Fatal("restart lost the settled revoke, replaced keys, or restored authority")
	}
}
