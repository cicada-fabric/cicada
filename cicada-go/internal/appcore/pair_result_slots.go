package appcore

import (
	"encoding/hex"
	"math"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// A status or completed revoke may retain the original occupied tuple after
// its candidate manifest stops being current. That historical projection is
// not a candidate, consent plan or peer authorization.
func validatePairResultSlots(result wire.NativePairResult, scope e2ee.OwnerNativePairScope) error {
	terminal := result.State == wire.NativePairRevoked || result.State == wire.NativePairExpired
	if terminal && result.AdministrativePermission {
		return wire.ErrInvalid
	}
	states := [2]wire.NativePairSlotState{result.SlotAState, result.SlotBState}
	for i, slot := range [2]*wire.NativePairSlot{result.SlotA, result.SlotB} {
		if slot == nil {
			if states[i] != wire.NativePairSlotReserved {
				return wire.ErrInvalid
			}
			continue
		}
		s := *slot
		attempt, err := hex.DecodeString(s.AttemptID)
		if s.Slot != string(rune('A'+i)) || s.Generation == 0 || s.Generation > wire.MaxNativePairSlotGenerations ||
			err != nil || len(attempt) != wire.RequestIDBytes || hex.EncodeToString(attempt) != s.AttemptID ||
			s.Runtime != "codex" || s.NodeID != scope.Node.NodeID || s.LeaseCeiling != result.PeerExpiresAt {
			return wire.ErrInvalid
		}
		for _, token := range []string{s.NativeSessionID, s.EndpointID, s.PrincipalID, s.NetworkAccessBindingID, s.BindingID, s.LeaseOwner} {
			if !pairResultToken(token) {
				return wire.ErrInvalid
			}
		}
		for _, n := range []uint64{s.NetworkAccessEpoch, s.NetworkMembershipRevision, s.EndpointNetworkRevision, s.BindingEpoch, s.MembershipRevision, s.EndpointJoinRevision} {
			if n == 0 || n >= math.MaxInt64 {
				return wire.ErrInvalid
			}
		}
		candidateAbsent := s.CandidateVersion == 0 && s.CandidatePublic.ID == "" && len(s.CandidatePublic.KEMPublic) == 0 &&
			len(s.CandidatePublic.SigningPublic) == 0 && s.CandidateFingerprint == "" && s.CandidateProofDigest == "" && len(s.CandidateAttestation) == 0
		if !candidateAbsent {
			if wire.ValidateNativePairSlot(s, scope, result.PeerExpiresAt) != nil {
				return wire.ErrInvalid
			}
			continue
		}
		if !((terminal && (states[i] == wire.NativePairSlotJoinedZero || states[i] == wire.NativePairSlotActive)) ||
			((result.State == wire.NativePairWaitingJoin || result.State == wire.NativePairWaitingConsent) && states[i] == wire.NativePairSlotJoinedZero)) {
			return wire.ErrInvalid
		}
	}
	return nil
}

func pairResultToken(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':')
	}) == -1
}
