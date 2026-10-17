package appui

import (
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func TestPairSlotReviewIncludesBothIdentitiesAndCompleteTarget(t *testing.T) {
	s := appcore.PairSlotSnapshot{NativeSessionID: "synthetic-A", PeerNativeSessionID: "synthetic-B", EndpointID: "endpoint-A", PrincipalID: "principal-A", CandidateKeyID: "key-A", CandidateVersion: 4, Generation: 2, AttemptID: "attempt-A", BindingID: "binding-A", BindingEpoch: 3, NetworkBindingID: "network-binding-A", NetworkEpoch: 5, NetworkMembership: 6, EndpointNetwork: 7, MembershipRevision: 8, EndpointJoinRevision: 9, LeaseOwner: "lease-A", LeaseCeiling: "synthetic-deadline", TargetDigest: "synthetic-target-digest"}
	for _, locale := range []Locale{English, Chinese} {
		raw := strings.Join(PairSlotReviewDetails(locale, s), "\n")
		for _, part := range []string{s.PeerNativeSessionID, s.EndpointID, s.PrincipalID, s.CandidateKeyID, s.AttemptID, s.BindingID, s.NetworkBindingID, s.LeaseOwner, s.LeaseCeiling, s.TargetDigest, "4", "2", "3", "5", "6", "7", "8", "9"} {
			if !strings.Contains(raw, part) {
				t.Fatalf("%s missing reviewed target component", locale)
			}
		}
	}
}
