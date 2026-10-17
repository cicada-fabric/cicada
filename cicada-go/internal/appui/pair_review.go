package appui

import (
	"fmt"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// The technical details are limited to the exact target the Owner is approving.
// No proof, public-key blob, peer message or private material reaches the view.
func PairSlotReviewDetails(locale Locale, s appcore.PairSlotSnapshot) []string {
	if s.NativeSessionID == "" {
		return nil
	}
	labels := []string{"Peer session", "Endpoint / principal", "Candidate key ID / version", "Generation / join attempt", "Group binding / epoch", "Network binding / epoch", "Network membership / endpoint revision", "Group membership / join revision", "Lease owner / deadline", "Full target digest"}
	if locale == Chinese {
		labels = []string{"对端会话", "端点 / 主体", "候选密钥 ID / 版本", "席位代次 / 加入尝试", "Group 绑定 / 代次", "Network 绑定 / 代次", "Network 成员 / 端点版本", "Group 成员 / 加入版本", "租约归属 / 截止", "完整目标摘要"}
	}
	return []string{
		labels[0] + ": " + s.PeerNativeSessionID,
		labels[1] + ": " + s.EndpointID + " / " + s.PrincipalID,
		fmt.Sprintf("%s: %s / %d", labels[2], s.CandidateKeyID, s.CandidateVersion),
		fmt.Sprintf("%s: %d / %s", labels[3], s.Generation, s.AttemptID),
		fmt.Sprintf("%s: %s / %d", labels[4], s.BindingID, s.BindingEpoch),
		fmt.Sprintf("%s: %s / %d", labels[5], s.NetworkBindingID, s.NetworkEpoch),
		fmt.Sprintf("%s: %d / %d", labels[6], s.NetworkMembership, s.EndpointNetwork),
		fmt.Sprintf("%s: %d / %d", labels[7], s.MembershipRevision, s.EndpointJoinRevision),
		labels[8] + ": " + s.LeaseOwner + " / " + s.LeaseCeiling,
		labels[9] + ": " + s.TargetDigest,
	}
}
