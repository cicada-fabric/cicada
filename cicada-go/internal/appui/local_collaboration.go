package appui

import (
	"slices"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

type LocalCollaborationSetupFlow struct {
	Visible                                     bool
	Stage                                       string
	Prepare, Activate, Refresh, Revoke, Recover bool
}

// The renderer follows authenticated core actions. Public capability
// availability and saved ACTIVE metadata never supply caller authorization.
func LocalCollaborationFlow(s appcore.Snapshot, now time.Time) LocalCollaborationSetupFlow {
	if !AccountInformationVisible(s, now) || s.Account.RootState != appcore.RootStateActive || s.Node.Binding == nil {
		return LocalCollaborationSetupFlow{}
	}
	domain := s.LocalCollaboration
	has := func(kind appcore.ActionKind) bool { return slices.Contains(s.AvailableActions, kind) }
	flow := LocalCollaborationSetupFlow{Visible: true, Refresh: has(appcore.ActionRefreshLocalCollaboration)}
	if domain.Pending {
		flow.Refresh = false
		flow.Stage, flow.Recover = "pending", has(appcore.ActionRecoverLocalCollaboration)
		return flow
	}
	if !domain.AvailabilityKnown {
		flow.Stage = "unchecked"
		return flow
	}
	if !domain.Available {
		flow.Stage = "unavailable"
		return flow
	}
	flow.Prepare = domain.Current && (domain.State == "UNCONFIGURED" || domain.State == "EXPIRED" || domain.State == "REVOKED") && has(appcore.ActionPrepareLocalCollaboration)
	if domain.State == "PREPARED" {
		if domain.ReviewID == "" {
			flow.Stage = "saved"
			return flow
		}
		end, err := time.Parse(time.RFC3339Nano, domain.ReviewExpiresAt)
		if err != nil || !now.Before(end) || !domain.Current {
			flow.Stage = "review-expired"
			return flow
		}
		flow.Stage, flow.Activate = "review", domain.ReviewID != "" && has(appcore.ActionActivateLocalCollaboration)
		return flow
	}
	switch domain.State {
	case "ACTIVE":
		if !domain.Current {
			flow.Stage = "saved"
			return flow
		}
		if domain.ExpiresAt != "" {
			if end, err := time.Parse(time.RFC3339Nano, domain.ExpiresAt); err != nil || !now.Before(end) {
				flow.Stage = "expired"
				return flow
			}
		}
		flow.Stage, flow.Revoke = "active", domain.StateReviewID != "" && has(appcore.ActionRevokeLocalCollaboration)
	case "EXPIRED":
		flow.Stage = "expired"
	case "REVOKED":
		flow.Stage = "revoked"
	case "UNCONFIGURED":
		flow.Stage = "unconfigured"
	case "":
		flow.Stage, flow.Prepare = "unchecked", false
	default:
		flow.Stage = "saved"
	}
	return flow
}

func LocalCollaborationPublicFields(s appcore.Snapshot, now time.Time) []PublicField {
	if !LocalCollaborationFlow(s, now).Visible {
		return nil
	}
	d := s.LocalCollaboration
	return presentPublicFields(PublicField{Key: "local_collaboration.policy", Value: d.PolicyID},
		PublicField{Key: "node.id", Value: d.NodeID}, PublicField{Key: "local_collaboration.os_user", Value: d.LocalUserScope},
		PublicField{Key: "local_collaboration.network_id", Value: d.NetworkID}, PublicField{Key: "local_collaboration.group_id", Value: d.GroupID})
}
