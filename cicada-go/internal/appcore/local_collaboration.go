package appcore

import (
	"slices"
	"time"
)

// LocalCollaborationSnapshot is display metadata, not a delegation or a peer
// credential. Policy lifetime is independent of account and App read leases.
type LocalCollaborationSnapshot struct {
	AvailabilityKnown bool   `json:"availability_known"`
	Available         bool   `json:"available"`
	Pending           bool   `json:"pending"`
	Current           bool   `json:"current"`
	State             string `json:"state,omitempty"`
	PolicyID          string `json:"policy_id,omitempty"`
	PolicyEpoch       uint64 `json:"policy_epoch,omitempty"`
	Revision          uint64 `json:"revision,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
	NodeName          string `json:"node_name,omitempty"`
	LocalUserScope    string `json:"local_user_scope,omitempty"`
	NetworkID         string `json:"network_id,omitempty"`
	NetworkName       string `json:"network_name,omitempty"`
	GroupID           string `json:"group_id,omitempty"`
	GroupName         string `json:"group_name,omitempty"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	ReviewID          string `json:"review_id,omitempty"`
	ReviewExpiresAt   string `json:"review_expires_at,omitempty"`
	StateReviewID     string `json:"state_review_id,omitempty"`
	ObservedAt        string `json:"observed_at,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
}

const (
	ActionPrepareLocalCollaboration  ActionKind = "PREPARE_LOCAL_COLLABORATION"
	ActionActivateLocalCollaboration ActionKind = "ACTIVATE_LOCAL_COLLABORATION"
	ActionRefreshLocalCollaboration  ActionKind = "REFRESH_LOCAL_COLLABORATION"
	ActionRevokeLocalCollaboration   ActionKind = "REVOKE_LOCAL_COLLABORATION"
	ActionRecoverLocalCollaboration  ActionKind = "RECOVER_LOCAL_COLLABORATION"
)

// LocalCollaborationAction records an explicit UI choice. The target OS user
// comes from the Node's signed report in the server preview, never App input.
// Zero ExpiresInHours selects until revoke. Request construction later fixes an
// absolute expiry once; retries must use the retained original packet.
type LocalCollaborationAction struct {
	NetworkID         string
	NewNetworkName    string
	GroupName         string
	ExpiresInHours    uint64
	ReviewID          string
	ConfirmActivation bool
	ConfirmRevoke     bool
}

func localCollaborationActionKind(kind ActionKind) bool {
	switch kind {
	case ActionPrepareLocalCollaboration, ActionActivateLocalCollaboration, ActionRefreshLocalCollaboration, ActionRevokeLocalCollaboration, ActionRecoverLocalCollaboration:
		return true
	}
	return false
}

func expireLocalCollaborationView(view *Snapshot, now time.Time) {
	domain := &view.LocalCollaboration
	accountLive := view.Hub.Verified && view.Account.RootState == RootStateActive &&
		(view.Account.State == AccountStateOwnerReady || view.Account.State == AccountStateSessionActive || view.Account.State == AccountStateOwnerProof) &&
		now.Before(parseExpiry(view.Account.SessionExpiresAt))
	if !accountLive || domain.Pending {
		domain.Current = false
	}
	if end := parseExpiry(domain.ExpiresAt); !end.IsZero() && !now.Before(end) && domain.State == "ACTIVE" {
		domain.State, domain.Current = "EXPIRED", false
	}
	view.AvailableActions = slices.DeleteFunc(view.AvailableActions, func(kind ActionKind) bool {
		if !localCollaborationActionKind(kind) {
			return false
		}
		if kind == ActionRecoverLocalCollaboration {
			return !domain.Pending
		}
		if domain.Pending || !accountLive {
			return true
		}
		if kind == ActionRefreshLocalCollaboration {
			return false
		}
		if !domain.Available {
			return true
		}
		switch kind {
		case ActionPrepareLocalCollaboration:
			return !domain.Current || (domain.State != "UNCONFIGURED" && domain.State != "EXPIRED" && domain.State != "REVOKED")
		case ActionActivateLocalCollaboration:
			return !domain.Current || domain.ReviewID == "" || !now.Before(parseExpiry(domain.ReviewExpiresAt))
		case ActionRevokeLocalCollaboration:
			return !domain.Current || domain.State != "ACTIVE" || domain.StateReviewID == ""
		}
		return false
	})
}
