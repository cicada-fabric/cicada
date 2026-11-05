package appcore

// Native gestures carry only a choice and a Core-generated exact-scope token.
// Owner/Thread identities, expected versions and proofs come from Core state.
type CoordinationAction struct {
	GestureID      string
	EndpointID     string
	GroupID        string
	Cursor         string
	Classification string
	Change         string
	Name           string
	Slot           int
	Confirm        bool
}

const (
	ActionReadThreadCoordination ActionKind = "READ_THREAD_CLASSIFICATION"
	ActionReadGroupCoordination  ActionKind = "READ_GROUP_COORDINATION"
	ActionPrepareCoordination    ActionKind = "PREPARE_OWNER_COORDINATION"
	ActionApplyCoordination      ActionKind = "APPLY_EXACT_OWNER_COORDINATION"
	ActionDismissCoordination    ActionKind = "DISMISS_OWNER_COORDINATION_REVIEW"
	ActionRecoverCoordination    ActionKind = "RECOVER_ORIGINAL_OWNER_COORDINATION"
)

type ThreadClassificationView struct {
	FreshUntil     string
	Current        bool
	State          string
	Classification string
	ActiveGroups   uint64
	CanChange      bool
	GestureID      string
}

type CoordinationReview struct {
	GestureID      string
	Change         string
	ThreadName     string
	GroupName      string
	HolderName     string
	Classification string
	Slot           int
	ExpiresAt      string
	CanApply       bool
	Details        []CoordinationDetail
}

type CoordinationDetail struct{ Key, Value string }

type CoordinationSnapshot struct {
	AvailabilityKnown bool
	RolesAvailable    bool
	LocksAvailable    bool
	Pending           bool
	ErrorCode         string
	Outcome           string
	Review            *CoordinationReview
	FreshUntil        string
}

func coordinationActionKind(kind ActionKind) bool {
	switch kind {
	case ActionReadThreadCoordination, ActionReadGroupCoordination, ActionPrepareCoordination, ActionApplyCoordination, ActionDismissCoordination, ActionRecoverCoordination:
		return true
	}
	return false
}
