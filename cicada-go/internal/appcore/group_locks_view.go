package appcore

// These are internal display models, not wire DTOs or permissions. An approved
// consumer must verify the exact Group scope before populating a relation.
const GroupProtocolLockSlots = 8

type GroupLockState string

const (
	GroupLockUnknown GroupLockState = "UNKNOWN"
	GroupLockFree    GroupLockState = "FREE"
	GroupLockHeld    GroupLockState = "HELD"
)

type GroupLockSlotView struct {
	Number     int
	Version    uint64
	State      GroupLockState
	HolderName string
	Purpose    string
}

type GroupLockBoardView struct {
	CanView    bool
	Current    bool
	Version    uint64
	ObservedAt string
	Slots      [GroupProtocolLockSlots]GroupLockSlotView
}

// ProjectGroupLockBoard preserves positions 1..8 without filling missing/stale
// observations with FREE, moving an entry to another slot, or granting an action.
// Current is supplied by Core, never inferred from a version or local clock.
func ProjectGroupLockBoard(source GroupLockBoardView) GroupLockBoardView {
	if !source.CanView {
		return GroupLockBoardView{}
	}
	result := source
	for i, slot := range source.Slots {
		row := GroupLockSlotView{Number: i + 1, State: GroupLockUnknown}
		if source.Current && slot.Number == i+1 {
			switch slot.State {
			case GroupLockFree:
				row = slot
				row.HolderName = ""
			case GroupLockHeld:
				row = slot
			}
		}
		result.Slots[i] = row
	}
	return result
}
