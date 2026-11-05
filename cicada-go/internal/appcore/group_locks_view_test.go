package appcore

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func syntheticGroupLockBoard() GroupLockBoardView {
	b := GroupLockBoardView{CanView: true, Current: true, Version: 9, ObservedAt: "2026-11-05T00:00:00Z"}
	for i := range b.Slots {
		b.Slots[i] = GroupLockSlotView{Number: i + 1, State: GroupLockFree, Version: uint64(i + 1)}
	}
	b.Slots[0].State, b.Slots[0].HolderName, b.Slots[0].Purpose = GroupLockHeld, "SYNTHETIC holder", "SYNTHETIC optional purpose"
	b.Slots[0].ExpiresAt = "2026-11-05T00:05:00Z"
	return b
}

func TestGroupLockProjectionNeverTurnsMissingOrStaleIntoFree(t *testing.T) {
	for _, mode := range []string{"missing", "stale", "invalid-state", "wrong-position"} {
		t.Run(mode, func(t *testing.T) {
			b := syntheticGroupLockBoard()
			switch mode {
			case "missing":
				b.Slots = [GroupProtocolLockSlots]GroupLockSlotView{}
			case "stale":
				b.Current = false
			case "invalid-state":
				for i := range b.Slots {
					b.Slots[i].State = GroupLockState("SYNTHETIC-not-a-state")
				}
			case "wrong-position":
				for i := range b.Slots {
					b.Slots[i].Number = GroupProtocolLockSlots - i
				}
			}
			projected := ProjectGroupLockBoard(b)
			for i, slot := range projected.Slots {
				if slot.Number != i+1 || slot.State != GroupLockUnknown || slot.HolderName != "" || slot.Purpose != "" || slot.ExpiresAt != "" {
					t.Fatal("missing/stale data became available or moved to another slot")
				}
			}
		})
	}
	b := syntheticGroupLockBoard()
	b.Slots[1].HolderName = "SYNTHETIC stale holder"
	b.Slots[1].Purpose, b.Slots[1].ExpiresAt = "SYNTHETIC stale note", "2026-11-05T00:05:00Z"
	projected := ProjectGroupLockBoard(b)
	if projected.Slots[0] != b.Slots[0] || projected.Slots[1].State != GroupLockFree || projected.Slots[1].HolderName != "" || projected.Slots[1].Purpose != "" || projected.Slots[1].ExpiresAt != "" {
		t.Fatal("projection changed confirmed holding or attached a holder to FREE")
	}
}

func TestGroupLockSnapshotClonesAndRedactsItsDisplayPermission(t *testing.T) {
	b := syntheticGroupLockBoard()
	source := ThreadGroupsSnapshot{Current: true, Selected: &GroupThreadView{Relations: []ThreadGroupRelation{{GroupID: "SYNTHETIC-group", Locks: &b}}}}
	source.Threads = []GroupThreadView{*source.Selected}
	copy := cloneThreadGroups(source)
	copy.Selected.Relations[0].Locks.Slots[0].HolderName = "SYNTHETIC mutated copy"
	copy.Threads[0].Relations[0].Locks.Slots[0].Purpose = "SYNTHETIC mutated copy"
	if source.Selected.Relations[0].Locks.Slots[0].HolderName != "SYNTHETIC holder" || source.Threads[0].Relations[0].Locks.Slots[0].Purpose != "SYNTHETIC optional purpose" {
		t.Fatal("snapshot aliases its lock rows")
	}
	source.Current = false
	stale := cloneThreadGroups(source)
	if stale.Selected.Relations[0].Locks.Current || stale.Selected.Relations[0].Locks.Slots[0].State != GroupLockUnknown || source.Selected.Relations[0].Locks.Slots[0].State != GroupLockHeld {
		t.Fatal("stale parent retained current lock state or modified its source")
	}
	b.CanView = false
	redacted := cloneThreadGroups(source)
	raw, _ := json.Marshal(redacted)
	if redacted.Selected.Relations[0].Locks != nil || strings.Contains(string(raw), "SYNTHETIC holder") || strings.Contains(string(raw), "SYNTHETIC optional purpose") {
		t.Fatal("unreadable lock data escaped in a display snapshot")
	}
	if projected := ProjectGroupLockBoard(b); projected != (GroupLockBoardView{}) {
		t.Fatal("CanView=false retained slot metadata")
	}
}

func TestGroupLockBoardCannotOutliveParentAuthority(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"fresh", "expired-read", "pending", "expired-login", "expired-hold"} {
		t.Run(mode, func(t *testing.T) {
			b := syntheticGroupLockBoard()
			s := Snapshot{
				Hub: HubSnapshot{Verified: true, HubID: "SYNTHETIC-hub", Origin: "https://SYNTHETIC.invalid", Fingerprint: "SYNTHETIC-pin"},
				Account: AccountSnapshot{State: AccountStateOwnerReady, RootState: RootStateActive, LocalOwnerKeyPresent: true,
					AccountID: "SYNTHETIC-account", OwnerID: "SYNTHETIC-owner", DeviceID: "SYNTHETIC-app", SessionExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)},
				Node: NodeSetupSnapshot{Binding: &NodeBindingSnapshot{NodeID: "SYNTHETIC-node"}},
				ThreadGroups: ThreadGroupsSnapshot{Current: true, FreshUntil: now.Add(time.Minute).Format(time.RFC3339Nano),
					Selected: &GroupThreadView{Relations: []ThreadGroupRelation{{Locks: &b}}}},
			}
			switch mode {
			case "expired-read":
				s.ThreadGroups.FreshUntil = now.Format(time.RFC3339Nano)
			case "pending":
				s.ThreadGroups.Pending = true
			case "expired-login":
				s.Account.SessionExpiresAt = now.Format(time.RFC3339Nano)
			case "expired-hold":
				b.Slots[0].ExpiresAt = now.Format(time.RFC3339Nano)
			}
			expireThreadGroupsView(&s, now)
			if mode == "expired-login" {
				if s.ThreadGroups.Selected != nil {
					t.Fatal("expired login retained private lock board")
				}
				return
			}
			board := s.ThreadGroups.Selected.Relations[0].Locks
			if mode == "fresh" {
				if !board.Current || board.Slots[0].State != GroupLockHeld {
					t.Fatal("fresh parent lost its scoped observation")
				}
				return
			}
			if (mode != "expired-hold" && board.Current) || board.Slots[0].State != GroupLockUnknown || board.Slots[0].HolderName != "" || board.Slots[0].Purpose != "" || board.Slots[0].ExpiresAt != "" {
				t.Fatal("pending/expired parent retained current lock metadata")
			}
		})
	}
}
