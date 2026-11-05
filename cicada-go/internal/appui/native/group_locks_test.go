package native

import (
	"fmt"
	"image"
	"strings"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func groupLockLayoutSnapshot() appcore.Snapshot {
	s := layoutSnapshot()
	s.Account.State, s.Account.RootState, s.Account.LocalOwnerKeyPresent = appcore.AccountStateOwnerReady, appcore.RootStateActive, true
	s.Node.Pairing = nil
	s.Node.Binding = &appcore.NodeBindingSnapshot{NodeID: "SYNTHETIC-lock-node", Name: "SYNTHETIC computer"}
	b := &appcore.GroupLockBoardView{CanView: true, Current: true, Version: 7, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	for i := range b.Slots {
		b.Slots[i] = appcore.GroupLockSlotView{Number: i + 1, Version: uint64(i), State: appcore.GroupLockFree}
		if i%2 == 0 {
			b.Slots[i].State = appcore.GroupLockHeld
			b.Slots[i].HolderName = "SYNTHETIC holder"
			b.Slots[i].Purpose = "SYNTHETIC optional protocol note"
		}
	}
	thread := appcore.GroupThreadView{EndpointID: "SYNTHETIC-endpoint", Name: "SYNTHETIC Thread", RelationsComplete: true, Relations: []appcore.ThreadGroupRelation{{GroupID: "SYNTHETIC-group", Name: "SYNTHETIC Group", State: "ACTIVE", Locks: b}}}
	s.ThreadGroups = appcore.ThreadGroupsSnapshot{AvailabilityKnown: true, Available: true, Current: true, NodeID: s.Node.Binding.NodeID, NodeName: s.Node.Binding.Name, NetworkID: "SYNTHETIC-network", NetworkName: "SYNTHETIC Network", Selected: &thread}
	s.AvailableActions = nil
	return s
}

func semanticLabel(nodes []input.SemanticNode, label string) (input.SemanticDesc, bool) {
	for _, n := range nodes {
		if n.Desc.Label == label {
			return n.Desc, true
		}
	}
	return input.SemanticDesc{}, false
}

// Drive the production outer scroll list with actual Gio wheel events. Label
// semantic bounds may include a whole text layout area, so its start plus one
// line, rather than that unbounded area, locates a visible text row.
func scrollLockLabel(t *testing.T, v *view, r *input.Router, size image.Point, scale float32, label string, button bool) []input.SemanticNode {
	t.Helper()
	var lastBounds image.Rectangle
	for i := 0; i < 50; i++ {
		nodes := layoutFrame(v, r, size, scale)
		var desc input.SemanticDesc
		var ok bool
		if button {
			desc, ok = findSemantic(nodes, label)
		} else {
			desc, ok = semanticLabel(nodes, label)
		}
		if !ok {
			t.Fatal("production lock entry/row was not laid out")
		}
		lastBounds = desc.Bounds
		bottom := desc.Bounds.Max.Y
		if !button {
			bottom = desc.Bounds.Min.Y + int(22*scale)
		}
		top := int(70 * scale)
		if desc.Bounds.Min.Y >= top && bottom < size.Y-int(8*scale) {
			return nodes
		}
		delta := float32(60) * scale
		if desc.Bounds.Min.Y < top {
			delta = -delta
		}
		r.Queue(pointer.Event{Kind: pointer.Scroll, Source: pointer.Mouse, Position: f32.Pt(float32(size.X/2), float32(size.Y/2)), Scroll: f32.Pt(0, delta)})
	}
	t.Fatalf("lock entry/row could not be reached by scrolling: bounds=%v list=%+v", lastBounds, v.contentList.Position)
	return nil
}

func TestGroupLockBoardEightRowsAreReadOnlyAndScrollable(t *testing.T) {
	for _, locale := range []appui.Locale{appui.English, appui.Chinese} {
		for _, pixels := range []image.Point{image.Pt(1100, 1200), image.Pt(640, 480)} {
			t.Run(fmt.Sprintf("%s-%d", locale, pixels.X), func(t *testing.T) {
				scale := float32(1)
				if pixels.X == 640 {
					scale = 2
				}
				v, r := newLayoutView(t, groupLockLayoutSnapshot())
				v.locale = locale
				layoutFrame(v, r, pixels, scale)
				v.workspacePage = "sessions"
				nodes := scrollLockLabel(t, v, r, pixels, scale, appui.Text(locale, "locks.show"), true)
				entry, _ := findSemantic(nodes, appui.Text(locale, "locks.show"))
				queueVisualClick(r, entry.Bounds)
				nodes = layoutFrame(v, r, pixels, scale)
				for i := 1; i <= appcore.GroupProtocolLockSlots; i++ {
					state := "locks.free"
					if i%2 == 1 {
						state = "locks.held"
					}
					label := fmt.Sprintf("%s %d · %s", appui.Text(locale, "locks.slot"), i, appui.Text(locale, state))
					if _, ok := semanticLabel(nodes, label); !ok {
						t.Fatalf("slot %d missing from actual production board", i)
					}
				}
				last := fmt.Sprintf("%s 8 · %s", appui.Text(locale, "locks.slot"), appui.Text(locale, "locks.free"))
				scrollLockLabel(t, v, r, pixels, scale, last, false)
				select {
				case <-v.controller.(*layoutController).actions:
					t.Fatal("viewing/scrolling lock state dispatched an operation")
				default:
				}
			})
		}
	}
}

func TestGroupLockBoardUnknownAndHiddenCannotReportFree(t *testing.T) {
	for _, mode := range []string{"stale", "unreadable", "logged-out"} {
		t.Run(mode, func(t *testing.T) {
			s := groupLockLayoutSnapshot()
			b := s.ThreadGroups.Selected.Relations[0].Locks
			for i := range b.Slots {
				b.Slots[i].HolderName = "SYNTHETIC-PRIVATE-HOLDER"
				b.Slots[i].Purpose = "SYNTHETIC-PRIVATE-PURPOSE"
			}
			if mode == "stale" {
				b.Current = false
			}
			if mode == "unreadable" {
				b.CanView = false
			}
			if mode == "logged-out" {
				s.Account.State = appcore.AccountStateLoginRequired
				s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin}
			}
			v, r := newLayoutView(t, s)
			size := image.Pt(1100, 1200)
			layoutFrame(v, r, size, 1)
			v.workspacePage = "sessions"
			nodes := layoutFrame(v, r, size, 1)
			if mode == "stale" {
				entry, ok := findSemantic(nodes, appui.Text(v.locale, "locks.show"))
				if !ok {
					t.Fatal("stale board lost its read-only entry")
				}
				queueVisualClick(r, entry.Bounds)
				nodes = layoutFrame(v, r, size, 1)
				for i := 1; i <= 8; i++ {
					if _, ok := semanticLabel(nodes, fmt.Sprintf("Slot %d · Unknown", i)); !ok {
						t.Fatal("stale board did not retain eight unknown positions")
					}
				}
			} else if _, ok := findSemantic(nodes, appui.Text(v.locale, "locks.show")); ok {
				t.Fatal("unreadable or pre-login board was exposed")
			}
			for _, n := range nodes {
				if strings.Contains(n.Desc.Label, "SYNTHETIC-PRIVATE") || strings.Contains(n.Desc.Label, "· Free") {
					t.Fatal("unknown/hidden board exposed private or available state")
				}
			}
			select {
			case <-v.controller.(*layoutController).actions:
				t.Fatal("unknown/hidden board started I/O")
			default:
			}
		})
	}
}
