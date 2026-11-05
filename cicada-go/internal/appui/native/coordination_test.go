package native

import (
	"fmt"
	"image"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/io/semantic"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func coordinationReviewSnapshot(change string) appcore.Snapshot {
	s := groupLockLayoutSnapshot()
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApplyCoordination, appcore.ActionDismissCoordination}
	s.Coordination.Review = &appcore.CoordinationReview{GestureID: "SYNTHETIC-exact-reviewed-source", Change: change, ThreadName: "Thread A", GroupName: "Group A", HolderName: "Holder A", Classification: "advisor", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), CanApply: true}
	if change == wire.ThreadCollaborationClearOneSlot {
		s.Coordination.Review.Slot = 8
	}
	return s
}

func coordinationControl(nodes []input.SemanticNode, label string, class semantic.ClassOp) (input.SemanticDesc, bool) {
	var contains func(input.SemanticNode) bool
	contains = func(n input.SemanticNode) bool {
		if n.Desc.Label == label {
			return true
		}
		for _, child := range n.Children {
			if contains(child) {
				return true
			}
		}
		return false
	}
	for _, n := range nodes {
		if n.Desc.Class == class && contains(n) {
			return n.Desc, true
		}
		if d, ok := coordinationControl(n.Children, label, class); ok {
			return d, true
		}
	}
	return input.SemanticDesc{}, false
}

func TestCoordinationConfirmationFooterUsesRealPointerAndConsent(t *testing.T) {
	for _, change := range []string{wire.ThreadCollaborationSetClassification, wire.ThreadCollaborationEnableGroupPolicy, wire.ThreadCollaborationClearOneSlot} {
		for _, locale := range []appui.Locale{appui.English, appui.Chinese} {
			for _, size := range []image.Point{image.Pt(1100, 1200), image.Pt(640, 480)} {
				t.Run(fmt.Sprintf("%s/%s/%d", change, locale, size.X), func(t *testing.T) {
					scale := float32(1)
					if size.X == 640 {
						scale = 2
					}
					v, r := newLayoutView(t, coordinationReviewSnapshot(change))
					v.locale = locale
					layoutFrame(v, r, size, scale)
					v.workspacePage = "sessions"
					nodes := layoutFrame(v, r, size, scale)
					apply, ok := findSemantic(nodes, appui.Text(locale, "coord.apply"))
					if !ok || !apply.Disabled || !apply.Bounds.In(image.Rectangle{Max: size}) || apply.Bounds.Min.Y <= int(60*scale) {
						t.Fatalf("unchecked confirmation is missing, active or clipped: %+v", apply)
					}
					consent, ok := coordinationControl(nodes, appui.Text(locale, "coord.consent"), semantic.CheckBox)
					if !ok || !consent.Bounds.In(image.Rectangle{Max: size}) {
						t.Fatal("real consent checkbox is not fully visible")
					}
					footer := apply.Bounds
					queueVisualClick(r, apply.Bounds)
					layoutFrame(v, r, size, scale)
					select {
					case <-v.controller.(*layoutController).actions:
						t.Fatal("unchecked confirmation dispatched")
					default:
					}
					// Wheel events must reach the small body above the fixed footer.
					// Checking a label's actual start avoids its unbounded text area.
					label := "Group A"
					if change == wire.ThreadCollaborationSetClassification {
						label = "Thread A"
					}
					visible := false
					for i := 0; i < 100; i++ {
						nodes = layoutFrame(v, r, size, scale)
						desc, found := semanticLabel(nodes, label)
						if !found {
							t.Fatal("review target absent")
						}
						bottom := consent.Bounds.Min.Y - int(12*scale)
						if desc.Bounds.Min.Y >= int(60*scale) && desc.Bounds.Min.Y+int(22*scale) <= bottom {
							visible = true
							break
						}
						delta := float32(20) * scale
						if desc.Bounds.Min.Y < int(60*scale) {
							delta = -delta
						}
						r.Queue(pointer.Event{Kind: pointer.Scroll, Source: pointer.Mouse, Position: f32.Pt(float32(size.X/2), float32(65)*scale), Scroll: f32.Pt(0, delta)})
					}
					if !visible {
						t.Fatal("review target cannot be reached above footer by actual wheel")
					}
					apply, _ = findSemantic(nodes, appui.Text(locale, "coord.apply"))
					if apply.Bounds != footer {
						t.Fatal("confirmation scrolled away with body")
					}
					queueVisualClick(r, consent.Bounds)
					nodes = layoutFrame(v, r, size, scale)
					apply, ok = findSemantic(nodes, appui.Text(locale, "coord.apply"))
					if !ok || apply.Disabled {
						t.Fatal("actual checkbox click did not enable current review")
					}
					r.Queue(key.Event{Name: key.NameReturn, State: key.Press}, key.Event{Name: key.NameReturn, State: key.Release})
					layoutFrame(v, r, size, scale)
					select {
					case <-v.controller.(*layoutController).actions:
						t.Fatal("Enter implicitly approved review")
					default:
					}
					queueVisualClick(r, apply.Bounds)
					layoutFrame(v, r, size, scale)
					select {
					case action := <-v.controller.(*layoutController).actions:
						if action.Kind != appcore.ActionApplyCoordination || !action.Coordination.Confirm || action.Coordination.GestureID != "SYNTHETIC-exact-reviewed-source" {
							t.Fatal("confirmation changed exact review")
						}
					case <-time.After(time.Second):
						t.Fatal("visible confirmation did not dispatch from actual pointer")
					}
					v.workerWG.Wait()
				})
			}
		}
	}
}

func TestCoordinationChangedOrFencedReviewCannotReuseConsent(t *testing.T) {
	v, r := newLayoutView(t, coordinationReviewSnapshot(wire.ThreadCollaborationEnableGroupPolicy))
	size := image.Pt(1100, 1200)
	layoutFrame(v, r, size, 1)
	v.workspacePage = "sessions"
	nodes := layoutFrame(v, r, size, 1)
	consent, _ := coordinationControl(nodes, appui.Text(v.locale, "coord.consent"), semantic.CheckBox)
	queueVisualClick(r, consent.Bounds)
	layoutFrame(v, r, size, 1)
	c := v.controller.(*layoutController)
	review := *c.snapshot.Coordination.Review
	review.GestureID = "SYNTHETIC-new-source"
	c.snapshot.Coordination.Review = &review
	nodes = layoutFrame(v, r, size, 1)
	apply, ok := findSemantic(nodes, appui.Text(v.locale, "coord.apply"))
	if !ok || !apply.Disabled || v.coordinationConsent.Value {
		t.Fatal("changed review inherited consent")
	}
	review.CanApply = false
	consent, _ = coordinationControl(nodes, appui.Text(v.locale, "coord.consent"), semantic.CheckBox)
	queueVisualClick(r, consent.Bounds)
	nodes = layoutFrame(v, r, size, 1)
	apply, _ = findSemantic(nodes, appui.Text(v.locale, "coord.apply"))
	queueVisualClick(r, apply.Bounds)
	layoutFrame(v, r, size, 1)
	select {
	case <-c.actions:
		t.Fatal("fenced review dispatched despite consent")
	default:
	}
}

func TestCoordinationControlsReachRolePolicyAndSlotEight(t *testing.T) {
	for _, mode := range []string{"read-role", "read-locks", "role", "enable", "clear8"} {
		for _, locale := range []appui.Locale{appui.English, appui.Chinese} {
			for _, size := range []image.Point{image.Pt(1100, 1200), image.Pt(640, 480)} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, locale, size.X), func(t *testing.T) {
					scale := float32(1)
					if size.X == 640 {
						scale = 2
					}
					s := groupLockLayoutSnapshot()
					thread := s.ThreadGroups.Selected
					relation := &thread.Relations[0]
					board := relation.Locks
					kind := appcore.ActionPrepareCoordination
					label := "coord.enable"
					s.AvailableActions = []appcore.ActionKind{kind}
					board.GestureID = "SYNTHETIC-policy-version"
					board.PolicyState = "NOT_ENABLED"
					switch mode {
					case "read-role":
						kind = appcore.ActionReadThreadCoordination
						s.AvailableActions = []appcore.ActionKind{kind}
						label = "coord.read_role"
						thread.CanReadClassification = true
						thread.CoordinationGestureID = "SYNTHETIC-read-role"
					case "read-locks":
						kind = appcore.ActionReadGroupCoordination
						s.AvailableActions = []appcore.ActionKind{kind}
						label = "coord.read_locks"
						relation.CanReadCoordination = true
						relation.CoordinationGestureID = "SYNTHETIC-read-locks"
						relation.Locks = nil
					case "role":
						label = "coord.change_role"
						thread.Classification = &appcore.ThreadClassificationView{Current: true, State: "CURRENT", Classification: "worker", ActiveGroups: 1, CanChange: true, GestureID: "SYNTHETIC-classification-revision"}
					case "enable":
						board.CanEnable = true
					case "clear8":
						label = "coord.clear"
						board.PolicyState = "REVOKED"
						board.Slots[7] = appcore.GroupLockSlotView{Number: 8, Version: 7, State: appcore.GroupLockHeld, HolderName: "Holder 8", Purpose: "SYNTHETIC Group note", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano), CanClear: true, GestureID: "SYNTHETIC-slot-8-generation"}
					}
					v, r := newLayoutView(t, s)
					v.locale = locale
					layoutFrame(v, r, size, scale)
					v.workspacePage = "sessions"
					if mode == "enable" || mode == "clear8" {
						nodes := scrollLockLabel(t, v, r, size, scale, appui.Text(locale, "locks.show"), true)
						d, _ := findSemantic(nodes, appui.Text(locale, "locks.show"))
						queueVisualClick(r, d.Bounds)
						layoutFrame(v, r, size, scale)
					}
					nodes := scrollLockLabel(t, v, r, size, scale, appui.Text(locale, label), true)
					button, _ := findSemantic(nodes, appui.Text(locale, label))
					queueVisualClick(r, button.Bounds)
					nodes = layoutFrame(v, r, size, scale)
					if mode == "role" {
						// Opening the role disclosure is local. Pick Advisor with a
						// real radio click before requesting a server-side review.
						select {
						case <-v.controller.(*layoutController).actions:
							t.Fatal("role disclosure changed authorization")
						default:
						}
						var radio input.SemanticDesc
						found := false
						for i := 0; i < 60; i++ {
							nodes = layoutFrame(v, r, size, scale)
							radio, found = coordinationControl(nodes, appui.Text(locale, "coord.role.advisor"), semantic.RadioButton)
							if !found {
								t.Fatal("Advisor radio missing")
							}
							if radio.Bounds.Min.Y >= int(70*scale) && radio.Bounds.Max.Y < size.Y-int(8*scale) {
								break
							}
							r.Queue(pointer.Event{Kind: pointer.Scroll, Source: pointer.Mouse, Position: f32.Pt(float32(size.X/2), float32(size.Y/2)), Scroll: f32.Pt(0, 40*scale)})
						}
						if !found || !radio.Bounds.In(image.Rectangle{Max: size}) {
							t.Fatal("role choice cannot be reached")
						}
						queueVisualClick(r, radio.Bounds)
						layoutFrame(v, r, size, scale)
						nodes = scrollLockLabel(t, v, r, size, scale, appui.Text(locale, "coord.review"), true)
						button, _ = findSemantic(nodes, appui.Text(locale, "coord.review"))
						queueVisualClick(r, button.Bounds)
						layoutFrame(v, r, size, scale)
					}
					select {
					case action := <-v.controller.(*layoutController).actions:
						if action.Kind != kind || action.Coordination.Confirm {
							t.Fatal("navigation/preparation implicitly confirmed a mutation")
						}
						switch mode {
						case "read-role":
							if action.Coordination.EndpointID != thread.EndpointID || action.Coordination.GestureID != thread.CoordinationGestureID {
								t.Fatal("role read target changed")
							}
						case "read-locks":
							if action.Coordination.GroupID != relation.GroupID || action.Coordination.GestureID != relation.CoordinationGestureID {
								t.Fatal("lock read target changed")
							}
						case "role":
							if action.Coordination.Change != wire.ThreadCollaborationSetClassification || action.Coordination.Classification != "advisor" || action.Coordination.GestureID != thread.Classification.GestureID {
								t.Fatal("selected Owner role or source changed")
							}
						case "enable":
							if action.Coordination.Change != wire.ThreadCollaborationEnableGroupPolicy || action.Coordination.GestureID != board.GestureID {
								t.Fatal("policy target changed")
							}
						case "clear8":
							if action.Coordination.Change != wire.ThreadCollaborationClearOneSlot || action.Coordination.Slot != 8 || action.Coordination.GestureID != board.Slots[7].GestureID {
								t.Fatal("clear changed slot or original generation")
							}
						}
					case <-time.After(time.Second):
						t.Fatal("actual pointer did not reach current consumer control")
					}
					v.workerWG.Wait()
				})
			}
		}
	}
}
