package native

import (
	"image"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/io/input"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

func queueVisualClick(r *input.Router, bounds image.Rectangle) {
	center := bounds.Min.Add(bounds.Size().Div(2))
	position := f32.Pt(float32(center.X), float32(center.Y))
	r.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: position}, pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: position})
}

func TestSecondaryThreadActionsKeepNaturalWidthAndExactGuards(t *testing.T) {
	for _, mode := range []string{"read", "apply", "unavailable", "invalid", "busy"} {
		t.Run(mode, func(t *testing.T) {
			s := layoutSnapshot()
			kind := appcore.ActionReadThreadRelations
			label := "groups.view"
			if mode == "apply" {
				kind = appcore.ActionApplyThreadGroup
				label = "groups.apply"
			}
			s.AvailableActions = []appcore.ActionKind{kind}
			if mode == "unavailable" {
				s.AvailableActions = nil
			}
			v, r := newLayoutView(t, s)
			v.workspaceButtons = make(map[string]*widget.Clickable)
			if mode == "busy" {
				v.busy.Store(true)
			}
			original := appcore.ThreadGroupAction{GestureID: "SYNTHETIC-original-gesture", EndpointID: "SYNTHETIC-original-endpoint", Confirm: mode == "apply"}
			button := v.threadGroupButton(s, kind, "SYNTHETIC-visual", label, original, mode != "invalid")
			render := func() (layout.Dimensions, []input.SemanticNode) {
				gtx := layout.Context{Ops: new(op.Ops), Source: r.Source(), Metric: unit.Metric{PxPerDp: 1, PxPerSp: 1}, Now: time.Now(), Constraints: layout.Constraints{Min: image.Pt(700, 0), Max: image.Pt(700, 80)}}
				d := button(gtx)
				r.Frame(gtx.Ops)
				return d, r.AppendSemantics(nil)
			}
			dims, nodes := render()
			desc, ok := findSemantic(nodes, appui.Text(v.locale, label))
			if !ok {
				t.Fatal("production action missing")
			}
			if mode == "apply" {
				if dims.Size.X != 700 {
					t.Fatal("Apply lost its primary layout")
				}
			} else if dims.Size.X >= 350 {
				t.Fatal("secondary action inherited a full row's width")
			}
			blocked := mode == "unavailable" || mode == "invalid" || mode == "busy"
			if desc.Disabled != blocked {
				t.Fatal("visual style changed action readiness")
			}
			queueVisualClick(r, desc.Bounds)
			render()
			if !blocked {
				select {
				case a := <-v.controller.(*layoutController).actions:
					if a.Kind != kind || a.ThreadGroups != original {
						t.Fatal("secondary click changed original action coordinates")
					}
				case <-time.After(time.Second):
					t.Fatal("actual Router click did not reach the natural-width action")
				}
			}
			v.workerWG.Wait()
			select {
			case <-v.controller.(*layoutController).actions:
				t.Fatal("disabled or repeated action dispatched")
			default:
			}
		})
	}
}

func TestSettingsPreviewIsCollapsedAndRemainsExplicitlyReachable(t *testing.T) {
	v, r := newLayoutView(t, layoutSnapshot())
	size := image.Pt(1100, 1000)
	layoutFrame(v, r, size, 1)
	v.workspacePage = "settings"
	nodes := layoutFrame(v, r, size, 1)
	for _, n := range nodes {
		if n.Desc.Label == appui.Text(v.locale, "section.canvas") {
			t.Fatal("Settings exposed canvas by default")
		}
	}
	if _, ok := findSemantic(nodes, appui.Text(v.locale, "canvas.preview")); ok {
		t.Fatal("Settings exposed preview action before disclosure")
	}
	advanced, ok := findSemantic(nodes, appui.Text(v.locale, "workspace.advanced"))
	if !ok {
		t.Fatal("advanced preview entry is unreachable")
	}
	queueVisualClick(r, advanced.Bounds)
	nodes = layoutFrame(v, r, size, 1)
	preview, ok := findSemantic(nodes, appui.Text(v.locale, "canvas.preview"))
	if !ok {
		t.Fatal("disclosed existing preview is unreachable")
	}
	queueVisualClick(r, preview.Bounds)
	layoutFrame(v, r, size, 1)
	if !v.preview {
		t.Fatal("explicit local preview action stopped working")
	}
	select {
	case <-v.controller.(*layoutController).actions:
		t.Fatal("preview created a controller/authorization operation")
	default:
	}
}
