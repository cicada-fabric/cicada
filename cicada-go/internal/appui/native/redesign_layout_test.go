package native

import (
	"context"
	"image"
	"strings"
	"testing"
	"time"

	"gioui.org/f32"
	"gioui.org/font/gofont"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/io/semantic"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

type layoutController struct {
	snapshot appcore.Snapshot
	actions  chan appcore.Action
}

func (c *layoutController) Snapshot() appcore.Snapshot { return c.snapshot }
func (c *layoutController) Dispatch(_ context.Context, a appcore.Action) error {
	c.actions <- a
	return nil
}
func (*layoutController) Close() error { return nil }

type layoutWindow struct{}

func (layoutWindow) Invalidate() {}

func layoutSnapshot() appcore.Snapshot {
	return appcore.Snapshot{
		Hub:              appcore.HubSnapshot{Verified: true, Origin: "https://SYNTHETIC.invalid", HubID: "SYNTHETIC-hub", Fingerprint: strings.Repeat("a", 64), Address: "127.0.0.1:8787"},
		Account:          appcore.AccountSnapshot{AccountID: "SYNTHETIC-account", OwnerID: "SYNTHETIC-owner", DeviceID: "SYNTHETIC-app", State: appcore.AccountStateSessionActive, SessionExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)},
		Node:             appcore.NodeSetupSnapshot{Available: true, Pairing: &appcore.NodePairingSnapshot{Available: true, Availability: "AVAILABLE", State: "CODE"}},
		AvailableActions: []appcore.ActionKind{appcore.ActionReviewNodePairing},
	}
}

func newLayoutView(t *testing.T, s appcore.Snapshot) (*view, *input.Router) {
	t.Helper()
	c := &layoutController{snapshot: s, actions: make(chan appcore.Action, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	v := newView(c, ctx, cancel, layoutWindow{})
	v.theme.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	v.workspacePage = "devices"
	t.Cleanup(func() { v.closed.Store(true); cancel(); v.workerWG.Wait() })
	return v, new(input.Router)
}

func layoutFrame(v *view, router *input.Router, pixels image.Point, scale float32, before ...func(layout.Context)) []input.SemanticNode {
	gtx := layout.Context{Ops: new(op.Ops), Source: router.Source(), Metric: unit.Metric{PxPerDp: scale, PxPerSp: scale}, Now: time.Now(), Constraints: layout.Exact(pixels)}
	for _, f := range before {
		f(gtx)
	}
	v.layout(gtx)
	router.Frame(gtx.Ops)
	return router.AppendSemantics(nil)
}

func TestNativePairingPasteUpdatesFooterBeforePointerOrEnter(t *testing.T) {
	for _, method := range []string{"pointer", "return", "keypad"} {
		t.Run(method, func(t *testing.T) {
			v, r := newLayoutView(t, layoutSnapshot())
			size := image.Pt(800, 600)
			layoutFrame(v, r, size, 1.5)
			v.workspacePage = "devices"
			layoutFrame(v, r, size, 1.5)
			layoutFrame(v, r, size, 1.5, func(gtx layout.Context) { gtx.Execute(key.FocusCmd{Tag: &v.devicePairingCode}) })
			code := syntheticDevicePairingCode(t, true)
			r.Queue(key.EditEvent{Range: key.Range{}, Text: code})
			nodes := layoutFrame(v, r, size, 1.5)
			d, ok := findSemantic(nodes, appui.Text(v.locale, "node_pairing.review_action"))
			if !ok || d.Disabled || v.devicePairingCode.Text() != code {
				t.Fatal("real paste did not update footer readiness in the same frame")
			}
			c := v.controller.(*layoutController)
			select {
			case <-c.actions:
				t.Fatal("paste submitted without an explicit action")
			default:
			}
			if method == "pointer" {
				center := d.Bounds.Min.Add(d.Bounds.Size().Div(2))
				position := f32.Pt(float32(center.X), float32(center.Y))
				r.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: position}, pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: position})
			} else {
				name := key.NameReturn
				if method == "keypad" {
					name = key.NameEnter
				}
				r.Queue(key.Event{Name: name, State: key.Press}, key.Event{Name: name, State: key.Press}, key.Event{Name: name, State: key.Release})
			}
			layoutFrame(v, r, size, 1.5)
			select {
			case action := <-c.actions:
				if action.Kind != appcore.ActionReviewNodePairing || action.DevicePairingCode != code || action.ConfirmNodePairing {
					t.Fatal("input changed the exact review action or approved implicitly")
				}
			case <-time.After(time.Second):
				t.Fatal("visible primary did not dispatch from actual Gio input")
			}
			v.workerWG.Wait()
			layoutFrame(v, r, size, 1.5)
			select {
			case <-c.actions:
				t.Fatal("input repeated a completed review")
			default:
			}
			if v.devicePairingCode.Text() != "" {
				t.Fatal("submitted code remained in the editor")
			}
		})
	}
}

func TestNativePairingEnterNeverApprovesOrReplacesPending(t *testing.T) {
	for _, mode := range []string{"busy", "review", "unknown", "fenced", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			s := layoutSnapshot()
			switch mode {
			case "review":
				s.Node.Pairing.State = "REVIEW"
				s.Node.Pairing.ReviewID = "SYNTHETIC-exact-review"
				s.Node.Pairing.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
				s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNodePairing}
			case "unknown":
				s.Node.Pending = true
				s.Node.Pairing.State = "UNKNOWN"
				s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverNodePairing}
			case "fenced":
				s.Node.Pairing.State = "FENCED"
				s.AvailableActions = []appcore.ActionKind{appcore.ActionCancelNodePairing}
			case "unavailable":
				s.Node.Pairing.Available = false
				s.Node.Pairing.Availability = "UNAVAILABLE"
				s.AvailableActions = nil
			}
			v, r := newLayoutView(t, s)
			size := image.Pt(640, 480)
			layoutFrame(v, r, size, 1)
			v.workspacePage = "devices"
			layoutFrame(v, r, size, 1)
			v.devicePairingCode.SetText(syntheticDevicePairingCode(t, false))
			layoutFrame(v, r, size, 1, func(gtx layout.Context) { gtx.Execute(key.FocusCmd{Tag: &v.devicePairingCode}) })
			if mode == "busy" {
				v.busy.Store(true)
			}
			r.Queue(key.Event{Name: key.NameReturn, State: key.Press})
			layoutFrame(v, r, size, 1)
			if mode == "busy" {
				v.busy.Store(false)
				layoutFrame(v, r, size, 1)
			}
			select {
			case <-v.controller.(*layoutController).actions:
				t.Fatal("Enter approved, replaced pending or queued a busy request")
			default:
			}
		})
	}
}

func TestNativeShellRendersFivePagesAndKeepsLoginPrivate(t *testing.T) {
	for _, page := range workspacePages {
		t.Run(page, func(t *testing.T) {
			v, r := newLayoutView(t, layoutSnapshot())
			size := image.Pt(1024, 720)
			layoutFrame(v, r, size, 1)
			v.workspacePage = page
			nodes := layoutFrame(v, r, size, 1)
			if len(nodes) == 0 {
				t.Fatal("page has no production layout")
			}
		})
	}
	s := layoutSnapshot()
	s.Account.State = appcore.AccountStateLoginRequired
	s.Node.Pairing.Name = "SYNTHETIC-PRIVATE-COMPUTER"
	s.Node.Pairing.NodeID = "SYNTHETIC-PRIVATE-NODE"
	s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin}
	v, r := newLayoutView(t, s)
	nodes := layoutFrame(v, r, image.Pt(640, 480), 1.5)
	for _, n := range nodes {
		if strings.Contains(n.Desc.Label, "SYNTHETIC-PRIVATE") {
			t.Fatal("pre-login shell exposed protected candidate metadata")
		}
	}
	if _, ok := findSemantic(nodes, appui.Text(v.locale, "node_pairing.review_action")); ok {
		t.Fatal("login screen exposed pairing action")
	}
}

func findSemantic(nodes []input.SemanticNode, label string) (input.SemanticDesc, bool) {
	for _, n := range nodes {
		if n.Desc.Class == semantic.Button {
			for _, child := range n.Children {
				if child.Desc.Label == label {
					return n.Desc, true
				}
			}
		}
		if result, ok := findSemantic(n.Children, label); ok {
			return result, true
		}
	}
	return input.SemanticDesc{}, false
}

// This probe executes the production renderer and actual Gio semantic clips.
// It is component geometry, not Windows pixels, native IME or Hub acceptance.
func TestNativePairingPrimaryStaysVisible(t *testing.T) {
	for _, mode := range []string{"code", "long-code", "empty", "invalid", "old-pending"} {
		for _, size := range []image.Point{image.Pt(1100, 780), image.Pt(640, 480), image.Pt(1000, 760)} {
			for _, scale := range []float32{1, 1.5, 2} {
				s := layoutSnapshot()
				label := appui.Text(appui.English, "node_pairing.review_action")
				if mode == "old-pending" {
					s.Node.Pending = true
					s.Node.Pairing.State = "UNKNOWN"
					s.Node.Pairing.NodeID = strings.Repeat("SYNTHETIC-node-", 16)
					s.Node.Pairing.ErrorCode = "APP_NODE_PAIRING_UNKNOWN"
					s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverNodePairing}
					label = appui.Text(appui.English, "node.recover")
				}
				v, r := newLayoutView(t, s)
				layoutFrame(v, r, size, scale)
				v.workspacePage = "devices"
				v.contentList.Position = layout.Position{}
				code := syntheticDevicePairingCode(t, mode == "long-code")
				if mode == "empty" {
					code = ""
				}
				if mode == "invalid" {
					code = "SYNTHETIC-invalid"
				}
				v.devicePairingCode.SetText(code)
				nodes := layoutFrame(v, r, size, scale)
				d, ok := findSemantic(nodes, label)
				t.Logf("mode=%s pixels=%v scale=%.1f primary=%t bounds=%v disabled=%t viewport=%v", mode, size, scale, ok, d.Bounds, d.Disabled, image.Rectangle{Max: size})
				if !ok || d.Bounds.Empty() || !d.Bounds.In(image.Rectangle{Max: size}) {
					t.Errorf("primary action is outside viewport: mode=%s size=%v scale=%.1f bounds=%v", mode, size, scale, d.Bounds)
				}
				if ok && d.Disabled != (mode == "empty" || mode == "invalid") {
					t.Errorf("primary readiness did not match current input: mode=%s disabled=%t", mode, d.Disabled)
				}
			}
		}
	}
}
