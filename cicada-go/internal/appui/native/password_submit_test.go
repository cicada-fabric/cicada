package native

import (
	"image"
	"testing"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/io/event"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

// Exercise the actual Gio Editor/Router and production SubmitEvent consumer.
// This is headless input routing, not a physical Windows/IME acceptance run.
func passwordInputFixture(t *testing.T) (*widget.Editor, *input.Router, layout.Context, appcore.Snapshot, appui.SetupFlow) {
	t.Helper()
	editor := &widget.Editor{SingleLine: true, Submit: true, Mask: '•'}
	router := new(input.Router)
	gtx := layout.Context{Ops: new(op.Ops), Source: router.Source(), Constraints: layout.Exact(image.Pt(300, 60))}
	gtx.Execute(key.FocusCmd{Tag: editor})
	editor.Layout(gtx, text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection())), font.Font{}, unit.Sp(14), op.CallOp{}, op.CallOp{})
	router.Frame(gtx.Ops)
	s := appcore.Snapshot{Hub: appcore.HubSnapshot{Verified: true}, AvailableActions: []appcore.ActionKind{appcore.ActionLogin}}
	flow := appui.SetupFlow{Stage: "login", Primary: appcore.ActionLogin, Username: true, Password: true}
	return editor, router, gtx, s, flow
}

func TestPasswordEnterSubmitsExactSecretOnce(t *testing.T) {
	for _, mode := range []string{"return", "keypad-enter", "text-newline"} {
		t.Run(mode, func(t *testing.T) {
			editor, router, gtx, s, flow := passwordInputFixture(t)
			secret := " SYNTHETIC 密码 meadow 42! "
			editor.SetText(secret)
			editor.SetCaret(editor.Len(), editor.Len())
			var events []event.Event
			switch mode {
			case "return":
				events = []event.Event{key.Event{Name: key.NameReturn, State: key.Press}, key.Event{Name: key.NameReturn, State: key.Press}, key.Event{Name: key.NameReturn, State: key.Release}}
			case "keypad-enter":
				events = []event.Event{key.Event{Name: key.NameEnter, State: key.Press}, key.Event{Name: key.NameEnter, State: key.Release}}
			case "text-newline":
				events = []event.Event{key.EditEvent{Range: key.Range{Start: editor.Len(), End: editor.Len()}, Text: "\n"}}
			}
			router.Queue(events...)
			calls := 0
			updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, func() {
				calls++
				if editor.Text() != secret || !editor.SingleLine || !editor.Submit || editor.Mask != '•' {
					t.Error("Enter changed the exact masked single-line password")
				}
				// The existing actionFor clears the password before Dispatch.
				editor.SetText("")
			})
			updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, func() { calls++ })
			if calls != 1 || editor.Text() != "" {
				t.Fatal("Enter was queued again or retained a password character")
			}
		})
	}
}

func TestPasswordEnterRespectsLoginReadinessAndDisabledRouting(t *testing.T) {
	for _, mode := range []string{"busy", "disabled", "empty-user", "empty-password", "unverified", "action-unavailable", "recovery", "setup", "activation", "not-password"} {
		t.Run(mode, func(t *testing.T) {
			editor, router, gtx, s, flow := passwordInputFixture(t)
			editor.SetText("SYNTHETIC secret")
			username, busy := "synthetic-user", false
			switch mode {
			case "busy":
				busy = true
			case "disabled":
				gtx = gtx.Disabled()
			case "empty-user":
				username = " \t "
			case "empty-password":
				editor.SetText("")
			case "unverified":
				s.Hub.Verified = false
			case "action-unavailable":
				s.AvailableActions = nil
			case "recovery":
				flow.Primary = appcore.ActionRecover
			case "setup":
				flow.Primary = appcore.ActionSetupAccount
			case "activation":
				flow.Primary, flow.LimitedConsent = appcore.ActionActivateApp, true
			case "not-password":
				flow.Password = false
			}
			router.Queue(key.Event{Name: key.NameReturn, State: key.Press})
			calls := 0
			updatePasswordEditor(gtx, editor, username, s, flow, busy, func() { calls++ })
			if calls != 0 {
				t.Fatal("Enter bypassed disabled login or triggered another account action")
			}
			if mode == "busy" {
				updatePasswordEditor(gtx, editor, username, s, flow, false, func() { calls++ })
				if calls != 0 {
					t.Fatal("busy Enter was deferred until the request completed")
				}
			}
		})
	}
}

func TestPasswordCompositionAndCommitDoNotSubmit(t *testing.T) {
	editor, router, gtx, s, flow := passwordInputFixture(t)
	calls := 0
	submit := func() { calls++ }
	router.Queue(key.CompositionEvent{Start: 0, End: 2}, key.EditEvent{Range: key.Range{}, Text: "测试"})
	updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, submit)
	router.Queue(key.EditEvent{Range: key.Range{Start: 0, End: 2}, Text: "密码"}, key.CompositionEvent{Start: -1, End: -1})
	updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, submit)
	if calls != 0 || editor.Text() != "密码" {
		t.Fatal("IME preedit or text commit became login")
	}
	router.Queue(key.Event{Name: key.NameReturn, State: key.Release})
	updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, submit)
	if calls != 0 {
		t.Fatal("key release submitted the password")
	}
	router.Queue(key.Event{Name: key.NameReturn, State: key.Press})
	updatePasswordEditor(gtx, editor, "synthetic-user", s, flow, false, submit)
	if calls != 1 || editor.Text() != "密码" {
		t.Fatal("explicit Enter failed to submit committed text exactly")
	}
}
