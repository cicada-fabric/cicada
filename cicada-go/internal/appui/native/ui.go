//go:build windows

package native

import (
	"context"
	"errors"
	"image"
	"image/color"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"gioui.org/app"
	"gioui.org/f32"
	"gioui.org/io/event"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

// RunWindow serves one native Gio window. The process main function must call
// app.Main on its main goroutine while RunWindow executes in another goroutine.
func RunWindow(controller appcore.Controller) error {
	if controller == nil {
		return errors.New("native app controller unavailable")
	}
	window := new(app.Window)
	window.Option(app.Title("Cicada"), app.Size(unit.Dp(1100), unit.Dp(780)))
	root, cancel := context.WithCancel(context.Background())
	defer cancel()
	view := newView(controller, root, cancel, window)
	var ops op.Ops
	for {
		switch event := window.Event().(type) {
		case app.DestroyEvent:
			view.closed.Store(true)
			cancel()
			view.clearSensitiveInputs()
			view.workerWG.Wait()
			return event.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, event)
			view.layout(gtx)
			event.Frame(gtx.Ops)
		}
	}
}

type view struct {
	controller    appcore.Controller
	window        *app.Window
	ctx           context.Context
	cancel        context.CancelFunc
	theme         *material.Theme
	locale        appui.Locale
	activation    widget.Editor
	username      widget.Editor
	password      widget.Editor
	buttons       map[appcore.ActionKind]*widget.Clickable
	contentList   widget.List
	canvasList    widget.List
	langEN        widget.Clickable
	langZH        widget.Clickable
	previewButton widget.Clickable
	canvas        canvasWidget
	preview       bool
	busy          atomic.Bool
	closed        atomic.Bool
	workerWG      sync.WaitGroup
	statusMu      sync.Mutex
	failed        bool
}

func newView(controller appcore.Controller, ctx context.Context, cancel context.CancelFunc, window *app.Window) *view {
	v := &view{
		controller: controller,
		window:     window,
		ctx:        ctx,
		cancel:     cancel,
		theme:      material.NewTheme(),
		locale:     appui.English,
		buttons:    make(map[appcore.ActionKind]*widget.Clickable),
	}
	v.activation.SingleLine, v.username.SingleLine, v.password.SingleLine = true, true, true
	v.activation.MaxLen = appui.ActivationCodeInputLimit()
	v.username.MaxLen, v.password.MaxLen = 128, 1024
	v.activation.InputHint = 1
	v.username.InputHint = 1
	v.password.Mask = '•'
	v.password.InputHint = 2
	return v
}

func (v *view) layout(gtx layout.Context) {
	snapshot := v.controller.Snapshot()
	managementAuthorized := snapshot.Management == appcore.ManagementAuthorized
	objects, isPreview := v.canvasObjects(snapshot, managementAuthorized)
	layout.UniformInset(18).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween}.Layout(gtx,
			layout.Rigid(v.header),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return v.statusCard(gtx, snapshot) }),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				rows := v.contentRows(snapshot, managementAuthorized, objects, isPreview)
				return v.contentList.Layout(gtx, len(rows), func(gtx layout.Context, index int) layout.Dimensions {
					return layout.UniformInset(8).Layout(gtx, rows[index])
				})
			}),
		)
	})
}

func (v *view) header(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return material.H5(v.theme, appui.Text(v.locale, "app.title")).Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(4).Layout(gtx, material.Body2(v.theme, appui.Text(v.locale, "app.language")).Layout)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.langEN.Clicked(gtx) {
						v.locale = appui.English
						v.window.Invalidate()
					}
					return v.button(gtx, &v.langEN, appui.Text(v.locale, "language.english"), v.locale != appui.English)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.langZH.Clicked(gtx) {
						v.locale = appui.Chinese
						v.window.Invalidate()
					}
					return v.button(gtx, &v.langZH, appui.Text(v.locale, "language.chinese"), v.locale != appui.Chinese)
				}),
			)
		}),
	)
}

func (v *view) statusCard(gtx layout.Context, s appcore.Snapshot) layout.Dimensions {
	return layout.UniformInset(14).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceEnd}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.H6(v.theme, v.phaseLabel(s.Phase)).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.Body2(v.theme, appui.Text(v.locale, "connection.health_public")).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.Body2(v.theme, v.hubSummary(s.Hub)).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.Body2(v.theme, v.accountSummary(s)).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return material.Body2(v.theme, v.managementLabel(s.Management)).Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if code := safeDisplay(s.ErrorCode, 80); code != "" {
					return material.Body2(v.theme, appui.Text(v.locale, "common.error_code")+": "+code).Layout(gtx)
				}
				v.statusMu.Lock()
				failed := v.failed
				v.statusMu.Unlock()
				if failed {
					return material.Body2(v.theme, appui.Text(v.locale, "common.request_failed")).Layout(gtx)
				}
				return layout.Dimensions{}
			}),
		)
	})
}

func (v *view) contentRows(s appcore.Snapshot, managementAuthorized bool, objects []appui.CanvasObject, preview bool) []layout.Widget {
	rows := make([]layout.Widget, 0, 12)
	if hasAction(s, appcore.ActionConnect) {
		rows = append(rows,
			v.labelRow(appui.Text(v.locale, "connection.not_connected")),
			v.editorRow(&v.activation, appui.Text(v.locale, "connection.activation_code"), false),
		)
	}
	if hasAction(s, appcore.ActionLoginPrepare) {
		rows = append(rows, v.editorRow(&v.username, appui.Text(v.locale, "account.username"), false))
	}
	if hasAction(s, appcore.ActionLoginComplete) || hasAction(s, appcore.ActionClaimComplete) {
		if hasAction(s, appcore.ActionClaimComplete) {
			rows = append(rows, v.editorRow(&v.username, appui.Text(v.locale, "account.username"), false))
		}
		rows = append(rows, v.editorRow(&v.password, appui.Text(v.locale, "account.password"), true))
	}
	for _, kind := range s.AvailableActions {
		if kind == appcore.ActionSetCanvasViewport || kind == appcore.ActionSelectCanvas {
			continue
		}
		label, ok := v.actionLabel(kind)
		if !ok {
			continue
		}
		rows = append(rows, v.actionButton(kind, label, s))
	}
	if s.Account.State == appcore.AccountStateOwnerProof || s.Phase == appcore.PhaseAccountPending || s.Phase == appcore.PhaseAccountSession {
		rows = append(rows, v.labelRow(appui.Text(v.locale, "account.owner_proof_pending")))
	}
	if !managementAuthorized {
		rows = append(rows, v.labelRow(appui.Text(v.locale, "account.management_disabled")))
	}
	rows = append(rows, v.canvasSection(s, managementAuthorized, objects, preview))
	return rows
}

func (v *view) actionButton(kind appcore.ActionKind, label string, s appcore.Snapshot) layout.Widget {
	button := v.buttons[kind]
	if button == nil {
		button = new(widget.Clickable)
		v.buttons[kind] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		if button.Clicked(gtx) && !v.busy.Load() {
			action, ok := v.actionFor(kind, s)
			if ok {
				v.startDispatch(action)
			}
		}
		return v.button(gtx, button, label, !v.busy.Load())
	}
}

func (v *view) actionFor(kind appcore.ActionKind, s appcore.Snapshot) (appcore.Action, bool) {
	action := appcore.Action{Kind: kind}
	switch kind {
	case appcore.ActionConnect:
		action.ActivationCode = strings.TrimSpace(v.activation.Text())
		v.activation.SetText("")
		return action, action.ActivationCode != ""
	case appcore.ActionLoginPrepare:
		action.Username = strings.TrimSpace(v.username.Text())
		return action, action.Username != ""
	case appcore.ActionClaimComplete:
		action.Username = strings.TrimSpace(v.username.Text())
		action.Password = v.password.Text()
		v.password.SetText("")
		return action, action.Username != "" && action.Password != ""
	case appcore.ActionLoginComplete:
		action.Password = v.password.Text()
		v.password.SetText("")
		return action, action.Password != ""
	case appcore.ActionImportOwner:
		ownerImport, err := chooseOwnerImport(v.locale)
		if err != nil {
			if !errors.Is(err, errOwnerImportCancelled) {
				v.markFailed()
			}
			return appcore.Action{}, false
		}
		action.OwnerImport = ownerImport
		return action, true
	case appcore.ActionGenerateOwner, appcore.ActionClaimPrepare,
		appcore.ActionSessionInspect, appcore.ActionLogout, appcore.ActionRetry:
		return action, true
	default:
		return appcore.Action{}, false
	}
}

func (v *view) startDispatch(action appcore.Action) {
	if !v.busy.CompareAndSwap(false, true) {
		clearOwnerImport(action.OwnerImport)
		return
	}
	v.workerWG.Add(1)
	go func() {
		defer v.workerWG.Done()
		err := v.controller.Dispatch(v.ctx, action)
		clearOwnerImport(action.OwnerImport)
		// Best-effort removal of secret-bearing references. Go strings cannot
		// guarantee physical zeroization, but they need not remain in this UI.
		action.Password = ""
		action.ActivationCode = ""
		action.Username = ""
		v.statusMu.Lock()
		v.failed = err != nil
		v.statusMu.Unlock()
		v.busy.Store(false)
		if !v.closed.Load() {
			v.window.Invalidate()
		}
	}()
}

func clearOwnerImport(owner *appcore.OwnerImport) {
	if owner == nil {
		return
	}
	clear(owner.KEMPrivatePKCS8)
	clear(owner.SigningPrivatePKCS8)
	clear(owner.KEMPublicSPKI)
	clear(owner.SigningPublicSPKI)
}

func (v *view) markFailed() {
	v.statusMu.Lock()
	v.failed = true
	v.statusMu.Unlock()
	v.window.Invalidate()
}

func (v *view) clearSensitiveInputs() {
	v.activation.SetText("")
	v.username.SetText("")
	v.password.SetText("")
	v.cancel()
}

func (v *view) actionLabel(kind appcore.ActionKind) (string, bool) {
	key := map[appcore.ActionKind]string{
		appcore.ActionConnect:        "connection.connect",
		appcore.ActionGenerateOwner:  "account.generate_local_owner",
		appcore.ActionImportOwner:    "account.select_owner_files",
		appcore.ActionClaimPrepare:   "account.prepare_claim",
		appcore.ActionClaimComplete:  "account.complete_claim",
		appcore.ActionLoginPrepare:   "account.start_login",
		appcore.ActionLoginComplete:  "account.login",
		appcore.ActionSessionInspect: "account.refresh",
		appcore.ActionLogout:         "account.logout",
		appcore.ActionRetry:          "operation.recover_exact",
	}
	label, ok := key[kind]
	return appui.Text(v.locale, label), ok
}

func (v *view) button(gtx layout.Context, button *widget.Clickable, label string, enabled bool) layout.Dimensions {
	style := material.Button(v.theme, button, label)
	if !enabled {
		style.Background = color.NRGBA{R: 85, G: 88, B: 92, A: 255}
		style.Color = color.NRGBA{R: 210, G: 210, B: 210, A: 255}
	}
	return style.Layout(gtx)
}

func (v *view) editorRow(editor *widget.Editor, hint string, password bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if password {
			editor.Mask = '•'
		}
		return material.Editor(v.theme, editor, hint).Layout(gtx)
	}
}

func (v *view) labelRow(label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions { return material.Body1(v.theme, label).Layout(gtx) }
}

func (v *view) canvasSection(s appcore.Snapshot, managementAuthorized bool, objects []appui.CanvasObject, preview bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		rows := []layout.Widget{
			func(gtx layout.Context) layout.Dimensions {
				return material.H6(v.theme, appui.Text(v.locale, "section.canvas")).Layout(gtx)
			},
			func(gtx layout.Context) layout.Dimensions {
				if preview {
					return material.Body2(v.theme, appui.Text(v.locale, "canvas.preview_banner")).Layout(gtx)
				}
				if !managementAuthorized || s.Canvas.State == appcore.CanvasNoAuthorization || s.Canvas.State == appcore.CanvasUnavailable {
					return material.Body2(v.theme, appui.Text(v.locale, "canvas.no_authorized_data")).Layout(gtx)
				}
				if len(objects) == 0 {
					return material.Body2(v.theme, appui.Text(v.locale, "common.no_data")).Layout(gtx)
				}
				return material.Body2(v.theme, appui.Text(v.locale, "canvas.instructions")).Layout(gtx)
			},
		}
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			if v.previewButton.Clicked(gtx) {
				v.preview = !v.preview
				v.canvas.selected = ""
				v.window.Invalidate()
			}
			label := appui.Text(v.locale, "canvas.preview")
			if preview {
				label = appui.Text(v.locale, "canvas.unavailable")
			}
			return v.button(gtx, &v.previewButton, label, true)
		})
		if preview || (managementAuthorized && s.Canvas.State == appcore.CanvasAvailable) {
			rows = append(rows, func(gtx layout.Context) layout.Dimensions {
				return v.canvas.Layout(gtx, v.theme, objects)
			})
			if v.canvas.selected != "" {
				selected := safeDisplay(v.canvas.selected, 128)
				rows = append(rows, v.labelRow(appui.Text(v.locale, "canvas.selected")+": "+selected))
			}
		}
		v.canvasList.Axis = layout.Vertical
		return v.canvasList.Layout(gtx, len(rows), func(gtx layout.Context, i int) layout.Dimensions {
			return layout.UniformInset(4).Layout(gtx, rows[i])
		})
	}
}

func (v *view) canvasObjects(s appcore.Snapshot, managementAuthorized bool) ([]appui.CanvasObject, bool) {
	if v.preview {
		return appui.PreviewCanvasObjects(), true
	}
	if !managementAuthorized || s.Canvas.State != appcore.CanvasAvailable {
		return nil, false
	}
	objects := make([]appui.CanvasObject, 0, min(16, len(s.Canvas.Objects)))
	for _, object := range s.Canvas.Objects {
		objects = append(objects, appui.CanvasObject{ID: safeDisplay(object.ID, 128), Label: safeDisplay(object.Label, 160), Bounds: appui.CanvasRect{
			X: float64(object.X), Y: float64(object.Y), Width: float64(object.Width), Height: float64(object.Height),
		}})
	}
	return objects, false
}

func (v *view) phaseLabel(phase appcore.Phase) string {
	key := map[appcore.Phase]string{
		appcore.PhaseNeedConnection: "state.connection",
		appcore.PhaseVerifyingHub:   "state.unverified",
		appcore.PhaseConnected:      "state.connection",
		appcore.PhaseLocked:         "state.locked",
		appcore.PhaseClaimChallenge: "state.claim_pending",
		appcore.PhaseLoginChallenge: "account.login",
		appcore.PhaseSessionCheck:   "account.state.session_check",
		appcore.PhaseAccountPending: "state.owner_pending",
		appcore.PhaseAccountSession: "state.owner_pending",
		appcore.PhaseOwnerReady:     "state.owner_ready",
		appcore.PhaseUnavailable:    "state.unavailable",
		appcore.PhaseError:          "state.error",
	}
	return appui.Text(v.locale, key[phase])
}

func (v *view) hubSummary(h appcore.HubSnapshot) string {
	parts := make([]string, 0, 4)
	if h.Verified {
		parts = append(parts, appui.Text(v.locale, "hub.pinned"))
	} else {
		parts = append(parts, appui.Text(v.locale, "hub.unverified"))
	}
	if h.Origin != "" {
		parts = append(parts, appui.Text(v.locale, "hub.origin")+": "+safeDisplay(h.Origin, 256))
	}
	if h.HubID != "" {
		parts = append(parts, appui.Text(v.locale, "hub.identity")+": "+safeDisplay(h.HubID, 128))
	}
	if h.Fingerprint != "" {
		parts = append(parts, appui.Text(v.locale, "hub.fingerprint")+": "+safeDisplay(h.Fingerprint, 64))
	}
	status := string(h.Health)
	if status == "" {
		status = string(appcore.HubHealthUnknown)
	}
	parts = append(parts, appui.Text(v.locale, "hub.health")+": "+safeDisplay(status, 32))
	return strings.Join(parts, "  •  ")
}

func (v *view) accountSummary(s appcore.Snapshot) string {
	account := s.Account
	parts := []string{
		appui.Text(v.locale, "account.state") + ": " + v.accountStateLabel(account.State),
		appui.Text(v.locale, "root.state") + ": " + v.rootStateLabel(account.RootState),
	}
	if account.LocalOwnerKeyPresent {
		parts = append(parts, appui.Text(v.locale, "account.local_owner_key_present"))
	} else {
		parts = append(parts, appui.Text(v.locale, "account.local_owner_key_missing"))
	}
	if account.Username != "" {
		parts = append(parts, appui.Text(v.locale, "account.username")+": "+safeDisplay(account.Username, 128))
	}
	if account.AccountID != "" {
		parts = append(parts, appui.Text(v.locale, "account.id")+": "+safeDisplay(account.AccountID, 128))
	}
	if account.OwnerID != "" {
		parts = append(parts, appui.Text(v.locale, "account.owner_id")+": "+safeDisplay(account.OwnerID, 128))
	}
	if account.OwnerFingerprint != "" {
		parts = append(parts, appui.Text(v.locale, "account.owner_fingerprint")+": "+safeDisplay(account.OwnerFingerprint, 64))
	}
	return appui.Text(v.locale, "section.account") + ": " + strings.Join(parts, "  •  ")
}

func (v *view) accountStateLabel(state appcore.AccountState) string {
	key := map[appcore.AccountState]string{
		appcore.AccountStateUnknown:       "account.state.unknown",
		appcore.AccountStateClaimPending:  "account.state.claim_pending",
		appcore.AccountStateLoginRequired: "account.state.login_required",
		appcore.AccountStateSessionCheck:  "account.state.session_check",
		appcore.AccountStateSessionActive: "account.state.session_active",
		appcore.AccountStateOwnerProof:    "account.state.owner_pending",
		appcore.AccountStateOwnerReady:    "account.state.owner_ready",
	}
	return appui.Text(v.locale, key[state])
}

func (v *view) rootStateLabel(state appcore.RootState) string {
	key := map[appcore.RootState]string{
		appcore.RootStateUnknown:     "root.state.unknown",
		appcore.RootStateUnavailable: "root.state.unavailable",
		appcore.RootStatePending:     "root.state.pending",
		appcore.RootStateActive:      "root.state.active",
	}
	return appui.Text(v.locale, key[state])
}

func (v *view) managementLabel(state appcore.ManagementState) string {
	if state == appcore.ManagementAuthorized {
		return appui.Text(v.locale, "account.management_enabled")
	}
	return appui.Text(v.locale, "account.management_disabled")
}

func hasAction(s appcore.Snapshot, target appcore.ActionKind) bool {
	for _, action := range s.AvailableActions {
		if action == target {
			return true
		}
	}
	return false
}

func safeDisplay(value string, maxRunes int) string {
	var b strings.Builder
	count := 0
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			continue
		}
		if count >= maxRunes {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

type canvasWidget struct {
	transform appui.CanvasTransform
	selected  string
	tag       struct{}
	dragging  bool
	dragMoved bool
	last      f32.Point
	dragStart f32.Point
}

func (c *canvasWidget) Layout(gtx layout.Context, theme *material.Theme, objects []appui.CanvasObject) layout.Dimensions {
	size := gtx.Constraints.Max
	if size.X <= 0 || size.Y <= 0 {
		return layout.Dimensions{}
	}
	viewport := appui.CanvasViewport{Width: float64(size.X), Height: float64(size.Y)}
	if c.transform.Scale == 0 {
		c.transform.Scale = 1
	}
	paint.FillShape(gtx.Ops, color.NRGBA{R: 20, G: 27, B: 36, A: 255}, clip.Rect{Max: size}.Op())
	clipper := clip.Rect{Max: size}.Push(gtx.Ops)
	event.Op(gtx.Ops, &c.tag)
	c.updateEvents(gtx, objects)
	for _, object := range appui.VisibleCanvasObjects(objects, viewport, c.transform) {
		bounds := c.transform.ScreenBounds(object.Bounds)
		if !finiteBounds(bounds) {
			continue
		}
		limitX, limitY := float64(size.X)*4, float64(size.Y)*4
		if bounds.X < -limitX || bounds.X > limitX || bounds.Y < -limitY || bounds.Y > limitY ||
			bounds.Width > limitX || bounds.Height > limitY {
			continue
		}
		left, top := int(math.Floor(bounds.X)), int(math.Floor(bounds.Y))
		width, height := int(math.Ceil(bounds.Width)), int(math.Ceil(bounds.Height))
		if width <= 0 || height <= 0 || width > size.X*4 || height > size.Y*4 {
			continue
		}
		rect := image.Rect(left, top, left+width, top+height)
		fill := color.NRGBA{R: 56, G: 82, B: 110, A: 255}
		if object.ID == c.selected {
			fill = color.NRGBA{R: 31, G: 118, B: 151, A: 255}
		}
		paint.FillShape(gtx.Ops, fill, clip.RRect{Rect: rect, NE: 8, NW: 8, SE: 8, SW: 8}.Op(gtx.Ops))
		label := safeDisplay(object.Label, 160)
		if label == "" {
			label = safeDisplay(object.ID, 128)
		}
		child := gtx
		child.Constraints = layout.Constraints{Min: image.Point{}, Max: image.Pt(width, height)}
		offset := op.Offset(image.Pt(left+12, top+8)).Push(gtx.Ops)
		labelClip := clip.Rect{Max: image.Pt(max(0, width-24), max(0, height-16))}.Push(gtx.Ops)
		material.Body1(theme, label).Layout(child)
		labelClip.Pop()
		offset.Pop()
	}
	clipper.Pop()
	return layout.Dimensions{Size: size}
}

func (c *canvasWidget) updateEvents(gtx layout.Context, objects []appui.CanvasObject) {
	for {
		event, ok := gtx.Source.Event(pointer.Filter{Target: &c.tag, Kinds: pointer.Press | pointer.Drag | pointer.Release | pointer.Cancel | pointer.Scroll})
		if !ok {
			break
		}
		p, ok := event.(pointer.Event)
		if !ok {
			continue
		}
		switch p.Kind {
		case pointer.Press:
			if !p.Buttons.Contain(pointer.ButtonPrimary) {
				continue
			}
			c.dragging = true
			c.dragMoved = false
			c.last = p.Position
			c.dragStart = p.Position
			gtx.Source.Execute(pointer.GrabCmd{Tag: &c.tag, ID: p.PointerID})
		case pointer.Drag:
			if !c.dragging {
				continue
			}
			dx := float64(p.Position.X - c.last.X)
			dy := float64(p.Position.Y - c.last.Y)
			c.transform.OffsetX += dx
			c.transform.OffsetY += dy
			c.last = p.Position
			if math.Abs(float64(p.Position.X-c.dragStart.X))+math.Abs(float64(p.Position.Y-c.dragStart.Y)) > 5 {
				c.dragMoved = true
			}
		case pointer.Release:
			if c.dragging && !c.dragMoved {
				if selected, ok := appui.HitTestCanvas(objects, float64(p.Position.X), float64(p.Position.Y), c.transform); ok {
					c.selected = selected.ID
				} else {
					c.selected = ""
				}
			}
			c.dragging = false
		case pointer.Cancel:
			c.dragging = false
		case pointer.Scroll:
			old := c.transform
			factor := 1.1
			if p.Scroll.Y > 0 {
				factor = 1 / factor
			}
			newScale := math.Min(3, math.Max(0.2, old.Scale*factor))
			worldX := (float64(p.Position.X) - old.OffsetX) / old.Scale
			worldY := (float64(p.Position.Y) - old.OffsetY) / old.Scale
			c.transform.Scale = newScale
			c.transform.OffsetX = float64(p.Position.X) - worldX*newScale
			c.transform.OffsetY = float64(p.Position.Y) - worldY*newScale
		}
	}
}

func finiteBounds(rect appui.CanvasRect) bool {
	return !math.IsNaN(rect.X) && !math.IsNaN(rect.Y) && !math.IsNaN(rect.Width) && !math.IsNaN(rect.Height) &&
		!math.IsInf(rect.X, 0) && !math.IsInf(rect.Y, 0) && !math.IsInf(rect.Width, 0) && !math.IsInf(rect.Height, 0)
}
