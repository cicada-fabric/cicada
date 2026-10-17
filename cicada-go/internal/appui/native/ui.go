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
	"time"
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
	view.startDispatch(appcore.Action{Kind: appcore.ActionDiscoverProfiles})
	var ops op.Ops
	for {
		switch event := window.Event().(type) {
		case app.DestroyEvent:
			view.closed.Store(true)
			view.updates.close()
			cancel()
			view.clearSensitiveInputs()
			view.workerWG.Wait()
			return event.Err
		case app.ConfigEvent:
			view.updates.setMinimized(event.Config.Mode == app.Minimized)
		case app.FrameEvent:
			gtx := app.NewContext(&ops, event)
			view.layout(gtx)
			event.Frame(gtx.Ops)
		}
	}
}

type view struct {
	cancelReplacement    widget.Clickable
	controller           appcore.Controller
	window               *app.Window
	ctx                  context.Context
	cancel               context.CancelFunc
	theme                *material.Theme
	locale               appui.Locale
	activation           widget.Editor
	username             widget.Editor
	password             widget.Editor
	buttons              map[appcore.ActionKind]*widget.Clickable
	profileButtons       map[string]*widget.Clickable
	pairButtons          map[string]*widget.Clickable
	pairLabel            widget.Editor
	pairBootstrapConsent widget.Bool
	pairSlotAConsent     widget.Bool
	pairSlotBConsent     widget.Bool
	pairRevokeConsent    widget.Bool
	pairReviewID         string
	pairStateReviewID    string
	contentList          widget.List
	canvasList           widget.List
	langEN               widget.Clickable
	langZH               widget.Clickable
	previewButton        widget.Clickable
	detailsButton        widget.Clickable
	details              bool
	consent              widget.Bool
	nodeCode             widget.Editor
	nodeIdentityConsent  widget.Bool
	nodeAccessConsent    widget.Bool
	nodeReviewID         string
	nodePinDetails       bool
	nodePinButton        widget.Clickable
	inputScope           appui.InputScope
	accountVisible       bool
	replacementInput     bool
	canvas               canvasWidget
	preview              bool
	busy                 atomic.Bool
	autoBusy             atomic.Bool
	updates              nodeStatusUpdater
	closed               atomic.Bool
	workerWG             sync.WaitGroup
	statusMu             sync.Mutex
	failed               bool
	uiErrorCode          string
}

func newView(controller appcore.Controller, ctx context.Context, cancel context.CancelFunc, window *app.Window) *view {
	v := &view{
		controller:     controller,
		window:         window,
		ctx:            ctx,
		cancel:         cancel,
		theme:          material.NewTheme(),
		locale:         appui.English,
		buttons:        make(map[appcore.ActionKind]*widget.Clickable),
		profileButtons: make(map[string]*widget.Clickable),
		pairButtons:    make(map[string]*widget.Clickable),
	}
	// Keep Gio system-font fallback enabled for Windows CJK fonts. Layout
	// dimensions use dp/sp so Windows scaling applies to text and controls.
	v.theme.Bg = color.NRGBA{R: 18, G: 25, B: 35, A: 255}
	v.theme.Fg = color.NRGBA{R: 229, G: 237, B: 245, A: 255}
	v.theme.ContrastBg = color.NRGBA{R: 100, G: 224, B: 191, A: 255}
	v.theme.ContrastFg = color.NRGBA{R: 13, G: 36, B: 33, A: 255}
	v.contentList.Axis = layout.Vertical
	v.activation.Mask = '•'
	v.activation.SingleLine, v.username.SingleLine, v.password.SingleLine = true, true, true
	v.activation.MaxLen = appui.ActivationCodeInputLimit()
	v.nodeCode.SingleLine, v.nodeCode.MaxLen = true, 32
	v.username.MaxLen, v.password.MaxLen = 128, 1024
	v.pairLabel.MaxLen, v.pairLabel.SingleLine = 128, true
	v.activation.InputHint = 1
	v.username.InputHint = 1
	v.password.Mask = '•'
	v.password.InputHint = 2
	return v
}

func (v *view) layout(gtx layout.Context) {
	paint.Fill(gtx.Ops, v.theme.Bg)
	raw := v.controller.Snapshot()
	now := time.Now()
	presentation := appui.PresentScreen(raw, now)
	if appui.ResetPresentationInputs(v.inputScope, v.accountVisible, raw, now) {
		v.resetPresentationInputs()
	}
	v.inputScope, v.accountVisible = appui.InputScopeFor(raw), presentation.InformationVisible
	snapshot := presentation.Snapshot
	scheduleSnapshotRedraw(gtx, raw, now)
	managementAuthorized := snapshot.Management == appcore.ManagementAuthorized
	objects, isPreview := v.canvasObjects(snapshot, managementAuthorized)
	layout.UniformInset(28).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical, Spacing: layout.SpaceBetween}.Layout(gtx,
			layout.Rigid(v.header),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				flow := presentation.Flow
				var rows []layout.Widget
				if presentation.InformationVisible {
					flow = v.updates.accountFlow(snapshot, now)
					rows = append(rows, func(gtx layout.Context) layout.Dimensions { return v.statusCard(gtx, snapshot) })
				} else {
					rows = append(rows, v.publicStatusRows(snapshot)...)
				}
				rows = append(rows, v.contentRows(snapshot, flow, presentation.InformationVisible, managementAuthorized, objects, isPreview)...)
				content := func(gtx layout.Context) layout.Dimensions {
					return v.card(gtx, func(gtx layout.Context) layout.Dimensions {
						return v.contentList.Layout(gtx, len(rows), func(gtx layout.Context, index int) layout.Dimensions {
							return layout.Inset{Top: 8, Bottom: 8, Left: 4, Right: 4}.Layout(gtx, rows[index])
						})
					})
				}
				if presentation.InformationVisible {
					return content(gtx)
				}
				return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					width := min(gtx.Constraints.Max.X, gtx.Dp(440))
					gtx.Constraints.Min = image.Pt(width, 0)
					gtx.Constraints.Max.X = width
					return content(gtx)
				})
			}),
		)
	})
	// Foreground controls above have already processed this frame's clicks.
	// The background due decision can neither block them nor issue I/O here.
	if presentation.InformationVisible {
		v.scheduleAutomaticNodeStatus(gtx)
	} else {
		v.updates.pauseForAccountScreen()
	}
}

func (v *view) header(gtx layout.Context) layout.Dimensions {
	title := func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: 4, Bottom: 12}.Layout(gtx, material.H5(v.theme, appui.Text(v.locale, "app.title")).Layout)
	}
	languages := func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if v.langEN.Clicked(gtx) {
					v.locale = appui.English
					v.window.Invalidate()
				}
				return layout.Inset{Right: 8}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return v.button(gtx, &v.langEN, "English", v.locale != appui.English)
				})
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if v.langZH.Clicked(gtx) {
					v.locale = appui.Chinese
					v.window.Invalidate()
				}
				return v.button(gtx, &v.langZH, "简体中文", v.locale != appui.Chinese)
			}),
		)
	}
	if gtx.Constraints.Max.X < gtx.Dp(600) {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, layout.Rigid(title), layout.Rigid(languages))
	}
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx, layout.Flexed(1, title), layout.Rigid(languages))
}

func (v *view) statusCard(gtx layout.Context, s appcore.Snapshot) layout.Dimensions {
	return v.card(gtx, func(gtx layout.Context) layout.Dimensions {
		rows := []layout.FlexChild{
			layout.Rigid(v.headingRow(v.phaseLabel(s.Phase))),
		}
		if s.Hub.Origin != "" {
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(s.Hub.Origin, 256))))
		}
		if v.busy.Load() && !v.autoBusy.Load() {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "operation.in_progress"))))
		}
		if s.Setup.OwnerKeyStored {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "setup.keys_stored"))))
		}
		if s.Setup.Purpose != "" && !s.Node.Available {
			rows = append(rows, layout.Rigid(v.labelRow(v.authorizationLabel(s.Authorization.State))))
			if expiry, err := time.Parse(time.RFC3339Nano, s.Authorization.ExpiresAt); err == nil {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "authorization.until")+" "+expiry.Local().Format("15:04"))))
			}
		}
		if s.ErrorCode != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, s.ErrorCode))))
		} else {
			v.statusMu.Lock()
			code, failed := v.uiErrorCode, v.failed
			v.statusMu.Unlock()
			if code != "" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.ErrorText(v.locale, code))))
			} else if failed {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "common.request_failed"))))
			}
		}
		rows = append(rows, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if v.detailsButton.Clicked(gtx) {
				v.details = !v.details
			}
			style := material.Button(v.theme, &v.detailsButton, appui.Text(v.locale, "connection.details"))
			style.Background = color.NRGBA{}
			style.Color = v.theme.ContrastBg
			return style.Layout(gtx)
		}))
		if v.details {
			rows = append(rows, layout.Rigid(v.labelRow(v.hubSummary(s.Hub))), layout.Rigid(v.labelRow(v.accountSummary(s))), layout.Rigid(v.labelRow(v.managementLabel(s.Management))))
			if s.Node.Available && s.Setup.Purpose != "" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "authorization.initial")+": "+v.authorizationLabel(s.Authorization.State))))
			}
			if s.Node.Available && hasAction(s, appcore.ActionRefresh) {
				rows = append(rows, layout.Rigid(v.actionButton(appcore.ActionRefresh, appui.Text(v.locale, "account.refresh"), s)))
			}
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

func (v *view) contentRows(s appcore.Snapshot, flow appui.SetupFlow, informationVisible, managementAuthorized bool, objects []appui.CanvasObject, preview bool) []layout.Widget {
	if v.replacementInput && s.Setup.ReplacementAllowed {
		flow = appui.SetupFlow{Stage: "replace", Primary: appcore.ActionConnect}
	}
	rows := make([]layout.Widget, 0, 12)
	switch flow.Stage {
	case "profile-recovery":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.profile_recovery_title")), v.labelRow(appui.Text(v.locale, "setup.profile_recovery_body")))
	case "connect":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.welcome")), v.labelRow(appui.Text(v.locale, "setup.welcome_body")))
		if len(s.Profiles) > 0 {
			rows = append(rows, v.headingRow(appui.Text(v.locale, "connection.saved_profiles")))
			for index, profile := range s.Profiles {
				rows = append(rows, v.profileRow(profile, index))
			}
		}
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_connect")), v.editorRow(&v.activation, appui.Text(v.locale, "connection.material"), false))
	case "keys":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_keys")), v.labelRow(appui.Text(v.locale, "setup.keys_body")))
	case "replace":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.replacement_code")), v.labelRow(appui.Text(v.locale, "setup.replacement_body")), v.editorRow(&v.activation, appui.Text(v.locale, "connection.material"), false))
	case "activate":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.activate_app")), v.labelRow(appui.Text(v.locale, "setup.grant_body")))
		if expiry, err := time.Parse(time.RFC3339Nano, s.Setup.AuthorizationDeadline); err == nil {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "authorization.until")+" "+expiry.Local().Format("15:04")))
		}
	case "account":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_account")))
	case "login":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "account.login")), v.labelRow(appui.Text(v.locale, "setup.login_body")))
	case "session-check":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "account.login")), v.labelRow(appui.Text(v.locale, "setup.check_saved_session")))
	case "recovery":
		body := "setup.recovery_body"
		if !informationVisible {
			body = "setup.private_recovery_body"
		}
		rows = append(rows, v.headingRow(appui.Text(v.locale, "operation.recover_connection")), v.labelRow(appui.Text(v.locale, body)))
	case "ready":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.account_ready")))
		if s.Account.State == appcore.AccountStateOwnerProof {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "account.owner_proof_pending")))
		}
	}
	if flow.Stage == "replace" && v.replacementInput && appui.Flow(s).Stage != "replace" {
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			if v.cancelReplacement.Clicked(gtx) {
				v.replacementInput = false
				v.activation.SetText("")
				v.password.SetText("")
				v.consent.Value = false
				v.window.Invalidate()
			}
			style := material.Button(v.theme, &v.cancelReplacement, appui.Text(v.locale, "setup.back_to_activation"))
			style.Background = color.NRGBA{R: 42, G: 56, B: 72, A: 255}
			style.Color = v.theme.Fg
			return style.Layout(gtx)
		})
	}
	if flow.Username {
		rows = append(rows, v.editorRow(&v.username, appui.Text(v.locale, "account.username"), false))
	}
	if flow.Password {
		rows = append(rows, v.editorRow(&v.password, appui.Text(v.locale, "account.password"), true))
	}
	if flow.LimitedConsent {
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			if v.busy.Load() {
				gtx = gtx.Disabled()
			}
			return material.CheckBox(v.theme, &v.consent, appui.Text(v.locale, "setup.grant_consent")).Layout(gtx)
		})
	}
	if label, ok := v.actionLabel(flow.Primary); ok && !(flow.Stage == "ready" && s.Node.Available) {
		if !informationVisible && flow.Stage == "session-check" {
			label = appui.Text(v.locale, "setup.continue_saved_session")
		}
		if flow.Stage == "profile-recovery" {
			label = appui.Text(v.locale, "connection.retry_saved_connection")
		}
		rows = append(rows, v.actionButton(flow.Primary, label, s, flow))
	}
	if informationVisible && appui.NodeCardVisible(s, flow) {
		rows = append(rows, v.nodeSection(s))
	}
	if informationVisible && appui.PairFlow(s, time.Now()).Visible {
		rows = append(rows, v.pairSection(s))
	}
	for _, kind := range flow.Secondary {
		if label, ok := v.actionLabel(kind); ok {
			if kind == appcore.ActionConnect && s.Setup.ReplacementAllowed {
				label = appui.Text(v.locale, "setup.replacement_code")
			}
			rows = append(rows, v.actionButton(kind, label, s))
		}
	}
	if informationVisible && flow.Stage == "ready" {
		if !s.Node.Available && !s.Node.Pending {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "account.management_disabled")), v.canvasSection(s, managementAuthorized, objects, preview))
		}
	}
	return rows
}

func (v *view) publicStatusRows(s appcore.Snapshot) []layout.Widget {
	var rows []layout.Widget
	if v.busy.Load() {
		rows = append(rows, v.labelRow(appui.Text(v.locale, "operation.in_progress")))
	}
	v.statusMu.Lock()
	code, failed := v.uiErrorCode, v.failed
	v.statusMu.Unlock()
	if s.ErrorCode != "" {
		code = s.ErrorCode
	}
	if code != "" {
		rows = append(rows, v.labelRow(appui.ErrorText(v.locale, code)))
	} else if failed {
		rows = append(rows, v.labelRow(appui.Text(v.locale, "common.request_failed")))
	}
	return rows
}

func (v *view) resetPresentationInputs() {
	v.activation.SetText("")
	v.username.SetText("")
	v.password.SetText("")
	v.nodeCode.SetText("")
	v.consent.Value = false
	v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
	v.nodeReviewID = ""
	v.pairLabel.SetText("")
	v.pairBootstrapConsent.Value, v.pairSlotAConsent.Value, v.pairSlotBConsent.Value, v.pairRevokeConsent.Value = false, false, false, false
	v.pairReviewID, v.pairStateReviewID = "", ""
	v.nodePinDetails = false
	v.details, v.preview, v.replacementInput = false, false, false
	v.canvas = canvasWidget{}
	v.contentList.Position, v.canvasList.Position = layout.Position{}, layout.Position{}
}

func (v *view) actionButton(kind appcore.ActionKind, label string, s appcore.Snapshot, selectedFlow ...appui.SetupFlow) layout.Widget {
	button := v.buttons[kind]
	if button == nil {
		button = new(widget.Clickable)
		v.buttons[kind] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := !v.busy.Load() && (kind != appcore.ActionActivateApp || v.consent.Value)
		if isNodeAction(kind) {
			enabled = v.nodeActionEnabled(kind, s)
		}
		flow := appui.Flow(s)
		if len(selectedFlow) != 0 {
			flow = selectedFlow[0]
		}
		if v.replacementInput && s.Setup.ReplacementAllowed {
			flow = appui.SetupFlow{Stage: "replace", Primary: appcore.ActionConnect}
		}
		if kind == flow.Primary {
			if flow.Username && strings.TrimSpace(v.username.Text()) == "" {
				enabled = false
			}
			if flow.Password && v.password.Text() == "" {
				enabled = false
			}
			if kind == appcore.ActionConnect && strings.TrimSpace(v.activation.Text()) == "" {
				enabled = false
			}
		}
		if button.Clicked(gtx) && enabled {
			if kind == appcore.ActionConnect && s.Hub.Verified && s.Setup.ReplacementAllowed && !v.replacementInput && appui.Flow(s).Stage != "replace" {
				v.replacementInput = true
				v.consent.Value = false
				v.password.SetText("")
				v.window.Invalidate()
				return v.button(gtx, button, label, true)
			}
			action, ok := v.actionFor(kind, s)
			if ok {
				v.startDispatch(action)
			}
		}
		if kind == appcore.ActionDiscoverProfiles || kind == appcore.ActionImportOwner || kind == appcore.ActionLogout || kind == appcore.ActionCancelNodeAccess || (kind == appcore.ActionRefresh && s.Node.Available) ||
			(kind == appcore.ActionConnect && s.Hub.Verified && appui.Flow(s).Primary != appcore.ActionConnect && !v.replacementInput) {
			if v.busy.Load() {
				gtx = gtx.Disabled()
			}
			style := material.Button(v.theme, button, label)
			style.Background = color.NRGBA{R: 42, G: 56, B: 72, A: 255}
			style.Color = v.theme.Fg
			style.CornerRadius = 10
			style.Inset = layout.Inset{Top: 12, Bottom: 12, Left: 20, Right: 20}
			return style.Layout(gtx)
		}
		return v.button(gtx, button, label, enabled)
	}
}

func (v *view) actionFor(kind appcore.ActionKind, s appcore.Snapshot) (appcore.Action, bool) {
	if isNodeAction(kind) {
		return v.nodeActionFor(kind, s)
	}
	action := appcore.Action{Kind: kind}
	switch kind {
	case appcore.ActionActivateApp:
		action.ConfirmLimitedAuthorization = v.consent.Value
		v.consent.Value = false
		if s.Setup.NeedsCredentials {
			action.Username = strings.TrimSpace(v.username.Text())
			action.Password = v.password.Text()
			v.password.SetText("")
		}
		return action, action.ConfirmLimitedAuthorization
	case appcore.ActionLogin, appcore.ActionSetupAccount:
		action.Username = strings.TrimSpace(v.username.Text())
		action.Password = v.password.Text()
		v.password.SetText("")
		return action, action.Username != "" && action.Password != ""
	case appcore.ActionConnect:
		v.replacementInput = false
		v.consent.Value = false
		if strings.HasPrefix(strings.TrimSpace(v.activation.Text()), "cicada-hub-connection-v1:") {
			action.ConnectionCard = strings.TrimSpace(v.activation.Text())
			v.activation.SetText("")
			return action, true
		}
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
				code := ""
				if errors.Is(err, errEncryptedOwnerPEMUnsupported) {
					code = "ENCRYPTED_OWNER_PEM_UNSUPPORTED"
				}
				v.markFailed(code)
			}
			return appcore.Action{}, false
		}
		action.OwnerImport = ownerImport
		return action, true
	case appcore.ActionExportOwnerPublic:
		path, err := chooseOwnerPublicDestination(appui.Text(v.locale, "account.export_owner_public"))
		if err != nil {
			if !errors.Is(err, errOwnerImportCancelled) {
				v.markFailed("APP_OWNER_PUBLIC_EXPORT_FAILED")
			}
			return appcore.Action{}, false
		}
		action.PublicExportPath = path
		return action, true
	case appcore.ActionRecoverPair, appcore.ActionRecover, appcore.ActionRefresh, appcore.ActionActivationStatus, appcore.ActionDiscoverProfiles, appcore.ActionGenerateOwner, appcore.ActionClaimPrepare,
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
		v.dispatchForeground(action)
	}()
}

func (v *view) dispatchForeground(action appcore.Action) {
	err := v.ctx.Err()
	if err == nil {
		err = v.controller.Dispatch(v.ctx, action)
	}
	if err == nil && action.Kind == appcore.ActionDiscoverProfiles {
		profiles := v.controller.Snapshot().Profiles
		if len(profiles) == 1 {
			err = v.controller.Dispatch(v.ctx, appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles[0].ID})
		}
	}
	clearOwnerImport(action.OwnerImport)
	// Best-effort removal of secret-bearing references. Go strings cannot
	// guarantee physical zeroization, but they need not remain in this UI.
	action.Password = ""
	action.ActivationCode = ""
	action.Username = ""
	action.NodeCode = ""
	v.statusMu.Lock()
	v.failed = err != nil
	v.uiErrorCode = ""
	v.statusMu.Unlock()
	v.updates.foregroundCompleted(v.controller.Snapshot(), time.Now(), action, err)
	v.busy.Store(false)
	if !v.closed.Load() {
		v.window.Invalidate()
	}
}

func (v *view) scheduleAutomaticNodeStatus(gtx layout.Context) {
	if v.closed.Load() {
		return
	}
	snapshot, now := v.controller.Snapshot(), time.Now()
	if !appui.AccountInformationVisible(snapshot, now) {
		v.updates.pauseForAccountScreen()
		return
	}
	at, target := v.updates.afterControls(snapshot, now, v.busy.Load())
	if !at.IsZero() {
		gtx.Execute(op.InvalidateCmd{At: at})
	}
	if target == nil {
		return
	}
	if !v.busy.CompareAndSwap(false, true) {
		v.updates.complete(v.controller.Snapshot(), time.Now(), appcore.ErrControllerBusy)
		return
	}
	v.autoBusy.Store(true)
	ctx := v.updates.begin(v.ctx)
	v.workerWG.Add(1)
	go func() {
		defer v.workerWG.Done()
		err := v.controller.Dispatch(ctx, appcore.Action{Kind: appcore.ActionRefreshNode, AutoNodeStatus: target})
		v.updates.completeAndRelease(v.controller.Snapshot(), time.Now(), err, func() {
			v.autoBusy.Store(false)
			v.busy.Store(false)
		})
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

func (v *view) markFailed(code string) {
	v.statusMu.Lock()
	v.failed = true
	v.uiErrorCode = code
	v.statusMu.Unlock()
	v.window.Invalidate()
}

func (v *view) clearSensitiveInputs() {
	v.activation.SetText("")
	v.username.SetText("")
	v.password.SetText("")
	v.nodeCode.SetText("")
	v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
	v.cancel()
}

func (v *view) actionLabel(kind appcore.ActionKind) (string, bool) {
	key := map[appcore.ActionKind]string{
		appcore.ActionConnect:           "connection.connect",
		appcore.ActionActivateApp:       "setup.activate_app",
		appcore.ActionLogin:             "account.login",
		appcore.ActionSetupAccount:      "account.claim",
		appcore.ActionRecover:           "operation.recover_connection",
		appcore.ActionRecoverNode:       "operation.recover_connection",
		appcore.ActionRecoverPair:       "operation.recover_connection",
		appcore.ActionRefresh:           "account.refresh",
		appcore.ActionActivationStatus:  "account.refresh",
		appcore.ActionDiscoverProfiles:  "connection.discover_profiles",
		appcore.ActionGenerateOwner:     "account.generate_local_owner",
		appcore.ActionImportOwner:       "account.select_owner_files",
		appcore.ActionExportOwnerPublic: "account.export_owner_public",
		appcore.ActionClaimPrepare:      "account.prepare_claim",
		appcore.ActionClaimComplete:     "account.complete_claim",
		appcore.ActionLoginPrepare:      "account.start_login",
		appcore.ActionLoginComplete:     "account.login",
		appcore.ActionSessionInspect:    "account.refresh",
		appcore.ActionLogout:            "account.logout",
		appcore.ActionRetry:             "operation.recover_exact",
	}
	label, ok := key[kind]
	return appui.Text(v.locale, label), ok
}

func (v *view) button(gtx layout.Context, button *widget.Clickable, label string, enabled bool) layout.Dimensions {
	style := material.Button(v.theme, button, label)
	style.CornerRadius = 10
	style.Inset = layout.Inset{Top: 12, Bottom: 12, Left: 20, Right: 20}
	if !enabled {
		gtx = gtx.Disabled()
		style.Background = color.NRGBA{R: 49, G: 61, B: 75, A: 255}
		style.Color = color.NRGBA{R: 210, G: 210, B: 210, A: 255}
	}
	return style.Layout(gtx)
}

func (v *view) editorRow(editor *widget.Editor, hint string, password bool) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		if password {
			editor.Mask = '•'
		}
		if v.busy.Load() {
			gtx = gtx.Disabled()
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
		appcore.PhaseNeedConnection:    "state.connection",
		appcore.PhaseVerifyingHub:      "state.unverified",
		appcore.PhaseConnected:         "state.connection",
		appcore.PhaseLocked:            "state.locked",
		appcore.PhaseClaimChallenge:    "state.claim_pending",
		appcore.PhaseLoginChallenge:    "account.login",
		appcore.PhaseSessionCheck:      "account.state.session_check",
		appcore.PhaseAccountPending:    "state.owner_pending",
		appcore.PhaseAccountSession:    "setup.account_ready",
		appcore.PhaseOwnerReady:        "state.owner_ready",
		appcore.PhaseActivationPending: "setup.activate_app",
		appcore.PhaseUnavailable:       "state.unavailable",
		appcore.PhaseError:             "state.error",
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
	if account.LocalOwnerKeyID != "" {
		parts = append(parts, appui.Text(v.locale, "account.owner_key_id")+": "+account.LocalOwnerKeyID)
	}
	if account.OwnerPeerFingerprint != "" {
		parts = append(parts, appui.Text(v.locale, "account.owner_peer_fingerprint")+": "+account.OwnerPeerFingerprint)
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

// Cards use a single spacing and surface treatment across connection, account
// and recovery steps. The native event loop remains free of IO.
func (v *view) card(gtx layout.Context, content layout.Widget) layout.Dimensions {
	return layout.Stack{}.Layout(gtx,
		layout.Expanded(func(gtx layout.Context) layout.Dimensions {
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, gtx.Dp(16)).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, color.NRGBA{R: 27, G: 37, B: 50, A: 255})
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions { return layout.UniformInset(20).Layout(gtx, content) }),
	)
}

func (v *view) headingRow(label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions { return material.H6(v.theme, label).Layout(gtx) }
}

func (v *view) profileRow(profile appcore.ProfileSnapshot, index int) layout.Widget {
	button := v.profileButtons[profile.ID]
	if button == nil {
		button = new(widget.Clickable)
		v.profileButtons[profile.ID] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		if button.Clicked(gtx) && !v.busy.Load() {
			v.startDispatch(appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profile.ID})
		}
		return v.card(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(v.labelRow(appui.SavedConnectionLabel(v.locale, index))),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{Top: 12}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						return v.button(gtx, button, appui.Text(v.locale, "connection.resume_profile"), !v.busy.Load())
					})
				}),
			)
		})
	}
}

func (v *view) authorizationLabel(state string) string {
	key := map[string]string{"ACTIVE": "authorization.active", "LOGIN_REQUIRED": "authorization.login_required", "RECHECK_REQUIRED": "authorization.recheck_required", "EXPIRED": "authorization.expired", "REVOKED": "authorization.revoked", "UNAVAILABLE": "authorization.unavailable", "UNCONFIRMED": "authorization.unconfirmed"}[state]
	if key == "" {
		key = "authorization.unconfirmed"
	}
	return appui.Text(v.locale, key)
}
