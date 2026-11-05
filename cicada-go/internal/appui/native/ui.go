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

// nativeWindow keeps the production renderer testable without creating an OS
// window. The Windows event loop remains the sole product entry point.
type nativeWindow interface{ Invalidate() }

type view struct {
	hubPicker                              widget.Clickable
	navigationIcons                        map[string]*widget.Icon
	navigationList                         widget.List
	appBindingReview                       string
	appBindingConsent                      widget.Bool
	hubConnections                         bool
	scopeChanging                          atomic.Bool
	profileControls                        map[string]*widget.Clickable
	profileRemovalID, profileRemovalReview string
	profileRemoveConsent                   widget.Bool
	cancelReplacement                      widget.Clickable
	controller                             appcore.Controller
	window                                 nativeWindow
	ctx                                    context.Context
	cancel                                 context.CancelFunc
	theme                                  *material.Theme
	locale                                 appui.Locale
	activation                             widget.Editor
	hubAddress                             widget.Editor
	username                               widget.Editor
	password                               widget.Editor
	buttons                                map[appcore.ActionKind]*widget.Clickable
	profileButtons                         map[string]*widget.Clickable
	profileAddresses                       map[string]*widget.Editor
	pairButtons                            map[string]*widget.Clickable
	publicFields                           map[string]*publicFieldState
	workspacePage                          string
	workspaceButtons                       map[string]*widget.Clickable
	disclosures                            map[string]*disclosureState
	pairLabel                              widget.Editor
	pairBootstrapConsent                   widget.Bool
	pairSlotAConsent                       widget.Bool
	pairSlotBConsent                       widget.Bool
	pairRevokeConsent                      widget.Bool
	pairReviewID                           string
	pairStateReviewID                      string
	contentList                            widget.List
	canvasList                             widget.List
	langEN                                 widget.Clickable
	langZH                                 widget.Clickable
	previewButton                          widget.Clickable
	detailsButton                          widget.Clickable
	details                                bool
	consent                                widget.Bool
	nodeCode                               widget.Editor
	devicePairingCode                      widget.Editor
	pairingPoll                            nodePairingPollScheduler
	nodeIdentityConsent                    widget.Bool
	nodeAccessConsent                      widget.Bool
	nodeReviewID                           string
	nodePinDetails                         bool
	nodePinButton                          widget.Clickable
	inputScope                             appui.InputScope
	accountVisible                         bool
	replacementInput                       bool
	canvas                                 canvasWidget
	preview                                bool
	busy                                   atomic.Bool
	autoBusy                               atomic.Bool
	updates                                nodeStatusUpdater
	closed                                 atomic.Bool
	workerWG                               sync.WaitGroup
	statusMu                               sync.Mutex
	failed                                 bool
	uiErrorCode                            string

	localDomainNetworkName   widget.Editor
	localDomainGroupName     widget.Editor
	localDomainExpiry        widget.Enum
	localDomainConsent       widget.Bool
	localDomainRevokeConsent widget.Bool
	localDomainNodeID        string
	localDomainNetworkChoice widget.Enum
	localDomainReviewID      string
	localDomainStateReviewID string
	threadGroupsScope        string
	threadGroupReviewID      string
	threadGroupName          widget.Editor
	threadGroupSearch        widget.Editor
	threadGroupDuration      widget.Enum
	threadGroupConsent       widget.Bool
}

func newView(controller appcore.Controller, ctx context.Context, cancel context.CancelFunc, window nativeWindow) *view {
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
		publicFields:   make(map[string]*publicFieldState),
	}
	configureNativeFonts(v.theme)
	// Layout dimensions use dp/sp so Windows scaling applies to text and controls.
	v.theme.Bg = appSurface
	v.theme.Fg = appInk
	v.theme.ContrastBg = appInk
	v.theme.TextSize = 14
	v.theme.ContrastFg = color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	v.contentList.Axis = layout.Vertical
	v.activation.Mask = '•'
	v.activation.SingleLine, v.username.SingleLine, v.password.SingleLine = true, true, true
	v.hubAddress.SingleLine, v.hubAddress.MaxLen = true, 128
	v.activation.MaxLen = appui.ActivationCodeInputLimit()
	v.nodeCode.SingleLine, v.nodeCode.MaxLen = true, 32
	v.devicePairingCode = newDevicePairingEditor()
	v.username.MaxLen, v.password.MaxLen = 128, 1024
	v.pairLabel.MaxLen, v.pairLabel.SingleLine = 128, true
	v.activation.InputHint = 1
	v.username.InputHint = 1
	v.password.Mask = '•'
	v.password.Submit = true
	v.password.InputHint = 2
	return v
}

func (v *view) layout(gtx layout.Context) {
	paint.Fill(gtx.Ops, v.theme.Bg)
	raw := v.controller.Snapshot()
	if v.scopeChanging.Load() {
		raw = appui.HubTransitionSnapshot(raw)
	}
	now := time.Now()
	presentation := appui.PresentScreen(raw, now)
	if appui.ResetPresentationInputs(v.inputScope, v.accountVisible, raw, now) {
		v.resetPresentationInputs()
	}
	v.inputScope, v.accountVisible = appui.InputScopeFor(raw), presentation.InformationVisible
	snapshot := presentation.Snapshot
	scheduleSnapshotRedraw(gtx, raw, now)
	flow := presentation.Flow
	if presentation.InformationVisible {
		flow = v.updates.accountFlow(snapshot, now)
		if v.workspacePage == "devices" && !v.hubConnections {
			updateDevicePairingEditor(gtx, &v.devicePairingCode, snapshot, now, v.busy.Load() || v.closed.Load(), func(code string) {
				v.devicePairingCode.SetText("")
				v.startDispatch(appcore.Action{Kind: appcore.ActionReviewNodePairing, DevicePairingCode: code})
			})
		}
	}
	v.shellLayout(gtx, snapshot, presentation.InformationVisible, flow)
	// Foreground controls above have already processed this frame's clicks.
	// The background due decision can neither block them nor issue I/O here.
	if presentation.InformationVisible {
		v.scheduleNodePairingPoll(gtx, raw)
		v.scheduleAutomaticNodeStatus(gtx)
	} else {
		v.pairingPoll.reset()
		v.updates.pauseForAccountScreen()
	}
}

func (v *view) statusCard(gtx layout.Context, s appcore.Snapshot) layout.Dimensions {
	return v.card(gtx, func(gtx layout.Context) layout.Dimensions {
		rows := []layout.FlexChild{
			layout.Rigid(v.headingRow(v.phaseLabel(s.Phase))),
		}
		if s.Hub.Address != "" {
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(s.Hub.Address, 128))))
		} else if s.Hub.Origin != "" {
			rows = append(rows, layout.Rigid(v.labelRow(safeDisplay(s.Hub.Origin, 256))))
		}
		transportLabel := ""
		switch s.Hub.TransportState {
		case appcore.HubTransportVerifying:
			transportLabel = "connection.transport_verifying"
		case appcore.HubTransportVerified:
			transportLabel = "connection.transport_verified"
		case appcore.HubTransportFailed:
			transportLabel = "connection.transport_failed"
		}
		if transportLabel != "" {
			rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, transportLabel))))
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
			rows = append(rows, v.publicFieldRows("account/", appui.AccountPublicFields(s, time.Now()))...)
			if s.Node.Available && s.Setup.Purpose != "" {
				rows = append(rows, layout.Rigid(v.labelRow(appui.Text(v.locale, "authorization.initial")+": "+v.authorizationLabel(s.Authorization.State))))
			}
		}
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx, rows...)
	})
}

func (v *view) contentRows(s appcore.Snapshot, flow appui.SetupFlow, informationVisible, managementAuthorized bool, objects []appui.CanvasObject, preview, includeActions bool) []layout.Widget {
	if v.hubConnections {
		return v.hubConnectionRows(s)
	}
	if v.replacementInput && s.Setup.ReplacementAllowed {
		flow = appui.SetupFlow{Stage: "replace", Primary: appcore.ActionConnect}
	}
	var rows []layout.Widget
	switch flow.Stage {
	case "app-rebind":
		return append(rows, v.appBindingRows(s, appcore.ActionRebindApp, includeActions)...)
	case "app-binding-recovery":
		return append(rows, v.appBindingRows(s, appcore.ActionRecoverAppBinding, includeActions)...)
	case "profile-recovery":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.profile_recovery_title")), v.labelRow(appui.Text(v.locale, "setup.profile_recovery_body")))
		for index, profile := range s.Profiles {
			if !profile.Removed {
				rows = append(rows, v.profileRow(profile, index))
			}
		}
	case "connect":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.welcome")), v.labelRow(appui.Text(v.locale, "setup.welcome_body")))
		if len(s.Profiles) > 0 {
			rows = append(rows, v.headingRow(appui.Text(v.locale, "connection.saved_profiles")))
			for index, profile := range s.Profiles {
				if !profile.Removed {
					rows = append(rows, v.profileRow(profile, index))
				}
			}
		}
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_connect")))
		rows = append(rows, v.connectionInputRows()...)
	case "keys":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_keys")), v.labelRow(appui.Text(v.locale, "setup.keys_body")))
	case "replace":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.replacement_code")), v.labelRow(appui.Text(v.locale, "setup.replacement_body")))
		rows = append(rows, v.connectionInputRows()...)
	case "activate":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.activate_app")), v.labelRow(appui.Text(v.locale, "setup.grant_body")))
		if expiry, err := time.Parse(time.RFC3339Nano, s.Setup.AuthorizationDeadline); err == nil {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "authorization.until")+" "+expiry.Local().Format("15:04")))
		}
	case "account":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "setup.step_account")))
	case "login":
		rows = append(rows, v.headingRow(appui.Text(v.locale, "account.login")), v.labelRow(appui.Text(v.locale, "setup.login_body")))
		if s.AppBinding.State == appcore.AppBindingBoundZero {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "binding.bound_zero")))
		}
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
			style.Background = workspaceMutedSurface
			style.Color = v.theme.Fg
			return style.Layout(gtx)
		})
	}
	if flow.Username {
		rows = append(rows, v.editorRow(&v.username, appui.Text(v.locale, "account.username"), false))
	}
	if flow.Password {
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			updatePasswordEditor(gtx, &v.password, v.username.Text(), s, flow, v.busy.Load() || v.closed.Load(), func() {
				if action, ok := v.actionFor(flow.Primary, s); ok {
					v.startDispatch(action)
				}
			})
			return v.editorRow(&v.password, appui.Text(v.locale, "account.password"), true)(gtx)
		})
	}
	if flow.LimitedConsent {
		rows = append(rows, func(gtx layout.Context) layout.Dimensions {
			if v.busy.Load() {
				gtx = gtx.Disabled()
			}
			return material.CheckBox(v.theme, &v.consent, appui.Text(v.locale, "setup.grant_consent")).Layout(gtx)
		})
	}
	if includeActions {
		rows = append(rows, v.setupActionRows(s, flow, informationVisible)...)
	}
	if informationVisible && v.workspacePage == "devices" && appui.NodeCardVisible(s, flow) {
		rows = append(rows, v.nodeSection(s))
	}
	if informationVisible && v.workspacePage == "sessions" && appui.PairFlow(s, time.Now()).Visible {
		rows = append(rows, v.pairSection(s))
	}
	if informationVisible && flow.Stage == "ready" {
		if !s.Node.Available && !s.Node.Pending {
			rows = append(rows, v.labelRow(appui.Text(v.locale, "account.management_disabled")), v.canvasSection(s, managementAuthorized, objects, preview))
		}
	}
	return rows
}

func (v *view) setupActionRows(s appcore.Snapshot, flow appui.SetupFlow, informationVisible bool) []layout.Widget {
	var rows []layout.Widget
	if flow.Stage == "app-rebind" || flow.Stage == "app-binding-recovery" {
		kind, key := appcore.ActionRebindApp, "binding.rebind"
		if flow.Stage == "app-binding-recovery" {
			kind, key = appcore.ActionRecoverAppBinding, "binding.recover"
		}
		if hasAction(s, kind) {
			rows = append(rows, v.actionButton(kind, appui.Text(v.locale, key), s))
		}
		return rows
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
	for _, kind := range flow.Secondary {
		if label, ok := v.actionLabel(kind); ok {
			if kind == appcore.ActionConnect && s.Setup.ReplacementAllowed {
				label = appui.Text(v.locale, "setup.replacement_code")
			}
			rows = append(rows, v.actionButton(kind, label, s))
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

func (v *view) connectionInputRows() []layout.Widget {
	return []layout.Widget{v.editorRow(&v.hubAddress, appui.Text(v.locale, "connection.hub_address"), false),
		v.editorRow(&v.activation, appui.Text(v.locale, "connection.bootstrap_code"), false)}
}

func (v *view) resetPresentationInputs() {
	v.appBindingReview, v.appBindingConsent.Value = "", false
	v.profileRemovalID, v.profileRemovalReview = "", ""
	v.profileRemoveConsent.Value = false
	v.profileAddresses = make(map[string]*widget.Editor)
	v.publicFields = make(map[string]*publicFieldState)
	v.workspacePage = "overview"
	v.workspaceButtons = make(map[string]*widget.Clickable)
	v.disclosures = make(map[string]*disclosureState)
	v.activation.SetText("")
	v.hubAddress.SetText("")
	v.username.SetText("")
	v.password.SetText("")
	v.nodeCode.SetText("")
	v.devicePairingCode.SetText("")
	v.consent.Value = false
	v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
	v.nodeReviewID = ""
	v.pairingPoll.reset()
	v.pairLabel.SetText("")
	v.pairBootstrapConsent.Value, v.pairSlotAConsent.Value, v.pairSlotBConsent.Value, v.pairRevokeConsent.Value = false, false, false, false
	v.pairReviewID, v.pairStateReviewID = "", ""
	v.localDomainNetworkName.SetText("")
	v.localDomainGroupName.SetText("")
	v.localDomainNodeID, v.localDomainReviewID, v.localDomainStateReviewID = "", "", ""
	v.localDomainConsent.Value, v.localDomainRevokeConsent.Value = false, false
	v.localDomainExpiry.Value = "until"
	v.threadGroupsScope, v.threadGroupReviewID = "", ""
	v.threadGroupName.SetText("")
	v.threadGroupSearch.SetText("")
	v.threadGroupDuration.Value = "until_revoked"
	v.threadGroupConsent.Value = false
	v.nodePinDetails = false
	v.details, v.preview, v.replacementInput = false, false, false
	v.canvas = canvasWidget{}
	v.contentList.Position, v.canvasList.Position, v.navigationList.Position = layout.Position{}, layout.Position{}, layout.Position{}
}

func (v *view) actionButton(kind appcore.ActionKind, label string, s appcore.Snapshot, selectedFlow ...appui.SetupFlow) layout.Widget {
	button := v.buttons[kind]
	if button == nil {
		button = new(widget.Clickable)
		v.buttons[kind] = button
	}
	return func(gtx layout.Context) layout.Dimensions {
		enabled := !v.busy.Load() && (kind != appcore.ActionActivateApp || v.consent.Value)
		if kind == appcore.ActionUnbindApp || kind == appcore.ActionRebindApp {
			enabled = enabled && hasAction(s, kind) && v.appBindingConsent.Value && v.appBindingReview != "" && v.appBindingReview == s.AppBinding.ReviewID
		}
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
			if kind == appcore.ActionConnect && strings.TrimSpace(v.hubAddress.Text()) == "" {
				enabled = false
			}
		}
		if button.Clicked(gtx) && enabled {
			if kind == appcore.ActionConnect && s.Hub.Verified && s.Setup.ReplacementAllowed && !v.replacementInput && appui.Flow(s).Stage != "replace" {
				v.replacementInput = true
				v.hubAddress.SetText(s.Hub.Address)
				v.activation.SetText("")
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
			style.Background = workspaceMutedSurface
			style.Color = v.theme.Fg
			style.CornerRadius = 8
			style.Inset = layout.Inset{Top: 10, Bottom: 10, Left: 16, Right: 16}
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
	case appcore.ActionUnbindApp, appcore.ActionRebindApp:
		action, confirmed := appui.ConfirmAppBinding(s, kind, v.appBindingReview, v.appBindingConsent.Value)
		v.appBindingConsent.Value = false
		return action, confirmed
	case appcore.ActionRecoverAppBinding:
		return action, hasAction(s, kind)
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
		address := v.hubAddress.Text()
		if strings.TrimSpace(address) == "" {
			return appcore.Action{}, false
		}
		v.replacementInput = false
		v.consent.Value = false
		action, ready := appui.ConnectionInputAction(address, v.activation.Text())
		v.activation.SetText("")
		return action, ready
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
	case appcore.ActionRecoverLocalCollaboration, appcore.ActionRecoverPair, appcore.ActionRecover, appcore.ActionRefresh, appcore.ActionActivationStatus, appcore.ActionDiscoverProfiles, appcore.ActionGenerateOwner, appcore.ActionClaimPrepare,
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
	switch action.Kind {
	case appcore.ActionUnbindApp, appcore.ActionRebindApp, appcore.ActionRecoverAppBinding:
		v.resetPresentationInputs()
		v.updates.pauseForAccountScreen()
	case appcore.ActionDiscoverProfiles:
		v.hubConnections = true
		fallthrough
	case appcore.ActionAddHub, appcore.ActionDisconnectHub, appcore.ActionConnect, appcore.ActionResumeProfile, appcore.ActionRestoreProfile, appcore.ActionRemoveProfile:
		v.scopeChanging.Store(true)
		v.resetPresentationInputs()
		v.updates.pauseForAccountScreen()
		if action.Kind == appcore.ActionAddHub || action.Kind == appcore.ActionResumeProfile || action.Kind == appcore.ActionRestoreProfile || action.Kind == appcore.ActionConnect {
			v.hubConnections = false
		}
		if action.Kind == appcore.ActionDisconnectHub {
			v.hubConnections = true
		}
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

	clearOwnerImport(action.OwnerImport)
	// Best-effort removal of secret-bearing references. Go strings cannot
	// guarantee physical zeroization, but they need not remain in this UI.
	action.Password = ""
	action.ActivationCode = ""
	action.Username = ""
	action.NodeCode = ""
	action.DevicePairingCode = ""
	action.BootstrapCode = ""
	v.statusMu.Lock()
	v.failed = err != nil
	v.uiErrorCode = ""
	v.statusMu.Unlock()
	v.updates.foregroundCompleted(v.controller.Snapshot(), time.Now(), action, err)
	v.scopeChanging.Store(false)
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
	v.devicePairingCode.SetText("")
	v.nodeIdentityConsent.Value, v.nodeAccessConsent.Value = false, false
	v.cancel()
}

func (v *view) actionLabel(kind appcore.ActionKind) (string, bool) {
	key := map[appcore.ActionKind]string{
		appcore.ActionConnect:               "connection.connect",
		appcore.ActionActivateApp:           "setup.activate_app",
		appcore.ActionLogin:                 "account.login",
		appcore.ActionSetupAccount:          "account.claim",
		appcore.ActionRecover:               "operation.recover_connection",
		appcore.ActionRecoverNode:           "operation.recover_connection",
		appcore.ActionRecoverPair:           "operation.recover_connection",
		appcore.ActionRecoverOwnerEndpoints: "directory.recover",
		appcore.ActionParkOwnerEndpoints:    "directory.park",
		appcore.ActionRefresh:               "account.refresh",
		appcore.ActionActivationStatus:      "account.refresh",
		appcore.ActionDiscoverProfiles:      "connection.discover_profiles",
		appcore.ActionGenerateOwner:         "account.generate_local_owner",
		appcore.ActionImportOwner:           "account.select_owner_files",
		appcore.ActionExportOwnerPublic:     "account.export_owner_public",
		appcore.ActionClaimPrepare:          "account.prepare_claim",
		appcore.ActionClaimComplete:         "account.complete_claim",
		appcore.ActionLoginPrepare:          "account.start_login",
		appcore.ActionLoginComplete:         "account.login",
		appcore.ActionSessionInspect:        "account.refresh",
		appcore.ActionLogout:                "account.logout",
		appcore.ActionRetry:                 "operation.recover_exact",

		appcore.ActionRecoverLocalCollaboration: "local_collaboration.recover",
	}
	label, ok := key[kind]
	return appui.Text(v.locale, label), ok
}

func (v *view) button(gtx layout.Context, button *widget.Clickable, label string, enabled bool) layout.Dimensions {
	style := material.Button(v.theme, button, label)
	style.CornerRadius = 8
	style.Inset = layout.Inset{Top: 10, Bottom: 10, Left: 16, Right: 16}
	if !enabled {
		gtx = gtx.Disabled()
		style.Background = selectedSurface
		style.Color = mutedInk
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
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Inset{Bottom: 8}.Layout(gtx, v.nodeCaption(hint))
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				line := appLine
				if gtx.Focused(editor) {
					line = appInk
				}
				return widget.Border{Color: line, CornerRadius: 8, Width: 1}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.UniformInset(12).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Min.Y = 0
						if editor.SingleLine {
							gtx.Constraints.Max.Y = min(gtx.Constraints.Max.Y, gtx.Dp(24))
						}
						style := material.Editor(v.theme, editor, "")
						style.TextSize = unit.Sp(14)
						return style.Layout(gtx)
					})
				})
			}),
		)
	}
}

func (v *view) labelRow(label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		style := material.Body1(v.theme, label)
		style.TextSize = 14
		style.LineHeight = 20
		return style.Layout(gtx)
	}
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
			return v.secondaryButton(gtx, &v.previewButton, label, true)
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
			defer clip.UniformRRect(image.Rectangle{Max: gtx.Constraints.Min}, gtx.Dp(8)).Push(gtx.Ops).Pop()
			paint.Fill(gtx.Ops, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
			return layout.Dimensions{Size: gtx.Constraints.Min}
		}),
		layout.Stacked(func(gtx layout.Context) layout.Dimensions { return layout.UniformInset(20).Layout(gtx, content) }),
	)
}

func (v *view) headingRow(label string) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		style := material.H6(v.theme, label)
		style.TextSize = 16
		return style.Layout(gtx)
	}
}

func (v *view) profileRow(profile appcore.ProfileSnapshot, index int) layout.Widget {
	return v.hubProfileRow(profile, index)
}

func (v *view) authorizationLabel(state string) string {
	key := map[string]string{"ACTIVE": "authorization.active", "LOGIN_REQUIRED": "authorization.login_required", "RECHECK_REQUIRED": "authorization.recheck_required", "EXPIRED": "authorization.expired", "REVOKED": "authorization.revoked", "UNAVAILABLE": "authorization.unavailable", "UNCONFIRMED": "authorization.unconfirmed"}[state]
	if key == "" {
		key = "authorization.unconfirmed"
	}
	return appui.Text(v.locale, key)
}
