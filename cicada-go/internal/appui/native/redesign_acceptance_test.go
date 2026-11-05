package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
)

// Independent acceptance uses the actual production view, Gio clips and
// input.Router. The Controller is an inert synthetic boundary: no network,
// private keys, Runtime, services or model calls are involved in UI geometry.
type acceptanceController struct {
	snapshot appcore.Snapshot
	actions  chan appcore.Action
}

func (c *acceptanceController) Snapshot() appcore.Snapshot { return c.snapshot }
func (c *acceptanceController) Dispatch(_ context.Context, a appcore.Action) error {
	c.actions <- a
	return nil
}
func (*acceptanceController) Close() error { return nil }

type acceptanceWindow struct{}

func (acceptanceWindow) Invalidate() {}

func acceptanceSnapshot() appcore.Snapshot {
	return appcore.Snapshot{
		Hub: appcore.HubSnapshot{Verified: true, Origin: "https://SYNTHETIC.invalid", HubID: "SYNTHETIC-hub", Fingerprint: strings.Repeat("a", 64), Address: "127.0.0.1:8787"},
		Account: appcore.AccountSnapshot{AccountID: "SYNTHETIC-account", OwnerID: "SYNTHETIC-owner", DeviceID: "SYNTHETIC-app", State: appcore.AccountStateSessionActive,
			SessionExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), RootState: appcore.RootStateActive},
		Node:             appcore.NodeSetupSnapshot{Available: true, Pairing: &appcore.NodePairingSnapshot{Available: true, Availability: "AVAILABLE", State: "CODE", ReviewID: "SYNTHETIC-exact-review"}},
		AvailableActions: []appcore.ActionKind{appcore.ActionReviewNodePairing},
	}
}

func acceptanceView(t *testing.T, snapshot appcore.Snapshot) (*view, *input.Router, *acceptanceController) {
	t.Helper()
	c := &acceptanceController{snapshot: snapshot, actions: make(chan appcore.Action, 32)}
	ctx, cancel := context.WithCancel(context.Background())
	v := newView(c, ctx, cancel, acceptanceWindow{})
	v.theme.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	t.Cleanup(func() { v.closed.Store(true); cancel(); v.workerWG.Wait() })
	return v, new(input.Router), c
}

func acceptanceFrame(v *view, router *input.Router, size image.Point, scale float32) (*op.Ops, []input.SemanticNode) {
	ops := new(op.Ops)
	gtx := layout.Context{Ops: ops, Source: router.Source(), Metric: unit.Metric{PxPerDp: scale, PxPerSp: scale}, Now: time.Now(), Constraints: layout.Exact(size)}
	v.layout(gtx)
	router.Frame(ops)
	return ops, router.AppendSemantics(nil)
}

func acceptanceDevices(t *testing.T, snapshot appcore.Snapshot, size image.Point, scale float32) (*view, *input.Router, *acceptanceController) {
	t.Helper()
	v, router, controller := acceptanceView(t, snapshot)
	// The first frame deliberately performs the production privacy/input-scope
	// reset. Only then navigate to Devices, as a real signed-in user would.
	acceptanceFrame(v, router, size, scale)
	v.workspacePage = "devices"
	v.contentList.Position = layout.Position{}
	return v, router, controller
}

func acceptanceButton(nodes []input.SemanticNode, label string) (input.SemanticDesc, bool) {
	for _, node := range nodes {
		if node.Desc.Class == semantic.Button {
			if acceptanceLabel(node.Children, label) {
				return node.Desc, true
			}
		}
		if found, ok := acceptanceButton(node.Children, label); ok {
			return found, true
		}
	}
	return input.SemanticDesc{}, false
}

func acceptanceLabel(nodes []input.SemanticNode, label string) bool {
	for _, node := range nodes {
		if node.Desc.Label == label || acceptanceLabel(node.Children, label) {
			return true
		}
	}
	return false
}

type acceptanceLayoutCase struct {
	Name, State, Error, Expiry string
	Action                     appcore.ActionKind
	Label                      string
	Long, Overflow, Busy       bool
}

func acceptanceLayoutCases() []acceptanceLayoutCase {
	future, past := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)
	return []acceptanceLayoutCase{
		{Name: "code", State: "CODE", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action"},
		{Name: "long-code", State: "CODE", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action", Long: true},
		{Name: "overflow", State: "CODE", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action", Long: true, Overflow: true},
		{Name: "busy", State: "CODE", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action", Busy: true},
		{Name: "error", State: "CODE", Error: "APP_NODE_PAIRING_UNKNOWN", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action"},
		{Name: "lookup", State: "LOOKUP", Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check"},
		{Name: "approving", State: "APPROVING", Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check"},
		{Name: "pending", State: "PENDING", Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check"},
		{Name: "waiting", State: "OWNER_APPROVED", Expiry: future, Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check"},
		{Name: "deadline", State: "OWNER_APPROVED", Expiry: past, Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check"},
		{Name: "review", State: "REVIEW", Expiry: future, Action: appcore.ActionApproveNodePairing, Label: "node_pairing.approve"},
		{Name: "expired-finish", State: "REVIEW", Expiry: past, Action: appcore.ActionCancelNodePairing, Label: "node_pairing.finish"},
		{Name: "fenced-finish", State: "FENCED", Error: "APP_NODE_PAIRING_UNKNOWN", Action: appcore.ActionCancelNodePairing, Label: "node_pairing.finish"},
		{Name: "fenced-read", State: "FENCED", Error: "APP_NODE_PAIRING_UNKNOWN", Action: appcore.ActionRefreshNodePairing, Label: "node_pairing.check_saved"},
		{Name: "uncertain-recover", State: "UNKNOWN", Error: "APP_NODE_PAIRING_UNKNOWN", Action: appcore.ActionRecoverNodePairing, Label: "node.recover"},
		{Name: "ended", State: "CANCELLED", Action: appcore.ActionReviewNodePairing, Label: "node_pairing.review_action"},
	}
}

func acceptanceCaseSnapshot(test acceptanceLayoutCase) appcore.Snapshot {
	s := acceptanceSnapshot()
	s.Node.Pairing.State, s.Node.Pairing.ErrorCode, s.Node.Pairing.ExpiresAt = test.State, test.Error, test.Expiry
	s.Node.Pairing.NodeID = strings.Repeat("SYNTHETIC-node-", 16)
	s.Node.Pairing.Name = "SYNTHETIC device with a long display name " + strings.Repeat("N", 128)
	s.AvailableActions = []appcore.ActionKind{test.Action}
	return s
}

var acceptanceCodes = struct {
	sync.Mutex
	values map[bool]string
}{values: make(map[bool]string)}

func acceptanceCode(t *testing.T, test acceptanceLayoutCase) string {
	t.Helper()
	acceptanceCodes.Lock()
	defer acceptanceCodes.Unlock()
	code := acceptanceCodes.values[test.Long]
	if code == "" {
		// Use the actual shared encoder with fresh synthetic identities. This
		// local parser fixture has no Hub signature or deployment authority.
		hubKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ncKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		nodeKey, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		origin, hubID, nodeID := "https://synthetic.invalid", "synthetic_ui_hub", "synthetic_ui_node"
		if test.Long {
			origin = "https://" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".synthetic.invalid"
			hubID, nodeID = "synthetic_"+strings.Repeat("h", 80), "synthetic_"+strings.Repeat("n", 80)
		}
		selector := "23456789ABCD"
		codeDigest, err := wire.AppNodeCodeDigest(hubID, selector)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		expires := now.Add(9 * time.Minute).Format(time.RFC3339Nano)
		context := wire.NodePairTrustScopedContext{
			ScopeVersion: 2, AuthorityNodeID: nodeID, Format: wire.NodePairTrustScopedFormat,
			AttemptID: strings.Repeat("a", 32), Hub: wire.HubIdentity{Contract: "android-hub-v1", HubID: hubID, Public: hubKey.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite},
			Origin: origin, DescriptorDigest: strings.Repeat("b", 64), NodeNonce: strings.Repeat("c", 64), Mode: wire.NodePairTrustScopedInitial,
			IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expires,
			Candidate: &e2ee.OwnerAppNodeCandidate{RequestID: "synthetic_ui_request", Version: 1, Mode: "INITIAL", State: "PENDING", HubID: hubID, NodeID: nodeID, NodeName: "SYNTHETIC UI device",
				NodePublic: nodeKey.Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(nodeKey.Public()), NodeKeyEpoch: 1,
				HubNodeControlPublic: ncKey.Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: nodewire.IdentityFingerprint(ncKey.Public()),
				CandidateDigest: strings.Repeat("d", 64), CodeDigest: codeDigest, ExpiresAt: expires},
		}
		secret := bytes.Repeat([]byte{0x63}, 32)
		code, err = wire.EncodeNodePairTrustScopedCode(context, selector, secret)
		clear(secret)
		if err != nil {
			t.Fatal("synthetic wire encoder fixture", err)
		}
		acceptanceCodes.values[test.Long] = code
	}
	if test.Overflow {
		code += strings.Repeat("A", devicePairingInputBytes+1-len(code))
	}
	return code
}

func TestAcceptanceDevicePrimaryGeometryAndPointer(t *testing.T) {
	var evidence []map[string]any
	defer func() { acceptanceWriteJSON(t, "device-primary-geometry.json", evidence) }()
	for _, test := range acceptanceLayoutCases() {
		for _, size := range []image.Point{image.Pt(640, 480), image.Pt(800, 600), image.Pt(1024, 768)} {
			for _, scale := range []float32{1, 1.5, 2} {
				t.Run(fmt.Sprintf("%s/%dx%d/%.1f", test.Name, size.X, size.Y, scale), func(t *testing.T) {
					v, router, controller := acceptanceDevices(t, acceptanceCaseSnapshot(test), size, scale)
					v.devicePairingCode.SetText(acceptanceCode(t, test))
					v.busy.Store(test.Busy)
					_, nodes := acceptanceFrame(v, router, size, scale)
					button, found := acceptanceButton(nodes, appui.Text(v.locale, test.Label))
					viewport := image.Rectangle{Max: size}
					reachable := found && !button.Bounds.Empty() && button.Bounds.In(viewport)
					evidence = append(evidence, map[string]any{"case": test.Name, "pixels": size, "scale": scale, "found": found, "bounds": button.Bounds, "disabled": button.Disabled, "in_viewport": reachable})
					if !reachable {
						t.Fatalf("production primary outside viewport: found=%v bounds=%v viewport=%v", found, button.Bounds, viewport)
					}
					if button.Disabled != (test.Busy || test.Overflow) {
						t.Fatalf("unexpected authorization/readiness: disabled=%v", button.Disabled)
					}
					point := f32.Pt(float32(button.Bounds.Min.X+button.Bounds.Dx()/2), float32(button.Bounds.Min.Y+button.Bounds.Dy()/2))
					router.Queue(pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: point}, pointer.Event{Kind: pointer.Release, Source: pointer.Mouse, Position: point})
					acceptanceFrame(v, router, size, scale)
					v.workerWG.Wait()
					select {
					case action := <-controller.actions:
						if test.Busy || test.Overflow || action.Kind != test.Action || action.NodePairingReviewID != "SYNTHETIC-exact-review" {
							t.Fatal("pointer bypassed readiness or dispatched another request", action.Kind)
						}
						if action.Kind == appcore.ActionReviewNodePairing && action.DevicePairingCode != acceptanceCode(t, test) {
							t.Fatal("pointer changed the exact case-sensitive code")
						}
					default:
						if !test.Busy && !test.Overflow {
							t.Fatal("visible enabled primary did not receive a real pointer click")
						}
					}
				})
			}
		}
	}
}

func TestAcceptanceDevicePasteReadinessAndEnter(t *testing.T) {
	for _, trigger := range []string{"paste", "return", "keypad-enter"} {
		t.Run(trigger, func(t *testing.T) {
			size := image.Pt(640, 480)
			v, router, controller := acceptanceDevices(t, acceptanceSnapshot(), size, 1)
			acceptanceFrame(v, router, size, 1)
			// Focus the real production editor through Gio's input command.
			router.Source().Execute(key.FocusCmd{Tag: &v.devicePairingCode})
			acceptanceFrame(v, router, size, 1)
			code := acceptanceCode(t, acceptanceLayoutCase{})
			router.Queue(key.EditEvent{Range: key.Range{}, Text: code})
			_, nodes := acceptanceFrame(v, router, size, 1)
			button, ok := acceptanceButton(nodes, appui.Text(v.locale, "node_pairing.review_action"))
			if !ok || button.Disabled {
				t.Fatal("paste did not enable the production primary in the same frame")
			}
			if trigger == "paste" {
				return
			}
			name := key.NameReturn
			if trigger == "keypad-enter" {
				name = key.NameEnter
			}
			router.Queue(key.Event{Name: name, State: key.Press}, key.Event{Name: name, State: key.Press}, key.Event{Name: name, State: key.Release})
			acceptanceFrame(v, router, size, 1)
			v.workerWG.Wait()
			select {
			case action := <-controller.actions:
				if action.Kind != appcore.ActionReviewNodePairing || action.DevicePairingCode != code {
					t.Fatal("Enter changed the exact review action/code", action.Kind)
				}
			default:
				t.Fatal("Enter did not submit the production device-code editor")
			}
			select {
			case <-controller.actions:
				t.Fatal("repeated Enter produced another authorization request")
			default:
			}
		})
	}
}

func TestAcceptanceDevicePrivacyAndUncertainRecovery(t *testing.T) {
	size := image.Pt(640, 480)
	s := acceptanceSnapshot()
	s.Account = appcore.AccountSnapshot{}
	s.Node.Pairing.Name = "SYNTHETIC_PRIVATE_DEVICE_NAME"
	s.Node.Pairing.NodeID = "SYNTHETIC_PRIVATE_NODE_ID"
	s.Node.Pairing.State = "REVIEW"
	s.Node.Pairing.ExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNodePairing}
	v, router, controller := acceptanceView(t, s)
	_, nodes := acceptanceFrame(v, router, size, 1)
	for _, secret := range []string{s.Node.Pairing.Name, s.Node.Pairing.NodeID, s.Node.Pairing.ReviewID, appui.Text(v.locale, "node_pairing.approve")} {
		if acceptanceLabel(nodes, secret) {
			t.Fatal("signed-out production semantics exposed device authority data")
		}
	}
	v.workerWG.Wait()
	if len(controller.actions) != 0 {
		t.Fatal("signed-out rendering dispatched a device operation")
	}

	s = acceptanceSnapshot()
	s.Node.Pairing.State, s.Node.Pairing.ErrorCode = "UNKNOWN", "APP_NODE_PAIRING_UNKNOWN"
	s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverNodePairing}
	v, router, controller = acceptanceDevices(t, s, size, 1)
	v.devicePairingCode.SetText("cicada-npts1.SYNTHETIC_fresh_code")
	_, nodes = acceptanceFrame(v, router, size, 1)
	if _, found := acceptanceButton(nodes, appui.Text(v.locale, "node_pairing.review_action")); found {
		t.Fatal("uncertain original request offered a new authorization")
	}
	if _, found := acceptanceButton(nodes, appui.Text(v.locale, "node_pairing.approve")); found {
		t.Fatal("uncertain original request offered fresh approval")
	}
	acceptanceFrame(v, router, size, 1)
	v.workerWG.Wait()
	if len(controller.actions) != 0 {
		t.Fatal("rendering automatically retried an uncertain mutation")
	}
}

func TestAcceptanceDeviceBlockedReadinessAndBusyEnter(t *testing.T) {
	for _, mode := range []string{"no-action", "root-pending", "unavailable", "busy"} {
		t.Run(mode, func(t *testing.T) {
			size := image.Pt(640, 480)
			s := acceptanceSnapshot()
			if mode != "busy" {
				s.AvailableActions = nil
			}
			if mode == "root-pending" {
				s.Account.RootState = appcore.RootStatePending
			}
			if mode == "unavailable" {
				s.Node.Pairing.Availability = "UNAVAILABLE"
			}
			v, router, controller := acceptanceDevices(t, s, size, 1)
			v.devicePairingCode.SetText(acceptanceCode(t, acceptanceLayoutCase{}))
			v.busy.Store(mode == "busy")
			_, nodes := acceptanceFrame(v, router, size, 1)
			if button, found := acceptanceButton(nodes, appui.Text(v.locale, "node_pairing.review_action")); found && !button.Disabled {
				t.Fatal("blocked account or busy editor offered an enabled review")
			}
			if mode != "busy" {
				key := "node_pairing.prerequisite"
				if mode == "unavailable" {
					key = "node_pairing.unavailable"
				}
				if !acceptanceLabel(nodes, appui.Text(v.locale, key)) {
					t.Fatal("blocked device form gave no reason or prerequisite")
				}
			}
			router.Source().Execute(key.FocusCmd{Tag: &v.devicePairingCode})
			acceptanceFrame(v, router, size, 1)
			router.Queue(key.Event{Name: key.NameReturn, State: key.Press}, key.Event{Name: key.NameReturn, State: key.Release})
			acceptanceFrame(v, router, size, 1)
			v.busy.Store(false)
			acceptanceFrame(v, router, size, 1)
			v.workerWG.Wait()
			if len(controller.actions) != 0 {
				t.Fatal("blocked/busy Enter was dispatched or deferred until re-enabled")
			}
		})
	}
}

func acceptanceWriteJSON(t *testing.T, name string, value any) {
	t.Helper()
	root := os.Getenv("CICADA_UI_ACCEPTANCE_OUTPUT")
	if root == "" {
		return
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(root, name), append(data, '\n'), 0600)
	}
	if err != nil {
		t.Error(err)
	}
}
