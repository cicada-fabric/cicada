//go:build linux && cicada_ui_acceptance

package native

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/gpu/headless"
	"gioui.org/text"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

// This opt-in test submits the production Gio op stream to the existing GPU
// headless backend and reads real pixels. It does not create a second UI or
// claim a Windows font, DPAPI, ACL, GUI, native input or physical-device pass.
func TestAcceptanceProductionPixels(t *testing.T) {
	output := os.Getenv("CICADA_UI_ACCEPTANCE_OUTPUT")
	if !filepath.IsAbs(output) {
		t.Fatal("set CICADA_UI_ACCEPTANCE_OUTPUT to an existing isolated absolute directory")
	}
	fonts := gofont.Collection()
	fontSHA := "Gio gofont; CJK physical rendering NOT_RUN"
	if path := os.Getenv("CICADA_UI_ACCEPTANCE_CJK_FONT"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		faces, err := opentype.ParseCollection(data)
		if err != nil {
			t.Fatal(err)
		}
		fonts = append(append([]font.FontFace{}, fonts...), faces...)
		digest := sha256.Sum256(data)
		fontSHA = hex.EncodeToString(digest[:])
	}
	var evidence []map[string]any
	defer func() { acceptanceWriteJSON(t, "production-pixels.json", evidence) }()
	for _, scene := range []struct {
		page   string
		size   image.Point
		scale  float32
		locale appui.Locale
	}{
		{"login", image.Pt(800, 600), 1, appui.English},
		{"overview", image.Pt(1024, 768), 1, appui.English},
		{"device-long-code", image.Pt(1024, 768), 1, appui.English},
		{"device-recovery", image.Pt(800, 600), 1.5, appui.English},
		{"device-review", image.Pt(1024, 768), 1, appui.English},
		{"sessions", image.Pt(1024, 768), 1, appui.English},
		{"identity", image.Pt(1024, 768), 1, appui.English},
		{"settings", image.Pt(1024, 768), 1, appui.English},
		{"hub-selection", image.Pt(1024, 768), 1, appui.English},
		{"devices", image.Pt(640, 480), 2, appui.Chinese},
		{"device-error", image.Pt(800, 600), 1.5, appui.Chinese},
		{"overview", image.Pt(1024, 768), 2, appui.Chinese},
	} {
		page, size, scale, locale := scene.page, scene.size, scene.scale, scene.locale
		name := fmt.Sprintf("%s-%dx%d-%.1f-%s", page, size.X, size.Y, scale, locale)
		t.Run(name, func(t *testing.T) {
			s := acceptanceSnapshot()
			if page == "login" {
				s.Account = appcore.AccountSnapshot{}
				s.AvailableActions = []appcore.ActionKind{appcore.ActionLogin}
			}
			if page == "device-recovery" {
				s.Node.Pairing.State, s.Node.Pairing.ErrorCode = "UNKNOWN", "APP_NODE_PAIRING_UNKNOWN"
				s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverNodePairing}
			}
			if page == "device-error" {
				s.Node.Pairing.ErrorCode = "APP_NODE_PAIRING_UNKNOWN"
			}
			if page == "device-review" {
				s.Node.Pairing.State = "REVIEW"
				s.Node.Pairing.Name = "SYNTHETIC reviewed device"
				s.Node.Pairing.ExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
				s.AvailableActions = []appcore.ActionKind{appcore.ActionApproveNodePairing}
			}
			if page == "hub-selection" {
				s.AvailableActions = []appcore.ActionKind{appcore.ActionAddHub, appcore.ActionDiscoverProfiles, appcore.ActionDisconnectHub}
			}
			if page == "settings" || page == "hub-selection" {
				s.Profiles = []appcore.ProfileSnapshot{{ID: "synthetic_saved_hub", Origin: "https://saved.synthetic.invalid", HubID: "SYNTHETIC saved Hub", Address: "192.0.2.25:8787", Direct: true, AccountID: "SYNTHETIC-account", OwnerID: "SYNTHETIC-owner"}}
			}
			if page == "sessions" {
				// Presentation only: these explicitly synthetic Owner/Root fields
				// supply no cryptographic authority and never reach a real Core.
				s.Account.State, s.Account.RootState, s.Account.LocalOwnerKeyPresent = appcore.AccountStateOwnerReady, appcore.RootStateActive, true
				s.Node.Binding = &appcore.NodeBindingSnapshot{ID: "synthetic_binding", NodeID: "synthetic_node", Name: "SYNTHETIC workstation"}
				relation := appcore.ThreadGroupRelation{GroupID: "synthetic_group", Name: "SYNTHETIC review group", State: "ACTIVE", KeyState: "CURRENT", OwnerMode: "UNTIL_REVOKED", CanRemove: true, GestureID: "synthetic_relation"}
				advisor := appcore.GroupThreadView{EndpointID: "synthetic_advisor", Name: "SYNTHETIC Advisor", Workspace: "/synthetic/project", Harness: "Codex", GestureID: "synthetic_advisor_review", Relations: []appcore.ThreadGroupRelation{relation}, RelationsComplete: true}
				worker := appcore.GroupThreadView{EndpointID: "synthetic_worker", Name: "SYNTHETIC Worker", Workspace: "/synthetic/project/tests", Harness: "Codex", GestureID: "synthetic_worker_review", Relations: []appcore.ThreadGroupRelation{relation}, RelationsComplete: true}
				s.ThreadGroups = appcore.ThreadGroupsSnapshot{AvailabilityKnown: true, Available: true, Current: true, NodeID: "synthetic_node", NodeName: "SYNTHETIC workstation", NetworkID: "synthetic_network", NetworkName: "SYNTHETIC private network", CapturedAt: time.Now().Format(time.RFC3339Nano), FreshUntil: time.Now().Add(time.Hour).Format(time.RFC3339Nano), GestureID: "synthetic_groups", Threads: []appcore.GroupThreadView{advisor, worker}, Selected: &advisor}
				s.AvailableActions = []appcore.ActionKind{appcore.ActionReadThreadGroups, appcore.ActionReadThreadRelations, appcore.ActionReadGroupCandidates, appcore.ActionPrepareThreadGroup}
			}
			v, router, _ := acceptanceDevices(t, s, size, scale)
			v.locale = locale
			v.theme.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(fonts))
			v.workspacePage = page
			if page == "device-long-code" || page == "device-error" || page == "device-recovery" || page == "device-review" {
				v.workspacePage = "devices"
			}
			if page == "hub-selection" {
				v.hubConnections = true
			}
			v.devicePairingCode.SetText(acceptanceCode(t, acceptanceLayoutCase{Long: page == "device-long-code"}))
			ops, nodes := acceptanceFrame(v, router, size, scale)
			window, err := headless.NewWindow(size.X, size.Y)
			if err != nil {
				t.Fatal("actual headless GPU context unavailable", err)
			}
			defer window.Release()
			if err := window.Frame(ops); err != nil {
				t.Fatal(err)
			}
			pixels := image.NewRGBA(image.Rectangle{Max: size})
			if err := window.Screenshot(pixels); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(output, name+".png")
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			encodeErr := png.Encode(file, pixels)
			closeErr := file.Close()
			if encodeErr != nil || closeErr != nil {
				t.Fatal(encodeErr, closeErr)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			evidence = append(evidence, map[string]any{"file": filepath.Base(path), "sha256": hex.EncodeToString(digest[:]), "bytes": len(data), "pixels": size, "scale": scale, "locale": locale, "page": page, "font_sha256": fontSHA, "renderer": "production Gio op stream / gpu.headless", "Windows_physical": "NOT_RUN"})
			acceptanceWriteJSON(t, name+".semantics.json", nodes)
		})
	}
}
