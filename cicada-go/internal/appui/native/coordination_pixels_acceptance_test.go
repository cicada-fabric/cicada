//go:build linux && cicada_ui_acceptance

package native

import (
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
	"gioui.org/gpu/headless"
	"gioui.org/io/semantic"
	"gioui.org/text"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Representative changed scenes only. Actual Controller/crypto acceptance is
// separate; these explicitly synthetic snapshots exercise production Gio ops,
// input and EGL pixels without claiming physical Windows/IME/font acceptance.
func TestCoordinationProductionPixels(t *testing.T) {
	output := os.Getenv("CICADA_UI_ACCEPTANCE_OUTPUT")
	fontPath := os.Getenv("CICADA_UI_ACCEPTANCE_CJK_FONT")
	if !filepath.IsAbs(output) || !filepath.IsAbs(fontPath) {
		t.Fatal("set isolated absolute CICADA_UI_ACCEPTANCE_OUTPUT and CJK font fixture paths")
	}
	fontData, err := os.ReadFile(fontPath)
	if err != nil {
		t.Fatal(err)
	}
	faces, err := opentype.ParseCollection(fontData)
	if err != nil {
		t.Fatal(err)
	}
	fontDigest := sha256.Sum256(fontData)
	var evidence []map[string]any
	defer func() { acceptanceWriteJSON(t, "coordination-pixels.json", evidence) }()
	for _, scene := range []struct {
		name, mode string
		size       image.Point
		scale      float32
		locale     appui.Locale
	}{
		{"role-review-en", wire.ThreadCollaborationSetClassification, image.Pt(1100, 1200), 1, appui.English},
		{"clear-review-zh-narrow", wire.ThreadCollaborationClearOneSlot, image.Pt(640, 480), 2, appui.Chinese},
		{"policy-review-en", wire.ThreadCollaborationEnableGroupPolicy, image.Pt(800, 600), 1.5, appui.English},
		{"role-picker-zh", "role-picker", image.Pt(1100, 1200), 1, appui.Chinese},
		{"slot-eight-zh-narrow", "slot-eight", image.Pt(640, 480), 2, appui.Chinese},
		{"original-recovery-en-narrow", "recovery", image.Pt(640, 480), 2, appui.English},
	} {
		t.Run(scene.name, func(t *testing.T) {
			s := coordinationReviewSnapshot(scene.mode)
			s.Coordination.Review.Details = []appcore.CoordinationDetail{{Key: "operation_id", Value: "SYNTHETIC-review-operation"}, {Key: "source_epoch", Value: "7"}}
			if scene.mode == "role-picker" || scene.mode == "slot-eight" {
				s = groupLockLayoutSnapshot()
				s.AvailableActions = []appcore.ActionKind{appcore.ActionPrepareCoordination}
				s.ThreadGroups.Selected.Classification = &appcore.ThreadClassificationView{Current: true, State: "CURRENT", Classification: "worker", ActiveGroups: 1, CanChange: true, GestureID: "SYNTHETIC-role-source"}
				b := s.ThreadGroups.Selected.Relations[0].Locks
				b.PolicyState = "ENABLED"
				b.Slots[7] = appcore.GroupLockSlotView{Number: 8, Version: 8, Generation: 2, State: appcore.GroupLockHeld, HolderName: "示例成员八", Purpose: "示例协作用途", ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano), CanClear: true, GestureID: "SYNTHETIC-slot-eight"}
			}
			if scene.mode == "recovery" {
				s.Coordination = appcore.CoordinationSnapshot{Pending: true, ErrorCode: "ORIGINAL_OUTCOME_UNCERTAIN"}
				s.AvailableActions = []appcore.ActionKind{appcore.ActionRecoverCoordination}
			}
			v, router := newLayoutView(t, s)
			v.locale = scene.locale
			v.theme.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(append(gofont.Collection(), faces...)))
			layoutFrame(v, router, scene.size, scene.scale)
			v.workspacePage = "sessions"
			nodes := layoutFrame(v, router, scene.size, scene.scale)
			switch scene.mode {
			case "role-picker":
				nodes = scrollLockLabel(t, v, router, scene.size, scene.scale, appui.Text(v.locale, "coord.change_role"), true)
				d, _ := findSemantic(nodes, appui.Text(v.locale, "coord.change_role"))
				queueVisualClick(router, d.Bounds)
				layoutFrame(v, router, scene.size, scene.scale)
			case "slot-eight":
				nodes = scrollLockLabel(t, v, router, scene.size, scene.scale, appui.Text(v.locale, "locks.show"), true)
				d, _ := findSemantic(nodes, appui.Text(v.locale, "locks.show"))
				queueVisualClick(router, d.Bounds)
				layoutFrame(v, router, scene.size, scene.scale)
				scrollLockLabel(t, v, router, scene.size, scene.scale, appui.Text(v.locale, "coord.clear"), true)
			case "recovery":
				d, ok := findSemantic(nodes, appui.Text(v.locale, "coord.recover"))
				if !ok || d.Disabled || !d.Bounds.In(image.Rectangle{Max: scene.size}) {
					t.Fatal("original recovery footer is unreachable")
				}
			default:
				consent, ok := coordinationControl(nodes, appui.Text(v.locale, "coord.consent"), semantic.CheckBox)
				if !ok || !consent.Bounds.In(image.Rectangle{Max: scene.size}) {
					t.Fatal("CJK consent footer is clipped")
				}
				if scene.mode == wire.ThreadCollaborationSetClassification {
					queueVisualClick(router, consent.Bounds)
					layoutFrame(v, router, scene.size, scene.scale)
				}
			}
			ops, nodes := acceptanceFrame(v, router, scene.size, scene.scale)
			window, err := headless.NewWindow(scene.size.X, scene.size.Y)
			if err != nil {
				t.Fatal("actual EGL context unavailable", err)
			}
			defer window.Release()
			if err := window.Frame(ops); err != nil {
				t.Fatal(err)
			}
			pixels := image.NewRGBA(image.Rectangle{Max: scene.size})
			if err := window.Screenshot(pixels); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(output, scene.name+".png")
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			encodeErr, closeErr := png.Encode(file, pixels), file.Close()
			if encodeErr != nil || closeErr != nil {
				t.Fatal(encodeErr, closeErr)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			evidence = append(evidence, map[string]any{"file": filepath.Base(path), "sha256": hex.EncodeToString(digest[:]), "bytes": len(data), "size": scene.size, "scale": scene.scale, "locale": scene.locale, "font_sha256": hex.EncodeToString(fontDigest[:]), "renderer": "production Gio op stream / gpu.headless", "Windows_physical": "NOT_RUN"})
			acceptanceWriteJSON(t, scene.name+".semantics.json", nodes)
		})
	}
}
