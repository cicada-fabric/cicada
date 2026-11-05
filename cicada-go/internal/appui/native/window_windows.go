//go:build windows

package native

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/font/opentype"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
	"github.com/cicada-ai/cicada/internal/appcore"
	"golang.org/x/sys/windows"
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

var nativeFonts struct {
	once   sync.Once
	faces  []font.FontFace
	family font.Typeface
}

// Load a bounded OS-provided CJK collection explicitly rather than relying on
// implicit system-family discovery. Failure leaves Gio's system fallback intact.
// Font loading happens during window construction, never in the frame loop.
func configureNativeFonts(theme *material.Theme) {
	nativeFonts.once.Do(func() {
		system, err := windows.GetWindowsDirectory()
		if err != nil || !filepath.IsAbs(system) || filepath.Clean(system) != system {
			return
		}
		const maxBytes = 64 << 20
		for _, name := range []string{"msyh.ttc", "simsun.ttc"} {
			path := filepath.Join(system, "Fonts", name)
			before, err := os.Lstat(path)
			if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > maxBytes {
				continue
			}
			wide, err := windows.UTF16PtrFromString(path)
			if err != nil {
				continue
			}
			attributes, err := windows.GetFileAttributes(wide)
			if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				continue
			}
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			opened, statErr := file.Stat()
			data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
			closeErr := file.Close()
			after, afterErr := os.Lstat(path)
			if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) || int64(len(data)) != before.Size() {
				continue
			}
			faces, err := opentype.ParseCollection(data)
			if err != nil || len(faces) == 0 || len(faces) > 32 {
				continue
			}
			for _, face := range faces {
				if face.Face == nil {
					continue
				}
				parsed := face.Face.Face()
				if parsed == nil {
					continue
				}
				if _, ok := parsed.NominalGlyph('中'); !ok {
					continue
				}
				nativeFonts.faces, nativeFonts.family = faces, face.Font.Typeface
				if strings.EqualFold(string(face.Font.Typeface), "Microsoft YaHei UI") {
					break
				}
			}
			if len(nativeFonts.faces) != 0 {
				return
			}
		}
	})
	if len(nativeFonts.faces) != 0 {
		theme.Shaper = text.NewShaper(text.WithCollection(nativeFonts.faces))
		theme.Face = nativeFonts.family
	}
}
