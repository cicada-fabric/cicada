package native

import (
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/widget"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The approved single-code UI budget. Protocol parsing belongs to the shared
// typed codec; this helper only prepares case-preserving input for that parser.
const devicePairingInputBytes = wire.MaxNodePairTrustScopedCodeBytes

func newDevicePairingEditor() widget.Editor {
	return widget.Editor{SingleLine: true, Submit: true, Mask: '•', MaxLen: devicePairingInputBytes + 1}
}

func devicePairingInput(editor *widget.Editor) (string, bool) {
	code := strings.TrimSpace(editor.Text())
	limit := devicePairingInputBytes
	// Keep one overflow rune in the editor so a pasted oversized code cannot
	// silently become a valid maximum-length code through widget truncation.
	return code, strings.HasPrefix(code, wire.NodePairTrustScopedCodePrefix) && len(code) <= limit
}

func devicePairingReady(editor *widget.Editor, now time.Time) (string, bool) {
	code, bounded := devicePairingInput(editor)
	if !bounded {
		return code, false
	}
	parsed, err := wire.DecodeNodePairTrustScopedCode(code, now)
	clear(parsed.OOBSecret)
	// Syntax/expiry is local input feedback only. The controller independently
	// verifies the selected Hub, exact candidate and every authorization proof.
	return code, err == nil
}

// Read input before measuring the fixed footer: a paste updates readiness in
// this frame. Only Gio SubmitEvent may review code; Enter never approves a
// reviewed computer, resumes an UNKNOWN or queues a request while busy.
func updateDevicePairingEditor(gtx layout.Context, editor *widget.Editor, s appcore.Snapshot, now time.Time, busy bool, review func(string)) {
	flow := appui.NodePairingFlow(s, now)
	canReview := gtx.Enabled() && !busy && s.Hub.Verified && flow.Primary == appcore.ActionReviewNodePairing && (flow.Stage == "code" || flow.Stage == "ended")
	editor.SingleLine, editor.Submit, editor.ReadOnly = true, true, !canReview
	submitted := false
	for {
		ev, ok := editor.Update(gtx)
		if !ok {
			return
		}
		if _, ok := ev.(widget.SubmitEvent); !ok || submitted {
			continue
		}
		submitted = true
		if code, ready := devicePairingReady(editor, now); ready && canReview {
			editor.ReadOnly = true
			review(code)
		}
	}
}
