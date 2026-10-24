package native

import (
	"strings"

	"gioui.org/widget"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// The approved single-code UI budget. Protocol parsing belongs to the shared
// typed codec; this helper only prepares case-preserving input for that parser.
const devicePairingInputBytes = wire.MaxNodePairTrustCodeBytes

func newDevicePairingEditor() widget.Editor {
	return widget.Editor{SingleLine: true, Mask: '•', MaxLen: devicePairingInputBytes + 1}
}

func devicePairingInput(editor *widget.Editor) (string, bool) {
	code := strings.TrimSpace(editor.Text())
	// Keep one overflow rune in the editor so a pasted oversized code cannot
	// silently become a valid maximum-length code through widget truncation.
	return code, code != "" && len(code) <= devicePairingInputBytes
}
