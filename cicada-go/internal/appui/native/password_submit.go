package native

import (
	"slices"
	"strings"

	"gioui.org/layout"
	"gioui.org/widget"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui"
)

// Consume editor events before material.Editor's layout consumes them. Let Gio
// handle IME editing and produce SubmitEvent; a global Enter handler would also
// intercept the key an input method uses to confirm its composing text.
func updatePasswordEditor(gtx layout.Context, editor *widget.Editor, username string, s appcore.Snapshot, flow appui.SetupFlow, busy bool, submit func()) {
	editor.SingleLine, editor.Submit, editor.ReadOnly = true, true, busy
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
		if passwordLoginAllowed(s, flow, username, editor.Text(), busy) {
			editor.ReadOnly = true
			submit()
		}
	}
}

func passwordLoginAllowed(s appcore.Snapshot, flow appui.SetupFlow, username, password string, busy bool) bool {
	if busy || !s.Hub.Verified || !flow.Password || password == "" ||
		(flow.Primary != appcore.ActionLogin && flow.Primary != appcore.ActionLoginComplete) ||
		!slices.Contains(s.AvailableActions, flow.Primary) {
		return false
	}
	return !flow.Username || strings.TrimSpace(username) != ""
}
