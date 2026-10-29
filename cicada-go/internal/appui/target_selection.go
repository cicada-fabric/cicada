package appui

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// Empty choice means a new Network. Saved choices only supply an exact target
// for the existing authenticated preview, never a grant or success state.
func LocalCollaborationSelection(s appcore.Snapshot, choice, name, group string, hours uint64) (appcore.LocalCollaborationAction, bool) {
	input := appcore.LocalCollaborationAction{GroupName: group, ExpiresInHours: hours}
	validName := func(v string) bool {
		return v != "" && len(v) <= 128 && utf8.ValidString(v) && strings.TrimSpace(v) == v && strings.IndexFunc(v, unicode.IsControl) < 0
	}
	if s.Targets.Locked || !s.LocalCollaboration.Current || !slices.Contains(s.AvailableActions, appcore.ActionPrepareLocalCollaboration) || !validName(group) {
		return input, false
	}
	if choice == "" {
		input.NewNetworkName = name
		return input, validName(name)
	}
	for _, n := range s.Targets.Networks {
		if n.NetworkID == choice {
			input.NetworkID = n.NetworkID
			return input, true
		}
	}
	return input, false
}
