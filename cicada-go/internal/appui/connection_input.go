package appui

import (
	"strings"

	"github.com/cicada-ai/cicada/internal/appcore"
)

// ConnectionInputAction separates the visible dial target from secret
// connection material. The controller validates transport and protocol data;
// building a native action neither contacts a Hub nor authenticates it.
// Leaving address empty preserves the original v1 card/code entry path.
func ConnectionInputAction(address, material string) (appcore.Action, bool) {
	address, material = strings.TrimSpace(address), strings.TrimSpace(material)
	if material == "" {
		return appcore.Action{}, false
	}
	action := appcore.Action{Kind: appcore.ActionConnect}
	if address != "" {
		action.HubAddress, action.BootstrapCode = address, material
	} else if strings.HasPrefix(material, "cicada-hub-connection-v1:") {
		action.ConnectionCard = material
	} else {
		action.ActivationCode = material
	}
	return action, true
}
