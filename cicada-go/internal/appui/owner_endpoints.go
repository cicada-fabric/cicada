package appui

import (
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
)

func OwnerEndpointDirectoryVisible(s appcore.Snapshot, now time.Time) bool {
	return AccountInformationVisible(s, now) && s.Account.RootState == appcore.RootStateActive && (s.OwnerEndpoints.NodeID != "" || s.OwnerEndpoints.Pending)
}

func OwnerEndpointPublicFields(s appcore.Snapshot, card appcore.OwnerEndpointView, now time.Time) []PublicField {
	if !OwnerEndpointDirectoryVisible(s, now) {
		return nil
	}
	// Only cards in the controller's authenticated snapshot are displayable.
	for _, actual := range s.OwnerEndpoints.Endpoints {
		if actual == card {
			return []PublicField{{Key: "directory.name", Value: card.Name}, {Key: "directory.workspace", Value: card.Workspace}}
		}
	}
	return nil
}
