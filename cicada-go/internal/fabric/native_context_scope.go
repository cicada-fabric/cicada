package fabric

import "github.com/cicada-ai/cicada/internal/store"

func nativeContextScopeForGroup(db *store.Store, group store.Group) (store.NativeContextScopeMetadata, error) {
	hubID, err := db.GetClientHubID()
	if err != nil || hubID == "" {
		return store.NativeContextScopeMetadata{}, ErrNotFoundOrNotAuthorized
	}
	scope := store.NativeContextScopeMetadata{HubID: hubID, NetworkID: group.NetworkID,
		GroupID: group.ID, GroupContextPolicy: group.ContextPolicy}
	if group.NetworkID != "" {
		network, err := db.GetNetwork(group.NetworkID)
		if err != nil || network.State != store.NetworkStateActive || network.HubID != hubID {
			return store.NativeContextScopeMetadata{}, ErrNotFoundOrNotAuthorized
		}
		scope.NetworkContextPolicy = network.ContextPolicy
	}
	return scope, nil
}
