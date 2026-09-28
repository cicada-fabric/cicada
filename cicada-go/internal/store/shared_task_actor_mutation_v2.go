package store

import (
	"database/sql"
	"time"
)

// guardSharedTaskMutationActorTx performs the complete native binding,
// membership, Network, Group, and action-grant check inside a Task write
// transaction. Older Store entry points retain their explicit identity
// checks, while Fabric uses the actor-scoped variants below.
func guardSharedTaskMutationActorTx(tx *sql.Tx, scope *NativeActorScope,
	principalID, endpointID, groupID, action string) error {
	if scope == nil {
		return networkGuardGroupEndpointTx(tx, principalID, endpointID, groupID, time.Now().UTC())
	}
	if scope.PrincipalID != principalID || scope.EndpointID != endpointID || scope.GroupID != groupID {
		return ErrNetworkPermission
	}
	return guardNativeActorTx(tx, *scope, action, time.Now().UTC())
}
