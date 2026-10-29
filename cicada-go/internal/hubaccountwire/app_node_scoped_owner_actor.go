package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// AppNodeScopedOwnerActor projects identity coordinates for a NEW, independently
// signed LocalDomain or OwnerEndpointGroups request. Those existing families
// deliberately use a v1 Owner actor with head=0. This is not a conversion of a
// scoped grant/proof, does not carry a Node confirmation, and cannot authorize
// legacy AppNode or NPT operations. The caller must match the current trusted
// session and separately use the exact ACKed Node binding as the signed target.
// Their Store guard rechecks current Root, session, binding and Network rights.
func AppNodeScopedOwnerActor(s e2ee.OwnerAppNodeScopedScope, hub HubIdentity) (e2ee.OwnerAppNodeScope, error) {
	if ValidateAppNodeScopedScope(s, hub) != nil {
		return e2ee.OwnerAppNodeScope{}, ErrInvalid
	}
	a := e2ee.OwnerAppNodeScope{
		Version: 1, Origin: s.Origin, HubID: s.HubID, HubFingerprint: s.HubFingerprint,
		AccountID: s.AccountID, AccountSessionID: s.AccountSessionID, AccountSessionExpiresAt: s.AccountSessionExpiresAt,
		OwnerID: s.OwnerID, OwnerPublic: s.OwnerPublic, OwnerKeyVersion: s.OwnerKeyVersion,
		DeviceID: s.DeviceID, DevicePublic: s.DevicePublic, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch,
		ClientSessionEpoch: s.ClientSessionEpoch, HeadVersion: 0, TransportPolicy: s.TransportPolicy,
	}
	if ValidateAppNodeScope(a, hub) != nil {
		return e2ee.OwnerAppNodeScope{}, ErrInvalid
	}
	return a, nil
}
