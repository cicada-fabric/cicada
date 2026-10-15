package appcore

import (
	"reflect"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// replacementDisposition returns authenticated terminal evidence, or an
// explicit never-started state. It never settles an uncertain business packet.
func (c *nativeController) replacementDisposition() (*pendingOperation, bool) {
	e := c.state.Enrollment
	if e == nil || !c.canBeginOperation() || c.device == nil || c.state.RootState == RootStateActive || c.state.RootState == RootStateUnavailable ||
		(e.Result != nil && (e.Result.RootState == wire.RootActiveState || e.Result.RootState == wire.RootUnavailableState)) {
		return nil, false
	}
	if e.Prepare == nil && e.Target == nil && e.Challenge == nil && e.Result == nil && c.state.Pending == nil {
		return nil, true
	}
	if e.Target == nil {
		return nil, false
	}
	validScope := func(r *wire.ActivationResult) bool {
		return r.ActivationID == e.Material.ActivationID && r.HubID == c.connection.HubID && r.Origin == c.connection.Origin &&
			r.AccountID == c.connection.AccountID && r.OwnerID == c.connection.OwnerID && r.DeviceID == c.state.DeviceID && r.RootState == wire.RootPendingState
	}
	if len(e.Target.Response) != 0 {
		opened, err := c.openPendingResponse(e.Target.Operation, e.Target.Request, e.Target.Response)
		if r, ok := opened.(*wire.ActivationResult); err == nil && ok && validScope(r) && (r.State == wire.ActivationRejected || r.State == wire.ActivationCancelled) {
			return e.Target, true
		}
	}
	if r := c.state.LastRecovery; r != nil && r.Operation == wire.OperationActivationStatus && len(r.Response) != 0 {
		opened, err := c.openPendingResponse(r.Operation, r.Request, r.Response)
		if result, ok := opened.(*wire.ActivationResult); err == nil && ok && validScope(result) && wire.ValidateActivationStatusTarget(*result, e.Target.Request) == nil &&
			(result.State == wire.ActivationCancelled || result.TargetState == wire.ActivationRejected || result.TargetState == wire.ActivationCancelled) {
			return r, true
		}
	}
	return nil, false
}

func (c *nativeController) installActivationMaterial(material wire.ActivationMaterial) error {
	e := c.state.Enrollment
	if e != nil && !reflect.DeepEqual(e.Material, material) {
		old := e.Material
		if old.HubID != material.HubID || old.HubFingerprint != material.HubFingerprint || old.Origin != material.Origin || old.AllowLoopbackHTTP != material.AllowLoopbackHTTP || old.AccountID != material.AccountID || old.OwnerID != material.OwnerID ||
			old.Purpose != material.Purpose || old.ActivationID == material.ActivationID || material.SetupEpoch < old.SetupEpoch || material.AccountEpoch < old.AccountEpoch ||
			material.AccountEpoch < c.state.ObservedAccountEpoch || !reflect.DeepEqual(old.ExpectedOwnerPublic, material.ExpectedOwnerPublic) {
			return ErrInvalidAction
		}
		receipt, ok := c.replacementDisposition()
		if !ok {
			return ErrInvalidAction
		}
		if material.ExpectedOwnerPublic != nil && c.owner != nil && !reflect.DeepEqual(*material.ExpectedOwnerPublic, c.owner.Public()) {
			return ErrInvalidAction
		}
		if receipt != nil {
			c.state.PreviousActivationReceipt = &pendingOperation{Operation: receipt.Operation, Request: append([]byte(nil), receipt.Request...), Response: append([]byte(nil), receipt.Response...), CreatedAt: receipt.CreatedAt}
		}
		// Only a settled activation slot is replaced. Keys, device ID, stable
		// account/Owner coordinates and highest observed epochs remain intact.
		if p := c.state.Pending; p != nil && (p.Operation == wire.OperationActivationPrepare || p.Operation == wire.OperationActivationComplete) {
			c.state.Pending = nil
		}
		c.state.Enrollment = nil
		c.authorizationChecked, c.activationStatusRequestID = false, ""
	}
	if c.state.Enrollment == nil {
		c.state.Enrollment = &enrollmentState{Material: material}
	}
	return nil
}
