package hubaccountwire

// These closed typed bodies are carried by the existing Node-Control PQC RPC.
// Caller identity, registered native source and current Group authority must be
// derived and rechecked on the server; this validates syntax only.
func ValidateThreadCollaborationNodeBody(operation string, body any) error {
	valid := false
	switch v := dereference(body).(type) {
	case ThreadScopeNodeRead:
		valid = operation == OperationThreadScopeRead && validID(v.EndpointID) && validID(v.NetworkID)
	case GroupLocksNodeRead:
		valid = operation == OperationGroupLocksRead && validID(v.EndpointID) && threadCollaborationScope(v.Scope)
	case GroupLocksNodeAcquire:
		valid = operation == OperationGroupLocksAcquire && validID(v.EndpointID) && ValidateGroupLockAcquireRequest(v.Request) == nil
	case GroupLocksNodeRenew:
		valid = operation == OperationGroupLocksRenew && validID(v.EndpointID) && ValidateGroupLockRenewRequest(v.Request) == nil
	case GroupLocksNodeRelease:
		valid = operation == OperationGroupLocksRelease && validID(v.EndpointID) && ValidateGroupLockReleaseRequest(v.Request) == nil
	}
	if !valid {
		return ErrInvalid
	}
	return nil
}
func DecodeThreadCollaborationNodeBody(operation string, raw []byte) (any, error) {
	var v any
	switch operation {
	case OperationThreadScopeRead:
		v = &ThreadScopeNodeRead{}
	case OperationGroupLocksRead:
		v = &GroupLocksNodeRead{}
	case OperationGroupLocksAcquire:
		v = &GroupLocksNodeAcquire{}
	case OperationGroupLocksRenew:
		v = &GroupLocksNodeRenew{}
	case OperationGroupLocksRelease:
		v = &GroupLocksNodeRelease{}
	default:
		return nil, ErrInvalid
	}
	if decodeCanonical(raw, MaxThreadCollaborationNodeBodyBytes, v) != nil || ValidateThreadCollaborationNodeBody(operation, v) != nil {
		return nil, ErrInvalid
	}
	return dereference(v), nil
}
