package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// AppNodeScopedResponse is a local tagged result. Prepare success is a challenge;
// an authenticated terminal prepare rejection uses the common result shape.
// No caller should guess a schema or clear pending state from an HTTP status.
type AppNodeScopedResponse struct {
	Challenge  *AppNodeScopedChallenge
	Result     *AppNodeScopedResult
	Reconciled *AppNodeScopedReconciled
}

func OpenAppNodeScopedResponse(device *e2ee.Identity, hub HubIdentity, original, response []byte) (AppNodeScopedResponse, error) {
	p, err := DecodePacket(original)
	if err != nil || !appNodeScopedOperation(p.Packet.Route.Operation) {
		return AppNodeScopedResponse{}, ErrInvalid
	}
	if p.Packet.Route.Operation == OperationAppNodeScopedPrepare {
		var ch AppNodeScopedChallenge
		if err := OpenClientResponse(device, hub, original, response, &ch); err == nil {
			return AppNodeScopedResponse{Challenge: &ch}, nil
		}
	}
	if p.Packet.Route.Operation == OperationAppNodeScopedReconcile {
		var r AppNodeScopedReconciled
		if err := OpenClientResponse(device, hub, original, response, &r); err != nil {
			return AppNodeScopedResponse{}, err
		}
		return AppNodeScopedResponse{Reconciled: &r}, nil
	}
	var r AppNodeScopedResult
	if err := OpenClientResponse(device, hub, original, response, &r); err != nil {
		return AppNodeScopedResponse{}, err
	}
	if p.Packet.Route.Operation == OperationAppNodeScopedPrepare && r.State != AppNodeScopedRejectedFenced {
		return AppNodeScopedResponse{}, ErrInvalid
	}
	return AppNodeScopedResponse{Result: &r}, nil
}
