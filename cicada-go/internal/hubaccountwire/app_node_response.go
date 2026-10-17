package hubaccountwire

import "github.com/cicada-ai/cicada/internal/e2ee"

// AppNodeResponse is a local tagged result. Prepare success is a challenge;
// an authenticated terminal prepare rejection uses the common result shape.
// No caller should guess a schema or clear pending state from an HTTP status.
type AppNodeResponse struct {
	Challenge  *AppNodeChallenge
	Result     *AppNodeResult
	Reconciled *AppNodeReconcileResult
}

func OpenAppNodeResponse(device *e2ee.Identity, hub HubIdentity, original, response []byte) (AppNodeResponse, error) {
	p, err := DecodePacket(original)
	if err != nil || !appNodeOperation(p.Packet.Route.Operation) {
		return AppNodeResponse{}, ErrInvalid
	}
	if p.Packet.Route.Operation == OperationAppNodePrepare {
		var ch AppNodeChallenge
		if err := OpenClientResponse(device, hub, original, response, &ch); err == nil {
			return AppNodeResponse{Challenge: &ch}, nil
		}
	}
	if p.Packet.Route.Operation == OperationAppNodeReconcile {
		var r AppNodeReconcileResult
		if err := OpenClientResponse(device, hub, original, response, &r); err != nil {
			return AppNodeResponse{}, err
		}
		return AppNodeResponse{Reconciled: &r}, nil
	}
	var r AppNodeResult
	if err := OpenClientResponse(device, hub, original, response, &r); err != nil {
		return AppNodeResponse{}, err
	}
	if p.Packet.Route.Operation == OperationAppNodePrepare && r.State != AppNodeRejectedFenced {
		return AppNodeResponse{}, ErrInvalid
	}
	return AppNodeResponse{Result: &r}, nil
}
