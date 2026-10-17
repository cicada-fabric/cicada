package hubaccountwire

import (
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func NativePairHTTPOperations() []string {
	return []string{OperationNativePairBootstrapPrepare, OperationNativePairBootstrapComplete, OperationNativePairSlotReject, OperationNativePairConsentPrepare, OperationNativePairConsentComplete, OperationNativePairStatus, OperationNativePairRevoke, OperationNativePairReconcile}
}
func NativePairNodeOperations() []string {
	return []string{OperationNativePairNodeDescribe, OperationNativePairNodeJoin, OperationNativePairNodeReconcile}
}

// Ordered closed discovery lists are part of this contract. Availability never
// supplies an actor; callers also enforce their pinned origin/transport profile.
func DecodeNativePairCapabilities(raw []byte) (NativePairCapabilities, error) {
	var c NativePairCapabilities
	if decodeCanonical(raw, MaxNativePairCapabilitiesBytes, &c) != nil || c.Format != NativePairFormat || c.ContractRevision != NativePairContractRevision || !c.Available || c.ServeMode != "--hub-nodes-only" ||
		(c.TransportPolicy != AppNodeTransportHTTPS && c.TransportPolicy != AppNodeTransportLoopbackTest) || c.PeerTransport != "SEALED_RELAY" ||
		!reflect.DeepEqual(c.HTTPOperations, NativePairHTTPOperations()) || !reflect.DeepEqual(c.NodeOperations, NativePairNodeOperations()) || c.Policy != e2ee.NativePairFixedPeerPolicy() {
		return NativePairCapabilities{}, ErrInvalid
	}
	return c, nil
}
