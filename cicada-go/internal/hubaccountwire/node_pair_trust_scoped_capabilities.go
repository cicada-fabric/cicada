package hubaccountwire

import "reflect"

// Decoding available=true is only a prerequisite for sending scoped requests.
// A public capability cannot establish a current caller or a Node grant.
func DecodeNodePairTrustScopedCapabilities(raw []byte) (NodePairTrustScopedCapabilities, error) {
	var c NodePairTrustScopedCapabilities
	want := NodePairTrustScopedContractCapabilities()
	want.Available = true
	if decodeCanonical(raw, MaxAppNodeScopedCapabilitiesBytes, &c) != nil || !reflect.DeepEqual(c, want) {
		return NodePairTrustScopedCapabilities{}, ErrInvalid
	}
	return c, nil
}
