package control

import "github.com/cicada-ai/cicada/internal/store"

// PreviewClientTopologyEndpointAdmissionForClientRequest binds an exact
// Endpoint-to-Group admission preview to the authenticated Client request.
// The Store repeats its current Owner, Network, Node, and CAS guards when the
// corresponding topology.apply action is committed.
func (c *Control) PreviewClientTopologyEndpointAdmissionForClientRequest(requestID, ownerID,
	networkID, groupID, endpointID string) (*store.ClientTopologyEndpointAdmissionPreview, error) {
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	return c.store.PreviewClientTopologyEndpointAdmissionForClientRequest(
		requestID, ownerID, networkID, groupID, endpointID)
}
