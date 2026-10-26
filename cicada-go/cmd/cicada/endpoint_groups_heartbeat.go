package main

import (
	"context"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Background renewal can retain only the already authenticated original
// registration. It has no selected Group and never consumes or invents a Hook.
func (b *machineAgentJoinBridge) endpointGroupsRegistrationHeartbeat(q localMCPMetadataRequest) (*localMCPMetadataResult, error) {
	if q.Version != localJoinProtocolVersion || q.Operation != "mcp_metadata_heartbeat" || q.APIOrigin != b.baseURL || q.NodeID != b.nodeID || q.Harness != "codex" || q.GroupID != "" || q.codexDomainBinding.validate() != nil || q.EndpointGroupsVersion != 1 || q.EndpointGroupAuthority != (wire.EndpointGroupCurrentEndpoint{}) || q.BindingID != q.RegistrationBindingID || q.BindingEpoch != q.RegistrationBindingEpoch || q.NativeBindingID != q.BindingID || q.NativeBindingEpoch != q.BindingEpoch {
		return nil, errEndpointGroupsRegistration
	}
	b.endpointGroupsMu.Lock()
	defer b.endpointGroupsMu.Unlock()
	c, err := openMachineNodeControlClientMode(b.stateDir, b.baseURL, b.nodeID, true)
	if err != nil {
		return nil, err
	}
	r, enrolled, err := c.endpointGroupsRegistrationCandidate(q.NativeSessionID, q.Workspace)
	if err != nil || !enrolled || r.Anchor.RegistrationDigest != q.RegistrationDigest || r.Anchor.RegistrationRevision != q.RegistrationRevision || r.Anchor.Registration.EndpointID != q.EndpointID || r.Anchor.Registration.PrincipalID != q.PrincipalID || r.Anchor.BindingID != q.BindingID || r.Anchor.BindingEpoch != q.BindingEpoch || r.Anchor.NodeKeyEpoch != q.RegistrationNodeKeyEpoch {
		return nil, errEndpointGroupsRegistration
	}
	if r.LocallyOffline {
		return nil, errEndpointGroupsOffline
	}
	if q.LocalAccessRevision == 0 || q.LocalAccessRevision != r.LocalAccessRevision {
		return nil, errEndpointGroupsOffline
	}
	_, original, _, err := c.endpointGroupsOriginal(r)
	if err != nil || original.SessionToken != q.SessionToken {
		return nil, errEndpointGroupsRegistration
	}
	ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
	defer cancel()
	r, err = b.renewEndpointGroupsRegistration(ctx, c, r)
	if err != nil {
		return nil, err
	}
	a := r.Anchor
	return &localMCPMetadataResult{StatusCode: 200, Body: marshalMCPMetadata(fabric.Actor{EndpointID: a.Registration.EndpointID, PrincipalID: a.Registration.PrincipalID, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, LeaseOwner: a.LeaseOwner, LeaseExpiresAt: a.LeaseExpiresAt})}, nil
}
