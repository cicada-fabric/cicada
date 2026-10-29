package main

import (
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

// Only an authenticated, locally S-verified, ACKED family may call this shared
// immutable Binding-leaf installer. It does not convert authority scopes.
func installMachineNodePairValidatedBinding(client *machineNodeControlClient, b e2ee.OwnerAppNodeBinding, d hubtransport.Descriptor, descriptorText, dialAddress, attemptID, credentialDigest string) error {
	if b.NodeID != client.nodeID || !reflect.DeepEqual(b.NodePublic, client.identity.Public()) || hubtransport.MatchNodeControl(d, b.HubID, b.HubNodeControlPublic, b.HubNodeControlKeyVersion, b.HubNodeControlFingerprint) != nil {
		return errMachineNodePairState
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	old := cloneMachineNodeControlState(client.state)
	address, e := retainedMachineNodePairBindingRouting(old, descriptorText, dialAddress)
	if e != nil {
		return e
	}
	if old.BindingID != "" {
		r := wire.NodePairTrustRetainedBinding{NodeID: old.NodeID, OwnerBindingID: old.BindingID, BindingVersion: old.BindingVersion, NodeKeyID: old.NodeKeyID, NodeKeyVersion: old.NodeKeyVersion, NodeKeyEpoch: old.NodeKeyEpoch, NodeKeyFingerprint: old.NodeKeyFingerprint, HubNodeControlPublic: old.HubPublicIdentity, HubNodeControlKeyVersion: old.HubKeyVersion, HubNodeControlFingerprint: old.HubFingerprint, ApprovedRequestID: old.ApprovedRequestID, ApprovedRequestVersion: uint64(old.ApprovedRequestVersion), ApprovedCandidateDigest: old.ApprovedCandidateDigest, CredentialDigest: credentialDigest}
		if wire.MatchNodePairTrustRetainedBinding(r, b, client.identity.Public()) != nil {
			return errMachineNodePairState
		}
	}
	if old.HubTransportDescriptor != "" && old.HubTransportDescriptor != descriptorText {
		return errMachineNodePairState
	}
	client.state.HubID = b.HubID
	client.state.HubKeyID = b.HubNodeControlPublic.ID
	client.state.HubFingerprint = b.HubNodeControlFingerprint
	client.state.HubKeyVersion = b.HubNodeControlKeyVersion
	client.state.HubPublicIdentity = b.HubNodeControlPublic
	client.state.NodeKeyID = b.NodePublic.ID
	client.state.NodeKeyFingerprint = nodewire.IdentityFingerprint(b.NodePublic)
	client.state.NodeKeyVersion = b.NodeKeyVersion
	client.state.BindingID = b.OwnerBindingID
	client.state.BindingVersion = b.BindingVersion
	client.state.NodeKeyEpoch = b.NodeKeyEpoch
	client.state.ApprovedRequestID = b.ApprovedRequestID
	client.state.ApprovedRequestVersion = int64(b.ApprovedRequestVersion)
	client.state.ApprovedCandidateDigest = b.ApprovedCandidateDigest
	client.state.HubCandidateID = ""
	client.state.HubCandidateFingerprint = ""
	client.state.HubCandidateVersion = 0
	client.state.HubCandidateIdentity = e2ee.PublicIdentity{}
	client.state.PendingPairing = nil
	client.state.PendingPairingUserCode = ""
	client.state.PendingPairingURI = ""
	client.state.HubTransportDescriptor = descriptorText
	client.state.HubDialAddress = address
	client.state.NodePairTrustAttemptID = attemptID
	if e = client.persistLocked(); e != nil {
		client.state = old
		return e
	}
	return nil
}

func retainedMachineNodePairBindingRouting(old machineNodeControlState, descriptorText, dialAddress string) (string, error) {
	if old.BindingID == "" && old.HubTransportDescriptor == "" && old.HubDialAddress == "" {
		if pqtls.ValidateIPDialAddress(dialAddress) != nil {
			return "", errMachineNodePairState
		}
		return dialAddress, nil
	}
	if old.BindingID == "" || old.HubTransportDescriptor == "" || old.HubTransportDescriptor != descriptorText || pqtls.ValidateIPDialAddress(old.HubDialAddress) != nil {
		return "", errMachineNodePairState
	}
	return old.HubDialAddress, nil
}
