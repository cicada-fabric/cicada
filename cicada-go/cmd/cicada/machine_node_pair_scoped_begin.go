package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

// Caller holds original Agent/WriterRoot locks. A candidate is never promoted
// into the ordinary Hub transport or a bearer-bearing request here.
func beginMachineNodePairScoped(ctx context.Context, stateDir, nodeID, name, address, expectedOrigin string, explicitOrigin bool, selectedDescriptor ...string) (*machineNodeControlClient, *machineNodePairScopedState, error) {
	if machineNodePairNoSymlinkPath(machineNodeStateDir(stateDir, nodeID)) != nil {
		return nil, nil, errMachineNodePairState
	}
	if pqtls.ValidateIPDialAddress(address) != nil {
		return nil, nil, hubtransport.ErrInvalid
	}
	if _, e := os.Lstat(machineNodePairStatePath(stateDir, nodeID)); !errors.Is(e, os.ErrNotExist) {
		return nil, nil, errMachineNodePairState
	}
	old, exists, e := readMachineNativeState(stateDir, nodeID)
	if e != nil {
		return nil, nil, e
	}
	path := machineNodePairScopedStatePath(stateDir, nodeID)
	_, pairErr := os.Lstat(path)
	hasPair := pairErr == nil
	if pairErr != nil && !errors.Is(pairErr, os.ErrNotExist) {
		return nil, nil, errMachineNodePairState
	}
	var text, origin string
	if hasPair {
		if !exists {
			return nil, nil, errMachineNodePairState
		}
		keyPath, statePath := machineNodeControlPaths(stateDir, nodeID)
		for _, p := range []string{keyPath, statePath, filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
			raw, e := machineNodePairPrivateRead(p, machineNodePairScopedLocalMax)
			clear(raw)
			if e != nil {
				return nil, nil, e
			}
		}
		client, e := openMachineNodeControlClientMode(stateDir, old.HubOrigin, nodeID, true)
		if e != nil {
			return nil, nil, e
		}
		s, e := loadMachineNodePairScopedState(stateDir, nodeID, client.identity)
		if e != nil {
			return nil, nil, e
		}
		d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
		if e != nil || s.DialAddress != address || old.HubOrigin != d.Claims.Origin {
			return nil, nil, errMachineNodePairState
		}
		if old.NodePairTrustAttemptID != s.AttemptID {
			if s.Stage != "NEW" || s.PendingOperation != "" {
				return nil, nil, errMachineNodePairState
			}
			if old.NodePairTrustAttemptID != "" && verifyMachineNodePairScopedPrevious(stateDir, client, s, old.NodePairTrustAttemptID) != nil {
				return nil, nil, errMachineNodePairState
			}
		}
		if old.HubTransportDescriptor != "" && old.HubTransportDescriptor != s.DescriptorText {
			return nil, nil, errMachineNodePairState
		}
		rawToken, tokenErr := machineNodePairPrivateRead(machineNodeCredentialPath(stateDir, nodeID), 64*1024)
		if tokenErr != nil {
			return nil, nil, tokenErr
		}
		actualDigest := hashNodeCredential(strings.TrimSpace(string(rawToken)))
		clear(rawToken)
		if actualDigest != machineNodePairScopedCredentialDigest(s) {
			return nil, nil, errMachineNodePairState
		}
		if explicitOrigin && expectedOrigin != d.Claims.Origin {
			return nil, nil, hubtransport.ErrOrigin
		}
		if old.NodePairTrustAttemptID != s.AttemptID {
			client.mu.Lock()
			client.state.NodePairTrustAttemptID = s.AttemptID
			e = client.persistLocked()
			client.mu.Unlock()
			if e != nil {
				return nil, nil, e
			}
		}
		return client, s, nil
	}
	if old.NodePairTrustAttemptID != "" {
		return nil, nil, errMachineNodePairState
	}
	if exists {
		// Retained existing Nodes may use only their already trusted native pin.
		// An incomplete legacy state cannot be reclassified as a pristine install.
		if old.BindingID == "" || old.HubTransportDescriptor == "" || old.HubDialAddress == "" {
			return nil, nil, errMachineNodePairState
		}
		selection, selected, e := resolveMachineNativeSelection(stateDir, nodeID, "", address, expectedOrigin, "", explicitOrigin)
		if e != nil {
			return nil, nil, e
		}
		selection.transport.CloseIdleConnections()
		text, origin = selection.text, selected
	} else {
		for _, p := range []string{filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
			if _, e := os.Lstat(p); e == nil || !errors.Is(e, os.ErrNotExist) {
				return nil, nil, errMachineNodePairState
			}
		}
		candidate, e := hubtransport.DiscoverCandidate(ctx, address)
		if e != nil {
			return nil, nil, e
		}
		text, origin = candidate.DescriptorText, candidate.Descriptor.Claims.Origin
		if explicitOrigin && expectedOrigin != origin {
			return nil, nil, hubtransport.ErrOrigin
		}
	}
	if len(selectedDescriptor) > 0 && selectedDescriptor[0] != "" && text != selectedDescriptor[0] {
		return nil, nil, errMachineNodePairState
	}
	if exists {
		keyPath, _ := machineNodeControlPaths(stateDir, nodeID)
		for _, p := range []string{keyPath, filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
			raw, e := machineNodePairPrivateRead(p, machineNodePairScopedLocalMax)
			clear(raw)
			if e != nil {
				return nil, nil, e
			}
		}
	}
	_, digest, e := loadOrCreateMachineNodeIdentity(stateDir, nodeID)
	if e != nil {
		return nil, nil, e
	}
	client, e := openMachineNodeControlClientMode(stateDir, origin, nodeID, exists)
	if e != nil {
		return nil, nil, e
	}
	var retained *machineNodeControlState
	if exists {
		retained = &old
	}
	s, e := newMachineNodePairScopedAttempt(client, text, address, name, digest, retained)
	if e != nil {
		return nil, nil, e
	}
	if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
		clear(s.Secret)
		return nil, nil, e
	}
	client.mu.Lock()
	client.state.NodePairTrustAttemptID = s.AttemptID
	e = client.persistLocked()
	client.mu.Unlock()
	if e != nil {
		clear(s.Secret)
		return nil, nil, e
	}
	return client, s, nil
}

func newMachineNodePairScopedAttempt(client *machineNodeControlClient, text, address, name, digest string, retained *machineNodeControlState) (*machineNodePairScopedState, error) {
	d, e := hubtransport.DecodeDescriptor(text)
	if e != nil {
		return nil, e
	}
	nodeID, origin := client.nodeID, d.Claims.Origin
	var old machineNodeControlState
	exists := retained != nil
	if exists {
		old = *retained
	}
	attempt, e := wire.NewRequestID()
	if e != nil {
		return nil, e
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return nil, e
	}
	nonce, e := wire.NewNonce()
	if e != nil {
		clear(secret)
		return nil, e
	}
	now := time.Now().UTC()
	s := &machineNodePairScopedState{Version: 1, NodeID: nodeID, AttemptID: attempt, DescriptorText: text, DialAddress: address, Secret: secret, Stage: "NEW"}
	if !exists {
		meta := machineNodeControlHubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm, HubID: d.Claims.Hub.HubID, KeyID: d.Claims.NodeControl.ID, KeyVersion: d.Claims.NodeControlKeyVersion, Fingerprint: nodewire.IdentityFingerprint(d.Claims.NodeControl), PublicIdentity: d.Claims.NodeControl}
		input, e := buildMachineNodeControlPairingInput(client, meta, name, digest)
		if e != nil {
			clear(secret)
			return nil, e
		}
		start := wire.NodePairTrustScopedStart{ScopeVersion: 2, Format: wire.NodePairTrustScopedFormat, Hub: d.Claims.Hub, Origin: origin, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(text), NodeID: nodeID, NodeName: strings.TrimSpace(name), CredentialDigest: digest, RequestNonce: input.RequestNonce, HubNodeControlPublic: d.Claims.NodeControl, HubNodeControlKeyVersion: d.Claims.NodeControlKeyVersion, PairingProof: input.ProofPacket, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
		s.StartOperation = wire.OperationNodePairTrustScopedStart
		s.StartBody, e = json.Marshal(start)
		if e != nil {
			clear(secret)
			return nil, e
		}
	} else {
		if old.ApprovedRequestVersion <= 0 {
			clear(secret)
			return nil, errMachineNodePairState
		}
		r := wire.NodePairTrustRetainedBinding{NodeID: old.NodeID, OwnerBindingID: old.BindingID, BindingVersion: old.BindingVersion, NodeKeyID: old.NodeKeyID, NodeKeyVersion: old.NodeKeyVersion, NodeKeyEpoch: old.NodeKeyEpoch, NodeKeyFingerprint: old.NodeKeyFingerprint, HubNodeControlPublic: old.HubPublicIdentity, HubNodeControlKeyVersion: old.HubKeyVersion, HubNodeControlFingerprint: old.HubFingerprint, ApprovedRequestID: old.ApprovedRequestID, ApprovedRequestVersion: uint64(old.ApprovedRequestVersion), ApprovedCandidateDigest: old.ApprovedCandidateDigest, CredentialDigest: digest}
		if wire.ValidateNodePairTrustRetainedBinding(r, client.identity.Public(), d.Claims.Hub) != nil || hubtransport.MatchNodeControl(d, old.HubID, old.HubPublicIdentity, old.HubKeyVersion, old.HubFingerprint) != nil {
			clear(secret)
			return nil, errMachineNodePairState
		}
		c := wire.NodePairTrustScopedContext{ScopeVersion: 2, AuthorityNodeID: nodeID, Format: wire.NodePairTrustScopedFormat, AttemptID: attempt, Hub: d.Claims.Hub, Origin: origin, DescriptorDigest: wire.NodePairTrustScopedDescriptorDigest(text), NodeNonce: hex.EncodeToString(nonce), Mode: wire.NodePairTrustScopedExisting, IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
		start := wire.NodePairTrustScopedExistingStart{Format: wire.NodePairTrustScopedFormat, Context: c, IssuedAt: now.Format(time.RFC3339Nano), RetainedBinding: &r}
		s.StartOperation = wire.OperationNodePairTrustScopedExisting
		s.StartBody, e = json.Marshal(start)
		if e != nil {
			clear(secret)
			return nil, e
		}
	}
	return s, nil
}
