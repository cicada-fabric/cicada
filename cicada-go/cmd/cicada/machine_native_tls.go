package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
)

type machineNativeSelection struct {
	text       string
	descriptor hubtransport.Descriptor
	address    string
	transport  *hubtransport.Transport
}

// Reading routing metadata never creates a Node identity or promotes the
// descriptor's public Hub ID into an Owner-approved Agent identity.
func readMachineNativeState(stateDir, nodeID string) (machineNodeControlState, bool, error) {
	var state machineNodeControlState
	_, path := machineNodeControlPaths(stateDir, nodeID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		keyPath, _ := machineNodeControlPaths(stateDir, nodeID)
		if _, e := os.Lstat(keyPath); e == nil {
			return state, false, errors.New("original Node-Control state is unavailable; refusing replacement")
		} else if !errors.Is(e, os.ErrNotExist) {
			return state, false, e
		}
		marker, e := readMachineNativeMarker(stateDir, nodeID)
		if e != nil {
			return state, false, e
		}
		if marker {
			return state, false, errors.New("original native Hub routing state is unavailable; no fallback")
		}
		return state, false, nil
	} else if err != nil {
		return state, false, err
	}
	raw, err := clientoperator.ReadPrivateFile(path, maxMachineNodeControlStateBytes)
	if err != nil {
		return state, true, err
	}
	defer clear(raw)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil {
		return state, true, hubtransport.ErrInvalid
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) || state.Version != machineNodeControlStateVersion || state.NodeID != nodeID {
		return state, true, hubtransport.ErrInvalid
	}
	marker, err := readMachineNativeMarker(stateDir, nodeID)
	if err != nil {
		return state, true, err
	}
	if marker && state.HubTransportDescriptor == "" {
		return state, true, errors.New("original native routing state is unavailable; no fallback")
	}
	return state, true, nil
}

func readMachineNativeMarker(stateDir, nodeID string) (bool, error) {
	path := filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	raw, err := clientoperator.ReadPrivateFile(path, 64*1024)
	if err != nil {
		return false, err
	}
	defer clear(raw)
	var identity machineNodeIdentity
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&identity) != nil || identity.Version != machineNodeIdentityVersion || identity.NodeID != nodeID {
		return false, hubtransport.ErrInvalid
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return false, hubtransport.ErrInvalid
	}
	return identity.NativeHubTransport, nil
}

func validateMachineNativeMetadata(text, address, origin string) (hubtransport.Descriptor, error) {
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil || hubtransport.ValidateDescriptor(d, time.Now()) != nil || d.Claims.Origin != origin || pqtls.ValidateIPDialAddress(address) != nil {
		return hubtransport.Descriptor{}, hubtransport.ErrInvalid
	}
	return d, nil
}

func matchMachineNativeState(d hubtransport.Descriptor, state machineNodeControlState) error {
	if state.HubOrigin != d.Claims.Origin {
		return hubtransport.ErrOrigin
	}
	if state.HubKeyID != "" && hubtransport.MatchNodeControl(d, state.HubID, state.HubPublicIdentity, state.HubKeyVersion, state.HubFingerprint) != nil {
		return hubtransport.ErrInvalid
	}
	if state.HubCandidateID != "" && (state.HubCandidateID != d.Claims.NodeControl.ID || state.HubCandidateVersion != d.Claims.NodeControlKeyVersion ||
		state.HubCandidateFingerprint != nodewire.IdentityFingerprint(d.Claims.NodeControl) || !sameMachineNodeControlPublicIdentity(state.HubCandidateIdentity, d.Claims.NodeControl)) {
		return hubtransport.ErrInvalid
	}
	return nil
}

func resolveMachineNativeSelection(stateDir, nodeID, file, address, base, pq string, explicitOrigin bool) (*machineNativeSelection, string, error) {
	state, exists, err := readMachineNativeState(stateDir, nodeID)
	if err != nil {
		return nil, "", err
	}
	if (state.HubTransportDescriptor == "") != (state.HubDialAddress == "") {
		return nil, "", hubtransport.ErrInvalid
	}
	text := state.HubTransportDescriptor
	if file != "" {
		raw, err := readPublicFile(file, int64(hubtransport.MaxDescriptorText+2))
		if err != nil {
			return nil, "", err
		}
		text = strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	}
	if text == "" {
		if address != "" {
			return nil, "", hubtransport.ErrInvalid
		}
		if exists {
			canonical, e := normalizeControlURL(base)
			if e != nil || state.HubOrigin != canonical {
				return nil, "", hubtransport.ErrOrigin
			}
		}
		return nil, base, nil
	}
	if address == "" {
		address = state.HubDialAddress
	}
	if pq != "" {
		return nil, "", errors.New("native Hub transport and enrolled Node PQ transport cannot be combined")
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil {
		return nil, "", err
	}
	if explicitOrigin {
		canonical, err := normalizeControlURL(base)
		if err != nil || canonical != d.Claims.Origin {
			return nil, "", hubtransport.ErrOrigin
		}
	}
	if exists && state.HubOrigin != d.Claims.Origin {
		return nil, "", hubtransport.ErrOrigin
	}
	if state.HubTransportDescriptor != "" && state.HubTransportDescriptor != text {
		return nil, "", errors.New("original native Hub descriptor cannot be replaced")
	}
	if exists && state.HubTransportDescriptor == "" && (state.BindingID != "" || state.HubCandidateID != "" || state.PendingOperationID != "") {
		return nil, "", errors.New("legacy Node transport migration requires a separate controlled operation")
	}
	if _, err = validateMachineNativeMetadata(text, address, d.Claims.Origin); err != nil {
		return nil, "", err
	}
	if exists {
		if err = matchMachineNativeState(d, state); err != nil {
			return nil, "", err
		}
	}
	if state.HubTransportDescriptor != "" {
		identityPath, _ := machineNodeControlPaths(stateDir, nodeID)
		for _, path := range []string{identityPath, filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), machineNodeCredentialPath(stateDir, nodeID)} {
			raw, err := clientoperator.ReadPrivateFile(path, maxMachineNodeControlStateBytes)
			clear(raw)
			if err != nil {
				return nil, "", errors.New("original native Node identity or credential is unavailable; refusing replacement")
			}
		}
	}
	transport, err := hubtransport.NewTransport(d, address)
	if err != nil {
		return nil, "", err
	}
	return &machineNativeSelection{text: text, descriptor: d, address: address, transport: transport}, d.Claims.Origin, nil
}

func probeMachineNativeHub(ctx context.Context, s *machineNativeSelection) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.descriptor.Claims.Origin+"/v2/node/identity", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: s.transport, Timeout: 15 * time.Second, CheckRedirect: rejectNodeRedirect}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return hubtransport.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if err != nil || len(raw) > 128*1024 {
		return hubtransport.ErrInvalid
	}
	var identity machineNodeControlHubIdentity
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&identity) != nil {
		return hubtransport.ErrInvalid
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) || identity.Version != nodewire.Version || identity.Algorithm != e2ee.Algorithm || identity.KeyID != identity.PublicIdentity.ID {
		return hubtransport.ErrInvalid
	}
	return hubtransport.MatchNodeControl(s.descriptor, identity.HubID, identity.PublicIdentity, identity.KeyVersion, identity.Fingerprint)
}

// Agent and WriterRoot locks are already held, and the original local bearer
// has been loaded. Validate the new physical destination before changing any
// saved routing field or sending a credential/business packet.
func activateMachineNativeSelection(ctx context.Context, hub *machineHubContext, s *machineNativeSelection) error {
	if s == nil {
		return nil
	}
	if hub.NodeTransport != nil || hub.TLSRuntime != nil || (hub.HubID != "" && hub.HubID != s.descriptor.Claims.Hub.HubID) {
		return hubtransport.ErrInvalid
	}
	client, err := openMachineNodeControlClient(hub.StateDir, hub.Origin, hub.NodeID)
	if err != nil {
		return err
	}
	if err = probeMachineNativeHub(ctx, s); err != nil {
		return err
	}
	client.mu.Lock()
	oldText, oldAddress := client.state.HubTransportDescriptor, client.state.HubDialAddress
	if oldText != "" && oldText != s.text {
		client.mu.Unlock()
		return hubtransport.ErrInvalid
	}
	if matchMachineNativeState(s.descriptor, client.state) != nil {
		client.mu.Unlock()
		return hubtransport.ErrInvalid
	}
	client.state.HubTransportDescriptor, client.state.HubDialAddress = s.text, s.address
	if err = client.persistLocked(); err != nil {
		client.state.HubTransportDescriptor, client.state.HubDialAddress = oldText, oldAddress
		client.mu.Unlock()
		return err
	}
	client.mu.Unlock()
	if hub.NativeTransport != nil {
		hub.NativeTransport.CloseIdleConnections()
	}
	hub.NativeTransport = s.transport
	hub.HubTransportDescriptor, hub.HubDialAddress = s.text, s.address
	return nil
}

func machineSavedNativeTransport(hub machineHubContext) (*hubtransport.Transport, error) {
	if hub.StateDir == "" || hub.NodeID == "" {
		return nil, nil
	}
	state, exists, err := readMachineNativeState(hub.StateDir, hub.NodeID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	if state.HubOrigin != hub.Origin {
		return nil, hubtransport.ErrOrigin
	}
	if state.HubTransportDescriptor == "" && state.HubDialAddress == "" {
		return nil, nil
	}
	d, err := validateMachineNativeMetadata(state.HubTransportDescriptor, state.HubDialAddress, hub.Origin)
	if err != nil {
		return nil, err
	}
	if matchMachineNativeState(d, state) != nil {
		return nil, hubtransport.ErrInvalid
	}
	return hubtransport.NewTransport(d, state.HubDialAddress)
}

func persistMachineNativeMarker(stateDir, nodeID string, identity *machineNodeIdentity) error {
	if identity.NativeHubTransport {
		return nil
	}
	identity.NativeHubTransport = true
	raw, err := json.Marshal(identity)
	if err != nil {
		identity.NativeHubTransport = false
		return err
	}
	defer clear(raw)
	if err = persistNodeSecretFile(filepath.Join(machineNodeStateDir(stateDir, nodeID), "identity.json"), append(raw, '\n'), ".native-node-identity-*"); err != nil {
		identity.NativeHubTransport = false
		return err
	}
	return nil
}

func validateMachineNativeHubIdentity(ctx context.Context, identity machineNodeControlHubIdentity) error {
	hub, ok := machineHubFrom(ctx)
	if !ok {
		return nil
	}
	text := hub.HubTransportDescriptor
	if text == "" {
		state, exists, err := readMachineNativeState(hub.StateDir, hub.NodeID)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		text = state.HubTransportDescriptor
	}
	if text == "" {
		return nil
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil {
		return err
	}
	return hubtransport.MatchNodeControl(d, identity.HubID, identity.PublicIdentity, identity.KeyVersion, identity.Fingerprint)
}
