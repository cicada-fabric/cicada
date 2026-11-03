package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

var errMachineNodePairScopedUnavailable = errors.New("NODE_PAIR_SCOPED_UNAVAILABLE: Hub must support current Node-scoped pairing; no pairing operation issued")
var errMachineNodePairLegacyUnsupported = errors.New("NODE_PAIR_PROTOCOL_UNSUPPORTED: only current Node-scoped pairing is supported; retained identity and evidence were not changed")

// File names select a family before decoding. Neither a failed parser nor a
// missing journal permits trying another family or replacing an enrolled Node.
func machineNodePairSavedProfile(stateDir, nodeID string) (string, error) {
	profile := ""
	for _, entry := range []struct{ name, path string }{
		{"legacy", machineNodePairStatePath(stateDir, nodeID)},
		{"scoped", machineNodePairScopedStatePath(stateDir, nodeID)},
	} {
		info, err := os.Lstat(entry.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || profile != "" {
			return "", errMachineNodePairState
		}
		profile = entry.name
	}
	return profile, nil
}

func machineNodePairCapabilitiesGET(ctx context.Context, client *http.Client, origin, path string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return nil, 0, errMachineNodePairScopedUnavailable
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, errMachineNodePairScopedUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, response.StatusCode, errMachineNodePairScopedUnavailable
	}
	return bytes.TrimSpace(raw), response.StatusCode, nil
}

func machineNodePairScopedAvailable(ctx context.Context, client *http.Client, origin string) error {
	raw, status, err := machineNodePairCapabilitiesGET(ctx, client, origin, wire.NodePairTrustScopedCapabilitiesPath)
	if err != nil || status != http.StatusOK {
		return errMachineNodePairScopedUnavailable
	}
	if _, err := wire.DecodeNodePairTrustScopedCapabilities(raw); err != nil {
		return errMachineNodePairScopedUnavailable
	}
	return nil
}

// Service control reads the protected, previously authenticated ACK fact. It
// neither re-runs the enrollment clock nor initializes trust, keys or transport.
func machineNodePairACKMarker(stateDir, nodeID string, client *machineNodeControlClient) error {
	profile, err := machineNodePairSavedProfile(stateDir, nodeID)
	if err != nil {
		return err
	}
	var binding *e2ee.OwnerAppNodeBinding
	var stage, attempt string
	if profile == "scoped" {
		s, err := loadMachineNodePairScopedState(stateDir, nodeID, client.identity)
		if err != nil {
			return err
		}
		defer clear(s.Secret)
		binding, stage, attempt = s.Binding, s.Stage, s.AttemptID
	} else {
		return errMachineNodePairLegacyUnsupported
	}
	s := client.state
	if stage != "ACKED" || binding == nil || attempt != s.NodePairTrustAttemptID ||
		binding.NodeID != nodeID || binding.OwnerBindingID != s.BindingID || binding.BindingVersion != s.BindingVersion ||
		binding.NodeKeyEpoch != s.NodeKeyEpoch || binding.NodeKeyVersion != s.NodeKeyVersion || binding.HubNodeControlKeyVersion != s.HubKeyVersion ||
		!reflect.DeepEqual(binding.NodePublic, client.identity.Public()) || !reflect.DeepEqual(binding.HubNodeControlPublic, s.HubPublicIdentity) {
		return errMachineNodePairState
	}
	return nil
}

// Caller holds the existing Agent/WriterRoot locks. Public discovery is bound
// to one descriptor before the current scoped family may initialize a journal.
// "auto" remains an argument alias for saved service argv, never negotiation.
func selectMachineNodePairProfile(ctx context.Context, stateDir, nodeID, address, expectedOrigin string, explicitOrigin bool, requested string) (string, string, error) {
	if requested != "auto" && requested != "scoped" {
		return "", "", errMachineNodePairLegacyUnsupported
	}
	saved, err := machineNodePairSavedProfile(stateDir, nodeID)
	if err != nil {
		return "", "", err
	}
	if saved == "legacy" {
		return "", "", errMachineNodePairLegacyUnsupported
	}
	old, exists, err := readMachineNativeState(stateDir, nodeID)
	if err != nil || saved == "" && old.NodePairTrustAttemptID != "" {
		return "", "", errMachineNodePairState
	}
	if saved == "" && exists {
		return "", "", errMachineNodePairLegacyUnsupported
	}
	var text string
	if saved == "scoped" {
		keyPath, _ := machineNodeControlPaths(stateDir, nodeID)
		raw, err := machineNodePairPrivateRead(keyPath, machineNodePairLocalMax)
		if err != nil {
			return "", "", err
		}
		identity, err := e2ee.UnmarshalIdentity(raw)
		clear(raw)
		if err != nil {
			return "", "", errMachineNodePairState
		}
		s, err := loadMachineNodePairScopedState(stateDir, nodeID, identity)
		if err != nil {
			return "", "", err
		}
		defer clear(s.Secret)
		if s.DialAddress != address {
			return "", "", errMachineNodePairState
		}
		text = s.DescriptorText
		// ACKED startup uses the original verified binding and current pin;
		// its old short code, proof and public availability are not enrollment.
		if s.Stage == wire.NodePairTrustScopedACKed {
			return "scoped", text, nil
		}
	} else {
		candidate, err := hubtransport.DiscoverCandidate(ctx, address)
		if err != nil {
			return "", "", err
		}
		text = candidate.DescriptorText
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil || explicitOrigin && d.Claims.Origin != expectedOrigin {
		return "", "", errMachineNodePairState
	}
	client, err := hubtransport.NewHTTPClient(d, address, 15*time.Second)
	if err != nil {
		return "", "", err
	}
	defer client.CloseIdleConnections()
	if err := machineNodePairScopedAvailable(ctx, client, d.Claims.Origin); err != nil {
		return "", "", err
	}
	return "scoped", text, nil
}
