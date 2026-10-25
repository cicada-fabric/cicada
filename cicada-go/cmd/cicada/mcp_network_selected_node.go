package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/gofrs/flock"
)

var errMCPNetworkSelection = errors.New("NETWORK_SESSION_UNAVAILABLE: restore this Node's original joined Network session")
var errMCPNetworkRenewUncertain = errors.New("NETWORK_RENEW_UNCERTAIN: original renewal may have committed; no automatic replacement renewal was attempted")
var errMCPNetworkBindingPending = errors.New("NETWORK_NATIVE_BINDING_PENDING: original renewed credential retained; native binding recovery is required before use")

// This is deliberately a closed exception to the installed-Node guard. It
// cannot configure invitations, Join, Owner proofs, grants or another Node.
func trustedNodeNetworkTool(name string) bool {
	switch name {
	case "cicada_network_directory", "cicada_network_resolve", "cicada_whoami", "cicada_send", "cicada_ask", "cicada_reply", "cicada_operation_status", "cicada_operation_retry", "cicada_request_status", "cicada_request_cancel":
		return true
	}
	return false
}

func (m *mcpServer) withTrustedNodeNetwork(network string, recoverMissing bool, fn func(harness.SessionContext, networkCLIState) (any, error)) (any, error) {
	if m.localNode == nil || !validNetworkRouteID(network) {
		return nil, errMCPNetworkSelection
	}
	if err := revalidateCodexLocalNode(context.Background(), m.localNode); err != nil {
		return nil, err
	}
	native, err := m.detectCurrentCodexSession()
	if err != nil || native.MachineID != m.localNode.Pin.NodeID {
		return nil, errMCPNetworkSelection
	}
	scope, _, err := mcpSessionScope(m.baseURL, native)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	m.sessionMu.RLock()
	domain := m.sessionDomain
	endpoint, currentToken := m.endpointID, m.sessionToken
	m.sessionMu.RUnlock()
	if endpoint != "" && currentToken != "" {
		// Domain access and the Group lease share a token/epoch. Never rotate
		// it through independent Network renewal. Read-only discovery remains
		// subject to its existing (normally empty) Network grants.
		state := networkCLIState{Version: 1, APIOrigin: m.baseURL, NetworkID: network, EndpointID: endpoint, Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace, SessionToken: currentToken}
		if _, err := m.networkPeerActor(state); err == nil {
			return fn(native, state)
		}
	}
	if domain.LocalDomainVersion != 0 {
		return nil, errMCPNetworkSelection
	}
	// The original discovery pin selects this directory. No environment or
	// model property may choose a credential path or sender Endpoint.
	parent, err := openLocalNodeDirectory(context.Background(), filepath.Dir(m.localNode.Pin.MCPSessionStateFile), false)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer parent.Close()
	base, err := localNodeChildDirectory(parent, "network-session", recoverMissing)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer base.Close()
	scopes, err := localNodeChildDirectory(base, "scopes", recoverMissing)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer scopes.Close()
	dir, err := localNodeChildDirectory(scopes, scope, recoverMissing)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer dir.Close()
	statePath := filepath.Join(filepath.Dir(m.localNode.Pin.MCPSessionStateFile), "network-session", "scopes", scope, network+".session.json")
	lock, err := boundedSelectedNetworkLock(dir, statePath, network)
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer lock.Unlock()
	filename := network + ".session.json"
	raw, _, readErr := readLocalNodeFile(dir, filename, 16<<10)
	if errors.Is(readErr, os.ErrNotExist) && recoverMissing {
		// A directory credential can be recovered only for the exact current
		// authenticated Endpoint, and only by the existing renewal Guard.
		endpoint := ""
		if m.isJoined() {
			self, err := m.api(http.MethodGet, "/v2/fabric/whoami", nil)
			if err != nil {
				return nil, errMCPNetworkSelection
			}
			card, err := networkCardFromResult(self)
			if err != nil || card.EndpointID == "" || card.NodeID != native.MachineID || card.NativeSessionID != native.NativeSessionID {
				return nil, errMCPNetworkSelection
			}
			endpoint = card.EndpointID
		}
		marker := network + ".renew-pending.json"
		if _, err := dir.Lstat(marker); err == nil {
			return nil, errMCPNetworkRenewUncertain
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errMCPNetworkSelection
		}
		intent, _ := json.Marshal(map[string]string{"network_id": network, "endpoint_id": endpoint, "scope": scope})
		f, err := dir.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, errMCPNetworkSelection
		}
		_, writeErr := f.Write(intent)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return nil, errMCPNetworkRenewUncertain
		}
		directory, err := dir.Open(".")
		if err != nil {
			return nil, errMCPNetworkRenewUncertain
		}
		syncErr := directory.Sync()
		directory.Close()
		if syncErr != nil {
			return nil, errMCPNetworkRenewUncertain
		}
		renewed, err := requestMachineAgentNetworkRenew(m.localNode.Pin.SocketPath, localNetworkRenewRequest{NetworkID: network, EndpointID: endpoint, Harness: native.Harness, NativeSessionID: native.NativeSessionID, Workspace: native.Workspace})
		// The legacy renewal route has no exact-operation receipt. Any failed
		// response is therefore retained as uncertain, even an apparent denial.
		if renewed == nil || renewed.NetworkID != network || renewed.SessionToken == "" || renewed.Endpoint.ID == "" || endpoint != "" && renewed.Endpoint.ID != endpoint || renewed.Endpoint.MachineID != native.MachineID || renewed.Endpoint.NativeSessionID != native.NativeSessionID || renewed.NativeContextScope.HubID != m.localNode.Pin.HubID {
			return nil, errMCPNetworkRenewUncertain
		}
		renewErr := err
		state := networkCLIState{Version: 1, APIOrigin: m.baseURL, NetworkID: network, EndpointID: renewed.Endpoint.ID, Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace, SessionToken: renewed.SessionToken}
		data, _ := json.Marshal(state)
		if err := writeNewPrivateNetworkSession(statePath, data); err != nil {
			return nil, errMCPNetworkRenewUncertain
		}
		if renewErr != nil {
			return nil, errMCPNetworkBindingPending
		}
		if err := dir.Remove(marker); err != nil {
			return nil, errMCPNetworkRenewUncertain
		}
		raw, _, readErr = readLocalNodeFile(dir, filename, 16<<10)
	}
	var state networkCLIState
	if readErr != nil || decodeLocalNodeJSON(raw, &state) != nil || state.Version != 1 || state.APIOrigin != m.baseURL || state.NetworkID != network || state.EndpointID == "" || state.SessionToken == "" || state.Harness != native.Harness || state.NativeSessionID != native.NativeSessionID || state.NodeID != native.MachineID || state.Workspace != native.Workspace {
		return nil, errMCPNetworkSelection
	}
	if _, err := dir.Lstat(network + ".renew-pending.json"); err == nil {
		return nil, errMCPNetworkBindingPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errMCPNetworkSelection
	}
	return fn(native, state)
}

func boundedSelectedNetworkLock(dir *os.Root, path, network string) (*flock.Flock, error) {
	guard, err := lockNetworkMCPState(filepath.Join(filepath.Dir(path), ".network-recovery"))
	if err != nil {
		return nil, errMCPNetworkSelection
	}
	defer guard.Unlock()
	exists := false
	for _, suffix := range []string{".session.json", ".session.json.lock", ".renew-pending.json"} {
		if info, err := dir.Lstat(network + suffix); err == nil {
			if !localNodePrivate(info, false) {
				return nil, errMCPNetworkSelection
			}
			exists = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errMCPNetworkSelection
		}
	}
	if !exists {
		file, err := dir.Open(".")
		if err != nil {
			return nil, errMCPNetworkSelection
		}
		entries, readErr := file.ReadDir(257)
		file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > 256 {
			return nil, errMCPNetworkSelection
		}
		ids := map[string]bool{}
		for _, entry := range entries {
			for _, suffix := range []string{".session.json.lock", ".session.json", ".renew-pending.json"} {
				if strings.HasSuffix(entry.Name(), suffix) {
					ids[strings.TrimSuffix(entry.Name(), suffix)] = true
					break
				}
			}
		}
		if len(ids) >= 64 {
			return nil, errors.New("NETWORK_RECOVERY_LIMIT: this native scope already retains 64 Network selections; no pending evidence was removed")
		}
	}
	return lockNetworkMCPState(path)
}

func (m *mcpServer) trustedNodeNetworkTool(name string, args map[string]any) (any, error) {
	if !trustedNodeNetworkTool(name) {
		return nil, codexLocalNodeError(ErrLocalNodeConfigRequired)
	}
	return m.withTrustedNodeNetwork(stringArgument(args, "network_id"), false, func(native harness.SessionContext, state networkCLIState) (any, error) {
		if name == "cicada_network_directory" || name == "cicada_network_resolve" {
			path := "/v2/fabric/networks/" + url.PathEscape(state.NetworkID)
			if name == "cicada_network_resolve" {
				return m.networkDirectHTTP(state, http.MethodPost, path+"/resolve", map[string]string{"query": stringArgument(args, "query")})
			}
			limit := intArgument(args, "limit")
			if limit < 1 || limit > 64 {
				limit = 64
			}
			return m.networkDirectHTTP(state, http.MethodGet, path+"/directory?limit="+strconv.Itoa(limit), nil)
		}
		return m.networkDirectToolLocked(name, args, native, state)
	})
}

func (m *mcpServer) networkPeerActor(state networkCLIState) (fabric.NetworkActor, error) {
	value, err := m.networkDirectHTTP(state, http.MethodGet, "/v2/fabric/networks/"+url.PathEscape(state.NetworkID)+"/whoami", nil)
	if err != nil {
		return fabric.NetworkActor{}, err
	}
	raw, _ := json.Marshal(value)
	var actor fabric.NetworkActor
	if json.Unmarshal(raw, &actor) != nil || actor.NetworkID != state.NetworkID || actor.EndpointID != state.EndpointID || actor.PrincipalID == "" {
		return actor, errMCPNetworkSelection
	}
	return actor, nil
}

func networkPeerSourceDigest(actor fabric.NetworkActor, state networkCLIState) string {
	return peerDigest([]any{actor.NetworkID, actor.EndpointID, actor.PrincipalID, state.APIOrigin, state.Harness, state.NativeSessionID, state.NodeID, state.Workspace, fabric.HashSessionCredential(state.SessionToken)})
}
