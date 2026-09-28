package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/gofrs/flock"
)

// Network secrets are configured in private local files, never in model tool
// arguments. Separate files per Network preserve multiple registrations for
// the same native Thread without changing its Group session or native writer.
func mcpNetworkFile(dir, networkID, suffix string) (string, error) {
	if dir == "" || !validNetworkRouteID(networkID) {
		return "", errors.New("a private Network directory and valid network_id are required")
	}
	return filepath.Join(dir, networkID+suffix), nil
}

func privateNetworkScopeDir(root, scope string, create bool) (string, error) {
	if root == "" || scope == "" {
		return "", errors.New("private Network scope directory is required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("Network root directory must already be private")
	}
	scopes := filepath.Join(root, "scopes")
	path := filepath.Join(scopes, scope)
	if create {
		if err := ensureMCPPrivateDir(scopes); err != nil {
			return "", err
		}
		if err := ensureMCPPrivateDir(path); err != nil {
			return "", err
		}
	} else {
		for _, candidate := range []string{scopes, path} {
			info, err := os.Lstat(candidate)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return "", errors.New("Network Join scope directory must already be private")
			}
		}
	}
	return path, nil
}

func lockNetworkMCPState(path string) (*flock.Flock, error) {
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("Network session lock file is not private")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	for attempt := 0; attempt < 200; attempt++ {
		locked, err := lock.TryLock()
		if err != nil {
			return nil, err
		}
		if locked {
			return lock, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("Network session is busy")
}

func (m *mcpServer) networkTool(name string, arguments map[string]any) (any, error) {
	networkID := stringArgument(arguments, "network_id")
	context, err := detectCodexMCPJoinSession()
	if err != nil {
		return nil, err
	}
	scope, _, err := mcpSessionScope(m.baseURL, context)
	if err != nil {
		return nil, err
	}
	stateDir, err := privateNetworkScopeDir(os.Getenv("CICADA_NETWORK_SESSION_DIR"), scope, true)
	if err != nil {
		return nil, err
	}
	statePath, err := mcpNetworkFile(stateDir, networkID, ".session.json")
	if err != nil {
		return nil, err
	}
	lock, err := lockNetworkMCPState(statePath)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()
	return m.networkToolLocked(name, arguments, context, scope, statePath)
}

func (m *mcpServer) networkToolLocked(name string, arguments map[string]any,
	context harness.SessionContext, scope, statePath string) (any, error) {
	networkID := stringArgument(arguments, "network_id")
	if name == "cicada_network_renew" {
		data, err := readPrivateNetworkFile(statePath, 16*1024)
		if err != nil {
			return nil, err
		}
		var state networkCLIState
		if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 ||
			state.NetworkID != networkID || state.EndpointID == "" ||
			state.NativeSessionID != context.NativeSessionID || state.NodeID != context.MachineID ||
			state.Harness != context.Harness || state.Workspace != context.Workspace {
			return nil, errors.New("Network session state does not match this native Session")
		}
		origin, err := normalizeMCPAPIOrigin(m.baseURL)
		if err != nil || state.APIOrigin != origin {
			return nil, errors.New("Network session state belongs to a different Hub origin")
		}
		renewed, err := requestMachineAgentNetworkRenew(defaultMCPJoinSocketPath(context), localNetworkRenewRequest{
			NetworkID: networkID, EndpointID: state.EndpointID, Harness: context.Harness,
			NativeSessionID: context.NativeSessionID, Workspace: context.Workspace,
		})
		if err != nil {
			return nil, err
		}
		state.SessionToken = renewed.SessionToken
		if err := replacePrivateNetworkFile(statePath, mustJSON(state)); err != nil {
			return nil, err
		}
		return map[string]any{"status": "renewed", "network_id": networkID,
			"endpoint_id": state.EndpointID, "lease_expires_at": renewed.LeaseExpiresAt}, nil
	}
	if name == "cicada_network_join" {
		if _, err := os.Lstat(statePath); err == nil {
			return m.networkToolLocked("cicada_network_renew", arguments, context, scope, statePath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		joinDir, err := privateNetworkScopeDir(os.Getenv("CICADA_NETWORK_JOIN_DIR"), scope, false)
		if err != nil {
			return nil, err
		}
		invitationPath, err := mcpNetworkFile(joinDir, networkID, ".invitation")
		if err != nil {
			return nil, err
		}
		proofPath, err := mcpNetworkFile(joinDir, networkID, ".proof.json")
		if err != nil {
			return nil, err
		}
		invitation, err := readPrivateNetworkFile(invitationPath, 16*1024)
		if err != nil {
			return nil, err
		}
		proof, err := readPrivateNetworkFile(proofPath, 16*1024)
		if err != nil {
			return nil, err
		}
		joined, err := requestMachineAgentNetworkJoin(defaultMCPJoinSocketPath(context), localNetworkJoinRequest{
			NetworkID: networkID, InvitationToken: string(bytes.TrimSpace(invitation)),
			OwnerJoinProof: string(bytes.TrimSpace(proof)), Harness: context.Harness,
			NativeSessionID: context.NativeSessionID, Workspace: context.Workspace,
		})
		if err != nil {
			return nil, err
		}
		origin, err := normalizeMCPAPIOrigin(m.baseURL)
		if err != nil {
			return nil, err
		}
		state := networkCLIState{Version: 1, APIOrigin: origin, NetworkID: networkID,
			EndpointID: joined.Endpoint.ID, Harness: context.Harness,
			NativeSessionID: context.NativeSessionID, NodeID: context.MachineID,
			Workspace: context.Workspace, SessionToken: joined.SessionToken}
		if err := writeNewPrivateNetworkFile(statePath, mustJSON(state)); err != nil {
			return nil, err
		}
		return map[string]any{"status": "joined", "network_id": networkID,
			"endpoint_id": joined.Endpoint.ID, "lease_expires_at": joined.LeaseExpiresAt}, nil
	}
	data, err := readPrivateNetworkFile(statePath, 16*1024)
	if err != nil {
		return nil, err
	}
	var state networkCLIState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 ||
		state.NetworkID != networkID || state.EndpointID == "" || state.SessionToken == "" ||
		state.NativeSessionID != context.NativeSessionID || state.NodeID != context.MachineID ||
		state.Harness != context.Harness || state.Workspace != context.Workspace {
		return nil, errors.New("Network session state does not match this native Session")
	}
	origin, err := normalizeMCPAPIOrigin(m.baseURL)
	if err != nil || state.APIOrigin != origin {
		return nil, errors.New("Network session state belongs to a different Hub origin")
	}
	if isMCPNetworkDirectTool(name) {
		return m.networkDirectToolLocked(name, arguments, context, state)
	}
	method, path := http.MethodGet, "/v2/fabric/networks/"+networkID+"/directory"
	var payload any
	switch name {
	case "cicada_network_directory":
		limit := intArgument(arguments, "limit")
		if limit > 0 {
			path += "?limit=" + strconv.Itoa(limit)
		}
	case "cicada_network_resolve":
		query := stringArgument(arguments, "query")
		if query == "" {
			return nil, errors.New("query is required")
		}
		method, path, payload = http.MethodPost, "/v2/fabric/networks/"+networkID+"/resolve", map[string]string{"query": query}
	case "cicada_network_leave":
		method, path, payload = http.MethodPost, "/v2/fabric/networks/"+networkID+"/leave", map[string]string{"reason": stringArgument(arguments, "reason")}
	}
	var reader io.Reader
	if payload != nil {
		encoded, _ := json.Marshal(payload)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, m.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Cicada-Network-Session "+state.SessionToken)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := networkHTTPClient().Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("Network API %s: %s", response.Status,
			strings.ReplaceAll(string(result), state.SessionToken, "<redacted>"))
	}
	var value any
	if err := json.Unmarshal(result, &value); err != nil {
		return nil, errors.New("invalid Network response")
	}
	if name == "cicada_network_leave" {
		if err := os.Remove(statePath); err != nil {
			return value, fmt.Errorf("left Network but could not remove local credential: %w", err)
		}
	}
	return value, nil
}
