package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/pqtls"
)

// These are local, same-OS-user management DTOs. They are not Hub wire
// messages, enrollment authority, or evidence that a remote grant was revoked.
const (
	LocalNodeHubsFormat          = "cicada.local-node-hubs.v1"
	LocalNodeHubRegistryFormat   = "cicada.node-hub-registry.v1"
	LocalNodeHubRemovalFormat    = "cicada.local-node-hub-removal.v1"
	MaxLocalNodeHubConnections   = 8
	MaxLocalNodeHubListBytes     = 64 << 10
	MaxLocalNodeHubRegistryBytes = 192 << 10
)

var ErrLocalNodeHubConfig = errors.New("NODE_HUB_CONFIG_INVALID")

type LocalNodeHubSelection struct {
	UserRoot     string
	ConnectionID string
	Alias        string
	HubAddress   string
	HubID        string
	NodeID       string
}

type LocalNodeHubView struct {
	ConnectionID string `json:"connection_id"`
	HubID        string `json:"hub_id"`
	NodeID       string `json:"node_id"`
	Alias        string `json:"alias"`
	HubAddress   string `json:"hub_address"`
	NodeName     string `json:"node_name"`
	DesiredState string `json:"desired_state"`
	PairingState string `json:"pairing_state"`
	RuntimeState string `json:"runtime_state"`
	HubOnline    string `json:"hub_online"`
	LocalFence   uint64 `json:"local_fence"`
}

type LocalNodeHubList struct {
	Format       string             `json:"format"`
	Revision     uint64             `json:"revision"`
	ManagerState string             `json:"manager_state"`
	Connections  []LocalNodeHubView `json:"connections"`
}

// New admission and original-service adoption are disjoint modes. Adoption
// reads the exact protected v1 service configuration; it never copies keys.
type LocalNodeHubAddInput struct {
	UserRoot     string
	ConnectionID string
	HubAddress   string
	Alias        string
	NodeID       string
	NodeName     string
	FromService  bool
	RetryPairing bool
}

type LocalNodeHubRemoval struct {
	Format           string `json:"format"`
	ConnectionID     string `json:"connection_id"`
	HubID            string `json:"hub_id"`
	NodeID           string `json:"node_id"`
	LocalFence       uint64 `json:"local_fence"`
	State            string `json:"state"`
	RemoteRevocation string `json:"remote_revocation"`
}

// Frozen local operation boundary. The implementation is supplied only after
// contract review; it composes the existing NPT and per-Hub Agent services.
type localNodeHubManagerOperations interface {
	List(context.Context, string) (LocalNodeHubList, error)
	Add(context.Context, LocalNodeHubAddInput) (LocalNodeHubView, error)
	Remove(context.Context, LocalNodeHubSelection) (LocalNodeHubRemoval, error)
}

// The MCP facade consumes verified live pins through this Go boundary. It
// never reads registry paths or treats configured/starting entries as live.
type ListVerifiedLocalNodeConnectionsFunc func(context.Context, string) ([]LocalNodeConnection, error)

type nodeHubRegistry struct {
	Format      string                 `json:"format"`
	Revision    uint64                 `json:"revision"`
	NodeID      string                 `json:"node_id"`
	NodeName    string                 `json:"node_name"`
	WriterRoot  string                 `json:"writer_root"`
	Connections []nodeHubRegistryEntry `json:"connections"`
}
type nodeHubRegistryEntry struct {
	ConnectionID        string `json:"connection_id"`
	Alias               string `json:"alias"`
	HubID               string `json:"hub_id"`
	NodeID              string `json:"node_id"`
	NodeName            string `json:"node_name"`
	HubAddress          string `json:"hub_address"`
	Origin              string `json:"origin"`
	StateDir            string `json:"state_dir"`
	WriterRoot          string `json:"writer_root"`
	MCPSessionStateFile string `json:"mcp_session_state_file"`
	MCPOutboxStateFile  string `json:"mcp_outbox_state_file"`
	DesiredState        string `json:"desired_state"`
	LocalFence          uint64 `json:"local_fence"`
}

// The manager's only local control operations are observational STATUS and
// RECONCILE of the already persisted desired registry. No remote method,
// command, environment, credential or executable is accepted through IPC.
type nodeHubControlRequest struct {
	Format     string `json:"format"`
	Operation  string `json:"operation"`
	Nonce      string `json:"nonce"`
	InstanceID string `json:"instance_id"`
	Revision   uint64 `json:"revision"`
}

type nodeHubControlReply struct {
	Format     string           `json:"format"`
	Operation  string           `json:"operation"`
	Nonce      string           `json:"nonce"`
	InstanceID string           `json:"instance_id"`
	Revision   uint64           `json:"revision"`
	Result     LocalNodeHubList `json:"result"`
}

func decodeNodeHubControlRequest(raw []byte) (nodeHubControlRequest, error) {
	var out nodeHubControlRequest
	if len(raw) == 0 || len(raw) > 1024 || decodeLocalNodeJSON(raw, &out) != nil || out.Format != "cicada.node-hub-control.v1" || !localNodeHubOneOf(out.Operation, "STATUS", "RECONCILE") || !localContextHex(out.Nonce, 32) || !localContextHex(out.InstanceID, 32) || out.Revision >= 1<<63 {
		return nodeHubControlRequest{}, ErrLocalNodeHubConfig
	}
	return out, nil
}

func decodeNodeHubControlReply(raw []byte, request nodeHubControlRequest) (nodeHubControlReply, error) {
	var out nodeHubControlReply
	if len(raw) == 0 || len(raw) > MaxLocalNodeHubListBytes+1024 || decodeLocalNodeJSON(raw, &out) != nil || out.Format != "cicada.node-hub-control-reply.v1" || out.Operation != request.Operation || out.Nonce != request.Nonce || out.InstanceID != request.InstanceID || out.Revision < request.Revision || out.Revision != out.Result.Revision {
		return nodeHubControlReply{}, ErrLocalNodeHubConfig
	}
	list, err := json.Marshal(out.Result)
	if err != nil {
		return nodeHubControlReply{}, ErrLocalNodeHubConfig
	}
	if _, err = DecodeLocalNodeHubList(list); err != nil {
		return nodeHubControlReply{}, ErrLocalNodeHubConfig
	}
	return out, nil
}

func decodeNodeHubRegistry(raw []byte) (nodeHubRegistry, error) {
	var out nodeHubRegistry
	if len(raw) == 0 || len(raw) > MaxLocalNodeHubRegistryBytes || decodeLocalNodeJSON(raw, &out) != nil || out.Format != LocalNodeHubRegistryFormat || out.Revision == 0 || out.Revision >= 1<<63 || !localNodeHubText(out.NodeID, 128) || !localNodeHubText(out.NodeName, 128) || !localNodePath(out.WriterRoot) || out.Connections == nil || len(out.Connections) > MaxLocalNodeHubConnections {
		return nodeHubRegistry{}, ErrLocalNodeHubConfig
	}
	ids, aliases, hubs, paths, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range out.Connections {
		if !localContextHex(v.ConnectionID, 32) || !localNodeHubText(v.Alias, 128) || !localNodeHubText(v.NodeID, 128) || !localNodeHubText(v.NodeName, 128) || v.LocalFence == 0 || v.LocalFence >= 1<<63 || !localNodeHubOneOf(v.DesiredState, "ENABLED", "REMOVING") || ids[v.ConnectionID] || aliases[strings.ToLower(v.Alias)] || v.HubID != "" && hubs[v.HubID] || paths[v.StateDir] || paths[v.MCPSessionStateFile] || paths[v.MCPOutboxStateFile] || v.MCPSessionStateFile == v.MCPOutboxStateFile || v.WriterRoot != out.WriterRoot {
			return nodeHubRegistry{}, ErrLocalNodeHubConfig
		}
		if v.HubID != "" && !localNodeHubText(v.HubID, 128) || pqtls.ValidateIPDialAddress(v.HubAddress) != nil || addresses[v.HubAddress] {
			return nodeHubRegistry{}, ErrLocalNodeHubConfig
		}
		if v.Origin != "" {
			origin, err := normalizeControlURL(v.Origin)
			if err != nil || origin != v.Origin {
				return nodeHubRegistry{}, ErrLocalNodeHubConfig
			}
		}
		for _, p := range []string{v.StateDir, v.WriterRoot, v.MCPSessionStateFile, v.MCPOutboxStateFile} {
			if !localNodePath(p) {
				return nodeHubRegistry{}, ErrLocalNodeHubConfig
			}
		}
		ids[v.ConnectionID], aliases[strings.ToLower(v.Alias)], paths[v.StateDir] = true, true, true
		paths[v.MCPSessionStateFile], paths[v.MCPOutboxStateFile] = true, true
		addresses[v.HubAddress] = true
		if v.HubID != "" {
			hubs[v.HubID] = true
		}
	}
	return out, nil
}

func localNodeHubText(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func localNodeHubOneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func ValidateLocalNodeHubView(v LocalNodeHubView) error {
	if !localContextHex(v.ConnectionID, 32) || !localNodeHubText(v.Alias, 128) || !localNodeHubText(v.NodeID, 128) || !localNodeHubText(v.NodeName, 128) || v.LocalFence == 0 || v.LocalFence >= 1<<63 || !localNodeHubOneOf(v.DesiredState, "ENABLED", "REMOVING") || !localNodeHubOneOf(v.PairingState, "NOT_STARTED", "PENDING", "READY", "TERMINAL", "UNKNOWN") || !localNodeHubOneOf(v.RuntimeState, "STOPPED", "STARTING", "RUNNING", "STOPPING", "FAILED", "UNKNOWN") || v.HubOnline != "UNKNOWN" {
		return ErrLocalNodeHubConfig
	}
	if pqtls.ValidateIPDialAddress(v.HubAddress) != nil {
		return ErrLocalNodeHubConfig
	}
	if v.HubID != "" && !localNodeHubText(v.HubID, 128) {
		return ErrLocalNodeHubConfig
	}
	if v.PairingState == "READY" && v.HubID == "" {
		return ErrLocalNodeHubConfig
	}
	if v.RuntimeState == "RUNNING" && (v.DesiredState != "ENABLED" || v.PairingState != "READY") {
		return ErrLocalNodeHubConfig
	}
	return nil
}

func DecodeLocalNodeHubList(raw []byte) (LocalNodeHubList, error) {
	var out LocalNodeHubList
	if len(raw) == 0 || len(raw) > MaxLocalNodeHubListBytes || decodeLocalNodeJSON(raw, &out) != nil || out.Format != LocalNodeHubsFormat || out.Revision >= 1<<63 || !localNodeHubOneOf(out.ManagerState, "STOPPED", "RUNNING", "UNKNOWN") || out.Connections == nil || len(out.Connections) > MaxLocalNodeHubConnections {
		return out, ErrLocalNodeHubConfig
	}
	ids, aliases, hubs, addresses := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range out.Connections {
		if ValidateLocalNodeHubView(v) != nil || ids[v.ConnectionID] || aliases[strings.ToLower(v.Alias)] || addresses[v.HubAddress] || v.HubID != "" && hubs[v.HubID] || out.ManagerState == "STOPPED" && v.RuntimeState == "RUNNING" {
			return LocalNodeHubList{}, ErrLocalNodeHubConfig
		}
		ids[v.ConnectionID], aliases[strings.ToLower(v.Alias)] = true, true
		addresses[v.HubAddress] = true
		if v.HubID != "" {
			hubs[v.HubID] = true
		}
	}
	return out, nil
}

func DecodeLocalNodeHubRemoval(raw []byte) (LocalNodeHubRemoval, error) {
	var out LocalNodeHubRemoval
	if len(raw) == 0 || len(raw) > 4<<10 || decodeLocalNodeJSON(raw, &out) != nil || out.Format != LocalNodeHubRemovalFormat || !localContextHex(out.ConnectionID, 32) || !localNodeHubText(out.NodeID, 128) || out.HubID != "" && !localNodeHubText(out.HubID, 128) || out.LocalFence == 0 || out.LocalFence >= 1<<63 || !localNodeHubOneOf(out.State, "LOCAL_STOPPED", "STOP_PENDING") || out.RemoteRevocation != "NOT_REQUESTED" {
		return LocalNodeHubRemoval{}, ErrLocalNodeHubConfig
	}
	return out, nil
}
