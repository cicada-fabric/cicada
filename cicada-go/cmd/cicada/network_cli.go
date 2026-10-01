package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
)

const networkUsage = "usage: cicada network consent-sign|join|renew|directory|resolve|leave|admin-invite|mcp-scope [options]"

func networkHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}
}

func validNetworkRouteID(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.' {
			continue
		}
		return false
	}
	return true
}

// Network credentials live in a separate private file from Group sessions.
// A Network-only registration is valid without a Group or a second writer.
type networkCLIState struct {
	Version         int    `json:"version"`
	APIOrigin       string `json:"api_origin"`
	NetworkID       string `json:"network_id"`
	EndpointID      string `json:"endpoint_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace"`
	SessionToken    string `json:"session_token"`
}

func networkCommand(args []string, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(networkUsage)
	}
	switch args[0] {
	case "consent-sign":
		return networkConsentSign(args[1:], output)
	case "mcp-scope":
		return networkMCPScope(args[1:], output)
	case "join":
		return networkCLIJoin(args[1:], output)
	case "renew":
		return networkCLIRenew(args[1:], output)
	case "directory", "resolve", "leave", "admin-invite":
		return networkCLISession(args[0], args[1:], output)
	case "create", "list", "migration-dry-run", "map-prepare", "map-quarantine", "map-approve", "activate", "invite", "invite-revoke", "member-revoke":
		return networkOperatorCommand(args[0], args[1:], output)
	default:
		return errors.New(networkUsage)
	}
}

func networkMCPScope(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network mcp-scope", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	networkID := flags.String("network", "", "Network ID")
	nativeSession := flags.String("session", "", "native Codex Session ID")
	workspace := flags.String("workspace", "", "native workspace")
	nodeID := flags.String("node", "", "Node ID")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || !validNetworkRouteID(*networkID) {
		return errors.New("mcp-scope requires --network")
	}
	context := harness.SessionContext{Harness: "codex", NativeSessionID: *nativeSession,
		Workspace: *workspace, MachineID: *nodeID}
	if context.NativeSessionID == "" || context.MachineID == "" || context.Workspace == "" {
		detected, err := harness.DetectCurrentSession()
		if err != nil {
			return err
		}
		if context.NativeSessionID == "" {
			context.NativeSessionID = detected.NativeSessionID
		}
		if context.MachineID == "" {
			context.MachineID = detected.MachineID
		}
		if context.Workspace == "" {
			context.Workspace = detected.Workspace
		}
	}
	scope, _, err := mcpSessionScope(envOr("CICADA_API_URL", "http://127.0.0.1:8787"), context)
	if err != nil {
		return err
	}
	joinRoot := os.Getenv("CICADA_NETWORK_JOIN_DIR")
	stateRoot := os.Getenv("CICADA_NETWORK_SESSION_DIR")
	if joinRoot == "" || stateRoot == "" {
		return errors.New("CICADA_NETWORK_JOIN_DIR and CICADA_NETWORK_SESSION_DIR are required")
	}
	joinDir := filepath.Join(joinRoot, "scopes", scope)
	stateDir := filepath.Join(stateRoot, "scopes", scope)
	return json.NewEncoder(output).Encode(map[string]any{"scope": scope, "network_id": *networkID,
		"invitation_file": filepath.Join(joinDir, *networkID+".invitation"),
		"proof_file":      filepath.Join(joinDir, *networkID+".proof.json"),
		"session_file":    filepath.Join(stateDir, *networkID+".session.json")})
}

func networkCLIRenew(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network renew", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	statePath := flags.String("session-state-file", "", "existing private Network session state file")
	socketPath := flags.String("node-socket", "", "owner-only local Node bridge socket")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *statePath == "" {
		return errors.New(networkUsage)
	}
	data, err := readPrivateNetworkFile(*statePath, 16*1024)
	if err != nil {
		return err
	}
	var state networkCLIState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 ||
		!validNetworkRouteID(state.NetworkID) || state.EndpointID == "" || state.NodeID == "" ||
		state.NativeSessionID == "" || state.Workspace == "" {
		return errors.New("invalid Network session state")
	}
	origin, err := normalizeMCPAPIOrigin(envOr("CICADA_API_URL", "http://127.0.0.1:8787"))
	if err != nil || origin != state.APIOrigin {
		return errors.New("Network session is bound to a different Hub API origin")
	}
	if *socketPath == "" {
		*socketPath = machineAgentJoinSocketPath(machineAgentStateDir(), state.NodeID)
	}
	renewed, err := requestMachineAgentNetworkRenew(*socketPath, localNetworkRenewRequest{
		NetworkID: state.NetworkID, EndpointID: state.EndpointID, Harness: state.Harness,
		NativeSessionID: state.NativeSessionID, Workspace: state.Workspace,
	})
	if err != nil {
		return err
	}
	state.SessionToken = renewed.SessionToken
	if err := replacePrivateNetworkFile(*statePath, mustJSON(state)); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{"status": "renewed", "network_id": state.NetworkID,
		"endpoint_id": state.EndpointID, "lease_expires_at": renewed.LeaseExpiresAt})
}

func networkConsentSign(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network consent-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("owner-private", "", "private Owner identity file on the Owner's trusted machine")
	proofPath := flags.String("proof-file", "", "new private file for the exact Join proof")
	invitationPath := flags.String("invitation-file", "", "private invitation token file")
	ownerID := flags.String("owner", "", "Owner ID")
	hubID := flags.String("hub", "", "authoritative Hub ID")
	networkID := flags.String("network", "", "Network ID")
	nodeID := flags.String("node", "", "Node ID bound to this Owner")
	sessionID := flags.String("session", "", "native Session ID")
	grantsArg := flags.String("grants", "", "exact comma-separated invitation grant set")
	preset := flags.String("preset", "", "named least-privilege Network permission preset")
	discoverable := flags.Bool("discoverable", false, "approve this Endpoint's directory disclosure")
	ttl := flags.Duration("ttl", 5*time.Minute, "proof lifetime, at most 15 minutes")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New(networkUsage)
	}
	if *privatePath == "" || *proofPath == "" || *invitationPath == "" || *ownerID == "" ||
		*hubID == "" || !validNetworkRouteID(*networkID) || *nodeID == "" || *sessionID == "" ||
		*ttl <= 0 || *ttl > 15*time.Minute {
		return errors.New("consent-sign requires exact Owner, Hub, Network, Node, native Session, invitation and bounded TTL")
	}
	private, err := readPrivateNetworkFile(*privatePath, 64*1024)
	if err != nil {
		return err
	}
	identity, err := e2ee.UnmarshalIdentity(private)
	if err != nil {
		return errors.New("invalid Owner private identity")
	}
	invitation, err := readPrivateNetworkFile(*invitationPath, 16*1024)
	if err != nil {
		return err
	}
	invitation = bytes.TrimSpace(invitation)
	if len(invitation) == 0 {
		return errors.New("invitation file is empty")
	}
	digest := sha256.Sum256(invitation)
	grants, err := selectNetworkPermissionGrants(*grantsArg, *preset, true)
	if err != nil {
		return err
	}
	if *discoverable {
		published := false
		for _, grant := range grants {
			if grant == "directory.publish" {
				published = true
			}
		}
		if !published {
			return errors.New("discoverable consent requires the directory.publish grant")
		}
	}
	now := time.Now().UTC()
	proof, err := identity.SignOwnerNetworkJoinGrant(*ownerID, *hubID, *networkID,
		*nodeID, *sessionID, hex.EncodeToString(digest[:]), identity.Public().ID,
		grants, *discoverable, now, now.Add(*ttl))
	if err != nil {
		return fmt.Errorf("sign Network Join consent: %w", err)
	}
	if err := writeNewPrivateNetworkFile(*proofPath, proof); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{
		"status": "signed", "proof_file": *proofPath, "owner_key_id": identity.Public().ID,
		"network_id": *networkID, "expires_at": now.Add(*ttl).Format(time.RFC3339Nano),
	})
}

func networkCLIJoin(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network join", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	networkID := flags.String("network", "", "Network ID")
	invitationPath := flags.String("invitation-file", "", "private invitation token file")
	proofPath := flags.String("proof-file", "", "private Owner-signed Join proof file")
	statePath := flags.String("session-state-file", "", "private Network session state file")
	socketPath := flags.String("node-socket", "", "owner-only local Node bridge socket")
	endpointName := flags.String("name", "", "Network nickname")
	nativeSession := flags.String("session", "", "native Codex Session ID; defaults to current Session")
	workspace := flags.String("workspace", "", "native Codex workspace; defaults to current Session")
	nodeID := flags.String("node", "", "local Node ID; defaults to current Session")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New(networkUsage)
	}
	if !validNetworkRouteID(*networkID) || *invitationPath == "" || *proofPath == "" || *statePath == "" {
		return errors.New("network join requires --network, --invitation-file, --proof-file and --session-state-file")
	}
	context := harness.SessionContext{Harness: "codex", NativeSessionID: strings.TrimSpace(*nativeSession),
		Workspace: strings.TrimSpace(*workspace), MachineID: strings.TrimSpace(*nodeID)}
	if context.NativeSessionID == "" || context.Workspace == "" || context.MachineID == "" {
		detected, detectErr := harness.DetectCurrentSession()
		if detectErr != nil && context.NativeSessionID == "" {
			return detectErr
		}
		if detectErr == nil {
			if context.NativeSessionID == "" {
				context.NativeSessionID = detected.NativeSessionID
			}
			if context.Workspace == "" {
				context.Workspace = detected.Workspace
			}
			if context.MachineID == "" {
				context.MachineID = detected.MachineID
			}
		}
	}
	if context.NativeSessionID == "" || context.Workspace == "" || context.MachineID == "" {
		return errors.New("native Session, workspace and Node are required")
	}
	invitation, err := readPrivateNetworkFile(*invitationPath, 16*1024)
	if err != nil {
		return err
	}
	proof, err := readPrivateNetworkFile(*proofPath, 16*1024)
	if err != nil {
		return err
	}
	if *socketPath == "" {
		*socketPath = defaultMCPJoinSocketPath(context)
	}
	joined, nativeScope, recovery, err := requestMachineAgentNetworkJoinWithScopeAndRecovery(*socketPath, localNetworkJoinRequest{
		NetworkID: *networkID, InvitationToken: string(bytes.TrimSpace(invitation)),
		OwnerJoinProof: string(bytes.TrimSpace(proof)), Harness: context.Harness,
		NativeSessionID: context.NativeSessionID, Workspace: context.Workspace,
		EndpointName: *endpointName,
	})
	if err != nil {
		if recovery, ok := localJoinRecoveryFromError(err); ok {
			return json.NewEncoder(output).Encode(recovery)
		}
		return err
	}
	origin, err := normalizeMCPAPIOrigin(envOr("CICADA_API_URL", "http://127.0.0.1:8787"))
	if err != nil {
		return err
	}
	state := networkCLIState{Version: 1, APIOrigin: origin, NetworkID: joined.NetworkID,
		EndpointID: joined.Endpoint.ID, Harness: context.Harness, NativeSessionID: context.NativeSessionID,
		NodeID: context.MachineID, Workspace: context.Workspace, SessionToken: joined.SessionToken}
	if err := writeNewPrivateNetworkFile(*statePath, mustJSON(state)); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{
		"status": "joined", "network_id": joined.NetworkID, "endpoint_id": joined.Endpoint.ID,
		"binding_id": joined.BindingID, "binding_epoch": joined.BindingEpoch,
		"lease_expires_at": joined.LeaseExpiresAt, "native_context_scope": nativeScope, "join_recovery": recovery,
	})
}

func networkCLISession(operation string, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("network "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	statePath := flags.String("session-state-file", "", "private Network session state file")
	query := flags.String("query", "", "Endpoint ID or Network nickname")
	limit := flags.Int("limit", 100, "directory result limit")
	reason := flags.String("reason", "", "optional leave reason")
	targetOwner := flags.String("target-owner", "", "Owner invited by a scoped Network administrator")
	grantsArg := flags.String("grants", "", "exact comma-separated invitation grants")
	preset := flags.String("preset", "", "named least-privilege Network permission preset")
	invitationPath := flags.String("invitation-file", "", "new private file for invitation token")
	ttl := flags.Duration("ttl", 15*time.Minute, "invitation lifetime")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *statePath == "" {
		return errors.New(networkUsage)
	}
	if operation == "resolve" && strings.TrimSpace(*query) == "" {
		return errors.New("network resolve requires --query")
	}
	if operation == "admin-invite" && (*targetOwner == "" || *invitationPath == "" || *ttl <= 0 || *ttl > 24*time.Hour) {
		return errors.New("admin-invite requires target Owner, private invitation file and TTL <= 24 hours")
	}
	data, err := readPrivateNetworkFile(*statePath, 16*1024)
	if err != nil {
		return err
	}
	var state networkCLIState
	if err := json.Unmarshal(data, &state); err != nil || state.Version != 1 ||
		!validNetworkRouteID(state.NetworkID) || state.EndpointID == "" || state.SessionToken == "" {
		return errors.New("invalid Network session state")
	}
	baseURL := envOr("CICADA_API_URL", "http://127.0.0.1:8787")
	origin, err := normalizeMCPAPIOrigin(baseURL)
	if err != nil || origin != state.APIOrigin {
		return errors.New("Network session is bound to a different Hub API origin")
	}
	method, path := http.MethodGet, "/v2/fabric/networks/"+state.NetworkID+"/directory"
	var body any
	switch operation {
	case "directory":
		if *limit < 1 || *limit > 200 {
			return errors.New("directory limit must be 1 through 200")
		}
		path += fmt.Sprintf("?limit=%d", *limit)
	case "resolve":
		method, path, body = http.MethodPost, "/v2/fabric/networks/"+state.NetworkID+"/resolve", map[string]string{"query": *query}
	case "leave":
		method, path, body = http.MethodPost, "/v2/fabric/networks/"+state.NetworkID+"/leave", map[string]string{"reason": *reason}
	case "admin-invite":
		grants, err := selectNetworkPermissionGrants(*grantsArg, *preset, false)
		if err != nil {
			return err
		}
		method, path, body = http.MethodPost, "/v2/fabric/networks/"+state.NetworkID+"/invitations",
			map[string]any{"target_owner_id": *targetOwner, "grants": grants, "ttl_seconds": int(ttl.Seconds())}
	}
	var reader io.Reader
	if body != nil {
		encoded, _ := json.Marshal(body)
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, strings.TrimRight(baseURL, "/")+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Cicada-Network-Session "+state.SessionToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := networkHTTPClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return err
	}
	if response.StatusCode >= 400 {
		message := strings.ReplaceAll(string(result), state.SessionToken, "<redacted>")
		return fmt.Errorf("Network API %s: %s", response.Status, message)
	}
	if operation == "leave" {
		if err := os.Remove(*statePath); err != nil {
			return fmt.Errorf("left Network but could not remove local credential: %w", err)
		}
	}
	if operation == "admin-invite" {
		var issued struct {
			NetworkID       string   `json:"network_id"`
			TargetOwnerID   string   `json:"target_owner_id"`
			InvitationToken string   `json:"invitation_token"`
			Grants          []string `json:"grants"`
			ExpiresAt       string   `json:"expires_at"`
		}
		if err := json.Unmarshal(result, &issued); err != nil || issued.InvitationToken == "" || issued.NetworkID != state.NetworkID {
			return errors.New("Hub returned an invalid Network invitation")
		}
		if err := writeNewPrivateNetworkFile(*invitationPath, []byte(issued.InvitationToken+"\n")); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(map[string]any{"status": "issued", "network_id": issued.NetworkID,
			"target_owner_id": issued.TargetOwnerID, "grants": issued.Grants,
			"expires_at": issued.ExpiresAt, "invitation_file": *invitationPath})
	}
	_, err = output.Write(append(bytes.TrimSpace(result), '\n'))
	return err
}

func readPrivateNetworkFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Network credential/proof file must be a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, errors.New("Network credential/proof file is empty or too large")
	}
	return data, nil
}

func writeNewPrivateNetworkFile(path string, data []byte) error {
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("Network credential/proof directory must already be private")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func replacePrivateNetworkFile(path string, data []byte) error {
	if _, err := readPrivateNetworkFile(path, 16*1024); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Network credential directory must be private")
	}
	temporary, err := os.CreateTemp(parent, ".network-session-*")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporary.Name())
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return err
	}
	keep = true
	return nil
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
