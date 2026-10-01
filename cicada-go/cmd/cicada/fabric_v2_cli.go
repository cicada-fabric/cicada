package main

// This file contains the v2 operator CLI facade.  It deliberately lives next
// to (rather than inside) main.go so the legacy v1 commands can remain
// available while callers migrate.  A v2 peer operation always uses the
// credential returned by the explicit join call; endpoint, group, role, and
// sender values in a command line are never treated as caller identity.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
)

const (
	fabricV2SessionTokenEnv = "CICADA_SESSION_TOKEN"
	fabricV2SessionFileEnv  = "CICADA_SESSION_TOKEN_FILE"
)

// fabricV2SessionState is deliberately scoped to the API origin and the
// native context used during explicit enrollment. A raw credential file would
// be too easy to reuse accidentally for another configured Control or thread.
type fabricV2SessionState struct {
	Version         int    `json:"version"`
	APIOrigin       string `json:"api_origin"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	NodeID          string `json:"node_id"`
	Workspace       string `json:"workspace,omitempty"`
	GroupID         string `json:"group_id"`
	EndpointID      string `json:"endpoint_id"`
	BindingID       string `json:"binding_id,omitempty"`
	BindingEpoch    uint64 `json:"binding_epoch,omitempty"`
	LeaseExpiresAt  string `json:"lease_expires_at,omitempty"`
	SessionToken    string `json:"session_token"`
}

const fabricV2SessionStateVersion = 1

// fabricV2Command is intentionally separate from the legacy fabricCommand in
// main.go.  main can route `fabric v2 ...` (or a future default) here without
// changing the operationally compatible v1 facade in the same release.
func fabricV2Command(baseURL string, args []string) error {
	return fabricV2CommandOutput(baseURL, args, os.Stdout)
}

func fabricV2CommandOutput(baseURL string, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New(fabricV2Usage)
	}
	client := &fabricV2CLI{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		output:  output,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	if client.baseURL == "" {
		return errors.New("Cicada API URL is required")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "join":
		return client.join(args[1:])
	case "leave":
		return client.leave(args[1:])
	case "leave-group":
		return client.leaveGroup(args[1:])
	case "use-group":
		return client.useGroup(args[1:])
	case "heartbeat", "renew":
		return client.heartbeat(args[1:])
	case "whoami":
		return client.sessionRequest(http.MethodGet, "/v2/fabric/whoami", nil)
	case "members", "list":
		return client.members(args[1:])
	case "find", "resolve", "inspect":
		return client.find(strings.ToLower(strings.TrimSpace(args[0])), args[1:])
	case "receive":
		return client.receive(args[1:])
	case "request-status", "status":
		return client.requestStatus(args[1:])
	case "cancel", "request-cancel":
		return client.cancel(args[1:])
	default:
		return errors.New(fabricV2Usage)
	}
}

const fabricV2Usage = "usage: cicada fabric v2 join|use-group|leave-group|leave|heartbeat|whoami|members|find|resolve|inspect|receive|request-status|cancel"

type fabricV2CLI struct {
	baseURL string
	output  io.Writer
	http    *http.Client
}

func (c *fabricV2CLI) join(args []string) error {
	flags := flag.NewFlagSet("fabric v2 join", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	group := flags.String("group", "", "Fabric Group ID (required)")
	groupID := flags.String("group-id", "", "Compatibility alias for --group")
	endpointID := flags.String("endpoint", "", "Existing stable Endpoint ID to rebind")
	name := flags.String("name", "", "Human-readable Endpoint name")
	harnessName := flags.String("harness", "", "Native harness")
	nativeSession := flags.String("session", "", "Native session/thread ID")
	nativeSessionID := flags.String("native-session-id", "", "Compatibility alias for --session")
	nodeID := flags.String("node", "", "Machine/Node ID")
	node := flags.String("node-id", "", "Compatibility alias for --node")
	machine := flags.String("machine", "", "Compatibility alias for --node")
	workspace := flags.String("workspace", "", "Workspace path")
	leaseSeconds := flags.Int("lease-seconds", 0, "Session lease duration in seconds")
	continuity := flags.String("context-continuity", "", "Verified native context continuity mode")
	tokenFile := flags.String("session-token-file", "", "Where to store the v2 session credential")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("fabric v2 join does not accept positional arguments")
	}
	if strings.TrimSpace(*group) == "" {
		*group = strings.TrimSpace(*groupID)
	}
	if strings.TrimSpace(*group) == "" {
		return errors.New("fabric v2 join requires --group GROUP_ID")
	}
	if strings.TrimSpace(*nativeSession) == "" {
		*nativeSession = strings.TrimSpace(*nativeSessionID)
	}
	if strings.TrimSpace(*nodeID) == "" {
		*nodeID = strings.TrimSpace(*node)
	}
	if strings.TrimSpace(*nodeID) == "" {
		*nodeID = strings.TrimSpace(*machine)
	}

	// Explicit join is the user action.  Session metadata may still be
	// discovered from the harness so the command does not require copying a
	// native UUID, but discovery never creates a membership implicitly.
	context := harness.SessionContext{}
	needsDiscovery := strings.TrimSpace(*nativeSession) == "" || strings.TrimSpace(*harnessName) == "" ||
		strings.TrimSpace(*nodeID) == "" || strings.TrimSpace(*workspace) == ""
	if needsDiscovery {
		detected, err := harness.DetectCurrentSession()
		if err != nil && strings.TrimSpace(*nativeSession) == "" {
			return err
		}
		if err == nil {
			context = detected
		}
	}
	if strings.TrimSpace(*nativeSession) == "" {
		*nativeSession = context.NativeSessionID
	}
	if strings.TrimSpace(*harnessName) == "" {
		*harnessName = context.Harness
	}
	if strings.TrimSpace(*nodeID) == "" {
		*nodeID = context.MachineID
	}
	if strings.TrimSpace(*workspace) == "" {
		*workspace = context.Workspace
	}
	if strings.TrimSpace(*nativeSession) == "" || strings.TrimSpace(*nodeID) == "" {
		return errors.New("fabric v2 join requires a native session and node; set --session and --node or configure the current harness")
	}
	if strings.TrimSpace(*harnessName) == "" {
		*harnessName = "codex"
	}

	_, body, err := c.request(http.MethodPost, "/v2/fabric/join", fabricpkg.JoinInput{
		GroupID:           strings.TrimSpace(*group),
		EndpointID:        strings.TrimSpace(*endpointID),
		EndpointName:      strings.TrimSpace(*name),
		Harness:           strings.TrimSpace(*harnessName),
		NativeSessionID:   strings.TrimSpace(*nativeSession),
		NodeID:            strings.TrimSpace(*nodeID),
		Workspace:         strings.TrimSpace(*workspace),
		LeaseSeconds:      *leaseSeconds,
		ContextContinuity: strings.TrimSpace(*continuity),
		Capabilities:      context.Capabilities,
	}, c.managementAuthorization())
	if err != nil {
		return err
	}
	var joined fabricpkg.JoinResult
	if err := json.Unmarshal(body, &joined); err != nil || strings.TrimSpace(joined.SessionToken) == "" {
		return errors.New("Cicada Fabric returned an invalid v2 join result")
	}
	path := c.sessionTokenPath(*tokenFile)
	if path != "" {
		origin, err := normalizeMCPAPIOrigin(c.baseURL)
		if err != nil {
			return err
		}
		if err := writeFabricV2SessionState(path, fabricV2SessionState{
			Version: fabricV2SessionStateVersion, APIOrigin: origin,
			Harness: strings.TrimSpace(*harnessName), NativeSessionID: strings.TrimSpace(*nativeSession),
			NodeID: strings.TrimSpace(*nodeID), Workspace: strings.TrimSpace(*workspace),
			GroupID: strings.TrimSpace(*group), EndpointID: strings.TrimSpace(joined.Endpoint.ID),
			BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt,
			SessionToken: strings.TrimSpace(joined.SessionToken),
		}); err != nil {
			return err
		}
	}
	// Never print the bearer credential.  The returned Network Card and
	// binding coordinates are enough to identify the explicit enrollment.
	safe := make(map[string]any)
	if err := json.Unmarshal(body, &safe); err != nil {
		return err
	}
	delete(safe, "session_token")
	return c.printJSON(safe)
}

func (c *fabricV2CLI) leave(args []string) error {
	flags := flag.NewFlagSet("fabric v2 leave", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reason := flags.String("reason", "", "Reason for leaving")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: cicada fabric v2 leave [--reason REASON]")
	}
	token, err := c.sessionToken()
	if err != nil {
		return err
	}
	groupID, err := c.sessionGroupID()
	if err != nil {
		return err
	}
	_, response, err := c.requestWithGroup(http.MethodPost, "/v2/fabric/leave", map[string]string{"reason": strings.TrimSpace(*reason)}, "CicadaSession "+token, groupID)
	if err != nil {
		return err
	}
	if path := c.sessionTokenPath(""); path != "" && strings.TrimSpace(os.Getenv(fabricV2SessionTokenEnv)) == "" {
		if err := removeFabricV2SessionToken(path); err != nil {
			return err
		}
	}
	return c.printJSONBytes(response)
}

func (c *fabricV2CLI) useGroup(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("usage: cicada fabric v2 use-group GROUP_ID")
	}
	path := c.sessionTokenPath("")
	if path == "" || strings.TrimSpace(os.Getenv(fabricV2SessionTokenEnv)) != "" {
		return errors.New("use-group requires a private session-token-file; one-shot callers may set CICADA_SESSION_GROUP_ID")
	}
	token, err := c.sessionToken()
	if err != nil {
		return err
	}
	groupID := strings.TrimSpace(args[0])
	_, body, err := c.requestWithGroup(http.MethodGet, "/v2/fabric/whoami", nil, "CicadaSession "+token, groupID)
	if err != nil {
		return err
	}
	var card fabricpkg.NetworkCard
	if err := json.Unmarshal(body, &card); err != nil || card.GroupID != groupID {
		return errors.New("server returned a different Group scope")
	}
	state, err := readFabricV2SessionState(path)
	if err != nil {
		return err
	}
	if card.EndpointID != state.EndpointID || (state.BindingID != "" && card.BindingID != state.BindingID) {
		return errors.New("server Group scope does not match the cached native binding")
	}
	state.GroupID = groupID
	if err := writeFabricV2SessionState(path, state); err != nil {
		return err
	}
	return c.printJSONBytes(body)
}

func (c *fabricV2CLI) leaveGroup(args []string) error {
	flags := flag.NewFlagSet("fabric v2 leave-group", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	reason := flags.String("reason", "", "Reason for leaving")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: cicada fabric v2 leave-group [--reason REASON]")
	}
	token, err := c.sessionToken()
	if err != nil {
		return err
	}
	groupID, err := c.sessionGroupID()
	if err != nil {
		return err
	}
	_, body, err := c.requestWithGroup(http.MethodPost, "/v2/fabric/leave-group", map[string]string{"reason": strings.TrimSpace(*reason)}, "CicadaSession "+token, groupID)
	if err != nil {
		return err
	}
	var result struct {
		RemainingGroupID string `json:"remaining_group_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if path := c.sessionTokenPath(""); path != "" && strings.TrimSpace(os.Getenv(fabricV2SessionTokenEnv)) == "" {
		if result.RemainingGroupID == "" {
			if err := removeFabricV2SessionToken(path); err != nil {
				return err
			}
		} else {
			state, err := readFabricV2SessionState(path)
			if err != nil {
				return err
			}
			state.GroupID = result.RemainingGroupID
			if err := writeFabricV2SessionState(path, state); err != nil {
				return err
			}
		}
	}
	return c.printJSONBytes(body)
}

func (c *fabricV2CLI) heartbeat(args []string) error {
	flags := flag.NewFlagSet("fabric v2 heartbeat", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: cicada fabric v2 heartbeat")
	}
	return c.sessionRequest(http.MethodPost, "/v2/fabric/heartbeat", nil)
}

func (c *fabricV2CLI) members(args []string) error {
	flags := flag.NewFlagSet("fabric v2 members", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	status := flags.String("status", "", "Endpoint status filter")
	nodeID := flags.String("node", "", "Node ID filter")
	harnessName := flags.String("harness", "", "Native harness filter")
	limit := flags.Int("limit", 0, "Maximum number of endpoints")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: cicada fabric v2 members [--status STATUS] [--node NODE] [--harness HARNESS] [--limit N]")
	}
	query := url.Values{}
	if value := strings.TrimSpace(*status); value != "" {
		query.Set("status", value)
	}
	if value := strings.TrimSpace(*nodeID); value != "" {
		query.Set("node_id", value)
	}
	if value := strings.TrimSpace(*harnessName); value != "" {
		query.Set("harness", value)
	}
	if *limit > 0 {
		query.Set("limit", strconv.Itoa(*limit))
	}
	path := "/v2/fabric/members"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	return c.sessionRequest(http.MethodGet, path, nil)
}

func (c *fabricV2CLI) find(operation string, args []string) error {
	flags := flag.NewFlagSet("fabric v2 "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nodeID := flags.String("node", "", "Node ID disambiguator")
	workspace := flags.String("workspace", "", "Workspace disambiguator")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 1 {
		return fmt.Errorf("usage: cicada fabric v2 %s QUERY [--node NODE] [--workspace PATH]", operation)
	}
	return c.sessionRequest(http.MethodPost, "/v2/fabric/"+operation, fabricpkg.ResolveInput{
		Query: strings.TrimSpace(flags.Args()[0]), NodeID: strings.TrimSpace(*nodeID), Workspace: strings.TrimSpace(*workspace),
	})
}

func (c *fabricV2CLI) receive(args []string) error {
	flags := flag.NewFlagSet("fabric v2 receive", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.String("cursor", "", "Retired plaintext inbox cursor")
	flags.Int("limit", 0, "Retired plaintext inbox page size")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: cicada fabric v2 receive [--cursor CURSOR] [--limit N]")
	}
	return fabricpkg.ErrPlaintextInboxReceiveRetired
}

func (c *fabricV2CLI) requestStatus(args []string) error {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New("usage: cicada fabric v2 request-status REQUEST_ID")
	}
	return c.sessionRequest(http.MethodGet, "/v2/fabric/requests/"+url.PathEscape(strings.TrimSpace(args[0])), nil)
}

func (c *fabricV2CLI) cancel(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: cicada fabric v2 cancel REQUEST_ID [REASON]")
	}
	reason := ""
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}
	return c.sessionRequest(http.MethodPost, "/v2/fabric/requests/"+url.PathEscape(strings.TrimSpace(args[0]))+"/cancel", fabricpkg.RequestCancelInput{
		RequestID: strings.TrimSpace(args[0]), Reason: reason,
	})
}

func (c *fabricV2CLI) sessionRequest(method, path string, body any) error {
	token, err := c.sessionToken()
	if err != nil {
		return err
	}
	groupID, err := c.sessionGroupID()
	if err != nil {
		return err
	}
	_, response, err := c.requestWithGroup(method, path, body, "CicadaSession "+token, groupID)
	if err != nil {
		return err
	}
	return c.printJSONBytes(response)
}

// request returns a decoded response value for callers that need to inspect
// the join credential and the original bounded JSON for safe output.
func (c *fabricV2CLI) request(method, path string, body any, authorization string) (any, []byte, error) {
	return c.requestWithGroup(method, path, body, authorization, "")
}

func (c *fabricV2CLI) requestWithGroup(method, path string, body any, authorization, groupID string) (any, []byte, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(authorization) != "" {
		request.Header.Set("Authorization", authorization)
	}
	if groupID = strings.TrimSpace(groupID); groupID != "" {
		request.Header.Set("Cicada-Group-Scope", groupID)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode >= 400 {
		message := strings.TrimSpace(string(data))
		if strings.HasPrefix(authorization, "CicadaSession ") {
			secret := strings.TrimSpace(strings.TrimPrefix(authorization, "CicadaSession "))
			message = strings.ReplaceAll(message, secret, "<redacted>")
			message = strings.ReplaceAll(message, fabricpkg.HashSessionCredential(secret), "<redacted>")
		}
		return nil, nil, fmt.Errorf("Cicada API %s: %s", response.Status, message)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, data, nil
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, nil, fmt.Errorf("decode Cicada API response: %w", err)
	}
	return value, data, nil
}

func (c *fabricV2CLI) sessionGroupID() (string, error) {
	if groupID := strings.TrimSpace(os.Getenv("CICADA_SESSION_GROUP_ID")); groupID != "" {
		return groupID, nil
	}
	if strings.TrimSpace(os.Getenv(fabricV2SessionTokenEnv)) != "" {
		return "", nil
	}
	path := c.sessionTokenPath("")
	if path == "" {
		return "", errors.New("session Group scope requires a private session-token-file")
	}
	state, err := readFabricV2SessionState(path)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(state.GroupID) == "" {
		return "", errors.New("cached Cicada session Group scope is empty")
	}
	return state.GroupID, nil
}

func readFabricV2SessionState(path string) (fabricV2SessionState, error) {
	var state fabricV2SessionState
	info, err := os.Lstat(path)
	if err != nil {
		return state, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return state, errors.New("Cicada session credential file is not private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, errors.New("Cicada session credential file is invalid")
	}
	return state, nil
}

func (c *fabricV2CLI) managementAuthorization() string {
	if token := clientAPIToken(); token != "" {
		return "Bearer " + token
	}
	return ""
}

func (c *fabricV2CLI) sessionToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv(fabricV2SessionTokenEnv)); token != "" {
		return token, nil
	}
	path := c.sessionTokenPath("")
	if path == "" {
		return "", errors.New("no active Cicada session credential; run `cicada fabric v2 join --group GROUP_ID` first")
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errors.New("no active Cicada session credential; run `cicada fabric v2 join --group GROUP_ID` first")
		}
		return "", fmt.Errorf("inspect Cicada session credential: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("Cicada session credential must not be a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("Cicada session credential is not private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Cicada session credential: %w", err)
	}
	var state fabricV2SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return "", errors.New("Cicada session credential file is invalid; run `cicada fabric v2 join --group GROUP_ID` first")
	}
	if state.Version != fabricV2SessionStateVersion || strings.TrimSpace(state.SessionToken) == "" ||
		strings.TrimSpace(state.APIOrigin) == "" || strings.TrimSpace(state.Harness) == "" ||
		strings.TrimSpace(state.NativeSessionID) == "" || strings.TrimSpace(state.NodeID) == "" ||
		strings.TrimSpace(state.GroupID) == "" || strings.TrimSpace(state.EndpointID) == "" {
		return "", errors.New("Cicada session credential file is incomplete; run `cicada fabric v2 join --group GROUP_ID` first")
	}
	origin, err := normalizeMCPAPIOrigin(c.baseURL)
	if err != nil {
		return "", err
	}
	if state.APIOrigin != origin {
		return "", errors.New("Cicada session credential is scoped to a different API origin")
	}
	if context, err := harness.DetectCurrentSession(); err == nil {
		trusted, trustedErr := normalizeMCPTrustedContext(context)
		if trustedErr == nil && (trusted.Harness != harness.Canonical(state.Harness) ||
			trusted.NativeSessionID != strings.TrimSpace(state.NativeSessionID) ||
			trusted.NodeID != strings.TrimSpace(state.NodeID) ||
			(state.Workspace != "" && trusted.Workspace != filepath.Clean(state.Workspace))) {
			return "", errors.New("Cicada session credential belongs to a different native session")
		}
	}
	if token := strings.TrimSpace(state.SessionToken); token != "" {
		return token, nil
	}
	return "", errors.New("Cicada session credential file is empty; run `cicada fabric v2 join --group GROUP_ID` first")
}

func (c *fabricV2CLI) sessionTokenPath(explicit string) string {
	if path := strings.TrimSpace(explicit); path != "" {
		return path
	}
	if path := strings.TrimSpace(os.Getenv(fabricV2SessionFileEnv)); path != "" {
		return path
	}
	// There is deliberately no ambient default. A session credential must be
	// selected explicitly so a different thread or API URL cannot silently use
	// the previous enrollment. CICADA_SESSION_TOKEN is the one-shot alternative.
	return ""
}

func (c *fabricV2CLI) printJSON(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.printJSONBytes(encoded)
}

func (c *fabricV2CLI) printJSONBytes(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = c.output.Write(append(encoded, '\n'))
	return err
}

func writeFabricV2SessionState(path string, state fabricV2SessionState) error {
	path = strings.TrimSpace(path)
	state.APIOrigin = strings.TrimSpace(state.APIOrigin)
	state.Harness = harness.Canonical(state.Harness)
	state.NativeSessionID = strings.TrimSpace(state.NativeSessionID)
	state.NodeID = strings.TrimSpace(state.NodeID)
	state.Workspace = strings.TrimSpace(state.Workspace)
	state.GroupID = strings.TrimSpace(state.GroupID)
	state.EndpointID = strings.TrimSpace(state.EndpointID)
	state.SessionToken = strings.TrimSpace(state.SessionToken)
	if state.Version == 0 {
		state.Version = fabricV2SessionStateVersion
	}
	if path == "" || state.Version != fabricV2SessionStateVersion || state.APIOrigin == "" ||
		state.NativeSessionID == "" || state.NodeID == "" || state.GroupID == "" ||
		state.EndpointID == "" || state.SessionToken == "" {
		return errors.New("incomplete Cicada session credential state")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create Cicada session credential directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect Cicada session credential directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("Cicada session credential directory must be a private directory")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect Cicada session credential directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".session-token-*")
	if err != nil {
		return fmt.Errorf("create Cicada session credential file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect Cicada session credential: %w", err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		_ = temporary.Close()
		return fmt.Errorf("encode Cicada session credential: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write Cicada session credential: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync Cicada session credential: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Cicada session credential: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("commit Cicada session credential: %w", err)
	}
	return nil
}

func removeFabricV2SessionToken(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove Cicada session credential: %w", err)
	}
	return nil
}
