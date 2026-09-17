package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	harnesspkg "github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

const maxFabricMessageBytes = 64 * 1024

var ErrEndpointAmbiguous = errors.New("endpoint address is ambiguous")

type EndpointAmbiguityError struct {
	Query      string           `json:"query"`
	Candidates []store.Endpoint `json:"candidates"`
}

func (e *EndpointAmbiguityError) Error() string {
	addresses := make([]string, 0, len(e.Candidates))
	for _, endpoint := range e.Candidates {
		addresses = append(addresses, endpoint.Address)
	}
	return fmt.Sprintf("%v %q: %s", ErrEndpointAmbiguous, e.Query, strings.Join(addresses, ", "))
}

func (e *EndpointAmbiguityError) Unwrap() error { return ErrEndpointAmbiguous }

type EndpointJoinInput struct {
	EndpointID      string         `json:"endpoint_id"`
	Name            string         `json:"name"`
	Role            string         `json:"role"`
	Harness         string         `json:"harness"`
	NativeSessionID string         `json:"native_session_id"`
	MachineID       string         `json:"machine_id"`
	Workspace       string         `json:"workspace"`
	GoalID          string         `json:"goal_id"`
	Status          string         `json:"status"`
	Capabilities    map[string]any `json:"capabilities"`
	Tags            []string       `json:"tags"`
	Owner           string         `json:"owner"`
	Visibility      string         `json:"visibility"`
}

type EndpointListInput struct {
	RequesterEndpointID string `json:"requester_endpoint_id"`
	Status              string `json:"status"`
	MachineID           string `json:"machine_id"`
	Owner               string `json:"owner"`
	Harness             string `json:"harness"`
	Limit               int    `json:"limit"`
}

type EndpointResolveInput struct {
	Query               string `json:"query"`
	RequesterEndpointID string `json:"requester_endpoint_id,omitempty"`
	MachineID           string `json:"machine_id,omitempty"`
	Workspace           string `json:"workspace,omitempty"`
}

type FabricSendInput struct {
	FromEndpointID string         `json:"from_endpoint_id"`
	Target         string         `json:"target"`
	Message        string         `json:"message"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type FabricAskInput struct {
	FromEndpointID string         `json:"from_endpoint_id"`
	Target         string         `json:"target"`
	Question       string         `json:"question"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type FabricReplyInput struct {
	FromEndpointID string         `json:"from_endpoint_id"`
	RequestID      string         `json:"request_id"`
	Message        string         `json:"message"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type NetworkCard struct {
	EndpointID   string         `json:"endpoint_id"`
	Address      string         `json:"address"`
	Name         string         `json:"name"`
	Role         string         `json:"role"`
	Harness      string         `json:"harness"`
	MachineID    string         `json:"machine_id"`
	Workspace    string         `json:"workspace,omitempty"`
	GoalID       string         `json:"goal_id,omitempty"`
	Status       string         `json:"status"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
	Visibility   string         `json:"visibility"`
	FabricID     string         `json:"fabric_id"`
	Tools        []string       `json:"tools"`
	LastSeen     string         `json:"last_seen"`
}

type MachineFabricDelivery struct {
	MessageID       string `json:"message_id"`
	RequestID       string `json:"request_id,omitempty"`
	Kind            string `json:"kind"`
	EndpointID      string `json:"endpoint_id"`
	Harness         string `json:"harness"`
	NativeSessionID string `json:"native_session_id"`
	Prompt          string `json:"prompt"`
}

func (c *Control) JoinEndpoint(input EndpointJoinInput) (*store.Endpoint, error) {
	input.EndpointID = strings.TrimSpace(input.EndpointID)
	input.NativeSessionID = strings.TrimSpace(input.NativeSessionID)
	if len(input.EndpointID) > 256 {
		return nil, errors.New("endpoint_id is too long")
	}
	input.Harness = harnesspkg.Canonical(input.Harness)
	if len(input.NativeSessionID) > 256 {
		return nil, errors.New("native_session_id is too long")
	}
	var previous *store.Endpoint
	if input.EndpointID != "" {
		byID, err := c.store.GetEndpoint(input.EndpointID)
		if err != nil {
			return nil, err
		}
		previous = byID
	}
	if input.Harness == "" {
		if previous != nil {
			input.Harness = previous.Harness
		} else {
			input.Harness = "codex"
		}
	}
	// Phase 3 provides a first-class Codex path while retaining Endpoint as a
	// harness-neutral persisted object for monitor and worker identities.
	if input.Harness != "codex" && input.Harness != "monitor" && input.Harness != "worker" && !harnesspkg.IsOptional(input.Harness) {
		return nil, fmt.Errorf("unsupported endpoint harness: %s", input.Harness)
	}
	if input.NativeSessionID != "" {
		bySession, err := c.store.GetEndpointBySession(input.Harness, input.NativeSessionID)
		if err != nil {
			return nil, err
		}
		if previous != nil && bySession != nil && previous.ID != bySession.ID {
			return nil, errors.New("endpoint_id and native_session_id identify different endpoints")
		}
		if previous == nil {
			previous = bySession
		}
	}
	if previous != nil && input.NativeSessionID == "" {
		input.NativeSessionID = previous.NativeSessionID
	}
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	if input.Role == "" {
		if previous != nil {
			input.Role = previous.Role
		} else {
			input.Role = "thread"
		}
	}
	if len(input.Role) > 64 {
		return nil, errors.New("endpoint role is too long")
	}
	if input.Role == "thread" && input.NativeSessionID == "" {
		return nil, errors.New("native_session_id is required when joining a thread endpoint")
	}
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	if !validEndpointStatus(input.Status) {
		return nil, fmt.Errorf("unsupported endpoint status: %s", input.Status)
	}
	if input.Status == "" {
		input.Status = "online"
	}
	input.Visibility = strings.ToLower(strings.TrimSpace(input.Visibility))
	if input.Visibility == "" {
		if previous != nil {
			input.Visibility = previous.Visibility
		} else {
			input.Visibility = "private"
		}
	}
	if input.Visibility != "private" && input.Visibility != "fabric" && input.Visibility != "public" {
		return nil, errors.New("visibility must be private, fabric, or public")
	}
	// Bind a Control-owned worker to its durable Goal/Machine metadata without
	// changing the native thread identity.
	if input.NativeSessionID != "" {
		worker, err := c.store.FindWorkerByThreadID(input.NativeSessionID)
		if err != nil {
			return nil, err
		}
		if worker != nil {
			if input.MachineID == "" {
				input.MachineID = worker.MachineID
			}
			if input.Workspace == "" {
				input.Workspace = worker.Workspace
			}
			if input.GoalID == "" {
				input.GoalID = worker.GoalID
			}
			if input.Role == "thread" {
				input.Role = "worker"
			}
		}
	}
	if previous != nil {
		if input.MachineID == "" {
			input.MachineID = previous.MachineID
		}
		if input.Workspace == "" {
			input.Workspace = previous.Workspace
		}
		if input.GoalID == "" {
			input.GoalID = previous.GoalID
		}
		if input.Capabilities == nil {
			input.Capabilities = previous.Capabilities
		}
		if input.Tags == nil {
			input.Tags = previous.Tags
		}
	}
	input.GoalID = strings.TrimSpace(input.GoalID)
	if input.GoalID != "" {
		goal, err := c.store.GetGoal(input.GoalID)
		if err != nil {
			return nil, err
		}
		if goal == nil {
			return nil, os.ErrNotExist
		}
	}
	if input.MachineID = strings.TrimSpace(input.MachineID); input.MachineID == "" {
		input.MachineID = "worker-local"
	}
	if len(input.MachineID) > 256 {
		return nil, errors.New("machine_id is too long")
	}
	if machine, err := c.store.GetMachine(input.MachineID); err != nil {
		return nil, err
	} else if machine == nil {
		if _, err := c.store.UpsertMachine(input.MachineID, input.MachineID, map[string]any{"role": "endpoint-host"}, "available"); err != nil {
			return nil, err
		}
	}
	input.Workspace = cleanDisplayWorkspace(input.Workspace)
	if len(input.Workspace) > 4096 {
		return nil, errors.New("endpoint workspace is too long")
	}
	input.Name = normalizeEndpointName(input.Name)
	if input.Name == "" && previous != nil {
		input.Name = previous.Name
	}
	if input.Name == "" {
		input.Name = endpointDefaultName(input.Workspace, input.Harness, input.NativeSessionID)
	}
	if len(input.Name) > 128 {
		return nil, errors.New("endpoint name is too long")
	}
	// The bearer-authenticated Control is the Phase 3 ownership boundary.
	// Never trust a caller-supplied owner string; cross-user ownership arrives
	// later through Contact identities and the E2EE federation path.
	input.Owner = c.Identity().ID
	capabilities, err := sanitizeEndpointCapabilities(input.Capabilities)
	if err != nil {
		return nil, err
	}
	input.Tags = normalizeEndpointTags(input.Tags)
	endpoint, err := c.store.UpsertEndpoint(store.Endpoint{
		ID: input.EndpointID, Name: input.Name, Role: input.Role, Harness: input.Harness,
		NativeSessionID: input.NativeSessionID, MachineID: input.MachineID,
		Workspace: input.Workspace, GoalID: input.GoalID, Status: input.Status,
		Capabilities: capabilities, Tags: input.Tags, Owner: input.Owner, Visibility: input.Visibility,
	})
	if err != nil {
		return nil, err
	}
	c.decorateEndpoint(endpoint)
	eventType := "EndpointJoined"
	if previous != nil && (previous.MachineID != endpoint.MachineID || previous.Workspace != endpoint.Workspace) {
		eventType = "EndpointMoved"
	} else if previous != nil {
		eventType = "EndpointRejoined"
	}
	_, _ = c.store.AppendFabricEvent(endpoint.ID, eventType, map[string]any{
		"address": endpoint.Address, "machine_id": endpoint.MachineID,
		"workspace": endpoint.Workspace, "harness": endpoint.Harness,
	})
	return endpoint, nil
}

func validEndpointStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "online", "idle", "busy", "offline", "left":
		return true
	default:
		return false
	}
}

func normalizeEndpointName(value string) string {
	value = strings.TrimSpace(value)
	var result strings.Builder
	lastDash := false
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '.' {
			result.WriteRune(character)
			lastDash = false
			continue
		}
		if !lastDash {
			result.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(strings.ToLower(result.String()), "-.")
}

func endpointDefaultName(workspace, harness, sessionID string) string {
	if workspace != "" {
		name := normalizeEndpointName(filepath.Base(strings.TrimSuffix(workspace, "/")))
		if name != "" && name != "." {
			return name
		}
	}
	if harness = normalizeEndpointName(harness); harness != "" {
		return harness
	}
	if len(sessionID) > 12 {
		sessionID = sessionID[:12]
	}
	if name := normalizeEndpointName(sessionID); name != "" {
		return name
	}
	return "endpoint"
}

func cleanDisplayWorkspace(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "~/") || value == "~" {
		return filepath.Clean(value)
	}
	if absolute, err := filepath.Abs(value); err == nil {
		value = filepath.Clean(absolute)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if value == home {
			return "~"
		}
		if strings.HasPrefix(value, home+string(filepath.Separator)) {
			return "~" + strings.TrimPrefix(value, home)
		}
	}
	return value
}

func sanitizeEndpointCapabilities(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	if len(input) > 64 {
		return nil, errors.New("endpoint capabilities contain too many keys")
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 128 {
			return nil, errors.New("endpoint capability keys must be non-empty and at most 128 bytes")
		}
		if err := rejectSensitiveCapability(key, value, 0); err != nil {
			return nil, err
		}
		result[key] = value
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode endpoint capabilities: %w", err)
	}
	if len(encoded) > 32*1024 {
		return nil, errors.New("endpoint capabilities are limited to 32 KiB")
	}
	return result, nil
}

func rejectSensitiveCapability(key string, value any, depth int) error {
	if depth > 8 {
		return errors.New("endpoint capabilities are nested too deeply")
	}
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, forbidden := range []string{"token", "secret", "password", "credential", "private_key", "api_key"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("endpoint capability %q may expose a credential", key)
		}
	}
	switch nested := value.(type) {
	case map[string]any:
		for nestedKey, nestedValue := range nested {
			if err := rejectSensitiveCapability(nestedKey, nestedValue, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, nestedValue := range nested {
			if err := rejectSensitiveCapability(key, nestedValue, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeEndpointTags(tags []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" || len(tag) > 64 {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		result = append(result, tag)
		if len(result) == 32 {
			break
		}
	}
	sort.Strings(result)
	return result
}

func (c *Control) decorateEndpoint(endpoint *store.Endpoint) {
	if endpoint != nil {
		machineName := endpoint.MachineID
		if machine, err := c.store.GetMachine(endpoint.MachineID); err == nil && machine != nil {
			machineName = machine.Name
		}
		if isLocalMachine(endpoint.MachineID) {
			if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
				machineName = hostname
			}
		}
		endpoint.Address = endpointAddress(*endpoint, machineAddressName(machineName, endpoint.MachineID))
	}
}

func endpointAddress(endpoint store.Endpoint, machine string) string {
	machine = normalizeEndpointName(machine)
	if machine == "" {
		machine = normalizeEndpointName(endpoint.MachineID)
	}
	if machine == "" {
		machine = "unknown"
	}
	address := endpoint.Name + "@" + machine
	if endpoint.Workspace != "" {
		address += ":" + endpoint.Workspace
	}
	return address
}

func machineAddressName(name, fallback string) string {
	name = strings.TrimSpace(name)
	if open := strings.LastIndex(name, "("); open >= 0 && strings.HasSuffix(name, ")") {
		if inner := strings.TrimSpace(name[open+1 : len(name)-1]); inner != "" {
			name = inner
		}
	}
	if normalizeEndpointName(name) == "" {
		name = fallback
	}
	return name
}

func (c *Control) Endpoint(id string) (*store.Endpoint, error) {
	endpoint, err := c.store.GetEndpoint(strings.TrimSpace(id))
	if err == nil {
		c.decorateEndpoint(endpoint)
	}
	return endpoint, err
}

func (c *Control) EndpointBySession(harness, nativeSessionID string) (*store.Endpoint, error) {
	endpoint, err := c.store.GetEndpointBySession(harnesspkg.Canonical(harness), strings.TrimSpace(nativeSessionID))
	if err == nil {
		c.decorateEndpoint(endpoint)
	}
	return endpoint, err
}

func (c *Control) HeartbeatEndpoint(id, status string) (*store.Endpoint, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "online"
	}
	if !validEndpointStatus(status) || status == "left" {
		return nil, errors.New("heartbeat status must be online, idle, busy, or offline")
	}
	id = strings.TrimSpace(id)
	previous, err := c.store.GetEndpoint(id)
	if err != nil {
		return nil, err
	}
	endpoint, err := c.store.TouchEndpoint(id, status)
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, os.ErrNotExist
	}
	c.decorateEndpoint(endpoint)
	if previous != nil && previous.Status != endpoint.Status {
		_, _ = c.store.AppendFabricEvent(endpoint.ID, "EndpointStatusChanged", map[string]any{"from": previous.Status, "to": endpoint.Status})
	}
	return endpoint, nil
}

func (c *Control) LeaveEndpoint(id string) (*store.Endpoint, error) {
	endpoint, err := c.store.TouchEndpoint(strings.TrimSpace(id), "left")
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, os.ErrNotExist
	}
	c.decorateEndpoint(endpoint)
	_, _ = c.store.AppendFabricEvent(endpoint.ID, "EndpointLeft", map[string]any{"address": endpoint.Address})
	return endpoint, nil
}

func (c *Control) ListEndpoints(input EndpointListInput) ([]store.Endpoint, error) {
	endpoints, err := c.store.ListEndpoints(store.EndpointFilter{
		Status: input.Status, MachineID: input.MachineID, Owner: input.Owner,
		Harness: harnesspkg.Canonical(input.Harness), Limit: input.Limit,
	})
	if err != nil {
		return nil, err
	}
	requesterOwner := ""
	if input.RequesterEndpointID != "" {
		requester, err := c.store.GetEndpoint(input.RequesterEndpointID)
		if err != nil {
			return nil, err
		}
		if requester == nil {
			return nil, os.ErrNotExist
		}
		requesterOwner = requester.Owner
	}
	result := make([]store.Endpoint, 0, len(endpoints))
	for index := range endpoints {
		endpoint := endpoints[index]
		if endpoint.Visibility == "private" && requesterOwner != "" && endpoint.Owner != requesterOwner {
			continue
		}
		c.decorateEndpoint(&endpoint)
		result = append(result, endpoint)
	}
	return result, nil
}

func (c *Control) ResolveEndpoint(input EndpointResolveInput) (*store.Endpoint, error) {
	query := strings.TrimSpace(input.Query)
	if query == "" {
		return nil, errors.New("endpoint query is required")
	}
	if endpoint, err := c.store.GetEndpoint(query); err != nil {
		return nil, err
	} else if endpoint != nil {
		c.decorateEndpoint(endpoint)
		return endpoint, nil
	}
	endpoints, err := c.ListEndpoints(EndpointListInput{RequesterEndpointID: input.RequesterEndpointID, Limit: 1000})
	if err != nil {
		return nil, err
	}
	lowerQuery := strings.ToLower(query)
	exact := make([]store.Endpoint, 0)
	qualified := make([]store.Endpoint, 0)
	global := make([]store.Endpoint, 0)
	for _, endpoint := range endpoints {
		if endpoint.Status == "left" {
			continue
		}
		address := strings.ToLower(endpoint.Address)
		serverAlias := strings.ToLower(strings.SplitN(endpoint.Address, ":", 2)[0])
		machineIDAlias := strings.ToLower(endpoint.Name + "@" + endpoint.MachineID)
		switch {
		case address == lowerQuery:
			exact = append(exact, endpoint)
		case serverAlias == lowerQuery || machineIDAlias == lowerQuery:
			qualified = append(qualified, endpoint)
		case strings.EqualFold(endpoint.Name, query):
			global = append(global, endpoint)
		}
	}
	candidates := exact
	if len(candidates) == 0 {
		candidates = qualified
	}
	if len(candidates) == 0 {
		candidates = global
	}
	// Context only narrows an already ambiguous alias. It never silently picks
	// an unrelated endpoint merely because it shares a workspace.
	if len(candidates) > 1 {
		contextMatches := make([]store.Endpoint, 0)
		for _, endpoint := range candidates {
			if input.MachineID != "" && endpoint.MachineID != input.MachineID {
				continue
			}
			if input.Workspace != "" && cleanDisplayWorkspace(endpoint.Workspace) != cleanDisplayWorkspace(input.Workspace) {
				continue
			}
			contextMatches = append(contextMatches, endpoint)
		}
		if len(contextMatches) > 0 {
			candidates = contextMatches
		}
	}
	if len(candidates) == 0 {
		return nil, os.ErrNotExist
	}
	if len(candidates) > 1 {
		return nil, &EndpointAmbiguityError{Query: query, Candidates: candidates}
	}
	return &candidates[0], nil
}

func (c *Control) InspectEndpoint(input EndpointResolveInput) (*NetworkCard, error) {
	endpoint, err := c.ResolveEndpoint(input)
	if err != nil {
		return nil, err
	}
	return c.networkCard(*endpoint), nil
}

func (c *Control) DirectoryCards(input EndpointListInput) ([]NetworkCard, error) {
	endpoints, err := c.ListEndpoints(input)
	if err != nil {
		return nil, err
	}
	cards := make([]NetworkCard, 0, len(endpoints))
	for _, endpoint := range endpoints {
		cards = append(cards, *c.networkCard(endpoint))
	}
	return cards, nil
}

func (c *Control) WhoAmI(endpointID string) (*NetworkCard, error) {
	endpoint, err := c.Endpoint(strings.TrimSpace(endpointID))
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, os.ErrNotExist
	}
	return c.networkCard(*endpoint), nil
}

func (c *Control) networkCard(endpoint store.Endpoint) *NetworkCard {
	return &NetworkCard{
		EndpointID: endpoint.ID, Address: endpoint.Address, Name: endpoint.Name,
		Role: endpoint.Role, Harness: endpoint.Harness, MachineID: endpoint.MachineID,
		Workspace: endpoint.Workspace, GoalID: endpoint.GoalID, Status: endpoint.Status,
		Capabilities: endpoint.Capabilities, Tags: endpoint.Tags, Visibility: endpoint.Visibility,
		FabricID: c.Identity().ID, LastSeen: endpoint.LastSeen,
		Tools: []string{"cicada_whoami", "cicada_list", "cicada_resolve", "cicada_inspect", "cicada_send", "cicada_ask"},
	}
}

func (c *Control) SendFabricMessage(input FabricSendInput) (*store.FabricMessage, error) {
	return c.createFabricMessage(input.FromEndpointID, input.Target, "send", input.Message, "", "", input.Metadata)
}

func (c *Control) AskFabric(input FabricAskInput) (*store.FabricMessage, error) {
	return c.createFabricMessage(input.FromEndpointID, input.Target, "ask", input.Question, store.NewID("rq"), "", input.Metadata)
}

func (c *Control) createFabricMessage(fromID, target, kind, body, requestID, replyTo string, metadata map[string]any) (*store.FabricMessage, error) {
	fromID = strings.TrimSpace(fromID)
	body = strings.TrimSpace(body)
	if fromID == "" || strings.TrimSpace(target) == "" || body == "" {
		return nil, errors.New("from_endpoint_id, target, and message are required")
	}
	if len(body) > maxFabricMessageBytes {
		return nil, errors.New("fabric message is limited to 64 KiB")
	}
	from, err := c.store.GetEndpoint(fromID)
	if err != nil {
		return nil, err
	}
	if from == nil {
		return nil, os.ErrNotExist
	}
	if from.Status == "left" || from.Status == "offline" {
		return nil, errors.New("source endpoint is not online")
	}
	to, err := c.ResolveEndpoint(EndpointResolveInput{Query: target, RequesterEndpointID: fromID, MachineID: from.MachineID, Workspace: from.Workspace})
	if err != nil {
		return nil, err
	}
	if from.ID == to.ID {
		return nil, errors.New("fabric message requires two different endpoints")
	}
	if _, err := c.CheckPermission("endpoint", from.ID, "fabric."+kind, to.ID); err != nil {
		return nil, err
	}
	message, err := c.store.CreateFabricMessage(store.FabricMessage{
		RequestID: requestID, ReplyTo: replyTo, FromEndpointID: from.ID,
		ToEndpointID: to.ID, Kind: kind, Body: body, Metadata: metadata,
	})
	if err != nil {
		return nil, err
	}
	_, _ = c.store.AppendFabricEvent(from.ID, "FabricMessageQueued", map[string]any{
		"message_id": message.ID, "request_id": message.RequestID, "kind": message.Kind, "to_endpoint_id": to.ID,
	})
	_, _ = c.store.AppendFabricEvent(to.ID, "FabricMessageEnqueued", map[string]any{
		"message_id": message.ID, "request_id": message.RequestID, "kind": message.Kind, "from_endpoint_id": from.ID,
	})
	c.wakeFabricEndpoint(*to, *message)
	return message, nil
}

func (c *Control) ReplyFabric(input FabricReplyInput) (*store.FabricMessage, error) {
	input.FromEndpointID = strings.TrimSpace(input.FromEndpointID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Message = strings.TrimSpace(input.Message)
	if input.FromEndpointID == "" || input.RequestID == "" || input.Message == "" {
		return nil, errors.New("from_endpoint_id, request_id, and message are required")
	}
	if len(input.Message) > maxFabricMessageBytes {
		return nil, errors.New("fabric reply is limited to 64 KiB")
	}
	request, err := c.store.GetFabricRequest(input.RequestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, os.ErrNotExist
	}
	if request.ToEndpointID != input.FromEndpointID {
		return nil, ErrPermissionDenied
	}
	if from, err := c.store.GetEndpoint(input.FromEndpointID); err != nil {
		return nil, err
	} else if from == nil {
		return nil, os.ErrNotExist
	}
	if _, err := c.CheckPermission("endpoint", input.FromEndpointID, "fabric.reply", request.FromEndpointID); err != nil {
		return nil, err
	}
	if request.Status == "replied" {
		return nil, errors.New("fabric request already has a reply")
	}
	reply, err := c.store.CreateFabricMessage(store.FabricMessage{
		RequestID: request.RequestID, ReplyTo: request.ID,
		FromEndpointID: input.FromEndpointID, ToEndpointID: request.FromEndpointID,
		Kind: "reply", Body: input.Message, Metadata: input.Metadata,
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.store.UpdateFabricMessage(request.ID, "replied", ""); err != nil {
		return nil, err
	}
	_, _ = c.store.AppendFabricEvent(input.FromEndpointID, "FabricRequestReplied", map[string]any{
		"message_id": reply.ID, "request_id": request.RequestID, "to_endpoint_id": request.FromEndpointID,
	})
	target, err := c.store.GetEndpoint(request.FromEndpointID)
	if err != nil {
		return nil, err
	}
	if target != nil {
		c.wakeFabricEndpoint(*target, *reply)
	}
	return reply, nil
}

func (c *Control) FabricMessage(id string) (*store.FabricMessage, error) {
	return c.store.GetFabricMessage(strings.TrimSpace(id))
}

func (c *Control) FabricMessages(endpointID, status string, limit int) ([]store.FabricMessage, error) {
	if endpointID != "" {
		if endpoint, err := c.store.GetEndpoint(endpointID); err != nil {
			return nil, err
		} else if endpoint == nil {
			return nil, os.ErrNotExist
		}
	}
	return c.store.ListFabricMessages(endpointID, status, limit)
}

func (c *Control) FabricEvents(endpointID string, after int64, limit int) ([]store.FabricEvent, error) {
	return c.store.ListFabricEvents(strings.TrimSpace(endpointID), after, limit)
}

func (c *Control) ClaimFabricMessages(endpointID string, limit int) ([]store.FabricMessage, error) {
	endpoint, err := c.store.GetEndpoint(strings.TrimSpace(endpointID))
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, os.ErrNotExist
	}
	if _, err := c.store.TouchEndpoint(endpoint.ID, endpoint.Status); err != nil {
		return nil, err
	}
	return c.store.ClaimFabricMessages(endpoint.ID, limit)
}

func (c *Control) MachineFabricDeliveries(machineID string, limit int) ([]MachineFabricDelivery, error) {
	machineID = strings.TrimSpace(machineID)
	if isLocalMachine(machineID) {
		return []MachineFabricDelivery{}, nil
	}
	machine, err := c.store.GetMachine(machineID)
	if err != nil {
		return nil, err
	}
	if machine == nil {
		return nil, os.ErrNotExist
	}
	if err := c.store.RequeueDispatchingFabricMessages(machineID); err != nil {
		return nil, err
	}
	messages, err := c.store.ClaimFabricMessagesForMachine(machineID, limit)
	if err != nil {
		return nil, err
	}
	deliveries := make([]MachineFabricDelivery, 0, len(messages))
	for _, message := range messages {
		endpoint, err := c.store.GetEndpoint(message.ToEndpointID)
		if err != nil {
			return nil, err
		}
		if endpoint == nil || endpoint.MachineID != machineID || endpoint.NativeSessionID == "" {
			_, _ = c.store.UpdateFabricMessage(message.ID, "queued", "target native session is unavailable")
			continue
		}
		deliveries = append(deliveries, MachineFabricDelivery{
			MessageID: message.ID, RequestID: message.RequestID, Kind: message.Kind,
			EndpointID: endpoint.ID, Harness: endpoint.Harness,
			NativeSessionID: endpoint.NativeSessionID, Prompt: fabricDeliveryPrompt(message),
		})
	}
	return deliveries, nil
}

func (c *Control) CompleteMachineFabricDelivery(machineID, messageID, deliveryError string) (*store.FabricMessage, error) {
	machineID = strings.TrimSpace(machineID)
	messageID = strings.TrimSpace(messageID)
	message, err := c.store.GetFabricMessage(messageID)
	if err != nil {
		return nil, err
	}
	if message == nil {
		return nil, os.ErrNotExist
	}
	endpoint, err := c.store.GetEndpoint(message.ToEndpointID)
	if err != nil {
		return nil, err
	}
	if endpoint == nil {
		return nil, os.ErrNotExist
	}
	if endpoint.MachineID != machineID {
		return nil, ErrPermissionDenied
	}
	deliveryError = strings.TrimSpace(deliveryError)
	if len(deliveryError) > 512 {
		deliveryError = deliveryError[:512]
	}
	if message.Status == "delivered" && deliveryError == "" {
		return message, nil
	}
	if message.Status == "queued" && deliveryError != "" {
		return message, nil
	}
	if message.Status != "dispatching" {
		return nil, errors.New("fabric delivery is not assigned to this machine")
	}
	if deliveryError != "" {
		updated, err := c.store.UpdateFabricMessage(message.ID, "queued", deliveryError)
		_, _ = c.store.AppendFabricEvent(endpoint.ID, "FabricDeliveryRetried", map[string]any{"message_id": message.ID, "error": deliveryError})
		return updated, err
	}
	updated, err := c.store.UpdateFabricMessage(message.ID, "delivered", "")
	_, _ = c.store.AppendFabricEvent(endpoint.ID, "FabricMessageDelivered", map[string]any{"message_id": message.ID, "machine_id": machineID})
	return updated, err
}

func (c *Control) wakeFabricEndpoint(endpoint store.Endpoint, message store.FabricMessage) {
	if endpoint.Status == "offline" || endpoint.Status == "left" {
		return
	}
	prompt := fabricDeliveryPrompt(message)
	if endpoint.NativeSessionID == "" {
		return
	}
	if worker, err := c.store.FindWorkerByThreadID(endpoint.NativeSessionID); err == nil && worker != nil {
		if c.wakeFabricWorker(*worker, prompt) == nil {
			_, _ = c.store.UpdateFabricMessage(message.ID, "delivered", "")
		}
		return
	}
	if endpoint.Harness != "codex" || !isLocalMachine(endpoint.MachineID) {
		return
	}
	// Manual Codex TUIs are resumed through the same official queue boundary as
	// the legacy thread API. Delivery is asynchronous; the durable queue remains
	// readable even if the native client has already exited.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		binary := strings.TrimSpace(c.config.CodexBinary)
		if binary == "" {
			binary = "codex"
		}
		command := exec.CommandContext(ctx, binary, "queue", "--thread", endpoint.NativeSessionID, "--message", prompt)
		command.Env = append(os.Environ(), "CODEX_HOME="+envOr("CODEX_HOME", "/state"))
		output, err := command.CombinedOutput()
		if err != nil {
			detail := strings.TrimSpace(string(output))
			if detail == "" {
				detail = err.Error()
			}
			if len(detail) > 512 {
				detail = detail[:512]
			}
			// Keep the envelope queued for polling. Record the wake error in
			// metadata only through the status error when no receiver claims it.
			_, _ = c.store.UpdateFabricMessage(message.ID, "queued", detail)
			return
		}
		_, _ = c.store.UpdateFabricMessage(message.ID, "delivered", "")
	}()
}

func fabricDeliveryPrompt(message store.FabricMessage) string {
	switch message.Kind {
	case "ask":
		return fmt.Sprintf("Cicada Fabric request %s from endpoint %s:\n\n%s\n\nWork on the request in this native session, then reply with cicada_reply using request_id %s.", message.RequestID, message.FromEndpointID, message.Body, message.RequestID)
	case "reply":
		return fmt.Sprintf("Cicada Fabric reply for request %s from endpoint %s:\n\n%s\n\nIncorporate this answer and continue the current work.", message.RequestID, message.FromEndpointID, message.Body)
	default:
		return fmt.Sprintf("Cicada Fabric message from endpoint %s:\n\n%s", message.FromEndpointID, message.Body)
	}
}

func (c *Control) wakeFabricWorker(worker store.Worker, prompt string) error {
	if worker.Status == "running" || worker.Status == "recovering" || worker.Status == "queued" || worker.Status == "verifying" {
		_, err := c.store.EnqueueCommand(worker.GoalID, worker.ID, prompt)
		return err
	}
	goal, err := c.store.GetGoal(worker.GoalID)
	if err != nil {
		return err
	}
	if goal == nil {
		return os.ErrNotExist
	}
	queued := "queued"
	if _, err := c.store.UpdateWorker(worker.ID, store.WorkerUpdate{
		Status: &queued, ClearPID: true, LastError: stringPtr(""), Summary: stringPtr(""), Prompt: &prompt,
	}); err != nil {
		return err
	}
	if _, err := c.store.UpdateGoal(worker.GoalID, queued, goal.Summary); err != nil {
		return err
	}
	if isLocalMachine(worker.MachineID) {
		c.launchWorker(worker.ID, prompt)
	}
	return nil
}
